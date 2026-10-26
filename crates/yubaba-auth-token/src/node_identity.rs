//! R997-B27: per-node identity for node-to-node requests.
//!
//! The cluster key proves only that a caller belongs to the group. This
//! module lets a caller prove *which* node (or which node's tenant-streamer)
//! it is, so a receiver can bind a write or a raft RPC to the node it names.
//!
//! An identity is an ed25519 keypair plus a [`NodeCert`]: the operator's
//! signature over `(kind, node_id, public_key)`. Verifiers hold only the
//! operator public keys they already trust, so no verifier holds a secret
//! and the certificate needs no replicated state to check. A request carries
//! a [`NODE_PROOF_HEADER`] whose signature covers the method, path, a
//! timestamp and the exact body bytes.

use std::path::Path;

use ed25519_compact::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::delegation::{sign_operator_payload, verify_operator_payload, OperatorSecretKey};
use crate::{decode_hex, encode_hex};

/// [`sign_operator_payload`] domain of a node certificate.
pub const NODE_CERT_DOMAIN: &str = "yubaba:node-cert:v1";

/// Domain prefix of the bytes a node key signs for one request.
pub const NODE_PROOF_DOMAIN: &str = "yubaba:node-proof:v1";

/// Request header carrying the proof.
pub const NODE_PROOF_HEADER: &str = "x-yubaba-node-proof";

/// Env var naming the identity file a node or tenant-streamer loads.
pub const NODE_IDENTITY_FILE_ENV: &str = "YUBABA_NODE_IDENTITY_FILE";

/// Where the identity file is installed on a host.
pub const DEFAULT_NODE_IDENTITY_PATH: &str = "/etc/yah-cloud/node-identity.json";

/// How far a proof's timestamp may sit from the receiver's clock, either way.
pub const NODE_PROOF_MAX_SKEW_SECS: i64 = 60;

/// What an identity is allowed to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    /// A raft node: may forward cluster writes and speak raft RPC as itself.
    Node,
    /// A node's tenant-streamer: may hold tenant leases for that node only.
    TenantStreamer,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::TenantStreamer => "tenant-streamer",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "node" => Ok(Self::Node),
            "tenant-streamer" => Ok(Self::TenantStreamer),
            other => Err(format!(
                "unknown identity kind {other:?} (expected \"node\" or \"tenant-streamer\")"
            )),
        }
    }
}

impl std::fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The operator's statement that `public_key` speaks for `kind` `node_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCert {
    pub kind: IdentityKind,
    pub node_id: u64,
    /// 64-char lowercase hex ed25519 public key.
    pub public_key: String,
    /// Hex operator signature over [`cert_body`] in [`NODE_CERT_DOMAIN`].
    pub operator_sig: String,
}

fn cert_body(kind: IdentityKind, node_id: u64, public_key: &str) -> Vec<u8> {
    format!("{kind}\n{node_id}\n{public_key}").into_bytes()
}

impl NodeCert {
    /// Certify `public_key` for `kind` `node_id` under the operator key.
    pub fn issue(
        operator: &OperatorSecretKey,
        kind: IdentityKind,
        node_id: u64,
        public_key: &[u8; 32],
    ) -> Result<Self, String> {
        let public_key = encode_hex(public_key);
        let operator_sig = sign_operator_payload(
            operator,
            NODE_CERT_DOMAIN,
            &cert_body(kind, node_id, &public_key),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            kind,
            node_id,
            public_key,
            operator_sig,
        })
    }

    /// `Ok` iff one of `operator_keys` signed this certificate.
    pub fn verify(&self, operator_keys: &[[u8; 32]]) -> Result<(), String> {
        if operator_keys.is_empty() {
            return Err("no operator key to verify a node certificate against".into());
        }
        let body = cert_body(self.kind, self.node_id, &self.public_key);
        if operator_keys.iter().any(|k| {
            verify_operator_payload(k, NODE_CERT_DOMAIN, &body, &self.operator_sig).is_ok()
        }) {
            Ok(())
        } else {
            Err(format!(
                "certificate for {} {} is not signed by a trusted operator key",
                self.kind, self.node_id
            ))
        }
    }

    fn public(&self) -> Result<PublicKey, String> {
        let bytes = decode_hex(&self.public_key, 32)?;
        PublicKey::from_slice(&bytes).map_err(|e| format!("certificate public key: {e}"))
    }
}

fn proof_message(cert: &NodeCert, ts: i64, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "{NODE_PROOF_DOMAIN}\0{}\n{}\n{}\n{ts}\n{method} {path}\n",
        cert.kind, cert.node_id, cert.public_key
    );
    [head.as_bytes(), body].concat()
}

/// The caller a verified proof names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenCaller {
    pub kind: IdentityKind,
    pub node_id: u64,
}

/// A node's own key and certificate: what it signs its requests with.
pub struct NodeIdentity {
    cert: NodeCert,
    secret: SecretKey,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("kind", &self.cert.kind)
            .field("node_id", &self.cert.node_id)
            .finish_non_exhaustive()
    }
}

/// On-disk shape of an identity file (0600: it holds the secret).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    cert: NodeCert,
    secret_key: String,
}

impl NodeIdentity {
    /// Generate a keypair and certify it under the operator key. Run by the
    /// operator, whose key never goes on a node.
    pub fn mint(
        operator: &OperatorSecretKey,
        kind: IdentityKind,
        node_id: u64,
    ) -> Result<Self, String> {
        use pasetors::keys::{AsymmetricKeyPair, Generate};
        let kp = AsymmetricKeyPair::<pasetors::version4::V4>::generate()
            .map_err(|e| format!("generating node keypair: {e:?}"))?;
        let secret = SecretKey::from_slice(kp.secret.as_bytes())
            .map_err(|e| format!("node secret key: {e}"))?;
        let mut public = [0u8; 32];
        public.copy_from_slice(kp.public.as_bytes());
        let cert = NodeCert::issue(operator, kind, node_id, &public)?;
        Ok(Self { cert, secret })
    }

    /// Parse an identity file. The secret must sign proofs the certificate's
    /// key verifies, so a file whose halves disagree is refused here rather
    /// than at the first peer that checks it.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let file: IdentityFile =
            serde_json::from_str(raw).map_err(|e| format!("identity file is not valid: {e}"))?;
        let secret = SecretKey::from_slice(&decode_hex(file.secret_key.trim(), 64)?)
            .map_err(|e| format!("identity secret key: {e}"))?;
        let identity = Self {
            cert: file.cert,
            secret,
        };
        let probe = identity.sign_message(0, "GET", "/", b"");
        identity
            .cert
            .public()?
            .verify(proof_message(&identity.cert, 0, "GET", "/", b""), &probe)
            .map_err(|_| "identity secret key does not match its certificate".to_string())?;
        Ok(identity)
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("reading identity file {}: {e}", path.display()))?;
        Self::from_json(&raw).map_err(|e| format!("identity file {}: {e}", path.display()))
    }

    /// The file form, secret included.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&IdentityFile {
            cert: self.cert.clone(),
            secret_key: encode_hex(&self.secret[..]),
        })
        .expect("an identity file always serializes")
    }

    pub fn cert(&self) -> &NodeCert {
        &self.cert
    }

    fn sign_message(&self, ts: i64, method: &str, path: &str, body: &[u8]) -> Signature {
        self.secret
            .sign(proof_message(&self.cert, ts, method, path, body), None)
    }

    /// The [`NODE_PROOF_HEADER`] value for one request.
    pub fn prove(&self, method: &str, path: &str, body: &[u8], now: i64) -> String {
        let sig = self.sign_message(now, method, path, body);
        format!(
            "v1.{}.{}.{}.{}.{now}.{}",
            self.cert.kind,
            self.cert.node_id,
            self.cert.public_key,
            self.cert.operator_sig,
            encode_hex(sig.as_ref())
        )
    }
}

/// Verify a [`NODE_PROOF_HEADER`] value against the receiver's operator keys
/// and the request it arrived on.
pub fn verify_node_proof(
    header: &str,
    operator_keys: &[[u8; 32]],
    method: &str,
    path: &str,
    body: &[u8],
    now: i64,
) -> Result<ProvenCaller, String> {
    let parts: Vec<&str> = header.trim().split('.').collect();
    let [version, kind, node_id, public_key, cert_sig, ts, sig] = parts.as_slice() else {
        return Err("malformed node proof".into());
    };
    if *version != "v1" {
        return Err(format!("unsupported node proof version {version:?}"));
    }
    let cert = NodeCert {
        kind: IdentityKind::parse(kind)?,
        node_id: node_id
            .parse()
            .map_err(|_| "node proof node id is not a number".to_string())?,
        public_key: (*public_key).to_string(),
        operator_sig: (*cert_sig).to_string(),
    };
    cert.verify(operator_keys)?;
    let ts: i64 = ts
        .parse()
        .map_err(|_| "node proof timestamp is not a number".to_string())?;
    if (now - ts).abs() > NODE_PROOF_MAX_SKEW_SECS {
        return Err(format!(
            "node proof timestamp is {}s from this node's clock, beyond {NODE_PROOF_MAX_SKEW_SECS}s",
            now - ts
        ));
    }
    let sig = Signature::from_slice(&decode_hex(sig, 64)?)
        .map_err(|e| format!("node proof signature: {e}"))?;
    cert.public()?
        .verify(proof_message(&cert, ts, method, path, body), &sig)
        .map_err(|_| "node proof signature does not verify".to_string())?;
    Ok(ProvenCaller {
        kind: cert.kind,
        node_id: cert.node_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> (OperatorSecretKey, [u8; 32]) {
        let (_, secret) = crate::generate_operator_keypair_hex().unwrap();
        let sk = crate::operator_secret_from_hex(&secret).unwrap();
        let public = crate::delegation::operator_public_bytes(&sk);
        (sk, public)
    }

    #[test]
    fn a_proof_names_its_node_and_binds_method_path_body_and_time() {
        let (op, op_pub) = operator();
        let id = NodeIdentity::mint(&op, IdentityKind::Node, 3).unwrap();
        let proof = id.prove("POST", "/raft/write", b"{\"a\":1}", 1_000);
        assert_eq!(
            verify_node_proof(
                &proof,
                &[op_pub],
                "POST",
                "/raft/write",
                b"{\"a\":1}",
                1_010
            ),
            Ok(ProvenCaller {
                kind: IdentityKind::Node,
                node_id: 3
            })
        );
        for (method, path, body, now) in [
            ("POST", "/raft/write", &b"{\"a\":2}"[..], 1_010),
            ("POST", "/raft/vote", &b"{\"a\":1}"[..], 1_010),
            ("PUT", "/raft/write", &b"{\"a\":1}"[..], 1_010),
            (
                "POST",
                "/raft/write",
                &b"{\"a\":1}"[..],
                1_000 + NODE_PROOF_MAX_SKEW_SECS + 1,
            ),
            (
                "POST",
                "/raft/write",
                &b"{\"a\":1}"[..],
                1_000 - NODE_PROOF_MAX_SKEW_SECS - 1,
            ),
        ] {
            assert!(
                verify_node_proof(&proof, &[op_pub], method, path, body, now).is_err(),
                "{method} {path} at {now} must not verify"
            );
        }
    }

    #[test]
    fn a_proof_cannot_be_relabelled_to_another_node_or_kind() {
        let (op, op_pub) = operator();
        let id = NodeIdentity::mint(&op, IdentityKind::TenantStreamer, 3).unwrap();
        let proof = id.prove("POST", "/tenant-lease", b"x", 50);
        for forged in [
            proof.replacen(".3.", ".4.", 1),
            proof.replacen("tenant-streamer", "node", 1),
        ] {
            assert!(
                verify_node_proof(&forged, &[op_pub], "POST", "/tenant-lease", b"x", 50).is_err()
            );
        }
    }

    #[test]
    fn a_certificate_from_an_untrusted_operator_is_refused() {
        let (op, _) = operator();
        let (_, other_pub) = operator();
        let id = NodeIdentity::mint(&op, IdentityKind::Node, 1).unwrap();
        let proof = id.prove("POST", "/raft/write", b"", 7);
        assert!(verify_node_proof(&proof, &[other_pub], "POST", "/raft/write", b"", 7).is_err());
        assert!(verify_node_proof(&proof, &[], "POST", "/raft/write", b"", 7).is_err());
    }

    #[test]
    fn a_proved_post_carries_a_proof_over_the_exact_body_sent() {
        let (op, op_pub) = operator();
        let id = std::sync::Arc::new(NodeIdentity::mint(&op, IdentityKind::Node, 5).unwrap());
        let signer = crate::PeerSigner::from_fn(|| Ok("t".into())).with_node_identity(Some(id));
        let req = crate::PeerClient::new(reqwest::Client::new(), signer)
            .post_json_proved(
                "http://10.0.0.1:7443/raft/write?x=1",
                &serde_json::json!({"r": 1}),
            )
            .unwrap()
            .build()
            .unwrap();
        let proof = req.headers()[NODE_PROOF_HEADER]
            .to_str()
            .unwrap()
            .to_string();
        let body = req.body().unwrap().as_bytes().unwrap().to_vec();
        let caller = verify_node_proof(
            &proof,
            &[op_pub],
            "POST",
            "/raft/write",
            &body,
            crate::now_unix(),
        )
        .unwrap();
        assert_eq!(caller.node_id, 5);
        assert!(req.headers().get(reqwest::header::AUTHORIZATION).is_some());

        let plain = crate::PeerClient::new(reqwest::Client::new(), crate::PeerSigner::unsigned())
            .post_json_proved("http://h/raft/write", &1)
            .unwrap()
            .build()
            .unwrap();
        assert!(plain.headers().get(NODE_PROOF_HEADER).is_none());
    }

    #[test]
    fn the_identity_file_round_trips_and_refuses_a_foreign_secret() {
        let (op, op_pub) = operator();
        let id = NodeIdentity::mint(&op, IdentityKind::Node, 9).unwrap();
        let back = NodeIdentity::from_json(&id.to_json()).unwrap();
        assert_eq!(back.cert(), id.cert());
        back.cert().verify(&[op_pub]).unwrap();

        let other = NodeIdentity::mint(&op, IdentityKind::Node, 9).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&id.to_json()).unwrap();
        let other_file: serde_json::Value = serde_json::from_str(&other.to_json()).unwrap();
        file["secret_key"] = other_file["secret_key"].clone();
        assert!(NodeIdentity::from_json(&file.to_string()).is_err());
    }
}
