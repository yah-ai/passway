//! R975-F14 (W375 §3-§4): the operator-signed camp-host delegation.
//!
//! "Camp `<camp_id>` is hosted by node `N` at claim epoch `E`", signed by the
//! operator's ed25519 key (the same keypair `yubaba auth keygen` mints and
//! [`crate::read_operator_key_file`] loads). Lives in this crate because it is
//! the owner of operator-key loading and a leaf with no yah-only deps; relay,
//! host and client all link it and apply [`accept_delegation`] identically.
//!
//! # Canonical encoding
//!
//! The signed bytes are UTF-8 JSON with **keys sorted lexicographically and no
//! whitespace**: `{"camp_id":"..","epoch":7,"issued_at":1,"node_id":"..","v":1}`.
//! `node_id` is the JSON `null` for a vacancy. Strings use serde_json escaping,
//! integers are decimal. The encoder here is hand-rolled so the bytes never
//! depend on a serializer's field order; a verifier re-encodes the parsed
//! struct rather than trusting received bytes. (W375 §3 shows `v` first as an
//! illustration; the sorted order is the normative one.)

use ed25519_compact::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::{decode_hex, encode_hex};

/// Current `v` of [`Delegation`].
pub const DELEGATION_VERSION: u32 = 1;

/// The signed payload. `node_id: None` is a **vacancy**: nobody hosts the camp
/// (W375 §4, host revocation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub v: u32,
    pub camp_id: String,
    /// Hex NodeId of the host; `None` = vacancy.
    pub node_id: Option<String>,
    /// The `store_claim` epoch. The only ordering; `issued_at` is never used.
    pub epoch: u64,
    /// Informational unix seconds.
    pub issued_at: u64,
}

fn jstr(s: &str) -> String {
    serde_json::to_string(s).expect("string serialises")
}

impl Delegation {
    pub fn new(camp_id: &str, node_id: Option<&str>, epoch: u64, issued_at: u64) -> Self {
        Self {
            v: DELEGATION_VERSION,
            camp_id: camp_id.to_string(),
            node_id: node_id.map(str::to_string),
            epoch,
            issued_at,
        }
    }

    /// The canonical bytes that are signed (see the module docs).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let node = match &self.node_id {
            Some(n) => jstr(n),
            None => "null".to_string(),
        };
        format!(
            "{{\"camp_id\":{},\"epoch\":{},\"issued_at\":{},\"node_id\":{},\"v\":{}}}",
            jstr(&self.camp_id),
            self.epoch,
            self.issued_at,
            node,
            self.v
        )
        .into_bytes()
    }

    pub fn is_vacancy(&self) -> bool {
        self.node_id.is_none()
    }
}

/// A [`Delegation`] with the operator's signature (hex) over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub sig: String,
}

/// Why a delegation or successor was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    UnsupportedVersion(u32),
    /// Malformed key or signature hex.
    Malformed(String),
    BadSignature,
    CampMismatch { expected: String, got: String },
    /// `epoch <= held` (and not the benign equal-same-node case).
    StaleEpoch { held: u64, offered: u64 },
    /// **ALARM.** Same epoch, different holder: `store_claim` cannot issue one
    /// epoch twice, so the operator key signed something wrong. Callers must
    /// surface this loudly, not treat it as an ordinary reject.
    EpochConflict { epoch: u64, held_node: Option<String>, offered_node: Option<String> },
    /// KeySuccessor signed by a key other than the pinned one.
    NotPinnedKey,
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EpochConflict { epoch, held_node, offered_node } => write!(
                f,
                "ALARM: two different hosts signed for epoch {epoch} ({held_node:?} vs {offered_node:?}); the operator key signed a conflicting delegation"
            ),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for DelegationError {}

/// The non-error outcomes of [`accept_delegation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// Strictly newer: replace what is held.
    Supersedes,
    /// Equal epoch, same holder: already held, nothing to do.
    NoOp,
}

fn pubkey(bytes: &[u8; 32]) -> Result<PublicKey, DelegationError> {
    PublicKey::from_slice(bytes).map_err(|e| DelegationError::Malformed(format!("public key: {e}")))
}

fn sig_of(hex: &str) -> Result<Signature, DelegationError> {
    let b = decode_hex(hex, 64).map_err(DelegationError::Malformed)?;
    Signature::from_slice(&b).map_err(|e| DelegationError::Malformed(format!("signature: {e}")))
}

fn secret_of(secret: &pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>) -> SecretKey {
    // A v4 secret is 64 bytes, seed then public key: ed25519-compact's layout.
    SecretKey::from_slice(secret.as_bytes()).expect("v4 secret is a 64-byte ed25519 key")
}

/// Raw 32-byte public key of a loaded operator secret.
pub fn operator_public_bytes(
    secret: &pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>,
) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret.as_bytes()[32..]);
    out
}

/// Sign with the operator key as loaded by [`crate::read_operator_key_file`].
pub fn sign_delegation(
    secret: &pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>,
    delegation: Delegation,
) -> SignedDelegation {
    let sig = secret_of(secret).sign(delegation.canonical_bytes(), None);
    SignedDelegation { delegation, sig: encode_hex(sig.as_ref()) }
}

/// The operator secret as [`crate::read_operator_key_file`] loads it, nameable
/// by callers that do not depend on pasetors themselves.
pub type OperatorSecretKey = pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>;

/// The bytes [`sign_operator_payload`] signs: `domain`, a NUL, then `body`.
/// A delegation's canonical bytes begin with `{` and a domain never does, so
/// no signature verifies as both a delegation and a payload.
fn payload_message(domain: &str, body: &[u8]) -> Result<Vec<u8>, DelegationError> {
    if domain.is_empty() || domain.starts_with('{') || domain.contains('\0') {
        return Err(DelegationError::Malformed(format!("signing domain {domain:?}")));
    }
    Ok([domain.as_bytes(), b"\0", body].concat())
}

/// R975-F15: sign some other operator-attested document (e.g. the W374 camp
/// vault manifest) with the same key as [`sign_delegation`]. Hex signature.
pub fn sign_operator_payload(
    secret: &OperatorSecretKey,
    domain: &str,
    body: &[u8],
) -> Result<String, DelegationError> {
    let sig = secret_of(secret).sign(payload_message(domain, body)?, None);
    Ok(encode_hex(sig.as_ref()))
}

/// Verify a [`sign_operator_payload`] signature under the pinned operator key.
pub fn verify_operator_payload(
    operator_pub: &[u8; 32],
    domain: &str,
    body: &[u8],
    sig_hex: &str,
) -> Result<(), DelegationError> {
    let sig = sig_of(sig_hex)?;
    pubkey(operator_pub)?
        .verify(payload_message(domain, body)?, &sig)
        .map_err(|_| DelegationError::BadSignature)
}

/// R997-B11: the [`sign_operator_payload`] domain for a workload spec the
/// operator admitted. A node places a replicated spec (a raft workload intent,
/// a floater record) only under a valid signature in this domain, so the
/// authority to deploy is the operator key, never the transport that carried it.
pub const WORKLOAD_SPEC_DOMAIN: &str = "yubaba:workload-spec:v1";

/// Canonical JSON for signing: object keys sorted at every depth, no
/// whitespace, scalars as `serde_json` prints them. Independent of whether the
/// signer's or the verifier's `serde_json` preserves insertion order.
pub fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", jstr(k), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        scalar => scalar.to_string(),
    }
}

/// Sign the deploy body `spec` (bare spec or envelope, exactly as sent) for
/// [`WORKLOAD_SPEC_DOMAIN`]. The workload's ident is a field of the spec, so
/// the signature binds it too; verifiers must still check that the key they
/// store a spec under is the ident the spec declares.
pub fn sign_workload_spec(
    secret: &OperatorSecretKey,
    spec: &serde_json::Value,
) -> Result<String, DelegationError> {
    sign_operator_payload(secret, WORKLOAD_SPEC_DOMAIN, canonical_json(spec).as_bytes())
}

/// Accept `sig_hex` over `spec` if ANY of `operator_pubs` signed it. No keys
/// configured verifies nothing.
pub fn verify_workload_spec(
    operator_pubs: &[[u8; 32]],
    spec: &serde_json::Value,
    sig_hex: &str,
) -> Result<(), DelegationError> {
    let body = canonical_json(spec);
    let mut last = DelegationError::BadSignature;
    for key in operator_pubs {
        match verify_operator_payload(key, WORKLOAD_SPEC_DOMAIN, body.as_bytes(), sig_hex) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Signature check only (version + ed25519 over the canonical bytes).
pub fn verify_delegation(
    signed: &SignedDelegation,
    operator_pub: &[u8; 32],
) -> Result<(), DelegationError> {
    if signed.delegation.v != DELEGATION_VERSION {
        return Err(DelegationError::UnsupportedVersion(signed.delegation.v));
    }
    let sig = sig_of(&signed.sig)?;
    pubkey(operator_pub)?
        .verify(signed.delegation.canonical_bytes(), &sig)
        .map_err(|_| DelegationError::BadSignature)
}

/// The W375 §3 acceptance rule, pure. Accept iff the signature verifies under
/// the pinned `operator_pub`, `camp_id` matches, and `epoch > held`. Equal
/// epoch + same holder is [`Accepted::NoOp`]; equal epoch + different holder is
/// [`DelegationError::EpochConflict`] (the alarm). A vacancy is an ordinary
/// delegation with `node_id: None` and supersedes by epoch like any other.
pub fn accept_delegation(
    signed: &SignedDelegation,
    operator_pub: &[u8; 32],
    camp_id: &str,
    held: Option<&Delegation>,
) -> Result<Accepted, DelegationError> {
    verify_delegation(signed, operator_pub)?;
    let d = &signed.delegation;
    if d.camp_id != camp_id {
        return Err(DelegationError::CampMismatch {
            expected: camp_id.to_string(),
            got: d.camp_id.clone(),
        });
    }
    let Some(h) = held else { return Ok(Accepted::Supersedes) };
    if d.epoch > h.epoch {
        Ok(Accepted::Supersedes)
    } else if d.epoch < h.epoch {
        Err(DelegationError::StaleEpoch { held: h.epoch, offered: d.epoch })
    } else if d.node_id == h.node_id {
        Ok(Accepted::NoOp)
    } else {
        Err(DelegationError::EpochConflict {
            epoch: d.epoch,
            held_node: h.node_id.clone(),
            offered_node: d.node_id.clone(),
        })
    }
}

// ── W375 §4: operator-key rotation ───────────────────────────────────────────

/// `old_pub` hands the operator role to `new_pub`. Signed by the **old** key.
/// Canonical bytes: `{"epoch":N,"new_pub":"<hex>","old_pub":"<hex>"}` (sorted,
/// no whitespace). Not usable if the old key is compromised; clients re-pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySuccessor {
    pub old_pub: String,
    pub new_pub: String,
    /// Rotation counter: a client accepts only a strictly higher one.
    pub epoch: u64,
}

impl KeySuccessor {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"epoch\":{},\"new_pub\":{},\"old_pub\":{}}}",
            self.epoch,
            jstr(&self.new_pub),
            jstr(&self.old_pub)
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeySuccessor {
    pub successor: KeySuccessor,
    pub sig: String,
}

/// Build and sign a successor record with the OLD secret.
pub fn sign_key_successor(
    old_secret: &pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>,
    new_pub: &[u8; 32],
    epoch: u64,
) -> SignedKeySuccessor {
    let successor = KeySuccessor {
        old_pub: encode_hex(&operator_public_bytes(old_secret)),
        new_pub: encode_hex(new_pub),
        epoch,
    };
    let sig = secret_of(old_secret).sign(successor.canonical_bytes(), None);
    SignedKeySuccessor { successor, sig: encode_hex(sig.as_ref()) }
}

/// Accept a rotation iff `old_pub` is the currently pinned key, the signature
/// verifies under it, and `epoch > held_epoch`. Returns the new key to pin.
pub fn accept_key_successor(
    signed: &SignedKeySuccessor,
    pinned_pub: &[u8; 32],
    held_epoch: Option<u64>,
) -> Result<[u8; 32], DelegationError> {
    let s = &signed.successor;
    let old = crate::decode_hex32(&s.old_pub).map_err(DelegationError::Malformed)?;
    if &old != pinned_pub {
        return Err(DelegationError::NotPinnedKey);
    }
    let new = crate::decode_hex32(&s.new_pub).map_err(DelegationError::Malformed)?;
    pubkey(&new)?;
    let sig = sig_of(&signed.sig)?;
    pubkey(&old)?
        .verify(s.canonical_bytes(), &sig)
        .map_err(|_| DelegationError::BadSignature)?;
    if let Some(h) = held_epoch {
        if s.epoch <= h {
            return Err(DelegationError::StaleEpoch { held: h, offered: s.epoch });
        }
    }
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>, [u8; 32]) {
        let (_, sec) = crate::generate_operator_keypair_hex().unwrap();
        let sk = crate::operator_secret_from_hex(&sec).unwrap();
        let pk = operator_public_bytes(&sk);
        (sk, pk)
    }

    #[test]
    fn a_workload_spec_signature_survives_key_order_and_refuses_tampering() {
        let (sk, pk) = keypair();
        let (_, other_pk) = keypair();
        let spec = serde_json::json!({"name": "web", "args": ["a", "b"], "env": {"Z": "1", "A": "2"}});
        let sig = sign_workload_spec(&sk, &spec).unwrap();
        // Same document, keys in another order: still the operator's.
        let reordered: serde_json::Value =
            serde_json::from_str(r#"{"env":{"A":"2","Z":"1"},"args":["a","b"],"name":"web"}"#).unwrap();
        verify_workload_spec(&[other_pk, pk], &reordered, &sig).unwrap();
        let mut tampered = spec.clone();
        tampered["args"] = serde_json::json!(["a", "c"]);
        assert_eq!(verify_workload_spec(&[pk], &tampered, &sig), Err(DelegationError::BadSignature));
        assert!(verify_workload_spec(&[other_pk], &spec, &sig).is_err());
        assert!(verify_workload_spec(&[], &spec, &sig).is_err());
        // A spec signature is not a signature in any other operator domain.
        let body = canonical_json(&spec);
        assert!(verify_operator_payload(&pk, "yah:other", body.as_bytes(), &sig).is_err());
    }

    fn signed(sk: &pasetors::keys::AsymmetricSecretKey<pasetors::version4::V4>, node: Option<&str>, epoch: u64) -> SignedDelegation {
        sign_delegation(sk, Delegation::new("camp1", node, epoch, 1792540800))
    }

    #[test]
    fn canonical_encoding_is_stable() {
        let d = Delegation::new("a4cbbff4b281", Some("ab12"), 7, 1792540800);
        assert_eq!(
            String::from_utf8(d.canonical_bytes()).unwrap(),
            r#"{"camp_id":"a4cbbff4b281","epoch":7,"issued_at":1792540800,"node_id":"ab12","v":1}"#
        );
        let v = Delegation::new("c", None, 8, 1);
        assert_eq!(
            String::from_utf8(v.canonical_bytes()).unwrap(),
            r#"{"camp_id":"c","epoch":8,"issued_at":1,"node_id":null,"v":1}"#
        );
    }

    #[test]
    fn signature_vector_is_deterministic_and_round_trips_json() {
        let seed = ed25519_compact::Seed::new([7u8; 32]);
        let kp = ed25519_compact::KeyPair::from_seed(seed);
        let sk2 = crate::operator_secret_from_hex(&encode_hex(&*kp.sk)).unwrap();
        let a = signed(&sk2, Some("n"), 3);
        let b = signed(&sk2, Some("n"), 3);
        assert_eq!(a.sig, b.sig);
        let json = serde_json::to_string(&a).unwrap();
        let back: SignedDelegation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
        verify_delegation(&back, &operator_public_bytes(&sk2)).unwrap();
    }

    #[test]
    fn accepts_first_and_higher_epoch() {
        let (sk, pk) = keypair();
        let s5 = signed(&sk, Some("a"), 5);
        assert_eq!(accept_delegation(&s5, &pk, "camp1", None), Ok(Accepted::Supersedes));
        let s6 = signed(&sk, Some("b"), 6);
        assert_eq!(accept_delegation(&s6, &pk, "camp1", Some(&s5.delegation)), Ok(Accepted::Supersedes));
    }

    #[test]
    fn rejects_lower_epoch() {
        let (sk, pk) = keypair();
        let held = signed(&sk, Some("b"), 6).delegation;
        assert_eq!(
            accept_delegation(&signed(&sk, Some("a"), 5), &pk, "camp1", Some(&held)),
            Err(DelegationError::StaleEpoch { held: 6, offered: 5 })
        );
    }

    #[test]
    fn equal_epoch_same_node_is_noop() {
        let (sk, pk) = keypair();
        let held = signed(&sk, Some("a"), 5).delegation;
        assert_eq!(
            accept_delegation(&signed(&sk, Some("a"), 5), &pk, "camp1", Some(&held)),
            Ok(Accepted::NoOp)
        );
    }

    #[test]
    fn equal_epoch_different_node_is_the_alarm() {
        let (sk, pk) = keypair();
        let held = signed(&sk, Some("a"), 5).delegation;
        let err = accept_delegation(&signed(&sk, Some("b"), 5), &pk, "camp1", Some(&held)).unwrap_err();
        assert!(matches!(err, DelegationError::EpochConflict { epoch: 5, .. }));
        assert!(err.to_string().starts_with("ALARM"));
        // vacancy vs a host at the same epoch is also a conflict
        assert!(matches!(
            accept_delegation(&signed(&sk, None, 5), &pk, "camp1", Some(&held)),
            Err(DelegationError::EpochConflict { .. })
        ));
    }

    #[test]
    fn rejects_wrong_camp_wrong_key_and_tampering() {
        let (sk, pk) = keypair();
        let (_, other_pk) = keypair();
        let s = signed(&sk, Some("a"), 5);
        assert!(matches!(
            accept_delegation(&s, &pk, "camp2", None),
            Err(DelegationError::CampMismatch { .. })
        ));
        assert_eq!(accept_delegation(&s, &other_pk, "camp1", None), Err(DelegationError::BadSignature));
        let mut t = s.clone();
        t.delegation.epoch = 99;
        assert_eq!(accept_delegation(&t, &pk, "camp1", None), Err(DelegationError::BadSignature));
        let mut bad = s.clone();
        bad.sig = "zz".into();
        assert!(matches!(accept_delegation(&bad, &pk, "camp1", None), Err(DelegationError::Malformed(_))));
        let mut v2 = s;
        v2.delegation.v = 2;
        assert_eq!(accept_delegation(&v2, &pk, "camp1", None), Err(DelegationError::UnsupportedVersion(2)));
    }

    #[test]
    fn vacancy_supersedes_a_host_and_is_superseded_in_turn() {
        let (sk, pk) = keypair();
        let host = signed(&sk, Some("a"), 5);
        let vacancy = signed(&sk, None, 6);
        assert!(vacancy.delegation.is_vacancy());
        assert_eq!(accept_delegation(&vacancy, &pk, "camp1", Some(&host.delegation)), Ok(Accepted::Supersedes));
        let next = signed(&sk, Some("c"), 7);
        assert_eq!(accept_delegation(&next, &pk, "camp1", Some(&vacancy.delegation)), Ok(Accepted::Supersedes));
        // the old host's delegation can no longer come back
        assert!(matches!(
            accept_delegation(&host, &pk, "camp1", Some(&vacancy.delegation)),
            Err(DelegationError::StaleEpoch { .. })
        ));
    }

    #[test]
    fn key_successor_rules() {
        let (old, old_pk) = keypair();
        let (_, new_pk) = keypair();
        let s = sign_key_successor(&old, &new_pk, 1);
        assert_eq!(accept_key_successor(&s, &old_pk, None), Ok(new_pk));
        assert_eq!(accept_key_successor(&s, &old_pk, Some(0)), Ok(new_pk));
        assert!(matches!(
            accept_key_successor(&s, &old_pk, Some(1)),
            Err(DelegationError::StaleEpoch { held: 1, offered: 1 })
        ));
        // signed by a key that is not the pinned one
        assert_eq!(accept_key_successor(&s, &new_pk, None), Err(DelegationError::NotPinnedKey));
        // tampered new_pub
        let mut t = s.clone();
        t.successor.new_pub = encode_hex(&old_pk);
        assert_eq!(accept_key_successor(&t, &old_pk, None), Err(DelegationError::BadSignature));
        // claims old_pub = pinned but signed by an impostor
        let (imp, _) = keypair();
        let mut f = sign_key_successor(&imp, &new_pk, 2);
        f.successor.old_pub = encode_hex(&old_pk);
        assert_eq!(accept_key_successor(&f, &old_pk, None), Err(DelegationError::BadSignature));
        assert_eq!(
            String::from_utf8(s.successor.canonical_bytes()).unwrap(),
            format!(r#"{{"epoch":1,"new_pub":"{}","old_pub":"{}"}}"#, encode_hex(&new_pk), encode_hex(&old_pk))
        );
    }

    #[test]
    fn operator_payload_is_domain_bound_and_never_a_delegation() {
        let (sk, pk) = keypair();
        let (_, other_pk) = keypair();
        let sig = sign_operator_payload(&sk, "yah/test/v1", b"body").unwrap();
        verify_operator_payload(&pk, "yah/test/v1", b"body", &sig).unwrap();
        for (p, dom, body) in [(pk, "yah/test/v2", &b"body"[..]), (pk, "yah/test/v1", b"bodY"), (other_pk, "yah/test/v1", b"body")] {
            assert_eq!(verify_operator_payload(&p, dom, body, &sig), Err(DelegationError::BadSignature));
        }
        assert!(sign_operator_payload(&sk, "{", b"").is_err());
        assert!(sign_operator_payload(&sk, "", b"").is_err());
        let d = signed(&sk, Some("aa"), 1);
        let forged = SignedDelegation { delegation: d.delegation.clone(), sig };
        assert_eq!(verify_delegation(&forged, &pk), Err(DelegationError::BadSignature));
    }
}
