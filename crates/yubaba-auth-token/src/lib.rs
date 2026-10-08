//! The yubaba control-plane token format, and the client that attaches one
//! (R876-T18).
//!
//! yubaba's HTTP surface (`yubaba::http_auth`) accepts two credential tiers:
//! PEER tokens are PASETO v4.local sealed under one cluster-wide symmetric key,
//! OPERATOR tokens are PASETO v4.public signed by an operator's secret key and
//! verified against public keys configured on the node. Both carry the same
//! claims: `aud`, `sub`, `iat`, `exp` and a `scope` array.
//!
//! This crate is the one owner of that format — the constants, the claims a
//! minter writes, the checks a verifier applies to them, and the hex spelling
//! of the keys. It exists because the format has callers in four places that
//! cannot share a crate any other way: the fleet daemon (verifies and mints),
//! `yubaba-consensus` (signs raft RPC), the tenant streamer (W253 tenet 1: it
//! must not link yubaba) and passway (its own workspace). Before it, the claims
//! lived in `yubaba::http_auth` and every out-of-process caller would have had
//! to copy them.
//!
//! Signature *verification* stays in `yubaba::http_auth`: only a node holds
//! the trust roots, and only a node decides what a route demands.
//!
//! # Mint per request, never cache
//!
//! A verifier refuses any token whose `exp` is more than
//! [`MAX_TOKEN_TTL_SECS`] from *now*, so a token minted once at boot starts
//! 401ing a day later. Minting is pure and cheap (one symmetric encryption, no
//! I/O), so [`PeerSigner::sign`] mints a fresh token for every request rather
//! than caching one with a refresh timer that would have its own failure mode.
//!
//! # Unsigned is a real state, not an error
//!
//! A caller with no cluster key configured sends no `Authorization` header —
//! exactly what every caller sent before R876-B15. Against a node in `warn`
//! mode that is served; against one in `require` mode it is a 401 the operator
//! can see. The roll order in R876-T18 (keys everywhere, then flip) is what
//! keeps that second case from happening on the fleet.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use pasetors::version4::{LocalToken, PublicToken, V4};

// ── The format ───────────────────────────────────────────────────────────────

/// `aud` every yubaba control-plane token must carry.
///
/// Present so a token minted for a *different* verifier that happens to
/// share a key — yubaba already mints cheers-audience tokens with its own
/// service-principal key — cannot be replayed here. Audience separation is the
/// cheap half of not reusing keys; the expensive half is not reusing keys,
/// which is why the operator trust set is configured separately from the
/// cheers principal.
pub const AUDIENCE: &str = "yubaba:control-plane";

/// `scope` entry an operator-tier token must carry.
pub const OPERATOR_SCOPE: &str = "yubaba:operator";

/// `scope` entry a peer-tier token must carry.
pub const PEER_SCOPE: &str = "yubaba:peer";

/// Default lifetime for a freshly minted token.
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 300;

/// Longest `exp` a verifier will honour, measured from *now* rather than
/// from the token's `iat`.
///
/// Without a ceiling, a bearer token is a standing credential: mint one
/// with `exp` ten years out, paste it into a script, and the tier's whole
/// point (a short-lived, revocable-by-expiry grant) is gone. Measuring from
/// now rather than from `iat` means a minter cannot dodge it by backdating,
/// and it needs no clock agreement beyond the one `exp` already assumes.
pub const MAX_TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

/// The env var naming the cluster-key FILE, on every process that holds one.
///
/// A *file*, not the key itself in an env var: the cluster key is a bearer
/// secret, and an env var is readable from `/proc/<pid>/environ`, inherited by
/// every child the process spawns, and printed by half the diagnostics in this
/// repo.
pub const CLUSTER_KEY_FILE_ENV: &str = "YUBABA_CLUSTER_KEY_FILE";

fn claims_json(subject: &str, scope: &str, ttl_secs: i64, now: i64) -> Result<String, String> {
    if ttl_secs <= 0 || ttl_secs > MAX_TOKEN_TTL_SECS {
        return Err(format!(
            "ttl {ttl_secs}s is outside (0, {MAX_TOKEN_TTL_SECS}]"
        ));
    }
    serde_json::to_string(&serde_json::json!({
        "aud": AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + ttl_secs,
        "scope": [scope],
    }))
    .map_err(|e| format!("serializing claims: {e}"))
}

/// Check `aud`, `exp` and `scope` on a token whose signature already
/// verified, and return its `sub`. `required_scope` is [`PEER_SCOPE`] or
/// [`OPERATOR_SCOPE`], per the tier whose key verified it.
pub fn validate_claims(payload: &str, required_scope: &str, now: i64) -> Result<String, String> {
    let claims: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| format!("token payload is not JSON: {e}"))?;

    match claims.get("aud").and_then(|v| v.as_str()) {
        Some(AUDIENCE) => {}
        Some(other) => return Err(format!("token audience {other:?} is not {AUDIENCE:?}")),
        None => return Err("token carries no aud".into()),
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "token carries no numeric exp".to_string())?;
    if exp <= now {
        return Err("token is expired".into());
    }
    if exp - now > MAX_TOKEN_TTL_SECS {
        return Err(format!(
            "token exp is {}s out, beyond the {MAX_TOKEN_TTL_SECS}s ceiling",
            exp - now
        ));
    }

    let has_scope = claims
        .get("scope")
        .and_then(|v| v.as_array())
        .is_some_and(|entries| entries.iter().any(|e| e.as_str() == Some(required_scope)));
    if !has_scope {
        return Err(format!("token does not carry scope {required_scope:?}"));
    }

    claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "token carries no sub".to_string())
}

// ── Minting ──────────────────────────────────────────────────────────────────

/// Mint an operator-tier token. The secret half never leaves the operator's
/// key store; nodes hold only the public half.
pub fn mint_operator_token(
    secret: &AsymmetricSecretKey<V4>,
    subject: &str,
    ttl_secs: i64,
    now: i64,
) -> Result<String, String> {
    let payload = claims_json(subject, OPERATOR_SCOPE, ttl_secs, now)?;
    PublicToken::sign(secret, payload.as_bytes(), None, None)
        .map_err(|e| format!("signing operator token: {e:?}"))
}

/// Mint a peer-tier token under the cluster key.
pub fn mint_peer_token(
    key: &SymmetricKey<V4>,
    subject: &str,
    ttl_secs: i64,
    now: i64,
) -> Result<String, String> {
    let payload = claims_json(subject, PEER_SCOPE, ttl_secs, now)?;
    LocalToken::encrypt(key, payload.as_bytes(), None, None)
        .map_err(|e| format!("encrypting peer token: {e:?}"))
}

/// Seconds since the epoch — the `now` every mint and check takes.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Key material ─────────────────────────────────────────────────────────────

/// Generate an operator keypair, hex-encoded as `(public, secret)`.
///
/// The public half is what goes on each node as `--operator-key`; the secret
/// half is what mints. Returned as hex rather than as key objects so callers
/// — `yubaba auth keygen`, cloud-client's round-trip test — need no crypto
/// dependency of their own.
pub fn generate_operator_keypair_hex() -> Result<(String, String), String> {
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    let kp = AsymmetricKeyPair::<V4>::generate()
        .map_err(|e| format!("generating operator keypair: {e:?}"))?;
    Ok((
        encode_hex(kp.public.as_bytes()),
        encode_hex(kp.secret.as_bytes()),
    ))
}

/// Generate a cluster key, hex-encoded. One per cluster, held by every node.
pub fn generate_cluster_key_hex() -> Result<String, String> {
    use pasetors::keys::Generate;
    let key =
        SymmetricKey::<V4>::generate().map_err(|e| format!("generating cluster key: {e:?}"))?;
    Ok(encode_hex(key.as_bytes()))
}

/// Parse a 128-char hex v4 asymmetric secret key (64 bytes: seed + pubkey).
pub fn operator_secret_from_hex(raw: &str) -> Result<AsymmetricSecretKey<V4>, String> {
    let bytes = decode_hex(raw.trim(), 64)?;
    AsymmetricSecretKey::<V4>::from(&bytes)
        .map_err(|e| format!("not a valid v4 secret key: {e:?}"))
}

/// Parse a 64-char hex ed25519 operator *public* key — the same spelling
/// `--control-plane-allow` uses for `NodeId`s.
pub fn operator_public_from_hex(raw: &str) -> Result<AsymmetricPublicKey<V4>, String> {
    let bytes = decode_hex32(raw.trim())?;
    AsymmetricPublicKey::<V4>::from(&bytes)
        .map_err(|e| format!("not a valid v4 public key: {e:?}"))
}

/// Parse a 64-char hex 32-byte cluster key.
pub fn cluster_key_from_hex(raw: &str) -> Result<SymmetricKey<V4>, String> {
    let bytes = decode_hex32(raw.trim())?;
    SymmetricKey::<V4>::from(&bytes).map_err(|e| format!("not a valid v4 symmetric key: {e:?}"))
}

/// Read and parse a cluster-key file (hex, surrounding whitespace ignored).
pub fn cluster_key_from_file(path: &Path) -> Result<SymmetricKey<V4>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading cluster key file {}: {e}", path.display()))?;
    cluster_key_from_hex(&raw)
        .map_err(|e| format!("cluster key file {}: {e}", path.display()))
}

/// Lowercase hex, the spelling `--control-plane-allow` already uses.
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex32(raw: &str) -> Result<[u8; 32], String> {
    let v = decode_hex(raw, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn decode_hex(raw: &str, want_bytes: usize) -> Result<Vec<u8>, String> {
    if raw.len() != want_bytes * 2 {
        return Err(format!(
            "expected {} hex chars, got {}",
            want_bytes * 2,
            raw.len()
        ));
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(want_bytes);
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("{:?} is not a hex digit", other as char)),
    }
}

// ── Attaching a token ────────────────────────────────────────────────────────

/// Mints one bearer token. `Err` is a configuration fault (an impossible TTL,
/// a broken key) and is logged, not propagated: see [`PeerSigner::bearer`].
type MintFn = dyn Fn() -> Result<String, String> + Send + Sync;

/// Attaches a freshly minted peer-tier token to outbound requests.
#[derive(Clone, Default)]
pub struct PeerSigner {
    mint: Option<Arc<MintFn>>,
}

impl std::fmt::Debug for PeerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSigner")
            .field("signing", &self.mint.is_some())
            .finish()
    }
}

impl PeerSigner {
    /// A signer that attaches nothing — a caller with no cluster key.
    pub fn unsigned() -> Self {
        Self { mint: None }
    }

    /// A signer that calls `mint` once per request.
    pub fn from_fn(mint: impl Fn() -> Result<String, String> + Send + Sync + 'static) -> Self {
        Self {
            mint: Some(Arc::new(mint)),
        }
    }

    /// Mint peer tokens for `subject` under `key`, [`DEFAULT_TOKEN_TTL_SECS`]
    /// each.
    pub fn for_cluster_key(key: SymmetricKey<V4>, subject: String) -> Self {
        Self::from_fn(move || mint_peer_token(&key, &subject, DEFAULT_TOKEN_TTL_SECS, now_unix()))
    }

    /// The signer an out-of-process caller builds from its config: signing
    /// under the key in `key_file` when one is named, unsigned when not.
    ///
    /// A named file that cannot be read or parsed is an `Err`, not a silent
    /// fall back to unsigned — that fallback would surface only once the fleet
    /// flips to `require`, as a 401 far from the misconfiguration.
    pub fn from_key_file(key_file: Option<&Path>, subject: String) -> Result<Self, String> {
        match key_file {
            Some(path) => Ok(Self::for_cluster_key(cluster_key_from_file(path)?, subject)),
            None => Ok(Self::unsigned()),
        }
    }

    /// Does this signer attach a credential at all?
    pub fn is_signing(&self) -> bool {
        self.mint.is_some()
    }

    /// The `Authorization` value for one request, if this signer has a key.
    ///
    /// A mint failure degrades to unsigned with a WARN rather than failing the
    /// request: an unsigned call to a warn-mode peer still works, and to a
    /// require-mode peer it fails with a 401 that names the problem — both
    /// strictly better than dropping raft traffic on the floor here.
    pub fn bearer(&self) -> Option<String> {
        let mint = self.mint.as_ref()?;
        match mint() {
            Ok(token) => Some(format!("Bearer {token}")),
            Err(e) => {
                tracing::warn!(error = %e, "minting a peer token failed; sending this request unsigned");
                None
            }
        }
    }

    /// Attach a fresh token to `rb`, or return it untouched when unsigned.
    pub fn sign(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.bearer() {
            Some(value) => rb.header(reqwest::header::AUTHORIZATION, value),
            None => rb,
        }
    }
}

/// A [`reqwest::Client`] whose every request carries a peer token.
///
/// The type exists so that "this client dials yubaba peer routes" is something
/// the compiler checks rather than something each call site remembers: a
/// function that takes a `&PeerClient` cannot be handed a bare client and
/// silently send unsigned requests once the fleet enforces.
#[derive(Clone, Debug)]
pub struct PeerClient {
    http: reqwest::Client,
    signer: PeerSigner,
}

impl PeerClient {
    pub fn new(http: reqwest::Client, signer: PeerSigner) -> Self {
        Self { http, signer }
    }

    /// The same underlying client, re-keyed.
    pub fn with_signer(self, signer: PeerSigner) -> Self {
        Self { signer, ..self }
    }

    pub fn signer(&self) -> &PeerSigner {
        &self.signer
    }

    /// The unsigned client underneath, for a caller that must set the
    /// credential itself (forwarding an operator's own token).
    pub fn raw(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn get(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.signer.sign(self.http.get(url))
    }

    pub fn post(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.signer.sign(self.http.post(url))
    }

    pub fn delete(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.signer.sign(self.http.delete(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::token::{Local, UntrustedToken};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn an_unsigned_signer_attaches_nothing() {
        let rb = PeerSigner::unsigned().sign(reqwest::Client::new().get("http://127.0.0.1:1/"));
        let req = rb.build().unwrap();
        assert!(req.headers().get(reqwest::header::AUTHORIZATION).is_none());
    }

    #[test]
    fn a_signer_mints_once_per_request_rather_than_caching() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let client = PeerClient::new(
            reqwest::Client::new(),
            PeerSigner::from_fn(move || Ok(format!("t{}", c.fetch_add(1, Ordering::SeqCst)))),
        );
        let a = client.post("http://127.0.0.1:1/raft/vote").build().unwrap();
        let b = client.get("http://127.0.0.1:1/raft/status").build().unwrap();
        assert_eq!(a.headers()[reqwest::header::AUTHORIZATION], "Bearer t0");
        assert_eq!(b.headers()[reqwest::header::AUTHORIZATION], "Bearer t1");
    }

    #[test]
    fn a_mint_failure_degrades_to_unsigned() {
        let signer = PeerSigner::from_fn(|| Err("bad ttl".into()));
        assert!(signer.is_signing());
        assert_eq!(signer.bearer(), None);
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let raw = [7u8; 32];
        assert_eq!(decode_hex32(&encode_hex(&raw)).unwrap(), raw);
        assert!(decode_hex32("abcd").is_err());
        assert!(decode_hex32(&"z".repeat(64)).is_err());
    }

    /// The whole out-of-process path: a key file on disk, a signer built from
    /// it, and a token that decrypts under the same key and validates as a
    /// peer — which is what yubaba's verifier will do with it.
    #[test]
    fn a_key_file_signer_mints_a_token_that_validates_as_peer() {
        let hex = generate_cluster_key_hex().unwrap();
        let dir = std::env::temp_dir().join(format!("yubaba-auth-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cluster.key");
        std::fs::write(&path, format!("{hex}\n")).unwrap();

        let signer = PeerSigner::from_key_file(Some(&path), "svc:tenant-streamer".into()).unwrap();
        let bearer = signer.bearer().unwrap();
        let token = bearer.strip_prefix("Bearer ").unwrap();

        let key = cluster_key_from_hex(&hex).unwrap();
        let untrusted = UntrustedToken::<Local, V4>::try_from(token).unwrap();
        let trusted = LocalToken::decrypt(&key, &untrusted, None, None).unwrap();
        let sub = validate_claims(trusted.payload(), PEER_SCOPE, now_unix()).unwrap();
        assert_eq!(sub, "svc:tenant-streamer");
        assert!(validate_claims(trusted.payload(), OPERATOR_SCOPE, now_unix()).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_named_but_unreadable_key_file_is_an_error_not_unsigned() {
        let missing = Path::new("/nonexistent/yubaba/cluster.key");
        assert!(PeerSigner::from_key_file(Some(missing), "x".into()).is_err());
        assert!(!PeerSigner::from_key_file(None, "x".into()).unwrap().is_signing());
    }
}
