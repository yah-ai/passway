//! Edge auth: verify a PASETO v4.public bearer via `cheers-verify`
//! (R594-F4 V0 MUST #3), gated **per route** rather than globally.
//!
//! W268's scope note is the reason for "per route, opt-in" rather than "on
//! by default": passway serves *anonymous public* traffic — once end-user
//! devices are enrolled mesh citizens, their traffic dials workloads
//! directly over the machine-identity transport (mshr) and never touches
//! this tier at all. So the safe default for a route here is anonymous;
//! a route must explicitly opt into requiring a bearer, not the reverse.
//!
//! [`CheersAuth`] mirrors `crates/yah/cloud-admin/src/auth.rs`'s
//! `CheersAuth` — the only other in-tree consumer of
//! `cheers_verify::PasetoV4PublicVerifier` outside the cheers workspace
//! itself (the ticket's "wire it like other consumers"): same
//! verifier + kid + iss/aud triple, same `verify_mcp_at` call, same
//! every-failure-mode-collapses-to-401 posture (a prober outside the edge
//! must not be able to tell "bad signature" from "expired" from "wrong
//! audience" — that distinction is only useful to an attacker). Unlike
//! cloud-admin, passway doesn't derive a scoped "viewer" from the claims —
//! its auth question is binary per route ("does this request carry a bearer
//! this deployment trusts"), not a role/ownership lens.
//!
//! ## JWKS note (v0 scope)
//!
//! "JWKS" in the wire sense (a live `.well-known/jwks.json` fetch, cache,
//! and kid-miss background refresh) is **not** implemented here in v0 —
//! [`CheersAuth`] holds a single, operator-configured `(kid, public key)`
//! pair, exactly like cloud-admin does today. `kamaji-bin`'s
//! `auth/jwks.rs` + `auth/verifier.rs` (a different oss workspace) already
//! prove the full fetch/cache/refresh pattern against this same PASETO
//! envelope; if passway ever needs multi-key rotation without a redeploy,
//! that module is the reference shape to port, not something to re-derive.
//! Swapping [`CheersAuth::new`]'s single verifier for a keyring keyed by
//! `kid` is a self-contained follow-up that doesn't touch `proxy.rs`.

use std::sync::Arc;

use cheers_core::McpClaims;
use cheers_verify::PasetoV4PublicVerifier;

/// Cheers verify-only material passway holds to authenticate bearers on
/// auth-required routes. No minter anywhere in this type or its
/// dependency graph (`cheers-verify` is verify-only by construction) — a
/// compromised passway process cannot forge a session, only reject or
/// accept ones minted elsewhere.
#[derive(Clone)]
pub struct CheersAuth {
    pub verifier: Arc<PasetoV4PublicVerifier>,
    pub expected_kid: String,
    pub expected_iss: String,
    pub expected_aud: String,
}

impl std::fmt::Debug for CheersAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheersAuth")
            .field("expected_kid", &self.expected_kid)
            .field("expected_iss", &self.expected_iss)
            .field("expected_aud", &self.expected_aud)
            .finish_non_exhaustive()
    }
}

impl CheersAuth {
    pub fn new(
        verifier: PasetoV4PublicVerifier,
        expected_kid: impl Into<String>,
        expected_iss: impl Into<String>,
        expected_aud: impl Into<String>,
    ) -> Self {
        Self {
            verifier: Arc::new(verifier),
            expected_kid: expected_kid.into(),
            expected_iss: expected_iss.into(),
            expected_aud: expected_aud.into(),
        }
    }

    /// Verify `token` (the raw bearer value, no `Bearer ` prefix) against
    /// wall-clock `now`. Every failure mode — bad signature, expired,
    /// malformed, unknown/wrong kid, wrong issuer, wrong audience —
    /// collapses to `Err(())`: deliberately no detail leaks to the caller
    /// about *why* a bearer was rejected.
    pub fn verify(&self, token: &str, now: i64) -> Result<McpClaims, ()> {
        let claims = self
            .verifier
            .verify_mcp_at(token, now, &self.expected_kid)
            .map_err(|_| ())?;
        if claims.iss != self.expected_iss || claims.aud != self.expected_aud {
            return Err(());
        }
        Ok(claims)
    }
}

/// Pull `Authorization: Bearer <token>` out of a header map. Missing,
/// non-UTF8, and malformed all collapse to `None` for the same
/// probe-blocking reason [`CheersAuth::verify`] collapses its own errors.
pub fn bearer_from_headers(headers: &http::HeaderMap) -> Option<&str> {
    let raw = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

/// Per-route auth requirement.
///
/// Anonymous by default (see module docs) — a route must be explicitly
/// listed to require a bearer. Longest-prefix match wins, so a broad
/// `require_auth("/")` can still be relaxed for a narrower anonymous
/// sub-path via [`RouteAuthPolicy::allow_anonymous`], or vice versa.
#[derive(Clone, Debug, Default)]
pub struct RouteAuthPolicy {
    rules: Vec<(String, bool)>,
}

impl RouteAuthPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark every path under `prefix` as requiring a valid bearer.
    pub fn require_auth(mut self, prefix: impl Into<String>) -> Self {
        self.rules.push((prefix.into(), true));
        self
    }

    /// Explicitly mark `prefix` as anonymous — carves an anonymous island
    /// out of a broader `require_auth`-covered parent prefix.
    pub fn allow_anonymous(mut self, prefix: impl Into<String>) -> Self {
        self.rules.push((prefix.into(), false));
        self
    }

    /// Does `path` require a valid bearer? No matching rule => anonymous
    /// (`false`) — the safe default for a proxy whose whole job (W268) is
    /// serving public traffic.
    ///
    /// Matching is **case-insensitive** (R594-F4 adversarial-review FIX 1):
    /// a protected prefix must catch its case variants (`/Admin` vs
    /// `/admin`), because an upstream that case-folds would otherwise resolve
    /// a case-variant into the protected resource. Over-requiring auth on a
    /// case variant is fail-safe; under-requiring is the bug. Callers should
    /// pass the canonical path from
    /// [`crate::path::prepare_auth_path`] so dot-segments/duplicate-slashes
    /// are already resolved before this prefix compare.
    pub fn auth_required_for(&self, path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        self.rules
            .iter()
            .filter(|(prefix, _)| path_lower.starts_with(&prefix.to_ascii_lowercase()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, required)| *required)
            .unwrap_or(false)
    }

    /// `true` if the policy protects at least one prefix (any
    /// [`require_auth`](Self::require_auth) rule). When `false`, the proxy is
    /// effectively anonymous and the caller can skip path canonicalization
    /// entirely; when `true`, the caller MUST canonicalize + fail-closed on
    /// ambiguous paths before consulting [`auth_required_for`](Self::auth_required_for)
    /// (R594-F4 FIX 1/2 — normalization matters only when something is
    /// actually protected).
    pub fn has_protected_prefix(&self) -> bool {
        self.rules.iter().any(|(_, required)| *required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn default_policy_is_anonymous_everywhere() {
        let p = RouteAuthPolicy::new();
        assert!(!p.auth_required_for("/"));
        assert!(!p.auth_required_for("/anything/at/all"));
    }

    #[test]
    fn require_auth_gates_the_prefix() {
        let p = RouteAuthPolicy::new().require_auth("/admin");
        assert!(p.auth_required_for("/admin"));
        assert!(p.auth_required_for("/admin/settings"));
        assert!(!p.auth_required_for("/public"));
        assert!(!p.auth_required_for("/"));
    }

    #[test]
    fn longest_prefix_wins_for_carve_outs() {
        let p = RouteAuthPolicy::new()
            .require_auth("/api")
            .allow_anonymous("/api/public");
        assert!(p.auth_required_for("/api/private"));
        assert!(!p.auth_required_for("/api/public"));
        assert!(!p.auth_required_for("/api/public/widgets"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        // FIX 1: a protected prefix must catch its case variants — an
        // upstream that case-folds resolves /Admin to the protected /admin.
        let p = RouteAuthPolicy::new().require_auth("/admin");
        assert!(p.auth_required_for("/Admin"));
        assert!(p.auth_required_for("/ADMIN/secret"));
        assert!(p.auth_required_for("/aDmIn/secret"));

        // And a protected prefix declared in mixed case still catches lower.
        let p2 = RouteAuthPolicy::new().require_auth("/API");
        assert!(p2.auth_required_for("/api/private"));
    }

    #[test]
    fn has_protected_prefix_reflects_require_auth_rules() {
        assert!(!RouteAuthPolicy::new().has_protected_prefix());
        assert!(!RouteAuthPolicy::new()
            .allow_anonymous("/public")
            .has_protected_prefix());
        assert!(RouteAuthPolicy::new()
            .require_auth("/admin")
            .has_protected_prefix());
    }

    #[test]
    fn bearer_from_headers_extracts_token() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc.def.ghi"),
        );
        assert_eq!(bearer_from_headers(&h), Some("abc.def.ghi"));
    }

    #[test]
    fn bearer_from_headers_lowercase_scheme() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer abc.def.ghi"),
        );
        assert_eq!(bearer_from_headers(&h), Some("abc.def.ghi"));
    }

    #[test]
    fn bearer_from_headers_missing_is_none() {
        let h = HeaderMap::new();
        assert_eq!(bearer_from_headers(&h), None);
    }

    #[test]
    fn bearer_from_headers_wrong_scheme_is_none() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(bearer_from_headers(&h), None);
    }

    // Cryptographic verify()/reject() coverage (valid token accepted, invalid
    // rejected) lives in `tests/auth_gate.rs`, which mints real PASETO
    // v4.public tokens with `pasetors` — that needs a live keypair and a
    // real `PasetoV4PublicVerifier`, not just header parsing.
}
