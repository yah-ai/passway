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

/// Per-route auth requirement, optionally scoped to one fronted hostname.
///
/// Anonymous by default (see module docs) — a route must be explicitly
/// listed to require a bearer. Longest-prefix match wins, so a broad
/// `require_auth("/")` can still be relaxed for a narrower anonymous
/// sub-path via [`RouteAuthPolicy::allow_anonymous`], or vice versa.
///
/// ## The hostname dimension (R556-F6)
///
/// One passway process fronts many hostnames, and before this a policy was
/// process-wide: protecting `/` for one confidential tenant demanded a bearer
/// for every public site on the same door. A rule may now name the hostname
/// it applies to ([`require_auth_on_host`](Self::require_auth_on_host)). For
/// a request whose authority resolved to `h`, the applicable rules are the
/// host-less ones plus those naming `h`; at equal prefix length the
/// host-scoped rule wins, being the more specific statement.
///
/// The host passed in MUST be the same resolved authority the router then
/// selects the upstream by (`crate::host::request_host`) — auth and routing
/// agreeing on "which tenant is this" is what makes a host-scoped rule sound,
/// exactly as they already agree on the canonical path.
///
/// A request with **no** resolvable authority is evaluated against every
/// host's rules and requires a bearer if any of them would: whichever set
/// the router falls back to, it cannot be a protected tenant served
/// anonymously.
#[derive(Clone, Debug, Default)]
pub struct RouteAuthPolicy {
    rules: Vec<AuthRule>,
}

#[derive(Clone, Debug)]
struct AuthRule {
    /// Lowercased hostname this rule is scoped to; `None` = every host.
    host: Option<String>,
    prefix: String,
    required: bool,
}

/// Normalize a hostname for rule matching: ASCII-lowercase, no trailing dot —
/// the same form `crate::host::request_host` hands the router.
fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl RouteAuthPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(mut self, host: Option<&str>, prefix: impl Into<String>, required: bool) -> Self {
        self.rules.push(AuthRule {
            host: host.map(normalize_host),
            prefix: prefix.into(),
            required,
        });
        self
    }

    /// Mark every path under `prefix` as requiring a valid bearer, on every
    /// hostname this process fronts.
    pub fn require_auth(self, prefix: impl Into<String>) -> Self {
        self.push(None, prefix, true)
    }

    /// Mark every path under `prefix` as requiring a valid bearer, on `host`
    /// only.
    pub fn require_auth_on_host(self, host: &str, prefix: impl Into<String>) -> Self {
        self.push(Some(host), prefix, true)
    }

    /// Explicitly mark `prefix` as anonymous — carves an anonymous island
    /// out of a broader `require_auth`-covered parent prefix.
    pub fn allow_anonymous(self, prefix: impl Into<String>) -> Self {
        self.push(None, prefix, false)
    }

    /// Host-scoped [`allow_anonymous`](Self::allow_anonymous).
    pub fn allow_anonymous_on_host(self, host: &str, prefix: impl Into<String>) -> Self {
        self.push(Some(host), prefix, false)
    }

    /// Parse `PASSWAY_AUTH_REQUIRED_PREFIXES`: comma-separated entries, each
    /// either a bare path prefix (`/admin` — every host) or
    /// `<hostname>=<prefix>` (`analytics.yah.dev=/` — that host only). A
    /// hostname may repeat to protect several prefixes.
    ///
    /// Refused rather than guessed: a bare entry not starting with `/`
    /// (typo'd separator), an empty hostname or prefix, and `*=` — the
    /// catch-all *set* is a routing notion, and "every host" already has a
    /// spelling here (the bare form), so `*=` could only be misread.
    pub fn parse_required_prefixes(raw: &str) -> Result<Self, String> {
        const VAR: &str = "PASSWAY_AUTH_REQUIRED_PREFIXES";
        let mut policy = Self::new();
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if entry.starts_with('/') {
                policy = policy.require_auth(entry);
                continue;
            }
            let Some((host, prefix)) = entry.split_once('=') else {
                return Err(format!(
                    "{VAR} entry {entry:?} is neither a path prefix (must start with '/') nor \
                     <hostname>=<prefix>"
                ));
            };
            let (host, prefix) = (host.trim(), prefix.trim());
            if host.is_empty() {
                return Err(format!("{VAR} entry {entry:?} has an empty hostname"));
            }
            if host == "*" {
                return Err(format!(
                    "{VAR} entry {entry:?}: `*=` is not accepted — write the bare prefix \
                     ({prefix:?}) to protect it on every hostname"
                ));
            }
            if !prefix.starts_with('/') {
                return Err(format!(
                    "{VAR} entry {entry:?}: the prefix after '=' must start with '/'"
                ));
            }
            policy = policy.require_auth_on_host(host, prefix);
        }
        Ok(policy)
    }

    /// The winning rule among those applicable to `host` (see the type doc)
    /// that match `path_lower`, if any.
    fn decide(&self, host: Option<&str>, path_lower: &str) -> bool {
        self.rules
            .iter()
            .filter(|r| match (&r.host, host) {
                (None, _) => true,
                (Some(rh), Some(h)) => rh == h,
                (Some(_), None) => false,
            })
            .filter(|r| path_lower.starts_with(&r.prefix.to_ascii_lowercase()))
            .max_by_key(|r| (r.prefix.len(), r.host.is_some()))
            .map(|r| r.required)
            .unwrap_or(false)
    }

    /// Does a request for `path` on authority `host` require a valid bearer?
    /// No matching rule => anonymous (`false`) — the safe default for a proxy
    /// whose whole job (W268) is serving public traffic.
    ///
    /// Matching is **case-insensitive** on both axes (R594-F4
    /// adversarial-review FIX 1): a protected prefix must catch its case
    /// variants (`/Admin` vs `/admin`), because an upstream that case-folds
    /// would otherwise resolve a case-variant into the protected resource.
    /// Over-requiring auth on a case variant is fail-safe; under-requiring is
    /// the bug. Callers should pass the canonical path from
    /// [`crate::path::prepare_auth_path`] so dot-segments/duplicate-slashes
    /// are already resolved before this prefix compare, and `host` from the
    /// same resolution the router uses.
    ///
    /// `host = None` (no resolvable authority) requires a bearer if ANY
    /// hostname's rules would — see the type doc.
    pub fn auth_required_for(&self, host: Option<&str>, path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        match host {
            Some(h) => self.decide(Some(&normalize_host(h)), &path_lower),
            None => {
                self.decide(None, &path_lower)
                    || self
                        .rules
                        .iter()
                        .filter_map(|r| r.host.as_deref())
                        .any(|h| self.decide(Some(h), &path_lower))
            }
        }
    }

    /// `true` if the policy protects at least one prefix on any host (any
    /// `require_auth*` rule). When `false`, the proxy is effectively
    /// anonymous and the caller can skip path canonicalization entirely;
    /// when `true`, the caller MUST canonicalize + fail-closed on ambiguous
    /// paths before consulting [`auth_required_for`](Self::auth_required_for)
    /// (R594-F4 FIX 1/2 — normalization matters only when something is
    /// actually protected).
    pub fn has_protected_prefix(&self) -> bool {
        self.rules.iter().any(|r| r.required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn default_policy_is_anonymous_everywhere() {
        let p = RouteAuthPolicy::new();
        assert!(!p.auth_required_for(None, "/"));
        assert!(!p.auth_required_for(None, "/anything/at/all"));
    }

    #[test]
    fn require_auth_gates_the_prefix() {
        let p = RouteAuthPolicy::new().require_auth("/admin");
        assert!(p.auth_required_for(None, "/admin"));
        assert!(p.auth_required_for(None, "/admin/settings"));
        assert!(!p.auth_required_for(None, "/public"));
        assert!(!p.auth_required_for(None, "/"));
    }

    #[test]
    fn longest_prefix_wins_for_carve_outs() {
        let p = RouteAuthPolicy::new()
            .require_auth("/api")
            .allow_anonymous("/api/public");
        assert!(p.auth_required_for(None, "/api/private"));
        assert!(!p.auth_required_for(None, "/api/public"));
        assert!(!p.auth_required_for(None, "/api/public/widgets"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        // FIX 1: a protected prefix must catch its case variants — an
        // upstream that case-folds resolves /Admin to the protected /admin.
        let p = RouteAuthPolicy::new().require_auth("/admin");
        assert!(p.auth_required_for(None, "/Admin"));
        assert!(p.auth_required_for(None, "/ADMIN/secret"));
        assert!(p.auth_required_for(None, "/aDmIn/secret"));

        // And a protected prefix declared in mixed case still catches lower.
        let p2 = RouteAuthPolicy::new().require_auth("/API");
        assert!(p2.auth_required_for(None, "/api/private"));
    }

    #[test]
    fn a_host_scoped_rule_protects_only_its_host() {
        // The R556-F6 shape: one door fronts a public site and a confidential
        // tenant. Protecting the tenant's `/` must not touch the public site.
        let p = RouteAuthPolicy::new().require_auth_on_host("analytics.yah.dev", "/");
        assert!(p.auth_required_for(Some("analytics.yah.dev"), "/"));
        assert!(p.auth_required_for(Some("analytics.yah.dev"), "/x/y"));
        assert!(!p.auth_required_for(Some("yah.dev"), "/"));
        assert!(!p.auth_required_for(Some("www.yah.dev"), "/x"));
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        let p = RouteAuthPolicy::new().require_auth_on_host("Analytics.Yah.Dev.", "/");
        assert!(p.auth_required_for(Some("analytics.yah.dev"), "/"));
        assert!(p.auth_required_for(Some("ANALYTICS.yah.dev."), "/"));
    }

    #[test]
    fn a_host_scoped_rule_beats_a_global_one_at_equal_length() {
        let p = RouteAuthPolicy::new()
            .require_auth("/api")
            .allow_anonymous_on_host("open.example", "/api");
        assert!(p.auth_required_for(Some("other.example"), "/api/x"));
        assert!(!p.auth_required_for(Some("open.example"), "/api/x"));

        let p = RouteAuthPolicy::new()
            .allow_anonymous("/")
            .require_auth_on_host("secret.example", "/");
        assert!(p.auth_required_for(Some("secret.example"), "/"));
        assert!(!p.auth_required_for(Some("public.example"), "/"));
    }

    #[test]
    fn a_request_with_no_authority_is_held_to_every_hosts_rules() {
        // Whatever set the router falls back to for a hostless request, a
        // protected tenant's path must not be reachable anonymously that way.
        let p = RouteAuthPolicy::new().require_auth_on_host("analytics.yah.dev", "/");
        assert!(p.auth_required_for(None, "/"));
        assert!(RouteAuthPolicy::new()
            .require_auth("/admin")
            .auth_required_for(None, "/admin"));
        assert!(!RouteAuthPolicy::new().auth_required_for(None, "/"));
    }

    #[test]
    fn required_prefixes_parse_both_forms() {
        let p = RouteAuthPolicy::parse_required_prefixes(
            "/admin, analytics.yah.dev=/, analytics.yah.dev=/api",
        )
        .unwrap();
        assert!(p.auth_required_for(Some("yah.dev"), "/admin/x"));
        assert!(!p.auth_required_for(Some("yah.dev"), "/"));
        assert!(p.auth_required_for(Some("analytics.yah.dev"), "/"));
        assert!(p.has_protected_prefix());

        assert!(!RouteAuthPolicy::parse_required_prefixes("")
            .unwrap()
            .has_protected_prefix());
    }

    #[test]
    fn required_prefixes_refuse_what_they_cannot_read() {
        for bad in ["admin", "=/", "*=/", "analytics.yah.dev=admin", "analytics.yah.dev="] {
            let err = RouteAuthPolicy::parse_required_prefixes(bad)
                .expect_err(&format!("{bad:?} must be refused"));
            assert!(err.contains("PASSWAY_AUTH_REQUIRED_PREFIXES"), "{err}");
        }
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
