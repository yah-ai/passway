//! Request-path canonicalization for the edge-auth decision (R594-F4
//! adversarial-review FIX 1 + FIX 2).
//!
//! ## The bug this closes
//!
//! [`auth::RouteAuthPolicy`](crate::auth::RouteAuthPolicy) decides whether a
//! path needs a bearer by prefix-matching. If that decision runs on the
//! *raw* request path while the upstream resolves a *different* canonical
//! form, an attacker slips past a `require_auth("/admin")` gate with a path
//! that doesn't literally start with `/admin` but resolves there anyway —
//! case (`/Admin`), duplicate slashes (`//admin`), dot-segments (`/./admin`,
//! `/public/../admin`), or percent-encoded dot-segments
//! (`/public/%2e%2e/admin`). Every one of those is a *default* normalization
//! in common upstream servers/frameworks, so the divergence is the common
//! case, not an exotic one.
//!
//! ## The principle
//!
//! The path the auth decision is made against MUST be the canonical form the
//! upstream will actually resolve, and any residual ambiguity MUST fail
//! CLOSED (reject, or require auth). Over-requiring auth is fail-safe;
//! under-requiring is the vulnerability.
//!
//! [`prepare_auth_path`] is the single entry point. Given the raw path
//! **bytes** (query already stripped by the caller), it either yields the
//! canonical path to make the decision against, or says "reject with 400":
//!
//! 1. **Non-UTF-8 → reject** (FIX 2). Pingora's `uri.path()` returns a lossy
//!    (U+FFFD-substituted) string for a non-UTF-8 path while the *true*
//!    bytes are still forwarded upstream via `raw_path()` — so a decision
//!    made on the lossy string matches a different string than what the
//!    upstream sees. An auth gate serving arbitrary-byte paths is inherently
//!    unsafe; reject.
//! 2. **Encoded separator → reject** (FIX 1). `%2f`/`%2F` (encoded `/`) or
//!    `%5c`/`%5C` (encoded `\`) inside a segment is genuinely ambiguous —
//!    whether the upstream treats it as a separator or literal text can't be
//!    known here — so it can't be safely normalized. Reject.
//! 3. **Percent-decode once**, then reject a *surviving* encoded structural
//!    character (`%2f`/`%5c` separator or `%2e` dot) in the decoded form.
//!    After one RFC-conformant decode, a residual `%2f`/`%2e`/`%5c` can only
//!    have come from double-encoding (`%252f`/`%252e`/`%255c`), whose sole
//!    purpose is to reach a non-conformant double-decoding upstream as a
//!    separator or dot-segment. Separator and dot are checked **symmetrically**
//!    — otherwise a double-encoded dot fails open on a double-decoder while a
//!    double-encoded slash fails closed.
//! 4. **Normalize** per RFC 3986 §5.2.4 / §6.2.2: collapse duplicate
//!    slashes, resolve `.`/`..` segments (clamped at root). Case is preserved
//!    in the canonical output; the case-insensitive comparison lives in
//!    [`RouteAuthPolicy::auth_required_for`](crate::auth::RouteAuthPolicy::auth_required_for).
//! 5. **Literal backslash or traversal residue → reject.** A backslash is
//!    treated as a separator by some servers; any `.`/`..` still present
//!    after normalization is unresolved ambiguity. Both fail closed.
//!
//! The caller keeps forwarding the *raw* path upstream (simpler and
//! lower-risk than rewriting it): because every case where raw and canonical
//! could diverge into a protected prefix is rejected above, and the
//! remaining normalizations (case via the matcher, slashes, dot-segments)
//! match what a conformant upstream resolves, forwarding raw is safe.
//!
//! ## Encoding-depth scope
//!
//! This canonicalizer defends against **single- and double-encoding** of
//! structural characters against a conformant-or-double-decoding upstream:
//! one decode pass plus the post-decode residual-encoding reject covers the
//! `%2e`/`%2f`/`%5c` (single) and `%252e`/`%252f`/`%255c` (double) forms.
//! **Triple-and-higher** encoding (`%25252e`) survives even this and would
//! only bite an upstream that decodes three-plus times — not a realistic
//! threat, so it is intentionally out of v0 scope. A deployment that fronts a
//! known multi-decoding upstream should additionally reject any residual
//! `%`+hex after the decode pass (a deployment config knob, not built here).

use percent_encoding::percent_decode_str;

/// Outcome of preparing a raw request path for the auth decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPathOutcome {
    /// Safe to proceed — make the prefix decision against this canonical path.
    Canonical(String),
    /// The path is ambiguous or non-UTF-8; the caller must reject the request
    /// with 400 rather than proxy it.
    Reject,
}

/// Prepare a raw request path (query already stripped) for the auth
/// decision. See the module docs for the full contract; the short version is
/// "canonicalize, or fail closed."
pub fn prepare_auth_path(raw_path: &[u8]) -> AuthPathOutcome {
    // FIX 2: an auth gate must not decide on a lossy view of bytes it
    // forwards verbatim.
    let s = match std::str::from_utf8(raw_path) {
        Ok(s) => s,
        Err(_) => return AuthPathOutcome::Reject,
    };
    match canonical_path_for_auth(s) {
        Some(c) => AuthPathOutcome::Canonical(c),
        None => AuthPathOutcome::Reject,
    }
}

/// Canonicalize a UTF-8 request path for the auth decision, or `None` to
/// signal "reject (400)". Exposed (and independently tested) so the exact
/// normalization rules are auditable without a live proxy.
pub fn canonical_path_for_auth(raw_path: &str) -> Option<String> {
    // (2) Reject an encoded separator in the raw form — ambiguous segment
    // boundary that can't be safely normalized.
    if contains_encoded_separator(raw_path) {
        return None;
    }

    // (3a) Percent-decode a single pass. Bytes that don't form valid UTF-8
    // once decoded (e.g. `%ff`) are rejected — same reasoning as FIX 2.
    let decoded = percent_decode_str(raw_path).decode_utf8().ok()?;

    // (2, defense in depth) After one RFC-conformant decode, a SURVIVING
    // encoded structural character means the input was multiply-encoded
    // around it — a `%252f`/`%252e`/`%255c` that decoded once to a literal
    // `%2f`/`%2e`/`%5c`. Such an input has no legitimate purpose: it exists
    // only to survive to a non-conformant double-decoding upstream that would
    // then read it as a separator (`/`, `\`) or a dot-segment (`.`/`..`). So
    // reject an encoded separator OR an encoded dot in the decoded form — the
    // two must be symmetric, or a double-encoded dot fails OPEN on a
    // double-decoder while a double-encoded slash fails closed. A literal
    // backslash (some servers treat `\` as `/`) is rejected the same way.
    if contains_encoded_separator(&decoded)
        || contains_encoded_dot(&decoded)
        || decoded.contains('\\')
    {
        return None;
    }

    // (3b) Collapse duplicate slashes + resolve dot-segments.
    let normalized = normalize_path(&decoded);

    // (4) Any dot-segment surviving normalization is unresolved ambiguity.
    if has_traversal_residue(&normalized) {
        return None;
    }

    Some(normalized)
}

/// `true` if `s` contains `%2f`/`%2F` (encoded `/`) or `%5c`/`%5C` (encoded
/// `\`), matched case-insensitively on the hex digits.
fn contains_encoded_separator(s: &str) -> bool {
    s.as_bytes().windows(3).any(|w| {
        w[0] == b'%' && {
            let hi = w[1].to_ascii_lowercase();
            let lo = w[2].to_ascii_lowercase();
            (hi == b'2' && lo == b'f') || (hi == b'5' && lo == b'c')
        }
    })
}

/// `true` if `s` contains `%2e`/`%2E` (encoded `.`), matched
/// case-insensitively on the hex digit. Applied only to the once-decoded
/// form: a `%2e` in the raw path is a legitimate single-encoded dot that
/// decodes to `.` and normalizes normally; a `%2e` still present *after* one
/// decode means the raw was `%252e` (double-encoded), which only serves to
/// survive to a double-decoding upstream as a dot-segment. See
/// [`canonical_path_for_auth`]'s post-decode check.
fn contains_encoded_dot(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'2' && w[2].to_ascii_lowercase() == b'e')
}

/// RFC 3986 §5.2.4-style path normalization: split on `/`, drop empty
/// segments (collapsing duplicate slashes), drop `.`, and pop the previous
/// segment on `..` (clamped at root so `..` above root can never escape).
/// Case is preserved. A leading `/` (absolute path) is preserved.
fn normalize_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = String::new();
    if absolute {
        result.push('/');
    }
    result.push_str(&out.join("/"));
    result
}

/// `true` if any `.`/`..` segment survives — with [`normalize_path`] this is
/// always `false`, so it's a belt-and-suspenders guard against a
/// normalization bug, and the explicit "reject residue" the review asked for.
fn has_traversal_residue(path: &str) -> bool {
    path.split('/').any(|seg| seg == "." || seg == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(p: &str) -> Option<String> {
        canonical_path_for_auth(p)
    }

    // ── Normalization: paths that must canonicalize (and, for the vectors
    //    the review named, land back on `/admin...` so a case-insensitive
    //    prefix match still catches them) ──────────────────────────────────

    #[test]
    fn plain_path_is_unchanged() {
        assert_eq!(canon("/admin/secret").as_deref(), Some("/admin/secret"));
        assert_eq!(canon("/public/data").as_deref(), Some("/public/data"));
    }

    #[test]
    fn case_is_preserved_in_output() {
        // Canonicalization keeps case; the case-INSENSITIVE compare is the
        // matcher's job. What matters is the segments are otherwise intact.
        assert_eq!(canon("/Admin/secret").as_deref(), Some("/Admin/secret"));
    }

    #[test]
    fn duplicate_slashes_collapse() {
        assert_eq!(canon("//admin/secret").as_deref(), Some("/admin/secret"));
        assert_eq!(canon("/admin//secret").as_deref(), Some("/admin/secret"));
    }

    #[test]
    fn single_dot_segments_drop() {
        assert_eq!(canon("/./admin").as_deref(), Some("/admin"));
        assert_eq!(canon("/admin/./secret").as_deref(), Some("/admin/secret"));
    }

    #[test]
    fn double_dot_segments_resolve() {
        assert_eq!(
            canon("/public/../admin/secret").as_deref(),
            Some("/admin/secret")
        );
    }

    #[test]
    fn encoded_dot_segments_resolve_after_decode() {
        // %2e = '.', so %2e%2e = '..' — the review's
        // /public/%2e%2e/admin/secret vector must resolve to /admin/secret.
        assert_eq!(
            canon("/public/%2e%2e/admin/secret").as_deref(),
            Some("/admin/secret")
        );
    }

    #[test]
    fn double_dot_above_root_clamps_not_escapes() {
        assert_eq!(canon("/..").as_deref(), Some("/"));
        assert_eq!(canon("/public/../../admin").as_deref(), Some("/admin"));
    }

    #[test]
    fn trailing_slash_normalizes() {
        assert_eq!(canon("/admin/").as_deref(), Some("/admin"));
    }

    // ── Reject (fail-closed) cases ───────────────────────────────────────

    #[test]
    fn encoded_slash_is_rejected() {
        assert_eq!(canon("/admin%2fsecret"), None);
        assert_eq!(canon("/admin%2Fsecret"), None);
        assert_eq!(canon("/public/foo%2fbar"), None);
    }

    #[test]
    fn encoded_backslash_is_rejected() {
        assert_eq!(canon("/admin%5csecret"), None);
        assert_eq!(canon("/admin%5Csecret"), None);
    }

    #[test]
    fn double_encoded_slash_is_rejected() {
        // %252f decodes once to %2f, which the decoded-form re-scan catches.
        assert_eq!(canon("/foo%252fadmin"), None);
    }

    #[test]
    fn double_encoded_dot_is_rejected() {
        // %252e decodes once to a literal %2e — inert to normalize_path, so it
        // would survive as an anonymous-looking segment and let a
        // double-decoding upstream resolve /public/%252e%252e/admin to /admin.
        // Must fail closed, symmetric with the double-encoded-slash case.
        assert_eq!(canon("/public/%252e%252e/admin"), None);
        assert_eq!(canon("/foo%252eadmin"), None);
        assert_eq!(canon("/foo%252Eadmin"), None); // case-insensitive hex
    }

    #[test]
    fn single_encoded_dot_is_not_rejected_but_normalizes() {
        // A single %2e is a legitimate encoded '.', decodes to '.', and
        // normalizes away — it must NOT be rejected (that would be
        // over-strict), only double-encoding is the attack.
        assert_eq!(canon("/public/%2e%2e/admin").as_deref(), Some("/admin"));
        assert_eq!(canon("/%2e/admin").as_deref(), Some("/admin"));
    }

    #[test]
    fn literal_backslash_is_rejected() {
        assert_eq!(canon("/admin\\secret"), None);
    }

    #[test]
    fn invalid_percent_encoding_producing_non_utf8_is_rejected() {
        assert_eq!(canon("/%ff"), None);
        assert_eq!(canon("/admin/%ff"), None);
    }

    // ── prepare_auth_path (byte boundary — includes FIX 2) ───────────────

    #[test]
    fn prepare_rejects_non_utf8_bytes() {
        // Raw path with a lone 0xFF byte — the FIX 2 case that never reaches
        // canonical_path_for_auth because it isn't a &str.
        assert_eq!(prepare_auth_path(b"/\xff/admin"), AuthPathOutcome::Reject);
        assert_eq!(prepare_auth_path(b"/admin/\xff"), AuthPathOutcome::Reject);
    }

    #[test]
    fn prepare_canonicalizes_valid_paths() {
        assert_eq!(
            prepare_auth_path(b"/public/../admin/secret"),
            AuthPathOutcome::Canonical("/admin/secret".to_string())
        );
        assert_eq!(
            prepare_auth_path(b"//admin"),
            AuthPathOutcome::Canonical("/admin".to_string())
        );
    }

    #[test]
    fn prepare_rejects_encoded_separator_bytes() {
        assert_eq!(prepare_auth_path(b"/admin%2fsecret"), AuthPathOutcome::Reject);
    }
}
