//! Request-smuggling hardening for the upstream-forwarding path.
//!
//! From the R594-S1 spike's smuggling-hardening checklist
//! (`.yah/docs/working/W267-sovereign-public-ingress.md` §Spike verdict):
//!
//! > In `upstream_request_filter`, strip hop-by-hop headers and reject
//! > conflicting `Content-Length`/`Transfer-Encoding` before forwarding
//! > upstream — defense in depth on top of pingora's own HTTP/1 parser
//! > guarantees.
//!
//! This is defense in depth, not the primary defense: pingora ≥0.8.1
//! already fixed CVE-2025-4366 (RUSTSEC-2025-0037) — a response-cache-hit
//! path that skipped draining the downstream body, letting an unread body
//! be reinterpreted as the start of the next pipelined request. `pingora-cache`
//! is unavoidably *in the dependency graph* (it's a mandatory dependency of
//! `pingora-proxy` itself — `ProxyHttp`'s own trait signature carries cache
//! types), but this crate never *behaviorally* enables it: `proxy::PassProxy`
//! never overrides `request_cache_filter` or `cache_key_callback`, so
//! `session.cache` is never populated and a cache hit can never occur —
//! that vulnerable code path is reachable-in-theory-only (see `deny.toml`'s
//! note on this). What lives in this module guards a *different* layer:
//! proxy-*application*-logic smuggling, where a hand-rolled (or
//! insufficiently careful) proxy forwards a request whose framing is
//! ambiguous or carries connection-scoped headers the upstream should never
//! see.
//!
//! Both checks are pure functions over [`http::HeaderMap`] — no pingora
//! `Session`/`RequestHeader` involved — so they're unit-testable without a
//! live proxy. `pingora_http::RequestHeader` (what `upstream_request_filter`
//! actually hands us) `Deref`s/`DerefMut`s to `http::request::Parts`, whose
//! `headers` field is exactly this type.

use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;

/// RFC 7230 §6.1 hop-by-hop headers, plus the legacy `Keep-Alive` header
/// (RFC 2616 §14.10 wording; still sent by real clients/proxies even though
/// RFC 7230 folded it under `Connection`). These are connection-scoped
/// between a client and *this* proxy — forwarding them to the upstream is
/// meaningless at best and a framing hazard at worst (`Upgrade` in
/// particular must never leak to an upstream that never agreed to it).
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Header names a client may **never** cause to be stripped by nominating
/// them in a `Connection` value (R594-F4 adversarial-review FIX 3).
///
/// RFC 7230 §6.1 lets a request nominate extra hop-by-hop headers via
/// `Connection: <name>`, and [`strip_hop_by_hop`] honors that — but a client
/// must not be able to point that mechanism at framing/routing headers. A
/// client sending `Connection: Content-Length` would otherwise get its
/// `Content-Length` stripped *after* [`has_conflicting_length_headers`]
/// already cleared the request, silently changing the message framing the
/// proxy forwards. (The adversarial trace confirmed pingora keeps the
/// *outgoing* framing self-consistent, so this is silent body loss rather
/// than smuggling — but a client nominating framing headers for removal is a
/// footgun regardless.) `transfer-encoding` and `te` are in [`HOP_BY_HOP`]
/// and thus stripped by the fixed list either way; listing them here just
/// keeps the "client can't nominate these" set explicit and complete.
const NEVER_NOMINATE_STRIP: &[&str] = &["content-length", "transfer-encoding", "host", "te"];

/// Compute the (lowercased) set of header names to strip from a request
/// before forwarding it upstream.
///
/// Two sources: the fixed [`HOP_BY_HOP`] list, plus — per RFC 7230 §6.1 —
/// any additional header name the request itself *nominates* via a
/// comma-separated `Connection` header value (e.g. `Connection: X-Foo` means
/// "also strip `X-Foo`, it was hop-by-hop for this specific request"),
/// except the framing/routing headers in [`NEVER_NOMINATE_STRIP`] which a
/// client may not point that mechanism at (FIX 3).
///
/// This computes names only (a read-only pass) so the *removal* can be done
/// through whichever header API keeps the target's invariants — critically,
/// pingora's `RequestHeader::remove_header`, which maintains its
/// case-preserving header map alongside the value map. Removing directly on
/// the underlying [`HeaderMap`] would desync those two and trip pingora's
/// HTTP/1 serializer.
pub fn headers_to_strip(headers: &HeaderMap) -> Vec<String> {
    let mut names: Vec<String> = HOP_BY_HOP.iter().map(|s| s.to_string()).collect();
    for v in headers.get_all(CONNECTION).iter() {
        if let Ok(s) = v.to_str() {
            for tok in s.split(',') {
                let tok = tok.trim().to_ascii_lowercase();
                if tok.is_empty() {
                    continue;
                }
                // FIX 3: a client cannot nominate a framing/routing header
                // for stripping (it's stripped only if it's an actual
                // hop-by-hop header on the fixed list above).
                if NEVER_NOMINATE_STRIP.contains(&tok.as_str()) {
                    continue;
                }
                if !names.contains(&tok) {
                    names.push(tok);
                }
            }
        }
    }
    names
}

/// Strip hop-by-hop headers from a plain [`HeaderMap`] in place.
///
/// This is the direct-on-`HeaderMap` form, used for unit testing the strip
/// semantics. The proxy's forwarding path does NOT call this — it drives
/// [`headers_to_strip`] + pingora's `RequestHeader::remove_header` so the
/// case-preserving map stays in sync (see [`headers_to_strip`]).
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in headers_to_strip(headers) {
        headers.remove(name.as_str());
    }
}

/// `true` when both `Content-Length` and `Transfer-Encoding` are present.
///
/// This is the canonical HTTP request-smuggling ambiguity (RFC 7230
/// §3.3.3 step 3: a message with both MUST be treated as an error, never
/// "resolved" by preferring one framing over the other — a proxy and an
/// upstream disagreeing on which one wins is exactly how a smuggled
/// second request gets hidden inside the first). Presence-only check
/// (not value inspection) — even a syntactically identical duplicate is
/// rejected, since the ambiguity is structural, not a parsing detail.
pub fn has_conflicting_length_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(CONTENT_LENGTH) && headers.contains_key(TRANSFER_ENCODING)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderName;
    use http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::try_from(*k).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn strips_fixed_hop_by_hop_list() {
        let mut h = headers(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic xyz"),
            ("te", "trailers"),
            ("trailer", "X-Checksum"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("host", "example.com"),
            ("x-request-id", "abc123"),
        ]);
        strip_hop_by_hop(&mut h);
        for name in HOP_BY_HOP {
            assert!(!h.contains_key(*name), "expected {name} to be stripped");
        }
        assert_eq!(h.get("host").unwrap(), "example.com");
        assert_eq!(h.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn strips_headers_nominated_by_connection_value() {
        let mut h = headers(&[
            ("connection", "X-Secret-Internal, X-Other"),
            ("x-secret-internal", "leak-me-not"),
            ("x-other", "also-strip"),
            ("x-keep", "kept"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("x-secret-internal"));
        assert!(!h.contains_key("x-other"));
        assert_eq!(h.get("x-keep").unwrap(), "kept");
    }

    #[test]
    fn connection_cannot_nominate_content_length_for_stripping() {
        // FIX 3: a client sending `Connection: Content-Length` must NOT get
        // its Content-Length stripped — that would silently change framing
        // after the conflict check already passed.
        let mut h = headers(&[
            ("connection", "Content-Length"),
            ("content-length", "42"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("connection"), "connection itself is stripped");
        assert_eq!(
            h.get("content-length").unwrap(),
            "42",
            "content-length must survive client nomination"
        );
    }

    #[test]
    fn connection_cannot_nominate_host_for_stripping() {
        let mut h = headers(&[("connection", "Host"), ("host", "example.com")]);
        strip_hop_by_hop(&mut h);
        assert_eq!(h.get("host").unwrap(), "example.com");
    }

    #[test]
    fn transfer_encoding_still_stripped_despite_nomination_exclusion() {
        // te/transfer-encoding are on the fixed HOP_BY_HOP list, so excluding
        // them from the nominate set doesn't stop the fixed-list strip.
        let mut h = headers(&[
            ("connection", "Transfer-Encoding, TE"),
            ("transfer-encoding", "chunked"),
            ("te", "trailers"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("te"));
    }

    #[test]
    fn leaves_ordinary_headers_untouched() {
        let mut h = headers(&[("content-type", "application/json"), ("accept", "*/*")]);
        strip_hop_by_hop(&mut h);
        assert_eq!(h.get("content-type").unwrap(), "application/json");
        assert_eq!(h.get("accept").unwrap(), "*/*");
    }

    #[test]
    fn detects_content_length_and_transfer_encoding_conflict() {
        let h = headers(&[("content-length", "10"), ("transfer-encoding", "chunked")]);
        assert!(has_conflicting_length_headers(&h));
    }

    #[test]
    fn content_length_alone_is_not_a_conflict() {
        let h = headers(&[("content-length", "10")]);
        assert!(!has_conflicting_length_headers(&h));
    }

    #[test]
    fn transfer_encoding_alone_is_not_a_conflict() {
        let h = headers(&[("transfer-encoding", "chunked")]);
        assert!(!has_conflicting_length_headers(&h));
    }

    #[test]
    fn neither_header_is_not_a_conflict() {
        let h = headers(&[("host", "example.com")]);
        assert!(!has_conflicting_length_headers(&h));
    }
}
