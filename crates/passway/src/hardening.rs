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

use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING, UPGRADE};
use http::HeaderMap;

/// RFC 7230 §6.1 hop-by-hop headers, plus the legacy `Keep-Alive` header
/// (RFC 2616 §14.10 wording; still sent by real clients/proxies even though
/// RFC 7230 folded it under `Connection`). These are connection-scoped
/// between a client and *this* proxy — forwarding them to the upstream is
/// meaningless at best and a framing hazard at worst.
///
/// `connection` and `upgrade` are on this list but are NOT stripped from a
/// well-formed upgrade request — see [`is_upgrade_request`] and R870-B14.
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

/// `true` when `headers` describe a well-formed protocol upgrade — an
/// `Upgrade` header naming the target protocol *and* an `upgrade` token in
/// `Connection`. RFC 7230 §6.7 requires both; either one alone is not an
/// upgrade and gets the ordinary hop-by-hop treatment.
///
/// R870-B14 — WHY THIS EXISTS, and why blanket-stripping `Upgrade` was wrong.
/// RFC 7230 §6.7 says an intermediary that intends to *forward* an upgrade
/// must pass `Connection: upgrade` + `Upgrade:` through; stripping them makes
/// it structurally impossible for any upstream behind passway to ever speak a
/// second protocol, because the upstream never learns an upgrade was asked
/// for. That took the whole fleet's mesh down for three days: R858-T1 moved
/// `cloud.mesh.yah.dev` (headscale) behind a passway door, headscale's
/// TS2021 noise transport IS an HTTP upgrade
/// (`Upgrade: tailscale-control-protocol`), and every control-plane request
/// in the fleet started failing with headscale logging "No Upgrade header in
/// TS2021 request. If headscale is behind a reverse proxy, make sure it is
/// configured to pass WebSockets through." Nodes already holding a netmap
/// coasted on it; us-west-011 rebooted, had to re-register, and could not.
///
/// The original concern — "`Upgrade` must never leak to an upstream that
/// never agreed to it" — is still honoured. An upstream that does not want to
/// upgrade simply does not answer `101`, and the exchange stays ordinary
/// HTTP. What it must not do is never see the offer at all.
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    if !headers.contains_key(UPGRADE) {
        return false;
    }
    headers.get_all(CONNECTION).iter().any(|v| {
        v.to_str()
            .map(|s| s.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("upgrade")))
            .unwrap_or(false)
    })
}

/// Header names that survive on a well-formed upgrade request (they are the
/// upgrade offer itself). Everything else in [`HOP_BY_HOP`] is still stripped.
const UPGRADE_PRESERVED: &[&str] = &["connection", "upgrade"];

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
    // R870-B14: on a well-formed upgrade request the offer itself must reach
    // the upstream, or no upstream behind passway can ever speak a second
    // protocol. See `is_upgrade_request` for the outage this caused.
    let upgrading = is_upgrade_request(headers);
    let mut names: Vec<String> = HOP_BY_HOP
        .iter()
        .filter(|n| !(upgrading && UPGRADE_PRESERVED.contains(*n)))
        .map(|s| s.to_string())
        .collect();
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
                // `Connection: Upgrade` nominates the token "upgrade"; on an
                // upgrade request that nomination must not undo the exemption
                // above.
                if upgrading && UPGRADE_PRESERVED.contains(&tok.as_str()) {
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

    // ---- R870-B14: upgrade offers must reach the upstream ----

    #[test]
    fn well_formed_upgrade_offer_survives_to_upstream() {
        // The headscale TS2021 shape that R858-T1 broke: without both headers
        // reaching the upstream, headscale logs "No Upgrade header in TS2021
        // request" and the whole tailnet loses its control plane.
        let mut h = headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "tailscale-control-protocol"),
            ("keep-alive", "timeout=5"),
            ("x-request-id", "abc123"),
        ]);
        assert!(is_upgrade_request(&h));
        strip_hop_by_hop(&mut h);
        assert_eq!(h.get("connection").unwrap(), "Upgrade");
        assert_eq!(h.get("upgrade").unwrap(), "tailscale-control-protocol");
        // Everything else hop-by-hop still goes.
        assert!(!h.contains_key("keep-alive"));
        assert_eq!(h.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn upgrade_offer_does_not_smuggle_other_hop_by_hop_headers() {
        // The exemption is exactly {connection, upgrade}; an upgrade request
        // must not become a way to push transfer-encoding/te upstream.
        let mut h = headers(&[
            ("connection", "Upgrade, TE, X-Sneaky"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("transfer-encoding", "chunked"),
            ("x-sneaky", "strip-me"),
        ]);
        strip_hop_by_hop(&mut h);
        assert_eq!(h.get("connection").unwrap(), "Upgrade, TE, X-Sneaky");
        assert_eq!(h.get("upgrade").unwrap(), "websocket");
        assert!(!h.contains_key("te"));
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("x-sneaky"), "nominated headers still strip");
    }

    #[test]
    fn upgrade_header_without_connection_token_is_not_an_upgrade() {
        // Half an offer is not an offer (RFC 7230 §6.7 requires both), so it
        // gets the ordinary hop-by-hop treatment and never reaches upstream.
        let mut h = headers(&[("connection", "keep-alive"), ("upgrade", "websocket")]);
        assert!(!is_upgrade_request(&h));
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("upgrade"));
        assert!(!h.contains_key("connection"));
    }

    #[test]
    fn connection_upgrade_token_without_upgrade_header_is_not_an_upgrade() {
        let mut h = headers(&[("connection", "Upgrade")]);
        assert!(!is_upgrade_request(&h));
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("connection"));
    }

    #[test]
    fn upgrade_detection_is_case_insensitive_and_tolerates_token_lists() {
        let h = headers(&[
            ("connection", "keep-alive, UPGRADE"),
            ("upgrade", "h2c"),
        ]);
        assert!(is_upgrade_request(&h));
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
