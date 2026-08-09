//! Request-authority extraction for host-based upstream selection
//! (R594-F10).
//!
//! One passway node fronts several services, so *which* service a request is
//! for has to be answered before an upstream set can be picked. That answer
//! is the request's **authority** — `Host:` on HTTP/1.1, `:authority` on
//! HTTP/2 (which pingora surfaces on the request URI) — and nothing else.
//! Host is **addressing**; the path is **rendering** and belongs to
//! mesofact's manifest, never to this crate (W267 §"Two front doors, one
//! render contract").
//!
//! ## Why not SNI, given the ticket says "host/SNI"
//!
//! It isn't reachable here. This crate pins pingora with the `rustls`
//! backend only (see `Cargo.toml` / `deny.toml`), and pingora 0.8.1's rustls
//! path never records the negotiated server name: `SslDigest::from_stream`
//! (`pingora-core-0.8.1/src/protocols/tls/rustls/stream.rs:364`) reads only
//! cipher, protocol version and peer certificate, and
//! `handshake_with_callback` in that same backend logs *"Callbacks are not
//! supported with feature rustls"* and drops the handshake callback that the
//! boringssl/openssl backend uses to stash SNI in the digest extension. So a
//! `Session` in a rustls build has no SNI to read, and the SNI-vs-Host
//! cross-check (the domain-fronting defense) cannot be implemented at this
//! pingora version without changing TLS backends — which the R594-S1 spike
//! verdict forbids. Routing is on the HTTP authority alone; the checks below
//! are what stands in for it.
//!
//! ## Fail closed on an ambiguous authority
//!
//! Same posture as [`crate::hardening`]: a request that names *two different*
//! authorities is rejected, never resolved by preferring one. Two disagreeing
//! authorities on a multi-tenant front door is a request-routing ambiguity of
//! exactly the smuggling family — the proxy picks one to route on, the
//! upstream reads the other. RFC 9113 §8.3.1 requires an intermediary to
//! treat an HTTP/2 `Host` that disagrees with `:authority` as malformed, and
//! RFC 7230 §5.4 requires a 400 for a missing-or-duplicated `Host` on
//! HTTP/1.1; [`HostOutcome::Ambiguous`] is how both surface here.

use http::header::HOST;
use http::uri::{Authority, Uri};
use http::HeaderMap;

/// What the request says its authority is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOutcome {
    /// Exactly one authority, normalized: lowercase ASCII, port removed,
    /// one optional trailing root dot removed.
    Host(String),
    /// No authority at all — an HTTP/1.0 request with no `Host` header.
    /// Not itself an error: a single-tenant deployment with a catch-all
    /// upstream set can still serve it (see [`crate::routing::HostRouter`]).
    Missing,
    /// Two disagreeing authorities, a duplicated `Host`, or one that isn't a
    /// usable hostname. Fail closed — the caller answers 400.
    Ambiguous,
}

/// Normalize one raw authority string to a routing key.
///
/// `None` means "not a usable hostname", which the caller escalates to
/// [`HostOutcome::Ambiguous`] rather than ignoring — a header we can't parse
/// is a header we can't safely route on.
fn normalize(raw: &str) -> Option<String> {
    let raw = raw.trim();
    // Userinfo (`evil.example.com@good.example.com`) is illegal in a `Host`
    // header and in `:authority` for a non-CONNECT request, and it's a
    // classic authority-confusion vector — the eye reads the left side, the
    // parser takes the right. Reject rather than parse.
    if raw.is_empty() || raw.contains('@') {
        return None;
    }
    // Parsing through `http::uri::Authority` rather than splitting on ':' by
    // hand: it validates the character set and gets IPv6 literals
    // (`[::1]:8443`) right, which a naive rsplit would mangle.
    let authority: Authority = raw.parse().ok()?;
    let host = authority.host();
    // IDN must arrive punycoded; a non-ASCII authority has more than one
    // byte-level spelling and so more than one routing key.
    if host.is_empty() || !host.is_ascii() {
        return None;
    }
    // `example.com.` is the fully-qualified spelling of `example.com` — one
    // root dot is normalized away, more than one is malformed.
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.ends_with('.') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// The authority this request is for, from the URI (`:authority` on HTTP/2,
/// absolute-form target on HTTP/1.1) and the `Host` header combined.
///
/// Both are consulted, and they must agree: taking only one would let the
/// other reach the upstream unexamined.
pub fn request_host(uri: &Uri, headers: &HeaderMap) -> HostOutcome {
    let from_uri = match uri.authority() {
        Some(a) => match normalize(a.as_str()) {
            Some(h) => Some(h),
            None => return HostOutcome::Ambiguous,
        },
        None => None,
    };

    let mut from_header: Option<String> = None;
    for value in headers.get_all(HOST).iter() {
        let Ok(raw) = value.to_str() else {
            return HostOutcome::Ambiguous;
        };
        let Some(host) = normalize(raw) else {
            return HostOutcome::Ambiguous;
        };
        match &from_header {
            // A duplicated `Host` that repeats the same name is harmless in
            // meaning but still malformed (RFC 7230 §5.4); it costs nothing
            // to accept, and rejecting only the disagreeing case keeps this
            // check about routing ambiguity rather than syntax policing.
            Some(seen) if *seen != host => return HostOutcome::Ambiguous,
            Some(_) => {}
            None => from_header = Some(host),
        }
    }

    match (from_uri, from_header) {
        (Some(a), Some(b)) if a != b => HostOutcome::Ambiguous,
        (Some(h), _) | (None, Some(h)) => HostOutcome::Host(h),
        (None, None) => HostOutcome::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                k.to_string().parse::<http::HeaderName>().unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn origin_form() -> Uri {
        "/some/path".parse().unwrap()
    }

    fn host_of(uri: &Uri, pairs: &[(&str, &str)]) -> HostOutcome {
        request_host(uri, &headers(pairs))
    }

    #[test]
    fn takes_the_host_header_on_an_origin_form_request() {
        assert_eq!(
            host_of(&origin_form(), &[("host", "marketing.example.com")]),
            HostOutcome::Host("marketing.example.com".into())
        );
    }

    #[test]
    fn lowercases_and_strips_the_port() {
        assert_eq!(
            host_of(&origin_form(), &[("host", "Marketing.Example.COM:8443")]),
            HostOutcome::Host("marketing.example.com".into())
        );
    }

    #[test]
    fn strips_one_trailing_root_dot() {
        assert_eq!(
            host_of(&origin_form(), &[("host", "marketing.example.com.")]),
            HostOutcome::Host("marketing.example.com".into())
        );
        assert_eq!(
            host_of(&origin_form(), &[("host", "marketing.example.com..")]),
            HostOutcome::Ambiguous
        );
    }

    #[test]
    fn keeps_ipv6_literals_intact() {
        assert_eq!(
            host_of(&origin_form(), &[("host", "[::1]:8443")]),
            HostOutcome::Host("[::1]".into())
        );
    }

    #[test]
    fn missing_host_header_is_missing_not_ambiguous() {
        assert_eq!(host_of(&origin_form(), &[]), HostOutcome::Missing);
    }

    #[test]
    fn two_disagreeing_host_headers_are_ambiguous() {
        assert_eq!(
            host_of(
                &origin_form(),
                &[("host", "a.example.com"), ("host", "b.example.com")]
            ),
            HostOutcome::Ambiguous
        );
    }

    #[test]
    fn a_repeated_identical_host_header_still_routes() {
        assert_eq!(
            host_of(
                &origin_form(),
                &[("host", "a.example.com"), ("host", "A.example.com:443")]
            ),
            HostOutcome::Host("a.example.com".into())
        );
    }

    #[test]
    fn uri_authority_disagreeing_with_host_header_is_ambiguous() {
        // HTTP/1.1 absolute-form target, or HTTP/2 `:authority`, naming a
        // different service than the `Host` header does.
        let uri: Uri = "http://a.example.com/path".parse().unwrap();
        assert_eq!(
            request_host(&uri, &headers(&[("host", "b.example.com")])),
            HostOutcome::Ambiguous
        );
    }

    #[test]
    fn uri_authority_agreeing_with_host_header_routes() {
        let uri: Uri = "http://a.example.com:443/path".parse().unwrap();
        assert_eq!(
            request_host(&uri, &headers(&[("host", "A.example.com")])),
            HostOutcome::Host("a.example.com".into())
        );
    }

    #[test]
    fn uri_authority_alone_routes() {
        let uri: Uri = "http://a.example.com/path".parse().unwrap();
        assert_eq!(
            request_host(&uri, &headers(&[])),
            HostOutcome::Host("a.example.com".into())
        );
    }

    #[test]
    fn userinfo_in_the_authority_is_rejected() {
        assert_eq!(
            host_of(
                &origin_form(),
                &[("host", "evil.example.com@good.example.com")]
            ),
            HostOutcome::Ambiguous
        );
    }

    #[test]
    fn non_ascii_authority_is_rejected() {
        // Must arrive punycoded; `münchen.example.com` and its escaped forms
        // would otherwise be two keys for one service.
        assert_eq!(
            host_of(&origin_form(), &[("host", "münchen.example.com")]),
            HostOutcome::Ambiguous
        );
    }

    #[test]
    fn empty_host_header_is_rejected() {
        assert_eq!(
            host_of(&origin_form(), &[("host", "")]),
            HostOutcome::Ambiguous
        );
    }

    #[test]
    fn a_host_header_that_is_not_a_hostname_is_rejected() {
        assert_eq!(
            host_of(&origin_form(), &[("host", "a.example.com/../b")]),
            HostOutcome::Ambiguous
        );
    }
}
