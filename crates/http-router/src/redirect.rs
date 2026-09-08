//! Building the `308`, and the strict `Host` validation that keeps it from
//! becoming an open redirect.
//!
//! ## The twin, and why the code is not shared
//!
//! `passway::redirect` (`crates/passway/src/redirect.rs`) answers the same
//! `308` for the SINGLE-tenant case, where one passway owns `:80` itself. The
//! rules here are deliberately identical to that module's — 308 rather than
//! 301, the `Host` header reflected into `Location` and validated strictly,
//! origin-form targets only, CR/LF rejected outright — and the tests below
//! mirror its tests case for case.
//!
//! They are separate code because they are separate *processes with separate
//! dependency graphs*: `passway::redirect` is a pingora `BackgroundService`
//! inside a crate that links pingora, rustls and an ACME client, and this
//! process links tokio and nothing else. Making one depend on the other would
//! either drag pingora onto the plaintext fan-in tier or put a third crate
//! between `passway` and crates.io. If you change a rule in one, change it in
//! the other — that is the cost this note exists to make visible.
//!
//! ## Why 308 and not 301
//!
//! Both are permanent and cacheable. 301 lets a client rewrite the method, so
//! a `POST http://…` silently becomes `GET https://…` and the body is dropped
//! — the request succeeds having done nothing. 308 preserves method and body.

/// Build the absolute HTTPS URL a request should be redirected to, or `None`
/// when it cannot be redirected safely.
///
/// `target` is the request target as [`crate::head::parse_head`] read it, and
/// `host` the `Host` header verbatim (port included — a redirect that dropped
/// a `:8080` would send the client somewhere it never asked for).
pub fn redirect_target(target: &str, host: &str) -> Option<String> {
    // Header injection: a CR or LF anywhere in the target would let a caller
    // append headers — or a whole second response — to what we write back.
    // Rejected rather than stripped; a request containing one is not one whose
    // intent we want to have guessed at.
    if target.contains('\r') || target.contains('\n') {
        return None;
    }
    // Only origin-form targets are redirectable. An absolute-form target
    // (`GET http://elsewhere/ HTTP/1.1`, legal for proxies) would otherwise let
    // the request line, not the `Host` header, choose the destination — and
    // `OPTIONS *` has no path to redirect at all.
    if !target.starts_with('/') {
        return None;
    }
    let host = validated_host(host)?;
    Some(format!("https://{host}{target}"))
}

/// Accept a `Host` header only if it is a bare hostname (or IP literal) with
/// an optional numeric port. Anything else — userinfo, a path, a scheme, a
/// space, CR/LF — is rejected rather than sanitized.
pub fn validated_host(raw: &str) -> Option<&str> {
    let host = raw.trim();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // Split off an optional port, tolerating a bracketed IPv6 literal.
    let (name, port) = match host.rfind(']') {
        Some(close) => {
            if !host.starts_with('[') {
                return None;
            }
            let (name, rest) = host.split_at(close + 1);
            (name, rest.strip_prefix(':'))
        }
        None => match host.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        },
    };
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    let inner = name.strip_prefix('[').and_then(|n| n.strip_suffix(']'));
    let allowed = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_');
    let ok = match inner {
        // IPv6 literal: hex, colons and a v4-mapped tail.
        Some(v6) => {
            !v6.is_empty()
                && v6
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        }
        None => !name.is_empty() && name.bytes().all(allowed),
    };
    ok.then_some(host)
}

/// The routing key for a `Host` header: the name without its port, lowercased.
///
/// `None` for anything [`validated_host`] refuses, so a name that cannot be
/// safely echoed also cannot be routed — one gate, not two that could drift.
pub fn route_key(raw: &str) -> Option<String> {
    let host = validated_host(raw)?;
    let name = match host.rfind(']') {
        // `[::1]:80` → `[::1]`, kept bracketed so the table's key and the
        // header agree; an IPv6 literal has no route here in practice.
        Some(close) => &host[..close + 1],
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    Some(name.to_ascii_lowercase())
}

/// The `308` response for an already-built `location`.
pub fn moved_permanently(location: &str) -> String {
    format!(
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: {location}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// `308` to where `target` and `host` say, or the `400` that a request we
/// will not build a redirect from gets instead.
pub fn redirect_response(target: &str, host: &str) -> String {
    match redirect_target(target, host) {
        Some(location) => moved_permanently(&location),
        None => bad_request_response(),
    }
}

/// What a request this tier will not act on gets. `Connection: close` on
/// every one: the router routes a connection by its FIRST request, so it must
/// never invite a second on the same socket.
pub fn text_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A request that is HTTP but not one we can build a redirect from.
pub fn bad_request_response() -> String {
    text_response(
        "400 Bad Request",
        "bad request: this port only redirects to https",
    )
}

/// A `Host` with no route. Deliberately not a redirect — `Location` is built
/// from the client's own header, so redirecting an unknown name would make
/// this an open redirector for anything that resolves here.
pub fn unrouted_response() -> String {
    text_response("404 Not Found", "no route for this host")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_scheme_less_install_one_liner_is_what_this_fixes() {
        assert_eq!(
            redirect_target("/install.sh", "example.com").as_deref(),
            Some("https://example.com/install.sh"),
        );
    }

    #[test]
    fn path_and_query_survive_the_redirect() {
        assert_eq!(
            redirect_target("/a/b?x=1&y=2", "example.com").as_deref(),
            Some("https://example.com/a/b?x=1&y=2"),
        );
    }

    #[test]
    fn a_port_in_the_host_header_is_preserved_not_dropped() {
        assert_eq!(
            redirect_target("/", "example.com:8443").as_deref(),
            Some("https://example.com:8443/"),
        );
    }

    #[test]
    fn header_injection_and_non_origin_form_are_refused() {
        assert!(redirect_target("/a\r\nX-Injected: 1", "example.com").is_none());
        assert!(redirect_target("http://elsewhere/", "example.com").is_none());
        assert!(redirect_target("*", "example.com").is_none());
    }

    #[test]
    fn a_host_that_is_not_a_bare_name_is_refused() {
        for bad in [
            "exa mple.com",
            "user@example.com",
            "example.com/path",
            "http://example.com",
            "example.com:notaport",
            "example.com:",
            "",
            "   ",
        ] {
            assert!(redirect_target("/", bad).is_none(), "{bad:?} was accepted");
        }
        assert!(redirect_target("/", &"a".repeat(254)).is_none());
    }

    #[test]
    fn ipv6_literals_round_trip_bracketed() {
        assert_eq!(
            redirect_target("/", "[::1]:8080").as_deref(),
            Some("https://[::1]:8080/"),
        );
        assert!(redirect_target("/", "::1]").is_none());
    }

    #[test]
    fn the_route_key_drops_the_port_and_lowercases() {
        assert_eq!(
            route_key("Example.COM:8080").as_deref(),
            Some("example.com")
        );
        assert_eq!(route_key(" example.com ").as_deref(), Some("example.com"));
        assert_eq!(route_key("[::1]:80").as_deref(), Some("[::1]"));
        assert_eq!(route_key("bad host"), None);
    }

    #[test]
    fn refusals_are_well_formed_responses_that_close() {
        for r in [bad_request_response(), unrouted_response()] {
            assert!(r.starts_with("HTTP/1.1 4"));
            assert!(r.contains("Connection: close\r\n"));
            let (head, body) = r.split_once("\r\n\r\n").unwrap();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(len, body.len());
        }
    }
}
