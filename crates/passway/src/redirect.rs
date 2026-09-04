//! Plain-HTTP listener that permanently redirects to HTTPS (R330-F37).
//!
//! ## Why a TLS-only front door is not enough
//!
//! passway terminates TLS and nothing else, so before this module a grey
//! (DNS-only) apex had **nothing listening on port 80**. That is invisible
//! until you notice how install one-liners are written: every one this repo
//! documents is scheme-less —
//!
//! ```text
//! curl -fsSL yah.dev/install.sh | sh
//! ```
//!
//! — and curl reads a scheme-less URL as `http://`, so it dials port 80 and
//! gets `Connection refused`. Behind Cloudflare that never showed, because the
//! edge answers `:80` and redirects for you; the day `yah.dev` went grey
//! (2026-09-03) the whole documented install path broke while `GET /` over
//! TLS kept returning 200. Browsers mostly hid it too — they try HTTPS first
//! now — so the failure lands specifically on curl, wget and scripts.
//!
//! A front door that owns a public apex therefore has to own `:80` as well,
//! even though it serves nothing there.
//!
//! ## Opt-in, because port 80 has another claimant
//!
//! Binding is off unless `PASSWAY_HTTP_REDIRECT_BIND` is set. The reason is
//! [`crate::acme`]'s HTTP-01 responder, which defaults to `0.0.0.0:80` and
//! *must* hold that port for validation to succeed. Two listeners on one
//! address is a race whose loser is a silent failed renewal, so
//! [`parse_redirect_bind`] refuses the combination up front (see
//! [`redirect_conflicts_with_acme`]) rather than letting the OS pick a winner.
//! A `dns-01` deployment — which is what both yah.dev origins run, and what
//! any wildcard needs — has no such claimant and is free to take `:80`.
//!
//! ## 308, not 301
//!
//! Both are permanent and cacheable. 301 lets a client rewrite the method,
//! so a `POST http://…` silently becomes `GET https://…` and the body is
//! dropped — the request succeeds having done nothing, which is exactly the
//! class of invisible failure this module exists because of. 308 preserves
//! method and body. Every client that matters has understood it for years,
//! and the one case we are actually fixing (`curl -fsSL`) is a GET either way.
//!
//! ## What it will not do
//!
//! The `Host` header is reflected into `Location`, the same shape as nginx's
//! `return 301 https://$host$request_uri`, so a request is only ever sent to
//! the host it already named. It is nonetheless attacker-controlled input
//! being written into a response header, so [`redirect_target`] validates it
//! strictly — hostname characters and an optional numeric port, nothing else —
//! and the request target is rejected outright if it carries CR or LF. Both
//! failures are a 400, never a redirect built from unvalidated bytes.

use std::net::SocketAddr;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Environment variable that arms the redirect listener.
pub const REDIRECT_BIND_ENV: &str = "PASSWAY_HTTP_REDIRECT_BIND";

/// Read [`REDIRECT_BIND_ENV`]. `Ok(None)` means the listener stays off,
/// which is the default and the pre-R330-F37 behaviour exactly.
pub fn parse_redirect_bind(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<SocketAddr>, String> {
    let Some(raw) = get(REDIRECT_BIND_ENV).filter(|s| !s.trim().is_empty()) else {
        return Ok(None);
    };
    let addr: SocketAddr = raw
        .trim()
        .parse()
        .map_err(|e| format!("{REDIRECT_BIND_ENV} {raw:?}: {e}"))?;
    Ok(Some(addr))
}

/// Whether arming the redirect listener would steal the port the ACME
/// HTTP-01 responder needs.
///
/// Compared as `SocketAddr`s rather than by port alone: `0.0.0.0:80` and
/// `127.0.0.1:80` genuinely do conflict (the wildcard covers the loopback),
/// so a wildcard on either side is treated as covering the other's address.
pub fn redirect_conflicts_with_acme(redirect: SocketAddr, http01: SocketAddr) -> bool {
    if redirect.port() != http01.port() {
        return false;
    }
    redirect.ip() == http01.ip() || redirect.ip().is_unspecified() || http01.ip().is_unspecified()
}

/// Build the absolute HTTPS URL a request should be redirected to, or
/// `None` when the request cannot be redirected safely.
///
/// `request_line` is the raw HTTP request line (`GET /path?q HTTP/1.1`) and
/// `host` the value of the `Host` header, if the request carried one.
pub fn redirect_target(request_line: &str, host: Option<&str>) -> Option<String> {
    // Header injection: a CR or LF inside the request line would let a caller
    // append headers (or a whole second response) to what we write back.
    // Rejected rather than stripped — a request containing one is not one we
    // want to have guessed the intent of.
    //
    // Checked on the WHOLE line before splitting, which is the part that is
    // easy to get wrong: `split_whitespace` treats CR and LF as whitespace, so
    // testing the extracted target instead silently passes
    // `GET /a\r\nX-Injected: 1 HTTP/1.1` as a clean `/a`. In practice
    // `read_line` stops at the first `\n` so the caller cannot hand us one,
    // but this is a public function and should not depend on that.
    let line = request_line.trim_end_matches(['\r', '\n']);
    if line.contains('\r') || line.contains('\n') {
        return None;
    }
    let target = line.split_whitespace().nth(1)?;
    // Only origin-form targets are redirectable. An absolute-form target
    // (`GET http://elsewhere/ HTTP/1.1`, legal for proxies) would otherwise
    // let the request line, not the Host header, choose the destination.
    if !target.starts_with('/') {
        return None;
    }
    let host = validated_host(host?)?;
    Some(format!("https://{host}{target}"))
}

/// Accept a `Host` header only if it is a bare hostname (or IP literal) with
/// an optional numeric port. Anything else — userinfo, a path, a scheme, a
/// space, CR/LF — is rejected rather than sanitized.
fn validated_host(raw: &str) -> Option<&str> {
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

/// The full response to write for a request, redirect or refusal.
pub fn redirect_response(request_line: &str, host: Option<&str>) -> String {
    match redirect_target(request_line, host) {
        Some(location) => format!(
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None => {
            let body = "bad request: this port only redirects to https";
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
        }
    }
}

async fn serve_redirect_conn(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    // Read headers for the `Host` only, draining the rest so the peer sees a
    // clean close rather than a mid-response reset — same discipline as the
    // ACME responder in `crate::acme`.
    let mut host: Option<String> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if host.is_none() {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("host") {
                    host = Some(value.trim().to_string());
                }
            }
        }
    }

    let response = redirect_response(request_line.trim_end(), host.as_deref());
    let mut stream = reader.into_inner();
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn run_redirect_listener(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                tokio::spawn(async move {
                    if let Err(e) = serve_redirect_conn(stream).await {
                        log::debug!("passway redirect: connection error: {e}");
                    }
                });
            }
            Err(e) => log::warn!("passway redirect: accept error: {e}"),
        }
    }
}

/// pingora background service that owns the plain-HTTP listener.
pub struct HttpRedirectService {
    bind: SocketAddr,
}

impl HttpRedirectService {
    pub fn new(bind: SocketAddr) -> Self {
        Self { bind }
    }
}

#[async_trait]
impl BackgroundService for HttpRedirectService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let listener = match TcpListener::bind(self.bind).await {
            Ok(listener) => listener,
            Err(e) => {
                // Loud, but not fatal: TLS is the service, and a front door
                // that still serves HTTPS beats one that refuses to boot
                // because something else holds :80.
                log::error!(
                    "passway redirect: failed to bind {} — plain-HTTP requests will be refused \
                     rather than redirected to https (scheme-less `curl yah.dev/...` will fail): {e}",
                    self.bind
                );
                return;
            }
        };
        log::info!(
            "passway redirect: {} -> 308 https:// (host-preserving)",
            self.bind
        );
        tokio::select! {
            _ = run_redirect_listener(listener) => {}
            _ = shutdown.changed() => {
                log::info!("passway redirect: shutting down");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(line: &str, host: &str) -> Option<String> {
        redirect_target(line, Some(host))
    }

    #[test]
    fn the_documented_scheme_less_install_one_liner_is_what_this_fixes() {
        // `curl -fsSL yah.dev/install.sh` dials :80 with this exact request.
        assert_eq!(
            target("GET /install.sh HTTP/1.1", "yah.dev").as_deref(),
            Some("https://yah.dev/install.sh"),
        );
    }

    #[test]
    fn path_and_query_survive_the_redirect() {
        assert_eq!(
            target("GET /a/b?x=1&y=2 HTTP/1.1", "yah.dev").as_deref(),
            Some("https://yah.dev/a/b?x=1&y=2"),
        );
    }

    #[test]
    fn the_port_in_a_host_header_is_preserved_not_stripped() {
        assert_eq!(
            target("GET / HTTP/1.1", "yah.dev:8080").as_deref(),
            Some("https://yah.dev:8080/"),
        );
    }

    #[test]
    fn an_ipv6_literal_host_is_accepted_with_and_without_a_port() {
        assert_eq!(
            target("GET / HTTP/1.1", "[::1]").as_deref(),
            Some("https://[::1]/"),
        );
        assert_eq!(
            target("GET / HTTP/1.1", "[::1]:8443").as_deref(),
            Some("https://[::1]:8443/"),
        );
    }

    #[test]
    fn a_request_with_no_host_header_cannot_be_redirected() {
        // HTTP/1.0 without a Host: there is no destination to name.
        assert_eq!(redirect_target("GET / HTTP/1.0", None), None);
    }

    #[test]
    fn crlf_in_the_request_target_is_refused_not_stripped() {
        // Header injection: appending a header (or a second response) to
        // what we write back.
        assert_eq!(
            target("GET /a\r\nX-Injected: 1 HTTP/1.1", "yah.dev"),
            None
        );
        assert_eq!(target("GET /a\nX-Injected: 1 HTTP/1.1", "yah.dev"), None);
    }

    #[test]
    fn a_host_header_that_is_not_a_bare_hostname_is_refused() {
        for bad in [
            "evil.com/@yah.dev",
            "yah.dev/path",
            "user@evil.com",
            "https://evil.com",
            "yah dev",
            "yah.dev:notaport",
            "yah.dev:",
            "",
        ] {
            assert_eq!(target("GET / HTTP/1.1", bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn an_absolute_form_target_does_not_get_to_choose_the_destination() {
        // Legal to send to a proxy; here it would let the request line
        // override the Host header.
        assert_eq!(
            target("GET http://evil.com/ HTTP/1.1", "yah.dev"),
            None
        );
    }

    #[test]
    fn a_refusal_is_a_400_and_a_redirect_is_a_308() {
        let ok = redirect_response("GET /install.sh HTTP/1.1", Some("yah.dev"));
        assert!(ok.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"), "{ok}");
        assert!(ok.contains("Location: https://yah.dev/install.sh\r\n"), "{ok}");
        // 308 rather than 301 so a POST keeps its method and body.
        assert!(!ok.contains("301"), "{ok}");

        let bad = redirect_response("GET / HTTP/1.1", None);
        assert!(bad.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{bad}");
        assert!(!bad.contains("Location:"), "{bad}");
    }

    #[test]
    fn the_listener_is_off_unless_the_env_var_is_set() {
        assert_eq!(parse_redirect_bind(|_| None).unwrap(), None);
        assert_eq!(
            parse_redirect_bind(|_| Some("   ".to_string())).unwrap(),
            None
        );
    }

    #[test]
    fn a_set_bind_address_parses_and_a_malformed_one_names_the_variable() {
        assert_eq!(
            parse_redirect_bind(|_| Some("0.0.0.0:80".to_string())).unwrap(),
            Some("0.0.0.0:80".parse().unwrap()),
        );
        let err = parse_redirect_bind(|_| Some("80".to_string())).unwrap_err();
        assert!(err.contains(REDIRECT_BIND_ENV), "{err}");
    }

    #[test]
    fn a_wildcard_bind_conflicts_with_a_loopback_acme_responder_on_the_same_port() {
        let w80: SocketAddr = "0.0.0.0:80".parse().unwrap();
        let lo80: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let lo81: SocketAddr = "127.0.0.1:81".parse().unwrap();
        assert!(redirect_conflicts_with_acme(w80, lo80));
        assert!(redirect_conflicts_with_acme(lo80, w80));
        assert!(redirect_conflicts_with_acme(lo80, lo80));
        // Different port: the two can coexist.
        assert!(!redirect_conflicts_with_acme(w80, lo81));
    }
}
