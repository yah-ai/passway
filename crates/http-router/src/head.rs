//! Reading exactly as much of an HTTP/1.x request as routing needs: the
//! request target and the `Host` header.
//!
//! Pure and total over `&[u8]`, the same shape as `sni_demux::hello::parse_sni`
//! and for the same reason — the caller owns the socket and the deadline, this
//! owns the bytes. It is fed a growing buffer and answers
//! [`HeadError::Incomplete`] until the blank line that ends the head arrives.
//!
//! ## What it deliberately does not do
//!
//! No method table, no version check, no header map, no body. This process
//! routes on one header and then either writes a redirect or stops looking at
//! the stream entirely, so parsing more would be surface with no consumer.
//! The one thing it *is* strict about is duplicate `Host` headers: RFC 9112
//! §3.2 says a request with more than one must be rejected, and "first one
//! wins" is precisely the disagreement between two hops that request
//! smuggling is built out of.

/// Largest request head this will read. A head longer than this is refused
/// rather than buffered — the router answers a `400` and closes.
///
/// 8 KiB is nginx's `large_client_header_buffers` default and roughly
/// Apache's `LimitRequestFieldSize`; a request that needs more than that on
/// the plaintext port, which serves redirects and ACME challenges, is not one
/// worth holding memory for.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;

/// The routable parts of a request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The request target verbatim — origin-form (`/a/b?q`) for anything a
    /// browser or curl sends. Validated by [`crate::redirect::redirect_target`]
    /// before it is ever written into a response.
    pub target: String,
    /// The `Host` header's value, if the request carried exactly one.
    pub host: Option<String>,
}

/// Why a buffer is not (yet) a routable request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadError {
    /// The head is not complete; read more and call again.
    Incomplete,
    /// The head exceeded [`MAX_HEAD_BYTES`] without ending.
    TooLarge,
    /// Complete, but not a request head we will route.
    Malformed,
    /// The first byte cannot begin an HTTP method, so this peer is not
    /// speaking HTTP at all (a TLS ClientHello starts `0x16`). The router
    /// closes on this without writing a response — there is nothing to say to
    /// something that is not listening in this protocol.
    NotHttp,
}

impl std::fmt::Display for HeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeadError::Incomplete => write!(f, "incomplete request head"),
            HeadError::TooLarge => write!(f, "request head over {MAX_HEAD_BYTES} bytes"),
            HeadError::Malformed => write!(f, "malformed request head"),
            HeadError::NotHttp => write!(f, "not HTTP"),
        }
    }
}

impl std::error::Error for HeadError {}

/// Parse the request target and `Host` out of a buffer.
pub fn parse_head(buf: &[u8]) -> Result<Head, HeadError> {
    match buf.first() {
        // Methods are uppercase ASCII tokens in every HTTP version. Anything
        // else is a different protocol pointed at the wrong port.
        Some(b) if b.is_ascii_uppercase() => {}
        Some(_) => return Err(HeadError::NotHttp),
        None => return Err(HeadError::Incomplete),
    }
    let Some(end) = head_end(buf) else {
        return Err(if buf.len() >= MAX_HEAD_BYTES {
            HeadError::TooLarge
        } else {
            HeadError::Incomplete
        });
    };
    if end > MAX_HEAD_BYTES {
        return Err(HeadError::TooLarge);
    }
    // Header field values are opaque bytes on the wire, but anything we route
    // on or echo has to be text; a non-UTF-8 head is refused rather than
    // lossily converted.
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| HeadError::Malformed)?;

    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
    let request_line = lines.next().ok_or(HeadError::Malformed)?;
    // `split_whitespace` would also split on the CR and LF this line no longer
    // has, but it accepts runs of spaces where the grammar wants exactly one;
    // that laxity is the one a smuggling pair disagrees over, so split on the
    // single SP the grammar specifies.
    let mut parts = request_line.split(' ');
    let _method = parts
        .next()
        .filter(|m| !m.is_empty())
        .ok_or(HeadError::Malformed)?;
    let target = parts
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(HeadError::Malformed)?;
    // Trailing junk after the version is not a request line we will guess at.
    match parts.next() {
        Some(v) if v.starts_with("HTTP/") && parts.next().is_none() => {}
        _ => return Err(HeadError::Malformed),
    }

    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                // Two hops that resolve this differently route one connection
                // two ways. Refuse instead of picking.
                return Err(HeadError::Malformed);
            }
            host = Some(value.trim().to_string());
        }
    }

    Ok(Head {
        target: target.to_string(),
        host,
    })
}

/// Index just past the blank line that ends the head, tolerating bare-LF line
/// endings the way every real server does.
fn head_end(buf: &[u8]) -> Option<usize> {
    for (i, b) in buf.iter().enumerate() {
        if *b != b'\n' {
            continue;
        }
        match (buf.get(i + 1), buf.get(i + 2)) {
            (Some(b'\n'), _) => return Some(i + 2),
            (Some(b'\r'), Some(b'\n')) => return Some(i + 3),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Head, HeadError> {
        parse_head(s.as_bytes())
    }

    #[test]
    fn the_scheme_less_install_one_liner_is_what_this_reads() {
        // `curl -fsSL example.com/install.sh` sends exactly this.
        let head =
            parse("GET /install.sh HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n").unwrap();
        assert_eq!(head.target, "/install.sh");
        assert_eq!(head.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn every_truncation_of_a_valid_head_is_incomplete_never_a_panic() {
        let full = "GET /a?b=c HTTP/1.1\r\nHost: example.com\r\nX: y\r\n\r\n";
        for n in 1..full.len() {
            let got = parse(&full[..n]);
            assert!(
                got == Err(HeadError::Incomplete) || got.is_ok(),
                "prefix of {n} bytes gave {got:?}"
            );
        }
        assert!(parse("").is_err());
    }

    #[test]
    fn bare_lf_endings_and_a_headerless_request_both_parse() {
        assert_eq!(parse("GET / HTTP/1.0\n\n").unwrap().host, None);
        let head = parse("GET / HTTP/1.1\nHost: a.example\n\n").unwrap();
        assert_eq!(head.host.as_deref(), Some("a.example"));
    }

    #[test]
    fn host_is_case_insensitive_and_found_anywhere_in_the_head() {
        let head = parse("GET / HTTP/1.1\r\nA: 1\r\nhOsT:   a.example  \r\nB: 2\r\n\r\n").unwrap();
        assert_eq!(head.host.as_deref(), Some("a.example"));
    }

    #[test]
    fn two_host_headers_are_refused_not_resolved() {
        assert_eq!(
            parse("GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"),
            Err(HeadError::Malformed),
        );
    }

    #[test]
    fn a_tls_client_hello_on_port_80_is_not_http() {
        assert_eq!(
            parse_head(&[0x16, 0x03, 0x01, 0x00]),
            Err(HeadError::NotHttp)
        );
    }

    #[test]
    fn malformed_request_lines_are_refused() {
        assert_eq!(parse("GET\r\n\r\n"), Err(HeadError::Malformed));
        assert_eq!(parse("GET /  HTTP/1.1\r\n\r\n"), Err(HeadError::Malformed));
        assert_eq!(
            parse("GET / HTTP/1.1 extra\r\n\r\n"),
            Err(HeadError::Malformed)
        );
        assert_eq!(parse("GET / NOTHTTP\r\n\r\n"), Err(HeadError::Malformed));
    }

    #[test]
    fn an_endless_head_is_too_large_rather_than_buffered_forever() {
        let mut req = b"GET / HTTP/1.1\r\n".to_vec();
        req.extend(std::iter::repeat_n(b'x', MAX_HEAD_BYTES));
        assert_eq!(parse_head(&req), Err(HeadError::TooLarge));
    }

    #[test]
    fn an_absolute_form_target_survives_parsing_and_is_rejected_downstream() {
        // Legal for a proxy; `redirect_target` is what refuses it, so that the
        // request line can never choose the destination instead of `Host`.
        let head = parse("GET http://elsewhere/ HTTP/1.1\r\nHost: a.example\r\n\r\n").unwrap();
        assert_eq!(head.target, "http://elsewhere/");
        assert!(crate::redirect::redirect_target(&head.target, "a.example").is_none());
    }
}
