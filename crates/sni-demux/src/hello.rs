//! TLS ClientHello parsing — exactly enough to read the `server_name`
//! extension (RFC 6066 §3) out of the first record, and nothing more.
//!
//! This is a pure function over `&[u8]`. It never allocates for anything
//! but the returned hostname, never looks past the first TLS record, and
//! treats every length field as untrusted (every slice is bounds-checked;
//! a lying length is [`HelloError::Malformed`], never a panic). That is the
//! whole trust-boundary posture of this crate: the demux is the most
//! exposed byte-parser on the box, so the parser is small enough to read
//! in one sitting and fuzz-shaped by construction.
//!
//! ## What it deliberately does not do
//!
//! - **No multi-record ClientHello.** RFC 8446 allows a handshake message
//!   to span TLS records; real clients do not do this for the ClientHello
//!   (haproxy's `req.ssl_sni`, nginx's `ssl_preread`, and sniproxy all make
//!   the same single-record assumption), and accepting it would mean
//!   buffering an unbounded handshake from an unauthenticated peer. A
//!   ClientHello whose handshake length exceeds the record it starts in
//!   is [`HelloError::Unsupported`], and the connection is closed.
//! - **No SSLv2-compatible hello.** Nothing this century sends one.
//! - **No ESNI / ECH.** With Encrypted Client Hello the outer SNI carries
//!   the *public* name (the client-facing server), which is exactly what a
//!   demux routes on — so ECH-capable clients still work here, they just
//!   route on the outer name. Nothing to parse.
//!
//! ## Incomplete vs. malformed
//!
//! The caller peeks a growing prefix of the stream, so "not enough bytes
//! yet" is a normal state, not an error. [`HelloError::Incomplete`] carries
//! the total number of bytes the parser needs to make progress, so the
//! caller can read exactly that much and retry instead of polling byte by
//! byte. Everything else is terminal.

use std::fmt;

/// TLS record content type for handshake messages.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// Handshake message type for ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// The `server_name` extension type (RFC 6066).
const EXT_SERVER_NAME: u16 = 0;
/// `host_name` NameType inside the server_name extension — the only one
/// RFC 6066 defines.
const NAME_TYPE_HOST_NAME: u8 = 0;
/// TLS record header: content type (1) + version (2) + length (2).
const RECORD_HEADER_LEN: usize = 5;
/// Maximum TLS plaintext record length (RFC 8446 §5.1). A record header
/// claiming more is not a TLS peer.
pub const MAX_RECORD_LEN: usize = 16384;
/// The most bytes a caller ever needs to buffer before this parser reaches
/// a verdict: one full record plus its header.
pub const MAX_HELLO_BYTES: usize = RECORD_HEADER_LEN + MAX_RECORD_LEN;

/// Why a byte prefix did not yield a server name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// Not enough bytes yet; the parser needs at least this many total
    /// bytes to make progress. Read up to that and call again.
    Incomplete(usize),
    /// The first bytes are not a TLS handshake record at all — a plain
    /// HTTP request on 443, a port scan, garbage. Close.
    NotTls,
    /// A length field points outside the data it is embedded in, or a
    /// structure is internally inconsistent. Close.
    Malformed,
    /// Well-formed TLS, but a shape this parser declines: a ClientHello
    /// spanning more than one record. Close.
    Unsupported,
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelloError::Incomplete(n) => write!(f, "need {n} bytes to parse ClientHello"),
            HelloError::NotTls => f.write_str("not a TLS handshake record"),
            HelloError::Malformed => f.write_str("malformed ClientHello"),
            HelloError::Unsupported => f.write_str("ClientHello spans multiple TLS records"),
        }
    }
}

impl std::error::Error for HelloError {}

/// Parse the leading bytes of a TLS connection and return the `server_name`
/// the client sent, lower-cased, or `Ok(None)` for a well-formed ClientHello
/// that carries no SNI at all (a bare-IP client, an old scanner).
///
/// See the module doc for what is and is not accepted.
pub fn parse_sni(buf: &[u8]) -> Result<Option<String>, HelloError> {
    // --- TLS record header -------------------------------------------------
    if buf.len() < RECORD_HEADER_LEN {
        return Err(HelloError::Incomplete(RECORD_HEADER_LEN));
    }
    if buf[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(HelloError::NotTls);
    }
    // Record-layer version is 0x0301 (TLS 1.0) for compatibility on every
    // modern hello, 0x0300 from a few legacy stacks, 0x0302/0x0303 from
    // some middleboxes. Major byte must be 3; anything else is not TLS.
    if buf[1] != 0x03 {
        return Err(HelloError::NotTls);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len == 0 || record_len > MAX_RECORD_LEN {
        return Err(HelloError::NotTls);
    }
    let record_end = RECORD_HEADER_LEN + record_len;
    if buf.len() < record_end {
        return Err(HelloError::Incomplete(record_end));
    }
    let record = &buf[RECORD_HEADER_LEN..record_end];

    // --- Handshake header --------------------------------------------------
    // type (1) + length (3)
    if record.len() < 4 {
        return Err(HelloError::Malformed);
    }
    if record[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(HelloError::NotTls);
    }
    let hs_len = u32::from_be_bytes([0, record[1], record[2], record[3]]) as usize;
    let body = &record[4..];
    if hs_len > body.len() {
        // The handshake continues into a later record — declined, see
        // module doc.
        return Err(HelloError::Unsupported);
    }
    let body = &body[..hs_len];

    // --- ClientHello body --------------------------------------------------
    let mut c = Cursor { buf: body, pos: 0 };
    c.skip(2)?; // client_version
    c.skip(32)?; // random
    let sid_len = c.u8()? as usize;
    if sid_len > 32 {
        return Err(HelloError::Malformed);
    }
    c.skip(sid_len)?;
    let cs_len = c.u16()? as usize;
    if cs_len == 0 || !cs_len.is_multiple_of(2) {
        return Err(HelloError::Malformed);
    }
    c.skip(cs_len)?;
    let comp_len = c.u8()? as usize;
    if comp_len == 0 {
        return Err(HelloError::Malformed);
    }
    c.skip(comp_len)?;

    // Extensions are optional (a TLS 1.0/1.1 hello with none is legal).
    if c.remaining() == 0 {
        return Ok(None);
    }
    let ext_total = c.u16()? as usize;
    if ext_total != c.remaining() {
        return Err(HelloError::Malformed);
    }

    // Scan every extension rather than returning at the first server_name:
    // RFC 8446 §4.2 forbids duplicate extension types, and a hello carrying
    // two server_names is a peer lying about itself — reject it instead of
    // routing on whichever one came first.
    let mut found: Option<Option<String>> = None;
    while c.remaining() > 0 {
        let ext_type = c.u16()?;
        let ext_len = c.u16()? as usize;
        let ext = c.take(ext_len)?;
        if ext_type != EXT_SERVER_NAME {
            continue;
        }
        if found.is_some() {
            return Err(HelloError::Malformed);
        }

        let mut e = Cursor { buf: ext, pos: 0 };
        let list_len = e.u16()? as usize;
        if list_len != e.remaining() {
            return Err(HelloError::Malformed);
        }
        let mut host: Option<String> = None;
        while e.remaining() > 0 {
            let name_type = e.u8()?;
            let name_len = e.u16()? as usize;
            let name = e.take(name_len)?;
            if name_type != NAME_TYPE_HOST_NAME {
                continue;
            }
            // RFC 6066: "The ServerNameList MUST NOT contain more than one
            // name of the same name_type."
            if host.is_some() {
                return Err(HelloError::Malformed);
            }
            host = Some(validate_host_name(name)?);
        }
        // An extension present but with no host_name entry is legal
        // (server-side SNI in a ServerHello has an empty list; a client
        // sending one is odd but not hostile). Treat as no SNI.
        found = Some(host);
    }
    Ok(found.flatten())
}

/// RFC 6066 §3: `HostName` is an ASCII byte string of a DNS hostname,
/// without a trailing dot, and "Literal IPv4 and IPv6 addresses are not
/// permitted." Anything outside `[A-Za-z0-9.-]` is malformed; the result is
/// lower-cased so routing is case-insensitive as DNS is.
fn validate_host_name(name: &[u8]) -> Result<String, HelloError> {
    if name.is_empty() || name.len() > 253 {
        return Err(HelloError::Malformed);
    }
    if name[0] == b'.' || name[name.len() - 1] == b'.' {
        return Err(HelloError::Malformed);
    }
    let mut out = String::with_capacity(name.len());
    for &b in name {
        match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' => out.push(b as char),
            b'A'..=b'Z' => out.push(b.to_ascii_lowercase() as char),
            _ => return Err(HelloError::Malformed),
        }
    }
    if out.contains("..") {
        return Err(HelloError::Malformed);
    }
    Ok(out)
}

/// Minimal bounds-checked reader. Every method returns `Malformed` on
/// overrun — inside a record the bytes are already fully present, so a
/// short read can only mean a lying length field.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], HelloError> {
        if n > self.remaining() {
            return Err(HelloError::Malformed);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<(), HelloError> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Result<u8, HelloError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, HelloError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
}

/// Build a syntactically valid ClientHello record carrying `sni` (or no
/// server_name extension when `None`). Test/fixture helper — also used by
/// the integration tests, which is why it is `pub`.
pub fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // session_id len
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // 2 suites
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    let mut exts = Vec::new();
    // A decoy extension first, so the parser proves it skips unknown ones.
    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]); // supported_groups
    if let Some(host) = sni {
        let h = host.as_bytes();
        let entry_len = 3 + h.len();
        let list_len = entry_len;
        let ext_len = 2 + list_len;
        exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(ext_len as u16).to_be_bytes());
        exts.extend_from_slice(&(list_len as u16).to_be_bytes());
        exts.push(NAME_TYPE_HOST_NAME);
        exts.extend_from_slice(&(h.len() as u16).to_be_bytes());
        exts.extend_from_slice(h);
    }
    // Another trailing extension after SNI.
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]); // supported_versions
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![HANDSHAKE_CLIENT_HELLO];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed offsets into a `build_client_hello` record: record header (5),
    /// handshake header (4), version (2), random (32), sid len (1), suites
    /// len plus 2 suites (6), comp len plus null (2) = 52 → ext_total;
    /// extensions start at 54; the 8-byte decoy puts the SNI ext at 62.
    const EXT_TOTAL_IDX: usize = 52;
    const SNI_EXT_IDX: usize = 62;

    #[test]
    fn parses_sni_from_well_formed_hello() {
        let h = build_client_hello(Some("Tenant-A.Example.COM"));
        assert_eq!(parse_sni(&h).unwrap().as_deref(), Some("tenant-a.example.com"));
    }

    #[test]
    fn hello_without_sni_is_ok_none() {
        let h = build_client_hello(None);
        assert_eq!(parse_sni(&h).unwrap(), None);
    }

    #[test]
    fn every_truncation_is_incomplete_never_panics() {
        let h = build_client_hello(Some("a.example"));
        for n in 0..h.len() {
            match parse_sni(&h[..n]) {
                Err(HelloError::Incomplete(need)) => assert!(need > n && need <= h.len()),
                other => panic!("prefix {n}: expected Incomplete, got {other:?}"),
            }
        }
    }

    #[test]
    fn incomplete_reports_exact_record_end() {
        let h = build_client_hello(Some("a.example"));
        assert_eq!(parse_sni(&h[..5]), Err(HelloError::Incomplete(h.len())));
        assert_eq!(parse_sni(&h[..2]), Err(HelloError::Incomplete(5)));
    }

    #[test]
    fn http_on_443_is_not_tls() {
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n"), Err(HelloError::NotTls));
    }

    #[test]
    fn oversized_record_is_not_tls() {
        assert_eq!(parse_sni(&[22, 3, 1, 0xff, 0xff]), Err(HelloError::NotTls));
        assert_eq!(parse_sni(&[22, 3, 1, 0, 0]), Err(HelloError::NotTls));
    }

    #[test]
    fn non_hello_handshake_is_not_tls() {
        let mut h = build_client_hello(Some("a.example"));
        h[5] = 2; // ServerHello
        assert_eq!(parse_sni(&h), Err(HelloError::NotTls));
    }

    #[test]
    fn handshake_spanning_records_is_unsupported() {
        let mut h = build_client_hello(Some("a.example"));
        // Claim the handshake is one byte longer than the record holds.
        let hs_len = u32::from_be_bytes([0, h[6], h[7], h[8]]) + 1;
        let b = hs_len.to_be_bytes();
        h[6] = b[1];
        h[7] = b[2];
        h[8] = b[3];
        assert_eq!(parse_sni(&h), Err(HelloError::Unsupported));
    }

    #[test]
    fn lying_inner_lengths_are_malformed() {
        let h = build_client_hello(Some("a.example"));
        assert_eq!(&h[SNI_EXT_IDX..SNI_EXT_IDX + 2], &[0, 0], "fixture layout");
        // Corrupt the SNI extension's list length (ext_type at +0, ext_len
        // at +2, list_len at +4).
        let mut bad = h.clone();
        bad[SNI_EXT_IDX + 4] = 0x7f;
        bad[SNI_EXT_IDX + 5] = 0xff;
        assert_eq!(parse_sni(&bad), Err(HelloError::Malformed));

        // Extensions total length not matching the remainder.
        let mut bad2 = h.clone();
        bad2[EXT_TOTAL_IDX + 1] ^= 0x01;
        assert_eq!(parse_sni(&bad2), Err(HelloError::Malformed));

        // Session id longer than 32.
        let mut bad3 = h;
        bad3[5 + 4 + 2 + 32] = 33;
        assert_eq!(parse_sni(&bad3), Err(HelloError::Malformed));
    }

    #[test]
    fn hostname_rules() {
        assert_eq!(validate_host_name(b"ok.example").unwrap(), "ok.example");
        assert!(validate_host_name(b"").is_err());
        assert!(validate_host_name(b".x").is_err());
        assert!(validate_host_name(b"x.").is_err());
        assert!(validate_host_name(b"a..b").is_err());
        assert!(validate_host_name(b"sp ace").is_err());
        assert!(validate_host_name(b"1.2.3.4:443").is_err());
        assert!(validate_host_name(b"\xc3\xa9.example").is_err()); // must be punycode
        assert!(validate_host_name(&[b'a'; 254]).is_err());
    }

    #[test]
    fn duplicate_sni_extension_is_malformed() {
        // Two server_name extensions: splice a copy of the SNI ext in twice.
        let h = build_client_hello(Some("a.example"));
        let idx = SNI_EXT_IDX;
        let ext_len = u16::from_be_bytes([h[idx + 2], h[idx + 3]]) as usize;
        let ext = h[idx..idx + 4 + ext_len].to_vec();
        let mut dup = h[..idx].to_vec();
        dup.extend_from_slice(&ext);
        dup.extend_from_slice(&h[idx..]);
        // Fix up the three enclosing lengths (ext_total, hs_len, record_len).
        let added = ext.len() as u16;
        let t = u16::from_be_bytes([dup[EXT_TOTAL_IDX], dup[EXT_TOTAL_IDX + 1]]) + added;
        dup[EXT_TOTAL_IDX..EXT_TOTAL_IDX + 2].copy_from_slice(&t.to_be_bytes());
        let hs = u32::from_be_bytes([0, dup[6], dup[7], dup[8]]) + added as u32;
        dup[6..9].copy_from_slice(&hs.to_be_bytes()[1..]);
        let rl = u16::from_be_bytes([dup[3], dup[4]]) + added;
        dup[3..5].copy_from_slice(&rl.to_be_bytes());
        assert_eq!(parse_sni(&dup), Err(HelloError::Malformed));
    }
}
