//! The hostname → backend table the demux routes on.
//!
//! Three match shapes, most specific first:
//!
//! 1. exact `tenant.example.com`
//! 2. wildcard `*.example.com` — one label only, like a TLS wildcard cert,
//!    so the table's notion of "which passway serves this name" agrees with
//!    the cert that passway will present. `*.example.com` does NOT match
//!    `example.com` or `a.b.example.com`.
//! 3. catch-all `*` — must be typed on purpose, same rule as passway's
//!    `PASSWAY_UPSTREAMS` (R594-F10): a multi-tenant front door never falls
//!    through to "somewhere" by accident.
//!
//! A name no entry matches is **unrouted**, and the demux closes the
//! connection (with a TLS `unrecognized_name` alert) rather than guessing.
//! That is the fail-closed half of the tenant boundary: the demux never
//! sends tenant A's bytes to tenant B's process.
//!
//! v0 is a static table parsed from `PASSWAY_DEMUX_ROUTES`; the seam a
//! yubaba-fed dynamic table would plug into is [`RouteTable`] itself (an
//! `Arc<RouteTable>` swapped under an `RwLock`), kept deliberately as a
//! plain value type so that swap stays trivial.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// Where a hostname's bytes go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// The per-tenant passway's listener (typically a loopback or mesh
    /// address on a non-443 port, or a kamaji-held JIT socket).
    pub addr: SocketAddr,
}

/// Immutable hostname → backend map. See the module doc for match rules.
#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    exact: HashMap<String, Backend>,
    /// Keyed by the suffix after `*.` (e.g. `example.com`).
    wildcard: HashMap<String, Backend>,
    catch_all: Option<Backend>,
}

/// A malformed `PASSWAY_DEMUX_ROUTES` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParseError(pub String);

impl fmt::Display for RouteParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid route: {}", self.0)
    }
}

impl std::error::Error for RouteParseError {}

impl RouteTable {
    /// Parse `host=addr,host=addr,...`. Hosts are lower-cased; a duplicate
    /// host is rejected rather than last-wins, because two tenants claiming
    /// one name is a configuration bug that must not resolve silently.
    ///
    /// Newlines separate entries exactly like commas, and `#` starts a
    /// comment that runs to end of line. That is what lets one parser take
    /// both `PASSWAY_DEMUX_ROUTES` (one comma-joined line) and the routes
    /// *file* yubaba publishes ([`crate::routes_file`], one entry per line so
    /// a 10k-domain table is diffable). Comments are stripped per line, not
    /// per entry, so a comma inside a comment is still a comment.
    pub fn parse(spec: &str) -> Result<Self, RouteParseError> {
        let mut t = RouteTable::default();
        for line in spec.lines() {
            let line = line.split_once('#').map_or(line, |(before, _)| before);
            for raw in line.split(',') {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                let (host, addr) = raw
                    .split_once('=')
                    .ok_or_else(|| RouteParseError(format!("`{raw}` is not host=addr")))?;
                let host = host.trim().to_ascii_lowercase();
                let addr: SocketAddr = addr
                    .trim()
                    .parse()
                    .map_err(|e| RouteParseError(format!("`{raw}`: bad address: {e}")))?;
                t.insert(&host, Backend { addr })?;
            }
        }
        Ok(t)
    }

    /// Add one entry. `host` must already be lower-case.
    pub fn insert(&mut self, host: &str, backend: Backend) -> Result<(), RouteParseError> {
        if host == "*" {
            if self.catch_all.replace(backend).is_some() {
                return Err(RouteParseError("catch-all `*` given twice".into()));
            }
            return Ok(());
        }
        if let Some(suffix) = host.strip_prefix("*.") {
            check_host(suffix)?;
            if self.wildcard.insert(suffix.to_string(), backend).is_some() {
                return Err(RouteParseError(format!("`{host}` given twice")));
            }
            return Ok(());
        }
        check_host(host)?;
        if self.exact.insert(host.to_string(), backend).is_some() {
            return Err(RouteParseError(format!("`{host}` given twice")));
        }
        Ok(())
    }

    /// Resolve an SNI (already lower-cased by the parser) to a backend.
    pub fn lookup(&self, sni: &str) -> Option<&Backend> {
        if let Some(b) = self.exact.get(sni) {
            return Some(b);
        }
        if let Some((_, suffix)) = sni.split_once('.') {
            if let Some(b) = self.wildcard.get(suffix) {
                return Some(b);
            }
        }
        self.catch_all.as_ref()
    }

    /// The backend for a connection that sent **no** SNI. Only the
    /// catch-all qualifies — there is no name to match, and routing a
    /// nameless hello to a named tenant would be guessing.
    pub fn no_sni_backend(&self) -> Option<&Backend> {
        self.catch_all.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.catch_all.is_none()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len() + usize::from(self.catch_all.is_some())
    }
}

fn check_host(host: &str) -> Result<(), RouteParseError> {
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || host.contains('*')
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(RouteParseError(format!("`{host}` is not a valid hostname")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(p: u16) -> SocketAddr {
        format!("127.0.0.1:{p}").parse().unwrap()
    }

    #[test]
    fn exact_wildcard_catchall_precedence() {
        let t = RouteTable::parse(
            "a.example.com=127.0.0.1:1, *.example.com=127.0.0.1:2, *=127.0.0.1:3",
        )
        .unwrap();
        assert_eq!(t.lookup("a.example.com").unwrap().addr, addr(1));
        assert_eq!(t.lookup("b.example.com").unwrap().addr, addr(2));
        assert_eq!(t.lookup("example.com").unwrap().addr, addr(3)); // wildcard does not cover apex
        assert_eq!(t.lookup("x.b.example.com").unwrap().addr, addr(3)); // one label only
        assert_eq!(t.lookup("other.net").unwrap().addr, addr(3));
        assert_eq!(t.no_sni_backend().unwrap().addr, addr(3));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn unrouted_without_catchall() {
        let t = RouteTable::parse("A.Example.com=127.0.0.1:1").unwrap();
        assert_eq!(t.lookup("a.example.com").unwrap().addr, addr(1));
        assert!(t.lookup("b.example.com").is_none());
        assert!(t.no_sni_backend().is_none());
    }

    #[test]
    fn rejects_bad_entries() {
        assert!(RouteTable::parse("nohost").is_err());
        assert!(RouteTable::parse("a.example=notanaddr").is_err());
        assert!(RouteTable::parse("a.example=127.0.0.1:1,a.example=127.0.0.1:2").is_err());
        assert!(RouteTable::parse("*=127.0.0.1:1,*=127.0.0.1:2").is_err());
        assert!(RouteTable::parse("*.*.example=127.0.0.1:1").is_err());
        assert!(RouteTable::parse("a..b=127.0.0.1:1").is_err());
        assert!(RouteTable::parse("").unwrap().is_empty());
    }
}
