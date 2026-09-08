//! The `Host` → disposition table the `:80` tier routes on.
//!
//! Same grammar and same match precedence as `sni_demux::route::RouteTable`
//! (`oss/passway/crates/sni-demux/src/route.rs`), so one operator reading
//! `/etc/passway-demux.routes` and `/etc/passway-http.routes` side by side is
//! reading one format:
//!
//! 1. exact `tenant.example.com`
//! 2. wildcard `*.example.com` — one label only, like a TLS wildcard cert.
//!    Does NOT match `example.com` or `a.b.example.com`.
//! 3. catch-all `*` — must be typed on purpose.
//!
//! A name no entry matches is **unrouted**: the router answers `404` and
//! closes rather than guessing. On this tier that is not only the tenant
//! boundary — it is what stops the redirect leg from being an open redirector,
//! since `Location` is built from the client's own `Host` header.
//!
//! ## The one difference from the `:443` table: what the value means
//!
//! The demux's value is always a backend address, because a TLS byte stream
//! can only be handed onward. Here it is a [`Disposition`], and the extra
//! variant is the default rather than the exception:
//!
//! ```text
//! yah.dev=redirect            # this process answers 308 https://yah.dev<target>
//! *.yah.dev=redirect
//! noisetable.com=127.0.0.1:8081   # spliced to that tenant's http-01 responder
//! ```
//!
//! `redirect` is what an enrolled domain with no `Enrollment::http_backend`
//! renders to, which is every domain today. That is deliberate: a second apex
//! becomes scheme-less-curl-able the moment it is enrolled, with no per-tenant
//! `:80` process to run, and a tenant that later needs `http-01` validation
//! gets an address in the same column without a format change.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// What the `:80` tier does with a request for a routed host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Answer `308 https://<host><target>` here. No backend is contacted.
    Redirect,
    /// Splice the connection to this address — the tenant passway's
    /// plaintext listener (`PASSWAY_ACME_HTTP01_BIND`).
    Proxy(SocketAddr),
}

/// The token that spells [`Disposition::Redirect`] in a routes file.
///
/// A word rather than an empty value or a bare `-`: an operator grepping a
/// 10k-line table should be able to see which hosts have a backend and which
/// do not without knowing the grammar.
pub const REDIRECT_TOKEN: &str = "redirect";

/// Immutable host → disposition map. See the module doc for match rules.
#[derive(Debug, Default, Clone)]
pub struct HostTable {
    exact: HashMap<String, Disposition>,
    /// Keyed by the suffix after `*.` (e.g. `example.com`).
    wildcard: HashMap<String, Disposition>,
    catch_all: Option<Disposition>,
}

/// A malformed routes entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParseError(pub String);

impl fmt::Display for RouteParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid route: {}", self.0)
    }
}

impl std::error::Error for RouteParseError {}

impl HostTable {
    /// Parse `host=disposition,host=disposition,...`.
    ///
    /// Newlines separate entries exactly like commas, and `#` starts a comment
    /// that runs to end of line — so one parser takes both the
    /// `PASSWAY_HTTP_ROUTER_ROUTES` env var (comma-joined) and the routes
    /// *file* yubaba publishes (one entry per line, so a big table is
    /// diffable). Hosts are lower-cased; a duplicate host is rejected rather
    /// than last-wins, because two tenants claiming one name is a
    /// configuration bug that must not resolve silently.
    pub fn parse(spec: &str) -> Result<Self, RouteParseError> {
        let mut t = HostTable::default();
        for line in spec.lines() {
            let line = line.split_once('#').map_or(line, |(before, _)| before);
            for raw in line.split(',') {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                let (host, value) = raw
                    .split_once('=')
                    .ok_or_else(|| RouteParseError(format!("`{raw}` is not host=disposition")))?;
                let host = host.trim().to_ascii_lowercase();
                let value = value.trim();
                let disposition = if value.eq_ignore_ascii_case(REDIRECT_TOKEN) {
                    Disposition::Redirect
                } else {
                    Disposition::Proxy(value.parse().map_err(|e| {
                        RouteParseError(format!(
                            "`{raw}`: expected `{REDIRECT_TOKEN}` or an address: {e}"
                        ))
                    })?)
                };
                t.insert(&host, disposition)?;
            }
        }
        Ok(t)
    }

    /// Add one entry. `host` must already be lower-case.
    pub fn insert(&mut self, host: &str, d: Disposition) -> Result<(), RouteParseError> {
        if host == "*" {
            if self.catch_all.replace(d).is_some() {
                return Err(RouteParseError("catch-all `*` given twice".into()));
            }
            return Ok(());
        }
        if let Some(suffix) = host.strip_prefix("*.") {
            check_host(suffix)?;
            if self.wildcard.insert(suffix.to_string(), d).is_some() {
                return Err(RouteParseError(format!("`{host}` given twice")));
            }
            return Ok(());
        }
        check_host(host)?;
        if self.exact.insert(host.to_string(), d).is_some() {
            return Err(RouteParseError(format!("`{host}` given twice")));
        }
        Ok(())
    }

    /// Resolve a routing key (see [`crate::redirect::route_key`] — already
    /// lower-cased and port-stripped) to a disposition.
    pub fn lookup(&self, host: &str) -> Option<Disposition> {
        if let Some(d) = self.exact.get(host) {
            return Some(*d);
        }
        if let Some((_, suffix)) = host.split_once('.') {
            if let Some(d) = self.wildcard.get(suffix) {
                return Some(*d);
            }
        }
        self.catch_all
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

    fn proxy(p: u16) -> Disposition {
        Disposition::Proxy(format!("127.0.0.1:{p}").parse().unwrap())
    }

    #[test]
    fn exact_wildcard_catchall_precedence() {
        let t =
            HostTable::parse("a.example.com=127.0.0.1:1, *.example.com=redirect, *=127.0.0.1:3")
                .unwrap();
        assert_eq!(t.lookup("a.example.com"), Some(proxy(1)));
        assert_eq!(t.lookup("b.example.com"), Some(Disposition::Redirect));
        assert_eq!(t.lookup("example.com"), Some(proxy(3))); // wildcard does not cover apex
        assert_eq!(t.lookup("x.b.example.com"), Some(proxy(3))); // one label only
        assert_eq!(t.lookup("other.net"), Some(proxy(3)));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn unrouted_without_catchall() {
        let t = HostTable::parse("A.Example.com=REDIRECT").unwrap();
        assert_eq!(t.lookup("a.example.com"), Some(Disposition::Redirect));
        assert_eq!(t.lookup("b.example.com"), None);
    }

    #[test]
    fn the_published_shape_is_one_entry_per_line_with_comments() {
        let t = HostTable::parse(
            "# published by yubaba, do not edit\n\
             yah.dev=redirect\n\
             *.yah.dev=redirect\n\
             noisetable.com=127.0.0.1:8081   # a tenant that validates by http-01\n\
             \n",
        )
        .unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.lookup("www.yah.dev"), Some(Disposition::Redirect));
        assert_eq!(t.lookup("noisetable.com"), Some(proxy(8081)));
    }

    #[test]
    fn rejects_bad_entries() {
        assert!(HostTable::parse("nohost").is_err());
        assert!(HostTable::parse("a.example=notanaddr").is_err());
        assert!(HostTable::parse("a.example=redirect,a.example=redirect").is_err());
        assert!(HostTable::parse("*=redirect,*=redirect").is_err());
        assert!(HostTable::parse("*.*.example=redirect").is_err());
        assert!(HostTable::parse("a..b=redirect").is_err());
        assert!(HostTable::parse("").unwrap().is_empty());
    }

    #[test]
    fn a_bad_address_names_the_two_things_a_value_may_be() {
        let err = HostTable::parse("a.example=127.0.0.1").unwrap_err();
        assert!(err.0.contains(REDIRECT_TOKEN), "{err}");
    }
}
