//! A route table that is reloaded from a file while the demux is serving
//! (R779 / W267).
//!
//! [`route`](crate::route) says the seam a yubaba-fed dynamic table plugs into
//! is `RouteTable` itself — "an `Arc<RouteTable>` swapped under an `RwLock`,
//! kept deliberately as a plain value type so that swap stays trivial". This is
//! that swap, plus the thing that drives it.
//!
//! The other end is `yubaba::demux_routes`, which sweeps the enrollment set in
//! the cert-store bucket and writes this file with tmp-plus-rename. A file
//! rather than an API call in either direction, because the demux is the one
//! process on the public `:443` that is shared across tenants: it links no TLS
//! stack, no HTTP client and holds no credential, and reading a local file is
//! the smallest possible way to learn about a new tenant. Handing it a bucket
//! client would give a compromise of it the whole fleet's routing *and* the
//! credential to change it.
//!
//! ## Reload policy: never make the table worse
//!
//! The watcher polls the file's bytes and swaps only on a strictly better
//! answer. An unreadable file, an unparseable one, and one that parses to an
//! **empty** table all leave the live table exactly as it was, loudly:
//!
//! - unreadable → the publisher may be mid-rename on another filesystem, or the
//!   file was removed by a bad deploy;
//! - unparseable → a truncated or hand-edited file;
//! - empty → indistinguishable from "every tenant was deleted", and the
//!   difference between a no-op and a total outage.
//!
//! This mirrors `main.rs` refusing to *start* on an empty table, and the
//! publisher's own refusal to write one. Three layers say the same thing
//! because de-routing every tenant at once is the failure that has no partial
//! form.
//!
//! In-flight connections are never affected: [`current`] hands each accepted
//! connection its own `Arc`, so a swap changes where the *next* connection
//! goes and nothing else.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::route::{RouteParseError, RouteTable};

/// The live table, swappable underneath the accept loop.
///
/// `std::sync::RwLock`, not tokio's: the critical section is one `Arc::clone`
/// and nothing awaits inside it, so an async lock would buy a scheduler hop for
/// no reason.
pub type SharedRoutes = Arc<RwLock<Arc<RouteTable>>>;

/// Wrap a table so it can be swapped.
pub fn shared(table: RouteTable) -> SharedRoutes {
    shared_arc(Arc::new(table))
}

/// [`shared`] for a table already behind an `Arc` — what the static
/// `PASSWAY_DEMUX_ROUTES` path has, so it can reach the same accept loop
/// without a second copy of a 10k-entry table.
pub fn shared_arc(table: Arc<RouteTable>) -> SharedRoutes {
    Arc::new(RwLock::new(table))
}

/// Snapshot the live table for one connection.
///
/// Recovers from a poisoned lock rather than panicking: the only writer is
/// [`watch`], which holds the lock across a single `Arc` assignment and cannot
/// leave a torn value behind — so a poisoned lock here means some *other* task
/// panicked while reading, and refusing to route every subsequent connection
/// over that would turn one panic into an outage.
pub fn current(routes: &SharedRoutes) -> Arc<RouteTable> {
    match routes.read() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Why a routes file could not become a table.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io(io::Error),
    /// The file's contents are not `host=addr` entries.
    Parse(RouteParseError),
    /// The file parsed to zero routes — refused, see the module doc.
    Empty,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "read: {e}"),
            LoadError::Parse(e) => write!(f, "{e}"),
            LoadError::Empty => write!(
                f,
                "no routes — a demux with an empty table would close every connection"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Read and parse a routes file. Never returns an empty table.
pub fn load(path: &Path) -> Result<RouteTable, LoadError> {
    let text = std::fs::read_to_string(path).map_err(LoadError::Io)?;
    let table = RouteTable::parse(&text).map_err(LoadError::Parse)?;
    if table.is_empty() {
        return Err(LoadError::Empty);
    }
    Ok(table)
}

/// Poll `path` every `interval` and swap `routes` when its contents change into
/// a table that parses non-empty.
///
/// Content comparison, not mtime: the publisher rewrites only on a real change,
/// but a `touch`, a redeploy, or a clock skew must not cost a re-parse of a 10k
/// entry table — and, more importantly, a table that changed *back* between two
/// polls must still be noticed.
///
/// Runs until the task is dropped.
pub async fn watch(path: PathBuf, routes: SharedRoutes, interval: Duration) {
    let mut last: Option<Vec<u8>> = None;
    loop {
        tokio::time::sleep(interval).await;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "routes file {}: {e}; keeping the live table",
                    path.display()
                );
                continue;
            }
        };
        if last.as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        // Remember the bytes even when they fail to parse: a broken file should
        // be complained about once, not once per poll forever.
        last = Some(bytes.clone());
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(e) => {
                log::warn!(
                    "routes file {}: not UTF-8 ({e}); keeping the live table",
                    path.display()
                );
                continue;
            }
        };
        let table = match RouteTable::parse(&text) {
            Ok(t) if t.is_empty() => {
                log::warn!(
                    "routes file {}: parsed to zero routes; keeping the live table \
                     rather than de-routing every tenant",
                    path.display()
                );
                continue;
            }
            Ok(t) => t,
            Err(e) => {
                log::warn!(
                    "routes file {}: {e}; keeping the live table",
                    path.display()
                );
                continue;
            }
        };
        let len = table.len();
        match routes.write() {
            Ok(mut g) => *g = Arc::new(table),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(table),
        }
        log::info!("routes file {}: reloaded, {len} routes", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(p: u16) -> SocketAddr {
        format!("127.0.0.1:{p}").parse().unwrap()
    }

    fn write(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("routes");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn loads_one_entry_per_line_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "# published by yubaba, do not edit\n\
             a.example.com=127.0.0.1:8443\n\
             *.example.net=127.0.0.1:8444   # a whole tenant, one line\n\
             \n",
        );
        let t = load(&path).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.lookup("a.example.com").unwrap().addr, addr(8443));
        assert_eq!(t.lookup("x.example.net").unwrap().addr, addr(8444));
    }

    #[test]
    fn a_comma_inside_a_comment_is_not_an_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "a.example.com=127.0.0.1:8443 # one, two, three\n");
        assert_eq!(load(&path).unwrap().len(), 1);
    }

    #[test]
    fn an_empty_or_missing_file_is_refused_rather_than_an_empty_table() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(&write(dir.path(), "\n# nothing\n")),
            Err(LoadError::Empty)
        ));
        assert!(matches!(
            load(&dir.path().join("absent")),
            Err(LoadError::Io(_))
        ));
        assert!(matches!(
            load(&write(dir.path(), "a.example.com 127.0.0.1:1\n")),
            Err(LoadError::Parse(_))
        ));
    }

    #[tokio::test]
    async fn watch_swaps_the_table_when_the_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "a.example.com=127.0.0.1:8443\n");
        let routes = shared(load(&path).unwrap());
        let handle = tokio::spawn(watch(
            path.clone(),
            routes.clone(),
            Duration::from_millis(10),
        ));

        std::fs::write(
            &path,
            "a.example.com=127.0.0.1:8443\nb.example.com=127.0.0.1:8444\n",
        )
        .unwrap();
        let swapped = await_routes(&routes, 2).await;
        assert!(swapped, "the watcher must pick up the new entry");
        assert_eq!(current(&routes).lookup("b.example.com").unwrap().addr, addr(8444));
        handle.abort();
    }

    #[tokio::test]
    async fn a_broken_or_empty_file_leaves_the_live_table_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "a.example.com=127.0.0.1:8443\n");
        let routes = shared(load(&path).unwrap());
        let handle = tokio::spawn(watch(
            path.clone(),
            routes.clone(),
            Duration::from_millis(10),
        ));

        for bad in ["", "not a route table\n", "a.example.com=not-an-addr\n"] {
            std::fs::write(&path, bad).unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert_eq!(
                current(&routes).lookup("a.example.com").map(|b| b.addr),
                Some(addr(8443)),
                "{bad:?} must not have taken the live route away"
            );
        }

        // And a good file after a bad one still lands — a parse failure must
        // not wedge the watcher.
        std::fs::write(&path, "a.example.com=127.0.0.1:9443\n").unwrap();
        assert!(await_routes_addr(&routes, "a.example.com", addr(9443)).await);
        handle.abort();
    }

    async fn await_routes(routes: &SharedRoutes, want_len: usize) -> bool {
        for _ in 0..100 {
            if current(routes).len() == want_len {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    async fn await_routes_addr(routes: &SharedRoutes, host: &str, want: SocketAddr) -> bool {
        for _ in 0..100 {
            if current(routes).lookup(host).map(|b| b.addr) == Some(want) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}
