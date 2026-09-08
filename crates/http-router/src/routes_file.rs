//! A host table reloaded from a file while the router is serving.
//!
//! The twin of `sni_demux::routes_file`, with the same reload policy for the
//! same reason, over [`HostTable`] instead of the demux's `RouteTable`. The
//! other end is `yubaba::demux_routes`, which sweeps the enrollment set once
//! and writes both tiers' files with tmp-plus-rename.
//!
//! ## Reload policy: never make the table worse
//!
//! The watcher polls the file's bytes and swaps only on a strictly better
//! answer. An unreadable file, an unparseable one, and one that parses to an
//! **empty** table all leave the live table exactly as it was, loudly:
//!
//! - unreadable → the publisher may be mid-rename on another filesystem, or
//!   the file was removed by a bad deploy;
//! - unparseable → a truncated or hand-edited file;
//! - empty → indistinguishable from "every tenant was deleted", and the
//!   difference between a no-op and a total outage.
//!
//! This mirrors `main.rs` refusing to *start* on an empty table, and the
//! publisher's own refusal to write one. The cost you meet in practice is
//! that un-enrolling the LAST domain needs a restart; that is the right way
//! round, and the same trade the `:443` tier makes.
//!
//! In-flight connections are never affected: [`current`] hands each accepted
//! connection its own `Arc`, so a swap changes where the *next* request goes
//! and nothing else.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::route::{HostTable, RouteParseError};

/// The live table, swappable underneath the accept loop.
///
/// `std::sync::RwLock`, not tokio's: the critical section is one `Arc::clone`
/// and nothing awaits inside it, so an async lock would buy a scheduler hop
/// for no reason.
pub type SharedRoutes = Arc<RwLock<Arc<HostTable>>>;

/// Wrap a table so it can be swapped.
pub fn shared(table: HostTable) -> SharedRoutes {
    shared_arc(Arc::new(table))
}

/// [`shared`] for a table already behind an `Arc`.
pub fn shared_arc(table: Arc<HostTable>) -> SharedRoutes {
    Arc::new(RwLock::new(table))
}

/// Snapshot the live table for one connection.
///
/// Recovers from a poisoned lock rather than panicking: the only writer is
/// [`watch`], which holds the lock across a single `Arc` assignment and cannot
/// leave a torn value behind — so a poisoned lock here means some *other* task
/// panicked while reading, and refusing to route every subsequent connection
/// over that would turn one panic into an outage.
pub fn current(routes: &SharedRoutes) -> Arc<HostTable> {
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
    /// The file's contents are not `host=disposition` entries.
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
                "no routes — a router with an empty table would refuse every host"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Read and parse a routes file. Never returns an empty table.
pub fn load(path: &Path) -> Result<HostTable, LoadError> {
    let text = std::fs::read_to_string(path).map_err(LoadError::Io)?;
    let table = HostTable::parse(&text).map_err(LoadError::Parse)?;
    if table.is_empty() {
        return Err(LoadError::Empty);
    }
    Ok(table)
}

/// Poll `path` every `interval` and swap `routes` when its contents change
/// into a table that parses non-empty.
///
/// Content comparison, not mtime: a `touch`, a redeploy or a clock skew must
/// not cost a re-parse of a big table — and, more importantly, a table that
/// changed *back* between two polls must still be noticed.
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
        // Remember the bytes even when they fail to parse: a broken file
        // should be complained about once, not once per poll forever.
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
        let table = match HostTable::parse(&text) {
            Ok(t) if t.is_empty() => {
                log::warn!(
                    "routes file {}: parsed to zero routes; keeping the live table \
                     rather than refusing every host",
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
    use crate::route::Disposition;

    fn write(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("routes");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn proxy(p: u16) -> Disposition {
        Disposition::Proxy(format!("127.0.0.1:{p}").parse().unwrap())
    }

    #[test]
    fn loads_one_entry_per_line_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "# published by yubaba, do not edit\n\
             a.example.com=redirect\n\
             *.example.net=127.0.0.1:8080   # a whole tenant, one line\n\
             \n",
        );
        let t = load(&path).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.lookup("a.example.com"), Some(Disposition::Redirect));
        assert_eq!(t.lookup("x.example.net"), Some(proxy(8080)));
    }

    #[test]
    fn an_empty_or_missing_or_broken_file_never_loads() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(&write(dir.path(), "# only a comment\n")),
            Err(LoadError::Empty)
        ));
        assert!(matches!(
            load(&write(dir.path(), "a.example=notanaddr\n")),
            Err(LoadError::Parse(_))
        ));
        assert!(matches!(
            load(&dir.path().join("nope")),
            Err(LoadError::Io(_))
        ));
    }

    #[tokio::test]
    async fn the_watcher_swaps_forward_and_never_backward() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "a.example.com=redirect\n");
        let routes = shared(load(&path).unwrap());
        let handle = tokio::spawn(watch(
            path.clone(),
            routes.clone(),
            Duration::from_millis(10),
        ));

        // A real change is picked up.
        std::fs::write(
            &path,
            "a.example.com=redirect\nb.example.com=127.0.0.1:8080\n",
        )
        .unwrap();
        let swapped = until(|| current(&routes).len() == 2).await;
        assert!(swapped, "the watcher never picked up the new entry");
        assert_eq!(current(&routes).lookup("b.example.com"), Some(proxy(8080)));

        // Each of the three "worse" answers leaves the live table alone.
        for worse in ["", "# every tenant deleted\n", "garbage\n"] {
            std::fs::write(&path, worse).unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert_eq!(current(&routes).len(), 2, "swapped to {worse:?}");
        }
        std::fs::remove_file(&path).unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(current(&routes).len(), 2, "swapped on a missing file");
        handle.abort();
    }

    async fn until(mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}
