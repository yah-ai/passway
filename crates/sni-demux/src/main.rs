//! `passway-demux` binary — env-configured, like `passway` itself.
//!
//! | Variable | Meaning | Default |
//! |---|---|---|
//! | `PASSWAY_DEMUX_LISTEN` | address to bind when no socket is inherited | `0.0.0.0:443` |
//! | `PASSWAY_DEMUX_ROUTES` | `host=addr,...`; `*.example.com=` one-label wildcard, `*=` catch-all | required unless `_FILE` is set |
//! | `PASSWAY_DEMUX_ROUTES_FILE` | same entries, one per line, `#` comments — reloaded while serving | unset |
//! | `PASSWAY_DEMUX_ROUTES_RELOAD_SECS` | how often `_FILE` is re-read | `10` |
//! | `PASSWAY_DEMUX_PEEK_TIMEOUT_SECS` | deadline for a complete ClientHello | `5` |
//! | `PASSWAY_DEMUX_CONNECT_TIMEOUT_SECS` | deadline for the backend TCP connect | `5` |
//! | `PASSWAY_DEMUX_MAX_CONNS` | concurrent spliced connections | `10000` |
//!
//! `PASSWAY_DEMUX_ROUTES_FILE` takes precedence when both are set, and is what
//! `yubaba::demux_routes` writes from the tenant enrollment set (R779 / W267) —
//! it is how a domain registered after this process started becomes routable
//! without a restart. See [`sni_demux::routes_file`] for the reload policy.
//!
//! ## Socket activation
//!
//! If `LISTEN_FDS=1` is set (and `LISTEN_PID`, when present, names this
//! process), fd 3 is adopted as the listener instead of binding
//! `PASSWAY_DEMUX_LISTEN`. Same contract `mesofact-serve` speaks and
//! kamaji's JIT tier (`kamaji/src/jit.rs`) provides — so kamaji can hold
//! `:443` in custody and the demux takes a binary upgrade without ever
//! releasing the port. The demux is hot by design and does not self-reap.
//!
//! Example — two tenants behind one IP, each its own passway on a loopback
//! port:
//!
//! ```text
//! PASSWAY_DEMUX_ROUTES='*.yah.dev=127.0.0.1:8443,yah.dev=127.0.0.1:8443,tenant.example=127.0.0.1:8444'
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sni_demux::{routes_file, serve_shared, DemuxOptions, RouteTable};
use tokio::net::TcpListener;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_secs(key: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(key)
            .ok()
            .map(|v| v.parse().unwrap_or_else(|_| panic!("{key} must be an integer number of seconds")))
            .unwrap_or(default),
    )
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // A published routes file wins over the static env var: a node running the
    // yubaba publisher has a table that changes as tenants register, and an
    // env var frozen at exec time would silently shadow it.
    let routes_file = std::env::var("PASSWAY_DEMUX_ROUTES_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from);
    let table = match &routes_file {
        Some(path) => routes_file::load(path)
            .unwrap_or_else(|e| panic!("PASSWAY_DEMUX_ROUTES_FILE {}: {e}", path.display())),
        None => {
            let routes =
                std::env::var("PASSWAY_DEMUX_ROUTES").expect(
                    "PASSWAY_DEMUX_ROUTES or PASSWAY_DEMUX_ROUTES_FILE is required",
                );
            let table =
                RouteTable::parse(&routes).unwrap_or_else(|e| panic!("PASSWAY_DEMUX_ROUTES: {e}"));
            if table.is_empty() {
                panic!(
                    "PASSWAY_DEMUX_ROUTES is empty — a demux with no routes would close every connection"
                );
            }
            table
        }
    };

    let opts = DemuxOptions {
        peek_timeout: env_secs("PASSWAY_DEMUX_PEEK_TIMEOUT_SECS", 5),
        connect_timeout: env_secs("PASSWAY_DEMUX_CONNECT_TIMEOUT_SECS", 5),
        max_connections: env_or("PASSWAY_DEMUX_MAX_CONNS", "10000")
            .parse()
            .expect("PASSWAY_DEMUX_MAX_CONNS must be an integer"),
    };

    let listener = match socket_activation_listener() {
        Ok(Some(l)) => {
            log::info!("passway-demux serving on inherited LISTEN_FDS socket, {} routes", table.len());
            l
        }
        Ok(None) => {
            let addr = env_or("PASSWAY_DEMUX_LISTEN", "0.0.0.0:443");
            let l = TcpListener::bind(&addr)
                .await
                .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
            log::info!("passway-demux listening on {addr}, {} routes", table.len());
            l
        }
        Err(e) => panic!("adopting LISTEN_FDS socket: {e}"),
    };

    let routes = routes_file::shared_arc(Arc::new(table));
    if let Some(path) = routes_file {
        let reload = env_secs("PASSWAY_DEMUX_ROUTES_RELOAD_SECS", 10);
        log::info!(
            "passway-demux reloading {} every {}s",
            path.display(),
            reload.as_secs()
        );
        tokio::spawn(routes_file::watch(path, routes.clone(), reload));
    }
    tokio::select! {
        r = serve_shared(listener, routes, opts) => {
            if let Err(e) = r { log::error!("demux exited: {e}"); }
        }
        _ = tokio::signal::ctrl_c() => log::info!("passway-demux: SIGINT, exiting"),
    }
}

/// Adopt fd 3 under the systemd socket-activation convention. Same shape as
/// `mesofact-serve`'s `socket_activation_listener` (kept in lockstep with
/// kamaji's `LISTEN_FD_CHILD = 3`).
#[cfg(unix)]
fn socket_activation_listener() -> std::io::Result<Option<TcpListener>> {
    use std::os::fd::FromRawFd;

    let n_fds: i32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if n_fds < 1 {
        return Ok(None);
    }
    if let Ok(pid) = std::env::var("LISTEN_PID") {
        if pid.parse::<u32>().ok() != Some(std::process::id()) {
            return Ok(None);
        }
    }
    const SD_LISTEN_FDS_START: i32 = 3;
    // SAFETY: the socket-activation contract guarantees fd 3 is a listening
    // socket passed to us and that we are its sole owner; we take exclusive
    // ownership of exactly one fd and never touch fd 3 by number again.
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(SD_LISTEN_FDS_START) };
    std_listener.set_nonblocking(true)?;
    Ok(Some(TcpListener::from_std(std_listener)?))
}

#[cfg(not(unix))]
fn socket_activation_listener() -> std::io::Result<Option<TcpListener>> {
    Ok(None)
}
