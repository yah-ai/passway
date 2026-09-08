//! `passway-http-router` binary — env-configured, like `passway` and
//! `passway-demux`.
//!
//! | Variable | Meaning | Default |
//! |---|---|---|
//! | `PASSWAY_HTTP_ROUTER_LISTEN` | address to bind when no socket is inherited | `0.0.0.0:80` |
//! | `PASSWAY_HTTP_ROUTER_ROUTES` | `host=redirect,host=addr,...`; `*.example.com=` one-label wildcard, `*=` catch-all | required unless `_FILE` is set |
//! | `PASSWAY_HTTP_ROUTER_ROUTES_FILE` | same entries, one per line, `#` comments — reloaded while serving | unset |
//! | `PASSWAY_HTTP_ROUTER_ROUTES_RELOAD_SECS` | how often `_FILE` is re-read | `10` |
//! | `PASSWAY_HTTP_ROUTER_READ_TIMEOUT_SECS` | deadline for a complete request head | `5` |
//! | `PASSWAY_HTTP_ROUTER_CONNECT_TIMEOUT_SECS` | deadline for the backend TCP connect | `5` |
//! | `PASSWAY_HTTP_ROUTER_MAX_CONNS` | concurrent connections | `10000` |
//!
//! The prefix is `PASSWAY_HTTP_ROUTER_`, not `PASSWAY_HTTP_`, because
//! `PASSWAY_HTTP_REDIRECT_BIND` already means something else and lives in a
//! sibling env file on the same box: it arms the SINGLE-tenant `:80`
//! redirect inside a `passway` process. The two are alternatives — a node
//! running this router must NOT also set that, or whichever binds second
//! loses `:80` (see `passway::redirect`, "port 80 has another claimant").
//!
//! `PASSWAY_HTTP_ROUTER_ROUTES_FILE` takes precedence when both are set, and
//! is what `yubaba::demux_routes` writes from the tenant enrollment set
//! (`YUBABA_HTTP_ROUTES_FILE`) — it is how a domain registered after this
//! process started becomes routable without a restart. See
//! [`http_router::routes_file`] for the reload policy.
//!
//! ## Socket activation
//!
//! If `LISTEN_FDS=1` is set (and `LISTEN_PID`, when present, names this
//! process), fd 3 is adopted as the listener instead of binding
//! `PASSWAY_HTTP_ROUTER_LISTEN`. Same contract `passway-demux` and
//! `mesofact-serve` speak.
//!
//! Example — one apex redirecting, one tenant validating by `http-01`:
//!
//! ```text
//! PASSWAY_HTTP_ROUTER_ROUTES='yah.dev=redirect,*.yah.dev=redirect,tenant.example=127.0.0.1:8081'
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use http_router::{routes_file, serve_shared, HostTable, RouterOptions};
use tokio::net::TcpListener;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_secs(key: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(key)
            .ok()
            .map(|v| {
                v.parse()
                    .unwrap_or_else(|_| panic!("{key} must be an integer number of seconds"))
            })
            .unwrap_or(default),
    )
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // A published routes file wins over the static env var: a node running the
    // yubaba publisher has a table that changes as tenants register, and an
    // env var frozen at exec time would silently shadow it.
    let routes_file = std::env::var("PASSWAY_HTTP_ROUTER_ROUTES_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from);
    let table = match &routes_file {
        Some(path) => routes_file::load(path)
            .unwrap_or_else(|e| panic!("PASSWAY_HTTP_ROUTER_ROUTES_FILE {}: {e}", path.display())),
        None => {
            let routes = std::env::var("PASSWAY_HTTP_ROUTER_ROUTES").expect(
                "PASSWAY_HTTP_ROUTER_ROUTES or PASSWAY_HTTP_ROUTER_ROUTES_FILE is required",
            );
            let table = HostTable::parse(&routes)
                .unwrap_or_else(|e| panic!("PASSWAY_HTTP_ROUTER_ROUTES: {e}"));
            if table.is_empty() {
                panic!(
                    "PASSWAY_HTTP_ROUTER_ROUTES is empty — a router with no routes would refuse every host"
                );
            }
            table
        }
    };

    let opts = RouterOptions {
        read_timeout: env_secs("PASSWAY_HTTP_ROUTER_READ_TIMEOUT_SECS", 5),
        connect_timeout: env_secs("PASSWAY_HTTP_ROUTER_CONNECT_TIMEOUT_SECS", 5),
        max_connections: env_or("PASSWAY_HTTP_ROUTER_MAX_CONNS", "10000")
            .parse()
            .expect("PASSWAY_HTTP_ROUTER_MAX_CONNS must be an integer"),
    };

    let listener = match socket_activation_listener() {
        Ok(Some(l)) => {
            log::info!(
                "passway-http-router serving on inherited LISTEN_FDS socket, {} routes",
                table.len()
            );
            l
        }
        Ok(None) => {
            let addr = env_or("PASSWAY_HTTP_ROUTER_LISTEN", "0.0.0.0:80");
            let l = TcpListener::bind(&addr)
                .await
                .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
            log::info!(
                "passway-http-router listening on {addr}, {} routes",
                table.len()
            );
            l
        }
        Err(e) => panic!("adopting LISTEN_FDS socket: {e}"),
    };

    let routes = routes_file::shared_arc(Arc::new(table));
    if let Some(path) = routes_file {
        let reload = env_secs("PASSWAY_HTTP_ROUTER_ROUTES_RELOAD_SECS", 10);
        log::info!(
            "passway-http-router reloading {} every {}s",
            path.display(),
            reload.as_secs()
        );
        tokio::spawn(routes_file::watch(path, routes.clone(), reload));
    }
    tokio::select! {
        r = serve_shared(listener, routes, opts) => {
            if let Err(e) = r { log::error!("router exited: {e}"); }
        }
        _ = tokio::signal::ctrl_c() => log::info!("passway-http-router: SIGINT, exiting"),
    }
}

/// Adopt fd 3 under the systemd socket-activation convention. Same shape as
/// `passway-demux`'s `socket_activation_listener` (kept in lockstep with
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
