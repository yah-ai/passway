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
//!
//! @yah:ticket(R853-T2, "Put passway-demux on :443 in front of the live passways on us-east-001 and us-south-001")
//! @yah:status(review)
//! @yah:at(2026-09-04T23:53:52Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:next("R779 step 3b, operator-SEQUENCED because these two nodes are live yah.dev origins and the change moves what answers :443. Per node: re-point PASSWAY_LISTEN to a loopback port, run passway-demux on :443 with a route per tenant, verify with `openssl s_client -servername <host>` against each. Routes can now come from PASSWAY_DEMUX_ROUTES_FILE plus the yubaba publisher (yubaba::demux_routes sweeps the enrollment set and rewrites the file tmp-plus-rename; PASSWAY_DEMUX_RELOAD_SECS default 10) instead of the static PASSWAY_DEMUX_ROUTES env var — the file path is the better shape for more than a couple of tenants. Node config lives in .yah/infra/machines/.")
//! @yah:gotcha("THREE LAYERS DELIBERATELY REFUSE AN EMPTY ROUTE TABLE — the publisher will not write one, the loader will not start on one, the watcher will not swap to one. A successful listing of an empty bucket and a bucket pointed at the wrong prefix are the same answer, and one of them de-routes every tenant at once. The cost you will meet in practice: unenrolling the LAST domain needs a demux restart. That is the right way round; do not \"fix\" it. One level down the trade flips — a malformed enrolled/ object is skipped with a warning, because one corrupt key should cost one tenant's route rather than everyone's.")
//! @yah:gotcha("The demux links NO TLS library, holds no key and sees no plaintext — that is the load-bearing R777 invariant that keeps a cross-tenant RCE contained at 10k domains, and it is why routes arrive as a FILE rather than a bucket API call in either direction: a bucket client on the shared public :443 would hand a compromise of it both the whole fleet's routing and the credential to change it. Do not add one while wiring this up.")
//! @yah:next("The :80 tier is still SINGLE-TENANT and is now the narrowest thing between here and a second apex. The demux only speaks TLS; passway owns 0.0.0.0:80 directly on each node for the 308 redirect, so tenant #2 gets no scheme-less redirect. W267 already names the fix (an :80 Host-router beside the demux, Enrollment::http_backend is carried unused for exactly this). Not blocking noisetable.com — https:// works fine — but any scheme-less URL it documents will be refused.")
//! @yah:handoff("ROUTES COME FROM A FILE, NOT THE ENV VAR, even though there are only two hostnames today — deliberately, and it is the whole reason the next tenant is cheap. PASSWAY_DEMUX_ROUTES_FILE=/etc/passway-demux.routes with _RELOAD_SECS=10. The static PASSWAY_DEMUX_ROUTES spelling would have made every future enrollment a demux restart, i.e. a :443 gap per tenant. When yubaba::demux_routes takes over, point YUBABA_DEMUX_ROUTES_FILE at this same path and stop hand-editing. Table is deliberately CATCH-ALL FREE: 'yah.dev' exact + '*.yah.dev' one-label, nothing else, so the table is the on-demand-TLS allowlist W267 Decision 2 specifies and an unknown SNI can never provoke an ACME order.")
//! @yah:verify("HOT ENROLLMENT PROVEN END TO END ON THE LIVE east DEMUX, which is the claim the whole ticket exists to make good: `openssl s_client -servername noisetable.com` -> alert 112; appended one line to /etc/passway-demux.routes; 13s later the same command -> subject=CN=*.yah.dev (routed and spliced, cert mismatch expected since no noisetable passway exists yet); removed the line; 13s later -> alert 112 again. `systemctl show passway-demux -p NRestarts` = 0 throughout, journal shows 'reloaded, 2 routes' -> '3 routes' -> '2 routes'. Probe line reverted; final table is the two yah.dev entries.")
//! @yah:gotcha("`pkill -f passway-demux` IN AN SSH COMMAND KILLS ITS OWN SHELL — cost me one aborted run. The remote `bash -c '...'` carries the pattern in its own argv, so -f matches the script and it dies mid-way. First attempt therefore made NO change at all (verified: env unchanged, no rollback file written, site still 200) rather than half of one, which is the lucky failure mode. Use `pkill -x passway-demux` (name-only match) on these boxes.")
//! @yah:handoff("DONE AND LIVE ON BOTH ORIGINS (2026-09-04, @Ashguard:blade, session:9ee43749, operator-authorized in chat). passway-demux 0.8.32 x86_64-unknown-linux-musl static-pie, cross-built from the camp Mac in 7s (2.7 MB; oss/passway is rustls so no sysroot), installed /usr/local/bin/passway-demux + /etc/passway-demux.{env,routes} + /etc/systemd/system/passway-demux.service, enabled. us-east-001 PASSWAY_LISTEN 0.0.0.0:443 -> 127.0.0.1:8443 (unit passway-test, env /etc/passway-test.env); us-south-001 the same (unit passway, env /etc/passway.env). Both env files backed up as *.env.rollback-20260904-demux. ROLLBACK is per node: `systemctl disable --now passway-demux; cp /etc/<env>.rollback-20260904-demux /etc/<env>; systemctl restart <passway unit>` — one file and two commands, no binary change.")
//! @yah:verify("SMOKE-TESTED ON EACH BOX BEFORE IT TOUCHED :443 — demux started on 127.0.0.1:9443 routing to the still-live passway on :443, curl through it 200/43488, only then the flip. On south the flip was gated on that smoke returning exactly 200. PUBLIC, AFTER, per origin with --resolve: east yah.dev/ 200 43488, /releases 200 40224, www.yah.dev 200 43488, passway-test.yah.dev 200 43488, issues.yah.dev GET /issues 405 (the tracker answering, so the PASSWAY_UPSTREAMS static pin survived the flip — a 404 HTML body would have meant it had fallen through to the marketing bundle); south yah.dev/ 200 43488, /releases 200 40224. Unknown SNI on both public :443 -> TLS alert 112 unrecognized_name. `yah cloud ingress verify --path .` = 2 rule(s) across 2 front door(s), 2 reachable AND serving, 0 not.")
//! @yah:handoff("R779 STEP 3B IS DONE — the demux is on :443 on both live origins and yah.dev is unchanged from the outside. This unblocks a second apex: the remaining work for noisetable.com is a passway process on a free loopback port with its own cert, one line in /etc/passway-demux.routes on each origin, and a grey A record — no change to anything yah.dev touches. Filed R853-B7 for a pre-existing south cert defect found while verifying (apex-only SAN + TLS-manual, so subdomains fail on half the round-robin and the cert expires unrenewed on 2026-11-10); it is independent of this ticket and does not block a second tenant.")
//! @yah:gotcha("FIXED IN PASS, one line, same class as the work: us-south-001 had NOTHING on :80. app/yah/web/marketing/src/releases.ts's R330-F37 handoff states 'passway now owns :80 on both origins and answers 308' — that was true of east and never of south, so every scheme-less `curl yah.dev/install.sh` that resolved to south was refused while the identical command on east worked, for as long as the apex has been round-robin. Added PASSWAY_HTTP_REDIRECT_BIND=0.0.0.0:80 to /etc/passway.env with a comment; both origins now answer 308 -> https://yah.dev/install.sh. Safe on south because that door is TLS-manual, so no http-01 responder wants :80.")
//!
//! @yah:relay(R870, "Second tenant on the sovereign front door: the tiers and rails a non-yah.dev apex still lacks")
//! @yah:at(2026-09-05T20:31:00Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)

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
