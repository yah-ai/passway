//! R779 — cold start, end to end: **SNI demux → held socket → no process at
//! all**, until the first connection forks one.
//!
//! `socket_activation.rs` proves the narrow thing (pingora adopts an inherited
//! fd under the bind string). This proves the thing that adoption exists *for*,
//! against the real binary rather than an in-process `Server`:
//!
//! 1. A supervisor stand-in binds and **holds** a listener and never `accept()`s
//!    — the [`kamaji::jit`] contract (`oss/kamaji/crates/kamaji/src/jit.rs`)
//!    reproduced in ~40 lines so this test needs no dependency on kamaji, which
//!    is a different workspace. Same three moves: arm a readable-watch, fork the
//!    binary with the held socket `dup2`'d to fd 3 under `LISTEN_FDS=1`, wait,
//!    re-arm.
//! 2. The real [`sni_demux`] runs in-process on its own port with one route,
//!    `tenant.example` → the held socket's address. It peeks the ClientHello and
//!    splices; it never terminates TLS, so the cert below is only ever seen by
//!    passway.
//! 3. A TLS client asks for `https://tenant.example:<demux>/`.
//!
//! The four assertions, in the order the lifecycle produces them:
//!
//! - **zero-resident when armed** — no passway process before the first
//!   connection;
//! - **lazy fork + serve** — the first request forks exactly one passway, which
//!   adopts fd 3, terminates TLS for the SNI the demux routed on, and proxies to
//!   the upstream;
//! - **self-reap** — that process exits on its own after `PASSWAY_IDLE_TTL_SECS`
//!   with nothing in flight (the supervisor is not what kills it);
//! - **re-fork over the same socket** — a later request is served again, because
//!   the listener belonged to the supervisor the whole time.
//!
//! The deadlock this catches if it ever regresses: passway binding fresh under a
//! supervisor that already holds the port, which fails at *runtime* on the
//! second fork (`EADDRINUSE`) and is invisible to every other test here.
//!
//! **Linux-only since R853-F6**, for the same reason as `socket_activation.rs`:
//! adoption now rides pingora's `SCM_RIGHTS` upgrade protocol, whose helpers
//! are `#[cfg(target_os = "linux")]` upstream. Off Linux the forked passway
//! refuses to start at all — deliberately, rather than binding fresh behind the
//! supervisor's back — so there is nothing here to assert. This test used to
//! run on the darwin dev machines and no longer does; that lost local coverage
//! is the accepted cost of dropping the pingora fork, and this repo has no CI
//! standing behind it.

#![cfg(all(target_os = "linux", feature = "socket-activation"))]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sni_demux::{DemuxOptions, RouteTable};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::common::spawn_fake_upstream;

/// The SNI the demux routes on and the name on the self-signed leaf. Never
/// resolved — the client is told which address to use.
const TENANT: &str = "tenant.example";

/// Short enough that the test does not crawl, long enough that a cold pingora
/// start plus one TCP health-check tick cannot be mistaken for idleness.
const IDLE_TTL_SECS: u64 = 3;

/// The child fd of the socket-activation convention (`SD_LISTEN_FDS_START`).
const LISTEN_FD_CHILD: RawFd = 3;

// ── scratch dir ──────────────────────────────────────────────────────────────

/// This crate deliberately carries no `tempfile` dependency (see `acme.rs`'s
/// test helper); same idiom here.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "passway-jit-cold-start-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── the supervisor stand-in (kamaji's jit.rs, minus kamaji) ──────────────────

/// A raw fd we only ever poll — no `Drop`, because the listener it came from is
/// owned by the test for the whole run. `AsyncFd` deregisters on drop; it does
/// not close.
struct HeldFd(RawFd);

impl AsRawFd for HeldFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Observable lifecycle counters. `forks` increments per spawn, `reaps` per
/// child exit — so `forks == reaps` means nothing is resident right now.
#[derive(Default)]
struct Counters {
    forks: AtomicUsize,
    reaps: AtomicUsize,
}

/// Arm → fork → wait → re-arm, forever. Aborted by dropping the `JoinHandle`.
async fn supervise(
    held: RawFd,
    bin: PathBuf,
    env: Vec<(String, String)>,
    log_dir: PathBuf,
    counters: Arc<Counters>,
) {
    loop {
        // A FRESH registration each cycle observes the socket's *current*
        // readability, so a connection that arrived while the previous child was
        // serving fires immediately rather than waiting for the next edge.
        {
            let watch = AsyncFd::with_interest(HeldFd(held), Interest::READABLE)
                .expect("register held fd with the reactor");
            let guard = watch.readable().await.expect("await readability");
            drop(guard);
        }

        let n = counters.forks.fetch_add(1, Ordering::SeqCst) + 1;
        let out = std::fs::File::create(log_dir.join(format!("passway-{n}.log")))
            .expect("create child log");
        let err = out.try_clone().expect("clone child log handle");

        let mut cmd = tokio::process::Command::new(&bin);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        cmd.env("LISTEN_FDS", "1")
            // LISTEN_PID is the systemd anti-inheritance guard; kamaji cannot
            // set it either (it would need an async-signal-unsafe setenv in the
            // pre_exec hook), and passway accepts it unset. Clear it so an
            // ambient value from the test runner's environment cannot make the
            // child refuse the fd.
            .env_remove("LISTEN_PID")
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true);

        // SAFETY: the closure runs post-fork/pre-exec in the child and calls
        // only async-signal-safe primitives (`dup2`, `fcntl`). `held` is a valid
        // fd for the whole test.
        unsafe {
            cmd.as_std_mut().pre_exec(move || {
                if held != LISTEN_FD_CHILD && libc::dup2(held, LISTEN_FD_CHILD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Explicit, because when `held` is already fd 3 the `dup2` above
                // is skipped and never clears the flag.
                let flags = libc::fcntl(LISTEN_FD_CHILD, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(LISTEN_FD_CHILD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn().expect("fork passway");
        let _ = child.wait().await;
        counters.reaps.fetch_add(1, Ordering::SeqCst);
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Everything the forked binary needs to serve `TENANT` from the held socket.
fn passway_env(listen: SocketAddr, upstream: SocketAddr, scratch: &Scratch) -> Vec<(String, String)> {
    let cert = scratch.path("tenant.crt");
    let key = scratch.path("tenant.key");
    let rcgen::CertifiedKey { cert: leaf, signing_key } =
        rcgen::generate_simple_self_signed(vec![TENANT.to_string()]).expect("self-signed leaf");
    std::fs::write(&cert, leaf.pem()).expect("write cert");
    std::fs::write(&key, signing_key.serialize_pem()).expect("write key");

    vec![
        // The bind string is the fd-table key: it is what passway seeds fd 3
        // under, so it must be the address the supervisor actually holds.
        ("PASSWAY_LISTEN".into(), listen.to_string()),
        ("PASSWAY_TLS_CERT".into(), cert.display().to_string()),
        ("PASSWAY_TLS_KEY".into(), key.display().to_string()),
        ("PASSWAY_UPSTREAMS".into(), upstream.to_string()),
        ("PASSWAY_IDLE_TTL_SECS".into(), IDLE_TTL_SECS.to_string()),
        // Default is 5s; at a 3s idle TTL the first health tick has to land
        // inside the window or the process reaps before it can answer 200.
        ("PASSWAY_HEALTH_CHECK_INTERVAL_SECS".into(), "1".into()),
        // Both default into /tmp with a fixed name — on this shared machine two
        // concurrent runs would fight over them.
        ("PASSWAY_PID_FILE".into(), scratch.path("pingora.pid").display().to_string()),
        (
            "PASSWAY_UPGRADE_SOCK".into(),
            scratch.path("pingora_upgrade.sock").display().to_string(),
        ),
    ]
}

/// A single-use client: after a reap the pooled connection is dead, and reusing
/// one would test reqwest's retry policy rather than the re-fork.
fn tls_client(demux: SocketAddr) -> reqwest::Client {
    reqwest::Client::builder()
        // The leaf is self-signed and its name is never in DNS; what is under
        // test is the SNI routing and the proxy behind it, not PKI.
        .danger_accept_invalid_certs(true)
        // Maps the hostname only — the port comes from the URL.
        .resolve(TENANT, demux)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build TLS client")
}

/// Ask through the demux until a 200 comes back or `deadline` passes. A cold
/// fork plus pingora's first health tick is legitimately slow; a 503 in that
/// window is not a failure, it is the window.
async fn get_until_ok(demux: SocketAddr, deadline: Instant) -> reqwest::Response {
    let url = format!("https://{TENANT}:{}/", demux.port());
    let mut last = String::from("never attempted");
    while Instant::now() < deadline {
        match tls_client(demux).get(&url).send().await {
            Ok(resp) if resp.status() == 200 => return resp,
            Ok(resp) => last = format!("HTTP {}", resp.status()),
            Err(e) => last = format!("{e}"),
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!("no 200 through the demux before the deadline; last attempt: {last}");
}

/// Child stdout/stderr, for a panic message that says *why* rather than just
/// "expected 1, got 0".
fn child_logs(dir: &Path) -> String {
    let mut out = String::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.extension().is_some_and(|e| e == "log") {
            out.push_str(&format!("\n--- {} ---\n", p.display()));
            out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
        }
    }
    out
}

// ── the test ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_start_through_the_demux_forks_serves_and_reaps() {
    let scratch = Scratch::new();
    let upstream = spawn_fake_upstream("jit-upstream").await;

    // The socket the supervisor holds for the whole run. Non-blocking because
    // we poll it; the flag rides the shared file description through `dup2`,
    // and pingora's `from_raw_fd` sets it again on the child side anyway.
    let held = StdTcpListener::bind("127.0.0.1:0").expect("bind held socket");
    held.set_nonblocking(true).expect("held socket non-blocking");
    let held_addr: SocketAddr = held.local_addr().expect("held local_addr");
    let held_fd = held.into_raw_fd();

    // The demux: one route, TENANT → the held socket.
    let demux_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind demux");
    let demux_addr = demux_listener.local_addr().expect("demux local_addr");
    let table = RouteTable::parse(&format!("{TENANT}={held_addr}")).expect("route table");
    let demux_task = tokio::spawn(sni_demux::serve(
        demux_listener,
        Arc::new(table),
        DemuxOptions::default(),
    ));

    let counters = Arc::new(Counters::default());
    let supervisor = tokio::spawn(supervise(
        held_fd,
        PathBuf::from(env!("CARGO_BIN_EXE_passway")),
        passway_env(held_addr, upstream, &scratch),
        scratch.0.clone(),
        Arc::clone(&counters),
    ));

    // ── zero-resident when armed ─────────────────────────────────────────────
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        counters.forks.load(Ordering::SeqCst),
        0,
        "arming the watch must not fork anything — the whole point of the tier"
    );

    // ── lazy fork + serve ────────────────────────────────────────────────────
    let resp = get_until_ok(demux_addr, Instant::now() + Duration::from_secs(30)).await;
    assert_eq!(
        resp.headers()
            .get("x-upstream-tag")
            .and_then(|v| v.to_str().ok()),
        Some("jit-upstream"),
        "the 200 has to have come from the upstream through passway, not from \
         anything else on the path"
    );
    assert_eq!(
        counters.forks.load(Ordering::SeqCst),
        1,
        "exactly one fork served the whole first request{}",
        child_logs(&scratch.0)
    );

    // ── self-reap ────────────────────────────────────────────────────────────
    // Nothing kills the child here: it exits on its own idle TTL. Generous
    // deadline because the clock only starts once the last request finishes.
    let deadline = Instant::now() + Duration::from_secs(IDLE_TTL_SECS + 20);
    while counters.reaps.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        counters.reaps.load(Ordering::SeqCst),
        1,
        "passway must self-reap on PASSWAY_IDLE_TTL_SECS with nothing in flight{}",
        child_logs(&scratch.0)
    );
    assert_eq!(
        counters.forks.load(Ordering::SeqCst),
        1,
        "an idle reap must not itself trigger a re-fork — that would busy-loop \
         the tier at zero traffic"
    );

    // ── re-fork over the same socket ─────────────────────────────────────────
    // The listener never closed, so this connect lands in the kernel accept
    // queue of a socket with no process behind it, and the fork drains it.
    let resp = get_until_ok(demux_addr, Instant::now() + Duration::from_secs(30)).await;
    assert_eq!(
        resp.headers()
            .get("x-upstream-tag")
            .and_then(|v| v.to_str().ok()),
        Some("jit-upstream"),
        "the re-forked passway serves the same upstream{}",
        child_logs(&scratch.0)
    );
    assert_eq!(
        counters.forks.load(Ordering::SeqCst),
        2,
        "the second request forked a second passway{}",
        child_logs(&scratch.0)
    );

    supervisor.abort();
    demux_task.abort();
}
