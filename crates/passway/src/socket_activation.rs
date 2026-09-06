//! R853-F6 — hand an already-listening socket to a pingora `Server`.
//!
//! A supervisor that owns the listening socket across restarts (kamaji's
//! on-demand JIT tier, a systemd `.socket` unit) passes it to the workload as
//! an inherited fd under the `LISTEN_FDS` convention. pingora has no API for
//! adopting such a socket: `Bootstrap::listen_fds` is filled only by the
//! private `load_fds`, `Server::listen_fds` is private, and `ServerAddress`
//! has no fd variant. Its *one* public seam into that table is the upgrade
//! socket — the `SCM_RIGHTS` protocol it uses to inherit listeners from a
//! previous pingora process during a zero-downtime restart. This module
//! speaks that protocol to our own server.
//!
//! This is what replaced a carried pingora fork (`Server::seed_listen_fd`).
//! `spikes/R853-S5-upgrade-socket-handoff/` is the standalone proof against
//! stock crates.io pingora.
//!
//! **The fork was not a mistake made on bad information**, and the record
//! should not be read that way. W267 §"Step 4b" weighed exactly this route in
//! writing on 2026-08-28 — "passway sends fd 3 to *itself* through pingora's
//! public `Fds::send_to_sock` while bootstrapping with `Opt::upgrade = true`.
//! Zero fork, but it rides the upgrade wire format, the socket-path retry loop,
//! and a thread racing bootstrap. Works; points the wrong way. **Rejected.**"
//! The operator took the fork deliberately as "the robust long-term route".
//! Nothing about the API was misread: `pub use transfer_fd::Fds` at
//! `server/mod.rs:50` with `{new, add, send_to_sock, get_from_sock}` all `pub`
//! was known then and is still true.
//!
//! Two things arrived later and reversed the call on evidence rather than on
//! error. (1) R853-S5 *built* the rejected option instead of reasoning about
//! it: 10/10 runs, with an `FDSPIKE_BLOCKING=1` control proving the timing dance
//! is absorbed by both sides' retry loops. The "points the wrong way" worry was
//! real but turned out cheap. (2) The fork's cost was discovered to be larger
//! than priced — `[patch.crates-io]` does not propagate into a published
//! `.crate`, so `cargo install passway --features socket-activation` could not
//! compile for *any* crates.io consumer, which is why `default` had to be
//! reverted to `[]` on 2026-08-31. That was not on the table on 2026-08-28.
//!
//! `patches/` (the carried hunks, the rebase onto upstream `main`, the
//! upstream-PR writeup) was deleted 2026-09-05 by operator decision on R853-T1:
//! with the fork gone there is nothing to upstream on our own behalf.
//! Recoverable at `git show be2680f4:oss/passway/patches/UPSTREAM.md` and
//! siblings if the non-Linux case below ever forces the question.
//!
//! **Linux-only, and not by our choice.** pingora's `get_fds_from` /
//! `send_fds_to` are `#[cfg(target_os = "linux")]` on 0.8.1 and on `main`
//! alike; elsewhere the receive returns `ECONNREFUSED` and `Bootstrap` answers
//! that with `std::process::exit(1)`. Callers must refuse loudly on other
//! platforms rather than binding fresh behind the supervisor's back.

/// Transfer `fd` into the fd table of a pingora `Server` that has not yet been
/// bootstrapped, announcing it under the bind address `bind`.
///
/// Returns the private socket path the caller must assign to
/// `ServerConf::upgrade_sock`, plus the join handle of the sending thread. The
/// caller must also set `Opt::upgrade = true` — `load_fds` runs under no other
/// condition — and must do both *before* constructing the `Server`, since
/// `Bootstrap` copies them out of `Opt`/`ServerConf` at construction.
///
/// A thread is required, and the direction is why: the **receiver**
/// (`Server::bootstrap()`) is what binds and listens on `upgrade_sock`, and the
/// **sender** connects to it. Calling both on one thread deadlocks. Both sides
/// retry — `ENOENT`/`ECONNREFUSED` on connect, `EAGAIN` on accept, 5×1s each on
/// 0.8.1 — so the startup skew between them is absorbed; the spike measured
/// 10/10 clean runs.
///
/// `bind` must equal the address string later passed to `add_tcp` /
/// `add_tls_with_settings` exactly. It is the key pingora looks the fd up by,
/// and it never inspects the fd's real address — which is precisely what makes
/// the adoption test unambiguous.
///
/// The fd is made non-blocking here. A socket bound by the std library — as a
/// supervisor's is — is blocking; neither pingora's `from_raw_fd` nor tokio's
/// `from_std` changes that, so the first accept would stall a worker. Doing it
/// on our own fd before the transfer is what let the third forked hunk go.
#[cfg(all(target_os = "linux", feature = "socket-activation"))]
pub fn spawn_fd_handoff(
    bind: &str,
    fd: std::os::unix::io::RawFd,
) -> std::io::Result<(String, std::thread::JoinHandle<Result<usize, String>>)> {
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    // Round-trip through std purely to set O_NONBLOCK without taking a runtime
    // dependency on libc for one fcntl. `into_raw_fd` hands ownership back
    // without closing, so the fd stays valid for the transfer below.
    let fd = {
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        listener.set_nonblocking(true)?;
        listener.into_raw_fd()
    };

    // Private to this process, and deliberately NOT `PASSWAY_UPGRADE_SOCK`:
    // that path belongs to the real graceful-upgrade handoff between two
    // passway processes, and a seed transfer landing on it would race the
    // predecessor's send.
    let path = format!("/tmp/passway-seed-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);

    let sender_path = path.clone();
    let sender_bind = bind.to_string();
    let handle = std::thread::spawn(move || {
        let mut fds = pingora::server::Fds::new();
        fds.add(sender_bind, fd);
        fds.send_to_sock(sender_path.as_str())
            .map_err(|e| format!("send_to_sock({sender_path}) failed: {e}"))
    });

    Ok((path, handle))
}
