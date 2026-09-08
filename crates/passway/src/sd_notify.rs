//! R870-T3 — tell systemd who the main process is, so a graceful upgrade can
//! replace it without the unit noticing.
//!
//! ## Why a front door needs this at all
//!
//! A cert rotation on a systemd-supervised door has to swap the process:
//! [`crate::tls`] records that pingora's `TlsSettings` is static, so a renewed
//! cert on disk reaches nobody until a *replacement* process reads it. pingora
//! ships the zero-downtime half of that (`SIGQUIT` + `SCM_RIGHTS` fd handoff to
//! a process started with `PASSWAY_UPGRADE=true`), and passway has wired the
//! signal contract since R594-F7. What was missing is the supervisor half, and
//! it is a systemd problem rather than a pingora one:
//!
//! **`Type=simple` cannot survive the handoff.** systemd equates the unit with
//! the pid it exec'd. When the old passway drains and exits, the unit is
//! "finished" — systemd deactivates it and, under the default
//! `KillMode=control-group`, kills everything left in the cgroup. That is the
//! replacement. `KillMode=process` only trades the kill for a lie: the unit
//! goes inactive (or restart-loops onto an address the replacement now holds)
//! while a live front door serves :443 unsupervised.
//!
//! systemd has exactly one mechanism for "the main process is now a different
//! pid": a `MAINPID=` datagram on `$NOTIFY_SOCKET`, from a unit declared
//! `Type=notify` with `NotifyAccess=all` (so a process that is not the current
//! main one may send it). That is all this module does — ~60 lines and no new
//! dependency, against the alternatives of a hand-rolled supervisor process
//! sitting in front of the door, or two alternating unit files.
//!
//! ## The contract, and who holds each end
//!
//! 1. `passway.service` is `Type=notify`, `NotifyAccess=all`, with an
//!    `ExecReload=` that runs `passway-graceful-upgrade`
//!    (`app/yah/cli/resources/`). The drop-in
//!    `passway-graceful-upgrade.conf` carries all of it, so the two live doors'
//!    hand-written units get it without being overwritten.
//! 2. On *any* start, passway sends `MAINPID=<self>` + `READY=1` right before
//!    `run_forever()`. On a first start `MAINPID` is a no-op (it already is the
//!    main pid); on a replacement start it is the whole point.
//! 3. `systemctl reload passway` runs the script, which spawns the replacement
//!    with `PASSWAY_UPGRADE=true`, waits for it to bind the upgrade socket,
//!    `SIGQUIT`s the old pid, and then blocks until systemd's `MainPID`
//!    actually equals the replacement — because if the script returned first,
//!    the old pid's exit would still read as "the service died".
//!
//! ## Two honest caveats
//!
//! **`READY=1` is sent just before the listeners bind, not after.** pingora's
//! `run_forever()` never returns and binds inside itself, so there is no seam
//! after the bind that is still on this thread. The window is milliseconds and
//! nothing in the fleet orders itself `After=` a passway; on the path this
//! module exists for — the replacement — it is not even inaccurate, since a
//! replacement already owns the inherited listening fd by the time
//! `Server::bootstrap()` has returned, hundreds of lines earlier in `main`.
//!
//! **`Type=notify` makes a slow first ACME issuance fatal.** A door whose first
//! order waits out `PASSWAY_ACME_DNS01_PROPAGATION_SECS` (75s on the mesh door)
//! blocks in `acme::ensure_cert_on_disk` *before* this notification, and
//! systemd's default `TimeoutStartSec=90s` would kill it mid-issuance. The
//! drop-in raises `TimeoutStartSec` for exactly this reason; do not drop that
//! line when adapting it.

use std::io;
use std::path::PathBuf;

/// The variable systemd sets on a `Type=notify` unit. Absent everywhere else,
/// which is what makes every function here inert off systemd.
pub const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";

/// Where a notification datagram should be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyTarget {
    /// An ordinary filesystem `AF_UNIX` path — what a system-manager unit gets
    /// (`/run/systemd/notify`).
    Path(PathBuf),
    /// A Linux abstract-namespace name, carried in `NOTIFY_SOCKET` with a
    /// leading `@`. Stored without it, since the `@` is the encoding and not
    /// part of the name.
    Abstract(Vec<u8>),
}

/// Parse `$NOTIFY_SOCKET` per systemd's own rule: a leading `@` means the
/// abstract namespace, a leading `/` means a filesystem path, anything else is
/// not addressable.
///
/// Rejecting rather than guessing matters here: a mis-parsed target sends the
/// `MAINPID=` handover into nothing, and the failure surfaces as systemd
/// killing the replacement door some seconds later, with no line connecting the
/// two.
pub fn parse_notify_socket(raw: &str) -> Result<NotifyTarget, String> {
    match raw.as_bytes().first() {
        Some(b'@') => Ok(NotifyTarget::Abstract(raw.as_bytes()[1..].to_vec())),
        Some(b'/') => Ok(NotifyTarget::Path(PathBuf::from(raw))),
        _ => Err(format!(
            "{NOTIFY_SOCKET_ENV}={raw:?} is neither an absolute path nor an abstract name (@…)"
        )),
    }
}

/// The datagram passway sends on every start.
///
/// `MAINPID=` first and `READY=1` last, deliberately: systemd reads the tags in
/// order, and a `READY=1` that arrives before the main-pid handover would
/// briefly leave the unit "started" while still pointing at the pid that is
/// draining out.
///
/// Newline-separated `KEY=value` with a trailing newline — systemd's wire
/// format, and the same shape `sd_notify(3)` documents.
pub fn ready_message(pid: u32) -> String {
    format!("MAINPID={pid}\nREADY=1\n")
}

/// Send `message` to `target`.
///
/// Unconnected datagram send, not `connect` + `write`: `/run/systemd/notify` is
/// a shared socket with no per-peer state, and connecting to it buys nothing
/// while adding a failure mode when the manager restarts.
pub fn send(target: &NotifyTarget, message: &str) -> io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    let sock = UnixDatagram::unbound()?;
    match target {
        NotifyTarget::Path(path) => {
            sock.send_to(message.as_bytes(), path)?;
        }
        #[cfg(target_os = "linux")]
        NotifyTarget::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(message.as_bytes(), &addr)?;
        }
        // The abstract namespace is a Linux extension. systemd only exists on
        // Linux, so this arm is unreachable in practice — it is here so the
        // crate keeps compiling on the darwin camp machines rather than
        // gating the whole module behind a cfg nobody can test.
        #[cfg(not(target_os = "linux"))]
        NotifyTarget::Abstract(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract-namespace unix sockets are Linux-only",
            ));
        }
    }
    Ok(())
}

/// Announce this process as the unit's main process and mark it ready.
///
/// Returns `false` when `$NOTIFY_SOCKET` is unset — i.e. every non-systemd
/// run: a bare binary, a test, kamaji's JIT tier. Never panics and never fails
/// the boot: a door that is serving traffic must not exit because it could not
/// tell its supervisor so. A failed send is logged at WARN because the
/// consequence (systemd killing this process at the end of the reload) is
/// otherwise unattributable.
pub fn notify_ready(get: impl Fn(&str) -> Option<String>) -> bool {
    let Some(raw) = get(NOTIFY_SOCKET_ENV).filter(|v| !v.is_empty()) else {
        return false;
    };
    let target = match parse_notify_socket(&raw) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("passway: cannot notify systemd: {e}");
            return false;
        }
    };
    let pid = std::process::id();
    match send(&target, &ready_message(pid)) {
        Ok(()) => {
            log::info!("passway: notified systemd READY with MAINPID={pid}");
            true
        }
        Err(e) => {
            log::warn!(
                "passway: notifying systemd on {raw} failed: {e} — if this is a graceful \
                 upgrade, systemd still believes the draining process is the main one and \
                 will kill this one when it exits"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_path_is_a_path_target() {
        assert_eq!(
            parse_notify_socket("/run/systemd/notify").unwrap(),
            NotifyTarget::Path(PathBuf::from("/run/systemd/notify"))
        );
    }

    #[test]
    fn a_leading_at_is_the_abstract_namespace_and_the_at_is_stripped() {
        assert_eq!(
            parse_notify_socket("@sd-notify").unwrap(),
            NotifyTarget::Abstract(b"sd-notify".to_vec())
        );
    }

    #[test]
    fn a_relative_target_is_refused_rather_than_guessed_at() {
        let err = parse_notify_socket("notify").unwrap_err();
        assert!(err.contains("abstract"), "{err}");
    }

    #[test]
    fn an_empty_target_is_refused() {
        assert!(parse_notify_socket("").is_err());
    }

    #[test]
    fn mainpid_precedes_ready_so_the_handover_lands_first() {
        let msg = ready_message(4242);
        assert_eq!(msg, "MAINPID=4242\nREADY=1\n");
        assert!(msg.find("MAINPID=").unwrap() < msg.find("READY=1").unwrap());
    }

    #[test]
    fn unset_notify_socket_is_a_silent_no_op() {
        assert!(!notify_ready(|_| None));
    }

    #[test]
    fn an_empty_notify_socket_is_a_silent_no_op() {
        assert!(!notify_ready(|_| Some(String::new())));
    }

    /// The real wire path, minus systemd: bind a datagram socket, point
    /// `notify_ready` at it, and read back the exact bytes a manager would.
    #[test]
    fn notify_ready_sends_the_datagram_a_manager_would_read() {
        use std::os::unix::net::UnixDatagram;

        // Hand-rolled scratch dir, matching this crate's own idiom (acme.rs's
        // `TempDir`) rather than taking a dep for one path. Short, because the
        // sun_path limit is 104 bytes on darwin.
        let dir = std::env::temp_dir().join(format!("pw-sdn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("n");
        let listener = UnixDatagram::bind(&path).unwrap();

        let socket = path.to_str().unwrap().to_string();
        assert!(notify_ready(|k| (k == NOTIFY_SOCKET_ENV).then(|| socket.clone())));

        let mut buf = [0u8; 128];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            ready_message(std::process::id())
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
