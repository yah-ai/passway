//! The accept → read → route → answer-or-splice loop.
//!
//! Per connection:
//!
//! 1. **Read** the request head into a buffer bounded by
//!    [`head::MAX_HEAD_BYTES`], feeding [`parse_head`] until it reaches a
//!    verdict. The whole read is under one deadline
//!    ([`RouterOptions::read_timeout`]): a client that connects and trickles
//!    one byte a second is cut off, and so is one that connects and says
//!    nothing. Nothing is *consumed* in a way a backend would miss — the
//!    buffered bytes are replayed verbatim before the splice starts.
//! 2. **Route** on the `Host` header, via
//!    [`redirect::route_key`](crate::redirect::route_key) so a name that
//!    cannot be safely echoed also cannot be routed. No `Host` → `400`; no
//!    match → `404` and close. Not HTTP at all → close without a word.
//! 3. **Answer or splice.** [`Disposition::Redirect`] is written here and the
//!    connection closes. [`Disposition::Proxy`] dials under
//!    [`RouterOptions::connect_timeout`], replays the buffered bytes and hands
//!    both halves to `copy_bidirectional`.
//!
//! Concurrency is capped by a semaphore ([`RouterOptions::max_connections`])
//! acquired *before* `accept`, so under overload the excess stays in the
//! kernel backlog rather than in this process's memory.
//!
//! ## One connection, one host
//!
//! A connection is routed by its **first** request and never re-examined.
//! HTTP/1.1 permits a client to reuse a connection for a different `Host`, so
//! a pipelined second request could in principle reach the first request's
//! backend. Two things keep that from being a tenant-boundary hole: every
//! response this process writes itself carries `Connection: close`, so the
//! redirect leg — which is every enrolled domain by default — never invites a
//! second request; and the proxy leg's backend is an ACME `http-01` responder,
//! which serves one challenge path and answers `404` to everything else, so a
//! misdirected follow-up gets a wrong answer rather than another tenant's
//! data. Re-parsing every request would mean buffering and re-emitting request
//! bodies on the shared plaintext tier, which is a much larger surface than
//! the one it closes. This is the same trade `haproxy` makes in `mode tcp`.
//!
//! ## What this process never has
//!
//! No private key, no TLS library, no credential, no HTTP client. It reads one
//! request head and then either writes a fixed-shape response or copies bytes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::head::{self, parse_head, HeadError};
use crate::redirect;
use crate::route::{Disposition, HostTable};

/// Tunables. `Default` is what the binary ships with.
#[derive(Debug, Clone)]
pub struct RouterOptions {
    /// Deadline for the client to deliver a complete request head.
    pub read_timeout: Duration,
    /// Deadline for the TCP connect to a proxied backend.
    pub connect_timeout: Duration,
    /// Maximum concurrently handled connections.
    pub max_connections: usize,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            // Same budget as the demux's ClientHello peek, for the same
            // reason: generous for a lossy mobile path, short enough that a
            // slowloris costs an attacker one fd-per-5-s per source.
            read_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            max_connections: 10_000,
        }
    }
}

/// How one connection ended. Logged at `debug` (ordinary internet background
/// noise) except `Backend*`, which is `warn` — that one is ours.
#[derive(Debug)]
pub enum Verdict {
    /// Answered `308`; carries the host and the `Location` written.
    Redirected { host: String, location: String },
    /// Spliced to a backend; carries the routed host.
    Proxied { host: String, backend: SocketAddr },
    /// Read deadline elapsed before a full head arrived.
    ReadTimeout,
    /// Client closed before sending a full head.
    ClientClosed,
    /// The head could not be parsed. `NotHttp` closed silently; the rest were
    /// answered `400`.
    BadRequest(HeadError),
    /// Parsed fine, no route for the host (or no `Host` at all). Answered.
    Unrouted { host: Option<String> },
    /// Backend did not accept within `connect_timeout`.
    BackendTimeout { host: String, backend: SocketAddr },
    /// Backend connect failed, or dropped the replayed head.
    BackendRefused {
        host: String,
        backend: SocketAddr,
        err: std::io::Error,
    },
}

/// Run the router on an already-bound listener over a fixed table.
pub async fn serve(
    listener: TcpListener,
    table: Arc<HostTable>,
    opts: RouterOptions,
) -> std::io::Result<()> {
    serve_shared(listener, crate::routes_file::shared_arc(table), opts).await
}

/// [`serve`] over a table that may be swapped while it runs.
///
/// Each accepted connection takes its own snapshot, so a reload changes where
/// the *next* connection goes and leaves every in-flight one alone.
pub async fn serve_shared(
    listener: TcpListener,
    routes: crate::routes_file::SharedRoutes,
    opts: RouterOptions,
) -> std::io::Result<()> {
    let permits = Arc::new(Semaphore::new(opts.max_connections));
    loop {
        // Acquire before accept: overload stays in the kernel backlog.
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("router semaphore is never closed");
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // EMFILE and friends: back off rather than spin.
                log::warn!("accept failed: {e}; pausing 100ms");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let table = crate::routes_file::current(&routes);
        let opts = opts.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let v = handle(stream, &table, &opts).await;
            match &v {
                Verdict::BackendTimeout { host, backend }
                | Verdict::BackendRefused { host, backend, .. } => {
                    log::warn!("{peer} host={host} -> {backend}: {v:?}")
                }
                other => log::debug!("{peer}: {other:?}"),
            }
        });
    }
}

/// Handle one accepted connection to completion. Public so a test (or an
/// embedding binary) can drive it against an arbitrary stream.
pub async fn handle(mut client: TcpStream, table: &HostTable, opts: &RouterOptions) -> Verdict {
    let _ = client.set_nodelay(true);

    // ---- 1. read -----------------------------------------------------------
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let read = tokio::time::timeout(opts.read_timeout, async {
        loop {
            match parse_head(&buf) {
                Ok(h) => return Ok(Ok(h)),
                Err(HeadError::Incomplete) => {
                    // `Incomplete` implies `buf.len() < MAX_HEAD_BYTES` — past
                    // that, `parse_head` answers `TooLarge` — so the buffer is
                    // bounded at one chunk over the cap without a clamp here.
                    let old = buf.len();
                    debug_assert!(old < head::MAX_HEAD_BYTES);
                    buf.resize(old + 1024, 0);
                    match client.read(&mut buf[old..]).await {
                        Ok(0) => {
                            buf.truncate(old);
                            return Err(());
                        }
                        Ok(n) => buf.truncate(old + n),
                        Err(_) => {
                            buf.truncate(old);
                            return Err(());
                        }
                    }
                }
                Err(e) => return Ok(Err(e)),
            }
        }
    })
    .await;

    let head = match read {
        Err(_elapsed) => return Verdict::ReadTimeout,
        Ok(Err(())) => return Verdict::ClientClosed,
        // Nothing to say to something that is not speaking HTTP.
        Ok(Ok(Err(HeadError::NotHttp))) => {
            let _ = client.shutdown().await;
            return Verdict::BadRequest(HeadError::NotHttp);
        }
        Ok(Ok(Err(e))) => {
            answer(&mut client, &redirect::bad_request_response()).await;
            return Verdict::BadRequest(e);
        }
        Ok(Ok(Ok(h))) => h,
    };

    // ---- 2. route ----------------------------------------------------------
    // An HTTP/1.1 request without a `Host`, or with one that is not a bare
    // name, is a `400` — there is no host to route it by and none to echo.
    let Some(raw_host) = head.host.as_deref() else {
        answer(&mut client, &redirect::bad_request_response()).await;
        return Verdict::Unrouted { host: None };
    };
    let Some(key) = redirect::route_key(raw_host) else {
        answer(&mut client, &redirect::bad_request_response()).await;
        return Verdict::Unrouted {
            host: Some(raw_host.to_string()),
        };
    };
    let Some(disposition) = table.lookup(&key) else {
        answer(&mut client, &redirect::unrouted_response()).await;
        return Verdict::Unrouted { host: Some(key) };
    };

    // ---- 3. answer or splice ----------------------------------------------
    let backend = match disposition {
        Disposition::Redirect => {
            return match redirect::redirect_target(&head.target, raw_host) {
                Some(location) => {
                    answer(&mut client, &redirect::moved_permanently(&location)).await;
                    Verdict::Redirected {
                        host: key,
                        location,
                    }
                }
                // Routed, but the target is not one we will echo into a
                // `Location` (absolute-form, `OPTIONS *`, CR/LF).
                None => {
                    answer(&mut client, &redirect::bad_request_response()).await;
                    Verdict::BadRequest(HeadError::Malformed)
                }
            };
        }
        Disposition::Proxy(addr) => addr,
    };

    let mut upstream =
        match tokio::time::timeout(opts.connect_timeout, TcpStream::connect(backend)).await {
            Err(_) => return Verdict::BackendTimeout { host: key, backend },
            Ok(Err(err)) => {
                return Verdict::BackendRefused {
                    host: key,
                    backend,
                    err,
                }
            }
            Ok(Ok(s)) => s,
        };
    let _ = upstream.set_nodelay(true);

    // Replay everything read so far so the backend sees the stream from byte
    // 0 — including any body bytes that arrived in the same segment as the
    // head.
    if upstream.write_all(&buf).await.is_err() {
        return Verdict::BackendRefused {
            host: key,
            backend,
            err: std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "backend closed on head replay",
            ),
        };
    }
    drop(buf);
    // Errors here are the ordinary end-of-life of a TCP pair (RST from either
    // side); the connection is done either way.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Verdict::Proxied { host: key, backend }
}

/// Write one response and close the write half. Best effort — the client may
/// already be gone, and there is no second thing to try.
async fn answer(client: &mut TcpStream, response: &str) {
    let _ = client.write_all(response.as_bytes()).await;
    let _ = client.shutdown().await;
}
