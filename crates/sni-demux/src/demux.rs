//! The accept → peek → route → splice loop.
//!
//! Per connection:
//!
//! 1. **Peek.** Read the client's first bytes into a buffer bounded by
//!    [`MAX_HELLO_BYTES`], feeding [`parse_sni`] until it reaches a verdict.
//!    The whole peek is under one deadline ([`DemuxOptions::peek_timeout`]):
//!    a client that connects and trickles one byte a second (slowloris on
//!    the peek) is cut off, and so is one that connects and says nothing.
//!    Nothing is *consumed* from the stream in any way the backend would
//!    miss — the buffered bytes are replayed to the backend verbatim before
//!    the splice starts, so the backend sees exactly the byte stream the
//!    client sent.
//! 2. **Route.** [`RouteTable::lookup`]. No SNI → only a typed catch-all
//!    qualifies. No match → send a fatal `unrecognized_name` TLS alert
//!    (RFC 6066 §3 says the server "MAY" — we do, so a misconfigured
//!    client gets a diagnosable failure instead of a silent RST) and close.
//!    Not TLS at all → close without a word; there is nothing to say to
//!    something that isn't speaking TLS.
//! 3. **Dial** the backend under [`DemuxOptions::connect_timeout`]. A
//!    backend behind kamaji's JIT tier accepts immediately (the kernel
//!    accept queue on the held socket takes the connection while the child
//!    forks), so this timeout is about a *dead* backend, not a cold one.
//! 4. **Splice** with `tokio::io::copy_bidirectional`, which propagates each
//!    side's EOF as a write-shutdown to the other, so a half-close from
//!    either end drains correctly instead of leaking the pair.
//!
//! Concurrency is capped by a semaphore ([`DemuxOptions::max_connections`])
//! acquired *before* `accept`, so under overload the excess stays in the
//! kernel backlog rather than in this process's memory. There is
//! deliberately no per-splice idle timeout: what "idle" means for a
//! spliced TLS stream is the backend's call (pingora has its own
//! keepalive/idle policy per listener), and a demux that guessed would
//! sever long-lived WebSocket and SSE streams.
//!
//! ## What this process never has
//!
//! No private key, no plaintext, no TLS library. It parses one record and
//! copies bytes. That is the load-bearing invariant from R777: one
//! compromised demux yields routing metadata (SNI + backend addresses) and
//! nothing a tenant's cert could be used for.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::hello::{parse_sni, HelloError, MAX_HELLO_BYTES};
use crate::route::RouteTable;

/// Tunables. `Default` is what the binary ships with.
#[derive(Debug, Clone)]
pub struct DemuxOptions {
    /// Deadline for the client to deliver a complete ClientHello.
    pub peek_timeout: Duration,
    /// Deadline for the TCP connect to the backend.
    pub connect_timeout: Duration,
    /// Maximum concurrently spliced connections.
    pub max_connections: usize,
}

impl Default for DemuxOptions {
    fn default() -> Self {
        Self {
            // Browsers send the hello in the first segment; 5 s is generous
            // for a lossy mobile path and short enough that a slowloris
            // costs an attacker one fd-per-5-s per source.
            peek_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            max_connections: 10_000,
        }
    }
}

/// Why one connection was not spliced. Logged at `debug` (normal internet
/// background noise) except `Backend*`, which is `warn` — that one is ours.
#[derive(Debug)]
pub enum Verdict {
    /// Spliced; carries the routed SNI and the backend.
    Spliced { sni: Option<String>, backend: SocketAddr },
    /// Peek deadline elapsed before a full hello arrived.
    PeekTimeout,
    /// Client closed before sending a full hello.
    ClientClosed,
    /// The hello could not be parsed (`NotTls` / `Malformed` / `Unsupported`).
    BadHello(HelloError),
    /// Parsed fine, no route for it. Alert sent.
    Unrouted { sni: Option<String> },
    /// Backend did not accept within `connect_timeout`.
    BackendTimeout { sni: Option<String>, backend: SocketAddr },
    /// Backend connect failed outright.
    BackendRefused { sni: Option<String>, backend: SocketAddr, err: std::io::Error },
}

/// TLS alert record: level fatal (2), description unrecognized_name (112).
/// Record version 0x0301 matches what an unparsed-yet hello would negotiate
/// down to; every client accepts it for an alert.
const ALERT_UNRECOGNIZED_NAME: [u8; 7] = [21, 0x03, 0x01, 0x00, 0x02, 2, 112];

/// Run the demux on an already-bound listener until the task is dropped.
/// Each accepted connection is handled on its own task; the returned
/// future only resolves on an `accept` error.
pub async fn serve(
    listener: TcpListener,
    table: Arc<RouteTable>,
    opts: DemuxOptions,
) -> std::io::Result<()> {
    serve_shared(listener, crate::routes_file::shared_arc(table), opts).await
}

/// [`serve`] over a table that may be swapped while it runs (R779).
///
/// Each accepted connection takes its own snapshot of the table, so a reload
/// (`crate::routes_file::watch`) changes where the *next* connection goes and
/// leaves every in-flight splice on the backend it was routed to. There is no
/// draining and nothing to quiesce: the demux never terminates TLS, so a
/// connection is just two sockets glued together.
pub async fn serve_shared(
    listener: TcpListener,
    routes: crate::routes_file::SharedRoutes,
    opts: DemuxOptions,
) -> std::io::Result<()> {
    let permits = Arc::new(Semaphore::new(opts.max_connections));
    loop {
        // Acquire before accept: overload stays in the kernel backlog.
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("demux semaphore is never closed");
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // EMFILE and friends: back off rather than spin.
                log::warn!("accept failed: {e}; pausing 100ms");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Snapshot per connection: a reload between two accepts is picked up
        // here, and never mid-splice.
        let table = crate::routes_file::current(&routes);
        let opts = opts.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let v = handle(stream, &table, &opts).await;
            match &v {
                Verdict::Spliced { sni, backend } => {
                    log::debug!("{peer} sni={} -> {backend}: closed", sni.as_deref().unwrap_or("-"))
                }
                Verdict::BackendTimeout { sni, backend } | Verdict::BackendRefused { sni, backend, .. } => {
                    log::warn!("{peer} sni={} -> {backend}: {v:?}", sni.as_deref().unwrap_or("-"))
                }
                other => log::debug!("{peer}: {other:?}"),
            }
        });
    }
}

/// Handle one accepted connection to completion. Public so a test (or an
/// embedding binary) can drive it against an arbitrary stream.
pub async fn handle(mut client: TcpStream, table: &RouteTable, opts: &DemuxOptions) -> Verdict {
    let _ = client.set_nodelay(true);

    // ---- 1. peek -----------------------------------------------------------
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let peek = tokio::time::timeout(opts.peek_timeout, async {
        loop {
            match parse_sni(&buf) {
                Ok(sni) => return Ok(Ok(sni)),
                Err(HelloError::Incomplete(need)) => {
                    let need = need.min(MAX_HELLO_BYTES);
                    if buf.len() >= need {
                        // Cannot happen (parser asks for more than it has),
                        // but never loop forever on a parser bug.
                        return Ok(Err(HelloError::Malformed));
                    }
                    let old = buf.len();
                    buf.resize(need, 0);
                    match client.read(&mut buf[old..]).await {
                        Ok(0) => {
                            buf.truncate(old);
                            return Err(None);
                        }
                        Ok(n) => buf.truncate(old + n),
                        Err(e) => {
                            buf.truncate(old);
                            return Err(Some(e));
                        }
                    }
                }
                Err(e) => return Ok(Err(e)),
            }
        }
    })
    .await;

    let sni = match peek {
        Err(_elapsed) => return Verdict::PeekTimeout,
        Ok(Err(_io)) => return Verdict::ClientClosed,
        Ok(Ok(Err(e))) => return Verdict::BadHello(e),
        Ok(Ok(Ok(sni))) => sni,
    };

    // ---- 2. route ----------------------------------------------------------
    log::debug!("peeked {} bytes, sni={:?}", buf.len(), sni);
    let backend = match &sni {
        Some(name) => table.lookup(name),
        None => table.no_sni_backend(),
    };
    let Some(backend) = backend else {
        // Best effort; the client may already be gone.
        let _ = client.write_all(&ALERT_UNRECOGNIZED_NAME).await;
        let _ = client.shutdown().await;
        return Verdict::Unrouted { sni };
    };
    let backend = backend.addr;

    // ---- 3. dial -----------------------------------------------------------
    let mut upstream = match tokio::time::timeout(opts.connect_timeout, TcpStream::connect(backend)).await {
        Err(_) => return Verdict::BackendTimeout { sni, backend },
        Ok(Err(err)) => return Verdict::BackendRefused { sni, backend, err },
        Ok(Ok(s)) => s,
    };
    let _ = upstream.set_nodelay(true);

    // ---- 4. splice ---------------------------------------------------------
    // Replay the peeked bytes first so the backend sees the stream from
    // byte 0; then hand both halves to copy_bidirectional.
    if upstream.write_all(&buf).await.is_err() {
        return Verdict::BackendRefused {
            sni,
            backend,
            err: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "backend closed on hello replay"),
        };
    }
    drop(buf);
    log::debug!("splicing to {backend}");
    // Errors here are the ordinary end-of-life of a TCP pair (RST from
    // either side); the connection is done either way.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Verdict::Spliced { sni, backend }
}
