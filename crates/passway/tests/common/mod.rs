//! Shared integration-test scaffolding: a real `pingora::server::Server`
//! running `passway::proxy::PassProxy` on an OS thread (mirrors pingora's
//! own test pattern — `pingora-proxy/tests/utils/server_utils.rs`'s
//! `Server::start()`), plus minimal fake HTTP/1.1 upstreams so tests can
//! observe real proxied traffic instead of mocking pingora's internals.
//!
//! Deliberately plaintext (`add_tcp`, no TLS): TLS termination is a
//! listener-level concern orthogonal to everything under test here
//! (routing, auth, hardening, health) — `src/tls.rs` and `main.rs` are what
//! actually wire TLS for the real binary.
//!
//! `mod common;` is compiled fresh into *every* `tests/*.rs` binary that
//! includes it, and no single test file uses every helper here — the
//! module-wide allow below is for that expected, harmless cross-binary
//! unused-function noise, not a signal to stop maintaining any of these.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use pingora::server::Server;
use pingora::services::background::background_service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use passway::auth::{CheersAuth, RouteAuthPolicy};
use passway::proxy::PassProxy;
use passway::routing::{build_host_router, HostKey};
use passway::upstream::{build_load_balancer, StaticUpstreams, UpstreamSource};

/// Reserve an ephemeral local port and immediately release it. Small
/// TOCTOU race accepted (standard practice for this kind of test harness).
pub fn free_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr")
}

/// Send a fully-formed raw HTTP/1.1 request and return the response status
/// code (0 if the peer closed without a parseable status line). This
/// bypasses reqwest/hyper's client-side URL normalization — essential for
/// the path-confusion vectors, which reqwest would collapse (`/public/../`
/// etc.) before they ever hit the proxy. Bytes-in so a non-UTF-8 path can be
/// sent verbatim.
pub async fn send_raw(addr: SocketAddr, raw_request: &[u8]) -> u16 {
    send_raw_full(addr, raw_request).await.0
}

/// [`send_raw`], but also returning the whole response as lossy text — for
/// assertions on response headers (e.g. which upstream answered) that a bare
/// status code can't make.
pub async fn send_raw_full(addr: SocketAddr, raw_request: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect to proxy");
    stream.write_all(raw_request).await.expect("write request");
    let mut buf = Vec::new();
    // We send `Connection: close`, so read_to_end gets the whole response
    // then EOF. Guard with a timeout so a hang fails the test loudly.
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    (
        parse_status(&buf),
        String::from_utf8_lossy(&buf).into_owned(),
    )
}

fn parse_status(response: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(response);
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// Build and send a GET with an arbitrary raw request-target (path), used to
/// drive the path-confusion vectors verbatim. `extra_headers` are appended
/// after the fixed Host/Connection headers.
pub async fn raw_get(addr: SocketAddr, target: &str, extra_headers: &[(&str, &str)]) -> u16 {
    let mut req = format!(
        "GET {target} HTTP/1.1\r\nHost: passway.test\r\nConnection: close\r\n"
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    send_raw(addr, req.as_bytes()).await
}

/// Start a real pingora `Server` running `proxy` on plaintext TCP at
/// `listen`, plus `lb_background` as its own service (drives the
/// round-robin load balancer's discovery + TCP health-check ticks). Runs on
/// a dedicated OS thread — `Server::run_forever()` never returns — and this
/// function blocks (briefly) until the listener actually accepts
/// connections, so callers never race server startup.
pub fn start_proxy(
    proxy: PassProxy,
    lb_background: pingora::services::background::GenBackgroundService<
        pingora::lb::LoadBalancer<pingora::lb::selection::RoundRobin>,
    >,
    listen: SocketAddr,
) {
    start_proxy_multi(proxy, vec![lb_background], listen);
}

/// [`start_proxy`] for a host-routed proxy, which has one background service
/// per upstream set (R594-F10). Every one of them must be added to the
/// server, or that set's discovery/health-check timers never fire and it
/// stays permanently unready.
pub fn start_proxy_multi(
    proxy: PassProxy,
    lb_backgrounds: Vec<
        pingora::services::background::GenBackgroundService<
            pingora::lb::LoadBalancer<pingora::lb::selection::RoundRobin>,
        >,
    >,
    listen: SocketAddr,
) {
    std::thread::spawn(move || {
        let mut server = Server::new(None).expect("construct pingora Server");
        server.bootstrap();

        let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
        proxy_service.add_tcp(&listen.to_string());

        server.add_service(proxy_service);
        for lb_background in lb_backgrounds {
            server.add_service(lb_background);
        }
        server.run_forever();
    });

    wait_until_accepting(listen);
}

/// Build a `PassProxy` (with the given upstream addresses and, optionally,
/// auth) and its backing load balancer's background service, ready for
/// [`start_proxy`]. Health/update ticks are fast (100ms) so tests don't
/// have to wait long for the TCP health check to mark fake upstreams ready.
pub fn build_proxy(
    addrs: Vec<SocketAddr>,
) -> (
    PassProxy,
    pingora::services::background::GenBackgroundService<
        pingora::lb::LoadBalancer<pingora::lb::selection::RoundRobin>,
    >,
) {
    build_proxy_with_source(Arc::new(StaticUpstreams::new(addrs)))
}

/// [`build_proxy`] over an arbitrary [`UpstreamSource`] — the seam itself,
/// exercised by `tests/yubaba_discovery.rs` with
/// `passway::discovery::YubabaUpstreams`. Same fast 100ms health/update ticks,
/// which for a dynamic source also sets how often it re-polls.
pub fn build_proxy_with_source(
    source: Arc<dyn UpstreamSource>,
) -> (
    PassProxy,
    pingora::services::background::GenBackgroundService<
        pingora::lb::LoadBalancer<pingora::lb::selection::RoundRobin>,
    >,
) {
    let lb = build_load_balancer(source, Duration::from_millis(100), Duration::from_millis(100));
    let lb_background = background_service("test upstream health", lb);
    let proxy = PassProxy::new(lb_background.task());
    (proxy, lb_background)
}

/// Build a host-routed `PassProxy` (R594-F10): one static upstream set per
/// [`HostKey`], each with its own load balancer and background service. Same
/// fast 100ms health/update ticks as [`build_proxy`].
pub fn build_host_routed_proxy(
    sets: Vec<(HostKey, Vec<SocketAddr>)>,
) -> (
    PassProxy,
    Vec<
        pingora::services::background::GenBackgroundService<
            pingora::lb::LoadBalancer<pingora::lb::selection::RoundRobin>,
        >,
    >,
) {
    let sources: Vec<(HostKey, Arc<dyn UpstreamSource>)> = sets
        .into_iter()
        .map(|(key, addrs)| {
            (
                key,
                Arc::new(StaticUpstreams::new(addrs)) as Arc<dyn UpstreamSource>,
            )
        })
        .collect();
    let (router, services) = build_host_router(
        sources,
        Duration::from_millis(100),
        Duration::from_millis(100),
    );
    (PassProxy::routed(router), services)
}

/// Like [`build_proxy`], but with cheers-verify edge auth wired in via
/// `PassProxy::with_auth`.
pub fn build_proxy_with_auth(
    addrs: Vec<SocketAddr>,
    auth: CheersAuth,
    policy: RouteAuthPolicy,
) -> (
    PassProxy,
    pingora::services::background::GenBackgroundService<
        pingora::lb::LoadBalancer<pingora::lb::selection::RoundRobin>,
    >,
) {
    let (proxy, lb_background) = build_proxy(addrs);
    (proxy.with_auth(auth, policy), lb_background)
}

fn wait_until_accepting(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("proxy at {addr} never started accepting connections");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Spawn a minimal fake HTTP/1.1 upstream: every request (regardless of
/// method/path) gets a `200 OK` with body `tag` and header
/// `x-upstream-tag: <tag>`, so a caller proxied through passway can tell
/// which backend answered. Serves multiple requests per connection
/// (pingora pools/reuses upstream connections by default), and tolerates a
/// bare TCP connect-then-close with no bytes sent — pingora's
/// `TcpHealthCheck` does exactly that.
pub async fn spawn_fake_upstream(tag: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake upstream");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(serve_fake_upstream_conn(stream, tag));
        }
    });

    addr
}

async fn serve_fake_upstream_conn(mut stream: tokio::net::TcpStream, tag: &'static str) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        // Read until we have a full header block (\r\n\r\n) or the peer
        // closes (a bare TcpHealthCheck connect-then-close, or the client
        // done sending further requests on this pooled connection).
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            match stream.read(&mut chunk).await {
                Ok(0) => return, // EOF: health-check probe or connection closed
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
        }

        // Drop everything up through the header terminator; a GET has no
        // body, and the test clients used against this harness never send
        // one, so nothing further to read for this request.
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        buf.drain(..header_end);

        let body = tag.as_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nx-upstream-tag: {tag}\r\n\r\n",
            body.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(body).await.is_err() {
            return;
        }
    }
}
