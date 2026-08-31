//! End-to-end: two loopback "tenants" behind one demux listener. Each
//! backend echoes everything it receives, so the assertion is byte-exact —
//! the backend must see the ClientHello it was never sent directly, then
//! whatever followed, in order.

use std::sync::Arc;
use std::time::Duration;

use sni_demux::hello::build_client_hello;
use sni_demux::{serve, DemuxOptions, RouteTable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Echo server that writes `tag` once on accept (so the test can tell which
/// tenant answered) and then echoes the byte stream verbatim. The tag goes
/// once per connection, not per read — TCP may coalesce the replayed hello
/// and whatever follows into one read, so a per-chunk tag is not stable.
async fn echo_backend(tag: &'static [u8]) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                if s.write_all(tag).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn demux(routes: String, opts: DemuxOptions) -> std::net::SocketAddr {
    let _ = env_logger::builder().is_test(true).try_init();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let table = Arc::new(RouteTable::parse(&routes).unwrap());
    tokio::spawn(async move {
        let _ = serve(l, table, opts).await;
    });
    addr
}

async fn read_exact_timeout(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(8), s.read_exact(&mut v))
        .await
        .expect("timed out")
        .unwrap();
    v
}

#[tokio::test]
async fn routes_by_sni_and_replays_hello_byte_exact() {
    let a = echo_backend(b"A:").await;
    let b = echo_backend(b"B:").await;
    let d = demux(format!("a.example={a},*.b.example={b}"), DemuxOptions::default()).await;

    for (sni, tag) in [("a.example", b"A:"), ("x.b.example", b"B:")] {
        let hello = build_client_hello(Some(sni));
        let mut c = TcpStream::connect(d).await.unwrap();
        // Send the hello in two fragments to exercise the Incomplete path.
        c.write_all(&hello[..7]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        c.write_all(&hello[7..]).await.unwrap();
        // Then an "application" payload after the hello.
        c.write_all(b"after-hello").await.unwrap();

        let got = read_exact_timeout(&mut c, 2 + hello.len()).await;
        assert_eq!(&got[..2], tag);
        assert_eq!(&got[2..], &hello[..], "backend must see the replayed hello byte-exact");
        let got2 = read_exact_timeout(&mut c, 11).await;
        assert_eq!(&got2[..], b"after-hello");

        // Half-close from the client propagates: backend EOF → our read EOF.
        c.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut rest))
            .await
            .expect("splice must close after half-close")
            .unwrap();
    }
}

#[tokio::test]
async fn unknown_sni_gets_unrecognized_name_alert_and_close() {
    let a = echo_backend(b"A:").await;
    let d = demux(format!("a.example={a}"), DemuxOptions::default()).await;

    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(&build_client_hello(Some("nobody.example"))).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, [21, 3, 1, 0, 2, 2, 112], "fatal unrecognized_name alert");
}

#[tokio::test]
async fn no_sni_without_catch_all_is_closed_and_with_catch_all_is_routed() {
    let a = echo_backend(b"A:").await;
    let d = demux(format!("a.example={a}"), DemuxOptions::default()).await;
    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(&build_client_hello(None)).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await.unwrap().unwrap();
    assert_eq!(got, [21, 3, 1, 0, 2, 2, 112]);

    let d2 = demux(format!("*={a}"), DemuxOptions::default()).await;
    let hello = build_client_hello(None);
    let mut c = TcpStream::connect(d2).await.unwrap();
    c.write_all(&hello).await.unwrap();
    let got = read_exact_timeout(&mut c, 2 + hello.len()).await;
    assert_eq!(&got[..2], b"A:");
}

#[tokio::test]
async fn plain_http_on_443_is_closed_silently() {
    let a = echo_backend(b"A:").await;
    let d = demux(format!("*={a}"), DemuxOptions::default()).await;
    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut got = Vec::new();
    // The demux decides at byte 5 and closes with the rest of the request
    // unread, so the kernel may answer with RST rather than FIN. Either is
    // fine; what matters is that not one byte was written back.
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await.unwrap();
    assert!(got.is_empty(), "nothing is said to a non-TLS peer");
}

#[tokio::test]
async fn slow_hello_is_cut_off_at_peek_timeout() {
    let a = echo_backend(b"A:").await;
    let opts = DemuxOptions { peek_timeout: Duration::from_millis(200), ..Default::default() };
    let d = demux(format!("*={a}"), opts).await;
    let mut c = TcpStream::connect(d).await.unwrap();
    // Three bytes of a valid hello, then silence.
    c.write_all(&build_client_hello(Some("a.example"))[..3]).await.unwrap();
    let started = std::time::Instant::now();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await.unwrap().unwrap();
    assert!(got.is_empty());
    assert!(started.elapsed() < Duration::from_secs(2), "closed at the peek deadline, not later");
}

#[tokio::test]
async fn dead_backend_closes_client() {
    // Bind then drop: a port nothing listens on.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let d = demux(format!("a.example={dead}"), DemuxOptions::default()).await;
    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(&build_client_hello(Some("a.example"))).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await.unwrap().unwrap();
    assert!(got.is_empty());
}

/// R779: a domain enrolled *after* the demux started becomes routable without
/// a restart. That is the whole point of the published routes file — under
/// on-demand TLS a tenant registers, yubaba publishes, and the very next
/// connection for that name has somewhere to go.
#[tokio::test]
async fn a_route_added_to_the_file_is_live_on_the_next_connection() {
    let a = echo_backend(b"A:").await;
    let b = echo_backend(b"B:").await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("routes");
    std::fs::write(&path, format!("a.example={a}\n")).unwrap();

    let _ = env_logger::builder().is_test(true).try_init();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let d = l.local_addr().unwrap();
    let routes = sni_demux::routes_file::shared(sni_demux::routes_file::load(&path).unwrap());
    tokio::spawn(sni_demux::routes_file::watch(
        path.clone(),
        routes.clone(),
        Duration::from_millis(10),
    ));
    tokio::spawn({
        let routes = routes.clone();
        async move {
            let _ = sni_demux::serve_shared(l, routes, DemuxOptions::default()).await;
        }
    });

    // Before enrollment: unrouted, so a fatal alert and a close.
    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(&build_client_hello(Some("b.example"))).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, vec![21, 0x03, 0x01, 0x00, 0x02, 2, 112], "unrecognized_name");

    // yubaba publishes the new tenant.
    std::fs::write(&path, format!("a.example={a}\nb.example={b}\n")).unwrap();
    for _ in 0..200 {
        if sni_demux::routes_file::current(&routes).lookup("b.example").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The next connection reaches the newly enrolled tenant's backend.
    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(&build_client_hello(Some("b.example"))).await.unwrap();
    assert_eq!(&read_exact_timeout(&mut c, 2).await, b"B:");

    // And the route that was already there still points where it did.
    let mut c = TcpStream::connect(d).await.unwrap();
    c.write_all(&build_client_hello(Some("a.example"))).await.unwrap();
    assert_eq!(&read_exact_timeout(&mut c, 2).await, b"A:");
}
