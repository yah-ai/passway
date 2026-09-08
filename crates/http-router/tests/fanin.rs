//! End-to-end: one `:80` listener, three tenants — one redirected here, one
//! spliced to its own backend, one that does not exist.
//!
//! The proxy assertion is byte-exact: the backend must see the request head it
//! was never sent directly, then whatever followed, in order.

use std::sync::Arc;
use std::time::Duration;

use http_router::{serve, HostTable, RouterOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Echo server that writes `tag` once on accept (so the test can tell which
/// tenant answered) and then echoes the byte stream verbatim.
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

async fn router(routes: String, opts: RouterOptions) -> std::net::SocketAddr {
    let _ = env_logger::builder().is_test(true).try_init();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let table = Arc::new(HostTable::parse(&routes).unwrap());
    tokio::spawn(async move {
        let _ = serve(l, table, opts).await;
    });
    addr
}

async fn read_to_end_timeout(s: &mut TcpStream) -> String {
    let mut v = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), s.read_to_end(&mut v))
        .await
        .expect("timed out")
        .unwrap();
    String::from_utf8_lossy(&v).into_owned()
}

async fn read_exact_timeout(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(8), s.read_exact(&mut v))
        .await
        .expect("timed out")
        .unwrap();
    v
}

async fn request(addr: std::net::SocketAddr, raw: &str) -> String {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(raw.as_bytes()).await.unwrap();
    read_to_end_timeout(&mut c).await
}

#[tokio::test]
async fn a_redirect_route_answers_308_here_without_a_backend() {
    let addr = router(
        "yah.dev=redirect,*.yah.dev=redirect".into(),
        RouterOptions::default(),
    )
    .await;

    // The exact bytes `curl -fsSL yah.dev/install.sh` sends.
    let response = request(
        addr,
        "GET /install.sh HTTP/1.1\r\nHost: yah.dev\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 308 "), "{response}");
    assert!(
        response.contains("Location: https://yah.dev/install.sh\r\n"),
        "{response}"
    );

    // A second tenant hostname under the wildcard, and the query string.
    let response = request(addr, "GET /a?x=1 HTTP/1.1\r\nHost: www.yah.dev\r\n\r\n").await;
    assert!(
        response.contains("Location: https://www.yah.dev/a?x=1\r\n"),
        "{response}"
    );
}

#[tokio::test]
async fn an_unrouted_host_is_404_and_never_a_redirect() {
    // The open-redirect case: this router must not build a `Location` out of a
    // `Host` it has no route for, or it redirects anything that resolves here.
    let addr = router("yah.dev=redirect".into(), RouterOptions::default()).await;
    let response = request(addr, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    assert!(!response.contains("Location:"), "{response}");
}

#[tokio::test]
async fn a_proxy_route_replays_the_head_byte_exactly_to_its_own_backend() {
    let a = echo_backend(b"A").await;
    let b = echo_backend(b"B").await;
    let addr = router(
        format!("a.example=redirect,b.example={b},c.example={a}"),
        RouterOptions::default(),
    )
    .await;

    // A tenant validating by http-01: the challenge GET must reach its own
    // responder, head intact.
    let head = "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: b.example\r\n\r\n";
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(head.as_bytes()).await.unwrap();
    assert_eq!(read_exact_timeout(&mut c, 1).await, b"B");
    assert_eq!(
        String::from_utf8(read_exact_timeout(&mut c, head.len()).await).unwrap(),
        head
    );

    // The splice stays open both ways after the head.
    c.write_all(b"trailing body bytes").await.unwrap();
    assert_eq!(read_exact_timeout(&mut c, 19).await, b"trailing body bytes");

    // The other tenant's name reaches the other backend, on the same router.
    let mut c2 = TcpStream::connect(addr).await.unwrap();
    c2.write_all(b"GET / HTTP/1.1\r\nHost: c.example\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_exact_timeout(&mut c2, 1).await, b"A");
}

#[tokio::test]
async fn a_body_arriving_with_the_head_is_replayed_too() {
    let b = echo_backend(b"B").await;
    let addr = router(format!("b.example={b}"), RouterOptions::default()).await;
    let raw = "POST /x HTTP/1.1\r\nHost: b.example\r\nContent-Length: 5\r\n\r\nhello";
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(raw.as_bytes()).await.unwrap();
    assert_eq!(read_exact_timeout(&mut c, 1).await, b"B");
    assert_eq!(
        String::from_utf8(read_exact_timeout(&mut c, raw.len()).await).unwrap(),
        raw
    );
}

#[tokio::test]
async fn a_fragmented_head_is_reassembled() {
    let addr = router("a.example=redirect".into(), RouterOptions::default()).await;
    let raw = "GET /slow HTTP/1.1\r\nHost: a.example\r\nX-Pad: 0123456789\r\n\r\n";
    let mut c = TcpStream::connect(addr).await.unwrap();
    for chunk in raw.as_bytes().chunks(3) {
        c.write_all(chunk).await.unwrap();
        c.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let response = read_to_end_timeout(&mut c).await;
    assert!(
        response.contains("Location: https://a.example/slow\r\n"),
        "{response}"
    );
}

#[tokio::test]
async fn a_client_that_says_nothing_is_cut_off_at_the_deadline() {
    let addr = router(
        "a.example=redirect".into(),
        RouterOptions {
            read_timeout: Duration::from_millis(150),
            ..RouterOptions::default()
        },
    )
    .await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    // No response, just a close, once the deadline elapses.
    assert_eq!(read_to_end_timeout(&mut c).await, "");
}

#[tokio::test]
async fn tls_pointed_at_port_80_is_closed_without_a_response() {
    let addr = router("a.example=redirect".into(), RouterOptions::default()).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05]).await.unwrap();
    assert_eq!(read_to_end_timeout(&mut c).await, "");
}

#[tokio::test]
async fn a_dead_backend_closes_rather_than_hanging() {
    // Port 1 on loopback: nothing listens, connect is refused immediately.
    let addr = router("b.example=127.0.0.1:1".into(), RouterOptions::default()).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: b.example\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_to_end_timeout(&mut c).await, "");
}

#[tokio::test]
async fn a_request_without_a_host_is_400_not_a_guess() {
    let addr = router("a.example=redirect".into(), RouterOptions::default()).await;
    let response = request(addr, "GET / HTTP/1.0\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
}
