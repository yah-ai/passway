//! R779: passway adopts an inherited, already-listening socket instead of
//! binding fresh — the half of kamaji's on-demand JIT contract that pingora
//! could not do until the `Server::seed_listen_fd` patch (yah-ai pingora
//! fork, W267 §"Free-tier ingress at 10k domains").
//!
//! The proof of adoption is deliberately unambiguous: the socket handed in is
//! bound to port A, but it is seeded under bind string `127.0.0.1:B` for a
//! port B that nothing ever binds. pingora keys the fd table by the bind
//! string and never inspects the fd's real address, so a request answered on
//! port A can only have come through the inherited socket — had pingora
//! bound fresh it would be listening on B and A would refuse.

use std::net::{SocketAddr, TcpListener};
use std::os::unix::io::IntoRawFd;
use std::time::{Duration, Instant};

use pingora::server::Server;

use crate::common::{build_proxy, free_addr, send_raw_full, spawn_fake_upstream};

#[tokio::test]
async fn inherited_listening_socket_is_adopted_under_the_bind_string() {
    let upstream = spawn_fake_upstream("upstream-a").await;
    let (proxy, lb_background) = build_proxy(vec![upstream]);

    // Port A: the socket a supervisor would hold and pass as fd 3.
    let held = TcpListener::bind("127.0.0.1:0").expect("bind held socket");
    let port_a: SocketAddr = held.local_addr().unwrap();
    // Port B: the bind string passway is told; nothing ever listens here.
    let port_b = free_addr();
    let fd = held.into_raw_fd();

    std::thread::spawn(move || {
        let mut server = Server::new(None).expect("construct pingora Server");
        server.seed_listen_fd(port_b.to_string(), fd);
        server.bootstrap();
        let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
        proxy_service.add_tcp(&port_b.to_string());
        server.add_service(proxy_service);
        server.add_service(lb_background);
        server.run_forever();
    });

    // Served on A (the inherited socket), never on B. /health flips to 200
    // once the fake upstream's TCP health check has ticked.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = (0u16, String::new());
    while Instant::now() < deadline {
        last = send_raw_full(port_a, b"GET /health HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n").await;
        if last.0 == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(last.0, 200, "health via the inherited socket: {last:?}");
    assert!(
        std::net::TcpStream::connect(port_b).is_err(),
        "nothing may be listening on the bind-string port; pingora must not have bound fresh"
    );
}
