//! R853-S5 — can a process hand a listening fd to its OWN pingora Server over
//! pingora's upgrade socket, using only public API on STOCK crates.io
//! pingora-core 0.8.1?
//!
//! If yes, passway's `socket-activation` feature no longer needs the
//! `Server::seed_listen_fd` fork: the `[patch.crates-io]` block, the
//! `deny.toml` `allow-git` carve-out, the rebase-per-pingora-release treadmill
//! and the broken `cargo install passway --features socket-activation` all go
//! away together.
//!
//! The proof is deliberately unambiguous, and is the same shape passway's own
//! `tests/socket_activation.rs` uses: the socket handed over is bound to port
//! A, but it is announced to pingora under the bind string for port B, which
//! nothing ever binds. pingora keys its fd table by the bind string and never
//! inspects the fd's real address — so a request answered on port A can only
//! have arrived through the transferred socket. Had pingora bound fresh it
//! would be listening on B, and A would refuse.
//!
//! Direction matters and is the opposite of the intuitive guess: the RECEIVER
//! (this server, under `Opt::upgrade = true`) unlinks, binds and listens on
//! `ServerConf::upgrade_sock`, then accept()s with retries. The SENDER
//! connects. So the sender must run off the main thread while `bootstrap()`
//! blocks on the receive; both sides retry, so the startup skew is tolerated.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::Response;
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_core::server::{Fds, Server};
use pingora_core::services::listening::Service;

struct Hello;

#[async_trait]
impl ServeHttp for Hello {
    async fn response(&self, _session: &mut ServerSession) -> Response<Vec<u8>> {
        Response::builder()
            .status(200)
            .body(b"adopted\n".to_vec())
            .unwrap()
    }
}

/// Grab a port, then drop the listener so nothing is bound on it.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind for free port");
    l.local_addr().unwrap().port()
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Port A: the socket a supervisor (kamaji's JIT tier, a systemd .socket
    // unit) would hold and hand over as fd 3.
    let held = TcpListener::bind("127.0.0.1:0").expect("bind held socket");
    let port_a = held.local_addr().unwrap().port();
    // Port B: the bind string the server is told about. Never bound.
    let port_b = free_port();
    let bind_b = format!("127.0.0.1:{port_b}");

    // The supervisor's fd is bound by the std library and is therefore
    // BLOCKING. pingora's `listeners::l4::from_raw_fd` does not set
    // O_NONBLOCK and tokio's `from_std` does not either, so the first accept
    // would stall a worker. On the fork this is fixed inside pingora (the
    // third of the three carried hunks); here we do it on our own fd before
    // handing it over, which is why that hunk is not needed either.
    //
    // FDSPIKE_BLOCKING=1 skips it, as the control: if the run then hangs, the
    // O_NONBLOCK really is load-bearing and doing it supervisor-side really is
    // what makes pingora's `l4.rs` hunk unnecessary.
    let fd: RawFd = held.into_raw_fd();
    if std::env::var("FDSPIKE_BLOCKING").as_deref() == Ok("1") {
        println!("spike: CONTROL — leaving the handed-over fd BLOCKING");
    } else {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL failed");
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "F_SETFL O_NONBLOCK failed"
        );
    }

    let sock_path = "/tmp/fdspike-upgrade.sock".to_string();
    let _ = std::fs::remove_file(&sock_path);

    println!("spike: port_a={port_a} (held socket), port_b={port_b} (bind string, never bound)");

    // The sender. Off the main thread, because `bootstrap()` below blocks in
    // the receive. `send_to_sock` retries ENOENT/ECONNREFUSED, so racing
    // ahead of the receiver's bind is fine.
    let sender_path = sock_path.clone();
    let sender_bind = bind_b.clone();
    let sender = std::thread::spawn(move || {
        let mut fds = Fds::new();
        fds.add(sender_bind, fd);
        fds.send_to_sock(sender_path.as_str())
    });

    let mut conf = ServerConf::default();
    conf.upgrade_sock = sock_path.clone();
    // One thread per service is plenty and keeps the output readable.
    conf.threads = 1;

    let opt = Opt {
        upgrade: true,
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(Some(opt), conf);
    // Receives over the upgrade socket. Exits the process on failure, which
    // is itself part of what the spike is testing.
    server.bootstrap();

    match sender.join().expect("sender thread panicked") {
        Ok(n) => println!("spike: send_to_sock ok, {n} bytes of payload"),
        Err(e) => {
            eprintln!("spike: FAIL — send_to_sock errored: {e:?}");
            std::process::exit(2);
        }
    }

    let mut svc = Service::new("spike".to_string(), Hello);
    svc.add_tcp(&bind_b);
    server.add_service(svc);

    std::thread::spawn(move || server.run_forever());

    // Now the actual question: is anyone accepting on port A?
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        if Instant::now() > deadline {
            eprintln!("spike: FAIL — nothing answered on port {port_a} within 10s: {last_err:?}");
            std::process::exit(1);
        }
        match probe(port_a) {
            Ok(body) => {
                assert!(
                    body.contains("adopted"),
                    "spike: FAIL — answered on {port_a} but not by our app: {body:?}"
                );
                println!("spike: PASS — port {port_a} answered, and only the transferred socket");
                println!("spike: is listening there ({port_b} was the bind string, never bound).");

                // Control: port B must refuse. If pingora had bound fresh it
                // would be listening here, and the result above would prove
                // nothing.
                match TcpStream::connect(("127.0.0.1", port_b)) {
                    Ok(_) => {
                        eprintln!("spike: FAIL — port {port_b} accepted; pingora bound fresh, so");
                        eprintln!("spike: the port-A answer does not prove adoption.");
                        std::process::exit(3);
                    }
                    Err(e) => {
                        println!("spike: control ok — port {port_b} refuses ({e})");
                        std::process::exit(0);
                    }
                }
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn probe(port: u16) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    if buf.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty response",
        ));
    }
    Ok(buf)
}
