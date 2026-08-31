//! Integration test: one passway instance fronting two services, selected by
//! the request's authority (R594-F10 VERIFY item 1).
//!
//! Everything goes through raw HTTP/1.1 rather than reqwest: the whole point
//! is control over the `Host` header — including sending two of them, which
//! no well-behaved client library will do.

use crate::common;

use std::net::SocketAddr;
use std::time::Duration;

use passway::routing::HostKey;

const HOST_A: &str = "marketing.example.test";
const HOST_B: &str = "analytics.example.test";

/// Send a GET for `path` with exactly the `Host` header(s) given, and return
/// `(status, which upstream answered)`.
async fn get_with_hosts(proxy: SocketAddr, path: &str, hosts: &[&str]) -> (u16, Option<String>) {
    let mut req = format!("GET {path} HTTP/1.1\r\n");
    for host in hosts {
        req.push_str(&format!("Host: {host}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    let (status, raw) = common::send_raw_full(proxy, req.as_bytes()).await;
    let tag = raw.lines().find_map(|line| {
        line.strip_prefix("x-upstream-tag: ")
            .map(|t| t.trim().to_string())
    });
    (status, tag)
}

async fn wait_until_both_hosts_ready(proxy: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (_, raw) = common::send_raw_full(
            proxy,
            b"GET /health HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n",
        )
        .await;
        // The per-host breakdown only appears on a host-routed instance, and
        // only names a host once that host's set has been discovered.
        if let Some(body) = raw.split("\r\n\r\n").nth(1) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                let per_host = &json["upstreams_by_host"];
                let ready = |host: &str| {
                    per_host
                        .as_array()
                        .map(|sets| {
                            sets.iter().any(|s| {
                                s["host"] == host && s["ready_upstreams"].as_u64() == Some(1)
                            })
                        })
                        .unwrap_or(false)
                };
                if ready(HOST_A) && ready(HOST_B) {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("both host sets never became ready within 5s; last /health: {raw}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn each_hostname_reaches_only_its_own_upstream_set() {
    let addr_a = common::spawn_fake_upstream("upstream-a").await;
    let addr_b = common::spawn_fake_upstream("upstream-b").await;

    let (proxy, lb_backgrounds) = common::build_host_routed_proxy(vec![
        (HostKey::Host(HOST_A.into()), vec![addr_a]),
        (HostKey::Host(HOST_B.into()), vec![addr_b]),
    ]);
    let listen = common::free_addr();
    common::start_proxy_multi(proxy, lb_backgrounds, listen);
    wait_until_both_hosts_ready(listen).await;

    // Same path, same instance, same port — only the authority differs, and
    // it is what decides which service answers.
    for _ in 0..3 {
        assert_eq!(
            get_with_hosts(listen, "/", &[HOST_A]).await,
            (200, Some("upstream-a".into()))
        );
        assert_eq!(
            get_with_hosts(listen, "/", &[HOST_B]).await,
            (200, Some("upstream-b".into()))
        );
    }

    // Port and case in the Host header are normalized away, not treated as a
    // different (unknown) service.
    assert_eq!(
        get_with_hosts(listen, "/", &[&format!("{}:8443", HOST_A.to_uppercase())]).await,
        (200, Some("upstream-a".into()))
    );

    // An unconfigured hostname is 503 — never a fallthrough into another
    // service's backend set. That distinction is the whole point: both
    // upstreams are up and ready, so a leak would answer 200 here.
    let (status, tag) = get_with_hosts(listen, "/", &["unknown.example.test"]).await;
    assert_eq!(status, 503, "an unrouted authority must fail closed");
    assert_eq!(
        tag, None,
        "no upstream may answer for an unrouted authority"
    );

    // Two disagreeing authorities is a routing ambiguity: 400, decided before
    // any upstream is picked.
    let (status, tag) = get_with_hosts(listen, "/", &[HOST_A, HOST_B]).await;
    assert_eq!(status, 400, "conflicting Host headers must be rejected");
    assert_eq!(tag, None);

    // /health is answered by the proxy itself whatever authority it carries.
    let (status, tag) = get_with_hosts(listen, "/health", &["unknown.example.test"]).await;
    assert_eq!(
        status, 200,
        "the node is ready: both sets have a ready upstream"
    );
    assert_eq!(tag, None);
}

#[tokio::test]
async fn a_declared_catch_all_serves_unrouted_hostnames() {
    let addr_a = common::spawn_fake_upstream("upstream-a").await;
    let addr_fallback = common::spawn_fake_upstream("upstream-fallback").await;

    let (proxy, lb_backgrounds) = common::build_host_routed_proxy(vec![
        (HostKey::Host(HOST_A.into()), vec![addr_a]),
        (HostKey::CatchAll, vec![addr_fallback]),
    ]);
    let listen = common::free_addr();
    common::start_proxy_multi(proxy, lb_backgrounds, listen);

    // Poll until routing is live rather than reading the breakdown, since
    // this instance's readiness depends on two differently-labeled sets.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if get_with_hosts(listen, "/", &[HOST_A]).await.0 == 200 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "upstreams never became ready within 5s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        get_with_hosts(listen, "/", &[HOST_A]).await,
        (200, Some("upstream-a".into())),
        "an explicitly routed host still prefers its own set"
    );
    assert_eq!(
        get_with_hosts(listen, "/", &["anything.example.test"]).await,
        (200, Some("upstream-fallback".into()))
    );
    // Including a request that carries no authority at all (HTTP/1.0).
    let (status, tag) = common::send_raw_full(listen, b"GET / HTTP/1.0\r\n\r\n").await;
    assert_eq!(status, 200);
    assert!(tag.contains("upstream-fallback"), "got: {tag}");
}

#[tokio::test]
async fn one_host_set_going_dark_does_not_borrow_another_hosts_backends() {
    let addr_a = common::spawn_fake_upstream("upstream-a").await;
    // HOST_B is configured with an address nothing listens on, so its set
    // discovers a backend but the TCP health check never marks it ready.
    let dead: SocketAddr = common::free_addr();

    let (proxy, lb_backgrounds) = common::build_host_routed_proxy(vec![
        (HostKey::Host(HOST_A.into()), vec![addr_a]),
        (HostKey::Host(HOST_B.into()), vec![dead]),
    ]);
    let listen = common::free_addr();
    common::start_proxy_multi(proxy, lb_backgrounds, listen);

    // Wait for the health check to have run at least once against both sets
    // (backends start optimistically ready, so this must wait for B to go
    // *down*, not for A to come up).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if get_with_hosts(listen, "/", &[HOST_B]).await.0 == 503 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dead host set never went unready within 5s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (status, tag) = get_with_hosts(listen, "/", &[HOST_B]).await;
    assert_eq!(status, 503);
    assert_eq!(
        tag, None,
        "a host with no ready upstreams must 503, not borrow another host's healthy backends"
    );
    assert_eq!(
        get_with_hosts(listen, "/", &[HOST_A]).await,
        (200, Some("upstream-a".into())),
        "the healthy host is unaffected by its neighbour being down"
    );
}
