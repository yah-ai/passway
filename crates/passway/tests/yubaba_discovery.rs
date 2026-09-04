//! Integration test: passway as an ingress **provider** (R594-F8).
//!
//! The unit tests in `src/discovery.rs` cover the wire projection in
//! isolation. These drive the whole path — a real `pingora::server::Server`
//! running `PassProxy` over a `YubabaUpstreams` source, against a fake yubaba
//! serving the real `GET /service-records?ready=true` shape — so the claim
//! "passway's backend set follows placement" is proven end to end rather than
//! asserted.
//!
//! Three behaviours, the last two being the ones that decide whether this is
//! safe to put in front of public traffic:
//!
//!   1. A record published by yubaba becomes a routable upstream, with no
//!      `PASSWAY_UPSTREAMS` anywhere.
//!   2. **A failed fetch is not an empty upstream set** — yubaba going away
//!      must not drain healthy backends.
//!   3. An *authoritative* empty answer does drain them, and passway
//!      fail-ready-503s rather than routing into a black hole.
//!   4. Only the fronted workload's records become backends — a sibling
//!      workload on the same node does not (R844-B6).
//!
//! ```bash
//! cargo test --test main yubaba_discovery::
//! ```

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use passway::discovery::{YubabaDiscoveryConfig, YubabaUpstreams};

/// What the fake yubaba answers with next: `(status, body)`. Swapped
/// mid-test to simulate a control-plane outage or a workload teardown.
type Answer = Arc<Mutex<(u16, String)>>;

/// A minimal stand-in for yubaba's discovery endpoint. Answers every request
/// with whatever [`Answer`] currently holds, so a test can flip the fleet's
/// state under a running proxy.
async fn spawn_fake_yubaba(answer: Answer) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake yubaba");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let answer = Arc::clone(&answer);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                // Read the request head; we don't care what it says beyond
                // it being complete.
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => return,
                    }
                }
                let (status, body) = answer.lock().expect("answer mutex").clone();
                let reason = if status == 200 { "OK" } else { "Error" };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            });
        }
    });

    addr
}

/// One ready record pointing at `upstream`, in yubaba's wire shape.
fn ready_body(upstream: SocketAddr) -> String {
    format!(
        r#"{{"version":1,"records":[{{"ident":"marketing","mesh_ip":"{}","ports":[{}],
            "endpoints":["{upstream}"],"container_id":"c-marketing","health":"ready",
            "observed_at_unix_ms":1}}]}}"#,
        upstream.ip(),
        upstream.port()
    )
}

/// Two ready records of *different* idents, as a node hosting several
/// workloads really answers. `marketing` is the one this proxy fronts.
fn two_idents_body(marketing: SocketAddr, revalidate: SocketAddr) -> String {
    format!(
        r#"{{"version":1,"records":[
            {{"ident":"marketing","mesh_ip":"{}","ports":[{}],"endpoints":["{marketing}"],
             "container_id":"c-marketing","health":"ready","observed_at_unix_ms":1}},
            {{"ident":"marketing-revalidate","mesh_ip":"{}","ports":[{}],
             "endpoints":["{revalidate}"],"container_id":"c-revalidate","health":"ready",
             "observed_at_unix_ms":1}}
        ]}}"#,
        marketing.ip(),
        marketing.port(),
        revalidate.ip(),
        revalidate.port()
    )
}

fn empty_body() -> String {
    r#"{"version":1,"records":[]}"#.to_string()
}

/// Poll `/health` until it reports `want_ready` ready upstreams, or fail.
async fn wait_for_ready(client: &reqwest::Client, base: &str, want_ready: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(resp) = client.get(format!("{base}/health")).send().await {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if body["ready_upstreams"].as_u64() == Some(want_ready) {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("never reached {want_ready} ready upstream(s) within 5s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn discovery_source(yubaba: SocketAddr) -> Arc<YubabaUpstreams> {
    Arc::new(YubabaUpstreams::new(&YubabaDiscoveryConfig {
        base_url: format!("http://{yubaba}"),
        ident: "marketing".to_string(),
        timeout: Duration::from_secs(2),
    }))
}

/// The headline: nothing configures an upstream address on passway. It learns
/// the backend from yubaba's record and proxies to it.
#[tokio::test]
async fn a_yubaba_published_record_becomes_a_routable_upstream() {
    let upstream = common::spawn_fake_upstream("marketing").await;
    let answer: Answer = Arc::new(Mutex::new((200, ready_body(upstream))));
    let yubaba = spawn_fake_yubaba(Arc::clone(&answer)).await;

    let (proxy, lb_background) = common::build_proxy_with_source(discovery_source(yubaba));
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");
    wait_for_ready(&client, &base, 1).await;

    let resp = client.get(format!("{base}/")).send().await.expect("request to proxy");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-upstream-tag").unwrap().to_str().unwrap(),
        "marketing",
        "traffic must reach the backend passway discovered, not a configured one"
    );
}

/// R844-B6. The discovery endpoint answers for the whole node, and a node
/// routinely hosts siblings of the workload being fronted (yah-marketing next
/// to yah-marketing-revalidate). Both are Ready; only one is ours. Without a
/// client-side ident filter passway adopts both, and half of `marketing.yah.dev`
/// lands in the revalidate container.
#[tokio::test]
async fn a_sibling_workloads_record_on_the_same_node_is_not_adopted() {
    let marketing = common::spawn_fake_upstream("marketing").await;
    let revalidate = common::spawn_fake_upstream("revalidate").await;
    let answer: Answer = Arc::new(Mutex::new((200, two_idents_body(marketing, revalidate))));
    let yubaba = spawn_fake_yubaba(Arc::clone(&answer)).await;

    let (proxy, lb_background) = common::build_proxy_with_source(discovery_source(yubaba));
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");

    // The count is the assertion. Under the pre-R844-B6 code this settles at
    // 2 and never at 1, so `wait_for_ready(.., 1)` fails — while any
    // "non-empty" assertion would have passed, which is exactly why the
    // defect shipped.
    wait_for_ready(&client, &base, 1).await;

    // And it stays 1 across further discovery ticks (100ms each).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let health = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("health request")
        .json::<serde_json::Value>()
        .await
        .expect("health body");
    assert_eq!(
        health["ready_upstreams"].as_u64(),
        Some(1),
        "exactly one backend — the sibling's record must never be adopted: {health}"
    );

    // Round-robin over an over-wide set would land some of these on the
    // sibling; every one must reach the workload this proxy fronts.
    for _ in 0..6 {
        let resp = client.get(format!("{base}/")).send().await.expect("request to proxy");
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-upstream-tag").unwrap().to_str().unwrap(),
            "marketing"
        );
    }
}

/// The load-bearing failure mode. yubaba going down is a control-plane
/// outage; the upstreams are still healthy and still serving. If a failed
/// fetch were read as "zero upstreams", a yubaba restart would take the
/// public site down with it.
#[tokio::test]
async fn a_yubaba_outage_does_not_drain_healthy_upstreams() {
    let upstream = common::spawn_fake_upstream("marketing").await;
    let answer: Answer = Arc::new(Mutex::new((200, ready_body(upstream))));
    let yubaba = spawn_fake_yubaba(Arc::clone(&answer)).await;

    let (proxy, lb_background) = common::build_proxy_with_source(discovery_source(yubaba));
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");
    wait_for_ready(&client, &base, 1).await;

    // yubaba starts failing. Several discovery ticks (100ms each) go by.
    *answer.lock().unwrap() = (500, r#"{"error":"raft unavailable"}"#.to_string());
    tokio::time::sleep(Duration::from_millis(600)).await;

    let resp = client.get(format!("{base}/")).send().await.expect("request to proxy");
    assert_eq!(
        resp.status(),
        200,
        "a failed discovery fetch must hold the last known good upstream set"
    );
    assert_eq!(
        resp.headers().get("x-upstream-tag").unwrap().to_str().unwrap(),
        "marketing"
    );
}

/// The other side of that coin: when yubaba *does* answer and says nothing is
/// ready, that is authoritative. Holding a stale set here would route traffic
/// at a torn-down workload.
#[tokio::test]
async fn an_authoritative_empty_answer_drains_and_fails_ready() {
    let upstream = common::spawn_fake_upstream("marketing").await;
    let answer: Answer = Arc::new(Mutex::new((200, ready_body(upstream))));
    let yubaba = spawn_fake_yubaba(Arc::clone(&answer)).await;

    let (proxy, lb_background) = common::build_proxy_with_source(discovery_source(yubaba));
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");
    wait_for_ready(&client, &base, 1).await;

    // The workload is destroyed; yubaba retracts the record.
    *answer.lock().unwrap() = (200, empty_body());
    wait_for_ready(&client, &base, 0).await;

    let resp = client.get(format!("{base}/")).send().await.expect("request to proxy");
    assert_eq!(
        resp.status(),
        503,
        "no upstreams must fail ready (503), never crash or hang"
    );
}
