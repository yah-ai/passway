//! Integration test: passway round-robins over 2 fake upstreams
//! (R594-F4 V0 MUST #1 + VERIFY list item 1).

use crate::common;

use std::time::Duration;

#[tokio::test]
async fn round_robins_over_two_upstreams() {
    let addr_a = common::spawn_fake_upstream("upstream-a").await;
    let addr_b = common::spawn_fake_upstream("upstream-b").await;

    let (proxy, lb_background) = common::build_proxy(vec![addr_a, addr_b]);
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");

    // The TCP health check ticks every 100ms (see common::build_proxy); wait
    // for /health to report both backends ready before measuring
    // round-robin distribution, so the test doesn't race the first tick.
    wait_until_healthy(&client, &base, 2).await;

    let mut tags = Vec::new();
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/"))
            .send()
            .await
            .expect("request to proxy");
        assert_eq!(resp.status(), 200);
        let tag = resp
            .headers()
            .get("x-upstream-tag")
            .expect("x-upstream-tag header")
            .to_str()
            .unwrap()
            .to_string();
        tags.push(tag);
    }

    // Strict alternation, phase-agnostic: which upstream serves the FIRST
    // request is not a round-robin property — pingora's LoadBalancer holds
    // backends in an address-ordered set, and these upstreams sit on
    // OS-assigned ephemeral ports, so "a before b" is a coin flip decided by
    // the port allocator. Asserting a fixed starting upstream made this test
    // flaky the moment anything else on the machine (or in this process)
    // interleaved port allocation. R743-T6 audit finding.
    for pair in tags.windows(2) {
        assert_ne!(
            pair[0], pair[1],
            "expected strict alternation over 2 upstreams, got {tags:?}"
        );
    }
    assert_eq!(
        tags.iter().filter(|t| *t == "upstream-a").count(),
        3,
        "expected an even 3/3 split over 2 upstreams, got {tags:?}"
    );
}

async fn wait_until_healthy(client: &reqwest::Client, base: &str, want_ready: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(resp) = client.get(format!("{base}/health")).send().await {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if body["ready_upstreams"].as_u64() == Some(want_ready as u64) {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("upstreams never became healthy within 5s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
