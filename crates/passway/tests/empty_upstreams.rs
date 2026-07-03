//! Integration test: an empty upstream set fails ready (503), never
//! crashes (R594-F4 V0 MUST #6 / R594-F6 cold-start gotcha; VERIFY list
//! item 2).

mod common;

#[tokio::test]
async fn empty_upstreams_returns_503_and_health_reports_unready() {
    let (proxy, lb_background) = common::build_proxy(vec![]);
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");

    // /health itself must report unready, not error or hang.
    let health = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("request /health");
    assert_eq!(health.status(), 503);
    let body: serde_json::Value = health.json().await.expect("health json body");
    assert_eq!(body["ready"], false);
    assert_eq!(body["ready_upstreams"], 0);
    assert_eq!(body["total_upstreams"], 0);

    // A normal proxied route must also fail ready with 503, not hang, not
    // 500, not a connection reset.
    let resp = client
        .get(format!("{base}/anything"))
        .send()
        .await
        .expect("request to proxy must complete, not crash the process");
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.expect("503 json body");
    assert_eq!(body["error"], "no ready upstreams");

    // The proxy process must still be alive and answering afterward — the
    // defining property of "fail-ready, not crash".
    let again = client.get(format!("{base}/health")).send().await;
    assert!(
        again.is_ok(),
        "proxy must still be answering after serving a 503, not have crashed"
    );
}
