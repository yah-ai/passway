//! Integration test: an empty upstream set fails ready (503), never
//! crashes (R594-F4 V0 MUST #6 / R594-F6 cold-start gotcha; VERIFY list
//! item 2).
//!
//! R870-F5 extends it to the two *bodies* that 503 now carries — the holding
//! page for a browser, the unchanged JSON for everything else — while pinning
//! the status at 503 for both.

use crate::common;

use std::path::PathBuf;

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
    // R870-F5: a machine caller (no `Accept: text/html`) keeps the exact JSON
    // it parsed before the holding page existed.
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("30")
    );
    let body: serde_json::Value = resp.json().await.expect("503 json body");
    assert_eq!(body["error"], "no ready upstreams");

    // R870-F5: a browser gets the holding page — same 503, decorated body.
    let page = client
        .get(format!("{base}/anything"))
        .header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .send()
        .await
        .expect("browser-shaped request to proxy must complete");
    assert_eq!(
        page.status(),
        503,
        "the holding page must NOT make an unbacked door look healthy"
    );
    assert_eq!(
        page.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        page.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let html = page.text().await.expect("holding page body");
    assert!(html.starts_with("<!doctype html>"), "got: {html:.80}");
    assert!(html.contains("503"));
    // Nothing from the request is reflected into the page (no host, no path).
    assert!(!html.contains("/anything"));
    assert!(!html.contains(&listen.to_string()));

    // The proxy process must still be alive and answering afterward — the
    // defining property of "fail-ready, not crash".
    let again = client.get(format!("{base}/health")).send().await;
    assert!(
        again.is_ok(),
        "proxy must still be answering after serving a 503, not have crashed"
    );
}

/// R870-F8: the per-domain override, end to end over the wire.
///
/// The unit tests in `passway::holding` cover the directory; this covers the
/// thing they cannot — that the authority on the *request* selects the body,
/// that an unbranded tenant on the same door is unaffected, and that the
/// machine leg is untouched by either.
#[tokio::test]
async fn a_branded_authority_gets_its_own_holding_page() {
    let dir = HoldingDir::new(
        "branded.test=camp\n",
        "camp",
        "<!doctype html><html><body><h1>parked</h1><p>camp art</p></body></html>",
    );

    let (proxy, lb_background) = common::build_proxy(vec![]);
    let proxy = proxy.with_holding_pages(passway::holding::shared(
        passway::holding::HoldingPages::load(&dir.0),
    ));
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");
    let browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    // The branded authority gets its own body — still a 503, still no-store.
    let page = client
        .get(format!("{base}/anything"))
        .header("host", "branded.test")
        .header("accept", browser)
        .send()
        .await
        .expect("branded request must complete");
    assert_eq!(page.status(), 503, "an override must not look healthy");
    assert_eq!(
        page.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    let html = page.text().await.expect("branded body");
    assert!(html.contains("camp art"), "got: {html:.120}");

    // A tenant on the same door with no entry is byte-identical to what it got
    // before this feature existed — the property that keeps the default
    // unbranded.
    let plain = client
        .get(format!("{base}/anything"))
        .header("host", "unbranded.test")
        .header("accept", browser)
        .send()
        .await
        .expect("unbranded request must complete");
    assert_eq!(plain.status(), 503);
    let plain = plain.text().await.expect("default body");
    assert_eq!(plain, passway::holding::HOLDING_PAGE);

    // And the machine leg is untouched for the branded authority too: a prober
    // asked for the error, not the artwork.
    let json = client
        .get(format!("{base}/anything"))
        .header("host", "branded.test")
        .send()
        .await
        .expect("machine request must complete");
    assert_eq!(json.status(), 503);
    assert_eq!(
        json.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body: serde_json::Value = json.json().await.expect("503 json body");
    assert_eq!(body["error"], "no ready upstreams");
}

/// A holding directory that cleans itself up. Same idiom as `acme.rs`'s tests;
/// this crate keeps no `tempfile` dev-dep.
struct HoldingDir(PathBuf);

impl HoldingDir {
    fn new(map: &str, page_name: &str, body: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "passway-holding-it-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pages")).unwrap();
        std::fs::write(dir.join("hosts"), map).unwrap();
        std::fs::write(dir.join("pages").join(format!("{page_name}.html")), body).unwrap();
        Self(dir)
    }
}

impl Drop for HoldingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
