//! Integration test: one passway instance dispatching between a single
//! service's own mounted components, selected by request PATH rather than
//! authority — the inner-door shape R870-F15 adds. Mirrors
//! `tests/host_routing.rs`'s structure and its verification style; the
//! difference under test is the key axis, not the mechanism.

use crate::common;

use std::time::Duration;

/// GET `path` and return `(status, which upstream answered, response headers
/// as raw text)`.
async fn get(proxy: std::net::SocketAddr, path: &str) -> (u16, Option<String>, String) {
    let (status, raw) = common::send_raw_full(
        proxy,
        format!("GET {path} HTTP/1.1\r\nHost: noisetable.test\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    let tag = raw.lines().find_map(|line| {
        line.strip_prefix("x-upstream-tag: ")
            .map(|t| t.trim().to_string())
    });
    (status, tag, raw)
}

async fn wait_until_ready(proxy: std::net::SocketAddr, mount_count: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (_, raw) = common::send_raw_full(
            proxy,
            b"GET /health HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n",
        )
        .await;
        if let Some(body) = raw.split("\r\n\r\n").nth(1) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                let ready = json["upstreams_by_host"]
                    .as_array()
                    .map(|sets| {
                        sets.len() == mount_count
                            && sets.iter().all(|s| s["ready_upstreams"].as_u64() == Some(1))
                    })
                    .unwrap_or(false);
                if ready {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("mount table never became fully ready within 5s; last /health: {raw}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// R870-F15's headline verification gate: a two-component service on one
/// hostname serves both `/` (root/site bundle) and `/app` (app bundle), and a
/// request for the segment-adjacent `/application` does NOT reach the `/app`
/// mount — it falls to root, exactly the naive-`startsWith` bug the ticket
/// names.
#[tokio::test]
async fn a_two_component_service_serves_both_mounts_and_application_does_not_leak_into_app() {
    let addr_root = common::spawn_fake_upstream("site-bundle").await;
    let addr_app = common::spawn_fake_upstream("app-bundle").await;

    let (proxy, lb_backgrounds) = common::build_path_routed_proxy(vec![
        ("", vec![addr_root], vec![]),
        ("/app", vec![addr_app], vec![]),
    ]);
    let listen = common::free_addr();
    common::start_proxy_multi(proxy, lb_backgrounds, listen);
    wait_until_ready(listen, 2).await;

    assert_eq!(get(listen, "/").await.0, 200);
    assert_eq!(get(listen, "/").await.1, Some("site-bundle".into()));

    assert_eq!(get(listen, "/app/").await.0, 200);
    assert_eq!(get(listen, "/app/").await.1, Some("app-bundle".into()));
    assert_eq!(get(listen, "/app/settings").await.1, Some("app-bundle".into()));

    // Segment safety: `/application` is NOT a `/app` sub-path.
    let (status, tag, _) = get(listen, "/application").await;
    assert_eq!(status, 200, "root mount still serves the segment-adjacent path");
    assert_eq!(
        tag,
        Some("site-bundle".into()),
        "/application must fall to the root mount, never to /app"
    );
}

/// A route's extra response headers (e.g. the domain manifest's COOP/COEP
/// pair for a wasm-isolated mount) apply only to responses that mount
/// served, never to a sibling mount's — "header ownership follows whoever
/// matched the path".
#[tokio::test]
async fn route_headers_apply_only_to_their_own_mount() {
    let addr_root = common::spawn_fake_upstream("site-bundle").await;
    let addr_app = common::spawn_fake_upstream("app-bundle").await;

    let (proxy, lb_backgrounds) = common::build_path_routed_proxy(vec![
        ("", vec![addr_root], vec![]),
        (
            "/app",
            vec![addr_app],
            vec![
                ("cross-origin-opener-policy", "same-origin"),
                ("cross-origin-embedder-policy", "require-corp"),
            ],
        ),
    ]);
    let listen = common::free_addr();
    common::start_proxy_multi(proxy, lb_backgrounds, listen);
    wait_until_ready(listen, 2).await;

    let (_, _, raw_app) = get(listen, "/app/").await;
    assert!(
        raw_app.to_lowercase().contains("cross-origin-opener-policy: same-origin"),
        "got: {raw_app}"
    );
    assert!(
        raw_app.to_lowercase().contains("cross-origin-embedder-policy: require-corp"),
        "got: {raw_app}"
    );

    let (_, _, raw_root) = get(listen, "/").await;
    assert!(
        !raw_root.to_lowercase().contains("cross-origin-opener-policy"),
        "root mount must not inherit /app's headers: {raw_root}"
    );
}

/// A path matching no configured mount is 503 — the same fail-ready answer
/// as an unmatched host, never a distinct 404 that would let a prober tell
/// "wrong mount" apart from "backend down".
#[tokio::test]
async fn an_unmatched_mount_is_503_not_404() {
    let addr_app = common::spawn_fake_upstream("app-bundle").await;

    // No root mount declared — deliberately, to exercise the no-catch-all path.
    let (proxy, lb_backgrounds) =
        common::build_path_routed_proxy(vec![("/app", vec![addr_app], vec![])]);
    let listen = common::free_addr();
    common::start_proxy_multi(proxy, lb_backgrounds, listen);
    wait_until_ready(listen, 1).await;

    let (status, tag, _) = get(listen, "/elsewhere").await;
    assert_eq!(status, 503);
    assert_eq!(tag, None);
}
