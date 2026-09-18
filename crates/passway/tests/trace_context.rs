//! R893-F16 — trace context through a real proxy.
//!
//! These drive a live `pingora::server::Server` against a fake upstream that
//! RECORDS the header block it received, because this ticket's failure mode is
//! a header that silently vanishes. A test that only asserts "the request
//! succeeded" passes just as happily with tracing severed, which is exactly how
//! `Connection: traceparent` would have turned tracing off from outside without
//! anything anywhere reporting it.

use std::time::Duration;

use passway::trace::{SampleRatio, TraceParent};

use crate::common::{
    build_proxy, free_addr, send_raw_full, spawn_header_recording_upstream, spawn_line_collector,
    start_proxy_traced, wait_for,
};

/// The W3C spec's own example value.
const INBOUND: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const INBOUND_TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

fn header_value(block: &str, name: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// **THE TICKET'S CORE GATE.** A client that nominates `traceparent` as
/// hop-by-hop via `Connection:` must NOT be able to strip it — the request has
/// to arrive upstream still carrying it.
///
/// Asserted on the forwarded header's presence AND value at the upstream, not
/// on the response status: with the header stripped this request still returns
/// 200 and every other assertion in this suite still passes.
#[tokio::test]
async fn a_nominated_traceparent_still_reaches_the_upstream() {
    let (upstream, seen) = spawn_header_recording_upstream().await;
    let (proxy, lb) = build_proxy(vec![upstream]);
    let listen = free_addr();
    start_proxy_traced(proxy, vec![lb], listen, None);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let request = format!(
        "GET /orders HTTP/1.1\r\nHost: passway.test\r\n\
         Connection: close, traceparent, tracestate\r\n\
         traceparent: {INBOUND}\r\ntracestate: yah=1\r\n\r\n"
    );
    let (status, _) = send_raw_full(listen, request.as_bytes()).await;
    assert_eq!(status, 200, "the request itself must still be served");

    let blocks = seen.lock().unwrap().clone();
    assert_eq!(blocks.len(), 1, "exactly one request should have reached the upstream");
    assert_eq!(
        header_value(&blocks[0], "traceparent").as_deref(),
        Some(INBOUND),
        "a Connection-nominated traceparent must survive the hop-by-hop strip — \
         otherwise any caller can sever every trace through this door"
    );
    assert_eq!(header_value(&blocks[0], "tracestate").as_deref(), Some("yah=1"));
    // The nomination mechanism itself is untouched: `Connection` is hop-by-hop
    // and still goes, and a header the client genuinely nominated still goes.
    assert!(header_value(&blocks[0], "connection").is_none());
}

/// The same request against an untraced door: passway does not invent a
/// `traceparent` when no collector is configured, and it does not mangle one
/// that arrives. An untraced hop is transparent, not a trace boundary.
#[tokio::test]
async fn an_untraced_door_neither_mints_nor_rewrites_trace_context() {
    let (upstream, seen) = spawn_header_recording_upstream().await;
    let (proxy, lb) = build_proxy(vec![upstream]);
    let listen = free_addr();
    start_proxy_traced(proxy, vec![lb], listen, None);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let plain = "GET /a HTTP/1.1\r\nHost: passway.test\r\nConnection: close\r\n\r\n";
    assert_eq!(send_raw_full(listen, plain.as_bytes()).await.0, 200);

    let blocks = seen.lock().unwrap().clone();
    assert!(
        header_value(&blocks[0], "traceparent").is_none(),
        "an untraced door must not mint trace context it will never record"
    );
}

/// A traced door continues the caller's trace and hands the upstream the
/// CLIENT span's id, and both spans reach the collector as
/// `observation::IngestLine` span lines.
#[tokio::test]
async fn a_traced_door_continues_the_trace_and_exports_both_spans() {
    let (upstream, seen) = spawn_header_recording_upstream().await;

    let dir = std::env::temp_dir().join(format!("passway-trace-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let socket = dir.join("scryer.sock");
    let _ = std::fs::remove_file(&socket);
    let lines = spawn_line_collector(socket.clone()).await;

    let (sink, exporter) = passway::trace::to_socket(
        "door.mesh".to_string(),
        socket.to_string_lossy().into_owned(),
        SampleRatio::new(1.0),
    );
    let (proxy, lb) = build_proxy(vec![upstream]);
    let listen = free_addr();
    start_proxy_traced(
        proxy.with_spans(sink),
        vec![lb],
        listen,
        Some(pingora::services::background::background_service(
            "test span exporter",
            exporter,
        )),
    );
    tokio::time::sleep(Duration::from_millis(250)).await;

    let request = format!(
        "GET /orders HTTP/1.1\r\nHost: passway.test\r\n\
         Connection: close, traceparent\r\ntraceparent: {INBOUND}\r\n\r\n"
    );
    assert_eq!(send_raw_full(listen, request.as_bytes()).await.0, 200);

    // The forwarded header: SAME trace, DIFFERENT span id — the upstream's own
    // server span must parent onto this proxy's client leg, not onto the
    // caller's span.
    let blocks = seen.lock().unwrap().clone();
    let forwarded = header_value(&blocks[0], "traceparent")
        .expect("a traced door writes trace context onto the forwarded request");
    let parsed = TraceParent::parse(&forwarded).expect("a well-formed traceparent");
    assert_eq!(parsed.trace_id.to_hex(), INBOUND_TRACE, "the trace must continue, not restart");
    assert_ne!(
        parsed.parent_span_id.to_hex(),
        "00f067aa0ba902b7",
        "the upstream must be handed THIS hop's client span, not the caller's"
    );
    assert!(parsed.sampled, "an inbound sampled decision is honoured, not re-rolled");

    // Both spans reach the collector.
    let got = wait_for(Duration::from_secs(3), || lines.lock().unwrap().len() >= 2).await;
    let exported = lines.lock().unwrap().clone();
    assert!(got, "expected 2 exported span lines, saw {}", exported.len());

    let mut kinds: Vec<String> = Vec::new();
    for line in &exported {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid IngestLine JSON");
        assert_eq!(v["signal"], "span", "the ingestion line must be signal-tagged");
        assert_eq!(v["scope_kind"], "service");
        assert_eq!(v["scope_id"], "door.mesh");
        let span = &v["span"];
        assert_eq!(span["trace_id"], INBOUND_TRACE, "spans carry the continued trace id");
        // R893-F15: the status code is an Int on the wire, so a `>= 500`
        // predicate downstream means something.
        assert!(
            span["attributes"]["http.response.status_code"].is_i64(),
            "http.response.status_code must be an integer, not a string"
        );
        assert_eq!(span["attributes"]["service.name"], "door.mesh");
        assert_eq!(span["attributes"]["http.request.method"], "GET");
        kinds.push(span["kind"].as_str().unwrap().to_string());
    }
    kinds.sort();
    assert_eq!(kinds, vec!["client".to_string(), "server".to_string()]);

    let _ = std::fs::remove_file(&socket);
}
