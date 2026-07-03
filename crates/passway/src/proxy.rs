//! `PassProxy` — the `pingora::proxy::ProxyHttp` implementation that ties
//! together upstream selection, auth, the health endpoint, and the
//! smuggling-hardening filters into the actual request path.
//!
//! Phase order (matches pingora's own `request_filter` -> `upstream_peer`
//! -> `upstream_request_filter` chain, see the R594-S1 spike's citation of
//! `docs/user_guide/phase_chart.md`):
//!
//! 1. [`request_filter`](PassProxy::request_filter) — runs before any
//!    upstream is chosen. Handles `/health` directly (never proxied);
//!    rejects a downstream request with conflicting `Content-Length` /
//!    `Transfer-Encoding` (400); gates auth-required routes (401); gates on
//!    upstream readiness (503, fail-ready per R594-F6's cold-start gotcha).
//! 2. [`upstream_peer`](PassProxy::upstream_peer) — round-robin selection
//!    over the health-checked backend set.
//! 3. [`upstream_request_filter`](PassProxy::upstream_request_filter) —
//!    defense-in-depth re-application of the hop-by-hop strip and the
//!    length-header conflict check, directly on the request about to be
//!    forwarded (the R594-S1 checklist's literal instruction).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::lb::selection::RoundRobin;
use pingora::lb::LoadBalancer;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result as PResult};

use crate::auth::{self, CheersAuth, RouteAuthPolicy};
use crate::hardening;
use crate::health::ReadinessBody;
use crate::upstream;

/// The passway proxy. Construct via [`PassProxy::new`], then chain the
/// `with_*` builders for whatever this deployment needs; everything not
/// explicitly configured defaults to the safest posture (no auth
/// configured, every route anonymous, plaintext-to-upstream since the
/// mesh transport is already encrypted).
pub struct PassProxy {
    lb: Arc<LoadBalancer<RoundRobin>>,
    auth: Option<CheersAuth>,
    route_policy: RouteAuthPolicy,
    upstream_tls: bool,
    upstream_sni: String,
    health_path: String,
    draining: Arc<AtomicBool>,
}

impl PassProxy {
    pub fn new(lb: Arc<LoadBalancer<RoundRobin>>) -> Self {
        Self {
            lb,
            auth: None,
            route_policy: RouteAuthPolicy::new(),
            upstream_tls: false,
            upstream_sni: String::new(),
            health_path: "/health".to_string(),
            draining: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Wire cheers-verify edge auth plus the per-route policy deciding
    /// which paths demand it (V0 MUST #3).
    pub fn with_auth(mut self, auth: CheersAuth, route_policy: RouteAuthPolicy) -> Self {
        self.auth = Some(auth);
        self.route_policy = route_policy;
        self
    }

    /// Whether to speak TLS to the upstream and, if so, which SNI to
    /// present. Defaults to plaintext: upstreams are reached over the
    /// already-encrypted WireGuard mesh (W267 §Design), so upstream TLS is
    /// an optional extra layer, not the primary confidentiality boundary.
    pub fn with_upstream_tls(mut self, tls: bool, sni: impl Into<String>) -> Self {
        self.upstream_tls = tls;
        self.upstream_sni = sni.into();
        self
    }

    /// Override the health-check path (default `/health`).
    pub fn with_health_path(mut self, path: impl Into<String>) -> Self {
        self.health_path = path.into();
        self
    }

    /// A shared flag a caller (signal handler, admin endpoint, graceful-
    /// shutdown sequence) can set to make `/health` report unready without
    /// tearing down the listener — the "or is draining" half of V0 MUST #4.
    pub fn draining_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.draining)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write a JSON response directly to the downstream and mark the session
/// done. Used for `/health` and for every filter-level rejection (400 /
/// 401 / 503) — none of these respond bodies ever go near an upstream.
async fn respond_json(session: &mut Session, status: u16, body: &serde_json::Value) -> PResult<()> {
    let payload = serde_json::to_vec(body).unwrap_or_default();
    let mut resp = ResponseHeader::build(status, Some(payload.len()))?;
    resp.insert_header("content-type", "application/json")?;
    resp.set_content_length(payload.len())?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(payload)), true)
        .await?;
    Ok(())
}

#[async_trait]
impl ProxyHttp for PassProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> PResult<bool> {
        let path = session.req_header().uri.path().to_string();

        // /health is answered directly — never gated by auth or upstream
        // readiness, since its entire job is to REPORT upstream readiness.
        if path == self.health_path {
            let (ready, total) = upstream::ready_count(&self.lb);
            let draining = self.draining.load(Ordering::Relaxed);
            let body = ReadinessBody::new(ready, total, draining);
            let status = body.status_code();
            let json = serde_json::to_value(&body).unwrap_or_default();
            respond_json(session, status, &json).await?;
            return Ok(true);
        }

        // Smuggling hardening, early gate (defense in depth #1 — the
        // authoritative re-check on the actual forwarded request happens in
        // `upstream_request_filter`, defense in depth #2).
        if hardening::has_conflicting_length_headers(&session.req_header().headers) {
            respond_json(
                session,
                400,
                &serde_json::json!({"error": "conflicting Content-Length and Transfer-Encoding"}),
            )
            .await?;
            return Ok(true);
        }

        // Per-route auth gate (V0 MUST #3). No matching rule => anonymous;
        // a route that DOES require auth but has no verifier configured
        // fails closed (indistinguishable from "no/invalid bearer" to the
        // caller — never leaks "this deployment is misconfigured").
        if self.route_policy.auth_required_for(&path) {
            let now = now_unix();
            let authed = auth::bearer_from_headers(&session.req_header().headers)
                .and_then(|token| self.auth.as_ref().map(|a| (a, token)))
                .is_some_and(|(a, token)| a.verify(token, now).is_ok());
            if !authed {
                respond_json(session, 401, &serde_json::json!({"error": "unauthorized"})).await?;
                return Ok(true);
            }
        }

        // Fail-ready (R594-F6 gotcha): an empty or fully-unhealthy upstream
        // set must 503, never fall through into `upstream_peer` and error
        // out mid-connect.
        if !upstream::any_ready(&self.lb) {
            respond_json(
                session,
                503,
                &serde_json::json!({"error": "no ready upstreams"}),
            )
            .await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> PResult<Box<HttpPeer>> {
        // `key` doesn't matter for RoundRobin (see pingora's own
        // load_balancer.rs example) — b"" mirrors it verbatim.
        match self.lb.select(b"", 256) {
            Some(backend) => Ok(Box::new(HttpPeer::new(
                backend,
                self.upstream_tls,
                self.upstream_sni.clone(),
            ))),
            // request_filter already gated emptiness; reaching here means a
            // backend flipped unhealthy in the race window between the two
            // checks. Fail the same way request_filter would have.
            None => Err(Error::explain(
                ErrorType::HTTPStatus(503),
                "no ready upstream (raced after request_filter's readiness gate)",
            )),
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> PResult<()> {
        // R594-S1 checklist, applied literally: strip hop-by-hop headers
        // and reject a conflicting Content-Length/Transfer-Encoding pair on
        // the actual request about to be forwarded.
        hardening::strip_hop_by_hop(&mut upstream_request.headers);
        if hardening::has_conflicting_length_headers(&upstream_request.headers) {
            return Err(Error::explain(
                ErrorType::HTTPStatus(400),
                "conflicting Content-Length/Transfer-Encoding at upstream_request_filter",
            ));
        }
        Ok(())
    }
}
