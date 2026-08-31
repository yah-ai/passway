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
//!    `Transfer-Encoding` (400); canonicalizes the request path and rejects
//!    ambiguous/non-UTF-8 paths (400) before making the per-route auth
//!    decision on the canonical form (see [`crate::path`]); gates
//!    auth-required routes (401); resolves the request's authority to an
//!    upstream set (400 on an ambiguous authority, 503 on one nothing
//!    serves — see [`crate::host`] / [`crate::routing`]); gates on that
//!    set's upstream readiness (503, fail-ready per R594-F6's cold-start
//!    gotcha).
//! 2. [`upstream_peer`](PassProxy::upstream_peer) — round-robin selection
//!    within the set `request_filter` chose.
//! 3. [`upstream_request_filter`](PassProxy::upstream_request_filter) —
//!    defense-in-depth re-application of the hop-by-hop strip and the
//!    length-header conflict check, directly on the request about to be
//!    forwarded (the R594-S1 checklist's literal instruction).
//!
//! Host selection sits **after** path canonicalization and the auth decision
//! (R594-F10), never before: the auth gate must keep deciding on the same
//! canonical path R594-F4's round-2 fix established, and no routing choice is
//! allowed to run ahead of it.

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
use crate::health::{HostReadiness, ReadinessBody};
use crate::host::{self, HostOutcome};
use crate::idle::IdleTracker;
use crate::routing::HostRouter;
use crate::upstream;

/// Per-request state. Carries the upstream set
/// [`request_filter`](PassProxy::request_filter) resolved from the request's
/// authority through to [`upstream_peer`](PassProxy::upstream_peer), so both
/// phases act on the same set — re-deriving the host in `upstream_peer` would
/// be a second chance to disagree with the readiness gate that already ran.
#[derive(Default)]
pub struct RequestCtx {
    upstreams: Option<Arc<LoadBalancer<RoundRobin>>>,
}

/// The passway proxy. Construct via [`PassProxy::new`] (one upstream set for
/// every host) or [`PassProxy::routed`] (a [`HostRouter`], for a node
/// fronting several services), then chain the `with_*` builders for whatever
/// this deployment needs; everything not explicitly configured defaults to
/// the safest posture (no auth configured, every route anonymous,
/// plaintext-to-upstream since the mesh transport is already encrypted).
pub struct PassProxy {
    router: HostRouter,
    auth: Option<CheersAuth>,
    route_policy: RouteAuthPolicy,
    upstream_tls: bool,
    upstream_sni: String,
    health_path: String,
    draining: Arc<AtomicBool>,
    /// R779: in-flight counter for idle self-reap. `None` = never reap.
    idle: Option<Arc<IdleTracker>>,
}

impl PassProxy {
    /// Single-upstream-set proxy: every request, whatever authority it
    /// carries, round-robins over `lb`.
    pub fn new(lb: Arc<LoadBalancer<RoundRobin>>) -> Self {
        Self::routed(HostRouter::single(lb))
    }

    /// Host-routed proxy (R594-F10): each request's authority selects its
    /// upstream set. See [`crate::routing`] for what an unmatched authority
    /// does (503, never another host's backends).
    pub fn routed(router: HostRouter) -> Self {
        Self {
            router,
            auth: None,
            route_policy: RouteAuthPolicy::new(),
            upstream_tls: false,
            upstream_sni: String::new(),
            health_path: "/health".to_string(),
            draining: Arc::new(AtomicBool::new(false)),
            idle: None,
        }
    }

    /// R779: count requests into `tracker` so an [`crate::idle::IdleReaper`]
    /// can exit the process once it has been idle for its TTL. Only
    /// meaningful behind a supervisor that re-arms on exit (kamaji's JIT
    /// tier); a standalone passway should leave this unset.
    pub fn with_idle_tracker(mut self, tracker: Arc<IdleTracker>) -> Self {
        self.idle = Some(tracker);
        self
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

/// The path portion of a raw request target. Pingora's `raw_path()` returns
/// `path_and_query()` (the query string is included), so split at the first
/// `?`. Operates on bytes because the raw path is not guaranteed to be UTF-8
/// (adversarial-review FIX 2) — the UTF-8 decision happens later, in
/// [`crate::path::prepare_auth_path`].
fn path_only(raw: &[u8]) -> &[u8] {
    match raw.iter().position(|&b| b == b'?') {
        Some(i) => &raw[..i],
        None => raw,
    }
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
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    /// Always called by pingora at the end of every request, including ones
    /// `request_filter` rejected — which is what keeps the R779 idle count
    /// balanced with the `begin()` at the top of `request_filter`.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX) {
        if let Some(idle) = &self.idle {
            idle.end();
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> PResult<bool> {
        if let Some(idle) = &self.idle {
            idle.begin();
        }
        // Pull everything the filter decides on out of the (immutable)
        // request header up front as owned values, so the rest of the method
        // can mutably borrow the session to write responses.
        //
        // The auth decision is made against `raw_path()` — the true bytes
        // pingora forwards upstream — NOT `uri.path()`, which is a lossy
        // (U+FFFD-substituted) view of a non-UTF-8 path while the real bytes
        // still reach the upstream (adversarial-review FIX 2). `raw_path()`
        // returns path-and-query, so `path_only` strips the query.
        let (path_bytes, has_conflict, bearer, host) = {
            let req = session.req_header();
            let path_bytes = path_only(req.raw_path()).to_vec();
            let has_conflict = hardening::has_conflicting_length_headers(&req.headers);
            let bearer = auth::bearer_from_headers(&req.headers).map(str::to_owned);
            let host = host::request_host(&req.uri, &req.headers);
            (path_bytes, has_conflict, bearer, host)
        };

        // /health is answered directly — never gated by auth, by the
        // authority, or by upstream readiness, since its entire job is to
        // REPORT upstream readiness. Byte-exact match, so a non-UTF-8 path
        // simply misses it and falls through to the gates below.
        if path_bytes == self.health_path.as_bytes() {
            let (ready, total) = self.router.total_ready_count();
            let draining = self.draining.load(Ordering::Relaxed);
            let mut body = ReadinessBody::new(ready, total, draining);
            if self.router.is_host_routed() {
                body = body.with_hosts(
                    self.router
                        .sets()
                        .map(|(label, lb)| {
                            let (ready_upstreams, total_upstreams) = upstream::ready_count(lb);
                            HostReadiness {
                                host: label.to_string(),
                                ready_upstreams,
                                total_upstreams,
                            }
                        })
                        .collect(),
                );
            }
            let status = body.status_code();
            let json = serde_json::to_value(&body).unwrap_or_default();
            respond_json(session, status, &json).await?;
            return Ok(true);
        }

        // Smuggling hardening, early gate (defense in depth #1 — the
        // authoritative re-check on the actual forwarded request happens in
        // `upstream_request_filter`, defense in depth #2).
        if has_conflict {
            respond_json(
                session,
                400,
                &serde_json::json!({"error": "conflicting Content-Length and Transfer-Encoding"}),
            )
            .await?;
            return Ok(true);
        }

        // Per-route auth gate (V0 MUST #3). Engaged only when the policy
        // protects at least one prefix — a pure anonymous proxy skips path
        // canonicalization entirely and forwards untouched.
        if self.route_policy.has_protected_prefix() {
            // FIX 1/2: canonicalize the path to the form the upstream will
            // actually resolve, failing CLOSED (400) on a non-UTF-8 or
            // otherwise-ambiguous path — so an upstream that normalizes
            // case/slashes/dot-segments differently than a raw match can't
            // resolve an "anonymous" path into a protected one. See
            // `crate::path`.
            let canonical = match crate::path::prepare_auth_path(&path_bytes) {
                crate::path::AuthPathOutcome::Canonical(c) => c,
                crate::path::AuthPathOutcome::Reject => {
                    respond_json(
                        session,
                        400,
                        &serde_json::json!({"error": "ambiguous or non-UTF-8 request path"}),
                    )
                    .await?;
                    return Ok(true);
                }
            };

            // A route that requires auth but has no verifier configured
            // fails closed (indistinguishable from "no/invalid bearer" to the
            // caller — never leaks "this deployment is misconfigured").
            if self.route_policy.auth_required_for(&canonical) {
                let now = now_unix();
                let authed = bearer
                    .as_deref()
                    .and_then(|token| self.auth.as_ref().map(|a| (a, token)))
                    .is_some_and(|(a, token)| a.verify(token, now).is_ok());
                if !authed {
                    respond_json(session, 401, &serde_json::json!({"error": "unauthorized"}))
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Host -> upstream set (R594-F10). Deliberately after the auth
        // decision above: routing never runs ahead of the gate.
        let host = match host {
            HostOutcome::Host(h) => Some(h),
            HostOutcome::Missing => None,
            // Two disagreeing authorities on a multi-tenant front door is a
            // routing ambiguity, not a preference to resolve (see
            // `crate::host`).
            HostOutcome::Ambiguous => {
                respond_json(
                    session,
                    400,
                    &serde_json::json!({"error": "ambiguous request authority"}),
                )
                .await?;
                return Ok(true);
            }
        };

        // An authority nothing serves is 503 — the same answer as "the set
        // that serves it has no ready upstreams", and deliberately NOT a
        // fallthrough to some other host's backends. The response body says
        // nothing about which hostnames do exist.
        let Some(lb) = self.router.resolve(host.as_deref()) else {
            respond_json(
                session,
                503,
                &serde_json::json!({"error": "no ready upstreams"}),
            )
            .await?;
            return Ok(true);
        };

        // Fail-ready (R594-F6 gotcha): an empty or fully-unhealthy upstream
        // set must 503, never fall through into `upstream_peer` and error
        // out mid-connect. Scoped to the selected set: one host's backends
        // being down never borrows another host's.
        if !upstream::any_ready(lb) {
            respond_json(
                session,
                503,
                &serde_json::json!({"error": "no ready upstreams"}),
            )
            .await?;
            return Ok(true);
        }

        ctx.upstreams = Some(Arc::clone(lb));
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PResult<Box<HttpPeer>> {
        // Always the set `request_filter` resolved and readiness-gated — a
        // request can only reach here through that path, so an unset ctx is
        // a bug in this file rather than a routing miss, and fails closed
        // the same way a raced-unhealthy backend does.
        let lb = ctx.upstreams.as_ref().ok_or_else(|| {
            Error::explain(
                ErrorType::HTTPStatus(503),
                "no upstream set on the request context (request_filter did not resolve one)",
            )
        })?;
        // `key` doesn't matter for RoundRobin (see pingora's own
        // load_balancer.rs example) — b"" mirrors it verbatim.
        match lb.select(b"", 256) {
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
        // R594-S1 checklist, applied literally, on the actual request about
        // to be forwarded (defense in depth #2).
        //
        // Order matters: reject a conflicting Content-Length/Transfer-Encoding
        // pair BEFORE stripping. Transfer-Encoding is hop-by-hop, so stripping
        // it first would silently "resolve" the conflict down to Content-Length
        // — the exact resolve-don't-reject anti-pattern RFC 7230 §3.3.3 forbids
        // and the shape a smuggled request hides behind.
        if hardening::has_conflicting_length_headers(&upstream_request.headers) {
            return Err(Error::explain(
                ErrorType::HTTPStatus(400),
                "conflicting Content-Length/Transfer-Encoding at upstream_request_filter",
            ));
        }
        // Strip via RequestHeader::remove_header (NOT a direct HeaderMap
        // mutation): pingora keeps a case-preserving header map alongside the
        // value map, and mutating only the latter desyncs them and panics its
        // HTTP/1 serializer. `headers_to_strip` is a read-only pass, so
        // collect the names first, then remove.
        for name in hardening::headers_to_strip(&upstream_request.headers) {
            upstream_request.remove_header(name.as_str());
        }
        Ok(())
    }
}
