//! W3C Trace Context propagation and OTel span emission for the proxy path
//! (R893-F16).
//!
//! # Why passway is where a trace starts
//!
//! R893-S10 established that the public edge *structurally cannot* start a
//! trace: `passway-demux` on `:443` splices raw TCP without terminating TLS and
//! sees no plaintext (`sni-demux`'s module doc), and R777's tenant-isolation
//! verdict depends on that staying true. The `:80` `http-router` only redirects
//! or splices. **The per-tenant passway is the first process in the chain that
//! can see a header**, so it is the Envoy-sidecar analogue and it already has
//! every hook it needs — no new process, no sidecar, no mesh.
//!
//! # The OTel position
//!
//! Data model and semantic-convention attribute NAMES are OpenTelemetry's. The
//! OTel SDK is not linked, and must not be: this is the third application of
//! the position reasoned out at `oss/yubaba/crates/yubaba/src/node.rs:18-58`
//! and restated at `observation::types`'s Span section. passway ships as a
//! curl-fetched musl-static binary at a trust boundary; `opentelemetry` +
//! `opentelemetry_sdk` + `opentelemetry-otlp` is a large dependency tree to
//! take for a struct and eleven string constants that
//! [`observation`] already defines. Attribute keys come from that crate's
//! `ATTR_*` consts and are never re-spelled here.
//!
//! # The two spans, and where each one closes
//!
//! One request through this proxy produces up to two spans:
//!
//! - a **`Server`** span covering the whole downstream exchange, parented to
//!   whatever `traceparent` arrived (or a root if none did), and
//! - a **`Client`** span covering the upstream call, parented to the server
//!   span. Its span id is the one written into the forwarded `traceparent`, so
//!   the upstream's own server span parents onto *it* and the chain is
//!   caller -> Client -> Server -> callee, which is what makes the hop matrix's
//!   `kind` column mean something (R893-F15 trap (b)).
//!
//! The server span closes in [`ProxyHttp::logging`](pingora::proxy::ProxyHttp),
//! **not** in `response_filter`, which is a deliberate deviation from R893-S10's
//! sketch. Two reasons, both about what the number would otherwise mean:
//! `response_filter` runs when the upstream's *header* arrives, so a span closed
//! there reports time-to-first-byte and silently omits body transfer; and
//! `response_filter` never runs at all for a request `request_filter` rejected,
//! so every 400/401/503 — the traffic an operator most wants in the matrix —
//! would be invisible. `logging` is pingora's always-called terminal hook (it is
//! already what keeps the R779 idle count balanced), so it sees both. The client
//! span *does* close in `response_filter`: upstream-header-arrival is exactly
//! the boundary that span is measuring.
//!
//! # Sampling
//!
//! Head-based, trace-id-ratio, consistent across the fleet: the decision is a
//! function of the trace id alone (OTel's `TraceIdRatioBased`), so every hop in
//! one trace decides the same way and traces come out whole rather than
//! perforated. An inbound `traceparent` that already carries the sampled flag is
//! **honoured, not re-rolled** — re-deciding upstream of someone else's decision
//! is how a trace ends up with holes in the middle.
//!
//! The ticket flagged sampling as an operator call. The shipped default is
//! `1.0`, and the reason that is not a guess is that *the gate is the env
//! contract, not the rate*: nothing is emitted at all unless both
//! `YAH_SERVICE_IDENT` and `YAH_SCRYER_SOCKET` are present, which is a
//! deploy-time act. For scale, scryer's `quota::ServiceQuotaManager` defaults to
//! 1000 ev/s per `MeshIdent` and this emitter produces at most 2 spans per
//! request, so a door starts shedding at roughly 500 req/s.
//! `PASSWAY_TRACE_SAMPLE` dials it down without a redeploy of anything else.
//!
//! # Where spans go
//!
//! To scryer's existing local ingestion socket, as `observation::IngestLine`
//! (see that module for why that transport and not a new one). Deliberately the
//! same `YAH_SERVICE_IDENT` + `YAH_SCRYER_SOCKET` pair `yah-log` reads, so
//! R893-B17 fixes the "where is my collector" contract once for both signals
//! rather than twice.
//!
//! Emission never blocks or fails a request: [`SpanSink::emit`] is a
//! `try_send` onto a bounded channel and **drops on backpressure**. A door that
//! cannot keep up with its own telemetry must serve traffic, not stall on it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use observation::{
    AttrValue, IngestLine, Span, SpanId, SpanKind, SpanStatus, TraceId, ATTR_CLIENT_ADDRESS,
    ATTR_ERROR_TYPE, ATTR_HTTP_REQUEST_METHOD, ATTR_HTTP_RESPONSE_STATUS_CODE, ATTR_HTTP_ROUTE,
    ATTR_SERVER_ADDRESS, ATTR_SERVER_PORT, ATTR_SERVICE_NAME, ATTR_URL_PATH,
    ATTR_YAH_PEER_SERVICE,
};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Env: this door's own mesh ident, which becomes `service.name` and the
/// ingestion scope. Shared with `yah-log` by design (R893-B17).
pub const SERVICE_IDENT_ENV: &str = "YAH_SERVICE_IDENT";
/// Env: scryer's local ingestion socket. Shared with `yah-log` by design.
pub const SCRYER_SOCKET_ENV: &str = "YAH_SCRYER_SOCKET";
/// Env: head sample ratio in `0.0..=1.0`. Unset or unparseable means `1.0`.
pub const TRACE_SAMPLE_ENV: &str = "PASSWAY_TRACE_SAMPLE";

/// How many finished spans may be queued for the exporter before new ones are
/// dropped. Bounded on purpose: an unbounded queue turns a stalled collector
/// into this process's memory leak.
const EXPORT_QUEUE_DEPTH: usize = 2048;

// ─── W3C Trace Context ────────────────────────────────────────────────────────

/// `traceparent`, per W3C Trace Context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceParent {
    pub trace_id: TraceId,
    /// The *caller's* span id — this proxy's server span parents onto it.
    pub parent_span_id: SpanId,
    pub sampled: bool,
}

pub const TRACEPARENT: &str = "traceparent";

impl TraceParent {
    /// Parse an inbound header value, or `None` if it is not one this hop may
    /// continue.
    ///
    /// Deliberately strict in three places the spec is strict, because each
    /// leniency would corrupt a trace rather than lose one: version `ff` is
    /// forbidden outright; an all-zero trace or span id is the spec's "invalid"
    /// sentinel and must not be adopted as a parent; and the four fields are
    /// fixed-width, so a short field is a malformed header and not a short id.
    ///
    /// Deliberately lenient in one: a FUTURE version (anything but `00`) with a
    /// well-formed first four fields is accepted and its trailing fields are
    /// ignored, which is what the spec requires of a forward-compatible
    /// receiver. Rejecting it would sever the trace at the first hop that
    /// upgraded.
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.trim().split('-');
        let version = parts.next()?;
        let trace = parts.next()?;
        let parent = parts.next()?;
        let flags = parts.next()?;
        if version.len() != 2 || version == "ff" || !version.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        // Version 00 is exactly four fields; later versions may append more.
        if version == "00" && parts.next().is_some() {
            return None;
        }
        if flags.len() != 2 || !flags.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let trace_id = TraceId::from_hex(trace).ok()?;
        let parent_span_id = SpanId::from_hex(parent).ok()?;
        if !trace_id.is_valid() || !parent_span_id.is_valid() {
            return None;
        }
        let sampled = u8::from_str_radix(flags, 16).ok()? & 0x01 != 0;
        Some(Self { trace_id, parent_span_id, sampled })
    }

    /// Render the header this proxy writes onto the FORWARDED request. `span_id`
    /// is the client span's id, never the server span's — the upstream's server
    /// span must parent onto the leg that actually called it.
    pub fn header_value(trace_id: TraceId, span_id: SpanId, sampled: bool) -> String {
        format!(
            "00-{}-{}-{}",
            trace_id.to_hex(),
            span_id.to_hex(),
            if sampled { "01" } else { "00" }
        )
    }
}

// ─── Id minting ───────────────────────────────────────────────────────────────

/// 16 random bytes from a v4 UUID. `uuid` is already in this crate's graph via
/// `observation`, so this adds no transitive surface and no hand-rolled RNG.
fn new_trace_id() -> TraceId {
    TraceId(*uuid::Uuid::new_v4().as_bytes())
}

fn new_span_id() -> SpanId {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[..8]);
    SpanId(id)
}

// ─── Sampling ─────────────────────────────────────────────────────────────────

/// OTel `TraceIdRatioBased`: the decision is a pure function of the trace id, so
/// every hop in a trace agrees without coordinating.
#[derive(Debug, Clone, Copy)]
pub struct SampleRatio(f64);

impl SampleRatio {
    pub fn new(ratio: f64) -> Self {
        Self(ratio.clamp(0.0, 1.0))
    }

    pub fn from_env() -> Self {
        match std::env::var(TRACE_SAMPLE_ENV) {
            Ok(v) => match v.trim().parse::<f64>() {
                Ok(r) => Self::new(r),
                Err(_) => {
                    log::warn!("{TRACE_SAMPLE_ENV}={v:?} is not a number; sampling every trace");
                    Self::new(1.0)
                }
            },
            Err(_) => Self::new(1.0),
        }
    }

    pub fn decide(&self, trace_id: &TraceId) -> bool {
        if self.0 >= 1.0 {
            return true;
        }
        if self.0 <= 0.0 {
            return false;
        }
        // Low 8 bytes of the trace id as a uniform draw, per OTel's sampler.
        let mut tail = [0u8; 8];
        tail.copy_from_slice(&trace_id.0[8..]);
        let draw = u64::from_be_bytes(tail);
        (draw as f64) < self.0 * (u64::MAX as f64)
    }
}

// ─── The sink a request path writes to ────────────────────────────────────────

/// The handle `PassProxy` holds. Cheap to clone, never blocks, never errors.
#[derive(Clone)]
pub struct SpanSink {
    service_ident: std::sync::Arc<str>,
    ratio: SampleRatio,
    tx: mpsc::Sender<String>,
    dropped: std::sync::Arc<AtomicU64>,
}

impl SpanSink {
    pub fn service_ident(&self) -> &str {
        &self.service_ident
    }

    pub fn ratio(&self) -> SampleRatio {
        self.ratio
    }

    /// Queue one finished span. Serialization happens here (on the request
    /// task) so the exporter task is pure I/O and one slow span cannot stall
    /// the queue behind it.
    pub fn emit(&self, span: Span) {
        let line = match serde_json::to_string(&IngestLine::span(&*self.service_ident, span)) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("passway: span serialization failed: {e}");
                return;
            }
        };
        if self.tx.try_send(line).is_err() {
            // Backpressure or a closed exporter. Dropping is the contract: a
            // door must serve traffic rather than stall on telemetry.
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(1000) {
                log::warn!("passway: dropped {n} spans (exporter queue full or closed)");
            }
        }
    }
}

/// Build the sink plus the background service that drains it, or `None` when
/// this deployment has no collector configured.
///
/// Returning `None` rather than a no-op sink is the point: with the env
/// contract absent, the proxy holds no sink at all and the request path does no
/// trace work whatsoever — not even minting ids.
pub fn from_env() -> Option<(SpanSink, SpanExportService)> {
    let ident = std::env::var(SERVICE_IDENT_ENV).ok().filter(|s| !s.is_empty())?;
    let socket = std::env::var(SCRYER_SOCKET_ENV).ok().filter(|s| !s.is_empty())?;
    Some(to_socket(ident, socket, SampleRatio::from_env()))
}

/// [`from_env`] without the environment — the seam a caller that already knows
/// its ident, collector and ratio uses, and the one the integration tests drive
/// (process-global env vars race across tests in one binary).
pub fn to_socket(
    service_ident: String,
    socket_path: String,
    ratio: SampleRatio,
) -> (SpanSink, SpanExportService) {
    let (tx, rx) = mpsc::channel(EXPORT_QUEUE_DEPTH);
    let sink = SpanSink {
        service_ident: service_ident.into(),
        ratio,
        tx,
        dropped: std::sync::Arc::new(AtomicU64::new(0)),
    };
    let service = SpanExportService { socket_path, rx: Mutex::new(Some(rx)) };
    (sink, service)
}

// ─── The exporter ─────────────────────────────────────────────────────────────

/// Drains the span queue onto scryer's ingestion socket, reconnecting lazily.
///
/// Registered with pingora's `background_service` so it lives on the server's
/// own runtime and shuts down with it.
pub struct SpanExportService {
    socket_path: String,
    /// `BackgroundService::start` takes `&self`, so the receiver is taken out
    /// on first start. A second start would find `None` and exit immediately,
    /// which is correct — there is one queue.
    rx: Mutex<Option<mpsc::Receiver<String>>>,
}

impl SpanExportService {
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }
}

#[async_trait]
impl BackgroundService for SpanExportService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(mut rx) = self.rx.lock().unwrap().take() else {
            return;
        };
        let mut conn: Option<tokio::net::UnixStream> = None;
        loop {
            tokio::select! {
                line = rx.recv() => {
                    let Some(line) = line else { return };
                    if conn.is_none() {
                        match tokio::net::UnixStream::connect(&self.socket_path).await {
                            Ok(s) => conn = Some(s),
                            Err(e) => {
                                log::debug!(
                                    "passway: scryer ingestion socket {} unavailable: {e}",
                                    self.socket_path
                                );
                                continue;
                            }
                        }
                    }
                    let stream = conn.as_mut().expect("connected just above");
                    if stream.write_all(line.as_bytes()).await.is_err()
                        || stream.write_all(b"\n").await.is_err()
                    {
                        // Collector restarted. Drop the connection; the next
                        // span reconnects. The line in hand is lost, which is
                        // the same trade `emit` already makes.
                        conn = None;
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    }
}

// ─── Per-request state ────────────────────────────────────────────────────────

/// Everything the hooks accumulate between `request_filter` and `logging`.
///
/// Lives on `proxy::RequestCtx`. Present only when the request was sampled, so
/// an unsampled request costs one id mint and one comparison.
pub struct RequestTrace {
    trace_id: TraceId,
    server_span_id: SpanId,
    inbound_parent: Option<SpanId>,
    sampled: bool,
    start_unix_nanos: u64,
    started: Instant,

    method: String,
    path: String,
    client_address: Option<String>,
    /// Low-cardinality route: a path-routed door's matched MOUNT. `None` on a
    /// host-routed door, which genuinely does not know the app's routes — and
    /// `url.path` is NOT substituted, because `http.route` is defined as
    /// low-cardinality and a raw path would explode the rollup key.
    route: Option<String>,
    /// The logical name of the other end — `yah.peer.service`. Set from the
    /// matched mount (path-routed) or the request authority (host-routed).
    /// Load-bearing for R893-F19: `server.address` alone collapses two tenants
    /// behind one mesh IP into one row of the hop matrix.
    peer_service: Option<String>,

    client_span_id: SpanId,
    client_started: Option<Instant>,
    client_duration: Option<Duration>,
    peer_address: Option<String>,
    peer_port: Option<i64>,
    upstream_status: Option<u16>,
}

/// `http.request.method` per OTel semconv: known methods verbatim, everything
/// else collapsed to `_OTHER` so an attacker cannot mint unbounded rollup keys
/// by inventing methods.
fn semconv_method(raw: &str) -> String {
    const KNOWN: &[&str] = &[
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ];
    let upper = raw.to_ascii_uppercase();
    if KNOWN.contains(&upper.as_str()) {
        upper
    } else {
        "_OTHER".to_string()
    }
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

impl RequestTrace {
    /// Begin a trace for an inbound request, adopting `inbound` when it is a
    /// header this hop may continue. Returns `None` when the sampler said no.
    pub fn begin(
        sink: &SpanSink,
        inbound: Option<&str>,
        method: &str,
        path: &str,
    ) -> Option<Self> {
        let parsed = inbound.and_then(TraceParent::parse);
        let (trace_id, inbound_parent, sampled) = match parsed {
            // An upstream decision already made is honoured, not re-rolled.
            Some(tp) => (tp.trace_id, Some(tp.parent_span_id), tp.sampled),
            None => {
                let id = new_trace_id();
                let sampled = sink.ratio().decide(&id);
                (id, None, sampled)
            }
        };
        if !sampled {
            return None;
        }
        Some(Self {
            trace_id,
            server_span_id: new_span_id(),
            inbound_parent,
            sampled,
            start_unix_nanos: now_unix_nanos(),
            started: Instant::now(),
            method: semconv_method(method),
            path: path.to_string(),
            client_address: None,
            route: None,
            peer_service: None,
            client_span_id: new_span_id(),
            client_started: None,
            client_duration: None,
            peer_address: None,
            peer_port: None,
            upstream_status: None,
        })
    }

    /// `client.address` — the downstream peer, available on the session rather
    /// than on the request header.
    pub fn set_client_address(&mut self, addr: &str) {
        self.client_address = Some(addr.to_string());
    }

    /// The route (path-routed door) and peer service, learned in
    /// `request_filter` once routing has resolved.
    pub fn set_route(&mut self, route: Option<&str>, peer_service: Option<&str>) {
        self.route = route.map(str::to_string);
        self.peer_service = peer_service.map(str::to_string);
    }

    /// The selected backend, learned in `upstream_peer`.
    pub fn set_peer_address(&mut self, addr: &str) {
        match addr.rsplit_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok() => {
                self.peer_address = Some(host.trim_matches(['[', ']']).to_string());
                self.peer_port = port.parse::<i64>().ok();
            }
            _ => self.peer_address = Some(addr.to_string()),
        }
    }

    /// The header value to write onto the forwarded request, and the moment the
    /// client span starts.
    pub fn begin_client_leg(&mut self) -> String {
        self.client_started = Some(Instant::now());
        TraceParent::header_value(self.trace_id, self.client_span_id, self.sampled)
    }

    /// The upstream answered: close the client leg.
    pub fn end_client_leg(&mut self, status: u16) {
        self.upstream_status = Some(status);
        if let Some(started) = self.client_started {
            self.client_duration = Some(started.elapsed());
        }
    }

    /// WHAT COUNTS AS AN ERROR AT THIS HOP — the call R893-F15 says the emitter
    /// owns, made here: **5xx and a request that never got a response are
    /// errors; 4xx is not.**
    ///
    /// A 401 from the auth gate, a 400 on an ambiguous path and a 404 from the
    /// app are the door working exactly as designed; counting them would make
    /// the hop matrix's error-rate column track how many malformed requests the
    /// internet sent rather than whether this hop is broken, which is the one
    /// question it exists to answer. passway's own fail-ready 503 IS counted —
    /// it is a 5xx and it does mean the hop cannot serve.
    fn status_for(code: Option<u16>) -> SpanStatus {
        match code {
            Some(c) if c >= 500 => SpanStatus::Error { message: Some(format!("HTTP {c}")) },
            Some(_) => SpanStatus::Ok,
            None => SpanStatus::Error { message: Some("no response".to_string()) },
        }
    }

    /// `error.type`, and only when [`Self::status_for`] called it an error.
    /// OTel semconv for HTTP says this is the status code as a string — a
    /// low-cardinality discriminator, not a message.
    fn error_type_for(code: Option<u16>) -> Option<String> {
        match code {
            Some(c) if c >= 500 => Some(c.to_string()),
            Some(_) => None,
            None => Some("no_response".to_string()),
        }
    }

    fn base_attributes(&self, sink: &SpanSink) -> std::collections::BTreeMap<String, AttrValue> {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert(ATTR_SERVICE_NAME.to_string(), AttrValue::Str(sink.service_ident().to_string()));
        attrs.insert(ATTR_HTTP_REQUEST_METHOD.to_string(), AttrValue::Str(self.method.clone()));
        attrs.insert(ATTR_URL_PATH.to_string(), AttrValue::Str(self.path.clone()));
        if let Some(route) = &self.route {
            attrs.insert(ATTR_HTTP_ROUTE.to_string(), AttrValue::Str(route.clone()));
        }
        attrs
    }

    fn span_name(&self) -> String {
        match &self.route {
            Some(route) => format!("{} {route}", self.method),
            None => self.method.clone(),
        }
    }

    /// Close the trace and hand both spans to `sink`. `downstream_status` is
    /// what the client actually received; `None` means the exchange failed
    /// before any response header was written.
    pub fn finish(self, sink: &SpanSink, downstream_status: Option<u16>) {
        let total = self.started.elapsed();

        let mut server_attrs = self.base_attributes(sink);
        if let Some(client) = &self.client_address {
            server_attrs.insert(ATTR_CLIENT_ADDRESS.to_string(), AttrValue::Str(client.clone()));
        }
        if let Some(code) = downstream_status {
            // Int, never Str — a `>= 500` predicate downstream depends on it
            // (R893-F15).
            server_attrs
                .insert(ATTR_HTTP_RESPONSE_STATUS_CODE.to_string(), AttrValue::Int(code as i64));
        }
        let server_status = Self::status_for(downstream_status);
        if let Some(kind) = Self::error_type_for(downstream_status) {
            server_attrs.insert(ATTR_ERROR_TYPE.to_string(), AttrValue::Str(kind));
        }
        // The SERVER span's peer is the CALLER, and passway does not know the
        // caller's logical service name — it is the public internet. So
        // `yah.peer.service` is deliberately absent here and present on the
        // client span, where the peer is a service the mesh can name.
        sink.emit(Span {
            trace_id: self.trace_id,
            span_id: self.server_span_id,
            parent_span_id: self.inbound_parent,
            name: self.span_name(),
            kind: SpanKind::Server,
            start_unix_nanos: self.start_unix_nanos,
            duration_nanos: total.as_nanos().min(u64::MAX as u128) as u64,
            status: server_status,
            attributes: server_attrs,
        });

        // No client leg means the request never reached an upstream (a filter
        // rejection). Emitting a zero-length client span there would invent a
        // hop that did not happen.
        let Some(client_started) = self.client_started else { return };
        let client_duration = self.client_duration.unwrap_or_else(|| client_started.elapsed());
        let mut client_attrs = self.base_attributes(sink);
        if let Some(addr) = &self.peer_address {
            client_attrs.insert(ATTR_SERVER_ADDRESS.to_string(), AttrValue::Str(addr.clone()));
        }
        if let Some(port) = self.peer_port {
            client_attrs.insert(ATTR_SERVER_PORT.to_string(), AttrValue::Int(port));
        }
        if let Some(peer) = &self.peer_service {
            client_attrs.insert(ATTR_YAH_PEER_SERVICE.to_string(), AttrValue::Str(peer.clone()));
        }
        if let Some(code) = self.upstream_status {
            client_attrs
                .insert(ATTR_HTTP_RESPONSE_STATUS_CODE.to_string(), AttrValue::Int(code as i64));
        }
        let client_status = Self::status_for(self.upstream_status);
        if let Some(kind) = Self::error_type_for(self.upstream_status) {
            client_attrs.insert(ATTR_ERROR_TYPE.to_string(), AttrValue::Str(kind));
        }
        let client_start_nanos = self
            .start_unix_nanos
            .saturating_add(client_started.duration_since(self.started).as_nanos().min(u64::MAX as u128) as u64);
        sink.emit(Span {
            trace_id: self.trace_id,
            span_id: self.client_span_id,
            parent_span_id: Some(self.server_span_id),
            name: self.span_name(),
            kind: SpanKind::Client,
            start_unix_nanos: client_start_nanos,
            duration_nanos: client_duration.as_nanos().min(u64::MAX as u128) as u64,
            status: client_status,
            attributes: client_attrs,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TP: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn sink() -> (SpanSink, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(64);
        (
            SpanSink {
                service_ident: "door.mesh".into(),
                ratio: SampleRatio::new(1.0),
                tx,
                dropped: std::sync::Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    fn spans(rx: &mut mpsc::Receiver<String>) -> Vec<Span> {
        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            match serde_json::from_str::<IngestLine>(&line).unwrap() {
                IngestLine::Span { span, .. } => out.push(*span),
                other => panic!("expected a span line, got {other:?}"),
            }
        }
        out
    }

    #[test]
    fn traceparent_round_trips() {
        let tp = TraceParent::parse(SAMPLE_TP).expect("the W3C spec's own example must parse");
        assert_eq!(tp.trace_id.to_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.parent_span_id.to_hex(), "00f067aa0ba902b7");
        assert!(tp.sampled);
        assert_eq!(
            TraceParent::header_value(tp.trace_id, tp.parent_span_id, true),
            SAMPLE_TP
        );
    }

    #[test]
    fn invalid_traceparents_are_refused_rather_than_half_adopted() {
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            // all-zero trace id — the spec's invalid sentinel
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            // all-zero parent span id
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            // forbidden version
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // short trace id
            "00-4bf92f3577b34da6a3ce929d0e0e47-00f067aa0ba902b7-01",
            // non-hex
            "00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // version 00 with a trailing field
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        ] {
            assert!(TraceParent::parse(bad).is_none(), "must reject {bad:?}");
        }
    }

    #[test]
    fn a_future_version_is_continued_not_severed() {
        let tp = TraceParent::parse(
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-what-comes-next",
        )
        .expect("a forward-compatible receiver continues an unknown version");
        assert_eq!(tp.trace_id.to_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(tp.sampled);
    }

    #[test]
    fn an_inbound_trace_is_adopted_and_the_client_leg_reparents_onto_the_server_span() {
        let (sink, mut rx) = sink();
        let mut t = RequestTrace::begin(&sink, Some(SAMPLE_TP), "get", "/orders")
            .expect("an inbound sampled traceparent is always sampled");
        t.set_client_address("1.2.3.4:51000");
        t.set_route(Some("/app"), Some("noisetable-app"));
        t.set_peer_address("100.64.0.5:8080");
        let forwarded = t.begin_client_leg();
        t.end_client_leg(200);
        t.finish(&sink, Some(200));

        let out = spans(&mut rx);
        assert_eq!(out.len(), 2, "one request produces a server span and a client span");
        let server = out.iter().find(|s| s.kind == SpanKind::Server).unwrap();
        let client = out.iter().find(|s| s.kind == SpanKind::Client).unwrap();

        // Same trace as the caller, parented onto the caller's span.
        assert_eq!(server.trace_id.to_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(server.parent_span_id.unwrap().to_hex(), "00f067aa0ba902b7");
        // The client leg hangs off the server span...
        assert_eq!(client.parent_span_id, Some(server.span_id));
        // ...and the header the UPSTREAM sees names the CLIENT span, so its own
        // server span parents onto the leg that actually called it.
        assert_eq!(
            forwarded,
            TraceParent::header_value(client.trace_id, client.span_id, true)
        );

        // Semconv attributes, with the status code as an Int.
        assert_eq!(server.attr(ATTR_HTTP_REQUEST_METHOD).unwrap().as_str(), Some("GET"));
        assert_eq!(server.attr(ATTR_HTTP_RESPONSE_STATUS_CODE).unwrap().as_i64(), Some(200));
        assert_eq!(server.attr(ATTR_CLIENT_ADDRESS).unwrap().as_str(), Some("1.2.3.4:51000"));
        assert_eq!(server.attr(ATTR_HTTP_ROUTE).unwrap().as_str(), Some("/app"));
        assert_eq!(server.name, "GET /app", "low-cardinality name, not the raw path");

        // R893-F15: the hop matrix keys on peer_ident(), which must resolve to
        // the LOGICAL name, not the mesh address.
        assert_eq!(client.attr(ATTR_SERVER_ADDRESS).unwrap().as_str(), Some("100.64.0.5"));
        assert_eq!(client.attr(ATTR_SERVER_PORT).unwrap().as_i64(), Some(8080));
        assert_eq!(client.peer_ident(), Some("noisetable-app"));
    }

    #[test]
    fn a_request_with_no_traceparent_starts_a_root_trace() {
        let (sink, mut rx) = sink();
        let t = RequestTrace::begin(&sink, None, "GET", "/").unwrap();
        t.finish(&sink, Some(200));
        let out = spans(&mut rx);
        assert_eq!(out.len(), 1, "a rejected/unproxied request emits no client span");
        assert_eq!(out[0].parent_span_id, None, "a root span carries None, not an all-zero id");
        assert!(out[0].trace_id.is_valid());
    }

    #[test]
    fn a_filter_rejection_still_produces_a_server_span_and_no_phantom_hop() {
        let (sink, mut rx) = sink();
        let t = RequestTrace::begin(&sink, None, "POST", "/private").unwrap();
        // No begin_client_leg: request_filter answered 401 itself.
        t.finish(&sink, Some(401));
        let out = spans(&mut rx);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SpanKind::Server);
        assert!(!out[0].is_error(), "a 401 is the gate working, not a broken hop");
        assert_eq!(out[0].attr(ATTR_HTTP_RESPONSE_STATUS_CODE).unwrap().as_i64(), Some(401));
    }

    #[test]
    fn five_hundreds_and_dead_exchanges_are_errors_but_four_hundreds_are_not() {
        let (sink, mut rx) = sink();
        for (code, want_error) in [(200u16, false), (404, false), (499, false), (500, true), (503, true)] {
            let t = RequestTrace::begin(&sink, None, "GET", "/").unwrap();
            t.finish(&sink, Some(code));
            let out = spans(&mut rx);
            assert_eq!(out[0].is_error(), want_error, "status {code}");
        }
        let t = RequestTrace::begin(&sink, None, "GET", "/").unwrap();
        t.finish(&sink, None);
        let out = spans(&mut rx);
        assert!(out[0].is_error(), "an exchange that never answered is an error");
    }

    #[test]
    fn an_unknown_method_collapses_to_other_so_it_cannot_explode_the_rollup_key() {
        assert_eq!(semconv_method("get"), "GET");
        assert_eq!(semconv_method("PROPFIND"), "_OTHER");
        assert_eq!(semconv_method("\u{1}\u{2}"), "_OTHER");
    }

    #[test]
    fn zero_ratio_drops_everything_and_one_keeps_everything() {
        let id = new_trace_id();
        assert!(!SampleRatio::new(0.0).decide(&id));
        assert!(SampleRatio::new(1.0).decide(&id));
        // Consistency: the same trace id always decides the same way, which is
        // what keeps a trace whole across hops.
        let half = SampleRatio::new(0.5);
        assert_eq!(half.decide(&id), half.decide(&id));
    }

    #[test]
    fn an_unsampled_request_does_no_trace_work() {
        let (mut sink, _rx) = sink();
        sink.ratio = SampleRatio::new(0.0);
        assert!(RequestTrace::begin(&sink, None, "GET", "/").is_none());
    }

    #[test]
    fn emit_drops_instead_of_blocking_when_the_exporter_is_gone() {
        let (sink, rx) = sink();
        drop(rx);
        let t = RequestTrace::begin(&sink, None, "GET", "/").unwrap();
        t.finish(&sink, Some(200)); // must not panic or block
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 1);
    }
}
