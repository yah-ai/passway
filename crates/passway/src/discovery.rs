//! Dynamic upstream discovery from yubaba (R594-F8).
//!
//! [`crate::upstream::UpstreamSource`] is the seam; [`YubabaUpstreams`] is its
//! first dynamic implementation. It polls yubaba's service-record surface —
//! `GET /service-records?ready=true`, homed at
//! `oss/yubaba/crates/yubaba/src/service_records.rs` — and turns the returned
//! `mesh_ip:port` endpoints into the backend set
//! [`crate::upstream::build_load_balancer`] health-checks and round-robins.
//!
//! One source fronts **one workload**, named by
//! [`YubabaDiscoveryConfig::ident`]. The endpoint answers for the whole node,
//! and `?ready=true` narrows by health only — nothing in the query says which
//! workload is asking — so the ident filter lives here and nowhere else
//! (R844-B6).
//!
//! ## Why this makes passway a *provider*
//!
//! W267's seam says both ingress providers answer one question: *given the
//! workloads this fleet has placed, make them publicly reachable.* The rented
//! arm (`cloudflare-tunnel`) answers it by pushing hostname→port ingress rules
//! into Cloudflare's API, because a token-form tunnel keeps its rules
//! server-side. The sovereign arm answers it here, by pulling the same
//! placement facts from the node that owns them. Neither arm is configured by
//! hand with an upstream list; both derive from yubaba's registry. That
//! symmetry is the point — an upstream set typed into `PASSWAY_UPSTREAMS` is a
//! *deployment*, not a provider.
//!
//! [`crate::upstream::StaticUpstreams`] stays the default and stays supported:
//! it needs no control plane at all, which is what you want for a standalone
//! passway, a test fixture, or an edge node fronting something yubaba doesn't
//! place.
//!
//! ## Pull, not push
//!
//! yubaba's registry is push-on-change (`tokio::sync::watch`) *in-process*.
//! Across a process and usually a host boundary, this client polls instead,
//! because pingora already owns the clock: `Backends` re-runs discovery every
//! `update_frequency` (`PASSWAY_UPDATE_INTERVAL_SECS`, 30s default), so a
//! poll costs one small GET per tick and needs no long-lived stream, no
//! reconnect logic, and no second source of truth for "am I still connected".
//! Cost-of-deciding stays far below cost-of-acting, which is the platform's
//! mesh rule. A record's *health* is not taken on trust either way — pingora's
//! own `TcpHealthCheck` still probes every backend, exactly as the
//! `UpstreamSource` docs describe (discovery answers "exists", the health
//! check answers "ready").
//!
//! ## A failed fetch is not an empty upstream set
//!
//! The load-bearing behaviour in this module. Two states look identical to a
//! naive client and must not be conflated:
//!
//! - **yubaba says zero ready records.** Authoritative. Nothing is up; the
//!   backend set really is empty and passway fail-ready-503s (see
//!   `tests/empty_upstreams.rs`).
//! - **The fetch failed** — connection refused, timeout, malformed body, an
//!   unrecognized [`WIRE_VERSION`]. Not authoritative. yubaba restarting, or a
//!   mesh blip, would otherwise drain every backend and take the site down
//!   while the upstreams themselves were perfectly healthy.
//!
//! So a failed fetch returns the **last known good** set and logs a warning.
//! This is the consumer-side mirror of the producer-side rule in yubaba's own
//! refresh sweep: *a failed `list_workloads()` is not an empty list, so skip
//! the tick.* Staleness here is bounded by the health check, which keeps
//! probing those addresses and ejects any that stop answering — so the
//! worst case is routing to a set that is stale but still individually
//! verified, never to a black hole.
//!
//! @yah:ticket(R844-F23, "Poll-N discovery (operator decision 2026-09-04): PASSWAY_YUBABA_IDENT takes a list of yubaba URLs per hostname, lifting R844-F20's multi-node refusal")
//! @yah:at(2026-09-04T19:07:13Z)
//! @yah:status(open)
//! @yah:assignee(agent:user-custom-char-gul2)
//! @yah:parent(R844)
//! @yah:next("Operator decided the W267 open question 2026-09-04: poll-N, not raft-replicated ServiceRecords. Decision + rationale recorded in W267 §'What this deliberately does not settle' — discovery stays node-local, raft does not grow a service-record map, the candidate set degrades per-door.")
//! @yah:next("Shape: PASSWAY_YUBABA_IDENT's <hostname>= fan-in grammar (R844-F20) extends so one hostname's workload can name several yubaba URLs; the door polls each, unions the records for that ident, and the existing per-host round-robin + TcpHealthCheck decides as today. A failed poll of one source holds that source's last-known-good set (the R594-F8 constraint, per-source).")
//! @yah:next("Then lift the two R844-F20 refusals in yah cloud apply's rendering: a multi-node placement renders the self-discovering form listing each placement machine's yubaba, instead of falling back to the static set.")
//! @yah:next("Unblocks the replica-layer track (W284 grammar → R626 runtime): a redundant set is unroutable until doors can discover a multi-node backend.")
//! @yah:next("Tier: Cleric — well-scoped seam extension along an existing grammar, but the union/hold-on-failure semantics need considered tests, not speed.")

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::upstream::UpstreamSource;

/// Path of yubaba's discovery endpoint. Mirrors
/// `yubaba::service_records::DISCOVERY_PATH` — passway is its own Cargo
/// workspace and cannot depend on yubaba, so the contract is re-declared here
/// rather than shared.
pub const DISCOVERY_PATH: &str = "/service-records";

/// Wire schema version this client understands
/// (`yubaba::service_records::WIRE_VERSION`). A body announcing anything else
/// is treated as a *fetch failure*, not as an empty record set — see the
/// module docs.
pub const WIRE_VERSION: u32 = 1;

/// The one `health` tag whose record is routable
/// (`yubaba::service_records::HEALTH_READY`).
pub const HEALTH_READY: &str = "ready";

/// Body of `GET /service-records`. Only the fields this client actually reads
/// are declared; unknown fields are ignored, so yubaba may add more without
/// a version bump.
#[derive(Debug, Deserialize)]
struct ServiceRecordsWire {
    version: u32,
    records: Vec<ServiceRecordWire>,
}

#[derive(Debug, Deserialize)]
struct ServiceRecordWire {
    ident: String,
    /// Pre-paired `mesh_ip:port`, one per declared port. Taken as given rather
    /// than re-derived from `mesh_ip` + `ports` (which this client does not
    /// deserialize at all) so the pairing has exactly one implementation.
    endpoints: Vec<String>,
    health: String,
}

/// Configuration for [`YubabaUpstreams`].
#[derive(Debug, Clone)]
pub struct YubabaDiscoveryConfig {
    /// Base URL of the yubaba to ask, e.g. `http://100.64.0.2:7443`. Plain
    /// HTTP is correct here: the hop rides the WireGuard mesh, which is
    /// already encrypted and authenticated, and yubaba's listener is
    /// mesh-bound.
    pub base_url: String,
    /// Workload ident this source fronts, matched against each record's
    /// `ident` (R844-B6). Required, not optional: a node hosts several
    /// workloads and `?ready=true` narrows by health only, so a source with no
    /// ident would adopt every Ready record on the node as a backend for the
    /// one hostname it serves. If you are pulling a backend set out of
    /// yubaba's registry you know which workload you front — an absent ident
    /// is the bug, not a relaxation.
    pub ident: String,
    /// Per-request timeout. Must stay well below the `update_frequency` that
    /// drives the polls, or a hung yubaba would stall pingora's discovery
    /// tick rather than falling back to the last-known-good set.
    pub timeout: Duration,
}

impl YubabaDiscoveryConfig {
    /// Full URL polled on each tick, `?ready=true` included.
    ///
    /// Server-side filtering keeps the body small; the client filters again
    /// anyway (see [`YubabaUpstreams::addrs`]) so correctness never depends on
    /// the query parameter being honoured. [`Self::ident`] is deliberately not
    /// a query parameter — the endpoint offers no such narrowing, and the
    /// client is the only side that knows which workload it fronts.
    pub fn url(&self) -> String {
        format!(
            "{}{DISCOVERY_PATH}?ready=true",
            self.base_url.trim_end_matches('/')
        )
    }
}

/// An [`UpstreamSource`] backed by yubaba's service-record surface.
#[derive(Debug)]
pub struct YubabaUpstreams {
    client: reqwest::Client,
    url: String,
    /// The one workload ident whose records become backends — see
    /// [`YubabaDiscoveryConfig::ident`].
    ident: String,
    /// Last successfully-fetched address set. Returned verbatim when a fetch
    /// fails, so a control-plane blip cannot drain the backend set — see the
    /// module docs. `None` until the first successful fetch: a cold start with
    /// an unreachable yubaba has no good set to fall back to and correctly
    /// reports none, which passway turns into a fail-ready 503.
    last_good: Mutex<Option<Vec<SocketAddr>>>,
}

impl YubabaUpstreams {
    pub fn new(config: &YubabaDiscoveryConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            // Only fails if the TLS backend can't initialize; the same
            // `ring` provider the ACME path already installed.
            .expect("failed to build the yubaba discovery HTTP client");
        Self {
            client,
            url: config.url(),
            ident: config.ident.clone(),
            last_good: Mutex::new(None),
        }
    }

    /// One fetch. `Err` means *the answer is unknown* (transport, status,
    /// body, or version), never "there are no upstreams".
    async fn fetch(&self) -> Result<Vec<SocketAddr>, String> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("unexpected status {status}"));
        }

        let body: ServiceRecordsWire = resp
            .json()
            .await
            .map_err(|e| format!("malformed body: {e}"))?;

        addrs_from_body(&body, &self.ident, &self.url)
    }
}

/// Project a fetched body onto the dialable addresses of one workload.
///
/// Split from the request so the whole filter/parse contract is unit-testable
/// without a live yubaba. `context` only ever appears in log lines.
fn addrs_from_body(
    body: &ServiceRecordsWire,
    ident: &str,
    context: &str,
) -> Result<Vec<SocketAddr>, String> {
    if body.version != WIRE_VERSION {
        return Err(format!(
            "unsupported wire version {} (this passway speaks {WIRE_VERSION}) — \
             holding the last known upstream set rather than draining it; \
             roll yubaba and passway together",
            body.version
        ));
    }

    let mut addrs = Vec::new();
    for record in &body.records {
        // Filter client-side as well as server-side: `?ready=true` is an
        // optimization, not the guarantee. Routing to a not-ready upstream
        // because an older yubaba ignored the query param would be a real
        // outage, and the check is one string compare.
        if record.health != HEALTH_READY {
            continue;
        }
        // Filter by workload as well as by health (R844-B6). A node hosts
        // many workloads and `?ready=true` narrows by health alone — the
        // query identifies no workload at all — so without this every Ready
        // record on the polled node becomes a backend for the single
        // hostname this source fronts, and a request for one service lands
        // in another's container. Server-side filtering could never do it:
        // yubaba is not told which workload the asking passway serves.
        if record.ident != ident {
            continue;
        }
        for endpoint in &record.endpoints {
            match endpoint.parse::<SocketAddr>() {
                Ok(addr) => addrs.push(addr),
                Err(e) => log::warn!(
                    "{context}: skipping unparsable endpoint {endpoint:?} on record {:?}: {e}",
                    record.ident
                ),
            }
        }
    }
    Ok(addrs)
}

#[async_trait]
impl UpstreamSource for YubabaUpstreams {
    async fn addrs(&self) -> Vec<SocketAddr> {
        match self.fetch().await {
            Ok(addrs) => {
                if addrs.is_empty() {
                    // Authoritative empty. Record it as the good set so a
                    // later failure holds *this* answer, not a stale one from
                    // before the workloads went away.
                    log::info!(
                        "{}: yubaba reports zero ready upstreams; passway will \
                         fail-ready 503 until one appears",
                        self.url
                    );
                }
                *self.last_good.lock().expect("last_good mutex") = Some(addrs.clone());
                addrs
            }
            Err(e) => {
                let held = self.last_good.lock().expect("last_good mutex").clone();
                match held {
                    Some(addrs) => {
                        log::warn!(
                            "{}: upstream discovery failed ({e}); holding the last known \
                             {} upstream(s). A failed fetch is not an empty upstream set.",
                            self.url,
                            addrs.len()
                        );
                        addrs
                    }
                    None => {
                        log::warn!(
                            "{}: upstream discovery failed ({e}) and no previous set exists \
                             (cold start) — passway will fail-ready 503 until yubaba answers",
                            self.url
                        );
                        Vec::new()
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(base: &str) -> YubabaDiscoveryConfig {
        YubabaDiscoveryConfig {
            base_url: base.to_string(),
            ident: "api".to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    fn body(json: &str) -> ServiceRecordsWire {
        serde_json::from_str(json).expect("test fixture parses")
    }

    #[test]
    fn url_appends_the_ready_filter_and_tolerates_a_trailing_slash() {
        assert_eq!(
            cfg("http://100.64.0.2:7443").url(),
            "http://100.64.0.2:7443/service-records?ready=true"
        );
        assert_eq!(
            cfg("http://100.64.0.2:7443/").url(),
            "http://100.64.0.2:7443/service-records?ready=true"
        );
    }

    #[test]
    fn ready_records_become_dialable_addresses() {
        let b = body(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.5:8080","100.64.0.5:9090"],
                 "health":"ready","mesh_ip":"100.64.0.5","ports":[8080,9090],
                 "container_id":"c","observed_at_unix_ms":1}
            ]}"#,
        );
        assert_eq!(
            addrs_from_body(&b, "api", "test").unwrap(),
            vec![
                "100.64.0.5:8080".parse::<SocketAddr>().unwrap(),
                "100.64.0.5:9090".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn records_for_other_workloads_on_the_same_node_are_not_adopted() {
        // The R844-B6 defect: a node hosts several workloads, and the
        // endpoint answers for all of them. Fronting `api` must not put
        // `revalidate`'s container behind `api`'s hostname.
        let b = body(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.5:8080"],"health":"ready"},
                {"ident":"revalidate","endpoints":["100.64.0.5:8081"],"health":"ready"},
                {"ident":"feed","endpoints":["100.64.0.5:8082"],"health":"ready"}
            ]}"#,
        );
        let addrs = addrs_from_body(&b, "api", "test").unwrap();
        assert_eq!(
            addrs.len(),
            1,
            "exactly one backend — a non-empty assertion is what let this ship: {addrs:?}"
        );
        assert_eq!(addrs, vec!["100.64.0.5:8080".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn a_node_hosting_none_of_this_workload_yields_no_upstreams() {
        // Distinct from an unparsable body: the answer is authoritative, it
        // just contains nothing this source fronts.
        let b = body(
            r#"{"version":1,"records":[
                {"ident":"revalidate","endpoints":["100.64.0.5:8081"],"health":"ready"}
            ]}"#,
        );
        assert_eq!(addrs_from_body(&b, "api", "test").unwrap(), Vec::new());
    }

    #[test]
    fn unready_records_are_filtered_even_when_the_server_sent_them() {
        // An older yubaba that ignores `?ready=true` must not get traffic
        // routed into a stopping container.
        let b = body(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.5:80"],"health":"ready"},
                {"ident":"api","endpoints":["100.64.0.6:80"],"health":"not-ready",
                 "reason":"stopping"},
                {"ident":"api","endpoints":["100.64.0.7:80"],"health":"retracted"}
            ]}"#,
        );
        assert_eq!(
            addrs_from_body(&b, "api", "test").unwrap(),
            vec!["100.64.0.5:80".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn zero_records_is_a_valid_empty_answer_not_an_error() {
        let b = body(r#"{"version":1,"records":[]}"#);
        assert_eq!(addrs_from_body(&b, "api", "test").unwrap(), Vec::new());
    }

    #[test]
    fn an_unknown_wire_version_is_an_error_not_an_empty_set() {
        let b = body(r#"{"version":99,"records":[]}"#);
        let err = addrs_from_body(&b, "api", "test").unwrap_err();
        assert!(err.contains("unsupported wire version 99"), "got {err}");
    }

    #[test]
    fn an_unparsable_endpoint_is_skipped_not_fatal() {
        let b = body(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["not-an-addr","100.64.0.5:80"],"health":"ready"}
            ]}"#,
        );
        assert_eq!(
            addrs_from_body(&b, "api", "test").unwrap(),
            vec!["100.64.0.5:80".parse::<SocketAddr>().unwrap()],
            "one bad endpoint must not cost the record its good ones"
        );
    }

    #[tokio::test]
    async fn a_cold_start_against_an_unreachable_yubaba_yields_no_upstreams() {
        // Port 1 on loopback: nothing listens, connection refused immediately.
        let source = YubabaUpstreams::new(&YubabaDiscoveryConfig {
            base_url: "http://127.0.0.1:1".into(),
            ident: "api".into(),
            timeout: Duration::from_millis(500),
        });
        assert!(
            source.addrs().await.is_empty(),
            "no previous good set exists, so there is nothing to hold"
        );
    }

    #[tokio::test]
    async fn a_failed_fetch_holds_the_last_known_good_set() {
        let source = YubabaUpstreams::new(&YubabaDiscoveryConfig {
            base_url: "http://127.0.0.1:1".into(),
            ident: "api".into(),
            timeout: Duration::from_millis(500),
        });
        let good = vec!["100.64.0.5:8080".parse::<SocketAddr>().unwrap()];
        *source.last_good.lock().unwrap() = Some(good.clone());

        assert_eq!(
            source.addrs().await,
            good,
            "a control-plane blip must not drain the backend set"
        );
    }

    #[tokio::test]
    async fn an_authoritative_empty_answer_replaces_the_held_set() {
        // The inverse of the test above: once yubaba *does* answer and says
        // nothing is ready, that supersedes the stale set. Driven through
        // `addrs_from_body` + the same bookkeeping `addrs()` performs, since
        // this assertion is about which answer wins, not about HTTP.
        let source = YubabaUpstreams::new(&cfg("http://127.0.0.1:1"));
        *source.last_good.lock().unwrap() =
            Some(vec!["100.64.0.5:8080".parse::<SocketAddr>().unwrap()]);

        let fresh = addrs_from_body(&body(r#"{"version":1,"records":[]}"#), "api", "test").unwrap();
        *source.last_good.lock().unwrap() = Some(fresh.clone());
        assert!(fresh.is_empty());
        assert_eq!(source.last_good.lock().unwrap().as_ref().unwrap().len(), 0);
    }
}
