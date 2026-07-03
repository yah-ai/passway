//! Pluggable upstream source (R594-F4 V0 MUST #6).
//!
//! [`UpstreamSource`] is the seam: implement it, hand an `Arc<dyn
//! UpstreamSource>` to [`build_load_balancer`], and the rest of this crate
//! (`proxy::PassProxy`, the round-robin selection, the TCP health checks)
//! never changes. V0 ships exactly one implementation, [`StaticUpstreams`]
//! — a fixed, config-supplied address list.
//!
//! ## Why not dynamic yet
//!
//! The obvious dynamic source is R594-F3's yubaba `ServiceRecords` (a
//! push-on-change, in-process registry of `workload -> mesh-IP:port` +
//! health, homed in `oss/yubaba/crates/yubaba/src/service_records.rs`).
//! Wiring it in today is impossible, not just deferred: `ServiceRecords`
//! has **no network surface** — it is an in-process `tokio::sync::watch`
//! registry inside yubaba's own server process, and nothing publishes it
//! over HTTP/gRPC/anything passway (a separate binary, typically on a
//! different rented-doorknob node) could reach. That surface is R594-F6's
//! job. Once it exists, a `YubabaUpstreams` implementing [`UpstreamSource`]
//! (poll or subscribe over that surface, filter to `Health::is_ready`,
//! return the `mesh_ip:port` set) drops in here without touching
//! `proxy.rs`, `main.rs`'s TLS/auth wiring, or any test in this crate.
//!
//! ## Empty is not an error
//!
//! An [`UpstreamSource`] returning zero addresses is a normal, expected
//! state (cold start before the first workload deploys; every workload
//! temporarily unhealthy) — R594-F6's own gotcha note is explicit that the
//! proxy "MUST tolerate a cold-start empty upstream set (fail-ready, not
//! crash)". [`build_load_balancer`] builds a working, empty-backend
//! `LoadBalancer` for this case; `LoadBalancer::select` then always returns
//! `None`, which [`crate::proxy::PassProxy`] turns into a 503 — see
//! `tests/empty_upstreams.rs`.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::health_check::TcpHealthCheck;
use pingora::lb::selection::RoundRobin;
use pingora::lb::{Backend, Backends, LoadBalancer};

/// Where passway learns which upstream addresses currently exist.
///
/// An implementor only answers "what addresses exist right now" — pingora's
/// own [`TcpHealthCheck`] (layered on top by [`build_load_balancer`]) is
/// what decides which of those addresses are *ready* to receive traffic.
/// Keeping "exists" and "ready" as separate questions (discovery vs. health
/// check) is exactly pingora's own [`Backends`] split, and it's why a
/// dynamic source doesn't need to reimplement liveness probing itself.
#[async_trait]
pub trait UpstreamSource: Send + Sync + std::fmt::Debug {
    /// Current set of upstream addresses. An empty `Vec` is valid and
    /// expected — callers must treat it as "no upstreams right now," never
    /// as an error to propagate or panic on.
    async fn addrs(&self) -> Vec<SocketAddr>;
}

/// V0's [`UpstreamSource`]: a fixed address set supplied at startup
/// (config file / env / CLI flags — `main.rs`'s concern, not this
/// module's). No I/O and nothing to refresh; `Backends`' periodic
/// re-discovery tick is a harmless no-op against this impl, kept wired
/// anyway so [`build_load_balancer`]'s behavior is identical once a
/// dynamic source is swapped in.
#[derive(Debug, Clone, Default)]
pub struct StaticUpstreams(Vec<SocketAddr>);

impl StaticUpstreams {
    pub fn new(addrs: Vec<SocketAddr>) -> Self {
        Self(addrs)
    }
}

#[async_trait]
impl UpstreamSource for StaticUpstreams {
    async fn addrs(&self) -> Vec<SocketAddr> {
        self.0.clone()
    }
}

/// Bridges any [`UpstreamSource`] into pingora's own
/// [`ServiceDiscovery`] trait — the seam [`Backends`] actually consumes.
/// Kept private: callers implement [`UpstreamSource`] and never see this
/// adapter, which is the whole point of not coupling the pluggable seam to
/// pingora's own trait shape.
#[derive(Debug)]
struct SourceDiscovery(Arc<dyn UpstreamSource>);

#[async_trait]
impl ServiceDiscovery for SourceDiscovery {
    async fn discover(&self) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let addrs = self.0.addrs().await;
        let mut backends = BTreeSet::new();
        for addr in addrs {
            backends.insert(Backend::new(&addr.to_string())?);
        }
        // No per-backend enablement override — readiness is entirely the
        // TcpHealthCheck's job (see `build_load_balancer`).
        Ok((backends, HashMap::new()))
    }
}

/// Build a round-robin, TCP-health-checked [`LoadBalancer`] over `source`.
///
/// `health_check_frequency` is V0 MUST #1 ("route to a health-checked
/// upstream set"). `update_frequency` re-polls `source.addrs()` so a future
/// dynamic source's changes are picked up without a restart; it's a
/// harmless no-op against [`StaticUpstreams`]. The caller must still run
/// the returned `LoadBalancer` as a pingora background service (see
/// `pingora::services::background::background_service`) for either timer
/// to actually fire — this function only constructs the value.
pub fn build_load_balancer(
    source: Arc<dyn UpstreamSource>,
    health_check_frequency: Duration,
    update_frequency: Duration,
) -> LoadBalancer<RoundRobin> {
    let mut backends = Backends::new(Box::new(SourceDiscovery(source)));
    backends.set_health_check(TcpHealthCheck::new());
    let mut lb = LoadBalancer::from_backends(backends);
    lb.health_check_frequency = Some(health_check_frequency);
    lb.update_frequency = Some(update_frequency);
    lb
}

/// `true` if at least one backend is currently ready to serve.
///
/// Deliberately does **not** call [`LoadBalancer::select`] to answer this:
/// `select` advances the round-robin rotation on every call, so using it
/// just to answer a yes/no readiness question would skew the real
/// selection sequence a caller relies on immediately afterward (e.g.
/// checking readiness in `request_filter` and then selecting in
/// `upstream_peer` would otherwise double-advance the rotation per
/// request). This reads [`Backends::ready`] directly instead, which is a
/// pure lookup against the last health-check result.
pub fn any_ready(lb: &LoadBalancer<RoundRobin>) -> bool {
    let backends = lb.backends();
    backends.get_backend().iter().any(|b| backends.ready(b))
}

/// `(ready, total)` backend counts — the numbers the `/health` endpoint
/// reports (see `health.rs`).
pub fn ready_count(lb: &LoadBalancer<RoundRobin>) -> (usize, usize) {
    let backends = lb.backends();
    let all = backends.get_backend();
    let ready = all.iter().filter(|b| backends.ready(b)).count();
    (ready, all.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedSource(Vec<SocketAddr>);

    #[async_trait]
    impl UpstreamSource for FixedSource {
        async fn addrs(&self) -> Vec<SocketAddr> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn empty_source_builds_a_working_empty_load_balancer() {
        let lb = build_load_balancer(
            Arc::new(FixedSource(vec![])),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        lb.update().await.expect("update against empty discovery must not error");
        assert!(!any_ready(&lb));
        assert_eq!(ready_count(&lb), (0, 0));
        // No backends at all => select() must return None, never panic.
        assert!(lb.select(b"", 1).is_none());
    }

    #[tokio::test]
    async fn discovers_backends_from_the_source_addrs() {
        let a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let lb = build_load_balancer(
            Arc::new(FixedSource(vec![a, b])),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        lb.update().await.unwrap();
        let (_, total) = ready_count(&lb);
        assert_eq!(total, 2);
    }
}
