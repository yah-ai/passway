//! Host → upstream-set selection: one node fronting several services
//! (R594-F10).
//!
//! Before this module passway resolved exactly one flat upstream set and
//! round-robined every request over it regardless of which hostname the
//! request arrived for — fine for a node fronting one service, useless for a
//! node fronting marketing + analytics + a revalidate receiver, which is what
//! W267's rented-doorknob tier actually needs.
//!
//! The seam is unchanged: [`crate::upstream::UpstreamSource`] still answers
//! "what addresses exist", pingora's `TcpHealthCheck` still answers "which are
//! ready", and [`crate::upstream::build_load_balancer`] still builds the
//! round-robin. This module only puts a **map above** it — N sources, N
//! `LoadBalancer`s, keyed by normalized authority (see [`crate::host`]) — so
//! the per-set behavior every existing test pins is exactly the old behavior.
//!
//! ## Two ways for a request to find no set, both 503
//!
//! An unknown host, and a known host whose set has zero ready upstreams, are
//! both 503 (fail-ready, R594-F6's cold-start gotcha). Neither is ever
//! allowed to fall through to a *different* host's backends: that would hand
//! one tenant's traffic to another tenant's process, which is a cross-tenant
//! leak, not a routing miss. The only set that ever serves an unmatched host
//! is a [catch-all](HostRouter::set_catch_all) the operator declared on
//! purpose.
//!
//! ## Exact match only
//!
//! No wildcard (`*.example.com`) matching, and no longest-suffix search:
//! every routable name is enumerated, so what a given hostname resolves to is
//! a lookup an operator can read off the config rather than a precedence rule
//! they have to simulate. A deployment that wants a subdomain family on one
//! backend set lists the names, or declares the catch-all.
//!
//! ## How to reach the upstream is per-set too (R858-T1)
//!
//! Upstream TLS and SNI used to live on the proxy, one pair for the whole
//! process. That is fine while every fronted service is reached the same way
//! and impossible the moment one is not: putting headscale
//! (`cloud.mesh.yah.dev`, which terminates its own Let's Encrypt TLS on :443)
//! behind the same door as a plain-HTTP bundle upstream needs `tls=true` for
//! one set and `tls=false` for the other, simultaneously.
//!
//! So each set carries an optional [`UpstreamOpts`] alongside its
//! `LoadBalancer` — see [`HostUpstream`]. `None` means "whatever the proxy's
//! process-wide default is", which is exactly the pre-R858 behavior and what
//! every set on a door configured with the bare `PASSWAY_UPSTREAM_TLS=true`
//! form still gets.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use pingora::lb::selection::RoundRobin;
use pingora::lb::LoadBalancer;
use pingora::services::background::{background_service, GenBackgroundService};

use crate::upstream::{build_load_balancer, ready_count, UpstreamSource};

/// The label a catch-all upstream set reports as, in `/health` and in the
/// `PASSWAY_UPSTREAMS` config grammar.
pub const CATCH_ALL_LABEL: &str = "*";

/// Which requests an upstream set serves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostKey {
    /// Requests whose normalized authority is exactly this hostname.
    Host(String),
    /// Every request that matched no [`HostKey::Host`] entry — including a
    /// request with no authority at all. Optional, and absent by default: a
    /// multi-host deployment that declares none returns 503 for an unknown
    /// hostname instead of quietly serving it from someone else's backends.
    CatchAll,
}

/// How to *reach* one upstream set, as opposed to which addresses are in it
/// (R858-T1).
///
/// Per set rather than per process because one door can front services whose
/// upstream schemes differ — see this module's doc.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamOpts {
    /// Speak TLS to the backend. `false` is the mesh default: upstreams are
    /// reached over the already-encrypted WireGuard mesh (W267 §Design).
    pub tls: bool,
    /// SNI to present when `tls` is set. Empty is only sensible with
    /// `tls: false`.
    pub sni: String,
}

/// One upstream set as the router holds it: the health-checked round-robin
/// balancer, plus how to reach it.
///
/// `opts: None` = use the proxy-wide default
/// ([`crate::proxy::PassProxy::with_upstream_tls`]). That is what keeps every
/// currently-deployed door — which configures TLS/SNI globally or not at all —
/// behaving exactly as it did before R858-T1.
#[derive(Clone)]
pub struct HostUpstream {
    pub lb: Arc<LoadBalancer<RoundRobin>>,
    pub opts: Option<UpstreamOpts>,
}

impl HostUpstream {
    /// A set reached however the proxy is configured to reach upstreams by
    /// default.
    pub fn new(lb: Arc<LoadBalancer<RoundRobin>>) -> Self {
        Self { lb, opts: None }
    }

    /// A set with its own upstream scheme, overriding the proxy default.
    pub fn with_opts(mut self, opts: Option<UpstreamOpts>) -> Self {
        self.opts = opts;
        self
    }
}

/// Maps a request's authority to the upstream set that serves it.
///
/// Cheap to clone into the proxy; the `LoadBalancer`s themselves are shared
/// `Arc`s driven by their own pingora background services.
#[derive(Clone, Default)]
pub struct HostRouter {
    hosts: BTreeMap<String, HostUpstream>,
    catch_all: Option<HostUpstream>,
}

impl HostRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The single-set router: every request, whatever its authority, goes to
    /// `lb`. This is the pre-R594-F10 behavior exactly, and stays the shape
    /// a single-service deployment (and every pre-existing test) gets.
    pub fn single(lb: Arc<LoadBalancer<RoundRobin>>) -> Self {
        Self {
            hosts: BTreeMap::new(),
            catch_all: Some(HostUpstream::new(lb)),
        }
    }

    /// Route `host` to `upstream`. The key is normalized the same way an
    /// incoming authority is (lowercase, no port), so config and request agree.
    pub fn insert_host(&mut self, host: impl AsRef<str>, upstream: HostUpstream) {
        self.hosts.insert(normalize_key(host.as_ref()), upstream);
    }

    /// Serve every otherwise-unmatched request from `upstream`.
    pub fn set_catch_all(&mut self, upstream: HostUpstream) {
        self.catch_all = Some(upstream);
    }

    /// The upstream set for `host` (`None` = the request carried no
    /// authority), or `None` when nothing serves it.
    ///
    /// Exact match first, catch-all second. There is deliberately no third
    /// step — see the module doc.
    pub fn resolve(&self, host: Option<&str>) -> Option<&HostUpstream> {
        host.and_then(|h| self.hosts.get(h))
            .or(self.catch_all.as_ref())
    }

    /// `true` when at least one hostname is routed explicitly — i.e. this
    /// node is fronting more than "whatever the catch-all points at". Used
    /// only for logging/diagnostics.
    pub fn is_host_routed(&self) -> bool {
        !self.hosts.is_empty()
    }

    /// Every configured set with its label, catch-all last as
    /// [`CATCH_ALL_LABEL`]. Drives the per-host `/health` breakdown.
    pub fn sets(&self) -> impl Iterator<Item = (&str, &HostUpstream)> {
        self.hosts
            .iter()
            .map(|(h, u)| (h.as_str(), u))
            .chain(self.catch_all.iter().map(|u| (CATCH_ALL_LABEL, u)))
    }

    /// `(ready, total)` summed across every set — the aggregate `/health`
    /// numbers. Identical to the single set's own counts when there is only
    /// one, which is why the pre-R594-F10 `/health` body is unchanged for a
    /// single-service deployment.
    pub fn total_ready_count(&self) -> (usize, usize) {
        self.sets().fold((0, 0), |(r, t), (_, u)| {
            let (sr, st) = ready_count(&u.lb);
            (r + sr, t + st)
        })
    }
}

fn normalize_key(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// One upstream set as *configuration* describes it, before any load balancer
/// exists: which requests it serves, where its addresses come from, and how to
/// reach them.
///
/// The input shape of [`build_host_router`]. Carrying [`UpstreamOpts`] here
/// rather than on the proxy is what lets one door front an upstream that
/// terminates its own TLS next to one that speaks plain HTTP (R858-T1).
pub struct UpstreamSet {
    pub key: HostKey,
    pub source: Arc<dyn UpstreamSource>,
    /// `None` = reach this set however the proxy reaches upstreams by default.
    pub opts: Option<UpstreamOpts>,
}

impl UpstreamSet {
    /// A set reached with the proxy-wide default upstream scheme.
    pub fn new(key: HostKey, source: Arc<dyn UpstreamSource>) -> Self {
        Self {
            key,
            source,
            opts: None,
        }
    }

    /// A set with its own upstream TLS/SNI, overriding the proxy default.
    pub fn with_opts(mut self, opts: Option<UpstreamOpts>) -> Self {
        self.opts = opts;
        self
    }
}

/// Build one health-checked, round-robin `LoadBalancer` per entry in
/// `sources` and wire them into a [`HostRouter`].
///
/// Returns the router plus one pingora background service per set — the
/// caller **must** add every one of them to the `Server`, or that set's
/// discovery and health-check timers never fire and it stays permanently
/// unready (which fails to 503, not to a wrong-backend route).
///
/// A repeated [`HostKey`] keeps the last entry; a repeated
/// [`HostKey::CatchAll`] likewise. Config parsers should merge before calling
/// (see `main.rs`'s `parse_upstream_sets`), so this is a last-resort tiebreak
/// rather than the intended way to add addresses to a set.
pub fn build_host_router(
    sources: Vec<UpstreamSet>,
    health_check_frequency: Duration,
    update_frequency: Duration,
) -> (
    HostRouter,
    Vec<GenBackgroundService<LoadBalancer<RoundRobin>>>,
) {
    let mut router = HostRouter::new();
    let mut services = Vec::with_capacity(sources.len());
    for UpstreamSet { key, source, opts } in sources {
        let lb = build_load_balancer(source, health_check_frequency, update_frequency);
        let label = match &key {
            HostKey::Host(h) => h.clone(),
            HostKey::CatchAll => CATCH_ALL_LABEL.to_string(),
        };
        let service = background_service(&format!("passway upstream health [{label}]"), lb);
        let upstream = HostUpstream::new(service.task()).with_opts(opts);
        match key {
            HostKey::Host(h) => router.insert_host(h, upstream),
            HostKey::CatchAll => router.set_catch_all(upstream),
        }
        services.push(service);
    }
    (router, services)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::StaticUpstreams;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn source(port: u16) -> Arc<dyn UpstreamSource> {
        Arc::new(StaticUpstreams::new(vec![addr(port)]))
    }

    fn router(sources: Vec<UpstreamSet>) -> HostRouter {
        // The background services are dropped: these tests only exercise
        // selection, not discovery/health ticks.
        build_host_router(sources, Duration::from_secs(1), Duration::from_secs(1)).0
    }

    fn set(key: HostKey, port: u16) -> UpstreamSet {
        UpstreamSet::new(key, source(port))
    }

    fn backends_of(lb: &LoadBalancer<RoundRobin>) -> Vec<String> {
        lb.backends()
            .get_backend()
            .iter()
            .map(|b| b.addr.to_string())
            .collect()
    }

    #[tokio::test]
    async fn each_host_reaches_only_its_own_upstream_set() {
        let r = router(vec![
            set(HostKey::Host("a.example.com".into()), 9001),
            set(HostKey::Host("b.example.com".into()), 9002),
        ]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }

        let a = r.resolve(Some("a.example.com")).expect("a routes");
        let b = r.resolve(Some("b.example.com")).expect("b routes");
        assert_eq!(backends_of(&a.lb), vec!["127.0.0.1:9001"]);
        assert_eq!(backends_of(&b.lb), vec!["127.0.0.1:9002"]);
    }

    #[test]
    fn an_unknown_host_resolves_to_nothing_without_a_catch_all() {
        let r = router(vec![set(HostKey::Host("a.example.com".into()), 9001)]);
        assert!(r.resolve(Some("c.example.com")).is_none());
        // ...and so does a request that carried no authority at all.
        assert!(r.resolve(None).is_none());
    }

    #[tokio::test]
    async fn an_unknown_host_uses_the_catch_all_when_one_is_declared() {
        let r = router(vec![
            set(HostKey::Host("a.example.com".into()), 9001),
            set(HostKey::CatchAll, 9999),
        ]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        let fallback = r
            .resolve(Some("c.example.com"))
            .expect("catch-all serves it");
        assert_eq!(backends_of(&fallback.lb), vec!["127.0.0.1:9999"]);
        // An explicitly-routed host still prefers its own set.
        let a = r.resolve(Some("a.example.com")).unwrap();
        assert_eq!(backends_of(&a.lb), vec!["127.0.0.1:9001"]);
    }

    #[test]
    fn host_keys_are_matched_case_insensitively_via_normalization() {
        let r = router(vec![set(HostKey::Host("A.Example.COM.".into()), 9001)]);
        // `crate::host::request_host` hands us an already-normalized
        // authority, so the config side must normalize identically.
        assert!(r.resolve(Some("a.example.com")).is_some());
    }

    #[test]
    fn a_single_set_router_serves_every_host() {
        let lb = Arc::new(build_load_balancer(
            source(9001),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ));
        let r = HostRouter::single(lb);
        assert!(r.resolve(Some("anything.example.com")).is_some());
        assert!(r.resolve(None).is_some());
        assert!(!r.is_host_routed());
    }

    #[tokio::test]
    async fn total_ready_count_sums_every_set() {
        let r = router(vec![
            set(HostKey::Host("a.example.com".into()), 9001),
            set(HostKey::Host("b.example.com".into()), 9002),
        ]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        // One backend discovered per set, summed across both. They read as
        // ready because pingora treats a backend as healthy until a health
        // check says otherwise, and these load balancers' background
        // services (dropped by `router`) never run one — the point of the
        // assertion is the summing, not the health verdict.
        assert_eq!(r.total_ready_count(), (2, 2));
    }

    #[test]
    fn each_set_carries_its_own_upstream_scheme() {
        // R858-T1: the headscale shape — one set reached over TLS with its own
        // SNI, next to a plain-HTTP set on the same door.
        let r = router(vec![
            set(HostKey::Host("cloud.mesh.yah.dev".into()), 443).with_opts(Some(UpstreamOpts {
                tls: true,
                sni: "cloud.mesh.yah.dev".into(),
            })),
            set(HostKey::CatchAll, 9999),
        ]);
        let headscale = r.resolve(Some("cloud.mesh.yah.dev")).unwrap();
        assert_eq!(
            headscale.opts,
            Some(UpstreamOpts {
                tls: true,
                sni: "cloud.mesh.yah.dev".into()
            })
        );
        // No override = whatever the proxy's process-wide default is, which is
        // how every pre-R858 door is configured.
        assert_eq!(r.resolve(Some("anything.else")).unwrap().opts, None);
    }

    #[test]
    fn sets_labels_the_catch_all() {
        let r = router(vec![
            set(HostKey::Host("a.example.com".into()), 9001),
            set(HostKey::CatchAll, 9999),
        ]);
        let labels: Vec<&str> = r.sets().map(|(label, _)| label).collect();
        assert_eq!(labels, vec!["a.example.com", CATCH_ALL_LABEL]);
    }
}
