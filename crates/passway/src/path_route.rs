//! Prefix routing WITHIN one authority: dispatch between a service's own
//! mounted components, e.g. `/` -> the site bundle, `/app` -> the app bundle
//! (R870-F15).
//!
//! [`crate::routing::HostRouter`] answers "which upstream set serves this
//! HOST"; this module answers "which upstream set serves this PATH", for a
//! passway deployed as one service's own inner door. Same underlying pieces
//! ([`crate::upstream::UpstreamSource`], [`crate::upstream::build_load_balancer`],
//! [`crate::routing::HostUpstream`]) — this module only adds a second key
//! axis, exactly like `routing.rs`'s own doc describes for hosts. It is the
//! same ONE mechanism the outer, host-routed tier could also apply to its own
//! reserved surfaces; which tier runs it is a deployment/configuration
//! choice, not a difference in code (R870-F15).
//!
//! ## Segment-aware, not `starts_with`
//!
//! A mount `/app` matches `/app` and `/app/anything`, never `/application` —
//! see [`mount_matches`]. A naive prefix match would route `/application` to
//! the `/app` upstream; this module's test suite pins the opposite.
//!
//! ## Longest mount wins, config load rejects ambiguity
//!
//! Mounts are enumerated, never patterns — [`PathRouter::new`] rejects a
//! duplicate or malformed mount rather than picking a winner silently, and
//! precedence among the rest is a total order by mount length: an operator
//! can still read the answer off the config. That keeps the spirit of
//! [`crate::routing`]'s "no wildcards, no precedence rule to simulate"
//! policy even though a mount — unlike a hostname — necessarily covers a
//! subtree and so can't be exact-match-only.
//!
//! ## Canonicalize with the SAME function auth uses
//!
//! [`PathRouter::resolve`] takes the canonical path from
//! [`crate::path::prepare_auth_path`] — never a second normalizer — because a
//! routing decision that disagrees with the auth decision about what a path
//! "really" is lets an attacker pick the backend. See that module's docs.
//!
//! ## No mount matches -> fail exactly like an unmatched host
//!
//! Deliberately the caller's job to answer 503 (fail-ready), not 404: a
//! routing miss and a readiness miss must be indistinguishable to the
//! caller, the same reasoning [`crate::routing::HostRouter`] applies to an
//! unmatched authority — see [`PathRouter::resolve`]'s `None` case. A real
//! deployment's mount table is expected to declare a root (`""`) mount as
//! its catch-all; an unmatched request past that is a config gap, not a
//! client error worth surfacing distinctly.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use pingora::lb::selection::RoundRobin;
use pingora::lb::LoadBalancer;
use pingora::services::background::{background_service, GenBackgroundService};

use crate::routing::{HostUpstream, UpstreamOpts};
use crate::upstream::{build_load_balancer, ready_count, UpstreamSource};

/// Translate `service.toml`'s mount convention (no leading slash, e.g.
/// `"app"` for `/app`, `None`/empty for the primary component — see
/// `mesofact_bundle::assemble::collect_component_files`) to this module's
/// mount convention (leading slash, `""` for root). The ONE place that
/// translation happens: a config loader that instead formats `format!("/{m}")`
/// ad hoc at each call site is exactly the divergent-normalizer risk this
/// ticket's `path.rs` precedent warns about, just at the config boundary
/// instead of the per-request one.
pub fn mount_from_component(mount: Option<&str>) -> String {
    match mount {
        Some(m) if !m.is_empty() => format!("/{m}"),
        _ => String::new(),
    }
}

/// One mount as *configuration* describes it, before any load balancer
/// exists — the [`build_path_router`] input shape, mirroring
/// [`crate::routing::UpstreamSet`].
pub struct MountSource {
    pub mount: String,
    pub source: Arc<dyn UpstreamSource>,
    /// `None` = reach this mount however the proxy reaches upstreams by
    /// default, exactly like [`crate::routing::UpstreamSet::opts`].
    pub opts: Option<UpstreamOpts>,
    /// Extra response headers this route earns — e.g. the domain manifest's
    /// COOP/COEP pair for a wasm-isolated mount. Applied only to responses
    /// this mount served, never to a sibling mount's (R870-F15: "header
    /// ownership follows whoever matches the path").
    pub headers: Vec<(String, String)>,
}

impl MountSource {
    pub fn new(mount: impl Into<String>, source: Arc<dyn UpstreamSource>) -> Self {
        Self {
            mount: mount.into(),
            source,
            opts: None,
            headers: Vec::new(),
        }
    }

    pub fn with_opts(mut self, opts: Option<UpstreamOpts>) -> Self {
        self.opts = opts;
        self
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }
}

/// One mount as the router holds it.
pub struct PathRoute {
    pub mount: String,
    pub upstream: HostUpstream,
    pub headers: Vec<(String, String)>,
}

/// Why [`PathRouter::new`] refused a table — refusing beats silently picking
/// a winner (this ticket's doctrinal call, see the module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRouterError {
    /// Not `""` (root) and not a `/`-prefixed, non-`/`-terminated path made
    /// of `[A-Za-z0-9/_.-]` segments — no leading-slash omission, no
    /// trailing slash, no empty segment, no wildcard/pattern character.
    /// Mounts are enumerated, not patterns.
    InvalidMount(String),
    /// The same mount named twice — ambiguous precedence the config load
    /// refuses to resolve for the operator.
    DuplicateMount(String),
}

impl std::fmt::Display for PathRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathRouterError::InvalidMount(m) => write!(
                f,
                "invalid mount {m:?}: must be \"\" (root) or \"/segment[/segment...]\" \
                 with no trailing slash, no empty segment, and no wildcard characters"
            ),
            PathRouterError::DuplicateMount(m) => {
                write!(f, "duplicate mount {m:?}: the same mount cannot be declared twice")
            }
        }
    }
}

impl std::error::Error for PathRouterError {}

/// A validated, longest-mount-first table of routes for one authority.
///
/// Cheap to clone into the proxy, like [`crate::routing::HostRouter`] — the
/// `LoadBalancer`s themselves are shared `Arc`s driven by their own pingora
/// background services.
#[derive(Clone)]
pub struct PathRouter {
    // Sorted longest-mount-first at construction, so `resolve` is a single
    // forward scan whose first hit is also the longest: every mount is
    // unique (rejected otherwise) and segment-matched (see `mount_matches`),
    // so there is no pattern-language reordering that could change which
    // mount "should" win.
    routes: Arc<Vec<PathRoute>>,
}

impl std::fmt::Debug for PathRouter {
    // Manual impl: `HostUpstream` doesn't implement `Debug` (its
    // `LoadBalancer` doesn't), so `#[derive(Debug)]` on `PathRoute`/`PathRouter`
    // isn't available. This reports the one thing a test failure or an
    // operator actually wants: which mounts are configured, in match order.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathRouter")
            .field(
                "mounts",
                &self.routes.iter().map(|r| r.mount.as_str()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PathRouter {
    /// Validate and build a table directly from already-built routes. Used
    /// by [`build_path_router`]; exposed directly for tests and for a caller
    /// that already has [`HostUpstream`]s in hand.
    pub fn new(mut routes: Vec<PathRoute>) -> Result<Self, PathRouterError> {
        let mut seen = BTreeSet::new();
        for route in &routes {
            validate_mount(&route.mount)?;
            if !seen.insert(route.mount.clone()) {
                return Err(PathRouterError::DuplicateMount(route.mount.clone()));
            }
        }
        routes.sort_by_key(|r| std::cmp::Reverse(r.mount.len()));
        Ok(Self {
            routes: Arc::new(routes),
        })
    }

    /// The mount serving `canonical_path` — the output of
    /// [`crate::path::prepare_auth_path`], never a raw request path (see
    /// module docs: routing must agree with auth on the canonical form by
    /// construction). `None` when no mount claims it, including when the
    /// table has no root (`""`) catch-all; the caller must answer that the
    /// same way it answers an unmatched host (fail-ready 503), not with a
    /// distinct 404 — see the module doc.
    pub fn resolve(&self, canonical_path: &str) -> Option<&PathRoute> {
        self.routes
            .iter()
            .find(|route| mount_matches(&route.mount, canonical_path))
    }

    /// `(ready, total)` summed across every mount's upstream set — the
    /// aggregate `/health` numbers for a path-routed door.
    pub fn total_ready_count(&self) -> (usize, usize) {
        self.routes.iter().fold((0, 0), |(r, t), route| {
            let (sr, st) = ready_count(&route.upstream.lb);
            (r + sr, t + st)
        })
    }

    /// Every mount with its label (`"/"` for the root mount, else the mount
    /// itself) and upstream — drives the per-mount `/health` breakdown, the
    /// path-routed analog of [`crate::routing::HostRouter::sets`].
    pub fn sets(&self) -> impl Iterator<Item = (&str, &HostUpstream)> {
        self.routes.iter().map(|route| {
            let label = if route.mount.is_empty() {
                "/"
            } else {
                route.mount.as_str()
            };
            (label, &route.upstream)
        })
    }

    /// Number of configured mounts. Used only for diagnostics/logging.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// `true` when `path` is served by `mount` — exact match, or `mount` plus a
/// `/`-delimited continuation. Root (`""`) matches every path. Never a raw
/// `starts_with`: `/app` must not match `/application` (R870-F15's named
/// test — the naive-prefix bug this module exists to avoid).
fn mount_matches(mount: &str, path: &str) -> bool {
    if mount.is_empty() {
        return true;
    }
    path == mount || (path.starts_with(mount) && path.as_bytes().get(mount.len()) == Some(&b'/'))
}

/// A mount must be `""` (root) or a `/`-prefixed run of non-empty segments
/// drawn from `[A-Za-z0-9_.-]`, no trailing slash. This is deliberately not
/// a pattern language — see the module doc's "mounts are enumerated" policy.
fn validate_mount(mount: &str) -> Result<(), PathRouterError> {
    if mount.is_empty() {
        return Ok(());
    }
    let well_formed = mount.starts_with('/')
        && !mount.ends_with('/')
        && mount[1..].split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        });
    if well_formed {
        Ok(())
    } else {
        Err(PathRouterError::InvalidMount(mount.to_string()))
    }
}

/// Build one health-checked, round-robin `LoadBalancer` per entry in
/// `sources` and wire them into a validated [`PathRouter`] — the path-table
/// analog of [`crate::routing::build_host_router`].
///
/// Returns the router plus one pingora background service per mount — same
/// caller obligation as `build_host_router`: add every one to the `Server`,
/// or that mount's discovery/health-check timers never fire and it stays
/// permanently unready (fails to 503, never to a wrong-mount route).
/// Background services for a built router — one per mount, matching
/// [`crate::routing::build_host_router`]'s per-set shape.
pub type PathLoadBalancerServices = Vec<GenBackgroundService<LoadBalancer<RoundRobin>>>;

pub fn build_path_router(
    sources: Vec<MountSource>,
    health_check_frequency: Duration,
    update_frequency: Duration,
) -> Result<(PathRouter, PathLoadBalancerServices), PathRouterError> {
    let mut routes = Vec::with_capacity(sources.len());
    let mut services = Vec::with_capacity(sources.len());
    for MountSource {
        mount,
        source,
        opts,
        headers,
    } in sources
    {
        let lb = build_load_balancer(source, health_check_frequency, update_frequency);
        let label = if mount.is_empty() {
            "/".to_string()
        } else {
            mount.clone()
        };
        let service = background_service(&format!("passway upstream health [mount {label}]"), lb);
        let upstream = HostUpstream::new(service.task()).with_opts(opts);
        routes.push(PathRoute {
            mount,
            upstream,
            headers,
        });
        services.push(service);
    }
    let router = PathRouter::new(routes)?;
    Ok((router, services))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::StaticUpstreams;
    use std::net::SocketAddr;

    #[test]
    fn mount_from_component_matches_the_bundle_assembler_convention() {
        // mesofact_bundle::assemble::collect_component_files: None/empty is
        // the primary component (root), "app" is `/app`.
        assert_eq!(mount_from_component(None), "");
        assert_eq!(mount_from_component(Some("")), "");
        assert_eq!(mount_from_component(Some("app")), "/app");
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn source(port: u16) -> Arc<dyn UpstreamSource> {
        Arc::new(StaticUpstreams::new(vec![addr(port)]))
    }

    fn router(sources: Vec<MountSource>) -> PathRouter {
        // The background services are dropped: these tests only exercise
        // selection, not discovery/health ticks.
        build_path_router(sources, Duration::from_secs(1), Duration::from_secs(1))
            .unwrap()
            .0
    }

    fn mount(m: &str, port: u16) -> MountSource {
        MountSource::new(m, source(port))
    }

    fn backends_of(u: &HostUpstream) -> Vec<String> {
        u.lb
            .backends()
            .get_backend()
            .iter()
            .map(|b| b.addr.to_string())
            .collect()
    }

    #[tokio::test]
    async fn each_mount_reaches_only_its_own_upstream_set() {
        let r = router(vec![mount("", 9001), mount("/app", 9002)]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        let root = r.resolve("/").expect("root routes");
        let app = r.resolve("/app").expect("/app routes");
        assert_eq!(backends_of(&root.upstream), vec!["127.0.0.1:9001"]);
        assert_eq!(backends_of(&app.upstream), vec!["127.0.0.1:9002"]);
    }

    #[tokio::test]
    async fn app_subpath_reaches_the_app_mount() {
        let r = router(vec![mount("", 9001), mount("/app", 9002)]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        let hit = r.resolve("/app/settings/profile").expect("subpath routes");
        assert_eq!(backends_of(&hit.upstream), vec!["127.0.0.1:9002"]);
    }

    /// R870-F15's named verification gate: a naive `starts_with` would route
    /// `/application` to the `/app` mount. Segment-aware matching must not.
    #[tokio::test]
    async fn application_does_not_match_the_app_mount_naive_prefix_bug() {
        let r = router(vec![mount("", 9001), mount("/app", 9002)]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        let hit = r.resolve("/application").expect("root catch-all still serves it");
        assert_eq!(
            backends_of(&hit.upstream),
            vec!["127.0.0.1:9001"],
            "/application must fall to the root mount, not /app"
        );
    }

    #[tokio::test]
    async fn longest_mount_wins() {
        let r = router(vec![mount("", 9001), mount("/app", 9002), mount("/app/admin", 9003)]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        assert_eq!(
            backends_of(&r.resolve("/app/admin/panel").unwrap().upstream),
            vec!["127.0.0.1:9003"]
        );
        assert_eq!(
            backends_of(&r.resolve("/app/other").unwrap().upstream),
            vec!["127.0.0.1:9002"]
        );
        assert_eq!(
            backends_of(&r.resolve("/elsewhere").unwrap().upstream),
            vec!["127.0.0.1:9001"]
        );
    }

    #[test]
    fn no_mount_matches_without_a_root_catch_all() {
        let r = router(vec![mount("/app", 9002)]);
        assert!(r.resolve("/").is_none());
        assert!(r.resolve("/elsewhere").is_none());
        // Still must not falsely match the segment-adjacent path.
        assert!(r.resolve("/application").is_none());
    }

    #[test]
    fn duplicate_mount_is_rejected_at_construction() {
        let err = PathRouter::new(vec![
            PathRoute {
                mount: "/app".into(),
                upstream: HostUpstream::new(Arc::new(LoadBalancer::try_from_iter(["127.0.0.1:1"]).unwrap())),
                headers: vec![],
            },
            PathRoute {
                mount: "/app".into(),
                upstream: HostUpstream::new(Arc::new(LoadBalancer::try_from_iter(["127.0.0.1:2"]).unwrap())),
                headers: vec![],
            },
        ])
        .unwrap_err();
        assert_eq!(err, PathRouterError::DuplicateMount("/app".into()));
    }

    #[test]
    fn malformed_mounts_are_rejected() {
        for bad in ["app", "/app/", "//app", "/app//admin", "/app*", "/app/../etc"] {
            let err = PathRouter::new(vec![PathRoute {
                mount: bad.into(),
                upstream: HostUpstream::new(Arc::new(LoadBalancer::try_from_iter(["127.0.0.1:1"]).unwrap())),
                headers: vec![],
            }])
            .unwrap_err();
            assert!(
                matches!(err, PathRouterError::InvalidMount(_)),
                "expected {bad:?} to be rejected as malformed, got {err:?}"
            );
        }
    }

    #[test]
    fn root_and_ordinary_mounts_are_well_formed() {
        for good in ["", "/", "/app", "/app/admin", "/api-v2", "/api_v2", "/a.b"] {
            let mount = if good == "/" { "" } else { good };
            let ok = PathRouter::new(vec![PathRoute {
                mount: mount.into(),
                upstream: HostUpstream::new(Arc::new(LoadBalancer::try_from_iter(["127.0.0.1:1"]).unwrap())),
                headers: vec![],
            }]);
            assert!(ok.is_ok(), "expected {good:?} to be accepted, got {ok:?}");
        }
    }

    #[tokio::test]
    async fn headers_travel_with_their_own_mount_only() {
        let r = router(vec![
            MountSource::new("", source(9001)),
            MountSource::new("/app", source(9002)).with_headers(vec![(
                "cross-origin-opener-policy".into(),
                "same-origin".into(),
            )]),
        ]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        assert!(r.resolve("/").unwrap().headers.is_empty());
        assert_eq!(
            r.resolve("/app").unwrap().headers,
            vec![("cross-origin-opener-policy".to_string(), "same-origin".to_string())]
        );
    }

    #[tokio::test]
    async fn total_ready_count_sums_every_mount() {
        let r = router(vec![mount("", 9001), mount("/app", 9002)]);
        for (_, u) in r.sets() {
            u.lb.update().await.unwrap();
        }
        assert_eq!(r.total_ready_count(), (2, 2));
    }

    #[test]
    fn sets_labels_the_root_mount_as_slash() {
        let r = router(vec![mount("", 9001), mount("/app", 9002)]);
        let labels: Vec<&str> = r.sets().map(|(label, _)| label).collect();
        assert_eq!(labels, vec!["/app", "/"]);
    }
}
