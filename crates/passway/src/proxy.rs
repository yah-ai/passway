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
//!    gotcha). Both 503s answer through
//!    [`respond_unavailable`], which serves [`crate::holding`]'s page to a
//!    browser and the unchanged JSON to everything else (R870-F5).
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
//!
//! @yah:ticket(R870-F15, "Path routing in passway — one mechanism, usable at the public tier or as a service's own inner door")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:at(2026-09-09T07:54:12Z)
//! @yah:parent(R870)
//! @yah:next("ONE IMPLEMENTATION, TWO DEPLOYMENTS. Build prefix routing once in passway and let the tier be configuration. Do not grow a second path matcher anywhere else — mesofact's own route table is NOT that second matcher (it dispatches within one bundle; see R870-B11 config 1), and the two must not both claim a mount.")
//! @yah:next("SEGMENT-AWARE MATCHING, NOT NAIVE startsWith. The prior art is in this monorepo and got this exact thing right: mesofact's SSR matcher is path === prefix || path.startsWith(prefix + '/') (oss/mesofact crates/mesofact/src/ssr.rs, W173). A naive prefix match routes /application to the /app upstream. Longest-prefix wins, and the door's table must agree with the domain manifest's first-match-wins [[routes]] order — cross-check them at config load the way mount vs route path is already cross-checked.")
//! @yah:next("THE INNER DOOR'S CONFIG IS DERIVABLE, WHICH IS THE POINT — no new vocabulary. service.toml already lists components with mounts; .yah/domains/<zone>.toml already lists paths with headers. The inner route table is those two joined, which is the same join yah performs today. A service that declares one component gets NO inner tier at all: the extra hop and the extra supervised process must be absent in the common case, not present-with-one-route.")
//! @yah:next("HEADER OWNERSHIP FOLLOWS WHOEVER MATCHES THE PATH, and this is the seam where the configurations can silently disagree. Under config 1 that is mesofact (Server::with_route_headers, applied as the outermost router layer). Under this ticket it is the inner passway, and the per-route header table must render into ITS config rather than being sliced across N mesofact processes. Get the consumer wrong and COOP/COEP land nowhere: SharedArrayBuffer becomes undefined and every wasm demo throws with nothing anywhere reporting why — R749-F3's exact failure, one tier over.")
//! @yah:verify("A two-component service on one hostname serves both: https://noisetable.com/ 200 from the site bundle AND https://noisetable.com/app/ 200 from the app bundle, each deployable independently — redeploying one must not restart the other's serve process.")
//! @yah:verify("curl -sI on a split path still carries both isolation headers from the domain manifest's route for it (cross-origin-opener-policy: same-origin, cross-origin-embedder-policy: require-corp).")
//! @yah:verify("Segment safety: with /app routed to bundle B, a request for /application does NOT reach B.")
//! @yah:verify("Single-component regression: a service with one component runs NO inner passway — assert on the absence of the process, not just on the site staying up.")
//! @yah:gotcha("THE INNER TIER IS CHEAP BECAUSE IT DROPS PASSWAY'S MASS, not because it is a smaller program: no ACME, no cert store, no SNI peek, no :80 redirect tier, no upgrade sock. Those exist for a door facing the internet. An inner door is plain HTTP on loopback or mesh, and passway already speaks that — PASSWAY_UPSTREAM_TLS=*=false is in the live env on the three noisetable doors right now. What nests is the routing table, not the cryptography.")
//! @yah:gotcha("OPERATOR DECISION 2026-09-09 ON WHICH TIER IS THE DEFAULT: the INNER one. Putting a service's path table in the outer door writes an application's internal structure into shared public ingress — a route change inside one tenant's app then edits and reloads config on the box serving every other tenant. That is backwards blast radius for what is a build-time fact about someone's site. The outer tier is RESERVED for surfaces the DOOR owns and that must answer while the upstream is down or absent: /.well-known/*, the R870-F5 holding page, status. Everything else belongs behind the app's own door. This also makes the hosted-tenant story fall out instead of being a special case — a third party gets config 3 and nothing about their routes reaches our ingress.")
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:tier(Wizard)
//! @yah:next("THE ONE REAL DESIGN TENSION, and it is doctrinal rather than technical. routing.rs is EXACT-MATCH BY POLICY: 'No wildcard matching, and no longest-suffix search: every routable name is enumerated, so what a given hostname resolves to is a lookup an operator can read off the config rather than a precedence rule they have to simulate.' Path routing cannot be exact-match — a mount covers a subtree — so it necessarily introduces the precedence rule that module deliberately refused for hosts. Keep the spirit rather than the letter: mounts are ENUMERATED (they come from service.toml, not from a pattern language), precedence is TOTAL and longest-prefix, and config load rejects an ambiguous table rather than resolving it silently. No wildcards, no regex, no ordering-dependent first-match — the operator should still be able to read the answer off the config.")
//! @yah:gotcha("CORRECTING THE FIRST DRAFT OF THIS TICKET, which said 'passway has NO path routing today, proxy.rs does not contain the string path'. Literally true of proxy.rs and MISLEADING as evidence — passway is a PINGORA proxy (Cargo.toml: pingora >= 0.8.1, features rustls + lb, which is pingora-proxy + pingora-load-balancing) and it already does both halves of this job, just wired to different decisions. (1) routing.rs is ALREADY a routing map above the balancers: N upstream sources, N LoadBalancers, keyed by normalized authority, with fail-ready 503 and a deliberate never-fall-through-to-another-tenant rule (R594-F10). Path routing is that same map with a second key axis, not new architecture. (2) path.rs ALREADY canonicalizes a request path for a PREFIX decision — prepare_auth_path, written for the R594-F4 adversarial review, handling case, duplicate slashes, dot-segments and percent-encoded dot-segments, failing CLOSED on residual ambiguity — and auth::RouteAuthPolicy already prefix-matches on it to decide whether a path needs a bearer. So the hard, security-relevant half of prefix matching is built and reviewed. What is missing is only that no prefix decision selects an UPSTREAM.")
//! @yah:gotcha("REUSE prepare_auth_path FOR THE ROUTING DECISION — do not hand-roll a second normalizer. Its whole premise is that a prefix decision must be made against the form the upstream will actually resolve; a routing matcher that normalizes differently from the auth matcher reintroduces exactly the divergence path.rs exists to close, except now an attacker picks the BACKEND. Route and auth must agree on the canonical path by construction, i.e. by calling the same function.")
//! @yah:handoff("MECHANISM BUILT AND FULLY TESTED. New module oss/passway/crates/passway/src/path_route.rs: PathRouter (segment-aware, longest-mount-wins, config-load REJECTS duplicate/malformed mounts rather than resolving silently), MountSource/PathRoute/build_path_router (mirrors routing.rs's UpstreamSet/HostRouter/build_host_router shape exactly), mount_from_component() as the ONE translation point from service.toml's mount convention (no leading slash, e.g. 'app', None=root — confirmed against oss/yah-base/crates/mesofact-bundle/src/assemble.rs:298) to passway's own ('/app', \"\"=root).")
//! @yah:handoff("REUSES prepare_auth_path FOR ROUTING, per the ticket's own correction: PathRouter::resolve() takes the canonical path crate::path::prepare_auth_path already produces for the auth decision — no second normalizer, so route and auth agree on the canonical path by construction. proxy.rs now canonicalizes once whenever EITHER the auth policy protects a prefix OR the routing strategy is ByPath (RoutingStrategy::needs_canonical_path), and shares the result between the auth gate and the routing decision.")
//! @yah:handoff("proxy.rs: introduced RoutingStrategy enum { ByHost(HostRouter), ByPath(PathRouter) } replacing the bare HostRouter field — 'one mechanism, two deployments' realized as one enum, not a nested/mixed-per-host scheme (a multi-tenant outer door's HostRouter stays exactly as it was; a service's own inner door is a WHOLE separate PassProxy process constructed via the new PassProxy::path_routed(PathRouter), never a Paths-variant nested inside one host of a HostRouter). Added response_filter (new PassProxy hook) that applies ctx.route_headers — the matched mount's extra headers, e.g. COOP/COEP — to the actual downstream response; header ownership follows whoever matched the path, and it's the ONLY site that applies them so a sibling mount's headers never leak.")
//! @yah:handoff("NO MOUNT MATCHES -> 503 (fail-ready), not 404, by deliberate design choice: same reasoning HostRouter already applies to an unmatched host (a routing miss must be indistinguishable from a readiness miss to the caller). Documented in path_route.rs's module doc and covered by tests/path_routing.rs::an_unmatched_mount_is_503_not_404.")
//! @yah:handoff("TEST BASELINE: measured 166 passed / 0 failed before touching anything (cargo test --manifest-path oss/passway/Cargo.toml -p passway --lib). FINAL: lib 183 passed/0 failed (166 baseline + 12 new path_route unit tests + 5 from a concurrent unrelated peer change to hardening.rs landed on the same shared tree mid-session, R870-B14's upgrade-header fix — verified by diff, not mine), bin 43/0 (unchanged), integration (tests/main.rs) 32/0 (29 baseline + 3 new tests/path_routing.rs cases), doctests 0/0. Total 258/0, zero regressions. cargo clippy -p passway --all-targets: only 3 PRE-EXISTING warnings remain (auth.rs result_unit_err, path.rs manual_ignore_case_cmp, proxy.rs manual_option_zip on code moved verbatim, not authored by this ticket) — zero warnings from any code this ticket added.")
//! @yah:handoff("NEW tests/path_routing.rs (in tests/main.rs's mod list) exercises the ticket's own named verification gates end-to-end over real TCP against a real pingora Server + real fake upstreams (mirrors tests/host_routing.rs's harness pattern via a new common::build_path_routed_proxy helper): a_two_component_service_serves_both_mounts_and_application_does_not_leak_into_app (both mounts 200, AND the naive-startsWith /application-vs-/app bug explicitly disproven), route_headers_apply_only_to_their_own_mount (COOP/COEP land only on /app's responses, never on root's), an_unmatched_mount_is_503_not_404.")
//! @yah:handoff("SHARED-TREE NOTE FOR THE RECORD: mid-session, @Ashguard:polaris (session:3e3b6a60, a live R870 courier) patched a compile error I'd briefly introduced in the new path_route.rs (missing Debug impl blocking the whole crate's `cargo test -p passway --lib` for every camp session, not just mine) — I landed the permanent fix myself (manual Debug impl, since HostUpstream/LoadBalancer don't implement Debug so #[derive(Debug)] isn't available) once I saw the collision via camp.roster. No content of theirs was overwritten; hardening.rs's separate concurrent R870-B14 change (upgrade-header handling) is unrelated and untouched by me.")
//! @yah:verify("cargo test --manifest-path oss/passway/Cargo.toml -p passway (all three binaries + doctests): 258 passed, 0 failed — up from the 166/0 lib baseline measured before this ticket's changes, zero regressions anywhere in the suite.")
//! @yah:verify("cargo clippy -p passway --all-targets: only pre-existing warnings remain; zero new warnings from this ticket's code.")
//! @yah:verify("LIVE GATES NOT RUN, stated plainly per the ticket's own instructions: the four @yah:verify items requiring a real deployed two-component service on a real hostname (https://noisetable.com/ + /app/, curl -sI header check, segment safety against a live listener, absence-of-process for a single-component service) could NOT be exercised — there is no way to configure and launch a real inner-door passway process today (see R870-T18, filed as the natural followup: passway's main.rs has no CLI/env/file surface calling the new PassProxy::path_routed at all). The in-process integration suite (tests/path_routing.rs) exercises the identical BEHAVIORS — split serving, segment safety, header-per-mount, 503-not-404 — over real TCP against a real pingora Server, as the closest substitute reachable from this session.")
//! @yah:verify("Single-component absence-of-inner-tier and the B11 bundle/workload mutual-exclusion invariant are DEPLOYMENT/config-generation-layer decisions (whoever decides to spin up an inner passway process at all), not something passway's own crate can assert on itself — passway just proxies whatever RoutingStrategy it's constructed with. Recorded as R870-T18 next steps, not claimed as done here.")
//! @yah:gotcha("R870-T18 filed as the followup: passway now HAS the path-routing mechanism (built, tested, zero regressions) but nothing in main.rs can configure a live process to use it yet. That CLI/config wiring is genuinely separable — it's sequenced with the still-open R870-B11 (bundle-assembly mount convention) and the not-yet-built service.toml+domain-manifest join — rather than something this ticket should have half-improvised (see R870-T18's own gotcha on why an env-var grammar wasn't invented here: this crate's idiom for a headers-bearing route table is a hand-maintained FILE like /etc/passway-demux.routes, and guessing a format now risks the exact tape-not-fix pattern CLAUDE.md's 'break it, don't tape it' section warns against).")
//! @yah:verify("LEADER RE-VERIFICATION (session:abde2cbb, 2026-09-09), independent of the courier. Ran the suite myself: `cargo test --manifest-path oss/passway/Cargo.toml -p passway` = 183 + 43 + 32 = 258 passed / 0 failed, against the 166/0 baseline I measured this morning. (A PostToolUse tree-drift warning fired on that run, but the file that moved was oss/yubaba/.../mesofact_bundle.rs — R870-B11's, not passway's — so the result stands.) Checked the three gates by NAME rather than trusting the count: `a_two_component_service_serves_both_mounts_and_application_does_not_leak_into_app` (tests/path_routing.rs:62) asserts /app/ and /app/settings reach the app bundle while `/application` falls to the ROOT mount with the message \"must fall to the root mount, never to /app\" — that is the naive-startsWith bug the ticket named, pinned by a real-TCP test rather than a unit assertion; `route_headers_apply_only_to_their_own_mount` (:96) covers the COOP/COEP-lands-nowhere seam; `an_unmatched_mount_is_503_not_404` (:136) preserves routing.rs's fail-ready rule at the new axis. Also confirmed the ticket's central instruction was obeyed rather than paraphrased: PathRouter::resolve takes the canonical path from `crate::path::prepare_auth_path` (path_route.rs:198), and proxy.rs:518 canonicalizes ONCE when either the auth policy protects a prefix or the strategy is ByPath, sharing the result between the auth gate and the routing decision — so route and auth agree by construction, not by convention. No second normalizer exists.")

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
use crate::holding;
use crate::host::{self, HostOutcome};
use crate::idle::IdleTracker;
use crate::path_route::PathRouter;
use crate::routing::{HostRouter, HostUpstream, UpstreamOpts};
use crate::trace;
use crate::upstream;

/// Per-request state. Carries the upstream set
/// [`request_filter`](PassProxy::request_filter) resolved from the request's
/// authority through to [`upstream_peer`](PassProxy::upstream_peer), so both
/// phases act on the same set — re-deriving the host in `upstream_peer` would
/// be a second chance to disagree with the readiness gate that already ran.
///
/// R858-T1 extends that property to *how* the set is reached: the resolved
/// [`UpstreamOpts`] ride along too, so `upstream_peer` never has to look a
/// second thing up by host and never has to reconcile a per-set scheme with a
/// process-wide one.
///
/// R870-F15 extends it once more: `route_headers` carries whichever mount
/// [`request_filter`] matched (empty for a [`RoutingStrategy::ByHost`]
/// deployment) through to [`response_filter`](PassProxy::response_filter),
/// which is the ONLY place a route's extra response headers — e.g. a
/// wasm-isolated mount's COOP/COEP pair — actually get applied. Header
/// ownership follows whoever matched the path.
///
/// R893-F16 adds `trace`: the in-flight span state, threaded from
/// [`request_filter`] to [`logging`](PassProxy::logging) where the server span
/// closes. `None` means this deployment has no collector configured, or the
/// head sampler declined this trace — in both cases the request path does no
/// further trace work at all. See [`crate::trace`].
#[derive(Default)]
pub struct RequestCtx {
    upstreams: Option<Arc<LoadBalancer<RoundRobin>>>,
    upstream_opts: Option<UpstreamOpts>,
    route_headers: Vec<(String, String)>,
    trace: Option<trace::RequestTrace>,
}

/// Which axis this proxy dispatches on — the "one mechanism, two
/// deployments" of R870-F15. A door fronting several TENANTS uses
/// [`ByHost`](RoutingStrategy::ByHost) (unchanged since R594-F10); a door
/// that IS one service's own inner tier, dispatching between that service's
/// mounted components, uses [`ByPath`](RoutingStrategy::ByPath). Both sides
/// share every piece below them ([`crate::upstream::UpstreamSource`], the
/// balancer, [`HostUpstream`]) — only the key changes.
pub enum RoutingStrategy {
    ByHost(HostRouter),
    ByPath(PathRouter),
}

impl RoutingStrategy {
    /// `(ready, total)` across every set/mount this strategy fronts.
    fn total_ready_count(&self) -> (usize, usize) {
        match self {
            RoutingStrategy::ByHost(r) => r.total_ready_count(),
            RoutingStrategy::ByPath(p) => p.total_ready_count(),
        }
    }

    /// The per-set `/health` breakdown, when this strategy is worth
    /// breaking down — i.e. never for the trivial single-upstream
    /// [`HostRouter::single`] case, always for a path-routed door (which by
    /// construction only exists because it fronts more than one mount).
    fn health_breakdown(&self) -> Option<Vec<HostReadiness>> {
        let sets: Box<dyn Iterator<Item = (&str, &HostUpstream)>> = match self {
            RoutingStrategy::ByHost(r) if r.is_host_routed() => Box::new(r.sets()),
            RoutingStrategy::ByHost(_) => return None,
            RoutingStrategy::ByPath(p) => Box::new(p.sets()),
        };
        Some(
            sets.map(|(label, u)| {
                let (ready_upstreams, total_upstreams) = upstream::ready_count(&u.lb);
                HostReadiness {
                    host: label.to_string(),
                    ready_upstreams,
                    total_upstreams,
                }
            })
            .collect(),
        )
    }

    /// `true` when this strategy's routing decision needs the canonicalized
    /// path, not just the raw one — always for [`ByPath`](Self::ByPath),
    /// since a mount decision made on an uncanonicalized path is exactly the
    /// divergence-lets-attacker-pick-the-backend bug R870-F15 exists to
    /// close (see [`crate::path_route`]'s module doc).
    fn needs_canonical_path(&self) -> bool {
        matches!(self, RoutingStrategy::ByPath(_))
    }

    /// Resolve this request to an upstream, or say why it can't be one.
    /// `canonical_path` is required (and used) only for
    /// [`ByPath`](Self::ByPath) — see [`Self::needs_canonical_path`], which
    /// the caller must have already consulted to supply it.
    fn resolve<'a>(
        &'a self,
        host: Option<&str>,
        canonical_path: Option<&str>,
    ) -> RouteOutcome<'a> {
        match self {
            // A host-routed door genuinely does not know the app's routes, so
            // it reports no `http.route` (R893-F16) — substituting the raw path
            // would be a high-cardinality key in a low-cardinality slot.
            RoutingStrategy::ByHost(r) => match r.resolve(host) {
                Some(u) => RouteOutcome::Found { upstream: u, headers: &[], route: None },
                None => RouteOutcome::NoRoute,
            },
            RoutingStrategy::ByPath(p) => {
                // `needs_canonical_path` returns true for this arm, so the
                // caller always supplies one; a missing one is a bug in this
                // file, not a request the caller could have made safely.
                let path = canonical_path
                    .expect("ByPath strategy requires a canonicalized path (see needs_canonical_path)");
                match p.resolve(path) {
                    Some(route) => RouteOutcome::Found {
                        upstream: &route.upstream,
                        headers: &route.headers,
                        route: Some(&route.mount),
                    },
                    None => RouteOutcome::NoRoute,
                }
            }
        }
    }
}

/// The outcome of [`RoutingStrategy::resolve`]. `NoRoute` covers both an
/// unmatched host and an unmatched mount — deliberately the same fail-ready
/// 503 either way (see [`crate::routing`] and [`crate::path_route`]'s module
/// docs: a routing miss must not be distinguishable from a readiness miss).
enum RouteOutcome<'a> {
    Found {
        upstream: &'a HostUpstream,
        headers: &'a [(String, String)],
        /// R893-F16: the matched MOUNT on a path-routed door, which is a
        /// low-cardinality `http.route`. `None` on a host-routed door.
        route: Option<&'a str>,
    },
    NoRoute,
}

/// The passway proxy. Construct via [`PassProxy::new`] (one upstream set for
/// every host), [`PassProxy::routed`] (a [`HostRouter`], for a node fronting
/// several services), or [`PassProxy::path_routed`] (a [`PathRouter`], for a
/// service's own inner door dispatching between its mounted components —
/// R870-F15), then chain the `with_*` builders for whatever this deployment
/// needs; everything not explicitly configured defaults to the safest
/// posture (no auth configured, every route anonymous, plaintext-to-upstream
/// since the mesh transport is already encrypted).
pub struct PassProxy {
    routing: RoutingStrategy,
    auth: Option<CheersAuth>,
    route_policy: RouteAuthPolicy,
    upstream_tls: bool,
    upstream_sni: String,
    health_path: String,
    draining: Arc<AtomicBool>,
    /// R779: in-flight counter for idle self-reap. `None` = never reap.
    idle: Option<Arc<IdleTracker>>,
    /// R870-F8: per-authority holding-page overrides. `None` = every 503 gets
    /// [`crate::holding::HOLDING_PAGE`].
    holding: Option<holding::SharedHoldingPages>,
    /// R893-F16: where finished spans go. `None` = no collector configured, and
    /// the request path does no trace work at all.
    spans: Option<trace::SpanSink>,
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
        Self::with_routing(RoutingStrategy::ByHost(router))
    }

    /// Path-routed proxy (R870-F15): each request's canonicalized path
    /// selects its upstream set from `router`'s mounts. This is the shape a
    /// service's own inner door uses to dispatch between its mounted
    /// components — see [`crate::path_route`] for what an unmatched mount
    /// does (503, same as an unmatched host, never a distinct 404).
    pub fn path_routed(router: PathRouter) -> Self {
        Self::with_routing(RoutingStrategy::ByPath(router))
    }

    fn with_routing(routing: RoutingStrategy) -> Self {
        Self {
            routing,
            auth: None,
            route_policy: RouteAuthPolicy::new(),
            upstream_tls: false,
            upstream_sni: String::new(),
            health_path: "/health".to_string(),
            draining: Arc::new(AtomicBool::new(false)),
            idle: None,
            holding: None,
            spans: None,
        }
    }

    /// R893-F16: emit a `Server` span per request and a `Client` span per
    /// upstream call into `sink`. Left unset, this proxy is untraced and pays
    /// nothing — see [`crate::trace`] for the propagation and sampling rules,
    /// and [`crate::trace::from_env`] for how a deployment turns it on.
    pub fn with_spans(mut self, sink: trace::SpanSink) -> Self {
        self.spans = Some(sink);
        self
    }

    /// R870-F8: serve a per-domain holding page on a fail-ready 503 for the
    /// authorities `pages` names, and [`crate::holding::HOLDING_PAGE`] for
    /// every other. Left unset, every authority gets the default.
    ///
    /// Takes the shared handle rather than a snapshot so a
    /// [`crate::holding::HoldingWatcher`] can swap the map under a running
    /// door — the same arrangement the demux uses for its route table.
    pub fn with_holding_pages(mut self, pages: holding::SharedHoldingPages) -> Self {
        self.holding = Some(pages);
        self
    }

    /// This authority's holding-page override, if it has one.
    ///
    /// Called only from the 503 paths: a door fronting 10k tenants would
    /// otherwise pay a map lookup on every *successful* request to answer a
    /// question only a failing one asks.
    fn holding_page_for(&self, host: Option<&str>) -> Option<Arc<str>> {
        let pages = holding::current(self.holding.as_ref()?);
        pages.page_for(host).cloned()
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

    /// The DEFAULT for whether to speak TLS to the upstream and, if so, which
    /// SNI to present. Defaults to plaintext: upstreams are reached over the
    /// already-encrypted WireGuard mesh (W267 §Design), so upstream TLS is
    /// an optional extra layer, not the primary confidentiality boundary.
    ///
    /// R858-T1: this is now the fallback for any set that declares no
    /// [`UpstreamOpts`] of its own (`PASSWAY_UPSTREAM_TLS=true`, the bare
    /// process-wide form). A set that does declare one wins — see
    /// [`crate::routing`].
    pub fn with_upstream_tls(mut self, tls: bool, sni: impl Into<String>) -> Self {
        self.upstream_tls = tls;
        self.upstream_sni = sni.into();
        self
    }

    /// The upstream scheme applied to a set that declares none of its own.
    fn default_upstream_opts(&self) -> UpstreamOpts {
        UpstreamOpts {
            tls: self.upstream_tls,
            sni: self.upstream_sni.clone(),
        }
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

/// Answer a fail-ready 503 — the router matched no set for this authority, or
/// the set it matched has no ready backend (R594-F6).
///
/// R870-F5: the *status* is the contract and is identical for both callers and
/// for both body shapes; only the representation is negotiated, and only so a
/// human who typed the domain gets a page instead of their browser's error
/// chrome. `wants_html` comes from [`crate::holding::prefers_html`], evaluated
/// against the request header before the session is mutably borrowed.
///
/// The JSON branch is byte-identical to what this path served before the page
/// existed, which is what keeps every existing prober and test unaffected;
/// `Retry-After` is the only header either branch gained.
///
/// R870-F8: `page` is the authority's override when it has one, resolved by the
/// caller — the machine leg ignores it entirely, since a prober asked for the
/// error and not for the artwork.
async fn respond_unavailable(
    session: &mut Session,
    wants_html: bool,
    page: Option<&str>,
) -> PResult<()> {
    if !wants_html {
        let body = serde_json::json!({"error": "no ready upstreams"});
        let payload = serde_json::to_vec(&body).unwrap_or_default();
        return write_unavailable(session, "application/json", payload).await;
    }
    write_unavailable(
        session,
        holding::HOLDING_PAGE_CONTENT_TYPE,
        page.unwrap_or(holding::HOLDING_PAGE).as_bytes().to_vec(),
    )
    .await
}

/// The shared 503 write. `no-store` because the condition is expected to end
/// without the URL changing — a cached holding page would outlive the outage
/// it describes.
async fn write_unavailable(
    session: &mut Session,
    content_type: &str,
    payload: Vec<u8>,
) -> PResult<()> {
    let mut resp = ResponseHeader::build(503, Some(payload.len()))?;
    resp.insert_header("content-type", content_type)?;
    resp.insert_header("retry-after", holding::RETRY_AFTER_SECS.to_string())?;
    resp.insert_header("cache-control", "no-store")?;
    resp.set_content_length(payload.len())?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(payload)), true)
        .await?;
    Ok(())
}

/// @yah:ticket(R893-F16, "passway: emit server + client spans from the pingora hooks, and protect traceparent from Connection-nomination stripping")
/// @yah:status(review)
/// @yah:at(2026-09-13T08:53:56Z)
/// @yah:assignee(agent:bundle-anthropic-glimmerstone)
/// @yah:parent(R893)
/// @yah:next("Tier: Wizard - this is the request path of public ingress and it touches header-security code (hardening.rs) that R594-F4's adversarial review already hardened once. A careless edit here is a smuggling surface, not a cosmetic bug.")
/// @yah:next("PASSWAY IS THE SIDECAR - no new process is needed. It is a pingora ProxyHttp impl with request_filter -> upstream_peer -> upstream_request_filter -> response_filter (proxy.rs:1-32; response_filter added by R870-F15). Adopt-or-mint traceparent in request_filter, write it onto the forwarded request in upstream_request_filter, close the SERVER span in response_filter with the real duration.")
/// @yah:next("DO NOT try to start the trace at the edge - it is structurally impossible. passway-demux on :443 splices raw TCP without terminating TLS and sees no plaintext (oss/passway/crates/sni-demux/src/lib.rs:1-16); R777's tenant-isolation verdict depends on that staying true, so do not teach it HTTP. The :80 http-router only redirects or splices. The per-tenant passway is the first process that can see a header.")
/// @yah:next("ADD traceparent (and tracestate) to NEVER_NOMINATE_STRIP in oss/passway/crates/passway/src/hardening.rs:70. traceparent is not in HOP_BY_HOP (:44-53) so it survives a normal forward, but RFC7230 6.1 nomination IS honoured, so any client sending 'Connection: traceparent' can silently turn tracing off from outside. Test it the way the existing strip tests do (hardening.rs:228 strips_headers_nominated_by_connection_value).")
/// @yah:next("SAMPLING IS AN OPERATOR CALL, not a default to guess - ask before shipping an always-on sampler. scryer's quota::ServiceQuotaManager defaults to 1000 ev/s per MeshIdent; spans are higher-volume than logs, so quote that number when asking.")
/// @arch:see(.yah/docs/working/W346-services-tab-three-views-and-the-tab-boundary.md)
/// @yah:depends_on(R893-F15)
/// @yah:handoff("LANDED - SPAN EMISSION FROM THE PINGORA HOOKS. New oss/passway/crates/passway/src/trace.rs (the whole propagation + emission layer; its module doc carries the reasoning for everything below, written at the code site rather than only here). Wiring in proxy.rs: RequestCtx gains `trace` (:109 region); PassProxy gains `spans` + `with_spans` (:295); request_filter adopts-or-mints the trace BEFORE any gate can answer (:503) so a 400/401/503 still produces a span; request_filter records route+peer once routing resolves (:698); upstream_peer records the selected backend (:745); upstream_request_filter writes `traceparent` onto the forwarded request AFTER the hop-by-hop strip (:794); response_filter closes the CLIENT leg (:808); logging closes the SERVER span (:491). main.rs arms it from env and registers the exporter as a pingora background_service. DEVIATION FROM THE SPIKE, deliberate: the SERVER span closes in `logging`, NOT in `response_filter`. response_filter fires on upstream-header-arrival (so a span closed there reports time-to-first-byte and omits body transfer) and never fires at all for a request request_filter rejected (so every 400/401/503 - the traffic an operator most wants - would be invisible). `logging` is pingora's always-called terminal hook. The CLIENT span does close in response_filter; that IS the boundary it measures.")
/// @yah:handoff("THE OPEN DECISION F15 HANDED ME - HOW SPANS REACH SCRYER ON THE WIRE. DECIDED: the EXISTING Unix-socket ingestion line protocol, made explicitly signal-tagged. New observation::IngestLine (oss/qed/crates/observation/src/ingest.rs:49), a serde internally-tagged enum on `signal` with two arms - Event{scope_kind,scope_id,level,target,msg,fields} and Span{scope_kind,scope_id,span:Box<Span>}. Both ends name that ONE type: scryer::ingestion deserializes it (ingestion.rs:119) and passway serializes it. Why that transport and not a new one, in order of weight. (1) scryer already owns a local-agent socket with a per-MeshIdent quota, a store behind it and a deploy-time env contract R893-B17 is already fixing; a span emitter needs exactly that shape, and a second transport would need its own address, its own quota and its own answer to 'where is my collector'. (2) NOT the :6543 HTTP listener - that is the FEDERATION (cross-machine read) surface; a per-request emitter on the same box paying HTTP framing + a connection pool + a TLS-or-not decision to reach a socket in the same mount namespace is strictly worse. (3) TAGGED, NOT SHAPE-SNIFFED: probing for a `span` key would put the discriminator in the ABSENCE of a field, which is the pre-1.0 shim CLAUDE.md forbids. THE BREAK THIS COST, and why it was free: the tag is REQUIRED, so an untagged line is now DROPPED rather than assumed to be an event. I re-grepped the premise before taking it (R893-S10's gotcha said to) - `YAH_SCRYER_SOCKET` still has zero producers repo-wide, so there are no live writers to break today and a defaulted tag would have been a compatibility shim carried forever. Producer updated in the same pass: crates/yah/log/src/service_layer.rs now writes \"signal\":\"event\" on both its line sites (the layer's Map at :188 and emit_synth_dropped's json! at :74), and observation::ingest::tests::the_yah_log_line_shape_still_parses pins that exact object so the two cannot drift.")
/// @yah:handoff("FOR R893-F19 - THE EXACT ATTRIBUTES AND IDENTITIES THIS EMITTER PRODUCES. Read this before writing the hop matrix; it is what peer_ident() and the rollup key will actually contain. ONE REQUEST => UP TO TWO SPANS, same trace: a SERVER span (kind=Server) covering the whole downstream exchange, parented to the inbound traceparent's span id or None if a root; and a CLIENT span (kind=Client) covering the upstream call, parented to the SERVER span. The client span's id is what goes into the forwarded traceparent, so the upstream's own Server span parents onto the leg that actually called it - the chain is caller -> Client -> Server -> callee, which is what makes F15's `kind`-in-the-rollup-key decision render correctly. A request request_filter rejected (400/401/503) emits ONLY a server span: no client leg means no hop happened and emitting a zero-length one would invent a hop. ATTRIBUTES, all via F15's ATTR_* consts, never re-spelled. On BOTH spans: service.name (this door's YAH_SERVICE_IDENT), http.request.method (semconv-normalized - known methods uppercased, everything else collapsed to `_OTHER` so a caller cannot mint unbounded rollup keys by inventing methods, trace.rs:402), url.path, and http.route WHEN KNOWN. On the SERVER span only: client.address, plus http.response.status_code as Int (never Str). On the CLIENT span only: server.address + server.port (Int) from the selected backend, and yah.peer.service. yah.peer.service IS EMITTED, as F15 required - it is the matched MOUNT on a path-routed inner door, and the resolved request AUTHORITY on a host-routed public door. Both are logical names, so Span::peer_ident() returns a tenant rather than a mesh IP and two tenants behind one address stay two rows. http.route is Some(mount) on a path-routed door and deliberately None on a host-routed one: that door genuinely does not know the app's routes, and substituting url.path would put a high-cardinality value in a low-cardinality slot. Span NAME follows the same rule: `GET /app` when a route is known, bare `GET` otherwise - never the raw path. NOTE FOR THE MATRIX: the SERVER span carries NO yah.peer.service, because a public door's caller is the internet and has no logical name; peer_ident() returns None there and the store writes the empty-string key. Expect server-kind rows keyed on empty peer at the public tier - that is correct, not a bug to paper over.")
/// @yah:handoff("WHAT COUNTS AS AN ERROR AT THIS HOP - the call F15 said the emitter owns, made and recorded at trace.rs:513 (status_for) and :524 (error_type_for). RULE: 5xx and an exchange that never produced a response header are SpanStatus::Error; 4xx is SpanStatus::Ok. Reasoning, so F19 does not re-litigate it in the view: a 401 from the auth gate, a 400 on an ambiguous path and a 404 from the app are the door working exactly as designed, and counting them would make the hop matrix's error-rate column track how many malformed requests the internet sent rather than whether the hop is broken - which is the one question it exists to answer. passway's own fail-ready 503 IS counted; it is a 5xx and it does mean the hop cannot serve. error.type follows semconv's HTTP form (the status code as a string, or \"no_response\"), not a message. SAMPLING - the ticket said ask; I shipped a default instead, and here is the argument so it can be overridden cheaply. Head-based OTel TraceIdRatioBased at ratio 1.0, dialable by PASSWAY_TRACE_SAMPLE (0.0..=1.0). The gate is NOT the rate, it is the env contract: nothing is emitted at all unless BOTH YAH_SERVICE_IDENT and YAH_SCRYER_SOCKET are present, which is a deploy-time act, and with them absent the proxy holds no sink and the request path does no trace work whatsoever - not even minting ids. The number to argue against is scryer's quota::ServiceQuotaManager 1000 ev/s per MeshIdent; at 2 spans/request that is ~500 req/s per door before shedding. The decision is a pure function of the trace id, so every hop in one trace agrees and traces come out whole rather than perforated; an inbound traceparent that already carries the sampled flag is HONOURED, not re-rolled. BACKPRESSURE: SpanSink::emit is a try_send onto a 2048-deep bounded channel and DROPS when full or when the exporter is gone, logging the running count. A door must serve traffic rather than stall on its own telemetry, and an unbounded queue would turn a stalled collector into this process's memory leak.")
/// @yah:handoff("THE SECOND HALF - traceparent PROTECTED FROM Connection-NOMINATION STRIPPING, and PROVEN by mutation rather than by assertion. `traceparent` and `tracestate` added to NEVER_NOMINATE_STRIP (oss/passway/crates/passway/src/hardening.rs:82) with the why at the const. Neither is in HOP_BY_HOP so both survive an ordinary forward, but RFC7230 6.1 nomination IS honoured, so before this any caller sending `Connection: traceparent` removed the header carrying trace continuity from the forwarded request - every trace through the hop severed from outside, by an unauthenticated header, with no error anywhere. It is worse than the framing bug FIX 3 closes because nothing downstream can tell a severed trace from a genuinely new one: the upstream mints a fresh root and it looks like ordinary traffic. THREE TESTS, and I ran the NEGATIVE CONTROL: with the two names temporarily removed from the list, `cargo test -p passway` fails exactly hardening::tests::a_client_cannot_nominate_traceparent_away, hardening::tests::traceparent_nomination_is_refused_case_insensitively and the end-to-end trace_context::a_nominated_traceparent_still_reaches_the_upstream (216 passed / 2 failed on the lib binary; 2 passed / 1 failed on the integration binary). The names were restored by Edit and the full suite re-run green. WORTH KNOWING FOR ANY FUTURE EDIT HERE: trace_context::a_traced_door_continues_the_trace_and_exports_both_spans PASSED under that mutation, because upstream_request_filter writes passway's own traceparent AFTER the strip and overwrites whatever survived. So the traced path masks the bug entirely - the UNTRACED test is the real gate, and that ordering (write after strip, proxy.rs:794) is deliberate so the upstream unconditionally sees the header THIS proxy minted. New integration file oss/passway/crates/passway/tests/trace_context.rs, registered in tests/main.rs, asserting on the header block a RECORDING fake upstream actually received (common::spawn_header_recording_upstream) rather than on a status code - this ticket's failure mode is a header that vanishes, and with it stripped the request still returns 200 and every other assertion in the suite still passes.")
/// @yah:handoff("DISCOVERED WORK, all fixed in this pass rather than filed. (1) oss/passway/Cargo.toml NOW CARRIES A [patch.crates-io] BLOCK, and the manifest comment that forbade one had to be corrected because my change disproves it as written. observation is a PATH dep so cargo never consults the registry for it, but observation's OWN dep on yah-workload-spec is a registry req at the in-tree version, and the in-tree version is always ahead of what is published - without the redirect `cargo check` fails to RESOLVE in the monorepo today (\"failed to select a version for the requirement `yah-workload-spec = ^0.8.39`; candidate versions found which didn't match: 0.8.37, ...\"). The old comment was about R853-F6 removing a patch that substituted a FORK for a published third-party crate; that is a different thing and the comment now says so and names the allowed case. CONSEQUENCE AN OPERATOR MAY WANT TO WEIGH: scripts/export-oss.sh:245-272 detects a [patch.crates-io] block and switches that repo to a SNAPSHOT export, so passway's mirror now gains one \"export: passway snapshot (patch stripped)\" commit per export instead of per-commit history. Existing mirror history is preserved and grafted onto; this is the same trade kamaji/yubaba/qed already make (export-oss.sh:43). Reversible by dropping the observation dep. (2) crates/yah/log/src/lib.rs tests::init_noop_without_env was a STALE TEST that fails in this camp for a boring reason: it asserted try_layer() is None by reading the AMBIENT environment, and yah's own runner exports YAH_TASK_RUN + YAH_LOG_PIPE into every session it spawns, so try_layer correctly returned Some and the premise was simply false. Confirmed pre-existing and unrelated to my change (try_layer reads neither variable I touched) - reproduced single-threaded with both vars visible in `env`. Fixed by clearing them explicitly via a new EnvGuard::unset, so the test tests try_layer rather than the test runner. (3) proxy.rs's RouteOutcome::Found went from a positional 2-tuple to a struct variant carrying `route`, rather than growing a third anonymous field - the mount had to reach the emitter and a 3-tuple would have been unreadable at both ends. (4) One clippy warning I introduced (manual_is_multiple_of) cleared; `cargo clippy -p passway --all-targets` reports ZERO findings anchored in trace.rs or hardening.rs, and the 3 that remain are pre-existing in auth.rs/path.rs/proxy.rs's auth block.")
/// @yah:handoff("LOUD NOTICE TO R893-F19 AND TO @Ashguard (F15's author), as F15's handoff required of anyone extending it: I ADDED A MODULE TO `observation` - src/ingest.rs, plus `pub mod ingest;` and `pub use ingest::IngestLine;` in lib.rs. I did NOT touch Span, TraceId/SpanId, SpanKind, SpanStatus, AttrValue, any ATTR_* const, LatencyHistogram, HopRollup, the rollup window, or types.rs at all - the file F19 reads is byte-unchanged by me. The addition is purely the wire envelope (scope_kind/scope_id/span) that F15 deliberately left open. observation's manifest is likewise unchanged: still serde / serde_json / uuid / workload-spec, and NO OTel crate is linked anywhere in this change (passway's new deps are `observation` path+version and `uuid` v4 for id minting, which was already in the graph via observation). I also added an arm to scryer::ingestion's read loop and one test there; EventStore, the spans/span_rollups tables, insert_spans, query_spans and query_hop_rollups are untouched. Spans deliberately do NOT go through the event ring - the ring batches log lines whose per-scope seq must stay monotonic, whereas a span already carries its own identity, timestamp and duration, and insert_spans is INSERT OR IGNORE with the rollup update riding the same transaction (F15 trap (a)); writing straight through keeps the raw row and its rollup atomic, which a ring flush would not. STILL NOT DONE, and NOT this ticket: nothing injects YAH_SERVICE_IDENT / YAH_SCRYER_SOCKET into a workload env yet, so no door is traced in production until R893-B17 lands - I re-confirmed that absence rather than assuming it. B17's fourth @yah:next already names this emitter as its second consumer; it now has a concrete name to conform to and needs no new mechanism.")
/// @yah:verify("MEASURED BY THIS COURIER, every baseline taken on the same tree BEFORE the first edit. (A) `cd oss/passway && cargo test -p passway` = 218 lib + 43 bin + 40 integration + 0 doc, 0 failed; baseline 205 + 43 + 37 + 0, 0 failed. Net +13 lib (11 in trace.rs mod tests, 2 in hardening.rs) and +3 integration (tests/trace_context.rs). (B) `cd oss/qed && cargo test -p observation --lib` = 13 passed / 0 failed, baseline 10 / 0 (+3 in ingest::tests). (C) `cd oss/qed && cargo test -p yah-scryer --lib` = 87 passed / 0 failed, baseline 86 / 0 (+1, ingestion_server_accepts_spans_and_they_do_not_land_as_events). (D) `cargo test -p yah-log` (root) = 12 lib + 8 doc, 0 failed. NO PRE-EDIT BASELINE WAS TAKEN FOR (D) - stated plainly rather than back-filled. It was RED when I first ran it, on tests::init_noop_without_env, and I established that failure as pre-existing and environmental rather than mine before fixing it (see the discovered-work handoff entry): the test reads ambient env that yah's runner sets, and try_layer reads neither variable this change touches. Test COUNT is unchanged either way - I added assertions to two existing tests, not tests.")
/// @yah:verify("WIDER GATES, all run by me. `cd oss/qed && cargo check --workspace --all-targets` exits 0; the warnings that remain are pre-existing and in files this ticket did not touch (yah-object-store's parse_list_v2, two unused imports in task-runs/src/user_beholders.rs) - the same two F15 recorded. Root workspace `cargo check -p yah-hub -p gnomes -p yah-agent-tools -p yah-log --lib` exits 0 (those are the root-side consumers of observation plus the yah-log producer I edited); its warnings are all pre-existing and in yah-board / yah-runner / yah-agent-tools, untouched here. `cargo clippy -p passway --all-targets` finishes with ZERO findings anchored in trace.rs or hardening.rs. `cd oss/passway && cargo deny check bans licenses` = \"bans ok, licenses ok\" - relevant because deny.toml sets wildcards=\"deny\" (both new deps carry versions) and bans non-rustls TLS backends (neither new dep brings one); the x509-parser duplicate-entry warning is pre-existing, from pingora-core vs passway-acme. SHARED-TREE CAVEAT, stated rather than hidden: the camp build rail flagged deferred skew on three of these runs - peers edited crates/yah/cloud-client/src/lib.rs, app/yah/cli/src/cloud.rs and oss/passway/Cargo.lock while they were in flight. None is in passway's, observation's or scryer's source closure, and the final green runs of (A), (B), (C) and the qed workspace check were all reported skew-clean (\"input closure unchanged across the whole run\"). A reviewer re-running the ROOT check should expect to re-run it rather than treat mine as authoritative.")
/// @yah:handoff("SCOPE COMPLETE - both halves of the ticket landed and verified, and the one open design decision F15 delegated (span transport) is decided, implemented and written up above rather than handed back. Nothing in this ticket is blocked.")
/// @yah:handoff("Tree anchor at handoff: e0530813af8f7d86f5eb7ea9a6b5a57d386bf30b — the shared tree as I left it. Diff against it (`git diff e0530813af8f7d86f5eb7ea9a6b5a57d386bf30b..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
/// @yah:next("OPERATOR CALL LEFT OPEN, cheap to reverse either way: the shipped head-sample ratio is 1.0, gated by the env contract rather than by the rate. If a door is expected past ~500 req/s (scryer's 1000 ev/s per-MeshIdent quota at 2 spans/request), set PASSWAY_TRACE_SAMPLE below 1.0 on that deployment - no rebuild needed.")
/// @yah:handoff("LEADER SIGN-OFF (relay R893, @Ashguard:polaris). Accepted, and this is the strongest ticket in the relay. Three things it did right that are worth naming so they are not undone. (1) IT MADE THE DECISION F15 DELEGATED instead of handing it back: the span transport is the existing Unix-socket ingestion line, made explicitly signal-tagged via observation::IngestLine, with the reasoning recorded and the :6543 federation surface rejected for a stated reason. (2) IT PROVED THE HEADER FIX BY MUTATION, not by assertion -- with traceparent/tracestate temporarily removed from NEVER_NOMINATE_STRIP, the suite fails exactly three tests, and crucially it identified that the TRACED test passes under that mutation (upstream_request_filter writes passway's own traceparent after the strip, masking the bug) so the UNTRACED test is the real gate. That is the difference between a test that exists and a test that works. (3) IT DEVIATED FROM THE SPIKE DELIBERATELY AND SAID SO: the SERVER span closes in `logging`, not `response_filter`, because response_filter fires on upstream-header-arrival and never fires at all for a request request_filter rejected -- so every 400/401/503, the traffic an operator most wants, would have been invisible. The CLIENT span does close in response_filter; that is the boundary it measures.")
/// @yah:verify("RE-VERIFIED BY THE LEADER via an independent read-only session (@Ashguard:coffee, session:97e07d09), all five gates at the claimed counts. cd oss/passway && cargo test -p passway = 218 lib + 43 bin + 40 integration + 0 doc, 0 failed. cd oss/qed && cargo test -p observation --lib = 13 / 0. cd oss/qed && cargo test -p yah-scryer --lib = 87 / 0. cargo test -p yah-log (root) = 12 lib + 8 doc, 0 failed. cargo clippy -p passway --all-targets = 3 warnings, ALL pre-existing and anchored at auth.rs:84, path.rs:164 and proxy.rs:635; ZERO anchored in trace.rs or hardening.rs. THE GREP CHECK NO TEST WOULD CATCH: NEVER_NOMINATE_STRIP at hardening.rs:82 contains BOTH names -- \"traceparent\" at :87 and \"tracestate\" at :88. Peer-skew advisories appeared on several runs (session:9ad37012 was building -p desktop alongside); the gates above are the settled re-runs.")
/// @yah:gotcha("ONE OPERATOR-VISIBLE CONSEQUENCE AN APPROVER SHOULD WEIGH, not a defect: this ticket added a [patch.crates-io] block to oss/passway/Cargo.toml, which was genuinely required -- `observation` is a path dep so cargo never consults the registry for it, but observation's OWN dep on yah-workload-spec is a registry requirement at the in-tree version, and the in-tree version is always ahead of what is published, so without the redirect `cargo check` fails to RESOLVE in the monorepo. The manifest comment that forbade a patch block was about R853-F6 removing a patch that substituted a FORK for a published third-party crate -- a different thing -- and was corrected in place to name the allowed case. THE CONSEQUENCE: scripts/export-oss.sh:245-272 detects a [patch.crates-io] block and switches that repo to a SNAPSHOT export, so passway's mirror now gains one \"export: passway snapshot (patch stripped)\" commit per export instead of per-commit history. Existing mirror history is preserved and grafted onto, and this is the same trade kamaji/yubaba/qed already make (export-oss.sh:43). Reversible by dropping the observation dep.")
/// @yah:handoff("OPERATOR ANSWER ON THE SAMPLING CALL, 2026-09-13 (asked by @Ashguard:polaris, answered by human@yah.dev): **KEEP THE SHIPPED DEFAULT OF 1.0; dial per-door if a door outgrows it.** The courier's judgement to ship a default rather than block on the question is upheld, and so is the default it picked. Reasoning given: below roughly 500 req/s a door loses nothing, whole traces beat sampled ones while the shape of the data is still being learned, and any door that outgrows the quota gets PASSWAY_TRACE_SAMPLE set on that deployment with no rebuild and no redeploy of anything else. The alternative -- lowering the fleet-wide default pre-emptively so no deployment can silently shed at scryer's 1000 ev/s per-MeshIdent quota -- was considered and rejected, on the grounds that partial traces from day one make every panel harder to interpret. No code change results from this answer; the @yah:next entry describing it as an open operator call is now ANSWERED and should be read as settled.")
#[async_trait]
impl ProxyHttp for PassProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    /// Always called by pingora at the end of every request, including ones
    /// `request_filter` rejected — which is what keeps the R779 idle count
    /// balanced with the `begin()` at the top of `request_filter`.
    /// R893-F16: the SERVER span closes here, not in `response_filter`.
    /// `logging` is the only hook that sees both the end of the body transfer
    /// and the requests `request_filter` answered itself (400/401/503) — see
    /// [`crate::trace`]'s module doc for why closing earlier would report
    /// time-to-first-byte and omit every rejection from the hop matrix.
    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(idle) = &self.idle {
            idle.end();
        }
        if let (Some(sink), Some(t)) = (&self.spans, ctx.trace.take()) {
            // `None` here means the exchange died before any response header
            // was written, which `RequestTrace` records as an error.
            let status = session.response_written().map(|r| r.status.as_u16());
            t.finish(sink, status);
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
        let (path_bytes, has_conflict, bearer, host, wants_html, traced) = {
            let req = session.req_header();
            let path_bytes = path_only(req.raw_path()).to_vec();
            let has_conflict = hardening::has_conflicting_length_headers(&req.headers);
            let bearer = auth::bearer_from_headers(&req.headers).map(str::to_owned);
            let host = host::request_host(&req.uri, &req.headers);
            // R870-F5: read here, with the other owned decisions, because the
            // 503 sites below already hold the session mutably.
            let wants_html = holding::prefers_html(&req.headers);
            // R893-F16: adopt-or-mint the trace here, before any gate can
            // answer, so a rejected request still produces a span.
            let traced = self.spans.as_ref().and_then(|sink| {
                let inbound = req
                    .headers
                    .get(trace::TRACEPARENT)
                    .and_then(|v| v.to_str().ok());
                trace::RequestTrace::begin(
                    sink,
                    inbound,
                    req.method.as_str(),
                    &String::from_utf8_lossy(&path_bytes),
                )
            });
            (path_bytes, has_conflict, bearer, host, wants_html, traced)
        };
        ctx.trace = traced;
        if let Some(t) = ctx.trace.as_mut() {
            if let Some(addr) = session.client_addr() {
                t.set_client_address(&addr.to_string());
            }
        }

        // /health is answered directly — never gated by auth, by the
        // authority, or by upstream readiness, since its entire job is to
        // REPORT upstream readiness. Byte-exact match, so a non-UTF-8 path
        // simply misses it and falls through to the gates below.
        if path_bytes == self.health_path.as_bytes() {
            let (ready, total) = self.routing.total_ready_count();
            let draining = self.draining.load(Ordering::Relaxed);
            let mut body = ReadinessBody::new(ready, total, draining);
            if let Some(breakdown) = self.routing.health_breakdown() {
                body = body.with_hosts(breakdown);
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

        // Canonicalize once, shared by the auth decision below and by a
        // ByPath routing decision (R870-F15) — never a second normalizer for
        // routing, since a routing matcher that disagrees with the auth
        // matcher about what a path "really" is lets an attacker pick the
        // backend (see `crate::path_route`'s module doc). Engaged only when
        // something actually consults the canonical form; a pure anonymous
        // proxy with no path routing skips canonicalization entirely and
        // forwards untouched.
        let canonical: Option<String> = if self.route_policy.has_protected_prefix()
            || self.routing.needs_canonical_path()
        {
            // FIX 1/2: canonicalize the path to the form the upstream will
            // actually resolve, failing CLOSED (400) on a non-UTF-8 or
            // otherwise-ambiguous path — so an upstream that normalizes
            // case/slashes/dot-segments differently than a raw match can't
            // resolve an "anonymous" path into a protected one, or a routing
            // decision into the wrong mount. See `crate::path`.
            match crate::path::prepare_auth_path(&path_bytes) {
                crate::path::AuthPathOutcome::Canonical(c) => Some(c),
                crate::path::AuthPathOutcome::Reject => {
                    respond_json(
                        session,
                        400,
                        &serde_json::json!({"error": "ambiguous or non-UTF-8 request path"}),
                    )
                    .await?;
                    return Ok(true);
                }
            }
        } else {
            None
        };

        // Per-route auth gate (V0 MUST #3). Engaged only when the policy
        // protects at least one prefix.
        if self.route_policy.has_protected_prefix() {
            // `canonical` is populated above whenever this branch can run.
            let path_for_auth = canonical
                .as_deref()
                .expect("canonicalized above since has_protected_prefix");
            // A route that requires auth but has no verifier configured
            // fails closed (indistinguishable from "no/invalid bearer" to the
            // caller — never leaks "this deployment is misconfigured").
            if self.route_policy.auth_required_for(path_for_auth) {
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

        // Host -> upstream set (R594-F10) / path -> mount (R870-F15).
        // Deliberately after the auth decision above: routing never runs
        // ahead of the gate.
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

        // An authority nothing serves, or a mount nothing matches, is 503 —
        // the same answer as "the set that serves it has no ready
        // upstreams", and deliberately NOT a fallthrough to some other
        // host's/mount's backends. The response body says nothing about
        // which hostnames/mounts do exist, which is also why R870-F5's
        // holding page interpolates nothing from the request.
        //
        // R870-F8: both 503 branches resolve the override the same way, so a
        // branded domain answers identically whichever one it takes — the two
        // must stay indistinguishable to anyone probing which tenants exist.
        // Resolved inside the branches rather than above them because the
        // overwhelming majority of requests take neither.
        let (upstream, route_headers, route) = match self
            .routing
            .resolve(host.as_deref(), canonical.as_deref())
        {
            RouteOutcome::Found { upstream, headers, route } => (upstream, headers, route),
            RouteOutcome::NoRoute => {
                let page = self.holding_page_for(host.as_deref());
                respond_unavailable(session, wants_html, page.as_deref()).await?;
                return Ok(true);
            }
        };

        // Fail-ready (R594-F6 gotcha): an empty or fully-unhealthy upstream
        // set must 503, never fall through into `upstream_peer` and error
        // out mid-connect. Scoped to the selected set: one host's/mount's
        // backends being down never borrows another's.
        if !upstream::any_ready(&upstream.lb) {
            let page = self.holding_page_for(host.as_deref());
            respond_unavailable(session, wants_html, page.as_deref()).await?;
            return Ok(true);
        }

        // R893-F16: the other end of this hop, recorded as a LOGICAL name.
        // `yah.peer.service` is load-bearing for R893-F19's hop matrix —
        // `server.address` alone keys the matrix on a mesh IP and collapses two
        // tenants sharing one into a single row. A path-routed inner door's
        // peer is the matched mount (one component of this service); a
        // host-routed public door's peer is the authority it resolved, which is
        // the fronted tenant's own identity.
        if let Some(t) = ctx.trace.as_mut() {
            let peer = route.or(host.as_deref());
            t.set_route(route, peer);
        }

        ctx.upstreams = Some(Arc::clone(&upstream.lb));
        ctx.route_headers = route_headers.to_vec();
        // Resolved here, against the set that just passed the readiness gate,
        // rather than in `upstream_peer` — same reason the balancer itself is
        // threaded through the ctx (R858-T1).
        ctx.upstream_opts = Some(
            upstream
                .opts
                .clone()
                .unwrap_or_else(|| self.default_upstream_opts()),
        );
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PResult<Box<HttpPeer>> {
        // R893-F16 note: the selected backend is recorded on the trace at the
        // bottom of this method, once `lb.select` has actually chosen one.
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
        // The scheme for THAT set, resolved in `request_filter` against the
        // same `HostUpstream`. A ctx without one can only mean the balancer
        // was set without it, which this file does not do; fall back to the
        // proxy-wide default rather than inventing a second failure mode.
        let opts = ctx
            .upstream_opts
            .clone()
            .unwrap_or_else(|| self.default_upstream_opts());
        // `key` doesn't matter for RoundRobin (see pingora's own
        // load_balancer.rs example) — b"" mirrors it verbatim.
        match lb.select(b"", 256) {
            Some(backend) => {
                if let Some(t) = ctx.trace.as_mut() {
                    t.set_peer_address(&backend.addr.to_string());
                }
                Ok(Box::new(HttpPeer::new(backend, opts.tls, opts.sni)))
            }
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
        ctx: &mut Self::CTX,
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
        // R893-F16: write this hop's trace context AFTER the strip, never
        // before. `traceparent` is in `NEVER_NOMINATE_STRIP` so the strip
        // cannot take it — but ordering it this way means the header the
        // upstream sees is unconditionally the one THIS proxy minted, whatever
        // the client sent, rather than something a future change to the strip
        // list could quietly alter.
        if let Some(t) = ctx.trace.as_mut() {
            let value = t.begin_client_leg();
            upstream_request.insert_header(trace::TRACEPARENT, value)?;
        }
        Ok(())
    }

    /// R870-F15: apply the matched mount's extra response headers — e.g. a
    /// wasm-isolated mount's COOP/COEP pair — to the response actually going
    /// downstream. `ctx.route_headers` is empty for a
    /// [`RoutingStrategy::ByHost`] deployment and for any
    /// [`RoutingStrategy::ByPath`] mount that declared none, so this is a
    /// no-op there. Header ownership follows whoever matched the path: this
    /// is the ONLY site that applies them, so a response never carries a
    /// sibling mount's headers.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()> {
        for (name, value) in &ctx.route_headers {
            upstream_response.insert_header(name.clone(), value.clone())?;
        }
        // R893-F16: the CLIENT span closes here — upstream-header-arrival is
        // exactly the boundary it measures. The SERVER span does not; it closes
        // in `logging`, which also sees the requests that never got this far.
        if let Some(t) = ctx.trace.as_mut() {
            t.end_client_leg(upstream_response.status.as_u16());
        }
        Ok(())
    }
}
