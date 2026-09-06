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
//! ## Poll N yubabas, and hold PER SOURCE (R844-F23)
//!
//! One source used to poll one yubaba, which meant a workload placed on more
//! than one node was undiscoverable: the service-record store is strictly
//! node-local (R844-B11 — a record's `mesh_ip` must equal the answering node's
//! own mesh address), so the records for a two-node placement live in two
//! different yubabas and no single poll sees both. `yah cloud apply` refused
//! such an edge by name and fell back to the static set, which is the port pin
//! R844 exists to delete.
//!
//! The operator settled this on 2026-09-04 (W267 §"What this deliberately does
//! not settle"): **poll N, don't replicate.** Discovery stays node-local, raft
//! does not grow a service-record map, and the candidate set degrades per-door.
//! So [`YubabaDiscoveryConfig::base_urls`] is a list, one entry per placement
//! node, and [`YubabaUpstreams`] polls each and hands the **union** of the
//! matching records to the round-robin + `TcpHealthCheck` that already decide
//! today. Nothing in the routing or health layers changed: a `HostKey::Host`
//! has had its own `UpstreamSource` since R594-F10, and this is still one.
//!
//! The subtle part is that the hold-on-failure rule above is **per source**,
//! which is why the held sets live inside this one type rather than in a
//! combinator over N single-URL sources. Each [`PolledSource`] keeps its own
//! last-known-good, so when node A's yubaba is restarting and node B's answers
//! fresh, the union is *A's held set plus B's fresh one*. Both of the wrong
//! answers here are outages:
//!
//! - Collapsing to B alone drains every backend on A — which is the exact
//!   whole-site failure the single-source rule was written to prevent, just
//!   applied to half the fleet.
//! - Holding the whole previous union pins B's stale addresses too, ignoring
//!   an answer that was authoritative.
//!
//! "Answered with none" and "could not be seen" therefore stay distinguishable
//! at the granularity of a single node, not of the whole door.
//!
//! Polling is sequential, so the per-tick budget is `base_urls.len() *
//! timeout` and must still fit inside `PASSWAY_UPDATE_INTERVAL_SECS` — at the
//! 5s/30s defaults that is six nodes, well past any placement this fronts. A
//! tick that overruns delays the next update; it drops no traffic, because the
//! health check goes on probing the set already in hand.
//!
//! @yah:ticket(R844-F23, "Poll-N discovery (operator decision 2026-09-04): PASSWAY_YUBABA_IDENT takes a list of yubaba URLs per hostname, lifting R844-F20's multi-node refusal")
//! @yah:status(review)
//! @yah:at(2026-09-05T04:27:03Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R844)
//! @yah:next("Operator decided the W267 open question 2026-09-04: poll-N, not raft-replicated ServiceRecords. Decision + rationale recorded in W267 §'What this deliberately does not settle' — discovery stays node-local, raft does not grow a service-record map, the candidate set degrades per-door.")
//! @yah:next("Shape: PASSWAY_YUBABA_IDENT's <hostname>= fan-in grammar (R844-F20) extends so one hostname's workload can name several yubaba URLs; the door polls each, unions the records for that ident, and the existing per-host round-robin + TcpHealthCheck decides as today. A failed poll of one source holds that source's last-known-good set (the R594-F8 constraint, per-source).")
//! @yah:next("Then lift the two R844-F20 refusals in yah cloud apply's rendering: a multi-node placement renders the self-discovering form listing each placement machine's yubaba, instead of falling back to the static set.")
//! @yah:next("Unblocks the replica-layer track (W284 grammar → R626 runtime): a redundant set is unroutable until doors can discover a multi-node backend.")
//! @yah:next("Tier: Cleric — well-scoped seam extension along an existing grammar, but the union/hold-on-failure semantics need considered tests, not speed.")
//! @yah:handoff("GRAMMAR (oss/passway/crates/passway/src/main.rs). `PASSWAY_YUBABA_URL` gained the `<hostname>=<value>` fan-in grammar its two siblings already had, and repeating a hostname ADDS a URL — additive like `PASSWAY_UPSTREAMS`, deliberately NOT exclusive like `PASSWAY_YUBABA_IDENT`. New `parse_yubaba_url_sets`; `PASSWAY_YUBABA_IDENT` is untouched and `a_repeated_hostname_is_an_error_rather_than_a_silent_pick` still passes. `the_ident_grammar_stays_exclusive_while_the_url_grammar_is_additive` asserts both halves in one test so a future edit \"making them consistent\" has to delete it deliberately. Backwards compatibility is asserted FIRST (`a_bare_yubaba_url_is_still_the_catch_all`): a bare URL with no `=` stays the catch-all every hostname falls back to, and `*=<url>` says the same on purpose. Not folded into `parse_upstream_sets` because that one warns-and-skips an unparsable value while an unreadable URL has to be a boot failure — a hostname with nothing to poll looks exactly like \"yubaba has no records\".")
//! @yah:handoff("THE DOOR (oss/passway/crates/passway/src/discovery.rs). `YubabaDiscoveryConfig.base_url: String` -> `base_urls: Vec<String>`, `url()` -> `urls()`. Took the ticket's preferred shape — N URLs held INSIDE one `YubabaUpstreams` rather than N sources plus a combinator — via a new private `PolledSource { url, last_good: Mutex<Option<Vec<SocketAddr>>> }`: moving the held set into the per-URL struct is what makes the R594-F8 hold rule per SOURCE rather than per door. `PolledSource::resolve(Result<Vec<SocketAddr>, String>)` carries that rule for one node and is split from the request so it needs no live yubaba, the same way `addrs_from_body` already was. `addrs()` polls each URL in `base_urls` order and extends the union; no dedupe, because the record store is per-node so two nodes cannot report one endpoint and `SourceDiscovery` collects into a `BTreeSet<Backend>` regardless. Routing and health untouched — `HostKey::Host` -> its own `UpstreamSource` (R594-F10) already supported this.")
//! @yah:handoff("THE RENDERER (app/yah/cli/src/cloud.rs, `passway_discovery_env`). The multi-node refusal is gone; the function now resolves one `http://<mesh_ipv4>:<yubaba_port>` per placement node and renders them UNPREFIXED — `PASSWAY_YUBABA_URL=http://100.64.0.3:7443,http://100.64.0.4:7443`. That works because unprefixed entries are passway's catch-all and repeating one adds to it, and it is exactly true here: the function fronts a single `workload_ident` whose rules share a placement, so \"every hostname discovers from these nodes\" is the whole content. A hostname-prefixed cross product would say the same thing N_hosts times over in a line an operator copies by hand. Consequence worth knowing: the SINGLE-node string is byte-identical to what F20 rendered, and it falls out of the same code path rather than a special case (one URL joined with commas is one URL). Still `mesh_ipv4`, never `reach_yubaba`'s tunnelled address; still pure over `&[MachineConfig]`. The other refusals stay and are tested: unplaced edge, machine absent from .yah/infra/machines/, no `[registration].mesh_ipv4`, no hostname rules — and a multi-node edge where ONE node fails any of those refuses the WHOLE edge rather than rendering the reachable half, which would front a partial placement while looking complete.")
//! @yah:handoff("TESTS, +18 in passway and +8/-1 in yah, every one accounted for against a MEASURED baseline. discovery.rs unit (+5): multi-URL `urls()`; two nodes' records unioned for one ident; ONE SOURCE FAILING WHILE THE OTHER ANSWERS -> the union is the failed node's last-known-good PLUS the healthy node's fresh set (the assertion a concatenate-the-fresh-answers fix cannot pass); a node answering NONE retires only its own share while its peer survives (the R844-F4 \"answered with none\" vs \"could not be seen\" distinction, applied per node); every source failing holds every source's set. The two-real-sources tests use a hand-rolled loopback responder — `acme.rs`'s reason, this crate carries no HTTP-server dep — because a stand-in for reqwest would assert against the mock rather than against `addrs()`. main.rs grammar (+9): bare-URL back-compat first, `*=` equivalence, per-host splitting, repeat-ADDS, ident-still-rejects-repeat, same-URL-twice-polled-once, mixing rejected, empty URL/hostname rejected, whitespace. tests/yubaba_discovery.rs (+2, end to end through the real LoadBalancer + TcpHealthCheck): two yubabas' records both become routable and round-robin reaches BOTH nodes' containers; and one yubaba going 500 mid-flight leaves that node's containers still receiving traffic beside its peer's.")
//! @yah:handoff("One assertion was DELETED, deliberately: `passway_discovery_tests::a_multi_node_placement_is_refused_because_one_source_polls_one_yubaba` asserted the refusal this ticket exists to lift, so it cannot survive. A comment stands where it was, pointing at the new `passway_poll_n_tests` module — kept separate from `passway_discovery_tests` (territory @Ashguard:eclipse has been in) so \"this was once refused\" and \"this is now rendered\" read side by side rather than interleaved. The no-port assertion is re-made there on the multi-node path (`no_port_appears_in_a_multi_node_discovery_env`), since the fan-out form has more places to leak one, and F20's original single-node byte-exact assertion is untouched and still green.")
//! @yah:gotcha("DESIGN CALL worth knowing before extending this: `YubabaUpstreams::addrs` polls its N sources SEQUENTIALLY, so the per-tick budget is `base_urls.len() * PASSWAY_YUBABA_TIMEOUT_SECS` and must stay under `PASSWAY_UPDATE_INTERVAL_SECS` — six nodes at the 5s/30s defaults, well past any placement this fronts. Concurrency was declined rather than overlooked: passway has no join combinator (no `futures` dep) and every dep in its Cargo.toml carries a written justification for adding no transitive surface, so buying parallelism costs a new dependency on a trust-boundary crate. An overrun delays the next update and drops no traffic — the health check keeps probing the set already in hand. The budget is documented at `YubabaDiscoveryConfig::timeout`; if a placement ever exceeds ~6 nodes, add the combinator there rather than shortening the timeout.")
//! @yah:gotcha("SHARED-TREE NOTE for whoever reads the verify numbers: both `-p yah` baselines had to be taken AFTER waiting out two peers' half-landed edits, neither mine. `app/yah/cli/src/keys_doctor.rs:4330` briefly held a literal two-character backslash-n (a shell-escaping accident) that failed the whole `yah` lib target; @Ashguard:spade (session:9ca2da4f, R856) owned it and fixed it. Then `oss/yubaba/crates/cloud/src/config.rs:2014` used `RequiredSpec::repel_archetype` mid-way through R860-T4's widening of that field to `repel_archetypes: Vec<..>`, which failed `yah-cloud`; @Ashguard:polaris (session:d44b73fc) owned it and it cleared on its own. Neither file was touched by this ticket. If a future reader sees those errors in a transcript here, they are not R844-F23's.")
//! @yah:verify("passway: `cargo test --manifest-path oss/passway/Cargo.toml` = 237 passed / 0 failed / 1 ignored, against a baseline I MEASURED FIRST on this tree at 219 / 0 / 1. +18, and every one is accounted for: +5 discovery.rs unit, +9 main.rs grammar, +2 tests/yubaba_discovery.rs integration, +2 more discovery.rs unit (the catch-all fallback pair). Note the ticket's stated 202 was the post-F20 figure; R858-T1 had since added tests, which is why the measured baseline is higher.")
//! @yah:verify("yah: `cargo test -p yah --lib -- cloud::` = 162 passed / 0 failed / 1 ignored. Baseline is the ticket's stated 155 / 0 / 1, NOT one I measured — two peers' half-landed edits (keys_doctor.rs, then yah-cloud's config.rs) failed the target on both of my baseline attempts, so I could not take a clean before-number and say so rather than implying I did. 155 + 8 new - 1 deliberately deleted = 162, which is the arithmetic that makes the stated baseline credible. `cargo check -p yah --lib` exits 0 with no errors; the `unused import` warnings in that output are pre-existing and in other modules (WorkItemAnno, WorkloadSpec, NodeId, ...), none in cloud.rs or in anything this ticket wrote.")
//! @yah:verify("PURITY CANARY HELD: `cargo test -p xtask --test main mirror_ingress` = 11 passed / 0 failed, unchanged, so `plan_ingress` still plans the real .yah/services tree with no network and no credentials. Expected — this ticket changed the RENDERING downstream of the plan, not the plan — but it is the assertion that proves it, so it was run rather than reasoned about. `.yah/services/` was not touched (R844-T10's comments-only diff is intact), and neither were `ReadyRecordWait` / `apply_mirror_phases` (R844-B24 / R844-B19). Nothing in oss/passway/crates/sni-demux/ was touched; that is @Ashguard:eclipse's R858 territory and `discovery.rs` / `main.rs` were clean when I took them.")
//! @yah:handoff("NOT COMMITTED — no git write was requested and this is a shared tree. Files changed: oss/passway/crates/passway/src/discovery.rs, oss/passway/crates/passway/src/main.rs, oss/passway/crates/passway/tests/yubaba_discovery.rs, app/yah/cli/src/cloud.rs. Note that `git diff --stat` on cloud.rs shows ~694 changed lines; only ~200 of those are this ticket's (the `passway_discovery_env` rewrite plus the new `passway_poll_n_tests` module), the rest being peers' uncommitted R844-B24 / R844-B19 work in the same file. Any commit here must be pathspec-scoped.")

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
    /// Base URLs of the yubabas to ask, e.g. `http://100.64.0.2:7443` — **one
    /// per node the fronted workload is placed on** (R844-F23). Plain HTTP is
    /// correct here: the hop rides the WireGuard mesh, which is already
    /// encrypted and authenticated, and yubaba's listener is mesh-bound.
    ///
    /// A list rather than a single URL because the record store is node-local,
    /// so an N-node placement is only visible to N polls — see the module
    /// docs. One entry is the ordinary single-node case and behaves exactly as
    /// it did before this was a list.
    pub base_urls: Vec<String>,
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
    ///
    /// With N entries in [`Self::base_urls`] the polls are sequential, so the
    /// budget to compare against `update_frequency` is `N * timeout` — six
    /// nodes at the 5s/30s defaults (`PASSWAY_YUBABA_TIMEOUT_SECS`,
    /// `PASSWAY_UPDATE_INTERVAL_SECS`).
    pub timeout: Duration,
}

impl YubabaDiscoveryConfig {
    /// Full URLs polled on each tick, `?ready=true` included, in
    /// [`Self::base_urls`] order.
    ///
    /// Server-side filtering keeps each body small; the client filters again
    /// anyway (see [`addrs_from_body`]) so correctness never depends on the
    /// query parameter being honoured. [`Self::ident`] is deliberately not a
    /// query parameter — the endpoint offers no such narrowing, and the client
    /// is the only side that knows which workload it fronts.
    pub fn urls(&self) -> Vec<String> {
        self.base_urls
            .iter()
            .map(|base| format!("{}{DISCOVERY_PATH}?ready=true", base.trim_end_matches('/')))
            .collect()
    }
}

/// One polled yubaba, and everything remembered about it.
///
/// The held set lives here rather than on [`YubabaUpstreams`] because the
/// hold-on-failure rule is per source (R844-F23): a node whose yubaba is
/// restarting must contribute its last-known-good backends to the union while
/// its healthy peers contribute fresh ones. State kept one level up could only
/// hold or drop the whole union, and both of those are outages — see the
/// module docs.
#[derive(Debug)]
struct PolledSource {
    /// Full poll URL, `?ready=true` included. Also the log prefix, so a warning
    /// names the node that could not be seen rather than "discovery".
    url: String,
    /// Last successfully-fetched address set *for this node*. Returned verbatim
    /// when this node's fetch fails, so a control-plane blip on one node cannot
    /// drain its share of the backend set. `None` until the first successful
    /// fetch: a cold start against an unreachable yubaba has no good set to
    /// fall back to and correctly contributes none.
    last_good: Mutex<Option<Vec<SocketAddr>>>,
}

impl PolledSource {
    fn new(url: String) -> Self {
        Self {
            url,
            last_good: Mutex::new(None),
        }
    }

    /// Reconcile one poll's outcome against what this node last knew, and
    /// return the addresses it contributes to the union.
    ///
    /// The whole "a failed fetch is not an empty upstream set" rule, scoped to
    /// a single node and split from the request so it is testable without a
    /// live yubaba.
    fn resolve(&self, fetched: Result<Vec<SocketAddr>, String>) -> Vec<SocketAddr> {
        match fetched {
            Ok(addrs) => {
                if addrs.is_empty() {
                    // Authoritative empty. Record it as the good set so a
                    // later failure holds *this* answer, not a stale one from
                    // before the workloads went away.
                    log::info!(
                        "{}: yubaba reports zero ready upstreams for this workload",
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
                             {} upstream(s) from this node. A failed fetch is not an empty \
                             upstream set.",
                            self.url,
                            addrs.len()
                        );
                        addrs
                    }
                    None => {
                        log::warn!(
                            "{}: upstream discovery failed ({e}) and no previous set exists \
                             for this node (cold start) — it contributes no upstreams until \
                             it answers",
                            self.url
                        );
                        Vec::new()
                    }
                }
            }
        }
    }
}

/// An [`UpstreamSource`] backed by yubaba's service-record surface.
#[derive(Debug)]
pub struct YubabaUpstreams {
    client: reqwest::Client,
    /// The yubabas this source polls, one per placement node (R844-F23). One
    /// entry is the ordinary case.
    sources: Vec<PolledSource>,
    /// The one workload ident whose records become backends — see
    /// [`YubabaDiscoveryConfig::ident`]. The same on every source: this is one
    /// hostname's set, gathered from every node that hosts it.
    ident: String,
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
            sources: config.urls().into_iter().map(PolledSource::new).collect(),
            ident: config.ident.clone(),
        }
    }

    /// One fetch against one node. `Err` means *the answer is unknown*
    /// (transport, status, body, or version), never "there are no upstreams".
    async fn fetch(&self, url: &str) -> Result<Vec<SocketAddr>, String> {
        let resp = self
            .client
            .get(url)
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

        addrs_from_body(&body, &self.ident, url)
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
    /// The union of every polled node's contribution, in `base_urls` order.
    ///
    /// Each node resolves independently ([`PolledSource::resolve`]), so a node
    /// that could not be seen holds its own last-known-good while its peers'
    /// fresh answers land beside it. Duplicates are not filtered here: the
    /// record store is per-node so two nodes cannot report the same endpoint,
    /// and `SourceDiscovery` collects into a `BTreeSet<Backend>` anyway.
    async fn addrs(&self) -> Vec<SocketAddr> {
        // Sequential rather than concurrent: this crate keeps a deliberately
        // small dependency graph and has no join combinator, and the budget it
        // costs (`sources.len() * timeout` per tick) is documented at
        // `YubabaDiscoveryConfig::timeout`.
        let mut union = Vec::new();
        for source in &self.sources {
            let fetched = self.fetch(&source.url).await;
            union.extend(source.resolve(fetched));
        }
        if union.is_empty() {
            log::info!(
                "no ready upstreams for ident {:?} across {} yubaba(s); passway will \
                 fail-ready 503 until one appears",
                self.ident,
                self.sources.len()
            );
        }
        union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(base: &str) -> YubabaDiscoveryConfig {
        cfg_n(&[base])
    }

    fn cfg_n(bases: &[&str]) -> YubabaDiscoveryConfig {
        YubabaDiscoveryConfig {
            base_urls: bases.iter().map(|b| b.to_string()).collect(),
            ident: "api".to_string(),
            timeout: Duration::from_millis(500),
        }
    }

    fn body(json: &str) -> ServiceRecordsWire {
        serde_json::from_str(json).expect("test fixture parses")
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test fixture is a socket address")
    }

    #[test]
    fn url_appends_the_ready_filter_and_tolerates_a_trailing_slash() {
        assert_eq!(
            cfg("http://100.64.0.2:7443").urls(),
            vec!["http://100.64.0.2:7443/service-records?ready=true".to_string()]
        );
        assert_eq!(
            cfg("http://100.64.0.2:7443/").urls(),
            vec!["http://100.64.0.2:7443/service-records?ready=true".to_string()]
        );
    }

    /// R844-F23: N placement nodes, N polls, in the order they were configured
    /// — the union is assembled in that order and the tests below rely on it.
    #[test]
    fn every_configured_yubaba_becomes_its_own_poll_url() {
        assert_eq!(
            cfg_n(&["http://100.64.0.3:7443", "http://100.64.0.2:7443/"]).urls(),
            vec![
                "http://100.64.0.3:7443/service-records?ready=true".to_string(),
                "http://100.64.0.2:7443/service-records?ready=true".to_string(),
            ]
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

    /// Loopback address nothing listens on, so a poll of it is refused
    /// immediately rather than waiting out the timeout.
    const UNREACHABLE: &str = "http://127.0.0.1:1";

    /// A loopback responder that answers every `GET` with `body` as JSON.
    ///
    /// Hand-rolled for the reason `acme.rs`'s HTTP-01 responder is: this crate
    /// deliberately carries no HTTP-server dependency. The tests below need a
    /// *real* fetch succeeding beside a *real* fetch failing — a stand-in for
    /// reqwest would assert against the mock rather than against `addrs()`.
    async fn serve_records(body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                // The request head is read and discarded: this responder
                // answers one shape and the client only ever asks for it.
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_cold_start_against_an_unreachable_yubaba_yields_no_upstreams() {
        let source = YubabaUpstreams::new(&cfg(UNREACHABLE));
        assert!(
            source.addrs().await.is_empty(),
            "no previous good set exists, so there is nothing to hold"
        );
    }

    #[tokio::test]
    async fn a_failed_fetch_holds_the_last_known_good_set() {
        let source = YubabaUpstreams::new(&cfg(UNREACHABLE));
        let good = vec![addr("100.64.0.5:8080")];
        *source.sources[0].last_good.lock().unwrap() = Some(good.clone());

        assert_eq!(
            source.addrs().await,
            good,
            "a control-plane blip must not drain the backend set"
        );
    }

    #[tokio::test]
    async fn an_authoritative_empty_answer_replaces_the_held_set() {
        // The inverse of the test above: once yubaba *does* answer and says
        // nothing is ready, that supersedes the stale set.
        let source = YubabaUpstreams::new(&cfg(UNREACHABLE));
        let held = &source.sources[0].last_good;
        *held.lock().unwrap() = Some(vec![addr("100.64.0.5:8080")]);

        assert!(
            source.sources[0].resolve(Ok(Vec::new())).is_empty(),
            "an answer of none is authoritative and wins over the held set"
        );
        assert_eq!(held.lock().unwrap().as_ref().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // R844-F23: N yubabas, one union, per-source hold
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn two_nodes_records_for_one_ident_are_unioned() {
        // The point of poll-N: a workload placed on two nodes has its records
        // split across two node-local stores, and the door serves both.
        let east = serve_records(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.3:8080"],"health":"ready"},
                {"ident":"other","endpoints":["100.64.0.3:9999"],"health":"ready"}
            ]}"#,
        )
        .await;
        let west = serve_records(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.2:8080"],"health":"ready"}
            ]}"#,
        )
        .await;

        let source = YubabaUpstreams::new(&cfg_n(&[&east, &west]));
        assert_eq!(
            source.addrs().await,
            vec![addr("100.64.0.3:8080"), addr("100.64.0.2:8080")],
            "both nodes contribute, and the ident filter still applies per node"
        );
    }

    /// **The load-bearing assertion of R844-F23.** An implementation that
    /// merely concatenates the fresh answers cannot pass it: node A is
    /// unreachable, so its contribution can only come from its OWN held set.
    #[tokio::test]
    async fn a_failed_source_holds_its_own_set_beside_a_healthy_peers_fresh_one() {
        let west = serve_records(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.2:8080"],"health":"ready"}
            ]}"#,
        )
        .await;

        let source = YubabaUpstreams::new(&cfg_n(&[UNREACHABLE, &west]));
        *source.sources[0].last_good.lock().unwrap() = Some(vec![addr("100.64.0.3:8080")]);

        assert_eq!(
            source.addrs().await,
            vec![addr("100.64.0.3:8080"), addr("100.64.0.2:8080")],
            "the union is the unreachable node's LAST-KNOWN-GOOD plus the healthy \
             node's fresh set — collapsing to the healthy node alone drains half \
             the fleet, which is the outage the hold rule exists to prevent"
        );
    }

    /// "Answered with none" and "could not be seen" stay distinguishable per
    /// node, not just per door — the R844-F4 distinction, applied here.
    #[tokio::test]
    async fn a_node_that_answers_none_drops_its_own_share_and_not_its_peers() {
        let drained = serve_records(r#"{"version":1,"records":[]}"#).await;
        let west = serve_records(
            r#"{"version":1,"records":[
                {"ident":"api","endpoints":["100.64.0.2:8080"],"health":"ready"}
            ]}"#,
        )
        .await;

        let source = YubabaUpstreams::new(&cfg_n(&[&drained, &west]));
        // Seed the drained node with a set it used to serve: unlike the test
        // above, this node ANSWERS, so its stale set must not survive.
        *source.sources[0].last_good.lock().unwrap() = Some(vec![addr("100.64.0.3:8080")]);

        assert_eq!(
            source.addrs().await,
            vec![addr("100.64.0.2:8080")],
            "an authoritative empty from one node retires only that node's backends"
        );
    }

    /// Every node failing is not the same as every node reporting none: the
    /// door holds what it last knew rather than 503-ing the site because the
    /// mesh blipped.
    #[tokio::test]
    async fn every_source_failing_holds_every_source_set() {
        let source = YubabaUpstreams::new(&cfg_n(&[UNREACHABLE, "http://127.0.0.1:2"]));
        *source.sources[0].last_good.lock().unwrap() = Some(vec![addr("100.64.0.3:8080")]);
        *source.sources[1].last_good.lock().unwrap() = Some(vec![addr("100.64.0.2:8080")]);

        assert_eq!(
            source.addrs().await,
            vec![addr("100.64.0.3:8080"), addr("100.64.0.2:8080")]
        );
    }
}
