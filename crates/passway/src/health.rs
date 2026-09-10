//! `/health` — mirrors yubaba's `GET /mesh/leader-health` pattern
//! (`oss/yubaba/crates/yubaba/src/lib.rs`'s `mesh_leader_health`): a bare
//! 200-vs-503 gate plus a small JSON body explaining *why*, so a
//! floating-IP/DNS health check (or Cloudflare break-glass health check)
//! can route traffic only to instances that return 200 (R594-F4 V0 MUST
//! #4).
//!
//! Two conditions gate readiness, matching the ticket verbatim: no ready
//! upstreams, or the instance is draining. Both collapse to 503 — the
//! caller (a health-check prober) doesn't need to distinguish "no capacity"
//! from "intentionally leaving rotation," it just needs to stop sending
//! traffic here.
//!
//! ## Aggregate node readiness, per-host detail (R594-F10)
//!
//! With one node fronting several services ([`crate::routing`]) the top-level
//! `ready` stays an **aggregate**: 200 while *any* upstream set can serve.
//! That is deliberate. This endpoint gates a floating-IP / DNS health check,
//! whose only lever is "is this node in rotation" — so reporting unready
//! because one of three services is down would take the two healthy ones
//! down with it, on every node at once (a service that's down is usually
//! down everywhere, not on one node). The per-set breakdown in
//! [`ReadinessBody::upstreams_by_host`] is what a *per-service* prober reads
//! instead; it's omitted entirely from the JSON for a single-set deployment,
//! so that body is byte-identical to the pre-R594-F10 one.
//!
//! @yah:ticket(R870-F5, "A door with no upstream serves a bare 503 — give an enrolled-but-unbacked tenant a real holding page")
//! @yah:status(review)
//! @yah:at(2026-09-08T22:39:15Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P2)
//! @yah:parent(R870)
//! @yah:next("THE STATE THIS IS ABOUT IS LIVE RIGHT NOW, so it can be looked at rather than imagined: https://noisetable.com is enrolled on all three origins as of 2026-09-08 — DNS resolves, the cert is browser-trusted (ssl_verify_result=0), :80 308s to https — and every request returns a BARE 503 because no workload is declared under ident `noisetable`. passway logs the reason clearly (\"no ready upstreams for ident X; passway will fail-ready 503 until one appears\") but the response body says nothing, so the visitor sees a naked error page on a domain whose TLS is perfect.")
//! @yah:verify("A request to an enrolled domain with zero ready upstreams returns a styled holding page, not a bare 503, and still carries a 503 STATUS — the status is the contract for uptime checks and search crawlers, only the body changes. The apex doors (yah.dev, ident yah-marketing) must be unaffected in the normal case, and must show the same page rather than a bare 503 during the ~1s cold-upstream window R870-T3's gotcha measured on reload.")
//! @yah:gotcha("DO NOT MAKE THIS A 200. The fail-ready posture is deliberate (R594-F6, and upstream.rs:34 documents it): an empty upstream set must not crash the door, and it must not look healthy either. A 200 holding page tells every uptime check and crawler the site is up, which is worse than the bare 503 it replaces. Status stays 503; only the body is decorated. health.rs already separates the 200-vs-503 gate from the JSON body that explains why, which is why the annotation lives here.")
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:next("Tier: Thief — one response body behind an existing gate, in a file that already separates status from body. The design question in `assumes` is the only part that needs thought, and it is one operator sentence.")
//! @yah:handoff("LANDED. New oss/passway/crates/passway/src/holding.rs: HOLDING_PAGE (a self-contained &'static str — no external font/stylesheet/script/image, since a door serving this page is by definition a door whose backend is missing), HOLDING_PAGE_CONTENT_TYPE, RETRY_AFTER_SECS = 30, and prefers_html(&HeaderMap). proxy.rs's two fail-ready 503 sites (router miss at the `let Some(upstream) = self.router.resolve(...) else` arm, and the !any_ready gate) now both answer through a new respond_unavailable(); wants_html is read in request_filter's existing owned-values block, alongside bearer/host, because the 503 sites already hold the session mutably. lib.rs gained `pub mod holding;` + a module-map entry.")
//! @yah:handoff("THE GOTCHA HELD: status is 503 on both branches, asserted explicitly in tests/empty_upstreams.rs (\"the holding page must NOT make an unbacked door look healthy\"). Two headers were added to both branches — `Retry-After: 30` (the machine-readable half of \"temporary\": a 503 WITH one is what tells a crawler not to drop the URL) and `Cache-Control: no-store` (the condition ends without the URL changing, so a cached holding page would outlive the outage it describes).")
//! @yah:handoff("DESIGN CALL SHIPPED, not asked — the `assumes` entry is removed because it is now answered. passway serves the page; a placeholder workload does not. Reasoning is the ticket's own: passway's page costs one build and covers EVERY tenant automatically including the cold-upstream window on doors that DO have a backend (where a per-tenant placeholder is exactly as absent as the real app), whereas a mesofact-SSR placeholder costs a deploy per tenant and would make the door a misleading 200. They compose without a switch: a tenant that deploys its own holding page has a ready upstream and never reaches this code. Reversing it costs deleting one module and restoring two respond_json calls.")
//! @yah:handoff("CONTENT NEGOTIATION, so no machine caller sees a change: prefers_html only fires on an explicit `text/html` / `application/xhtml+xml` in Accept, never on `*/*`, `text/*` or a missing header, and treats `;q=0` as a refusal. Every prober, curl and existing test keeps the byte-identical {\"error\":\"no ready upstreams\"} JSON. The conservative direction is deliberate: a browser misread as a prober just sees plain JSON, whereas a prober misread as a browser gets HTML where it expected JSON.")
//! @yah:handoff("NOTHING FROM THE REQUEST IS REFLECTED INTO THE PAGE — no hostname, no path, no header, zero interpolation sites (unit-tested). Two reasons, both load-bearing at this trust boundary: reflecting attacker-controlled bytes into HTML is the injection sink, and the 503 bodies are deliberately IDENTICAL for \"unknown authority\" and \"known authority, backends down\" so the door never enumerates which tenants exist. A page naming the host would break the second even if it escaped its way out of the first.")
//! @yah:verify("`cargo test -p passway` GREEN on the shared tree: 152 lib + 43 bin + 28 integration = 223, 0 failed, doc-tests 0. 7 new unit tests in holding.rs (real Firefox/Chrome Accept strings, curl/JSON/`text/*`/absent-header negatives, q=0 refusal, case+whitespace, multiple Accept header lines, and the no-interpolation/no-external-fetch properties of the page itself). tests/empty_upstreams.rs extended: same URL requested twice, once machine-shaped and once browser-shaped, asserting 503 on BOTH plus content-type/Retry-After on the JSON leg and content-type/no-store/`<!doctype html>`/no-reflected-path on the HTML leg.")
//! @yah:verify("rustfmt --edition 2021 --check clean on holding.rs, proxy.rs and tests/empty_upstreams.rs (edition is 2021 per oss/passway/Cargo.toml:41 — checking with --edition 2024 produces spurious import-order diffs across the whole crate). `cargo clippy -p passway --all-targets` produced no errors and no warnings on the touched files.")
//! @yah:verify("NOT VERIFIED LIVE, and this is the honest gap: https://noisetable.com still serves the bare 503 until a rebuilt passway reaches the three origins. R870-B2 is exactly the finding that passway rides neither the release nor the rollout, so there is no rail to do that from here, and rolling the public front door is outward-facing. The apex-unaffected half of the verify criterion is met by construction rather than by measurement — both 503 sites are shared by every host, and a door WITH a ready upstream never enters either.")
//! @yah:gotcha("CONCURRENT WORK ON THE SAME SYMPTOM, from the other end — @Ashguard:dove (session:6a4e7be5) has uncommitted edits in oss/passway/src/discovery.rs + src/main.rs + tests/yubaba_discovery.rs persisting each PolledSource's last-known-good upstream set (new cache_path/cache_max_age on YubabaDiscoveryConfig, PASSWAY_DISCOVERY_CACHE env wiring), because rolling all three prod voters restarted passway beside yubaba and every door cold-started into a ~30s fail-ready 503 with healthy backends throughout. Their change REMOVES that window; this one DECORATES whatever window remains. Not duplicates, and no file overlap — F5's set is holding.rs/proxy.rs/lib.rs/health.rs/tests/empty_upstreams.rs, none of which they touched. Their tests assert the JSON leg and are unaffected by the negotiation. NOTE for whoever builds passway next: YubabaDiscoveryConfig gains two fields in their tree, so any other construction site needs them.")
//! @yah:handoff("ART ADDED (operator request, second pass). The page now carries the `solid-parked` illustration — a hooded traveller camped by a fire, which is the right semantics for a parked door. Both colour variants ship, selected by a `<picture>` + `media=\"(prefers-color-scheme: dark)\"` source. New oss/passway/crates/passway/assets/{parked-dark,parked-light}.webp, derived from packages/yah/ui/public/illustrations/solid-parked-{dark,light}.webp: cropped to drop the source's empty top margin and re-encoded 1054x1492 -> 340x310, 376KB/242KB -> 39.9KB/28.2KB. assets/README.md carries the exact dwebp/cwebp line to regenerate. Copied rather than path-referenced because oss/passway is an independent workspace exported standalone — a ../../../../packages/ reference would not survive export-oss.sh.")
//! @yah:handoff("INLINED AS data: URIs, NOT SERVED, and that is the load-bearing choice. Serving them would need a reserved URL path answered unconditionally on every request — a cost paid by every healthy tenant to decorate the unhealthy ones, and a second thing that can fail on a door whose whole problem is that a request cannot be served. Rendered page is 92,668 bytes; a test pins a 160 KiB ceiling so a source-resolution asset dropped into assets/ fails the suite instead of quietly shipping a multi-megabyte error page.")
//! @yah:handoff("SHAPE CHANGE: `HOLDING_PAGE: &str` became `holding_page() -> &'static str`, rendered once into a `OnceLock<String>` (base64-encoding 68KB of webp per 503 would be a real cost on a door under crawl; a test asserts pointer identity across calls). Taking no arguments is now what ENFORCES the no-reflection property structurally — there is no parameter through which a hostname could arrive. New direct dep `base64 = \"0.22\"`, already in this crate's lockfile transitively at 0.22.1, so no new dependency tree and nothing for deny.toml.")
//! @yah:verify("Re-verified after the art landed: `cargo test -p passway` 155 lib + 43 bin + 28 integration = 226, 0 failed. Four new/changed unit tests — both variants present in the rendered page and byte-identical to the files (RIFF/WEBP magic checked, so a truncated asset fails here rather than as a broken image on a live door), the dark `<source>` media query present (losing it would silently serve dark ink on a dark page), the 160 KiB ceiling, and render-once pointer identity. rustfmt --edition 2021 --check clean.")
//! @yah:gotcha("THE ART SHIPS TO A PUBLIC MIRROR AND IS AN OPERATOR CALL IF THAT IS UNWANTED. oss/passway is exported to github.com/yah-ai/passway by scripts/export-oss.sh, so assets/parked-{dark,light}.webp go out under whatever licence that crate carries, and a yah-branded illustration is then baked into a general-purpose OSS reverse proxy. Separately, it renders on TENANT domains — a parked noisetable.com shows yah's art. Both were flagged to the operator and neither blocks; reversing is deleting assets/ and the <picture> block.")
//! @yah:handoff("ART REVERTED, third pass, on the operator's call: the camp illustration is OVERRIDE content for the yah.dev family, so it must not be the passway default that every tenant inherits. Removed assets/, the `<picture>` block, the `base64` direct dep, and the OnceLock render — `holding_page()` is back to `pub const HOLDING_PAGE: &str`, arg-less and interpolation-free, which is again what enforces the no-reflection property structurally. The default is text-only pending R870-F7's inline-CSS graphic (a design agent is drawing it now); R870-F8 builds the per-domain override the camp art lands on. Net for this ticket: the 503 body change and the negotiation are unchanged from pass one, and 92,668 bytes came back off the wire.")
//! @yah:handoff("TWO NEW GUARD TESTS SO THIS DOES NOT SILENTLY REGRESS: `the_page_carries_no_branding` fails on any `data:` URI or brand string in the default page, and MAX_PAGE_BYTES dropped 160KiB -> 16KiB so a re-inlined raster fails the suite rather than shipping. Both are cited in R870-F7's verify list as things its graphic must satisfy unchanged.")
//! @yah:gotcha("SHARED-TREE NOTE, and why the art is still recoverable: while this ticket was in flight a peer wip commit 09e3f35d (hotship, 2026-09-08 15:57) swept the then-untracked oss/passway/crates/passway/assets/ into git. So the later removal is a working-tree deletion of TRACKED files, not an untracked cleanup, and both webps plus assets/README.md come back with `git show 09e3f35d:oss/passway/crates/passway/assets/<name>`. R870-F8 is pointed at that SHA rather than at the cwebp recipe. Nothing was lost; flagged because git status showed that dir as clean right up until the delete, which is exactly the shared-tree trap.")
//! @yah:handoff("R870-F7 LANDED ON TOP, so the default page is no longer text-only: it now carries the inline-CSS cyberdeck graphic (perspective grid receding to a lit doorway, scanlines, three pulses that recede and dissolve). Page is 6,030 bytes, still pure CSS, still no fetch, no data: URI and no branding — F5's guard tests all pass unchanged, which was the point of writing them. F5's own scope (503 body, Accept negotiation, Retry-After/no-store, status untouched) is unaffected by that landing.")
//! @yah:gotcha("HEAD CARRIES THE VETOED RASTER VERSION — DO NOT BUILD A FLEET BINARY FROM IT. Measured 2026-09-08: `git show HEAD:oss/passway/crates/passway/src/holding.rs | grep -c \"data:image/webp\"` = 2, `git ls-tree HEAD --name-only oss/passway/crates/passway/assets/` lists all three asset files, and HEAD's Cargo.toml still has the base64 dep. The peer wip commit 09e3f35d (hotship) snapshotted the tree at the exact moment the camp illustration was inlined; the revert that removed it AND R870-F7's replacement graphic are both working-tree only, because agents cannot commit in this camp (.yah/git-policy). So a rebuild from the only committed SHA puts yah-branded art on every tenant door — precisely what the operator killed. The commit is the gate on shipping, not the roll. Operator runs: `git add oss/passway/crates/passway/{Cargo.toml,src/health.rs,src/holding.rs,src/proxy.rs,assets} oss/yubaba/crates/yubaba/src/cert_store.rs && git commit`. COROLLARY: the text-only 1670-byte page currently live on noisetable.com corresponds to NO commit — it is a build from a working tree in the window between the revert and F7. Do not treat the running binary as reconstructible from git history.")

use serde::Serialize;

/// Ready/total upstream counts for one host's upstream set. `host` is the
/// routed hostname, or [`crate::routing::CATCH_ALL_LABEL`] for the catch-all
/// set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostReadiness {
    pub host: String,
    pub ready_upstreams: usize,
    pub total_upstreams: usize,
}

/// The `/health` response body. `Serialize` only — this module never talks
/// to a pingora `Session` directly (kept testable without a live proxy);
/// `proxy.rs` is what turns this into an actual HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessBody {
    pub ready: bool,
    pub ready_upstreams: usize,
    pub total_upstreams: usize,
    pub draining: bool,
    /// Per-host-set counts, present only when this node routes by host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams_by_host: Vec<HostReadiness>,
}

impl ReadinessBody {
    /// Compute readiness from the raw signals. `ready` is `true` only when
    /// not draining *and* at least one upstream is ready — a proxy with
    /// zero ready upstreams is never "healthy," even if nothing is
    /// draining it (R594-F6's "fail-ready, not crash" gotcha extends to the
    /// health endpoint: an empty upstream set must read as unhealthy, not
    /// panic and not silently report 200).
    pub fn new(ready_upstreams: usize, total_upstreams: usize, draining: bool) -> Self {
        Self {
            ready: !draining && ready_upstreams > 0,
            ready_upstreams,
            total_upstreams,
            draining,
            upstreams_by_host: Vec::new(),
        }
    }

    /// Attach the per-host-set breakdown (R594-F10). Does not change
    /// [`Self::ready`] — see this module's doc for why node readiness stays
    /// an aggregate.
    pub fn with_hosts(mut self, upstreams_by_host: Vec<HostReadiness>) -> Self {
        self.upstreams_by_host = upstreams_by_host;
        self
    }

    /// The HTTP status this body should be served with: 200 only when
    /// [`Self::ready`], 503 otherwise.
    pub fn status_code(&self) -> u16 {
        if self.ready {
            200
        } else {
            503
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_when_upstreams_present_and_not_draining() {
        let b = ReadinessBody::new(2, 3, false);
        assert!(b.ready);
        assert_eq!(b.status_code(), 200);
        assert_eq!(b.ready_upstreams, 2);
        assert_eq!(b.total_upstreams, 3);
    }

    #[test]
    fn not_ready_when_zero_ready_upstreams() {
        let b = ReadinessBody::new(0, 3, false);
        assert!(!b.ready);
        assert_eq!(b.status_code(), 503);
    }

    #[test]
    fn not_ready_when_zero_total_upstreams() {
        // The empty-cold-start case: nothing has ever been discovered.
        let b = ReadinessBody::new(0, 0, false);
        assert!(!b.ready);
        assert_eq!(b.status_code(), 503);
    }

    #[test]
    fn not_ready_when_draining_even_with_ready_upstreams() {
        let b = ReadinessBody::new(3, 3, true);
        assert!(!b.ready);
        assert_eq!(b.status_code(), 503);
    }

    #[test]
    fn serializes_to_the_expected_json_shape() {
        let b = ReadinessBody::new(1, 2, false);
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["ready"], true);
        assert_eq!(v["ready_upstreams"], 1);
        assert_eq!(v["total_upstreams"], 2);
        assert_eq!(v["draining"], false);
        // A single-set deployment's body is unchanged by R594-F10.
        assert!(v.get("upstreams_by_host").is_none());
    }

    #[test]
    fn per_host_breakdown_is_reported_when_present() {
        let b = ReadinessBody::new(1, 3, false).with_hosts(vec![
            HostReadiness {
                host: "a.example.com".into(),
                ready_upstreams: 1,
                total_upstreams: 1,
            },
            HostReadiness {
                host: "b.example.com".into(),
                ready_upstreams: 0,
                total_upstreams: 2,
            },
        ]);
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["upstreams_by_host"][0]["host"], "a.example.com");
        assert_eq!(v["upstreams_by_host"][1]["ready_upstreams"], 0);
    }

    #[test]
    fn node_stays_ready_while_one_host_set_is_fully_down() {
        // The aggregate gate: b is dark, a still serves, so the node stays in
        // floating-IP rotation and b's outage is visible in the breakdown
        // rather than by pulling a's traffic too.
        let b = ReadinessBody::new(1, 3, false).with_hosts(vec![HostReadiness {
            host: "b.example.com".into(),
            ready_upstreams: 0,
            total_upstreams: 2,
        }]);
        assert!(b.ready);
        assert_eq!(b.status_code(), 200);
    }
}
