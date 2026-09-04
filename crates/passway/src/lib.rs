//! # passway — sovereign public-ingress L7 proxy (R594-F4 / W267 Tier-1)
//!
//! The one new crate W267's "rent IPs, not the edge" strategy needs: an L7
//! reverse proxy, built on [pingora](https://docs.rs/pingora) (Apache-2.0,
//! Cloudflare's own edge-proxy framework — "run the same machinery CF runs,
//! on our VPS" is the whole thesis), that terminates TLS, load-balances
//! round-robin over a health-checked upstream set, verifies edge auth via
//! `cheers-verify`, and answers a `/health` endpoint a floating-IP/DNS
//! health check can gate on.
//!
//! ## Module map
//!
//! - [`proxy`] — [`proxy::PassProxy`], the `pingora::proxy::ProxyHttp` impl
//!   that is the actual request path (routing, auth gate, hardening,
//!   `/health`).
//! - [`acme`] — R594-F7: automated Let's Encrypt issuance + renewal for
//!   [`tls::TlsMode::Acme`] (`instant-acme`, HTTP-01, writes to the same
//!   cert/key paths `TlsMode::Manual` reads; the reload gap is closed via
//!   pingora's graceful-upgrade, documented as a supervisor signal
//!   contract rather than a self-triggered restart — see the module doc).
//! - [`upstream`] — the pluggable [`upstream::UpstreamSource`] seam plus
//!   the v0 [`upstream::StaticUpstreams`] implementation and the
//!   `pingora::lb::LoadBalancer` builder.
//! - [`discovery`] — R594-F8: [`discovery::YubabaUpstreams`], the dynamic
//!   [`upstream::UpstreamSource`] that learns the backend set from yubaba's
//!   service-record surface. This is what makes passway an ingress
//!   *provider* — the sovereign twin of the cloudflared arm — rather than a
//!   proxy someone hand-configured with an address list.
//! - [`routing`] — R594-F10: [`routing::HostRouter`], the host →
//!   upstream-set map that lets one node front several services. Sits above
//!   the [`upstream`] seam (N sources, N load balancers) rather than
//!   replacing it.
//! - [`host`] — request-authority extraction and normalization for that map
//!   (`Host` / `:authority`, fail-closed on an ambiguous authority).
//! - [`auth`] — `cheers-verify` wiring ([`auth::CheersAuth`]) and the
//!   per-route auth policy ([`auth::RouteAuthPolicy`]).
//! - [`hardening`] — the request-smuggling defenses (hop-by-hop header
//!   stripping, Content-Length/Transfer-Encoding conflict rejection) as
//!   pure, independently-testable functions over [`http::HeaderMap`].
//! - [`idle`] — R779: [`idle::IdleTracker`] / [`idle::IdleReaper`], the
//!   in-flight count and idle-TTL self-reap that let a per-tenant passway
//!   sit cold behind kamaji's on-demand JIT tier (`PASSWAY_IDLE_TTL_SECS`).
//! - [`path`] — request-path canonicalization for the auth decision
//!   (percent-decode, dot-segment/duplicate-slash normalization, fail-closed
//!   rejection of ambiguous or non-UTF-8 paths) so the auth gate decides on
//!   the same form the upstream resolves.
//! - [`health`] — the `/health` readiness computation, independent of any
//!   pingora type.
//! - [`tls`] — TLS listener configuration: v0's bring-your-own-cert path,
//!   plus the documented ACME hook for a follow-up ticket.
//!
//! `main.rs` (not part of the library target) is the thinnest possible
//! wiring of these pieces into a running `pingora::server::Server` —
//! reading listener/upstream/auth/TLS configuration from the environment
//! and handing it to [`proxy::PassProxy`].
//!
//! ## Trust boundary
//!
//! This crate terminates public, untrusted, unauthenticated network
//! traffic. Every module above was written and reviewed against that
//! posture — fail closed on ambiguity (auth, smuggling-shaped requests),
//! fail ready rather than crash on an empty upstream set (R594-F6's
//! cold-start gotcha), and keep the dependency surface exactly what the
//! R594-S1 spike verdict specified (pingora `rustls` + `lb` features only —
//! see `deny.toml`'s explicit TLS-backend bans).
//!
//! The board ticket for this crate (R594-F4) is homed in
//! `.yah/docs/working/W267-sovereign-public-ingress.md` (single source of
//! truth — Rule11 dedup, 2026-07-03), alongside its sibling R594 tickets.
//!
//! @yah:ticket(R743-T6, "passway: 6 test binaries to 1")
//! @yah:at(2026-08-11T01:18:48Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R743)
//! @yah:next("tests/main.rs mod'ing all 6 siblings + autotests = false and [[test]] name = \"main\" in oss/passway/crates/passway/Cargo.toml. tests/common/ becomes an ordinary sibling module, unchanged.")
//! @yah:verify("cargo test -p passway -- --list count unchanged; three green runs. One commit — oss subtree.")
//! @yah:handoff("LANDED. tests/main.rs mods common once plus the 6 siblings; each sibling's `mod common;` became `use crate::common;`; autotests = false + [[test]] name = \"main\" in Cargo.toml. yubaba_discovery.rs's doc-comment invocation updated to `cargo test --test main yubaba_discovery::`. common/ itself unchanged.")
//! @yah:handoff("AUDIT FINDING, fixed in-scope: round_robin::round_robins_over_two_upstreams asserted WHICH upstream serves the first request. That is not a round-robin property — pingora's LoadBalancer holds backends address-ordered, and the fake upstreams sit on OS-assigned ephemeral ports, so the phase is a port-allocator coin flip. Standalone binaries won that flip by allocating two near-adjacent ports on a quiet machine; 25 tests sharing one process interleave allocation and it failed 5 of 6 runs (including run-alone and --test-threads=1, proving it was never cross-test interference). Assertion rewritten phase-agnostic: strict alternation via windows(2) + exact 3/3 split.")
//! @yah:handoff("AUDIT NOTE, not fixed: empty_upstreams_returns_503_and_health_reports_unready failed once under peak machine load during the audit storm, 0 recurrences in 8 subsequent full runs. start_proxy already gates on wait_until_accepting, so the plausible vector is the free_addr TOCTOU that common/mod.rs documents as accepted. Pre-existing, consolidation only raises in-process port churn; left as recorded risk.")
//! @yah:handoff("Context: done in an ephemeral cloud container without the camp's cargo-orphan-gc/sccache wrapper chain — every cargo call ran with RUSTC_WRAPPER=\"\". No camp daemon involved; nothing in this crate needed one.")
//! @yah:verify("Ran: --list on a pristine-HEAD worktree vs consolidated tree — lib 99 + bin 8 + integration 25 = 132 both sides (integration count also cross-checked statically: 25 #[test]/#[tokio::test] fns across the 6 files at HEAD). Suite green: 2 full-suite runs + 8 consecutive --test main runs all 25/25 after the phase fix (before it: 5 of 6 red, see finding).")
//! @yah:tier(Cleric)

pub mod acme;
pub mod auth;
pub mod discovery;
pub mod hardening;
pub mod health;
pub mod host;
pub mod idle;
pub mod path;
pub mod proxy;
pub mod redirect;
pub mod routing;
pub mod tls;
pub mod upstream;

pub use acme::{AcmeConfig, AcmeDirectory, AcmeRenewalService};
pub use auth::{CheersAuth, RouteAuthPolicy};
pub use discovery::{YubabaDiscoveryConfig, YubabaUpstreams};
pub use health::{HostReadiness, ReadinessBody};
pub use host::{request_host, HostOutcome};
pub use proxy::PassProxy;
pub use routing::{build_host_router, HostKey, HostRouter};
pub use tls::TlsMode;
pub use upstream::{StaticUpstreams, UpstreamSource};
