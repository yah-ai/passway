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

pub mod acme;
pub mod auth;
pub mod discovery;
pub mod hardening;
pub mod health;
pub mod host;
pub mod path;
pub mod proxy;
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
