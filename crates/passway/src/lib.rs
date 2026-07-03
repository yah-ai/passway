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
//! - [`upstream`] — the pluggable [`upstream::UpstreamSource`] seam plus
//!   the v0 [`upstream::StaticUpstreams`] implementation and the
//!   `pingora::lb::LoadBalancer` builder.
//! - [`auth`] — `cheers-verify` wiring ([`auth::CheersAuth`]) and the
//!   per-route auth policy ([`auth::RouteAuthPolicy`]).
//! - [`hardening`] — the request-smuggling defenses (hop-by-hop header
//!   stripping, Content-Length/Transfer-Encoding conflict rejection) as
//!   pure, independently-testable functions over [`http::HeaderMap`].
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
//! The `@yah:ticket(R594-F4)` annotation is homed in
//! `.yah/docs/working/W267-sovereign-public-ingress.md` (single source of
//! truth — Rule11 dedup, 2026-07-03), alongside its sibling R594 tickets.

pub mod auth;
pub mod hardening;
pub mod health;
pub mod proxy;
pub mod tls;
pub mod upstream;

pub use auth::{CheersAuth, RouteAuthPolicy};
pub use health::ReadinessBody;
pub use proxy::PassProxy;
pub use tls::TlsMode;
pub use upstream::{StaticUpstreams, UpstreamSource};
