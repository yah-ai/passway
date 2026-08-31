//! # passway-demux — the SNI demultiplexer (W267 / R779)
//!
//! One hot process on `:443` that lets one public IP front N per-tenant
//! passway processes. It peeks each connection's TLS ClientHello, reads the
//! `server_name` extension, and splices the raw TCP stream to the backend
//! that owns that hostname — **without terminating TLS**.
//!
//! That last clause is the design, not a detail. R777 decided the tenant
//! boundary is the process: one passway, one cert, one tenant's private key
//! (see `passway/src/tls.rs` §"One listener serves one cert"). The obvious
//! objection was cost — one process per tenant means one public IP per
//! tenant, because two listeners cannot share `:443`. This crate is the
//! answer to that objection that *keeps* the verdict: the demux holds no
//! private key and sees no plaintext, so a compromise of the one shared
//! process yields routing metadata and nothing more. It is strictly better
//! than SNI-selecting certs inside one TLS terminator (W267 "option A") on
//! isolation, not a compromise of it.
//!
//! The same shape is what haproxy (`tcp-request inspect-delay` +
//! `req.ssl_sni`), nginx (`ssl_preread`), and sniproxy ship; none of those
//! are linkable from a musl-static Rust binary that must not carry a TLS
//! stack, hence this crate. It is ~400 lines because the problem is small:
//! the risk lives in the failure modes, and each one is named in
//! [`demux::Verdict`].
//!
//! ## Module map
//!
//! - [`hello`] — [`hello::parse_sni`], the pure ClientHello parser.
//!   Bounds-checked on every length, single-record only, returns
//!   `Incomplete(n)` so the reader can fetch exactly what is missing.
//! - [`route`] — [`route::RouteTable`], exact / one-label-wildcard /
//!   explicit catch-all, fail-closed on anything unmatched.
//! - [`demux`] — [`demux::serve`] / [`demux::handle`], the accept → peek →
//!   route → splice loop with its deadlines and connection cap.
//! - [`routes_file`] — the live table, reloaded from the file
//!   `yubaba::demux_routes` publishes from the tenant enrollment set, so a
//!   newly registered domain becomes routable without restarting `:443`.
//!
//! The binary (`src/main.rs`) wires env config to these and also adopts an
//! inherited `LISTEN_FDS` socket, so the demux itself can sit behind
//! kamaji's socket custody like any other workload.

pub mod demux;
pub mod hello;
pub mod route;
pub mod routes_file;

pub use demux::{handle, serve, serve_shared, DemuxOptions, Verdict};
pub use hello::{parse_sni, HelloError};
pub use route::{Backend, RouteTable};
pub use routes_file::{LoadError, SharedRoutes};
