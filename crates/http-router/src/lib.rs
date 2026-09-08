//! # passway-http-router — the `:80` tier (W267 / R870)
//!
//! One hot process on port 80 that lets one public IP answer plain HTTP for
//! N tenants. It reads each request's `Host` header and does one of two
//! things:
//!
//! - **`308 https://<host><target>`**, written by this process, for a host
//!   whose route says `redirect`. That is the disposition every enrolled
//!   domain gets by default, and it is the whole reason this crate exists:
//!   `curl -fsSL example.com/install.sh` dials `:80`, and a front door that
//!   owns a public apex has to own `:80` too even though it serves nothing
//!   there (see `passway::redirect` for the outage that taught us).
//! - **splice to that tenant's plaintext backend**, for a host whose route
//!   names an address — the tenant passway's `PASSWAY_ACME_HTTP01_BIND`
//!   responder, so an `http-01` order can still be validated behind the
//!   fan-in.
//!
//! A host with **no route is closed**, with a `404` and nothing else. It is
//! never redirected: `Location` is built from the client's own `Host` header,
//! so redirecting an unknown host would make this an open redirector for any
//! name that resolves here.
//!
//! ## Why this is not the `:443` binary
//!
//! `passway-demux` (`oss/passway/crates/sni-demux`) is the same shape one
//! layer up: peek, route on a name, splice. The obvious economy is to teach
//! it a second listener. **Do not.** The demux's load-bearing R777 invariant
//! is that the shared `:443` process links no TLS library, holds no key and
//! sees no plaintext — a compromise of it yields routing metadata and
//! nothing more. This process *does* parse an application protocol and *does*
//! write responses, which is a strictly larger attack surface; putting it in
//! the same address space would spend the demux's invariant to save a
//! systemd unit. W267's `custom domains validate by DNS-01` section records
//! the same reasoning from the other side — keeping a second protocol off the
//! edge is why DNS-01 CNAME delegation was chosen over HTTP-01.
//!
//! The two tiers therefore share a *policy* and no code: the match
//! precedence, the fail-closed miss, and the never-make-the-table-worse
//! reload rule are deliberately identical to
//! [`sni_demux::route`](https://docs.rs/passway-demux) and
//! `sni_demux::routes_file`, and each module here names its twin.
//!
//! ## Module map
//!
//! - [`head`] — [`head::parse_head`], the request-line + `Host` reader.
//!   Bounded at [`head::MAX_HEAD_BYTES`], returns `Incomplete` so the reader
//!   fetches more rather than guessing.
//! - [`route`] — [`route::HostTable`], exact / one-label-wildcard / explicit
//!   catch-all → [`route::Disposition`]. Fail-closed on a miss.
//! - [`redirect`] — building the `308`, and the strict `Host` validation that
//!   keeps it from becoming an open redirect.
//! - [`router`] — [`router::serve_shared`] / [`router::handle`], the
//!   accept → read → route → answer-or-splice loop.
//! - [`routes_file`] — the live table, reloaded from the file
//!   `yubaba::demux_routes` publishes from the tenant enrollment set.
//!
//! The binary (`src/main.rs`) wires env config to these and adopts an
//! inherited `LISTEN_FDS` socket, exactly as `passway-demux` does.

pub mod head;
pub mod redirect;
pub mod route;
pub mod router;
pub mod routes_file;

pub use head::{parse_head, Head, HeadError};
pub use redirect::{redirect_response, redirect_target};
pub use route::{Disposition, HostTable};
pub use router::{handle, serve, serve_shared, RouterOptions, Verdict};
pub use routes_file::{LoadError, SharedRoutes};
