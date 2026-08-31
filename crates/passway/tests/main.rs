//! R743-T6: single consolidated integration-test binary for the 6 test
//! files that used to compile (and link pingora + the whole dep graph)
//! separately. `common` is now an ordinary sibling module declared once
//! here, rather than being recompiled fresh into every one of the 6
//! `tests/*.rs` binaries `mod common;` used to build. See Cargo.toml's
//! `autotests = false` + `[[test]] name = "main"`.
mod common;

mod auth_gate;
mod empty_upstreams;
mod host_routing;
#[cfg(all(unix, feature = "socket-activation"))]
mod jit_cold_start;
mod path_confusion;
mod round_robin;
#[cfg(all(unix, feature = "socket-activation"))]
mod socket_activation;
mod yubaba_discovery;
