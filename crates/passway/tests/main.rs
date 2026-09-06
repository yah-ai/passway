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
// R853-F6: `unix` → `target_os = "linux"`. Adoption now rides pingora's
// SCM_RIGHTS upgrade protocol, whose helpers are Linux-only upstream.
//
// Worth knowing before reading a green run as coverage: between 2026-08-31 and
// 2026-09-04 these two modules compiled on NO default build, because R779 set
// `default = []` and this gate is on the feature. They were dark for four days
// and the suite still reported all-green. F6 restores `default =
// ["socket-activation"]`, so on Linux they are live again.
#[cfg(all(target_os = "linux", feature = "socket-activation"))]
mod jit_cold_start;
mod path_confusion;
mod round_robin;
#[cfg(all(target_os = "linux", feature = "socket-activation"))]
mod socket_activation;
mod yubaba_discovery;
