//! TLS termination configuration.
//!
//! R594-F4 V0 MUST #2 shipped [`TlsMode::Manual`]: bring-your-own-cert,
//! rustls-backed, "like mshr's `tls_manual`"
//! (`oss/mshr/crates/mshr/src/relay.rs`). R594-F7 adds [`TlsMode::Acme`] —
//! automated Let's Encrypt issuance + renewal — as a second, additive mode
//! selected by config/env (see `main.rs`'s env table and
//! `acme::parse_acme_config`). Manual stays the default and the fallback;
//! nothing about it changed.
//!
//! [`TlsMode::Manual`] and [`TlsMode::Acme`] both wrap `pingora`'s own
//! [`pingora::listeners::tls::TlsSettings::intermediate`], which — under
//! this crate's `rustls` feature — loads a PEM cert chain + key from disk
//! and builds a rustls-backed TLS acceptor (verified against pingora
//! 0.8.1's source: `pingora-core/src/listeners/tls/rustls/mod.rs`,
//! `TlsSettings::build` calls `pingora_rustls::load_certs_and_key_files`
//! then `ServerConfig::builder_with_protocol_versions(&[TLS12, TLS13])`).
//! `enable_h2()` sets ALPN to prefer HTTP/2 with HTTP/1.1 as fallback,
//! satisfying V0 MUST #1's "HTTP/1.1+HTTP/2 on a TLS listener".
//!
//! ## Why `TlsMode::Acme` builds identical `TlsSettings` to `Manual`
//!
//! `pingora_rustls`'s `TlsSettings::build()` calls
//! `ServerConfig::builder(...).with_single_cert(certs, key)` — a **static**
//! rustls `ServerConfig` baked once at construction time. There is no
//! `ResolvesServerCert` hook exposed through `TlsSettings` (the rustls
//! backend's `with_callbacks()` constructor is unconditionally
//! `Err("Certificate callbacks are not supported with feature \"rustls\"")`
//! — confirmed directly in
//! `pingora-core-0.8.1/src/listeners/tls/rustls/mod.rs`). So there is
//! nothing an ACME mode could plug into at the `TlsSettings` layer to
//! respond differently per-connection; all the ACME automation lives
//! *upstream* of this function, in the [`acme`][crate::acme] module, whose
//! entire job is to make sure a valid cert+key already sit at `cert_path`/
//! `key_path` before `build_tls_settings` is ever called. By the time this
//! function runs, `Acme` and `Manual` are the same operation: read
//! whatever's on disk right now.
//!
//! ## The reload gap — solved via graceful-upgrade, not a live swap
//!
//! Because `TlsSettings` is static, a renewed cert sitting on disk does
//! **not** get picked up by the already-running process. Do not try to
//! chase an in-place swap — pingora's own answer to "replace a listener's
//! TLS config with zero downtime" is its graceful-upgrade machinery
//! (`SIGQUIT` + `SCM_RIGHTS` fd-passing to a freshly-started sibling
//! process — see `pingora-core-0.8.1/src/server/transfer_fd/mod.rs`,
//! Linux-only, confirmed in the R594-S1 spike), and `main.rs` now wires the
//! pieces needed to actually invoke it (`PASSWAY_PID_FILE`,
//! `PASSWAY_UPGRADE_SOCK`, `PASSWAY_UPGRADE`; see that file's module doc).
//!
//! **passway never sends itself `SIGQUIT`.** pingora's upgrade dance
//! requires a *replacement* process to already be alive and connected to
//! `upgrade_sock` before the running process receives `SIGQUIT` — the
//! `SIGQUIT` handler unconditionally proceeds to shut the listener down
//! after its fd-send step whether or not a peer was there to receive it
//! (`ExecutionPhase::GracefulUpgradeTransferringFds` ->
//! `GracefulUpgradeCloseTimeout`, no rollback branch). Self-signalling
//! without a coordinated new process already listening would tear down
//! the only listener — exactly the self-inflicted-downtime failure mode
//! this module is written to avoid. Spawning that replacement process is
//! an orchestration action (which binary, which env, when it's healthy
//! enough to receive the handoff) that belongs to whatever supervises this
//! process's lifecycle — for a kamaji-managed `ingress` workload, that's
//! kamaji. The signal contract `acme.rs`'s `AcmeRenewalService` documents
//! and logs on every renewal:
//!
//! 1. `acme::AcmeRenewalService` writes a renewed cert+key to `cert_path`/
//!    `key_path` and logs it (INFO, "renewed cert written to ... trigger a
//!    graceful-upgrade restart now").
//! 2. The supervisor starts a **new** passway process, same env plus
//!    `PASSWAY_UPGRADE=true` (and the same `PASSWAY_PID_FILE`/
//!    `PASSWAY_UPGRADE_SOCK` as the process it's replacing).
//! 3. Once the new process logs that it's up (past `server.bootstrap()`),
//!    the supervisor sends `SIGQUIT` to the *old* process's pid (read from
//!    `PASSWAY_PID_FILE`).
//! 4. The old process hands its listening fds to the new one over
//!    `upgrade_sock` and drains in-flight connections; the new process —
//!    already running with the fresh cert files ACME wrote — takes over.
//!
//! ## First-boot bootstrapping
//!
//! Unlike [`TlsMode::Manual`] (which simply fails to start if the files are
//! missing — an operator error caught immediately), [`TlsMode::Acme`]
//! handles "no cert on disk yet" in `main.rs`, *before* this module is ever
//! called: `acme::ensure_cert_on_disk` blocks startup on a first issuance
//! (its own bounded retry/timeout), using a dedicated one-shot Tokio
//! runtime that exists only for that blocking call (pingora's own runtime
//! doesn't exist yet at that point in `main()` — it starts inside
//! `server.run_forever()`). See `acme.rs`'s module doc for the full
//! design, including why HTTP-01 (not TLS-ALPN-01) is the challenge type
//! used for both first issuance and every renewal.
//!
//! @yah:assumes-style: this module (and `acme.rs`) build on the
//! `TlsMode`/cert-path shape R594-F4 shipped, which was still in REVIEW at
//! the time R594-F7 was written. If review changes that shape, this
//! adapts — nothing here depends on anything beyond "a mode carries a
//! `cert_path`/`key_path` pair that `build_tls_settings` reads."

use pingora::listeners::tls::TlsSettings;

/// How passway terminates TLS for its public listener.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Bring-your-own-cert: a PEM certificate chain and a PEM private key
    /// on disk, loaded once at startup (mirrors mshr's `tls_manual`). The
    /// default and fallback — nothing manages these files but the
    /// operator.
    Manual { cert_path: String, key_path: String },
    /// Automated Let's Encrypt (or any RFC-8555 ACME directory): the same
    /// shape as [`TlsMode::Manual`] — a PEM cert chain and PEM private key
    /// on disk — but the files are kept fresh by
    /// [`crate::acme::AcmeRenewalService`] instead of an operator. By the
    /// time this variant reaches [`build_tls_settings`], a valid cert+key
    /// MUST already exist at these paths: `main.rs` guarantees this by
    /// calling `acme::ensure_cert_on_disk` first (see that function and
    /// this module's "First-boot bootstrapping" doc above).
    Acme { cert_path: String, key_path: String },
}

/// Build a rustls-backed [`TlsSettings`] for `mode`, with HTTP/2 ALPN
/// enabled (V0 MUST #1: HTTP/1.1 **and** HTTP/2 on the TLS listener).
///
/// `Manual` and `Acme` are handled identically here on purpose — see this
/// module's doc for why the ACME automation can't and doesn't reach this
/// function at all; it only ever sees "read this cert_path/key_path pair".
pub fn build_tls_settings(mode: &TlsMode) -> pingora::Result<TlsSettings> {
    let (cert_path, key_path) = match mode {
        TlsMode::Manual { cert_path, key_path } => (cert_path, key_path),
        TlsMode::Acme { cert_path, key_path } => (cert_path, key_path),
    };
    let mut settings = TlsSettings::intermediate(cert_path, key_path)?;
    settings.enable_h2();
    Ok(settings)
}
