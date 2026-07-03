//! TLS termination configuration.
//!
//! R594-F4 V0 MUST #2: bring-your-own-cert, rustls-backed, "like mshr's
//! `tls_manual`" (`oss/mshr/crates/mshr/src/relay.rs`). ACME automation is
//! SHOULD, not MUST, and is **deferred** — see §ACME hook below for exactly
//! what's missing and why.
//!
//! [`TlsMode::Manual`] wraps `pingora`'s own
//! [`pingora::listeners::tls::TlsSettings::intermediate`], which — under
//! this crate's `rustls` feature — loads a PEM cert chain + key from disk
//! and builds a rustls-backed TLS acceptor (verified against pingora
//! 0.8.1's source: `pingora-core/src/listeners/tls/rustls/mod.rs`,
//! `TlsSettings::build` calls `pingora_rustls::load_certs_and_key_files`
//! then `ServerConfig::builder_with_protocol_versions(&[TLS12, TLS13])`).
//! `enable_h2()` sets ALPN to prefer HTTP/2 with HTTP/1.1 as fallback,
//! satisfying V0 MUST #1's "HTTP/1.1+HTTP/2 on a TLS listener".
//!
//! ## ACME hook (deferred to a follow-up ticket)
//!
//! What full ACME automation would need, precisely:
//!
//! 1. A cert-issuance side-process (e.g. `instant-acme` or `rustls-acme`,
//!    both MIT/Apache-2.0 — license-compatible with this crate's
//!    permissive-only `deny.toml`) that speaks RFC-8555 to Let's Encrypt
//!    and writes the issued chain + key to the same on-disk paths
//!    [`TlsMode::Manual`] already reads. `mshr`'s `relay.rs` proves the
//!    TLS-ALPN-01 + rustls half of this shape works in this stack
//!    end-to-end (`AcmeConfig` / `tls_letsencrypt`) — but it's wired to
//!    `iroh_relay::server::Server`'s own accept loop, not to pingora's
//!    `TlsSettings`, so it is not a drop-in for this crate.
//! 2. A renewal-triggered **rebind**, because `TlsSettings::build()` reads
//!    the cert/key files once at construction time and produces a static
//!    `Acceptor` — there is no live-reload hook on the settings object
//!    itself. Pingora's own answer to "swap a listener's config without
//!    dropping connections" is its graceful-upgrade machinery (`--upgrade`
//!    CLI flag + `SIGQUIT`, `SCM_RIGHTS` fd-passing to a freshly-`exec`'d
//!    process — see `pingora-core-0.8.1/src/server/transfer_fd/mod.rs`,
//!    confirmed Linux-only in the R594-S1 spike): a renewed cert ships by
//!    restarting the process via that upgrade path, not by mutating a
//!    running listener.
//! 3. First-boot bootstrapping: unlike [`TlsMode::Manual`] (which simply
//!    fails to start if the files are missing — an operator error caught
//!    immediately), an ACME path must handle "no cert on disk yet" by
//!    blocking startup on a first issuance, with its own timeout/retry and
//!    (for TLS-ALPN-01) a moment where the listener must already be bound
//!    and answering the ACME challenge before a *real* cert exists.
//!
//! None of this is individually large in any one piece, but composing it
//! correctly (particularly step 2's interaction with pingora's own
//! zero-downtime restart story) is real, standalone work — shipping it
//! half-done inside this same pass would risk exactly the kind of
//! TLS-listener bug that matters most on TRUST-BOUNDARY code. Follow-up:
//! a new ticket under R594 (or a T-ticket on this one) titled roughly
//! "passway ACME automation via instant-acme + graceful upgrade."
//!
//! A future `TlsMode::Acme { .. }` variant is the intended extension point
//! — `main.rs` already matches on `TlsMode` to build the `TlsSettings`, so
//! adding a variant there is the only wiring change a follow-up needs.

use pingora::listeners::tls::TlsSettings;

/// How passway terminates TLS for its public listener.
///
/// Only [`TlsMode::Manual`] exists in v0 — see the module docs' §ACME hook
/// for what a future `Acme` variant would require.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Bring-your-own-cert: a PEM certificate chain and a PEM private key
    /// on disk, loaded once at startup (mirrors mshr's `tls_manual`).
    Manual { cert_path: String, key_path: String },
}

/// Build a rustls-backed [`TlsSettings`] for `mode`, with HTTP/2 ALPN
/// enabled (V0 MUST #1: HTTP/1.1 **and** HTTP/2 on the TLS listener).
pub fn build_tls_settings(mode: &TlsMode) -> pingora::Result<TlsSettings> {
    match mode {
        TlsMode::Manual { cert_path, key_path } => {
            let mut settings = TlsSettings::intermediate(cert_path, key_path)?;
            settings.enable_h2();
            Ok(settings)
        }
    }
}
