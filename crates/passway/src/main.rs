//! passway binary entrypoint — the thinnest possible wiring of
//! `passway::proxy::PassProxy` into a running `pingora::server::Server`.
//!
//! Configuration is read from the environment (no config-file parser in
//! v0 — this binary is deployed by the R594-F2 `ingress` workload kind,
//! kamaji-supervised, which already owns env-injection for its workloads).
//! All variables:
//!
//! | Variable | Meaning | Default |
//! |---|---|---|
//! | `PASSWAY_LISTEN` | TLS listener address | `0.0.0.0:443` |
//! | `PASSWAY_TLS_CERT` | PEM cert chain path | required |
//! | `PASSWAY_TLS_KEY` | PEM private key path | required |
//! | `PASSWAY_TLS_MODE` | `manual` (bring-your-own-cert) or `acme` (R594-F7) | `manual` |
//! | `PASSWAY_ACME_DOMAIN` | comma-separated SAN list to issue for (wildcards need `dns-01`) | required if `PASSWAY_TLS_MODE=acme` |
//! | `PASSWAY_ACME_CONTACT_EMAIL` | ACME account contact | required if `PASSWAY_TLS_MODE=acme` |
//! | `PASSWAY_ACME_DIRECTORY` | `production`, `staging`, or a custom ACME directory URL (Pebble/step-ca) | `staging` |
//! | `PASSWAY_ACME_CHALLENGE` | `http-01` or `dns-01` (Cloudflare; required for wildcard domains) | `http-01` |
//! | `PASSWAY_ACME_DNS01_CLOUDFLARE_TOKEN_FILE` | path to a file holding a CF API token with `DNS:Edit` on the zone | required if `dns-01` |
//! | `PASSWAY_ACME_DNS01_CLOUDFLARE_ZONE_ID` | CF zone ID the `_acme-challenge` TXT records are created in | required if `dns-01` |
//! | `PASSWAY_ACME_DNS01_PROPAGATION_SECS` | wait between publishing a TXT record and asking the CA to validate | `10` |
//! | `PASSWAY_ACME_ACCOUNT_CACHE` | path to cache ACME account credentials (JSON) | `<PASSWAY_TLS_CERT>.acme-account.json` |
//! | `PASSWAY_ACME_HTTP01_BIND` | address the HTTP-01 challenge responder binds | `0.0.0.0:80` |
//! | `PASSWAY_ACME_RENEW_BEFORE_DAYS` | renew when within this many days of expiry | `30` |
//! | `PASSWAY_ACME_CHECK_INTERVAL_SECS` | how often the renewal loop wakes to check | `43200` (12h) |
//! | `PASSWAY_ACME_CERT_LIFETIME_DAYS` | assumed cert validity (LE/ZeroSSL standard) | `90` |
//! | `PASSWAY_UPSTREAMS` | comma-separated `host:port` list | empty (fail-ready 503) |
//! | `PASSWAY_UPSTREAM_TLS` | speak TLS to upstreams (`true`/`false`) | `false` (mesh is already encrypted) |
//! | `PASSWAY_UPSTREAM_SNI` | SNI to present when `PASSWAY_UPSTREAM_TLS=true` | empty |
//! | `PASSWAY_HEALTH_PATH` | `/health`-equivalent path | `/health` |
//! | `PASSWAY_HEALTH_CHECK_INTERVAL_SECS` | TCP health-check cadence | `5` |
//! | `PASSWAY_UPDATE_INTERVAL_SECS` | upstream-source re-poll cadence | `30` |
//! | `PASSWAY_AUTH_PUBLIC_KEY_FILE` | path to a raw 32-byte Ed25519 public key | unset (auth disabled) |
//! | `PASSWAY_AUTH_KID` | the `kid` this deployment trusts | required if the key file is set |
//! | `PASSWAY_AUTH_ISS` | expected PASETO `iss` | required if the key file is set |
//! | `PASSWAY_AUTH_AUD` | expected PASETO `aud` | required if the key file is set |
//! | `PASSWAY_AUTH_REQUIRED_PREFIXES` | comma-separated path prefixes requiring a bearer | empty (fully anonymous) |
//! | `PASSWAY_PID_FILE` | pingora's pid file (per-instance path — required for a supervisor to target the right process with a graceful-upgrade signal on a node running more than one instance) | `/tmp/pingora.pid` |
//! | `PASSWAY_UPGRADE_SOCK` | pingora's graceful-upgrade fd-handoff socket (per-instance path, same reason) | `/tmp/pingora_upgrade.sock` |
//! | `PASSWAY_UPGRADE` | `true` to start this process in graceful-upgrade mode (receive listening fds from a running sibling over `PASSWAY_UPGRADE_SOCK` instead of binding fresh) | `false` |
//!
//! ## The graceful-upgrade signal contract (R594-F7)
//!
//! `PASSWAY_TLS_MODE=acme` keeps `PASSWAY_TLS_CERT`/`PASSWAY_TLS_KEY` fresh
//! (see `passway::acme`), but the already-running process never picks up
//! a renewed cert on its own — pingora's rustls `TlsSettings` has no live
//! reload hook (see `tls.rs`'s module doc). This binary wires
//! `PASSWAY_PID_FILE`/`PASSWAY_UPGRADE_SOCK`/`PASSWAY_UPGRADE` so pingora's
//! own zero-downtime hot-upgrade dance is actually invokable — by a
//! supervisor (kamaji, for a kamaji-managed `ingress` workload), not by
//! this process itself:
//!
//! 1. `acme::AcmeRenewalService` renews the cert, writes it to disk, and
//!    logs that a restart is due.
//! 2. The supervisor starts a **new** passway process: same env, plus
//!    `PASSWAY_UPGRADE=true`, and the *same* `PASSWAY_PID_FILE` /
//!    `PASSWAY_UPGRADE_SOCK` as the process it's replacing.
//! 3. Once the new process is up, the supervisor sends `SIGQUIT` to the
//!    *old* process's pid (read from `PASSWAY_PID_FILE`).
//! 4. The old process hands its listening fds to the new one over
//!    `PASSWAY_UPGRADE_SOCK` and drains in-flight connections; the new
//!    process — already running with the fresh cert files — takes over.
//!
//! This process never sends itself `SIGQUIT` or execs a replacement: step
//! 2 (spawning a live sibling before the handoff) is an orchestration
//! action only the supervisor can safely sequence — see `tls.rs`'s module
//! doc for exactly why a self-triggered upgrade would be actively unsafe.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cheers_verify::PasetoV4PublicVerifier;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::background::background_service;

use passway::acme::{self, AcmeConfig};
use passway::auth::{CheersAuth, RouteAuthPolicy};
use passway::proxy::PassProxy;
use passway::tls::{build_tls_settings, TlsMode};
use passway::upstream::{build_load_balancer, StaticUpstreams};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_secs(key: &str, default: u64) -> Duration {
    let v = std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default);
    Duration::from_secs(v)
}

fn parse_upstreams(raw: &str) -> Vec<SocketAddr> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                log::warn!("PASSWAY_UPSTREAMS: skipping unparsable entry {s:?}: {e}");
                None
            }
        })
        .collect()
}

/// Build the [`CheersAuth`] + [`RouteAuthPolicy`] pair from the environment,
/// if `PASSWAY_AUTH_PUBLIC_KEY_FILE` is set. Returns `None` when auth is not
/// configured at all — every route stays anonymous in that case.
fn build_auth() -> Option<(CheersAuth, RouteAuthPolicy)> {
    let key_path = std::env::var("PASSWAY_AUTH_PUBLIC_KEY_FILE").ok()?;
    let bytes = std::fs::read(&key_path)
        .unwrap_or_else(|e| panic!("PASSWAY_AUTH_PUBLIC_KEY_FILE {key_path:?}: {e}"));
    let key: [u8; 32] = bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "PASSWAY_AUTH_PUBLIC_KEY_FILE {key_path:?}: expected exactly 32 bytes, got {}",
            bytes.len()
        )
    });
    let verifier =
        PasetoV4PublicVerifier::from_public_key(&key).expect("valid Ed25519 public key bytes");
    let kid = std::env::var("PASSWAY_AUTH_KID").expect("PASSWAY_AUTH_KID required with an auth key");
    let iss = std::env::var("PASSWAY_AUTH_ISS").expect("PASSWAY_AUTH_ISS required with an auth key");
    let aud = std::env::var("PASSWAY_AUTH_AUD").expect("PASSWAY_AUTH_AUD required with an auth key");
    let auth = CheersAuth::new(verifier, kid, iss, aud);

    let mut policy = RouteAuthPolicy::new();
    for prefix in env_or("PASSWAY_AUTH_REQUIRED_PREFIXES", "")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        policy = policy.require_auth(prefix);
    }

    Some((auth, policy))
}

fn main() {
    // rustls 0.23 requires a process-level CryptoProvider before the first
    // TLS use, and this dependency graph enables both `ring` (instant-acme's
    // pin, see Cargo.toml) and `aws-lc-rs` (rustls's own default via
    // pingora-rustls), so rustls cannot auto-select one. pingora installs
    // `ring` itself, but only lazily inside `TlsSettings::build()` /
    // connector setup — too late for the ACME first-boot bootstrap below,
    // which speaks HTTPS to the directory before pingora's TLS layer is
    // constructed. Install `ring` up front; pingora's later install is a
    // no-op re-install of the same provider.
    pingora::tls::install_default_crypto_provider();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let listen = env_or("PASSWAY_LISTEN", "0.0.0.0:443");
    let cert_path = std::env::var("PASSWAY_TLS_CERT").expect("PASSWAY_TLS_CERT is required");
    let key_path = std::env::var("PASSWAY_TLS_KEY").expect("PASSWAY_TLS_KEY is required");

    let acme_config: Option<AcmeConfig> =
        acme::parse_acme_config(|k| std::env::var(k).ok(), cert_path.clone(), key_path.clone())
            .unwrap_or_else(|e| panic!("invalid ACME configuration: {e}"));

    let tls_mode = match &acme_config {
        Some(_) => TlsMode::Acme {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        },
        None => TlsMode::Manual {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        },
    };

    if let Some(config) = &acme_config {
        // First-boot bootstrap: block on obtaining a usable cert before
        // pingora's own runtime (which only starts inside
        // `server.run_forever()`, below) exists. A dedicated one-shot
        // runtime drives this; it's dropped once bootstrap completes —
        // steady state runs as a normal pingora-managed background
        // service instead (see `acme::AcmeRenewalService`, added below).
        // See `tls.rs`'s "First-boot bootstrapping" doc for why this
        // ordering is necessary.
        let bootstrap_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build the ACME bootstrap runtime");
        bootstrap_rt
            .block_on(acme::ensure_cert_on_disk(config))
            .expect("initial ACME certificate issuance failed — check PASSWAY_ACME_* env vars and that port 80 is reachable from the public internet for HTTP-01 validation");
    }

    let upstream_addrs = parse_upstreams(&env_or("PASSWAY_UPSTREAMS", ""));
    if upstream_addrs.is_empty() {
        log::warn!(
            "PASSWAY_UPSTREAMS is empty at startup — passway will report /health as unready \
             (fail-ready) until an upstream source populates it. This is expected on a fresh \
             R594-F6 cold start, not a crash condition."
        );
    }
    let upstream_tls = env_or("PASSWAY_UPSTREAM_TLS", "false") == "true";
    let upstream_sni = env_or("PASSWAY_UPSTREAM_SNI", "");
    let health_check_interval = env_secs("PASSWAY_HEALTH_CHECK_INTERVAL_SECS", 5);
    let update_interval = env_secs("PASSWAY_UPDATE_INTERVAL_SECS", 30);

    // Wire pingora's graceful-upgrade machinery to per-instance paths
    // (never its shared `/tmp/pingora*` defaults, which would collide
    // across multiple instances on one node) and let a supervisor start
    // this process in upgrade mode via `PASSWAY_UPGRADE=true`. See this
    // file's module doc for the full signal contract R594-F7 relies on to
    // actually reload a renewed ACME cert (this process never triggers
    // the upgrade itself).
    let mut conf = ServerConf::default();
    conf.pid_file = env_or("PASSWAY_PID_FILE", &conf.pid_file);
    conf.upgrade_sock = env_or("PASSWAY_UPGRADE_SOCK", &conf.upgrade_sock);
    let opt = Opt {
        upgrade: env_or("PASSWAY_UPGRADE", "false") == "true",
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(opt), conf);
    server.bootstrap();

    let source = Arc::new(StaticUpstreams::new(upstream_addrs));
    let lb = build_load_balancer(source, health_check_interval, update_interval);
    let lb_background = background_service("passway upstream health", lb);
    let lb_handle = lb_background.task();

    let mut proxy = PassProxy::new(lb_handle).with_upstream_tls(upstream_tls, upstream_sni);
    if let Some((auth, policy)) = build_auth() {
        proxy = proxy.with_auth(auth, policy);
    }
    proxy = proxy.with_health_path(env_or("PASSWAY_HEALTH_PATH", "/health"));

    let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    let tls_settings = build_tls_settings(&tls_mode)
        .expect("failed to build TLS settings — check PASSWAY_TLS_CERT / PASSWAY_TLS_KEY");
    proxy_service.add_tls_with_settings(&listen, None, tls_settings);

    server.add_service(proxy_service);
    server.add_service(lb_background);
    if let Some(config) = acme_config {
        let acme_service = background_service("passway acme renewal", acme::AcmeRenewalService::new(config));
        server.add_service(acme_service);
    }

    log::info!("passway listening on {listen}");
    server.run_forever();
}
