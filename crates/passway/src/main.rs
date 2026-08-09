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
//! | `PASSWAY_UPSTREAM_SOURCE` | `static` (from `PASSWAY_UPSTREAMS`) or `yubaba` (R594-F8 discovery) | `static` |
//! | `PASSWAY_UPSTREAMS` | comma-separated backend list, optionally `<hostname>=` prefixed to give each fronted service its own set (`static` source only — see below) | empty (fail-ready 503) |
//! | `PASSWAY_YUBABA_URL` | base URL of the yubaba to discover upstreams from, e.g. `http://100.64.0.2:7443` | required if `PASSWAY_UPSTREAM_SOURCE=yubaba` |
//! | `PASSWAY_YUBABA_TIMEOUT_SECS` | per-request timeout for a discovery poll | `5` |
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
//!
//! ## Choosing an upstream source (R594-F8)
//!
//! `PASSWAY_UPSTREAM_SOURCE=static` (the default) reads a fixed address list
//! out of `PASSWAY_UPSTREAMS` — no control plane, right for a standalone
//! passway, a test fixture, or an edge fronting something yubaba doesn't
//! place. `PASSWAY_UPSTREAM_SOURCE=yubaba` polls yubaba's service-record
//! surface instead (`passway::discovery`), which is what makes this process
//! an ingress *provider*: the backend set follows placement rather than being
//! typed in. Neither is a migration of the other; see `upstream.rs`.
//!
//! ## Fronting several services from one node (R594-F10)
//!
//! Prefix a `PASSWAY_UPSTREAMS` entry with `<hostname>=` to give that
//! hostname its own upstream set; repeat the hostname to add addresses to it.
//! Requests are routed by authority (`Host` / `:authority`), and each set is
//! round-robined and health-checked independently:
//!
//! ```text
//! PASSWAY_UPSTREAMS=marketing.example.com=100.64.0.5:8080,\
//!                   marketing.example.com=100.64.0.6:8080,\
//!                   analytics.example.com=100.64.0.7:9000
//! ```
//!
//! An authority no entry names gets a 503 — never another service's
//! backends. To serve unmatched authorities anyway, declare a catch-all
//! explicitly with the reserved `*=` prefix (`*=100.64.0.9:8080`).
//!
//! Unprefixed entries are the pre-R594-F10 single-set form and become the
//! catch-all, so `PASSWAY_UPSTREAMS=100.64.0.5:8080` behaves exactly as it
//! always has. **Mixing** unprefixed and `<hostname>=` entries is rejected at
//! boot rather than guessed at: it reads as "and everything else goes here",
//! which is a catch-all, and a catch-all on a multi-tenant front door has to
//! be typed on purpose (`*=`) — not arrived at by forgetting a prefix.
//!
//! `PASSWAY_UPSTREAM_SOURCE=yubaba` is one flat set, so it becomes the
//! catch-all; per-host dynamic discovery is R594-F6/F8 territory and does not
//! gate this.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cheers_verify::PasetoV4PublicVerifier;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::background::background_service;

use passway::acme::{self, AcmeConfig};
use passway::auth::{CheersAuth, RouteAuthPolicy};
use passway::discovery::{YubabaDiscoveryConfig, YubabaUpstreams};
use passway::proxy::PassProxy;
use passway::routing::{build_host_router, HostKey, CATCH_ALL_LABEL};
use passway::tls::{build_tls_settings, TlsMode};
use passway::upstream::{StaticUpstreams, UpstreamSource};

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

/// Parse `PASSWAY_UPSTREAMS` into one address list per fronted hostname
/// (R594-F10). See this file's module doc for the grammar.
///
/// An individual unparsable *address* is warned about and skipped (the
/// pre-R594-F10 behavior — its set is then simply short one backend, or
/// empty and fail-ready). A structurally ambiguous *config* — unprefixed
/// entries mixed with `<hostname>=` ones — is an error the caller turns into
/// a boot failure, because the only reading of it is an accidental catch-all.
fn parse_upstream_sets(raw: &str) -> Result<Vec<(HostKey, Vec<SocketAddr>)>, String> {
    let mut sets: BTreeMap<HostKey, Vec<SocketAddr>> = BTreeMap::new();
    let mut bare: Vec<&str> = Vec::new();
    let mut keyed: Vec<&str> = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        // Split on the FIRST '=' only: the value is an address, which never
        // contains one, and a hostname must not.
        let (key, addr_str) = match entry.split_once('=') {
            Some((host, addr)) => {
                let host = host.trim();
                if host == CATCH_ALL_LABEL {
                    (HostKey::CatchAll, addr.trim())
                } else if host.is_empty() {
                    return Err(format!("PASSWAY_UPSTREAMS entry {entry:?} has an empty hostname"));
                } else {
                    keyed.push(host);
                    (HostKey::Host(host.to_string()), addr.trim())
                }
            }
            None => {
                bare.push(entry);
                (HostKey::CatchAll, entry)
            }
        };
        match addr_str.parse::<SocketAddr>() {
            Ok(addr) => sets.entry(key).or_default().push(addr),
            Err(e) => log::warn!("PASSWAY_UPSTREAMS: skipping unparsable entry {entry:?}: {e}"),
        }
    }

    if !bare.is_empty() && !keyed.is_empty() {
        return Err(format!(
            "PASSWAY_UPSTREAMS mixes unprefixed entries ({bare:?}) with host-prefixed ones \
             ({keyed:?}). An unprefixed entry means \"serve every hostname from here\", which \
             on a host-routed front door is a catch-all — write it as \"*=<addr>\" if that is \
             what you meant, or give it a hostname prefix."
        ));
    }

    Ok(sets.into_iter().collect())
}

/// Pick the [`UpstreamSource`]s from `PASSWAY_UPSTREAM_SOURCE` (R594-F8),
/// one per fronted hostname (R594-F10).
///
/// Panics on an unrecognized value rather than silently falling back to
/// `static`: a typo'd source name that quietly yields an empty static list
/// looks exactly like "yubaba has no ready upstreams", and the operator would
/// debug the wrong half of the system. Fail loudly at boot instead.
fn build_upstream_sources() -> Vec<(HostKey, Arc<dyn UpstreamSource>)> {
    match env_or("PASSWAY_UPSTREAM_SOURCE", "static").as_str() {
        "static" => {
            let sets = parse_upstream_sets(&env_or("PASSWAY_UPSTREAMS", ""))
                .unwrap_or_else(|e| panic!("invalid PASSWAY_UPSTREAMS: {e}"));
            if sets.is_empty() {
                log::warn!(
                    "PASSWAY_UPSTREAMS is empty at startup — passway will report /health as \
                     unready (fail-ready) until an upstream source populates it. This is \
                     expected on a fresh cold start, not a crash condition. For a \
                     placement-driven backend set, set PASSWAY_UPSTREAM_SOURCE=yubaba."
                );
                // Still build one (empty) catch-all set, so the proxy answers
                // 503 from the readiness gate rather than from "no set for
                // this host" — same status, but the operator-facing log above
                // is the one that explains it.
                return vec![(
                    HostKey::CatchAll,
                    Arc::new(StaticUpstreams::new(Vec::new())) as Arc<dyn UpstreamSource>,
                )];
            }
            for (key, addrs) in &sets {
                log::info!("upstream set {key:?}: {addrs:?}");
            }
            sets.into_iter()
                .map(|(key, addrs)| {
                    (
                        key,
                        Arc::new(StaticUpstreams::new(addrs)) as Arc<dyn UpstreamSource>,
                    )
                })
                .collect()
        }
        "yubaba" => {
            let base_url = std::env::var("PASSWAY_YUBABA_URL")
                .expect("PASSWAY_YUBABA_URL is required with PASSWAY_UPSTREAM_SOURCE=yubaba");
            let config = YubabaDiscoveryConfig {
                base_url,
                timeout: env_secs("PASSWAY_YUBABA_TIMEOUT_SECS", 5),
            };
            log::info!(
                "upstream discovery: polling {} every PASSWAY_UPDATE_INTERVAL_SECS",
                config.url()
            );
            // One flat set, so it serves every authority — per-host dynamic
            // discovery is R594-F6/F8 territory (see the module doc).
            vec![(HostKey::CatchAll, Arc::new(YubabaUpstreams::new(&config)))]
        }
        other => panic!(
            "PASSWAY_UPSTREAM_SOURCE {other:?} is not recognized (expected \"static\" or \"yubaba\")"
        ),
    }
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

    let upstream_sources = build_upstream_sources();
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

    // One health-checked, round-robin load balancer per fronted hostname
    // (R594-F10). Every returned background service must be added to the
    // server below, or its set's discovery/health timers never fire.
    let (router, lb_services) =
        build_host_router(upstream_sources, health_check_interval, update_interval);

    let mut proxy = PassProxy::routed(router).with_upstream_tls(upstream_tls, upstream_sni);
    if let Some((auth, policy)) = build_auth() {
        proxy = proxy.with_auth(auth, policy);
    }
    proxy = proxy.with_health_path(env_or("PASSWAY_HEALTH_PATH", "/health"));

    let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    let tls_settings = build_tls_settings(&tls_mode)
        .expect("failed to build TLS settings — check PASSWAY_TLS_CERT / PASSWAY_TLS_KEY");
    proxy_service.add_tls_with_settings(&listen, None, tls_settings);

    server.add_service(proxy_service);
    for lb_service in lb_services {
        server.add_service(lb_service);
    }
    if let Some(config) = acme_config {
        let acme_service = background_service("passway acme renewal", acme::AcmeRenewalService::new(config));
        server.add_service(acme_service);
    }

    log::info!("passway listening on {listen}");
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_unprefixed_list_is_the_catch_all_set() {
        // The pre-R594-F10 form, unchanged.
        let sets = parse_upstream_sets("127.0.0.1:9001, 127.0.0.1:9002").unwrap();
        assert_eq!(
            sets,
            vec![(
                HostKey::CatchAll,
                vec![addr("127.0.0.1:9001"), addr("127.0.0.1:9002")]
            )]
        );
    }

    #[test]
    fn host_prefixes_split_the_addresses_into_per_host_sets() {
        let sets = parse_upstream_sets(
            "marketing.example.com=127.0.0.1:9001,analytics.example.com=127.0.0.1:9003,\
             marketing.example.com=127.0.0.1:9002",
        )
        .unwrap();
        assert_eq!(
            sets,
            vec![
                (
                    HostKey::Host("analytics.example.com".into()),
                    vec![addr("127.0.0.1:9003")]
                ),
                (
                    HostKey::Host("marketing.example.com".into()),
                    vec![addr("127.0.0.1:9001"), addr("127.0.0.1:9002")]
                ),
            ]
        );
    }

    #[test]
    fn a_star_prefix_declares_an_explicit_catch_all_alongside_hosts() {
        let sets =
            parse_upstream_sets("a.example.com=127.0.0.1:9001, *=127.0.0.1:9999").unwrap();
        assert_eq!(
            sets,
            vec![
                (HostKey::Host("a.example.com".into()), vec![addr("127.0.0.1:9001")]),
                (HostKey::CatchAll, vec![addr("127.0.0.1:9999")]),
            ]
        );
    }

    #[test]
    fn mixing_unprefixed_and_host_prefixed_entries_is_rejected() {
        let err = parse_upstream_sets("127.0.0.1:9001,a.example.com=127.0.0.1:9002")
            .expect_err("an accidental catch-all must not be guessed at");
        assert!(err.contains("*=<addr>"), "error should name the fix: {err}");
    }

    #[test]
    fn an_empty_hostname_is_rejected() {
        assert!(parse_upstream_sets("=127.0.0.1:9001").is_err());
    }

    #[test]
    fn an_unparsable_address_is_skipped_leaving_its_set_fail_ready() {
        // Per-address leniency is the pre-R594-F10 behavior: the set exists
        // but is empty, so that host answers 503 rather than the whole
        // process refusing to boot.
        let sets = parse_upstream_sets("a.example.com=not-an-address,b.example.com=127.0.0.1:9002")
            .unwrap();
        assert_eq!(
            sets,
            vec![(
                HostKey::Host("b.example.com".into()),
                vec![addr("127.0.0.1:9002")]
            )]
        );
    }

    #[test]
    fn an_empty_config_yields_no_sets() {
        assert!(parse_upstream_sets("").unwrap().is_empty());
        assert!(parse_upstream_sets("  ,  ").unwrap().is_empty());
    }

    #[test]
    fn ipv6_literals_survive_the_host_prefix_split() {
        let sets = parse_upstream_sets("a.example.com=[::1]:9001").unwrap();
        assert_eq!(
            sets,
            vec![(HostKey::Host("a.example.com".into()), vec![addr("[::1]:9001")])]
        );
    }
}
