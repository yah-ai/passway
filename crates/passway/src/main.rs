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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cheers_verify::PasetoV4PublicVerifier;
use pingora::server::Server;
use pingora::services::background::background_service;

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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let listen = env_or("PASSWAY_LISTEN", "0.0.0.0:443");
    let cert_path = std::env::var("PASSWAY_TLS_CERT").expect("PASSWAY_TLS_CERT is required");
    let key_path = std::env::var("PASSWAY_TLS_KEY").expect("PASSWAY_TLS_KEY is required");

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

    let mut server = Server::new(None).expect("failed to construct pingora Server");
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
    let tls_settings = build_tls_settings(&TlsMode::Manual {
        cert_path,
        key_path,
    })
    .expect("failed to build TLS settings — check PASSWAY_TLS_CERT / PASSWAY_TLS_KEY");
    proxy_service.add_tls_with_settings(&listen, None, tls_settings);

    server.add_service(proxy_service);
    server.add_service(lb_background);

    log::info!("passway listening on {listen}");
    server.run_forever();
}
