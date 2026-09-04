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
//! | `PASSWAY_ACME_DNS01_DELEGATE_ZONE` | R779: publish the challenge TXT at `<domain>.<this zone>` instead of `_acme-challenge.<domain>` — for a domain whose zone we do not hold, whose owner CNAMEs `_acme-challenge.<domain>` here | unset (we hold the zone) |
//! | `PASSWAY_ACME_CF_API_BASE` | R779: base URL the DNS-01 TXT create/delete calls go to, e.g. `http://127.0.0.1:8080`. A test hook only — the DNS-01 integration harness points it at a Cloudflare-shaped shim; leave it unset in production | unset (`https://api.cloudflare.com/client/v4`) |
//! | `PASSWAY_ACME_DNS01_PROPAGATION_SECS` | wait between publishing a TXT record and asking the CA to validate | `10` |
//! | `PASSWAY_ACME_ACCOUNT_CACHE` | path to cache ACME account credentials (JSON) | `<PASSWAY_TLS_CERT>.acme-account.json` |
//! | `PASSWAY_ACME_HTTP01_BIND` | address the HTTP-01 challenge responder binds | `0.0.0.0:80` |
//! | `PASSWAY_HTTP_REDIRECT_BIND` | R330-F37: address a plain-HTTP listener binds to answer `308 https://<host><path>`. A front door on a grey apex needs this or scheme-less `curl yah.dev/...` (which dials `:80`) is refused. Refuses to start alongside an `http-01` responder on the same address — see [`passway::redirect`] | unset (no plain-HTTP listener) |
//! | `PASSWAY_ACME_RENEW_BEFORE_DAYS` | renew when within this many days of expiry | `30` |
//! | `PASSWAY_ACME_CHECK_INTERVAL_SECS` | how often the renewal loop wakes to check | `43200` (12h) |
//! | `PASSWAY_ACME_CERT_LIFETIME_DAYS` | assumed cert validity (LE/ZeroSSL standard) | `90` |
//! | `PASSWAY_ACME_BOOTSTRAP_TIMEOUT_SECS` | R779: cap on the first-boot issuance (certmagic's handshake budget); a timeout is recorded in the `<cert>.acme-failed` backoff marker | `180` |
//! | `LISTEN_FDS` / `LISTEN_PID` | R779: systemd socket-activation convention — with `LISTEN_FDS=1` (and `LISTEN_PID` unset or equal to this pid) fd 3 is adopted as the `PASSWAY_LISTEN` socket instead of binding fresh; this is how the process sits behind kamaji's on-demand JIT tier | unset |
//! | `PASSWAY_IDLE_TTL_SECS` | R779: exit once no request has been in flight for this long — for kamaji's on-demand JIT tier, which re-forks on the next connection. Unset = never | unset |
//! | `PASSWAY_UPSTREAM_SOURCE` | `static` (from `PASSWAY_UPSTREAMS`) or `yubaba` (R594-F8 discovery) | `static` |
//! | `PASSWAY_UPSTREAMS` | comma-separated backend list, optionally `<hostname>=` prefixed to give each fronted service its own set (`static` source only — see below) | empty (fail-ready 503) |
//! | `PASSWAY_YUBABA_URL` | base URL of the yubaba to discover upstreams from, e.g. `http://100.64.0.2:7443` | required if `PASSWAY_UPSTREAM_SOURCE=yubaba` |
//! | `PASSWAY_YUBABA_IDENT` | R844-B6: workload ident whose service records become this proxy's backends. A node hosts several workloads and the endpoint answers for all of them, so without this passway would adopt every Ready record on the node. R844-F20: optionally `<hostname>=` prefixed, exactly like `PASSWAY_UPSTREAMS`, to give each fronted hostname its own discovered set | required if `PASSWAY_UPSTREAM_SOURCE=yubaba` |
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
//! ## Per-host DISCOVERY, not just per-host addresses (R844-F20)
//!
//! `PASSWAY_UPSTREAM_SOURCE=yubaba` used to be one flat set adopted as the
//! catch-all, which meant a door fronting several hostnames could not use
//! discovery at all — it had to be *told* its backends statically. That is the
//! literal port pin R844 exists to delete, relocated from a TOML file into an
//! operator's terminal: every time a supervisor allocated a new port, a human
//! had to retype it here. On 2026-09-03 that cost yah.dev four minutes of 503s.
//!
//! `PASSWAY_YUBABA_IDENT` therefore takes the **same `<hostname>=` fan-in
//! grammar** as `PASSWAY_UPSTREAMS`, naming the workload to discover rather
//! than the address to dial:
//!
//! ```text
//! PASSWAY_YUBABA_IDENT=yah.dev=yah-marketing,analytics.yah.dev=yah-analytics
//! ```
//!
//! One polling source per hostname, each filtered to its own workload ident
//! (R844-B6), each round-robined and health-checked independently — the same
//! [`routing::HostRouter`](passway::routing::HostRouter) the static path
//! already fills. A bare `PASSWAY_YUBABA_IDENT=yah-marketing` is still the
//! catch-all, so every existing deployment is unchanged, and `*=yah-marketing`
//! says the same thing on purpose.
//!
//! Two shapes are boot failures rather than guesses. **Mixing** bare and
//! prefixed entries is rejected for the `PASSWAY_UPSTREAMS` reason above.
//! **Repeating** a hostname is rejected too — and this is where the two
//! variables differ: repeating a hostname in `PASSWAY_UPSTREAMS` *adds an
//! address* to its set, but a hostname has exactly one workload behind it, so
//! two idents for it has no meaning that is not a guess.
//!
//! @yah:relay(R853, "R779 outward actions: publish the pingora fork upstream, put the demux on :443 in front of the live origins, and settle the ACME order budget")
//! @yah:at(2026-09-03T06:33:30Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Split out of R779 at its P8 close-out. R779's code is complete and verified; these three are the actions that make it REACH the world, and every one of them is outward-facing (a public PR, a change to live yah.dev origins, a request to a third party) rather than something a session should do unsupervised. They were sitting as @yah:next prose on R779, which would have been stripped from source when R779 archived — filed as real tickets so they survive it. Design canon: .yah/docs/working/W267-sovereign-public-ingress.md.")
//!
//! @yah:ticket(R853-T1, "Upstream the seed-listen-fds patch to cloudflare/pingora, then drop the fork pin")
//! @yah:at(2026-09-03T06:33:42Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:blocked_on(operator)
//! @yah:next("THE OPERATOR ACTION: open a PR against cloudflare/pingora main from github.com/yah-ai/pingora branch yah/seed-listen-fds-0.8.1 = 2f52d944c832089bad6bd847b868d5c9f37fb201 (tag 0.8.1 plus the carried patch). Three hunks: `Server::seed_listen_fd(bind, fd)` + `Bootstrap::seed_fd` merged into the same fd table the SCM_RIGHTS upgrade path fills (upgrade wins for the same bind), and `listeners::l4::from_raw_fd` setting the adopted fd non-blocking. That last hunk is NOT cosmetic — a std-bound socket is blocking and tokio's from_std leaves it so, which stalled a worker on the first accept until a test caught it. On main, Bootstrap.listen_fds is already a non-optional ListenFds, so load_fds merges instead of replacing. Carried patch + rationale: oss/passway/patches/pingora-0.8.1-seed-listen-fds.patch and patches/README.md.")
//! @yah:next("THE AGENT HALF, once it merges and a release ships: three things move TOGETHER or the build breaks — oss/passway/Cargo.toml's [patch.crates-io] block (all 14 pingora crates, pinned to the fork rev), oss/passway/crates/passway/Cargo.toml's `default = [\"socket-activation\"]`, and oss/passway/deny.toml's allow-git entry for yah-ai/pingora. The socket-activation feature does not compile against crates.io pingora, by design.")
//! @yah:gotcha("Patching pingora-core ALONE fails confusingly: pingora-error / pingora-http end up duplicated registry-vs-fork and the types stop unifying, giving E0308 everywhere. All 14 pingora crates in the graph must come from the same source. Also: a cold build of oss/passway now REQUIRES network access to github.com/yah-ai/pingora — an offline machine gets a resolution failure, not a compile error. The rev is public, so it is a reachability question, not a permissions one. Recorded in oss/passway/patches/README.md.")

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
use passway::idle::{IdleReaper, IdleTracker};
use passway::proxy::PassProxy;
use passway::redirect;
use passway::routing::{build_host_router, HostKey, CATCH_ALL_LABEL};
use passway::tls::{build_tls_settings, TlsMode};
use passway::upstream::{StaticUpstreams, UpstreamSource};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// The inherited listening socket under the systemd socket-activation
/// convention (`LISTEN_FDS=1`, socket at fd 3), or `None` to bind fresh. If
/// `LISTEN_PID` is set it must name this process — a grandchild must not
/// adopt a socket meant for its parent. Same contract `mesofact-serve` and
/// `passway-demux` speak, and the one kamaji's JIT tier provides (it sets
/// `LISTEN_FDS=1` and deliberately no `LISTEN_PID`).
#[cfg(unix)]
fn socket_activation_fd() -> Option<std::os::unix::io::RawFd> {
    let n_fds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if n_fds < 1 {
        return None;
    }
    if let Ok(pid) = std::env::var("LISTEN_PID") {
        if pid.parse::<u32>().ok() != Some(std::process::id()) {
            return None;
        }
    }
    const SD_LISTEN_FDS_START: std::os::unix::io::RawFd = 3;
    Some(SD_LISTEN_FDS_START)
}

#[cfg(not(unix))]
fn socket_activation_fd() -> Option<i32> {
    None
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

/// Parse `PASSWAY_YUBABA_IDENT` into one workload ident per fronted hostname
/// (R844-F20).
///
/// Same `<hostname>=<value>` fan-in grammar as [`parse_upstream_sets`], and
/// deliberately so: the two variables answer the same question — *which
/// backends serve this hostname* — one by naming addresses and one by naming
/// the workload to discover them from. An operator who has written one should
/// not have to learn a second shape to write the other.
///
/// ```text
/// yah-marketing                                        # catch-all, the pre-F20 form
/// *=yah-marketing                                      # the same, said explicitly
/// yah.dev=yah-marketing,analytics.yah.dev=yah-analytics # per host
/// ```
///
/// Two structural errors, both boot failures rather than warnings. **Mixing**
/// a bare entry with keyed ones is the [`parse_upstream_sets`] rule for the
/// same reason: the only reading is an accidental catch-all, and a catch-all
/// on a multi-tenant door serves one tenant's traffic from another's backends.
/// **Repeating** a hostname is an error here where the address parser merges,
/// because a hostname has exactly one workload behind it — merging two idents
/// would silently pick one, and picking one is the guess this relay exists to
/// remove.
fn parse_ident_sets(raw: &str) -> Result<Vec<(HostKey, String)>, String> {
    let mut sets: BTreeMap<HostKey, String> = BTreeMap::new();
    let mut bare: Vec<&str> = Vec::new();
    let mut keyed: Vec<&str> = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (key, ident) = match entry.split_once('=') {
            Some((host, ident)) => {
                let host = host.trim();
                if host == CATCH_ALL_LABEL {
                    (HostKey::CatchAll, ident.trim())
                } else if host.is_empty() {
                    return Err(format!(
                        "PASSWAY_YUBABA_IDENT entry {entry:?} has an empty hostname"
                    ));
                } else {
                    keyed.push(host);
                    (HostKey::Host(host.to_string()), ident.trim())
                }
            }
            None => {
                bare.push(entry);
                (HostKey::CatchAll, entry)
            }
        };
        if ident.is_empty() {
            return Err(format!(
                "PASSWAY_YUBABA_IDENT entry {entry:?} names no workload ident. An empty ident \
                 would adopt every Ready record on the polled node (R844-B6)."
            ));
        }
        if let Some(prior) = sets.insert(key.clone(), ident.to_string()) {
            return Err(format!(
                "PASSWAY_YUBABA_IDENT names {key:?} twice, as {prior:?} and {ident:?}. A \
                 hostname is fronted by exactly one workload; two idents for it has no \
                 meaning that is not a guess."
            ));
        }
    }

    if !bare.is_empty() && !keyed.is_empty() {
        return Err(format!(
            "PASSWAY_YUBABA_IDENT mixes unprefixed entries ({bare:?}) with host-prefixed ones \
             ({keyed:?}). An unprefixed entry means \"discover every hostname's backends from \
             this workload\", which on a host-routed front door is a catch-all — write it as \
             \"*=<ident>\" if that is what you meant, or give it a hostname prefix."
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
            // Required, not defaulted: an unset ident would make this proxy
            // adopt every Ready record on the polled node (R844-B6), which is
            // the failure a default would hide. Loud at boot, same as a
            // missing URL.
            let raw = std::env::var("PASSWAY_YUBABA_IDENT")
                .expect("PASSWAY_YUBABA_IDENT is required with PASSWAY_UPSTREAM_SOURCE=yubaba");
            let sets = parse_ident_sets(&raw)
                .unwrap_or_else(|e| panic!("invalid PASSWAY_YUBABA_IDENT: {e}"));
            if sets.is_empty() {
                panic!(
                    "PASSWAY_YUBABA_IDENT is set but names no workload — see \
                     PASSWAY_UPSTREAM_SOURCE=yubaba in this binary's module docs"
                );
            }
            // R844-F20: one discovery source PER FRONTED HOSTNAME, not one flat
            // set adopted as the catch-all. That flat shape is why a door
            // fronting several hostnames could not use discovery at all and had
            // to be TOLD its backends statically — which is the literal port pin
            // R844 exists to delete, relocated from a TOML file into an
            // operator's terminal.
            sets.into_iter()
                .map(|(key, ident)| {
                    let config = YubabaDiscoveryConfig {
                        base_url: base_url.clone(),
                        ident,
                        timeout: env_secs("PASSWAY_YUBABA_TIMEOUT_SECS", 5),
                    };
                    log::info!(
                        "upstream discovery for {key:?}: polling {} for records of ident {:?} \
                         every PASSWAY_UPDATE_INTERVAL_SECS",
                        config.url(),
                        config.ident
                    );
                    (
                        key,
                        Arc::new(YubabaUpstreams::new(&config)) as Arc<dyn UpstreamSource>,
                    )
                })
                .collect()
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

    // R330-F37: a grey (DNS-only) apex has no edge answering port 80, and
    // every install one-liner this project documents is scheme-less — curl
    // reads `yah.dev/install.sh` as `http://` and gets a refused connection
    // while HTTPS keeps returning 200. Opt-in, because `crate::acme`'s
    // HTTP-01 responder defaults to the same port and must win it when it is
    // in use; see `crate::redirect`.
    let redirect_bind = redirect::parse_redirect_bind(|k| std::env::var(k).ok())
        .unwrap_or_else(|e| panic!("invalid HTTP-redirect configuration: {e}"));
    if let (Some(bind), Some(acme)) = (redirect_bind, acme_config.as_ref()) {
        if matches!(acme.challenge, acme::AcmeChallengeKind::Http01)
            && redirect::redirect_conflicts_with_acme(bind, acme.http01_bind)
        {
            panic!(
                "{} is {bind} but PASSWAY_ACME_CHALLENGE=http-01 needs {} for validation — two \
                 listeners on one address is a race whose loser is a silently failed renewal. \
                 Move one of them, or switch to PASSWAY_ACME_CHALLENGE=dns-01 (which validates \
                 at the DNS provider and leaves port 80 free).",
                redirect::REDIRECT_BIND_ENV,
                acme.http01_bind,
            );
        }
    }

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
        // R779: bound the bootstrap at certmagic's 180 s handshake budget.
        // Under kamaji's JIT the first client is waiting in the kernel
        // accept queue for this to finish; a timeout is recorded as a
        // failure so the backoff marker stops a re-fork loop from
        // re-ordering immediately (see acme.rs "Issuance failure backoff").
        let bootstrap_timeout = env_secs("PASSWAY_ACME_BOOTSTRAP_TIMEOUT_SECS", 180);
        let outcome = bootstrap_rt.block_on(async {
            tokio::time::timeout(bootstrap_timeout, acme::ensure_cert_on_disk(config)).await
        });
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!(
                "initial ACME certificate issuance failed: {e} — check PASSWAY_ACME_* env vars and that port 80 is reachable from the public internet for HTTP-01 validation"
            ),
            Err(_elapsed) => {
                acme::record_issuance_failure(config, std::time::SystemTime::now());
                panic!(
                    "initial ACME certificate issuance did not finish within {}s (PASSWAY_ACME_BOOTSTRAP_TIMEOUT_SECS)",
                    bootstrap_timeout.as_secs()
                );
            }
        }
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
    // ONE worker thread per service, pinned deliberately (R777). This is
    // pingora 0.8.1's own default (`ServerConf::default()` -> `threads: 1`,
    // `pingora-core/src/server/configuration/mod.rs:137`), so today the line
    // changes nothing — it is here because inheriting it is not safe enough.
    //
    // Two reasons it must be stated rather than inherited:
    //
    // 1. `Cargo.toml` requires `pingora = ">=0.8.1"`, an *unbounded* range. A
    //    future release is free to change this default, and because the count
    //    is per-service-per-process it would multiply across every passway on
    //    the fleet at once, silently.
    // 2. Per-tenant deployment (W267 §"One listener, one cert") makes the
    //    per-process footprint a per-tenant cost. Measured 2026-08-15 on the
    //    live fleet: 9.8 MB RSS on us-south-001 (1 core, 961 MB box) and
    //    13.2 MB on us-east-001 (6 cores) — flat across core count precisely
    //    BECAUSE this is 1 and not `nproc`. That flatness is the property
    //    that makes one-process-per-tenant affordable.
    //
    // Raising it is a legitimate throughput decision, not a forbidden one —
    // but it is an N-tenants-wide decision, so make it on purpose and
    // re-measure. pingora's work-stealing runtime means 1 thread is not 1
    // connection at a time.
    conf.threads = 1;
    conf.pid_file = env_or("PASSWAY_PID_FILE", &conf.pid_file);
    conf.upgrade_sock = env_or("PASSWAY_UPGRADE_SOCK", &conf.upgrade_sock);
    let opt = Opt {
        upgrade: env_or("PASSWAY_UPGRADE", "false") == "true",
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(opt), conf);
    // R779: socket activation. When a supervisor (kamaji's on-demand JIT
    // tier, or a systemd .socket unit) hands us an already-listening socket
    // as fd 3 under the LISTEN_FDS convention, seed it for the TLS listener
    // so pingora accepts on it instead of binding `PASSWAY_LISTEN` fresh.
    // The bind string must match exactly — that is the key pingora looks up.
    if let Some(fd) = socket_activation_fd() {
        #[cfg(feature = "socket-activation")]
        {
            log::info!("passway: adopting inherited LISTEN_FDS socket (fd {fd}) for {listen}");
            server.seed_listen_fd(listen.as_str(), fd);
        }
        // Fail loudly rather than bind fresh: a supervisor that handed us a
        // socket expects us to accept on it, and a second listener on the
        // same address would either EADDRINUSE or silently split traffic.
        #[cfg(not(feature = "socket-activation"))]
        panic!(
            "LISTEN_FDS is set (fd {fd}) but this passway was built without the `socket-activation` feature — see crates/passway/Cargo.toml [features]"
        );
    }
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

    // R779: idle self-reap for the kamaji JIT tier. Unset = never exit on
    // idle (a standalone passway must stay up).
    let mut idle_reaper = None;
    if let Ok(v) = std::env::var("PASSWAY_IDLE_TTL_SECS") {
        let ttl = Duration::from_secs(
            v.parse()
                .expect("PASSWAY_IDLE_TTL_SECS must be an integer number of seconds"),
        );
        let tracker = Arc::new(IdleTracker::new());
        proxy = proxy.with_idle_tracker(tracker.clone());
        idle_reaper = Some(background_service("passway idle reaper", IdleReaper::new(tracker, ttl)));
        log::info!("passway idle self-reap armed: exit after {}s with no requests in flight", ttl.as_secs());
    }

    let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    let tls_settings = build_tls_settings(&tls_mode)
        .expect("failed to build TLS settings — check PASSWAY_TLS_CERT / PASSWAY_TLS_KEY");
    proxy_service.add_tls_with_settings(&listen, None, tls_settings);

    server.add_service(proxy_service);
    for lb_service in lb_services {
        server.add_service(lb_service);
    }
    if let Some(reaper) = idle_reaper {
        server.add_service(reaper);
    }
    if let Some(bind) = redirect_bind {
        let redirect_service =
            background_service("passway http redirect", redirect::HttpRedirectService::new(bind));
        server.add_service(redirect_service);
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

    // ── PASSWAY_YUBABA_IDENT, per host (R844-F20) ────────────────────────────

    /// Every deployment written before F20 keeps working, unchanged, and that
    /// is the property the whole change rests on.
    #[test]
    fn a_bare_ident_is_still_the_catch_all() {
        assert_eq!(
            parse_ident_sets("yah-marketing").unwrap(),
            vec![(HostKey::CatchAll, "yah-marketing".to_string())]
        );
    }

    #[test]
    fn a_star_prefix_says_catch_all_on_purpose() {
        assert_eq!(
            parse_ident_sets("*=yah-marketing").unwrap(),
            parse_ident_sets("yah-marketing").unwrap()
        );
    }

    #[test]
    fn host_prefixes_give_each_hostname_its_own_workload() {
        assert_eq!(
            parse_ident_sets("yah.dev=yah-marketing, analytics.yah.dev=yah-analytics").unwrap(),
            vec![
                (
                    HostKey::Host("analytics.yah.dev".into()),
                    "yah-analytics".to_string()
                ),
                (HostKey::Host("yah.dev".into()), "yah-marketing".to_string()),
            ]
        );
    }

    /// The one place this grammar deliberately differs from
    /// `PASSWAY_UPSTREAMS`, where a repeated hostname ADDS an address. A
    /// hostname has exactly one workload behind it, so two idents for it is
    /// not a set — it is a guess about which one wins.
    #[test]
    fn a_repeated_hostname_is_an_error_rather_than_a_silent_pick() {
        let err = parse_ident_sets("yah.dev=yah-marketing,yah.dev=yah-analytics")
            .expect_err("two idents for one hostname must not be resolved by ordering");
        assert!(err.contains("yah-marketing"), "{err}");
        assert!(err.contains("yah-analytics"), "{err}");
    }

    /// Same rule, and the same reason, as the address parser: an unprefixed
    /// entry alongside prefixed ones reads as "and everything else goes here",
    /// which on a multi-tenant door serves one tenant from another's backends.
    #[test]
    fn mixing_bare_and_prefixed_entries_is_a_boot_failure() {
        let err = parse_ident_sets("yah-marketing,analytics.yah.dev=yah-analytics")
            .expect_err("an accidental catch-all must not be guessed at");
        assert!(err.contains("*=<ident>"), "{err}");
    }

    #[test]
    fn an_empty_ident_is_rejected_because_it_would_adopt_every_record() {
        let err = parse_ident_sets("yah.dev=").expect_err("an empty ident is not a filter");
        assert!(err.contains("R844-B6"), "{err}");
    }

    #[test]
    fn an_empty_hostname_is_rejected_in_the_ident_grammar_too() {
        assert!(parse_ident_sets("=yah-marketing").is_err());
    }

    #[test]
    fn whitespace_and_empty_entries_are_tolerated_like_the_address_grammar() {
        assert_eq!(
            parse_ident_sets(" yah.dev = yah-marketing , , ").unwrap(),
            vec![(HostKey::Host("yah.dev".into()), "yah-marketing".to_string())]
        );
    }
}
