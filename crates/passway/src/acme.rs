//! Automated ACME (Let's Encrypt) certificate issuance + renewal for
//! [`crate::tls::TlsMode::Acme`] (R594-F7, follow-up to R594-F4's
//! bring-your-own-cert `TlsMode::Manual`).
//!
//! @yah:assumes-style: this module builds on `tls.rs`'s `TlsMode` /
//! cert-path shape as shipped by R594-F4, which was still in REVIEW when
//! this was written. If review changes that shape (e.g. the field names on
//! `TlsMode::Manual`), this module adapts to match — nothing here depends
//! on more than "a `cert_path`/`key_path` pair that gets read from disk at
//! `TlsSettings` build time."
//!
//! ## ACME crate choice
//!
//! [`instant-acme`](https://docs.rs/instant-acme) 0.8.5, Apache-2.0
//! (license verified via `cargo info instant-acme` and re-checked by
//! `cargo deny check`, which allow-lists only permissive licenses for this
//! crate). Selected over `rustls-acme` because `rustls-acme` is designed to
//! *own* the TLS accept loop itself (it hands you a `ResolvesServerCert` to
//! install into a listener you run) — useful when you control the accept
//! loop, but pingora's rustls `TlsSettings` has no such hook (see `tls.rs`
//! module doc), so that design center doesn't help here. `instant-acme` is
//! the lower-level piece: it only speaks RFC 8555 to the ACME server and
//! leaves challenge-serving entirely to the caller, which is exactly the
//! shape this module needs (a small standalone HTTP-01 responder — see
//! below). Enabled with `default-features = false, features = ["ring",
//! "hyper-rustls", "rcgen"]`: `ring` (not the crate's own default,
//! `aws-lc-rs`) is chosen to match the `ring` provider `pingora-rustls`
//! already installs at runtime
//! (`pingora-core-0.8.1/src/listeners/tls/rustls/mod.rs`'s
//! `install_default_crypto_provider()`), so this crate's own dependency
//! declaration doesn't add a *second* reason to need `aws-lc-rs`. Note
//! this doesn't make `aws-lc-rs` disappear from the build: `pingora-rustls`
//! 0.8.1's own Cargo.toml depends on `rustls` without disabling default
//! features (`features = ["ring"]`, no `default-features = false`), so
//! `rustls`'s own default feature set — which includes `aws_lc_rs` — is
//! already compiled in via plain `pingora` regardless of anything in this
//! module (confirmed by rebuilding with `instant-acme` removed: `aws-lc-rs`
//! still resolves, solely through `pingora-rustls`). That's upstream
//! pingora's dependency hygiene, not something this ticket introduces or
//! can fix from here. `hyper-rustls` gives `instant-acme` its built-in
//! HTTPS client for talking to the ACME directory (over rustls, never
//! native-tls/openssl); `rcgen` lets `Order::finalize()` generate the
//! end-entity keypair + CSR for us so this module never hand-rolls X.509.
//!
//! ## Challenge type: HTTP-01, not TLS-ALPN-01
//!
//! The ticket's design guidance called TLS-ALPN-01 "cleanest for an edge
//! TLS proxy" — true in general, but not reachable here. TLS-ALPN-01
//! validation is a TLS handshake on the **same port** (443) the real
//! listener uses, where the server must present a special self-signed
//! certificate carrying the challenge, selected by ALPN protocol
//! (`acme-tls/1`) rather than a static config. That requires exactly the
//! per-connection dynamic cert selection `tls.rs`'s module doc explains
//! pingora's rustls `TlsSettings` cannot do — not just "awkward for
//! renewal," genuinely infeasible without a second listener contending for
//! port 443, which is worse than the reload problem this ticket already
//! solved another way. It would technically work for the very first
//! issuance (nothing is listening on 443 yet at that point), but it cannot
//! work for any *renewal*, because by then the production TLS listener
//! already owns port 443 with a fixed cert and passway must not touch it.
//!
//! HTTP-01 instead validates against a plain HTTP listener on its own port
//! (80 by default, `PASSWAY_ACME_HTTP01_BIND`), fully decoupled from the
//! TLS listener and its static-cert model. That listener can simply stay
//! up for the entire process lifetime (see [`AcmeRenewalService`]), so
//! first issuance and every renewal use the exact same mechanism with no
//! special-casing and zero contention with the production listener. Not
//! just simpler to wire — it's the only one of the two that composes with
//! pingora's TLS story at all once renewals are in scope.
//!
//! ## The reload gap: graceful-upgrade, documented as a supervisor contract
//!
//! See `tls.rs`'s module doc for the full reasoning (mirrored from here so
//! it isn't duplicated): this module writes a renewed cert+key to disk and
//! logs clearly that a restart is needed; it does **not** send itself
//! `SIGQUIT` or exec a replacement. `main.rs` wires `PASSWAY_PID_FILE` /
//! `PASSWAY_UPGRADE_SOCK` / `PASSWAY_UPGRADE` so the standard pingora
//! hot-upgrade dance (new process started with `PASSWAY_UPGRADE=true`,
//! then `SIGQUIT` sent to the old pid once the new one is up) is actually
//! invokable by whatever supervises this process — kamaji, for an
//! `ingress` workload.
//!
//! ## Module shape
//!
//! - [`AcmeDirectory`] / [`AcmeConfig`] — configuration, parsed from env by
//!   [`parse_acme_config`] (a pure function over a `key -> value` lookup,
//!   not `std::env` directly, so it's unit-testable without racing on
//!   real process env vars).
//! - [`ensure_cert_on_disk`] — the first-boot path: skips network
//!   entirely if a fresh-enough cert already sits on disk (e.g. a
//!   restart with a persistent volume), else blocks on one issuance
//!   using a transient HTTP-01 responder.
//! - [`AcmeRenewalService`] — the steady-state pingora
//!   `BackgroundService`: keeps the HTTP-01 responder bound for the
//!   process lifetime and wakes every `check_interval` to renew if due.
//!   A renewal failure is logged and retried next tick — it never panics
//!   or otherwise disturbs the already-running proxy, which keeps serving
//!   the still-valid (if aging) cert on disk. This mirrors the crate's
//!   existing fail-ready posture (R594-F6's cold-start gotcha) rather than
//!   fail-crash.
//! - [`is_renewal_due`] — the pure renewal-due decision (cert age vs.
//!   lifetime vs. renew-before margin), factored out from any I/O so it's
//!   directly unit-testable.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// Shared `token -> key_authorization` map the HTTP-01 responder answers
/// challenge requests from. Populated just before `set_ready()` on each
/// challenge and drained again right after (successful or not) — see
/// [`issue`].
type ChallengeTokens = Arc<RwLock<HashMap<String, String>>>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Which ACME directory to issue against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeDirectory {
    /// Real Let's Encrypt production directory. Subject to LE's production
    /// rate limits — use [`AcmeDirectory::Staging`] while iterating on a
    /// new deployment.
    Production,
    /// Let's Encrypt staging directory: issues real (but untrusted by
    /// default) certs with much higher rate limits. The default — an
    /// operator must opt into `production` explicitly.
    Staging,
    /// Any RFC-8555 ACME directory URL — Pebble / step-ca for integration
    /// tests, or a private CA.
    Custom(String),
}

impl AcmeDirectory {
    /// The directory URL this variant resolves to.
    pub fn url(&self) -> String {
        match self {
            AcmeDirectory::Production => LetsEncrypt::Production.url().to_string(),
            AcmeDirectory::Staging => LetsEncrypt::Staging.url().to_string(),
            AcmeDirectory::Custom(url) => url.clone(),
        }
    }

    /// Parse the `PASSWAY_ACME_DIRECTORY` env value: `"production"`,
    /// `"staging"`, or any other value taken as a literal directory URL.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "production" => AcmeDirectory::Production,
            "staging" => AcmeDirectory::Staging,
            other => AcmeDirectory::Custom(other.to_string()),
        }
    }
}

/// Configuration for [`crate::tls::TlsMode::Acme`] — everything the
/// issuance/renewal machinery needs. Built by [`parse_acme_config`].
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// The domain the cert is issued for. v0: a single domain (no SAN
    /// list) — passway fronts one hostname per deployment; extend to
    /// `Vec<String>` if a future ticket needs multi-SAN.
    pub domain: String,
    /// Contact email for the ACME account (`mailto:` prefix added
    /// automatically).
    pub contact_email: String,
    /// Which ACME directory to issue against.
    pub directory: AcmeDirectory,
    /// Where the issued PEM cert chain is written — the same path
    /// `TlsMode::Manual` (and thus `build_tls_settings`) reads.
    pub cert_path: String,
    /// Where the issued PEM private key is written.
    pub key_path: String,
    /// Where the ACME account credentials (JSON, includes the account's
    /// private key) are cached across restarts, so this process doesn't
    /// register a fresh account on every boot. Should be on a persistent
    /// volume in production.
    pub account_cache_path: String,
    /// Address the HTTP-01 challenge responder binds. Must be reachable
    /// as `http://<domain>/.well-known/acme-challenge/...` from the
    /// public internet — typically `0.0.0.0:80`.
    pub http01_bind: SocketAddr,
    /// Renew when the current cert's age is within this long of
    /// `cert_lifetime`. Default 30 days — LE/ZeroSSL certs are valid ~90
    /// days, so this gives a wide retry window before actual expiry.
    pub renew_before: Duration,
    /// How often the background loop wakes to check whether renewal is
    /// due. Default 12h — cheap to check (one `stat(2)`), no need for a
    /// tighter loop.
    pub check_interval: Duration,
    /// Assumed validity duration of an issued cert, used only to compute
    /// renewal-due (this module never parses the X.509 `notAfter` field —
    /// it uses the cert file's own mtime as "issued_at" instead, see
    /// [`is_renewal_due`]). Default 90 days, the current LE/ZeroSSL
    /// standard; override for a custom directory with a different
    /// lifetime.
    pub cert_lifetime: Duration,
}

/// Build an [`AcmeConfig`] from a `key -> value` lookup, or `None` if this
/// deployment isn't using ACME at all (`PASSWAY_TLS_MODE` isn't `"acme"` —
/// stays on `TlsMode::Manual`).
///
/// Takes a lookup closure rather than reading `std::env` directly so this
/// is a pure function callers can unit test against a fixed map — reading
/// real process env vars from `cargo test`'s parallel harness would
/// otherwise race across tests.
pub fn parse_acme_config(
    get: impl Fn(&str) -> Option<String>,
    cert_path: String,
    key_path: String,
) -> Result<Option<AcmeConfig>, String> {
    if get("PASSWAY_TLS_MODE").as_deref() != Some("acme") {
        return Ok(None);
    }

    let domain = get("PASSWAY_ACME_DOMAIN")
        .ok_or("PASSWAY_ACME_DOMAIN is required when PASSWAY_TLS_MODE=acme")?;
    let contact_email = get("PASSWAY_ACME_CONTACT_EMAIL")
        .ok_or("PASSWAY_ACME_CONTACT_EMAIL is required when PASSWAY_TLS_MODE=acme")?;
    let directory =
        AcmeDirectory::parse(&get("PASSWAY_ACME_DIRECTORY").unwrap_or_else(|| "staging".to_string()));
    let account_cache_path = get("PASSWAY_ACME_ACCOUNT_CACHE")
        .unwrap_or_else(|| format!("{cert_path}.acme-account.json"));
    let http01_bind_raw = get("PASSWAY_ACME_HTTP01_BIND").unwrap_or_else(|| "0.0.0.0:80".to_string());
    let http01_bind: SocketAddr = http01_bind_raw
        .parse()
        .map_err(|e| format!("PASSWAY_ACME_HTTP01_BIND {http01_bind_raw:?}: {e}"))?;
    let renew_before_days = parse_env_u64(&get, "PASSWAY_ACME_RENEW_BEFORE_DAYS", 30)?;
    let check_interval_secs = parse_env_u64(&get, "PASSWAY_ACME_CHECK_INTERVAL_SECS", 43_200)?;
    let cert_lifetime_days = parse_env_u64(&get, "PASSWAY_ACME_CERT_LIFETIME_DAYS", 90)?;

    Ok(Some(AcmeConfig {
        domain,
        contact_email,
        directory,
        cert_path,
        key_path,
        account_cache_path,
        http01_bind,
        renew_before: Duration::from_secs(renew_before_days * 86_400),
        check_interval: Duration::from_secs(check_interval_secs),
        cert_lifetime: Duration::from_secs(cert_lifetime_days * 86_400),
    }))
}

fn parse_env_u64(get: &impl Fn(&str) -> Option<String>, key: &str, default: u64) -> Result<u64, String> {
    match get(key) {
        Some(v) => v.parse::<u64>().map_err(|e| format!("{key} {v:?}: {e}")),
        None => Ok(default),
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from ACME issuance/renewal. Never crosses the trust boundary (no
/// untrusted network input reaches this type — it wraps `instant-acme`'s
/// own error type plus this module's config/IO failures); used only for
/// operator-facing logs and the one first-boot `.expect()` in `main.rs`.
#[derive(Debug)]
pub enum AcmeError {
    Acme(instant_acme::Error),
    Io(io::Error),
    Config(String),
    Authorization(String),
    NoHttp01Challenge,
    OrderNotReady(OrderStatus),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Acme(e) => write!(f, "ACME protocol error: {e}"),
            AcmeError::Io(e) => write!(f, "I/O error: {e}"),
            AcmeError::Config(msg) => write!(f, "{msg}"),
            AcmeError::Authorization(msg) => write!(f, "{msg}"),
            AcmeError::NoHttp01Challenge => {
                write!(f, "ACME server did not offer an HTTP-01 challenge for this identifier")
            }
            AcmeError::OrderNotReady(status) => {
                write!(f, "order did not reach Ready status (got {status:?})")
            }
        }
    }
}

impl std::error::Error for AcmeError {}

impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        AcmeError::Acme(e)
    }
}

impl From<io::Error> for AcmeError {
    fn from(e: io::Error) -> Self {
        AcmeError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Renewal-due decision (pure) + the disk check that feeds it
// ---------------------------------------------------------------------------

/// Pure decision: given a cert `issued_at`, a fixed validity `lifetime`,
/// and a `renew_before` safety margin, is a cert due for renewal at `now`?
pub fn is_renewal_due(issued_at: SystemTime, lifetime: Duration, renew_before: Duration, now: SystemTime) -> bool {
    let expires_at = issued_at.checked_add(lifetime).unwrap_or(issued_at);
    let renew_at = expires_at.checked_sub(renew_before).unwrap_or(issued_at);
    now >= renew_at
}

/// IO wrapper around [`is_renewal_due`]: treats a missing cert (or a cert
/// present without its key) as unconditionally due, and otherwise uses the
/// cert file's own mtime as "issued_at" — this module always atomically
/// (re)writes both files together at issuance time (see
/// [`write_cert_atomic`]), so the mtime is exactly the issuance time; no
/// X.509 parsing needed to answer this question.
fn cert_needs_renewal(config: &AcmeConfig, now: SystemTime) -> io::Result<bool> {
    let cert_meta = match std::fs::metadata(&config.cert_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    if !Path::new(&config.key_path).is_file() {
        return Ok(true);
    }
    let issued_at = cert_meta.modified()?;
    Ok(is_renewal_due(issued_at, config.cert_lifetime, config.renew_before, now))
}

// ---------------------------------------------------------------------------
// Atomic cert/key (and account-credential) writes
// ---------------------------------------------------------------------------

/// Write `contents` to `path` atomically: write to a `.tmp` sibling in the
/// same directory (so the final `rename` is on the same filesystem, hence
/// atomic), `fsync`, then rename over `path`. A reader (this crate's own
/// `tls::build_tls_settings`, or a peer process during a graceful upgrade)
/// never observes a partially-written file.
fn write_file_atomic(path: &Path, contents: &[u8], #[allow(unused_variables)] mode: u32) -> io::Result<()> {
    let tmp_path = tmp_sibling(path);
    {
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(mode);
        }
        let mut file = open_opts.open(&tmp_path)?;
        use std::io::Write;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!("{file_name}.tmp"))
}

/// Write a freshly issued cert chain + private key to the paths
/// `tls::build_tls_settings` reads. Key first (mode `0600`): if the
/// process dies between the two writes, a cert with a missing/stale key
/// is caught by [`cert_needs_renewal`] (it treats a keyless cert as
/// unconditionally due) — the reverse ordering (fresh key, stale cert)
/// would instead silently keep serving an about-to-expire cert until the
/// next check.
fn write_cert_atomic(cert_path: &str, key_path: &str, cert_chain_pem: &str, key_pem: &str) -> io::Result<()> {
    write_file_atomic(Path::new(key_path), key_pem.as_bytes(), 0o600)?;
    write_file_atomic(Path::new(cert_path), cert_chain_pem.as_bytes(), 0o644)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP-01 challenge responder
// ---------------------------------------------------------------------------

/// Extract the ACME HTTP-01 challenge token from a raw HTTP request line
/// (`"GET /.well-known/acme-challenge/<token> HTTP/1.1"`), or `None` if the
/// line isn't a well-formed `GET` against that well-known path. Restricts
/// the token to the base64url alphabet ACME always uses, so a
/// path-traversal-shaped request (`../../etc/passwd`) never reaches the
/// token lookup.
fn parse_challenge_token(request_line: &str) -> Option<&str> {
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let path = parts.next()?;
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    let token = token.split(['?', '#']).next().unwrap_or("");
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    Some(token)
}

async fn serve_http01_conn(stream: TcpStream, tokens: ChallengeTokens) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    // Drain the remaining header lines up to the blank-line terminator.
    // We don't need their contents (no auth, no body on a validation GET)
    // but must consume them so the peer sees a clean close, not a
    // mid-response reset.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let body = match parse_challenge_token(request_line.trim_end()) {
        Some(token) => tokens.read().await.get(token).cloned(),
        None => None,
    };

    let mut stream = reader.into_inner();
    let response = match body {
        Some(key_authorization) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            key_authorization.len(),
            key_authorization
        ),
        None => {
            let body = "not found";
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
        }
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn run_http01_responder(listener: TcpListener, tokens: ChallengeTokens) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let tokens = tokens.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_http01_conn(stream, tokens).await {
                        log::debug!("passway acme: http-01 responder connection error: {e}");
                    }
                });
            }
            Err(e) => log::warn!("passway acme: http-01 responder accept error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ACME account + issuance
// ---------------------------------------------------------------------------

async fn load_or_create_account(config: &AcmeConfig) -> Result<Account, AcmeError> {
    let cache_path = Path::new(&config.account_cache_path);
    if let Ok(existing) = std::fs::read_to_string(cache_path) {
        let credentials: AccountCredentials = serde_json::from_str(&existing).map_err(|e| {
            AcmeError::Config(format!(
                "corrupt ACME account cache at {cache_path:?}: {e} — remove the file to force re-registration"
            ))
        })?;
        return Ok(Account::builder()?.from_credentials(credentials).await?);
    }

    log::info!(
        "passway acme: no cached account at {cache_path:?} — registering a new ACME account for {}",
        config.contact_email
    );
    let contact = format!("mailto:{}", config.contact_email);
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory.url(),
            None,
        )
        .await?;

    let serialized = serde_json::to_string_pretty(&credentials)
        .map_err(|e| AcmeError::Config(format!("failed to serialize new ACME account credentials: {e}")))?;
    write_file_atomic(cache_path, serialized.as_bytes(), 0o600)?;
    Ok(account)
}

/// Run the full RFC-8555 dance for `config.domain`: load or create the
/// ACME account, create an order, complete an HTTP-01 challenge per
/// pending authorization (registering/withdrawing tokens in `tokens`,
/// which the caller's HTTP-01 responder answers from), finalize, and
/// write the resulting cert chain + key to `config.cert_path` /
/// `config.key_path`.
async fn issue(config: &AcmeConfig, tokens: &ChallengeTokens) -> Result<(), AcmeError> {
    let account = load_or_create_account(config).await?;

    let identifiers = [Identifier::Dns(config.domain.clone())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let mut issued_tokens = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(AcmeError::Authorization(format!(
                        "authorization for {} is {other:?}, not pending",
                        config.domain
                    )));
                }
            }

            let mut challenge = authz.challenge(ChallengeType::Http01).ok_or(AcmeError::NoHttp01Challenge)?;
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_string();
            tokens.write().await.insert(token.clone(), key_authorization);
            issued_tokens.push(token);
            challenge.set_ready().await?;
        }
    }

    let ready_result = order.poll_ready(&RetryPolicy::default().timeout(Duration::from_secs(90))).await;

    // The responder only needs to answer during validation; drop the
    // tokens whether or not validation succeeded so a stale token never
    // lingers and answers a later, unrelated challenge.
    {
        let mut guard = tokens.write().await;
        for token in &issued_tokens {
            guard.remove(token);
        }
    }

    let status = ready_result?;
    if status != OrderStatus::Ready {
        return Err(AcmeError::OrderNotReady(status));
    }

    let key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default().timeout(Duration::from_secs(60))).await?;

    write_cert_atomic(&config.cert_path, &config.key_path, &cert_chain_pem, &key_pem)?;
    log::info!(
        "passway acme: issued a new cert for {} from {} (~{:?} validity) — written to {}",
        config.domain,
        config.directory.url(),
        config.cert_lifetime,
        config.cert_path
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// First-boot bootstrap
// ---------------------------------------------------------------------------

/// First-boot entry point: block until a usable cert sits at
/// `config.cert_path`/`config.key_path`. Skips the network entirely if a
/// fresh-enough cert is already there (e.g. a restart with a persistent
/// volume) — otherwise binds a transient HTTP-01 responder and performs
/// one issuance.
///
/// Called from `main.rs` via a dedicated one-shot Tokio runtime, *before*
/// `pingora::server::Server::run_forever()` starts pingora's own runtime —
/// see `tls.rs`'s "First-boot bootstrapping" doc for why that ordering is
/// necessary.
pub async fn ensure_cert_on_disk(config: &AcmeConfig) -> Result<(), AcmeError> {
    if !cert_needs_renewal(config, SystemTime::now())? {
        log::info!(
            "passway acme: existing cert at {} is fresh enough — skipping first-boot issuance",
            config.cert_path
        );
        return Ok(());
    }

    log::warn!(
        "passway acme: no usable cert at {} for domain {} — blocking startup on a first ACME issuance \
         (HTTP-01, directory {})",
        config.cert_path,
        config.domain,
        config.directory.url()
    );
    let tokens: ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
    let listener = TcpListener::bind(config.http01_bind).await.map_err(AcmeError::Io)?;
    let accept_task = tokio::spawn(run_http01_responder(listener, tokens.clone()));
    let result = issue(config, &tokens).await;
    accept_task.abort();
    result
}

// ---------------------------------------------------------------------------
// Steady-state renewal service
// ---------------------------------------------------------------------------

/// The steady-state pingora background service for
/// [`crate::tls::TlsMode::Acme`]: keeps the HTTP-01 responder bound for
/// the process lifetime (renewals reuse it exactly like the first-boot
/// issuance does — see this module's doc for why that decoupling from the
/// TLS listener is the point) and wakes every `check_interval` to renew
/// the cert if it's due.
///
/// Renewal failures are logged and retried on the next tick — they never
/// panic or otherwise affect the already-running proxy, which keeps
/// serving the still-valid (if aging) cert on disk. This mirrors the
/// crate's existing fail-ready posture (R594-F6) rather than fail-crash.
pub struct AcmeRenewalService {
    config: AcmeConfig,
}

impl AcmeRenewalService {
    pub fn new(config: AcmeConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl BackgroundService for AcmeRenewalService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let tokens: ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
        let listener = match TcpListener::bind(self.config.http01_bind).await {
            Ok(listener) => listener,
            Err(e) => {
                log::error!(
                    "passway acme: failed to bind HTTP-01 responder on {} — renewals will fail until this \
                     is fixed (the existing cert keeps serving until it expires): {e}",
                    self.config.http01_bind
                );
                return;
            }
        };
        let responder = tokio::spawn(run_http01_responder(listener, tokens.clone()));

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    responder.abort();
                    return;
                }
                _ = tokio::time::sleep(self.config.check_interval) => {
                    match cert_needs_renewal(&self.config, SystemTime::now()) {
                        Ok(true) => {
                            log::info!("passway acme: cert for {} is due for renewal", self.config.domain);
                            match issue(&self.config, &tokens).await {
                                Ok(()) => log::info!(
                                    "passway acme: renewed cert written to {} — this process keeps serving \
                                     the OLD cert until a graceful-upgrade restart picks up the new files \
                                     (see tls.rs / acme.rs module docs); trigger one now",
                                    self.config.cert_path
                                ),
                                Err(e) => log::error!(
                                    "passway acme: renewal attempt failed, will retry in {:?}: {e}",
                                    self.config.check_interval
                                ),
                            }
                        }
                        Ok(false) => {}
                        Err(e) => {
                            log::warn!("passway acme: could not check cert age at {}: {e}", self.config.cert_path)
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_renewal_due (pure) -----------------------------------------

    #[test]
    fn not_due_when_freshly_issued() {
        let now = SystemTime::now();
        let issued_at = now;
        assert!(!is_renewal_due(issued_at, Duration::from_secs(90 * 86_400), Duration::from_secs(30 * 86_400), now));
    }

    #[test]
    fn not_due_just_outside_the_renew_before_window() {
        let now = SystemTime::now();
        // Issued 59 days ago; 90-day lifetime, 30-day renew-before window
        // opens at day 60 — one day early, should not be due yet.
        let issued_at = now - Duration::from_secs(59 * 86_400);
        assert!(!is_renewal_due(issued_at, Duration::from_secs(90 * 86_400), Duration::from_secs(30 * 86_400), now));
    }

    #[test]
    fn due_inside_the_renew_before_window() {
        let now = SystemTime::now();
        // Issued 61 days ago; the 30-day renew-before window opened at
        // day 60 — one day inside it, should be due.
        let issued_at = now - Duration::from_secs(61 * 86_400);
        assert!(is_renewal_due(issued_at, Duration::from_secs(90 * 86_400), Duration::from_secs(30 * 86_400), now));
    }

    #[test]
    fn due_past_expiry() {
        let now = SystemTime::now();
        let issued_at = now - Duration::from_secs(100 * 86_400);
        assert!(is_renewal_due(issued_at, Duration::from_secs(90 * 86_400), Duration::from_secs(30 * 86_400), now));
    }

    // -- cert_needs_renewal (IO wrapper) --------------------------------

    #[test]
    fn cert_needs_renewal_true_when_files_missing() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    #[test]
    fn cert_needs_renewal_false_for_a_freshly_written_cert_and_key() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        write_cert_atomic(&config.cert_path, &config.key_path, "cert pem", "key pem").unwrap();
        assert!(!cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    #[test]
    fn cert_needs_renewal_true_when_key_is_missing() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        // Write only the cert file, not the key.
        write_file_atomic(Path::new(&config.cert_path), b"cert pem", 0o644).unwrap();
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    #[test]
    fn cert_needs_renewal_true_once_lifetime_and_renew_before_are_both_zero() {
        let dir = tempfile_dir();
        let mut config = test_config(&dir);
        config.cert_lifetime = Duration::ZERO;
        config.renew_before = Duration::ZERO;
        write_cert_atomic(&config.cert_path, &config.key_path, "cert pem", "key pem").unwrap();
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    // -- write_cert_atomic round trip ------------------------------------

    #[test]
    fn write_cert_atomic_round_trips_content() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        write_cert_atomic(&config.cert_path, &config.key_path, "the cert chain", "the private key").unwrap();
        assert_eq!(std::fs::read_to_string(&config.cert_path).unwrap(), "the cert chain");
        assert_eq!(std::fs::read_to_string(&config.key_path).unwrap(), "the private key");
        // No leftover .tmp siblings.
        assert!(!Path::new(&format!("{}.tmp", config.cert_path)).exists());
        assert!(!Path::new(&format!("{}.tmp", config.key_path)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_cert_atomic_sets_restrictive_key_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile_dir();
        let config = test_config(&dir);
        write_cert_atomic(&config.cert_path, &config.key_path, "cert", "key").unwrap();
        let key_mode = std::fs::metadata(&config.key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600);
        let cert_mode = std::fs::metadata(&config.cert_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(cert_mode, 0o644);
    }

    #[test]
    fn write_cert_atomic_overwrites_a_previous_cert() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        write_cert_atomic(&config.cert_path, &config.key_path, "old cert", "old key").unwrap();
        write_cert_atomic(&config.cert_path, &config.key_path, "new cert", "new key").unwrap();
        assert_eq!(std::fs::read_to_string(&config.cert_path).unwrap(), "new cert");
        assert_eq!(std::fs::read_to_string(&config.key_path).unwrap(), "new key");
    }

    // -- parse_challenge_token (pure) ------------------------------------

    #[test]
    fn parses_a_well_formed_http01_request_line() {
        assert_eq!(
            parse_challenge_token("GET /.well-known/acme-challenge/abc123_-XYZ HTTP/1.1"),
            Some("abc123_-XYZ")
        );
    }

    #[test]
    fn rejects_non_get_methods() {
        assert_eq!(parse_challenge_token("POST /.well-known/acme-challenge/abc HTTP/1.1"), None);
    }

    #[test]
    fn rejects_paths_outside_the_well_known_prefix() {
        assert_eq!(parse_challenge_token("GET /etc/passwd HTTP/1.1"), None);
    }

    #[test]
    fn rejects_path_traversal_shaped_tokens() {
        assert_eq!(parse_challenge_token("GET /.well-known/acme-challenge/../../etc/passwd HTTP/1.1"), None);
    }

    #[test]
    fn rejects_an_empty_token() {
        assert_eq!(parse_challenge_token("GET /.well-known/acme-challenge/ HTTP/1.1"), None);
    }

    #[test]
    fn strips_a_query_string_from_the_token() {
        assert_eq!(parse_challenge_token("GET /.well-known/acme-challenge/abc?x=1 HTTP/1.1"), Some("abc"));
    }

    // -- AcmeDirectory::parse --------------------------------------------

    #[test]
    fn directory_parse_recognizes_production_and_staging() {
        assert_eq!(AcmeDirectory::parse("production"), AcmeDirectory::Production);
        assert_eq!(AcmeDirectory::parse("staging"), AcmeDirectory::Staging);
    }

    #[test]
    fn directory_parse_treats_anything_else_as_a_custom_url() {
        assert_eq!(
            AcmeDirectory::parse("https://pebble.example/dir"),
            AcmeDirectory::Custom("https://pebble.example/dir".to_string())
        );
    }

    #[test]
    fn directory_urls_resolve_correctly() {
        assert_eq!(AcmeDirectory::Production.url(), "https://acme-v02.api.letsencrypt.org/directory");
        assert_eq!(AcmeDirectory::Staging.url(), "https://acme-staging-v02.api.letsencrypt.org/directory");
        assert_eq!(AcmeDirectory::Custom("https://example/dir".to_string()).url(), "https://example/dir");
    }

    // -- parse_acme_config (pure config parsing) -------------------------

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn parse_acme_config_returns_none_when_tls_mode_is_not_acme() {
        let env = env_map(&[]);
        let result = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap();
        assert!(result.is_none());

        let env = env_map(&[("PASSWAY_TLS_MODE", "manual")]);
        let result = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_acme_config_requires_domain_and_contact_email() {
        let env = env_map(&[("PASSWAY_TLS_MODE", "acme")]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("PASSWAY_ACME_DOMAIN"));

        let env = env_map(&[("PASSWAY_TLS_MODE", "acme"), ("PASSWAY_ACME_DOMAIN", "example.com")]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("PASSWAY_ACME_CONTACT_EMAIL"));
    }

    #[test]
    fn parse_acme_config_applies_documented_defaults() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
        ]);
        let config = parse_acme_config(|k| env.get(k).cloned(), "/etc/passway/cert.pem".into(), "/etc/passway/key.pem".into())
            .unwrap()
            .expect("acme mode requested");

        assert_eq!(config.domain, "example.com");
        assert_eq!(config.contact_email, "ops@example.com");
        assert_eq!(config.directory, AcmeDirectory::Staging);
        assert_eq!(config.account_cache_path, "/etc/passway/cert.pem.acme-account.json");
        assert_eq!(config.http01_bind, "0.0.0.0:80".parse::<SocketAddr>().unwrap());
        assert_eq!(config.renew_before, Duration::from_secs(30 * 86_400));
        assert_eq!(config.check_interval, Duration::from_secs(43_200));
        assert_eq!(config.cert_lifetime, Duration::from_secs(90 * 86_400));
    }

    #[test]
    fn parse_acme_config_honors_overrides() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
            ("PASSWAY_ACME_DIRECTORY", "production"),
            ("PASSWAY_ACME_ACCOUNT_CACHE", "/var/lib/passway/acme-account.json"),
            ("PASSWAY_ACME_HTTP01_BIND", "127.0.0.1:8080"),
            ("PASSWAY_ACME_RENEW_BEFORE_DAYS", "10"),
            ("PASSWAY_ACME_CHECK_INTERVAL_SECS", "3600"),
            ("PASSWAY_ACME_CERT_LIFETIME_DAYS", "7"),
        ]);
        let config =
            parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap().unwrap();

        assert_eq!(config.directory, AcmeDirectory::Production);
        assert_eq!(config.account_cache_path, "/var/lib/passway/acme-account.json");
        assert_eq!(config.http01_bind, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(config.renew_before, Duration::from_secs(10 * 86_400));
        assert_eq!(config.check_interval, Duration::from_secs(3600));
        assert_eq!(config.cert_lifetime, Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn parse_acme_config_rejects_an_unparsable_bind_address() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
            ("PASSWAY_ACME_HTTP01_BIND", "not-an-address"),
        ]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("PASSWAY_ACME_HTTP01_BIND"));
    }

    // -- test helpers -----------------------------------------------------

    /// A directory unique to this test process+thread, cleaned up on
    /// drop. Avoids a `tempfile` dev-dependency for this crate's small
    /// need: a scratch dir per test.
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempfile_dir() -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "passway-acme-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn test_config(dir: &TempDir) -> AcmeConfig {
        AcmeConfig {
            domain: "example.com".to_string(),
            contact_email: "ops@example.com".to_string(),
            directory: AcmeDirectory::Staging,
            cert_path: dir.0.join("cert.pem").to_string_lossy().into_owned(),
            key_path: dir.0.join("key.pem").to_string_lossy().into_owned(),
            account_cache_path: dir.0.join("account.json").to_string_lossy().into_owned(),
            http01_bind: "127.0.0.1:0".parse().unwrap(),
            renew_before: Duration::from_secs(30 * 86_400),
            check_interval: Duration::from_secs(43_200),
            cert_lifetime: Duration::from_secs(90 * 86_400),
        }
    }
}
