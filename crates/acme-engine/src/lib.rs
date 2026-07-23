//! Provider-agnostic ACME (RFC-8555 / Let's Encrypt) certificate issuance
//! engine — the one home for the issuance logic, extracted from passway's
//! `acme.rs` (R600-F3 / W273) so a second workspace can consume it via a
//! path patch without dragging in passway's pingora deployment shell.
//!
//! This crate speaks the protocol and hands back an in-memory cert chain +
//! key ([`Issued`]); it never writes a cert to disk and never binds a
//! listener. The caller ([`issue`]'s caller) owns deployment: it runs the
//! HTTP-01 responder that answers from the shared [`ChallengeTokens`] map,
//! and it decides where the resulting [`Issued`] bytes go. The only disk
//! I/O this engine does is caching the ACME *account* credentials (see
//! [`load_or_create_account`]) so a process doesn't register a fresh
//! account on every boot.
//!
//! ## ACME crate choice
//!
//! [`instant-acme`](https://docs.rs/instant-acme) 0.8.5, Apache-2.0
//! (license verified via `cargo info instant-acme` and re-checked by
//! `cargo deny check`, which allow-lists only permissive licenses). Chosen
//! as the lower-level piece over `rustls-acme`: `rustls-acme` is designed to
//! *own* the TLS accept loop (it hands you a `ResolvesServerCert` to install
//! into a listener you run), whereas `instant-acme` only speaks RFC 8555 to
//! the ACME server and leaves challenge-serving entirely to the caller —
//! exactly the shape an issuance engine needs. Enabled with
//! `default-features = false, features = ["ring", "hyper-rustls",
//! "rcgen"]`: `ring` (not the crate's own default, `aws-lc-rs`) matches the
//! `ring` provider an edge like passway installs into `pingora-rustls` at
//! runtime, so this crate's dependency declaration doesn't add a *second*
//! reason to need `aws-lc-rs`; `hyper-rustls` gives `instant-acme` its
//! built-in HTTPS client (over rustls, never native-tls/openssl); `rcgen`
//! lets `Order::finalize()` generate the end-entity keypair + CSR so this
//! engine never hand-rolls X.509.
//!
//! ## Challenge types
//!
//! - HTTP-01 ([`AcmeChallengeKind::Http01`]): the engine registers each
//!   `token -> key_authorization` in the shared [`ChallengeTokens`] map just
//!   before `set_ready()` and drains it again right after (success or not);
//!   the caller's own HTTP responder answers
//!   `/.well-known/acme-challenge/<token>` from that map. Cannot issue
//!   wildcard identifiers (RFC 8555 §7.1.3 restricts wildcards to DNS-01).
//! - DNS-01 via Cloudflare ([`AcmeChallengeKind::Dns01Cloudflare`]): the
//!   engine publishes/removes `_acme-challenge.<domain>` TXT records via the
//!   Cloudflare API. Required for wildcards; also the only challenge a
//!   standby node (not holding the public identity) can renew with, since
//!   validation never touches the node.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tokio::sync::RwLock;

/// Shared `token -> key_authorization` map the caller's HTTP-01 responder
/// answers challenge requests from. Populated just before `set_ready()` on
/// each challenge and drained again right after (successful or not) — see
/// [`issue`].
pub type ChallengeTokens = Arc<RwLock<HashMap<String, String>>>;

// ---------------------------------------------------------------------------
// Directory + challenge configuration
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

/// How this deployment proves control of its identifiers to the ACME
/// server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeChallengeKind {
    /// HTTP-01: answer `/.well-known/acme-challenge/<token>` on port 80.
    /// Zero external dependencies, but cannot issue wildcard identifiers
    /// (RFC 8555 §7.1.3 restricts wildcards to DNS-01) and every renewal
    /// requires the public internet to reach *this* node on port 80.
    Http01,
    /// DNS-01 via the Cloudflare API: publish `_acme-challenge.<domain>`
    /// TXT records for validation. Required for wildcards; also the only
    /// challenge a standby node (not currently holding the public
    /// identity) can renew with, since validation never touches the node.
    Dns01Cloudflare {
        /// Path to a file holding the Cloudflare API token (needs
        /// `DNS:Edit` on the zone). A file rather than an env var so the
        /// secret doesn't leak via `/proc/<pid>/environ` or
        /// `systemctl show-environment`.
        token_file: String,
        /// The Cloudflare zone ID the `_acme-challenge.*` records are
        /// created in. Explicit (not looked up by name) so the token can
        /// be scoped without `Zone:Read`.
        zone_id: String,
    },
}

/// The provider-agnostic input to [`issue`]: everything the RFC-8555 dance
/// needs, with no reference to where the resulting cert lands on disk — the
/// caller owns that. Built by the deployment shell (e.g. passway's
/// `AcmeConfig`) from its own richer config.
#[derive(Debug, Clone)]
pub struct IssueConfig {
    /// The identifiers the cert is issued for (the SAN list). Wildcard
    /// entries (`*.example.com`) require [`AcmeChallengeKind::Dns01Cloudflare`].
    pub domains: Vec<String>,
    /// Contact email for the ACME account (`mailto:` prefix added
    /// automatically).
    pub contact_email: String,
    /// Which ACME directory to issue against.
    pub directory: AcmeDirectory,
    /// Where the ACME account credentials (JSON, includes the account's
    /// private key) are cached across restarts, so this process doesn't
    /// register a fresh account on every boot. Should be on a persistent
    /// volume in production.
    pub account_cache_path: String,
    /// Which challenge type proves control of the identifiers.
    pub challenge: AcmeChallengeKind,
    /// How long to wait after publishing a `_acme-challenge` TXT record
    /// before telling the ACME server to validate — covers the provider's
    /// authoritative-edge propagation. Unused under HTTP-01.
    pub dns01_propagation_delay: Duration,
}

/// A freshly issued cert chain + private key, in memory. The caller decides
/// where these bytes go (passway writes them atomically to the paths its
/// TLS listener reads).
pub struct Issued {
    /// The PEM-encoded certificate chain.
    pub cert_chain_pem: String,
    /// The PEM-encoded private key.
    pub key_pem: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from ACME issuance/renewal. Never crosses the trust boundary (no
/// untrusted network input reaches this type — it wraps `instant-acme`'s
/// own error type plus this engine's config/IO failures); used only for
/// operator-facing logs and the caller's first-boot bootstrap.
#[derive(Debug)]
pub enum AcmeError {
    Acme(instant_acme::Error),
    Io(io::Error),
    Config(String),
    Authorization(String),
    /// The ACME server offered no challenge of the configured type for an
    /// identifier (the `&'static str` names the type, e.g. `"http-01"`).
    NoChallengeOffered(&'static str),
    /// A DNS-01 provider API call failed (record create/delete).
    Dns(String),
    OrderNotReady(OrderStatus),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Acme(e) => write!(f, "ACME protocol error: {e}"),
            AcmeError::Io(e) => write!(f, "I/O error: {e}"),
            AcmeError::Config(msg) => write!(f, "{msg}"),
            AcmeError::Authorization(msg) => write!(f, "{msg}"),
            AcmeError::NoChallengeOffered(kind) => {
                write!(f, "ACME server did not offer a {kind} challenge for this identifier")
            }
            AcmeError::Dns(msg) => write!(f, "DNS-01 provider error: {msg}"),
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
// Renewal-due decision (pure)
// ---------------------------------------------------------------------------

/// Pure decision: given a cert `issued_at`, a fixed validity `lifetime`,
/// and a `renew_before` safety margin, is a cert due for renewal at `now`?
pub fn is_renewal_due(issued_at: SystemTime, lifetime: Duration, renew_before: Duration, now: SystemTime) -> bool {
    let expires_at = issued_at.checked_add(lifetime).unwrap_or(issued_at);
    let renew_at = expires_at.checked_sub(renew_before).unwrap_or(issued_at);
    now >= renew_at
}

// ---------------------------------------------------------------------------
// Atomic file writes (account credentials here; the caller reuses these for
// its own cert-to-disk write)
// ---------------------------------------------------------------------------

/// Write `contents` to `path` atomically: write to a `.tmp` sibling in the
/// same directory (so the final `rename` is on the same filesystem, hence
/// atomic), `fsync`, then rename over `path`. A reader (a TLS-settings
/// builder, or a peer process during a graceful upgrade) never observes a
/// partially-written file.
///
/// `pub` so the deployment shell can reuse the exact same atomic-write
/// primitive for its cert-to-disk write rather than duplicating the logic.
pub fn write_file_atomic(path: &Path, contents: &[u8], #[allow(unused_variables)] mode: u32) -> io::Result<()> {
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

// ---------------------------------------------------------------------------
// DNS-01 via the Cloudflare API
// ---------------------------------------------------------------------------

/// A TXT record created for one authorization, remembered so [`issue`] can
/// delete it again once the order has been validated (or failed).
struct CreatedTxtRecord {
    record_id: String,
    name: String,
}

/// Create a `_acme-challenge` TXT record. Deliberately a bare create, not
/// an upsert: a wildcard + apex order produces two authorizations for the
/// *same* record name (`_acme-challenge.example.com`) whose TXT values must
/// coexist for validation — an upsert would clobber the first.
async fn cloudflare_create_txt(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
    name: &str,
    content: &str,
) -> Result<String, AcmeError> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
    let body = serde_json::json!({
        "type": "TXT",
        "name": name,
        // The TXT value is the base64url SHA-256 digest of the key
        // authorization (RFC 8555 §8.4) — quoted per DNS convention by CF.
        "content": content,
        "ttl": 60,
        "comment": "passway ACME DNS-01 challenge — deleted automatically after validation",
    });
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| AcmeError::Dns(format!("creating TXT {name}: {e}")))?;
    let status = resp.status();
    let parsed: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AcmeError::Dns(format!("creating TXT {name}: non-JSON response: {e}")))?;
    if !status.is_success() || parsed["success"] != serde_json::Value::Bool(true) {
        return Err(AcmeError::Dns(format!(
            "creating TXT {name}: HTTP {status}, errors: {}",
            parsed["errors"]
        )));
    }
    parsed["result"]["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| AcmeError::Dns(format!("creating TXT {name}: response carried no record id")))
}

/// Delete a record created by [`cloudflare_create_txt`]. Best-effort at the
/// call site — a leaked 60s-TTL TXT record is harmless, so failures are
/// logged, never fatal.
async fn cloudflare_delete_record(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
    record_id: &str,
) -> Result<(), AcmeError> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}");
    let resp = client
        .delete(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| AcmeError::Dns(format!("deleting record {record_id}: {e}")))?;
    if !resp.status().is_success() {
        return Err(AcmeError::Dns(format!(
            "deleting record {record_id}: HTTP {}",
            resp.status()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ACME account + issuance
// ---------------------------------------------------------------------------

async fn load_or_create_account(config: &IssueConfig) -> Result<Account, AcmeError> {
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
        "acme-engine: no cached account at {cache_path:?} — registering a new ACME account for {}",
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

/// Run the full RFC-8555 dance for `config.domains`: load or create the
/// ACME account, create an order, complete one challenge of the configured
/// kind per pending authorization — HTTP-01 registers/withdraws tokens in
/// `tokens` (answered by the caller's responder), DNS-01 publishes/removes
/// `_acme-challenge` TXT records via the Cloudflare API — then finalize and
/// return the resulting cert chain + key as [`Issued`]. This engine never
/// touches the cert-to-disk path; the caller decides where the bytes land.
pub async fn issue(config: &IssueConfig, tokens: &ChallengeTokens) -> Result<Issued, AcmeError> {
    let account = load_or_create_account(config).await?;

    let identifiers: Vec<Identifier> =
        config.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    // DNS-01 collateral, resolved once up front. The token lives in a
    // root-readable file, not the environment — see [`AcmeChallengeKind`].
    let dns01 = match &config.challenge {
        AcmeChallengeKind::Http01 => None,
        AcmeChallengeKind::Dns01Cloudflare { token_file, zone_id } => {
            let token = std::fs::read_to_string(token_file)
                .map_err(|e| {
                    AcmeError::Config(format!("reading Cloudflare token file {token_file:?}: {e}"))
                })?
                .trim()
                .to_string();
            Some((reqwest::Client::new(), token, zone_id.clone()))
        }
    };

    let mut issued_tokens = Vec::new();
    let mut created_records: Vec<CreatedTxtRecord> = Vec::new();
    let challenge_result = async {
        match &dns01 {
            None => {
                let mut authorizations = order.authorizations();
                while let Some(result) = authorizations.next().await {
                    let mut authz = result?;
                    match authz.status {
                        AuthorizationStatus::Valid => continue,
                        AuthorizationStatus::Pending => {}
                        other => {
                            return Err(AcmeError::Authorization(format!(
                                "an authorization for this order is {other:?}, not pending"
                            )));
                        }
                    }
                    let mut challenge = authz
                        .challenge(ChallengeType::Http01)
                        .ok_or(AcmeError::NoChallengeOffered("http-01"))?;
                    let token = challenge.token.clone();
                    let key_authorization = challenge.key_authorization().as_str().to_string();
                    tokens.write().await.insert(token.clone(), key_authorization);
                    issued_tokens.push(token);
                    challenge.set_ready().await?;
                }
            }
            Some((client, token, zone_id)) => {
                // Two passes, deliberately: publish EVERY record first,
                // then trigger validations. A wildcard + apex order has
                // two authorizations validating at the *same* record name
                // (`_acme-challenge.<base>`); CAs cache their resolver
                // answers for that name up to the record TTL, so a
                // publish→validate→publish→validate sequence lets the
                // second validation hit a cached answer that predates its
                // TXT value and fail the whole order. With both values
                // published before the first validation query, even a
                // cached answer contains every needed value. (Each
                // `order.authorizations()` call re-fetches, so the second
                // pass sees the same pending set.)
                let mut authorizations = order.authorizations();
                while let Some(result) = authorizations.next().await {
                    let mut authz = result?;
                    match authz.status {
                        AuthorizationStatus::Valid => continue,
                        AuthorizationStatus::Pending => {}
                        other => {
                            return Err(AcmeError::Authorization(format!(
                                "an authorization for this order is {other:?}, not pending"
                            )));
                        }
                    }
                    let challenge = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or(AcmeError::NoChallengeOffered("dns-01"))?;
                    let txt_value = challenge.key_authorization().dns_value();
                    // The record name is built from the *base* identifier:
                    // a wildcard authorization (`*.example.com`) validates
                    // at `_acme-challenge.example.com`, same as the apex.
                    let base = match challenge.identifier().identifier {
                        Identifier::Dns(dns) => dns.clone(),
                        other => {
                            return Err(AcmeError::Authorization(format!(
                                "DNS-01 requires a DNS identifier, got {other:?}"
                            )))
                        }
                    };
                    let name = format!("_acme-challenge.{base}");
                    let record_id =
                        cloudflare_create_txt(client, token, zone_id, &name, &txt_value).await?;
                    log::info!("acme-engine: published TXT {name} for DNS-01 validation");
                    created_records.push(CreatedTxtRecord { record_id, name });
                }

                // One wait for the provider's authoritative edge to serve
                // everything published above — the CA fails a missing-TXT
                // lookup immediately, without retrying.
                tokio::time::sleep(config.dns01_propagation_delay).await;

                let mut authorizations = order.authorizations();
                while let Some(result) = authorizations.next().await {
                    let mut authz = result?;
                    if authz.status != AuthorizationStatus::Pending {
                        continue;
                    }
                    let mut challenge = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or(AcmeError::NoChallengeOffered("dns-01"))?;
                    challenge.set_ready().await?;
                }
            }
        }
        Ok(())
    }
    .await;

    let ready_result = match challenge_result {
        Ok(()) => {
            order
                .poll_ready(&RetryPolicy::default().timeout(Duration::from_secs(180)))
                .await
                .map_err(AcmeError::from)
        }
        Err(e) => Err(e),
    };

    // The responder only needs to answer during validation; drop the
    // tokens whether or not validation succeeded so a stale token never
    // lingers and answers a later, unrelated challenge. Same for the TXT
    // records — best-effort delete, since a leaked 60s-TTL record is
    // harmless while a hard failure here would mask the real result.
    {
        let mut guard = tokens.write().await;
        for token in &issued_tokens {
            guard.remove(token);
        }
    }
    if let Some((client, token, zone_id)) = &dns01 {
        for record in &created_records {
            if let Err(e) = cloudflare_delete_record(client, token, zone_id, &record.record_id).await {
                log::warn!(
                    "acme-engine: failed to clean up TXT {} (record {}) — it has a 60s TTL and \
                     can be deleted manually: {e}",
                    record.name,
                    record.record_id
                );
            }
        }
    }

    let status = ready_result?;
    if status != OrderStatus::Ready {
        // Surface per-authorization failure detail before bailing — the
        // order status alone ("Invalid") tells an operator nothing about
        // *which* identifier failed or what the CA saw.
        let mut authorizations = order.authorizations();
        while let Some(Ok(authz)) = authorizations.next().await {
            for challenge in &authz.challenges {
                if let Some(problem) = &challenge.error {
                    log::error!(
                        "acme-engine: {} challenge for {} failed: {problem:?}",
                        match challenge.r#type {
                            ChallengeType::Http01 => "http-01",
                            ChallengeType::Dns01 => "dns-01",
                            _ => "other",
                        },
                        authz.identifier(),
                    );
                }
            }
        }
        return Err(AcmeError::OrderNotReady(status));
    }

    let key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default().timeout(Duration::from_secs(60))).await?;

    log::info!(
        "acme-engine: issued a new cert for [{}] from {}",
        config.domains.join(", "),
        config.directory.url(),
    );
    Ok(Issued { cert_chain_pem, key_pem })
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

    // -- write_file_atomic round trip -----------------------------------

    #[test]
    fn write_file_atomic_round_trips_and_leaves_no_tmp() {
        let dir = tempfile_dir();
        let path = dir.0.join("creds.json");
        write_file_atomic(&path, b"the contents", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "the contents");
        assert!(!path.with_file_name("creds.json.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_file_atomic_honors_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile_dir();
        let path = dir.0.join("creds.json");
        write_file_atomic(&path, b"secret", 0o600).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
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
            "acme-engine-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}
