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
//! ## The issuance engine lives in `acme-engine`
//!
//! The provider-agnostic RFC-8555 issuance logic — account registration,
//! HTTP-01/DNS-01 challenge completion, order finalization to an in-memory
//! cert chain + key — was extracted into the sibling [`acme_engine`] crate
//! (R600-F3 / W273) so a second workspace can consume it via a path patch
//! without pulling in pingora. This module is the *deployment shell* over
//! it: env-config parsing ([`parse_acme_config`]), the HTTP-01 responder,
//! the cert-to-disk write ([`write_cert_atomic`]), and the pingora
//! `BackgroundService` renewal loop ([`AcmeRenewalService`]). It builds an
//! [`acme_engine::IssueConfig`] from an [`AcmeConfig`], calls
//! [`acme_engine::issue`], and writes the returned [`acme_engine::Issued`]
//! bytes to disk. See `acme_engine`'s module doc for the `instant-acme`
//! crate-choice rationale (`ring` over `aws-lc-rs` to match the provider
//! `pingora-rustls` installs at runtime; `hyper-rustls` + `rcgen`).
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
//! - [`acme_engine::renewal_decision`] — the pure renewal decision (SAN
//!   coverage first, then cert age vs. lifetime vs. renew-before margin),
//!   factored out from any I/O so it's directly unit-testable; lives in the
//!   engine and is wrapped here by the disk-reading [`cert_needs_renewal`].

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// The engine types that are part of passway's public surface (referenced by
// `pub struct AcmeConfig`'s fields, `ensure_cert_on_disk`'s return type, and
// re-exported from `lib.rs`) are re-exported so `passway::acme::AcmeDirectory`
// etc. keep resolving exactly as before the extraction.
pub use acme_engine::{AcmeChallengeKind, AcmeDirectory, AcmeError};
// Engine internals this shell drives but doesn't re-expose.
use acme_engine::{
    cert_dns_names, renewal_decision, write_file_atomic, CertSans, ChallengeTokens, IssueConfig, RenewalDecision,
};
use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// Configuration for [`crate::tls::TlsMode::Acme`] — everything the
/// issuance/renewal machinery needs. Built by [`parse_acme_config`].
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// The identifiers the cert is issued for (the SAN list). Parsed from
    /// comma-separated `PASSWAY_ACME_DOMAIN`; wildcard entries
    /// (`*.example.com`) require [`AcmeChallengeKind::Dns01Cloudflare`].
    pub domains: Vec<String>,
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
    /// Which challenge type proves control of the identifiers.
    pub challenge: AcmeChallengeKind,
    /// Address the HTTP-01 challenge responder binds. Must be reachable
    /// as `http://<domain>/.well-known/acme-challenge/...` from the
    /// public internet — typically `0.0.0.0:80`. Unused (never bound)
    /// under [`AcmeChallengeKind::Dns01Cloudflare`].
    pub http01_bind: SocketAddr,
    /// How long to wait after publishing a `_acme-challenge` TXT record
    /// before telling the ACME server to validate — covers the provider's
    /// authoritative-edge propagation. Unused under HTTP-01.
    pub dns01_propagation_delay: Duration,
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
    /// [`acme_engine::renewal_decision`]). Default 90 days, the current LE/ZeroSSL
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

    let domains: Vec<String> = get("PASSWAY_ACME_DOMAIN")
        .ok_or("PASSWAY_ACME_DOMAIN is required when PASSWAY_TLS_MODE=acme")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if domains.is_empty() {
        return Err("PASSWAY_ACME_DOMAIN must name at least one domain".to_string());
    }
    let contact_email = get("PASSWAY_ACME_CONTACT_EMAIL")
        .ok_or("PASSWAY_ACME_CONTACT_EMAIL is required when PASSWAY_TLS_MODE=acme")?;

    let challenge = match get("PASSWAY_ACME_CHALLENGE").as_deref().unwrap_or("http-01") {
        "http-01" => AcmeChallengeKind::Http01,
        "dns-01" => AcmeChallengeKind::Dns01Cloudflare {
            token_file: get("PASSWAY_ACME_DNS01_CLOUDFLARE_TOKEN_FILE").ok_or(
                "PASSWAY_ACME_DNS01_CLOUDFLARE_TOKEN_FILE is required when PASSWAY_ACME_CHALLENGE=dns-01",
            )?,
            zone_id: get("PASSWAY_ACME_DNS01_CLOUDFLARE_ZONE_ID").ok_or(
                "PASSWAY_ACME_DNS01_CLOUDFLARE_ZONE_ID is required when PASSWAY_ACME_CHALLENGE=dns-01",
            )?,
            // R779: unset is the ordinary case (we hold the zone named by
            // ZONE_ID). Set it when the identifier's zone belongs to someone
            // else and they have CNAMEd `_acme-challenge.<domain>` into a zone
            // we do hold — see `acme_engine::dns01_record_name`.
            delegate_zone: get("PASSWAY_ACME_DNS01_DELEGATE_ZONE")
                .map(|z| z.trim().to_string())
                .filter(|z| !z.is_empty()),
            // R779-P8: unset is production (the real Cloudflare API). Only a
            // Cloudflare-shaped stand-in — the DNS-01 integration harness —
            // has any reason to set it.
            api_base: get("PASSWAY_ACME_CF_API_BASE")
                .map(|b| b.trim().to_string())
                .filter(|b| !b.is_empty()),
        },
        other => {
            return Err(format!(
                "PASSWAY_ACME_CHALLENGE {other:?}: expected \"http-01\" or \"dns-01\""
            ))
        }
    };
    // Fail at parse time, not mid-order: the ACME server would only offer
    // DNS-01 for a wildcard identifier, so an HTTP-01 deployment can never
    // complete this order.
    if challenge == AcmeChallengeKind::Http01 {
        if let Some(wild) = domains.iter().find(|d| d.starts_with("*.")) {
            return Err(format!(
                "PASSWAY_ACME_DOMAIN {wild:?} is a wildcard, which requires \
                 PASSWAY_ACME_CHALLENGE=dns-01 (RFC 8555 restricts wildcards to DNS-01)"
            ));
        }
    }
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
    let dns01_propagation_secs = parse_env_u64(&get, "PASSWAY_ACME_DNS01_PROPAGATION_SECS", 10)?;

    Ok(Some(AcmeConfig {
        domains,
        contact_email,
        directory,
        cert_path,
        key_path,
        account_cache_path,
        challenge,
        http01_bind,
        dns01_propagation_delay: Duration::from_secs(dns01_propagation_secs),
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
// Renewal-due disk check (wraps the engine's pure decision)
// ---------------------------------------------------------------------------

/// IO wrapper around [`acme_engine::renewal_decision`]: treats a missing cert (or a cert
/// present without its key) as unconditionally due, and otherwise uses the
/// cert file's own mtime as "issued_at" — this module always atomically
/// (re)writes both files together at issuance time (see
/// [`write_cert_atomic`]), so the mtime is exactly the issuance time.
///
/// Age is not the only reason to reissue. The cert on disk is also read for
/// its SAN set ([`acme_engine::cert_dns_names`]) and handed to the engine as
/// [`acme_engine::CertSans::Known`], which compares it against
/// `config.domains`: a cert that does not cover every configured name is due
/// NOW regardless of how fresh it is. Without that, widening `PASSWAY_ACME_DOMAIN` and
/// restarting logs "fresh enough — skipping" and keeps serving the old,
/// narrower cert for up to `cert_lifetime - renew_before` — silently, with
/// the config file reading as though the fix landed (R853-B8, found while
/// fixing the live incident in R853-B7).
///
/// Coverage is checked against what a TLS client would accept, so a
/// `*.yah.dev` SAN satisfies a configured `www.yah.dev`; see
/// [`acme_engine::domains_not_covered`] for the exact rule. An unparseable
/// cert file is due — this process could not serve it either.
///
/// @yah:ticket(R853-B8, "passway decides renewal from cert file mtime alone, so widening PASSWAY_ACME_DOMAIN silently serves the old narrower cert until expiry")
/// @yah:status(review)
/// @yah:at(2026-09-05T08:51:55Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R853)
/// @yah:severity(medium)
/// @yah:next("Watch the interaction with the R779 issuance-failure backoff marker: a config whose SAN set can never be satisfied (e.g. a name redundant with a wildcard, which LE rejects outright) would otherwise turn 'needs renewal' into a re-order loop. The .acme-failed marker already bounds this, but add a test that a coverage-driven renewal respects it.")
/// @yah:verify("Regression test: write a cert whose SAN is [yah.dev] with a fresh mtime, configure domains = [*.yah.dev, yah.dev], assert cert_needs_renewal() == true. Confirm it fails on today's code (it returns false).")
/// @yah:gotcha("FOUND WHILE FIXING R853-B7, 2026-09-05. cert_needs_renewal() reads only fs::metadata(cert_path).modified() and feeds it to is_renewal_due(); it never parses the cert on disk and never compares its SAN set against config.domains. So an operator who widens PASSWAY_ACME_DOMAIN (here: apex-only -> wildcard, to fix www on half the round-robin) and restarts gets 'existing cert is fresh enough - skipping first-boot issuance' and the door keeps serving the OLD, NARROWER cert until the mtime-based renewal window opens - up to 60 days later. The failure is silent and the config file reads as if the fix landed. This is exactly why B7 was fixed by issuing out of band to a scratch path and installing the result, rather than by editing the env and restarting.")
/// @yah:handoff("FIXED. cert_needs_renewal (oss/passway/crates/passway/src/acme.rs) now reads the cert FILE, not just its metadata, and reissues when the SAN set does not cover config.domains — regardless of age. An unparseable cert file is also due (this process could not serve it either). Age remains the second check, unchanged.")
/// @yah:handoff("THE MATCHING LIVES IN THE ENGINE, as two pure public functions beside is_renewal_due (oss/passway/crates/acme-engine/src/lib.rs): cert_dns_names(pem) -> Option<Vec<String>> reads the LEAF's dNSName SANs, normalized (lowercase, trailing root dot trimmed); domains_not_covered(have, wanted) -> Vec<String> returns the uncovered names so the log can name them back to the operator exactly as they wrote them. Coverage follows RFC 6125 as a TLS client applies it: exact match, or a *.example.com SAN covering exactly ONE more label — not the apex, not a.b.example.com, and a wildcard in config needs a wildcard in the cert (a bag of specific SANs does not add up to one). Both sides are normalized inside domains_not_covered rather than trusted; comparing raw strings would re-order a good cert forever over a capital letter, which is how this fix could have become a slow rate-limit burn.")
/// @yah:handoff("cert_dns_names returns None for anything that is not a readable certificate and Some(vec![]) for a cert with no SAN extension — the distinction is load-bearing, since callers treat None as 'reissue'. It deliberately does NOT fall back to the Subject CN: CN-as-hostname is ignored by every current TLS client, so honouring it would report coverage no browser agrees with.")
/// @yah:handoff("DISCOVERED AND FIXED IN PASS, and it is the reason this fix was not safe on its own. The steady-state AcmeRenewalService loop (acme.rs:~737) called issue_and_write DIRECTLY: it never consulted the R779 issuance-backoff marker and never recorded a failure into it. issuance_backoff_remaining had exactly ONE production caller, ensure_cert_on_disk. That was survivable while renewal was driven by age alone (changes at most once per cert lifetime), but this ticket's own @yah:next flagged the consequence: once COVERAGE drives renewal, a config the CA will never satisfy re-orders every check_interval forever, straight into Let's Encrypt's 5-failed-validations/hour/identifier limit. Both paths now go through one new issue_respecting_backoff(config, tokens, now) so a third call site cannot reintroduce the gap, and the refusal message is shared via backoff_refusal() so the two checks cannot drift. A refusal deliberately does NOT record a failure — no order was attempted, and recording one would double the backoff on every tick off failures that never happened (there is a test for exactly that).")
/// @yah:handoff("x509-parser 0.18 moved from dev-dependency to a real dependency of passway-acme. Not a new supply-chain surface: it arrived in this workspace as the R779-P8 Pebble test's dev-dep and was already in the graph. rcgen 0.14 added as an acme-engine dev-dep so the tests assert against a real DER encoding rather than a checked-in fixture that could rot into agreeing with a hand-written blob. cargo deny stays fully green.")
/// @yah:handoff("FIXED THREE PRE-EXISTING TESTS THAT WERE PASSING FOR THE WRONG REASON: cert_needs_renewal_false_for_a_freshly_written_cert_and_key and cert_needs_renewal_true_once_lifetime_and_renew_before_are_both_zero wrote the literal string \"cert pem\" to the cert path. The check that made that acceptable IS the check this bug was. They now write a real self-signed cert covering the configured names, so the age test still tests age.")
/// @yah:verify("MUTATION CONTROL, per this ticket's own verify line. With the coverage branch's `return Ok(true)` removed, exactly ONE test fails — cert_needs_renewal_true_when_the_cert_does_not_cover_a_widened_config (6 passed / 1 failed) — and it is the B8 regression test. Restored and re-run green. So the test has teeth and this is not a test that would pass either way.")
/// @yah:verify("cargo test --manifest-path oss/passway/Cargo.toml --workspace --lib -> passway 130 / passway-acme 24 / passway-demux 19, 0 failed. Was 125 / 15 / 19 before this pass: +5 passway (3 coverage cases, 2 backoff-enforcement async tests) and +9 passway-acme (6 pure-matching, 3 cert_dns_names).")
/// @yah:verify("passway integration, built then run DIRECTLY as oss/passway/target/debug/deps/main-7d74632cfa65bb79 (the camp daemon has no keychain — see R779's P2 gotcha) -> 28 passed / 0 failed.")
/// @yah:verify("cargo clippy --manifest-path oss/passway/Cargo.toml --workspace --all-targets -> exit 0, exactly the 3 pre-existing warnings (auth.rs case-insensitive compare, path.rs Result<_,()>, proxy.rs manual Option::zip). Nothing added.")
/// @yah:verify("cargo deny --manifest-path oss/passway/Cargo.toml check -> advisories ok, bans ok, licenses ok, sources ok, with x509-parser promoted to a real dep.")
/// @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib -> 708 passed / 0 failed. yubaba consumes acme-engine, and the change is purely additive (two new pub fns), so this confirms no downstream break.")
/// @yah:gotcha("SCOPE, STATED LOUDLY: this fixes passway only. The IDENTICAL defect is live in yubaba's fleet issuer — acme_issuer.rs:424-432 decides renewal from the record's updated_at alone, and its domain list is operator-widenable via YUBABA_ACME_EXTRA_DOMAINS. Filed as R853-B9 rather than folded in here, because passway reads its cert off disk while yubaba's is a SEALED SecretRecord, so coverage there costs a KEK unseal per tick — a genuine design fork (three options weighed on the ticket, with a recommendation), not a mechanical port of this change. The engine helpers this ticket added are exactly what B9 needs; it should not rewrite the matching.")
fn cert_needs_renewal(config: &AcmeConfig, now: SystemTime) -> io::Result<bool> {
    let cert_meta = match std::fs::metadata(&config.cert_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    if !Path::new(&config.key_path).is_file() {
        return Ok(true);
    }

    // Reading the file (rather than only its metadata) is the whole point —
    // mtime cannot see a SAN set. The engine puts coverage ahead of age.
    let san_names = cert_dns_names(&std::fs::read_to_string(&config.cert_path)?);
    let decision = renewal_decision(
        san_names.as_deref().map_or(CertSans::Unreadable, CertSans::Known),
        &config.domains,
        cert_meta.modified()?,
        config.cert_lifetime,
        config.renew_before,
        now,
    );

    match &decision {
        RenewalDecision::DueUnreadable => log::warn!(
            "passway acme: cert at {} is not a readable certificate — treating it as due for reissue",
            config.cert_path
        ),
        RenewalDecision::DueForCoverage(missing) => log::warn!(
            "passway acme: cert at {} covers [{}] but the configured domains are [{}] — \
             missing [{}], so it is due for reissue regardless of age",
            config.cert_path,
            san_names.unwrap_or_default().join(", "),
            config.domains.join(", "),
            missing.join(", ")
        ),
        RenewalDecision::DueForAge | RenewalDecision::Fresh => {}
    }

    Ok(decision.is_due())
}

// ---------------------------------------------------------------------------
// Atomic cert/key writes (reusing the engine's atomic-write primitive)
// ---------------------------------------------------------------------------

/// Write a freshly issued cert chain + private key to the paths
/// `tls::build_tls_settings` reads. Key first (mode `0600`): if the
/// process dies between the two writes, a cert with a missing/stale key
/// is caught by [`cert_needs_renewal`] (it treats a keyless cert as
/// unconditionally due) — the reverse ordering (fresh key, stale cert)
/// would instead silently keep serving an about-to-expire cert until the
/// next check.
///
/// The atomic-write primitive itself ([`acme_engine::write_file_atomic`])
/// lives in the engine — the account-cache write needs it too, so both the
/// engine and this cert-to-disk write share the one implementation.
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
// Bridge to the issuance engine
// ---------------------------------------------------------------------------

impl AcmeConfig {
    /// Project the deployment config down to the provider-agnostic
    /// [`IssueConfig`] the engine consumes — the engine reads only the
    /// protocol inputs (domains, contact, directory, account cache,
    /// challenge, DNS-01 propagation delay), never the cert-to-disk paths
    /// or the renewal cadence, which stay this shell's concern.
    fn to_issue_config(&self) -> IssueConfig {
        IssueConfig {
            domains: self.domains.clone(),
            contact_email: self.contact_email.clone(),
            directory: self.directory.clone(),
            account_cache_path: self.account_cache_path.clone(),
            challenge: self.challenge.clone(),
            dns01_propagation_delay: self.dns01_propagation_delay,
            // Public roots only. A private/test directory is an integration
            // -harness concern, not something passway's env surface exposes.
            directory_root_cert: None,
        }
    }
}

/// Issue via [`acme_engine::issue`] and write the returned cert chain + key
/// to `config.cert_path` / `config.key_path`. The engine runs the full
/// RFC-8555 dance (account, order, one challenge per authorization,
/// finalize) and hands back the PEM bytes in memory; this shell owns the
/// cert-to-disk write, so the on-disk shape the TLS listener reads is
/// unchanged from before the engine extraction.
async fn issue_and_write(config: &AcmeConfig, tokens: &ChallengeTokens) -> Result<(), AcmeError> {
    let issued = acme_engine::issue(&config.to_issue_config(), tokens).await?;
    write_cert_atomic(&config.cert_path, &config.key_path, &issued.cert_chain_pem, &issued.key_pem)?;
    log::info!(
        "passway acme: issued a new cert for [{}] from {} (~{:?} validity) — written to {}",
        config.domains.join(", "),
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
    // Checked here as well as inside `issue_respecting_backoff` so a refusal
    // does not first bind the HTTP-01 responder on :80 — that bind can fail
    // for its own reasons and would mask the real, actionable answer.
    if let Some(remaining) = issuance_backoff_remaining(config, SystemTime::now()) {
        return Err(backoff_refusal(config, remaining));
    }

    log::warn!(
        "passway acme: no usable cert at {} for [{}] — blocking startup on a first ACME issuance \
         ({}, directory {})",
        config.cert_path,
        config.domains.join(", "),
        match &config.challenge {
            AcmeChallengeKind::Http01 => "HTTP-01",
            AcmeChallengeKind::Dns01Cloudflare { .. } => "DNS-01 via Cloudflare",
        },
        config.directory.url()
    );
    let tokens: ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
    // DNS-01 validation never connects to this node, so only HTTP-01
    // needs the port-80 responder bound.
    let accept_task = match config.challenge {
        AcmeChallengeKind::Http01 => {
            let listener = TcpListener::bind(config.http01_bind).await.map_err(AcmeError::Io)?;
            Some(tokio::spawn(run_http01_responder(listener, tokens.clone())))
        }
        AcmeChallengeKind::Dns01Cloudflare { .. } => None,
    };
    let result = issue_respecting_backoff(config, &tokens, SystemTime::now()).await;
    if let Some(task) = accept_task {
        task.abort();
    }
    result
}

/// The one place an ACME order is allowed to start: refuse while the failure
/// backoff is unexpired, otherwise issue and record the outcome into the
/// marker.
///
/// Both issuance paths go through here — first-boot ([`ensure_cert_on_disk`])
/// and the steady-state [`AcmeRenewalService`] loop. Until R853-B8 only the
/// first-boot path consulted the marker, so a renewal that could never
/// succeed re-ordered every `check_interval` forever and neither wrote nor
/// respected a backoff. That was survivable only because renewal was driven
/// by age alone, which changes at most once per cert lifetime; making
/// coverage drive it (a config asking for a name the CA will not issue — a
/// name redundant with a wildcard, say) turns the same loop into a steady
/// burn of the CA's 5-failed-validations/hour/identifier budget. The gate and
/// the thing it gates belong in one function so a third call site cannot
/// reintroduce the gap.
///
/// A refusal deliberately does NOT call [`record_issuance_failure`]: no order
/// was attempted, and recording one would double the backoff on every tick,
/// growing it without bound from failures that never happened.
async fn issue_respecting_backoff(
    config: &AcmeConfig,
    tokens: &ChallengeTokens,
    now: SystemTime,
) -> Result<(), AcmeError> {
    if let Some(remaining) = issuance_backoff_remaining(config, now) {
        return Err(backoff_refusal(config, remaining));
    }
    let result = issue_and_write(config, tokens).await;
    match &result {
        Ok(()) => clear_issuance_failure(config),
        Err(_) => record_issuance_failure(config, now),
    }
    result
}

/// The operator-facing refusal message, shared by the pre-flight check in
/// [`ensure_cert_on_disk`] and the enforcing one in
/// [`issue_respecting_backoff`] so the two can never drift apart.
fn backoff_refusal(config: &AcmeConfig, remaining: Duration) -> AcmeError {
    AcmeError::Config(format!(
        "passway acme: a previous issuance for [{}] failed and the backoff has {}s left \
         (marker {}) — not ordering again yet, so a broken DNS record cannot burn the \
         CA's failed-validation budget; delete the marker to force a retry",
        config.domains.join(", "),
        remaining.as_secs(),
        failure_marker_path(config).display()
    ))
}

// ---------------------------------------------------------------------------
// Issuance failure backoff (R779)
// ---------------------------------------------------------------------------
//
// Under kamaji's on-demand JIT tier a passway that fails its first-boot
// issuance exits, kamaji re-forks it on the very next connection, and it
// tries again — as fast as clients arrive, straight into Let's Encrypt's
// 5 authorization failures / hour / identifier. certmagic has no negative
// cache (checked 2026-08-28; it relies on its `ask` gate plus the CA's own
// limit), so this one is ours: a marker file beside the cert records the
// last failure and a backoff that doubles from
// `FAILURE_BACKOFF_INITIAL` up to `FAILURE_BACKOFF_MAX`. A boot that finds
// an unexpired marker refuses to order (`ensure_cert_on_disk` returns
// `Err`, the process exits) and the kernel accept queue on kamaji's held
// socket simply waits for the next fork. Deleting the marker forces a
// retry; a successful issuance clears it.

/// First backoff after a failed issuance.
pub const FAILURE_BACKOFF_INITIAL: Duration = Duration::from_secs(5 * 60);
/// Backoff ceiling. One retry per hour keeps a permanently broken domain
/// at ~24 orders/day against a 5/hour/identifier failure limit.
pub const FAILURE_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);

/// `<cert_path>.acme-failed`.
pub fn failure_marker_path(config: &AcmeConfig) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.acme-failed", config.cert_path))
}

/// Marker contents: `<failed_at_unix_secs> <backoff_secs>`.
fn read_marker(path: &Path) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(path).ok()?;
    let mut it = s.split_whitespace();
    let at = it.next()?.parse().ok()?;
    let backoff = it.next()?.parse().ok()?;
    Some((at, backoff))
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// How much of the current backoff is still to run, or `None` if a new
/// order may be placed. Pure over the marker file and `now`.
pub fn issuance_backoff_remaining(config: &AcmeConfig, now: SystemTime) -> Option<Duration> {
    let (failed_at, backoff) = read_marker(&failure_marker_path(config))?;
    let until = failed_at.saturating_add(backoff);
    let now = unix_secs(now);
    (now < until).then(|| Duration::from_secs(until - now))
}

/// Record a failed issuance: writes the marker with the next backoff
/// (doubling the previous one, capped at [`FAILURE_BACKOFF_MAX`]). Public
/// so `main.rs` can record a *timeout* of the bootstrap the same way.
pub fn record_issuance_failure(config: &AcmeConfig, now: SystemTime) {
    let path = failure_marker_path(config);
    let next = match read_marker(&path) {
        Some((_, prev)) => Duration::from_secs(prev.saturating_mul(2)).min(FAILURE_BACKOFF_MAX),
        None => FAILURE_BACKOFF_INITIAL,
    };
    let body = format!("{} {}\n", unix_secs(now), next.as_secs());
    if let Err(e) = write_file_atomic(&path, body.as_bytes(), 0o644) {
        log::warn!("passway acme: could not write failure marker {}: {e}", path.display());
    } else {
        log::warn!(
            "passway acme: issuance failed; next attempt no sooner than {}s from now (marker {})",
            next.as_secs(),
            path.display()
        );
    }
}

/// A successful issuance forgets the failure history.
pub fn clear_issuance_failure(config: &AcmeConfig) {
    let path = failure_marker_path(config);
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != io::ErrorKind::NotFound {
            log::warn!("passway acme: could not remove failure marker {}: {e}", path.display());
        }
    }
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
        // DNS-01 renewals validate at the DNS provider, not this node —
        // only HTTP-01 keeps the port-80 responder bound for the process
        // lifetime.
        let responder = match self.config.challenge {
            AcmeChallengeKind::Http01 => {
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
                Some(tokio::spawn(run_http01_responder(listener, tokens.clone())))
            }
            AcmeChallengeKind::Dns01Cloudflare { .. } => None,
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if let Some(responder) = responder {
                        responder.abort();
                    }
                    return;
                }
                _ = tokio::time::sleep(self.config.check_interval) => {
                    match cert_needs_renewal(&self.config, SystemTime::now()) {
                        Ok(true) => {
                            log::info!(
                                "passway acme: cert for [{}] is due for renewal",
                                self.config.domains.join(", ")
                            );
                            match issue_respecting_backoff(&self.config, &tokens, SystemTime::now()).await {
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
    use std::path::PathBuf;

    // Note: the pure `is_renewal_due` and `AcmeDirectory` tests moved with
    // their code into the `acme-engine` crate. What remains here covers the
    // deployment shell: the disk-checking renewal wrapper, the cert-to-disk
    // write, the HTTP-01 request parser, and env-config parsing.

    // -- issuance failure backoff (R779) --------------------------------

    #[test]
    fn backoff_absent_then_doubles_then_caps_then_clears() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(issuance_backoff_remaining(&config, t0), None);

        record_issuance_failure(&config, t0);
        assert_eq!(issuance_backoff_remaining(&config, t0), Some(FAILURE_BACKOFF_INITIAL));
        assert_eq!(
            issuance_backoff_remaining(&config, t0 + Duration::from_secs(100)),
            Some(FAILURE_BACKOFF_INITIAL - Duration::from_secs(100))
        );
        assert_eq!(issuance_backoff_remaining(&config, t0 + FAILURE_BACKOFF_INITIAL), None);

        // Second failure doubles; keep failing until the cap holds.
        record_issuance_failure(&config, t0);
        assert_eq!(issuance_backoff_remaining(&config, t0), Some(FAILURE_BACKOFF_INITIAL * 2));
        for _ in 0..10 {
            record_issuance_failure(&config, t0);
        }
        assert_eq!(issuance_backoff_remaining(&config, t0), Some(FAILURE_BACKOFF_MAX));

        clear_issuance_failure(&config);
        assert_eq!(issuance_backoff_remaining(&config, t0), None);
        clear_issuance_failure(&config); // idempotent
    }

    #[test]
    fn corrupt_marker_means_no_backoff() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        std::fs::write(failure_marker_path(&config), "garbage").unwrap();
        assert_eq!(issuance_backoff_remaining(&config, SystemTime::now()), None);
    }

    // -- cert_needs_renewal (IO wrapper) --------------------------------

    #[test]
    fn cert_needs_renewal_true_when_files_missing() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    /// A self-signed cert carrying exactly `names`, so the coverage half of
    /// `cert_needs_renewal` sees a real SAN set instead of a placeholder
    /// string. Before R853-B8 these tests wrote the literal `"cert pem"`,
    /// which is not a certificate at all — the check that made that fine is
    /// the check the bug was.
    fn self_signed_pem(names: &[&str]) -> String {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("self-signed leaf");
        cert.pem()
    }

    /// Write a cert covering `names` plus a key, both fresh.
    fn write_cert_for(config: &AcmeConfig, names: &[&str]) {
        write_cert_atomic(&config.cert_path, &config.key_path, &self_signed_pem(names), "key pem").unwrap();
    }

    #[test]
    fn cert_needs_renewal_false_for_a_freshly_written_cert_and_key() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        write_cert_for(&config, &["example.com"]);
        assert!(!cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    /// R853-B8, the regression this ticket exists for. An operator widens
    /// `PASSWAY_ACME_DOMAIN` from the apex to apex+wildcard and restarts; the
    /// cert on disk has a brand-new mtime, so the age check says "fine".
    /// Before the fix this returned `false` and the door kept serving the
    /// narrow cert for up to 60 days.
    #[test]
    fn cert_needs_renewal_true_when_the_cert_does_not_cover_a_widened_config() {
        let dir = tempfile_dir();
        let mut config = test_config(&dir);
        config.domains = vec!["*.yah.dev".to_string(), "yah.dev".to_string()];
        write_cert_for(&config, &["yah.dev"]);
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    /// The other direction, and the one that would cost real money to get
    /// wrong: a wildcard cert DOES cover a configured subdomain, so a
    /// perfectly good cert must not be re-ordered on every check.
    #[test]
    fn cert_needs_renewal_false_when_a_wildcard_cert_covers_the_configured_names() {
        let dir = tempfile_dir();
        let mut config = test_config(&dir);
        config.domains = vec!["www.yah.dev".to_string(), "yah.dev".to_string()];
        write_cert_for(&config, &["yah.dev", "*.yah.dev"]);
        assert!(!cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    /// A cert path holding something that is not a certificate (a truncated
    /// write, a key written to the wrong path) is due — this process could
    /// not serve it either, so "reissue" is the only useful answer.
    #[test]
    fn cert_needs_renewal_true_when_the_cert_file_is_not_a_certificate() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        write_cert_atomic(&config.cert_path, &config.key_path, "cert pem", "key pem").unwrap();
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
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
        // A cert that DOES cover the config, so the coverage check passes and
        // this still tests the age path it names.
        write_cert_for(&config, &["example.com"]);
        assert!(cert_needs_renewal(&config, SystemTime::now()).unwrap());
    }

    // -- backoff enforcement shared by both issuance paths (R853-B8) ------

    /// The `@yah:next` this ticket carried: once COVERAGE can drive renewal,
    /// a config the CA will never satisfy would re-order every
    /// `check_interval`. Both issuance paths now go through
    /// `issue_respecting_backoff`, so an unexpired marker refuses before any
    /// order — this is the assertion that the renewal loop, which never
    /// consulted the marker at all before R853-B8, now does.
    #[tokio::test]
    async fn a_coverage_driven_renewal_still_respects_the_failure_backoff() {
        let dir = tempfile_dir();
        let mut config = test_config(&dir);
        config.domains = vec!["*.yah.dev".to_string(), "yah.dev".to_string()];
        write_cert_for(&config, &["yah.dev"]);
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // Due for coverage reasons, not age.
        assert!(cert_needs_renewal(&config, t0).unwrap());

        record_issuance_failure(&config, t0);
        let tokens: ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
        let err = issue_respecting_backoff(&config, &tokens, t0)
            .await
            .expect_err("an unexpired marker must refuse to order");
        assert!(
            matches!(&err, AcmeError::Config(msg) if msg.contains("backoff has")),
            "expected the backoff refusal, got: {err}"
        );
    }

    /// A refusal is not a failure: it must not escalate the backoff, or a
    /// loop that ticks faster than `FAILURE_BACKOFF_INITIAL` would double the
    /// wait forever off orders that were never placed.
    #[tokio::test]
    async fn refusing_under_backoff_does_not_escalate_it() {
        let dir = tempfile_dir();
        let config = test_config(&dir);
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        record_issuance_failure(&config, t0);
        assert_eq!(issuance_backoff_remaining(&config, t0), Some(FAILURE_BACKOFF_INITIAL));

        let tokens: ChallengeTokens = Arc::new(RwLock::new(HashMap::new()));
        for _ in 0..5 {
            assert!(issue_respecting_backoff(&config, &tokens, t0).await.is_err());
        }
        assert_eq!(
            issuance_backoff_remaining(&config, t0),
            Some(FAILURE_BACKOFF_INITIAL),
            "a refusal recorded a failure it never attempted"
        );
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

        assert_eq!(config.domains, vec!["example.com".to_string()]);
        assert_eq!(config.contact_email, "ops@example.com");
        assert_eq!(config.directory, AcmeDirectory::Staging);
        assert_eq!(config.account_cache_path, "/etc/passway/cert.pem.acme-account.json");
        assert_eq!(config.challenge, AcmeChallengeKind::Http01);
        assert_eq!(config.http01_bind, "0.0.0.0:80".parse::<SocketAddr>().unwrap());
        assert_eq!(config.dns01_propagation_delay, Duration::from_secs(10));
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
    fn parse_acme_config_splits_a_comma_separated_san_list() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "*.example.com, example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
            ("PASSWAY_ACME_CHALLENGE", "dns-01"),
            ("PASSWAY_ACME_DNS01_CLOUDFLARE_TOKEN_FILE", "/etc/cf-token"),
            ("PASSWAY_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
        ]);
        let config =
            parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap().unwrap();
        assert_eq!(config.domains, vec!["*.example.com".to_string(), "example.com".to_string()]);
        assert_eq!(
            config.challenge,
            AcmeChallengeKind::Dns01Cloudflare {
                token_file: "/etc/cf-token".to_string(),
                zone_id: "zone123".to_string(),
                delegate_zone: None,
                api_base: None,
            }
        );
    }

    #[test]
    fn parse_acme_config_carries_the_dns01_delegate_zone() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "shop.tenant.io"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
            ("PASSWAY_ACME_CHALLENGE", "dns-01"),
            ("PASSWAY_ACME_DNS01_CLOUDFLARE_TOKEN_FILE", "/etc/cf-token"),
            ("PASSWAY_ACME_DNS01_CLOUDFLARE_ZONE_ID", "zone123"),
            ("PASSWAY_ACME_DNS01_DELEGATE_ZONE", " acme.yah.dev "),
        ]);
        let config =
            parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap().unwrap();
        assert_eq!(
            config.challenge,
            AcmeChallengeKind::Dns01Cloudflare {
                token_file: "/etc/cf-token".to_string(),
                zone_id: "zone123".to_string(),
                delegate_zone: Some("acme.yah.dev".to_string()),
                api_base: None,
            },
            "the delegate zone is trimmed and carried through to the engine"
        );
    }

    #[test]
    fn parse_acme_config_rejects_a_wildcard_under_http01() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "*.example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
        ]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("dns-01"), "got: {err}");
    }

    #[test]
    fn parse_acme_config_requires_cloudflare_settings_for_dns01() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
            ("PASSWAY_ACME_CHALLENGE", "dns-01"),
        ]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("PASSWAY_ACME_DNS01_CLOUDFLARE_TOKEN_FILE"), "got: {err}");
    }

    #[test]
    fn parse_acme_config_rejects_an_unknown_challenge_kind() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", "example.com"),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
            ("PASSWAY_ACME_CHALLENGE", "tls-alpn-01"),
        ]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("PASSWAY_ACME_CHALLENGE"), "got: {err}");
    }

    #[test]
    fn parse_acme_config_rejects_an_empty_domain_list() {
        let env = env_map(&[
            ("PASSWAY_TLS_MODE", "acme"),
            ("PASSWAY_ACME_DOMAIN", " , "),
            ("PASSWAY_ACME_CONTACT_EMAIL", "ops@example.com"),
        ]);
        let err = parse_acme_config(|k| env.get(k).cloned(), "cert.pem".into(), "key.pem".into()).unwrap_err();
        assert!(err.contains("at least one domain"), "got: {err}");
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
            domains: vec!["example.com".to_string()],
            contact_email: "ops@example.com".to_string(),
            directory: AcmeDirectory::Staging,
            cert_path: dir.0.join("cert.pem").to_string_lossy().into_owned(),
            key_path: dir.0.join("key.pem").to_string_lossy().into_owned(),
            account_cache_path: dir.0.join("account.json").to_string_lossy().into_owned(),
            challenge: AcmeChallengeKind::Http01,
            http01_bind: "127.0.0.1:0".parse().unwrap(),
            dns01_propagation_delay: Duration::from_secs(10),
            renew_before: Duration::from_secs(30 * 86_400),
            check_interval: Duration::from_secs(43_200),
            cert_lifetime: Duration::from_secs(90 * 86_400),
        }
    }
}
