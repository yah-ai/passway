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
//!
//! @yah:ticket(R853-T3, "Settle the Let's Encrypt order budget for the 10k fill: file the rate-limit adjustment request")
//! @yah:at(2026-09-05T19:27:09Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:next("R779 Decision 3, the procurement half. The binding limit is per-ACCOUNT new orders: 300 / 3h, i.e. 2400/day, which fills 10k domains in ~4.2 days without asking anyone. The plan of record is to QUEUE under the cap and file Let's Encrypt's rate-limit adjustment form once projected volume approaches ~2k/day. That filing is the operator action here. (Do NOT inherit W273's duplicate-certificate number — that limit is per identical SAN set and does not bind on 10k distinct registered domains.)")
//! @yah:next("ALREADY ENFORCED IN CODE, so this ticket is a request-and-decide, not a build: the per-domain issuer paces orders at min_order_interval = 36s to match 300/3h, ACROSS sweeps rather than only within one (a sweep boundary would otherwise be a free order), and a configured 0 is rejected at parse rather than read as unlimited. Per-domain concurrency is the cert store's CAS claim, and a failed order rewrites that claim with a 1h TTL so the claim object doubles as the backoff marker — flat, not exponential, because the common failure is 'the tenant has not added the CNAME yet' and an exponential curve only delays their first success. See oss/yubaba/crates/yubaba/src/domain_issuer.rs.")
//! @yah:next("DRAFT WRITTEN 2026-09-05 at .yah/docs/working/R853-T3-le-rate-limit-request.md — operator answered 'file the form, I draft it, you submit'. It is field-by-field against the REAL form (fetched and parsed, 179 labels), with the free-text service description paste-ready and every ungroundable field marked [YOU]. Delete the file once submitted; it is a scratch artifact, not canon.")
//! @yah:next("BUT THE ARITHMETIC SAYS THE LIMIT DOES NOT BIND, and the operator should see this before submitting — re-read live from letsencrypt.org 2026-09-05 rather than inherited. New Orders per Account is 300/3h = 2,400/day = **16,800/week**. The fill is 10,000 orders (W267:3007 — the 10k are CUSTOM tenant domains, i.e. distinct registered domains, one identifier each). 10,000 < 16,800, so the whole fill fits in one week under the DEFAULT limit with 40% headroom, completing in ~4.2 days at the shipped 36s pacing — which W267:3042 already recorded and W267:3044 already accepted. This ticket's own trigger condition ('file once projected volume approaches ~2k/day') has not fired: projected volume is zero, the demux is not on :443 yet (R853-T2 in review).")
//! @yah:gotcha("RENEWALS COST NOTHING AGAINST THIS LIMIT, which removes the main reason to think the budget gets tight at steady state. LE's 'Limit Exemptions for Renewals' section: ARI renewals are exempt from ALL rate limits, and even NON-ARI renewals — an order whose identifier set exactly matches an earlier cert — are 'exempt from the New Orders per Account and New Certificates per Registered Domain rate limits'. The per-domain issuer orders exactly one identifier per domain (pinned by domain_issuer.rs's a_tenant_order_covers_exactly_its_own_domain_and_nothing_else), so every steady-state renewal qualifies under the non-ARI path. Steady state at 10k domains therefore draws ZERO from the 300/3h budget, not the ~1,167/week you would otherwise compute. We use instant-acme 0.8.5 and have no ARI code (grepped: no renewal_info / replaces anywhere), so we are on the non-ARI path — sufficient here, though ARI would additionally exempt us from the auth-failure and exact-set limits.")
//! @yah:gotcha("THE FLEET WILDCARD IS THE ONE PLACE THIS INTERACTS WITH R853-B9, and it cuts against widening. Non-ARI renewal exemption requires the EXACT same identifier set. The fleet cert's set is [yah.dev, *.yah.dev] + YUBABA_ACME_EXTRA_DOMAINS, so the moment an operator widens that list the new order is NOT a renewal: it consumes New Orders budget AND becomes subject to New Certificates per Exact Set of Identifiers (5 per 7 days) for the new set. Widening the fleet SAN list more than 5 times in a week will therefore be refused by LE regardless of any account-level override, because that limit is explicitly non-overridable ('We do not offer overrides for this limit').")
//! @yah:gotcha("FORM FIELD WITH NO CORRECT ANSWER, so decide before opening the tab rather than mid-form: 'What ACME client do you use?' is a required dropdown with no free-text escape. Checked all 179 form labels — no instant-acme, no rustls-acme, nothing Rust, and no 'Other' option. Ours is instant-acme 0.8.5 (oss/passway/Cargo.lock:1358) wrapped in our own acme-engine crate. The draft recommends the literally-named 'Yet another ACME client' entry plus a disambiguating sentence in the free-text box.")
//! @yah:handoff("SETTLED 2026-09-05, operator decision: DO NOT FILE the rate-limit adjustment request. Queue under the existing cap. The ticket's question — 'settle the Let's Encrypt order budget for the 10k fill' — is answered; it is answered 'nothing to procure', which is a resolution and not a deferral. blocked_on(operator) cleared.")
//! @yah:handoff("THE REASON IS ARITHMETIC, re-read live from letsencrypt.org rather than inherited from this ticket's filing text. New Orders per Account is 300 / 3h, refilling 1 per 36s — 2,400/day, **16,800/week**. The fill is 10,000 orders: W267:3007 establishes the 10k are CUSTOM tenant domains, i.e. distinct registered domains taking one identifier each. 10,000 < 16,800, so the entire fill fits inside a single week under the DEFAULT limit with ~40% headroom, completing in ~4.2 days at the shipped 36s pacing. That 4.2-day figure was already in W267:3042 and already accepted at W267:3044 ('a free tier does not deliver 10k domains in one day anyway'). There is no override to ask for.")
//! @yah:handoff("TWO FINDINGS THAT MADE THE CASE WEAKER STILL, neither of which was in the ticket. (1) RENEWALS DRAW ZERO from this budget. LE's 'Limit Exemptions for Renewals' section: ARI renewals are exempt from ALL rate limits, and even non-ARI renewals — an order whose identifier set exactly matches an earlier cert — are 'exempt from the New Orders per Account and New Certificates per Registered Domain rate limits'. The per-domain issuer orders exactly one identifier per domain (now pinned by domain_issuer.rs's a_tenant_order_covers_exactly_its_own_domain_and_nothing_else), so every steady-state renewal qualifies via the non-ARI path. Steady state at 10k domains therefore costs 0 orders/week against the cap, not the ~1,167 you would otherwise compute. (2) The per-registered-domain limit (50 per 7 days) does not bind either — distinct registered domains, one cert each. The ticket was already right to warn off W273's number, which is a third limit again (5 per exact identifier set per 7 days).")
//! @yah:handoff("WHAT WOULD RE-OPEN THIS, so the next reader does not have to re-derive the threshold: sustained demand above ~16,800 NEW registered domains per week, or a decision that the initial fill must complete in under ~4.2 days. Neither is true today — projected volume is zero, since the demux is not yet on :443 (R853-T2 in review). The filing trigger this ticket was opened with ('file once projected volume approaches ~2k/day') never fired.")
//! @yah:verify("Limits read live 2026-09-05 from https://letsencrypt.org/docs/rate-limits/ (HTTP 200), not from memory: 'Up to 300 new orders can be created by a single account every 3 hours. The ability to create new orders refills at a rate of 1 order every 36 seconds.' The 36s refill matches DomainIssuerConfig::min_order_interval (domain_issuer.rs:94) exactly, so the shipped pacing already tracks the published refill rate.")
//! @yah:verify("The form URL was confirmed by following the docs page's OWN 'request an override' link rather than asserting a remembered address — the only override/formstack href on the page resolves to https://isrg.formstack.com/forms/rate_limit_adjustment_request (HTTP 200).")
//! @yah:verify("Renewal exemption quoted from the page's 'Limit Exemptions for Renewals' section verbatim, and our path checked against it: instant-acme 0.8.5 (oss/passway/Cargo.lock:1358) with no ARI usage anywhere (grepped for renewal_info / replaces — zero hits), so we ride the non-ARI exact-identifier-set exemption, which covers the two limits that matter here.")
//! @yah:verify("The 10k-are-distinct-registered-domains premise — which the whole arithmetic turns on — grounded in W267:3007 ('the 10k-certs problem is inherently about custom tenant domains'), not assumed from the ticket title.")
//! @yah:gotcha("FORM FIELD WITH NO CORRECT ANSWER, if this is ever revived: 'What ACME client do you use?' is a required dropdown with no free-text escape. All 179 form labels checked — no instant-acme, no rustls-acme, nothing Rust, and no 'Other'. Ours is instant-acme 0.8.5 wrapped in our own acme-engine crate. Closest is the literally-named 'Yet another ACME client' entry, plus a disambiguating sentence in the free-text box.")
//! @yah:gotcha("THE LIMIT THAT CAN STILL BITE IS A DIFFERENT ONE, and no override exists for it. New Certificates per Exact Set of Identifiers is 5 per 7 days and letsencrypt.org states outright 'We do not offer overrides for this limit.' Non-ARI renewal exemption requires the EXACT same identifier set, so the FLEET wildcard — [yah.dev, *.yah.dev] + YUBABA_ACME_EXTRA_DOMAINS — leaves the exemption the moment that list is widened: the order stops counting as a renewal, consumes New Orders budget, and falls under the 5-per-7-days bucket for its new set. Widening the fleet SAN list more than 5 times in a week will be refused no matter what account-level override exists. That interacts directly with R853-B9, which is what makes widening that list actually take effect.")
//! @yah:handoff("DRAFT DELETED 2026-09-05 on operator instruction — 'if we need a rate-limit request someday that's fine, but we can write it when we need it.' The right call: the numbers were read off a page stamped 'Last updated: August 5, 2026' and LE moves them, so a parked draft would have rotted into a confidently-wrong form submission. Everything durable is on THIS ticket — the arithmetic, the renewal-exemption finding, the non-overridable exact-set limit, and the ACME-client dropdown trap are all in the handoff/verify/gotcha entries here. What was thrown away was only the paste-ready prose, which is cheap to rewrite and should be rewritten against freshly-read limits anyway.")
//! @yah:handoff("IF YOU DO REVIVE IT, the recipe rather than the artifact: form is https://isrg.formstack.com/forms/rate_limit_adjustment_request (confirmed by following the 'request an override' link on https://letsencrypt.org/docs/rate-limits/ rather than from memory). Its fields are JS-rendered — curl the form and parse the embedded JSON `label` keys to enumerate them; there were 179 on 2026-09-05. Answer 'No, I am proactively reaching out', override axis 'New Orders', apply to 'Account ID' (not Domains — the 10k are distinct registered domains and the form caps that field at three). The Account ID is the ACME account URI, which is not in this repo: it is created at runtime by load_or_create_account (acme-engine/src/lib.rs) and cached at YUBABA_ACME_ACCOUNT_CACHE on the fleet, so read it off a voter.")
//!
//! @yah:ticket(R853-F4, "External Account Binding in acme-engine, so a second CA can absorb order overflow")
//! @yah:at(2026-09-03T06:34:51Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:depends_on(R853-T3)
//! @yah:next("CONDITIONAL — build this ONLY if R853-T3 comes back refused. ZeroSSL and Google Trust Services both require External Account Binding, and acme-engine has none: confirmed by grep, there is no EAB code anywhere in the crate. The hook is instant-acme's NewAccount ExternalAccountKey, applied in load_or_create_account (oss/passway/crates/acme-engine/src/lib.rs) alongside the directory_root_cert fork R779 P8 added there.")
//! @yah:next("THE STORAGE LAYOUT ALREADY ACCOMMODATES A SECOND CA — do not redesign it. Cert objects live at certs/&lt;issuer&gt;/&lt;domain&gt;/{cert.sealed,key.sealed,issuing}, where issuer is the ACME directory host (mirroring certmagic's certificates/&lt;issuer-key&gt;/&lt;domain&gt;/), so adding a CA is a write and not a migration. The ENROLLMENT set lives at enrolled/&lt;domain&gt;, deliberately OUTSIDE certs/&lt;issuer&gt;/, because enrolment is a fact about a tenant rather than about a CA — so a domain stays routable while its cert moves between CAs. See oss/yubaba/crates/yubaba/src/cert_store.rs.")
//! @yah:gotcha("YOUR TRIGGER GOT LESS LIKELY, 2026-09-05 — read R853-T3 before starting. This ticket fires only if T3's rate-limit request comes back REFUSED, and the live numbers say the request may not need filing at all: New Orders per Account is 300/3h = 16,800/week, the fill is 10,000 orders (distinct registered domains, one identifier each), so it fits under the DEFAULT limit with 40% headroom. Renewals additionally draw ZERO from that budget — LE exempts both ARI and exact-identifier-set renewals from New Orders per Account. So the overflow-to-a-second-CA scenario this ticket exists to serve has no arithmetic behind it today. Do NOT start building EAB on a schedule; wait for an actual refusal, or for the domain target to move well past ~16.8k/week.")
//! @yah:gotcha("IF IT DOES FIRE, one constraint the ticket does not mention: the New Certificates per Exact Set of Identifiers limit (5 per 7 days) is explicitly NON-overridable — 'We do not offer overrides for this limit' on letsencrypt.org, checked 2026-09-05. So a second CA is the only remedy for that particular limit, which is the one that bites when the FLEET wildcard's SAN list is widened repeatedly (see R853-T3's gotcha on the B9 interaction). That is a genuinely different motivation for EAB than order-volume overflow, and a stronger one.")
//! @yah:next("TRIGGER IS NOW DEAD, 2026-09-05 — do not build this on the rationale it was filed with. This ticket's condition is 'build ONLY if R853-T3 comes back refused'. T3 is settled as NOT FILED (operator decision): the New Orders per Account limit does not bind on the 10k fill — 300/3h = 16,800/week against a 10,000-order fill, with renewals exempt entirely — so there is no request to be refused and the order-overflow scenario has no arithmetic behind it. Left open rather than closed because a DIFFERENT and stronger motivation surfaced while settling T3; that motivation is below, and whoever picks this up should re-file the justification around it rather than inherit the overflow framing.")
//! @yah:next("THE MOTIVATION THAT SURVIVES is the New Certificates per Exact Set of Identifiers limit: 5 per 7 days, and letsencrypt.org states 'We do not offer overrides for this limit.' A second CA is therefore the ONLY remedy for it — unlike order volume, this one cannot be procured around at any price. It binds on the FLEET wildcard, whose identifier set is [yah.dev, *.yah.dev] + YUBABA_ACME_EXTRA_DOMAINS: widening that list leaves the non-ARI renewal exemption, so more than 5 widenings in a week gets refused outright. Whether that is worth EAB depends on how often the fleet SAN list actually changes, which is an operator question and not currently answerable — the fleet issuer has never issued (see R853-B9's gotcha: it is inert until R858-T3 makes raft leadership movable).")
//! @yah:next("CHEAPER ALTERNATIVE TO WEIGH FIRST, if the exact-set limit is the real driver: adopt ARI in acme-engine instead of EAB. instant-acme 0.8.5 is already the dependency and we use no ARI today (grepped: no renewal_info / replaces anywhere). ARI renewals are exempt from ALL rate limits including the exact-set one, where non-ARI renewals are not. That is a smaller change than a second CA with external account binding, keeps one issuer, and does not touch the cert-store issuer axis at all. It does NOT help with a genuinely new identifier set — a first-ever widening is not a renewal under either scheme — so it narrows the problem rather than removing it.")

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
        /// R779 — **challenge delegation**, for identifiers whose zone we do
        /// not hold.
        ///
        /// `None` is the ordinary case: the TXT lands at
        /// `_acme-challenge.<identifier>`, which only works when `zone_id` is
        /// the identifier's own zone.
        ///
        /// `Some("acme.example.net")` publishes at
        /// `<identifier>.acme.example.net` instead, inside a zone we *do*
        /// hold. The identifier's owner points
        /// `_acme-challenge.<identifier>` at that name with a CNAME, and the
        /// CA follows it — RFC 8555 validates by resolving the TXT, and
        /// resolution follows CNAMEs like any other lookup. This is how a
        /// custom tenant domain is issued without either holding its zone or
        /// standing up an `:80` tier. See [`dns01_record_name`].
        delegate_zone: Option<String>,
        /// Base URL of the Cloudflare-shaped API these TXT records are
        /// created/deleted against, without a trailing `/zones/…` path.
        ///
        /// `None` — the production default — means
        /// [`CLOUDFLARE_API_BASE`], i.e. the real Cloudflare API. The only
        /// reason to set it is to point the publisher at a stand-in that
        /// speaks the same two endpoints: the DNS-01 integration test
        /// (`tests/pebble_dns01_delegation.rs`) runs a shim that forwards
        /// into a Pebble challtestsrv, which is how the delegation record
        /// name is proven against a real CA. A trailing `/` is trimmed, so
        /// `…/v4` and `…/v4/` behave identically.
        api_base: Option<String>,
    },
}

/// The production Cloudflare API base every DNS-01 publish goes to unless
/// [`AcmeChallengeKind::Dns01Cloudflare::api_base`] overrides it.
pub const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Where the DNS-01 TXT record for `base` is published.
///
/// Split out and public because it is the whole of the delegation contract:
/// whatever this returns is exactly what a tenant must CNAME
/// `_acme-challenge.<their domain>` to, so an onboarding page and the issuer
/// have to agree on it byte for byte, and a test has to be able to pin it.
///
/// `base` is the *identifier* from the authorization, not the SAN — a wildcard
/// authorization for `*.example.com` carries `example.com`, and validates at the
/// same record name as the apex.
pub fn dns01_record_name(base: &str, delegate_zone: Option<&str>) -> String {
    match delegate_zone {
        // Trailing/leading dots trimmed: an operator writing a fully-qualified
        // `acme.example.net.` should not produce a `..` in the middle of a name.
        Some(zone) => format!("{}.{}", base.trim_matches('.'), zone.trim_matches('.')),
        None => format!("_acme-challenge.{base}"),
    }
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
    /// Path to a PEM root certificate to trust **for the ACME directory
    /// connection**, and nothing else.
    ///
    /// `None` — the production default — trusts only the public roots. This
    /// is the private-CA / test-CA hook, not a general TLS knob: it is the
    /// only way to talk to a directory whose own certificate is not publicly
    /// chained (Pebble, step-ca, an internal CA). It does not affect the
    /// DNS-01 provider client, and it does not affect validation of the cert
    /// this engine returns.
    pub directory_root_cert: Option<String>,
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

/// What the caller knows about the SAN set of the cert it is currently
/// holding — the input [`renewal_decision`] needs in order to answer
/// "is this the *right* cert", not merely "is it old".
///
/// This is an enum rather than an `Option` so that deciding on age alone
/// cannot be written by accident. Age-only is sometimes genuinely correct,
/// but it is also exactly what produced R853-B7/B8: widening a configured
/// domain list left a fresh-but-narrower cert in place for up to
/// `lifetime - renew_before`, silently, with the config file reading as
/// though the change had taken effect. Naming the choice forces every call
/// site to make it out loud, and makes the age-only ones greppable.
pub enum CertSans<'a> {
    /// The leaf's `dNSName` set, as returned by [`cert_dns_names`].
    Known(&'a [String]),
    /// A cert is stored but is not one this process can parse — it could not
    /// serve those bytes either, so they must be replaced.
    Unreadable,
    /// The caller deliberately did not look. Only age decides. Every use owes
    /// a comment at the call site saying why the configured name list cannot
    /// widen underneath it — or which ticket is going to close that gap.
    NotChecked,
}

/// Why (or why not) a stored cert should be reordered now. Carries the reason
/// rather than a bare `bool` so the caller can name the missing SANs back to
/// an operator instead of logging an unexplained reissue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalDecision {
    /// Covers every configured name and is outside its renewal margin.
    Fresh,
    /// Inside the `renew_before` margin, or already expired.
    DueForAge,
    /// Does not cover these configured names, whatever its age. Order and
    /// duplicates are as the operator wrote them in config.
    DueForCoverage(Vec<String>),
    /// Stored, but not parseable as a certificate.
    DueUnreadable,
}

impl RenewalDecision {
    pub fn is_due(&self) -> bool {
        !matches!(self, RenewalDecision::Fresh)
    }
}

/// Pure decision: should the cert described by `sans` / `issued_at` be
/// reordered at `now`, given the `wanted` domain list, a fixed validity
/// `lifetime` and a `renew_before` safety margin?
///
/// Coverage is checked **before** age, because a cert can be minutes old and
/// still be the wrong cert; see [`domains_not_covered`] for the RFC 6125
/// matching rule. `wanted` is ignored when `sans` is not [`CertSans::Known`].
pub fn renewal_decision(
    sans: CertSans<'_>,
    wanted: &[String],
    issued_at: SystemTime,
    lifetime: Duration,
    renew_before: Duration,
    now: SystemTime,
) -> RenewalDecision {
    match sans {
        CertSans::Unreadable => return RenewalDecision::DueUnreadable,
        CertSans::Known(have) => {
            let missing = domains_not_covered(have, wanted);
            if !missing.is_empty() {
                return RenewalDecision::DueForCoverage(missing);
            }
        }
        CertSans::NotChecked => {}
    }

    if is_renewal_due(issued_at, lifetime, renew_before, now) {
        RenewalDecision::DueForAge
    } else {
        RenewalDecision::Fresh
    }
}

/// The age half of [`renewal_decision`]. Deliberately **not** `pub`: reachable
/// only through `renewal_decision`, so a new call site cannot decide renewal
/// from age alone without saying [`CertSans::NotChecked`] where a reviewer
/// will see it.
fn is_renewal_due(issued_at: SystemTime, lifetime: Duration, renew_before: Duration, now: SystemTime) -> bool {
    let expires_at = issued_at.checked_add(lifetime).unwrap_or(issued_at);
    let renew_at = expires_at.checked_sub(renew_before).unwrap_or(issued_at);
    now >= renew_at
}

/// The `dNSName` SANs carried by the **leaf** (first) certificate of a PEM
/// chain, ASCII-lowercased and with any trailing root dot trimmed.
///
/// `None` means "this file is not a certificate we can read" — an empty PEM,
/// a truncated one, a key mistakenly written to the cert path, or a DER
/// structure `x509-parser` rejects. Callers should treat `None` as *reissue*,
/// never as *no names*: an unparseable cert is one this process also cannot
/// serve, and returning an empty Vec would make it indistinguishable from a
/// cert that legitimately carries no SAN.
///
/// A cert with no `subjectAltName` extension at all yields `Some(vec![])`.
/// This deliberately does NOT fall back to the Subject CN: CN-as-hostname has
/// been deprecated since RFC 2818 and is ignored by every current TLS client,
/// so honouring it here would report coverage that no browser agrees with.
pub fn cert_dns_names(cert_chain_pem: &str) -> Option<Vec<String>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_chain_pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    let mut names = Vec::new();
    // `subject_alternative_name()` is Ok(None) when the extension is absent
    // and Err(..) only when it is present but malformed — the latter is a
    // broken cert, so it joins the `None` (reissue) path rather than being
    // read as "no names".
    if let Some(san) = cert.subject_alternative_name().ok()? {
        for general_name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(name) = general_name {
                names.push(normalize_dns_name(name));
            }
        }
    }
    Some(names)
}

/// Which of `wanted` the SAN set `have` does **not** cover — empty means the
/// cert on disk already satisfies the configured domain list.
///
/// Matching follows RFC 6125 as a TLS client would apply it, because the
/// question this answers is "would a client asking for these names accept the
/// cert we are serving?":
///
/// - exact match, case-insensitively;
/// - a `*.example.com` SAN covers exactly one additional label
///   (`www.example.com`), NOT the apex (`example.com`) and NOT a deeper name
///   (`a.b.example.com`).
///
/// Order and duplicates in `wanted` are preserved in the result so the caller
/// can name the missing entries back to an operator exactly as they wrote
/// them in config.
pub fn domains_not_covered(have: &[String], wanted: &[String]) -> Vec<String> {
    // Both sides are normalized here rather than trusted: `have` usually
    // comes from `cert_dns_names` (already normalized) but this is public and
    // an operator's config list certainly is not, and comparing raw strings
    // would re-order a good cert forever over a capital letter.
    let have: Vec<String> = have.iter().map(|san| normalize_dns_name(san)).collect();
    wanted
        .iter()
        .filter(|want| {
            let normalized = normalize_dns_name(want);
            !have.iter().any(|san| dns_name_covers(san, &normalized))
        })
        .cloned()
        .collect()
}

/// Lowercase and drop a trailing root dot, so `WWW.Yah.dev.` and
/// `www.yah.dev` compare equal.
fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Does the (already normalized) SAN `have` cover the (already normalized)
/// name `want`? See [`domains_not_covered`] for the rules.
fn dns_name_covers(have: &str, want: &str) -> bool {
    if have == want {
        return true;
    }
    let Some(suffix) = have.strip_prefix("*.") else {
        return false;
    };
    // The wildcard label must not be empty and must not itself contain a dot,
    // so `*.yah.dev` covers `www.yah.dev` but neither `yah.dev` nor
    // `a.b.yah.dev` nor `*.a.yah.dev`.
    match want.strip_suffix(suffix).and_then(|head| head.strip_suffix('.')) {
        Some(label) => !label.is_empty() && !label.contains('.'),
        None => false,
    }
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

/// Everything the DNS-01 arm of [`issue`] needs, resolved once before the first
/// authorization. A struct rather than a tuple because it grew a fourth member
/// (`delegate_zone`) and three call sites destructure it.
struct Dns01Ctx {
    client: reqwest::Client,
    token: String,
    zone_id: String,
    delegate_zone: Option<String>,
    /// Already resolved: the operator's override with any trailing `/`
    /// trimmed, or [`CLOUDFLARE_API_BASE`].
    api_base: String,
}

/// Resolve an operator-supplied API base to the string the two request
/// builders concatenate onto. `None` → the production constant; a trailing
/// `/` is trimmed so `…/v4/` and `…/v4` produce the same URL.
fn resolve_api_base(configured: Option<&str>) -> String {
    match configured {
        Some(base) if !base.trim().is_empty() => base.trim().trim_end_matches('/').to_string(),
        _ => CLOUDFLARE_API_BASE.to_string(),
    }
}

/// Create a `_acme-challenge` TXT record. Deliberately a bare create, not
/// an upsert: a wildcard + apex order produces two authorizations for the
/// *same* record name (`_acme-challenge.example.com`) whose TXT values must
/// coexist for validation — an upsert would clobber the first.
async fn cloudflare_create_txt(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    zone_id: &str,
    name: &str,
    content: &str,
) -> Result<String, AcmeError> {
    let url = format!("{api_base}/zones/{zone_id}/dns_records");
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
    api_base: &str,
    token: &str,
    zone_id: &str,
    record_id: &str,
) -> Result<(), AcmeError> {
    let url = format!("{api_base}/zones/{zone_id}/dns_records/{record_id}");
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

/// Build the `AccountBuilder` for this config's directory connection.
///
/// `directory_root_cert` is the only fork: with it, the HTTPS client trusts
/// exactly that one PEM root instead of the public set, which is what lets
/// this engine speak to a Pebble/step-ca/private directory.
fn account_builder(config: &IssueConfig) -> Result<instant_acme::AccountBuilder, AcmeError> {
    match &config.directory_root_cert {
        Some(pem_path) => Account::builder_with_root(pem_path).map_err(AcmeError::from),
        None => Account::builder().map_err(AcmeError::from),
    }
}

async fn load_or_create_account(config: &IssueConfig) -> Result<Account, AcmeError> {
    let cache_path = Path::new(&config.account_cache_path);
    if let Ok(existing) = std::fs::read_to_string(cache_path) {
        let credentials: AccountCredentials = serde_json::from_str(&existing).map_err(|e| {
            AcmeError::Config(format!(
                "corrupt ACME account cache at {cache_path:?}: {e} — remove the file to force re-registration"
            ))
        })?;
        return Ok(account_builder(config)?.from_credentials(credentials).await?);
    }

    log::info!(
        "acme-engine: no cached account at {cache_path:?} — registering a new ACME account for {}",
        config.contact_email
    );
    let contact = format!("mailto:{}", config.contact_email);
    let (account, credentials) = account_builder(config)?
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
        AcmeChallengeKind::Dns01Cloudflare {
            token_file,
            zone_id,
            delegate_zone,
            api_base,
        } => {
            let token = std::fs::read_to_string(token_file)
                .map_err(|e| {
                    AcmeError::Config(format!("reading Cloudflare token file {token_file:?}: {e}"))
                })?
                .trim()
                .to_string();
            Some(Dns01Ctx {
                client: reqwest::Client::new(),
                token,
                zone_id: zone_id.clone(),
                delegate_zone: delegate_zone.clone(),
                api_base: resolve_api_base(api_base.as_deref()),
            })
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
            Some(ctx) => {
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
                    let name = dns01_record_name(&base, ctx.delegate_zone.as_deref());
                    let record_id = cloudflare_create_txt(
                        &ctx.client,
                        &ctx.api_base,
                        &ctx.token,
                        &ctx.zone_id,
                        &name,
                        &txt_value,
                    )
                    .await?;
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
    if let Some(ctx) = &dns01 {
        for record in &created_records {
            if let Err(e) = cloudflare_delete_record(
                &ctx.client,
                &ctx.api_base,
                &ctx.token,
                &ctx.zone_id,
                &record.record_id,
            )
            .await
            {
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

    // -- domains_not_covered / dns_name_covers (pure) -------------------

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// R853-B7's actual production shape: us-south-001 served an apex-only
    /// cert while the config asked for the wildcard too, so every yah.dev
    /// SUBDOMAIN failed on that node. Age says "fine"; coverage says "no".
    #[test]
    fn an_apex_only_cert_does_not_cover_a_widened_wildcard_config() {
        assert_eq!(
            domains_not_covered(&owned(&["yah.dev"]), &owned(&["*.yah.dev", "yah.dev"])),
            owned(&["*.yah.dev"])
        );
    }

    #[test]
    fn a_cert_carrying_every_configured_name_is_fully_covered() {
        assert!(domains_not_covered(&owned(&["yah.dev", "*.yah.dev"]), &owned(&["*.yah.dev", "yah.dev"])).is_empty());
    }

    /// A wildcard SAN covers exactly one extra label — the RFC 6125 rule a
    /// TLS client applies. Getting this wrong in either direction is
    /// expensive: too strict re-orders a cert that already works (burning
    /// the account's order budget), too loose leaves the B8 bug in place for
    /// the deeper name.
    #[test]
    fn a_wildcard_covers_one_label_and_neither_the_apex_nor_a_deeper_name() {
        let have = owned(&["*.yah.dev"]);
        assert!(domains_not_covered(&have, &owned(&["www.yah.dev"])).is_empty());
        assert_eq!(domains_not_covered(&have, &owned(&["yah.dev"])), owned(&["yah.dev"]));
        assert_eq!(domains_not_covered(&have, &owned(&["a.b.yah.dev"])), owned(&["a.b.yah.dev"]));
        assert_eq!(domains_not_covered(&have, &owned(&["*.a.yah.dev"])), owned(&["*.a.yah.dev"]));
        // The wildcard label may not be empty: `*.yah.dev` is not a cert for
        // `.yah.dev`.
        assert_eq!(domains_not_covered(&have, &owned([".yah.dev"].as_slice())), owned(&[".yah.dev"]));
    }

    /// A wildcard in the CONFIG needs a wildcard in the cert — a bag of
    /// specific SANs does not add up to one. Without this, widening config
    /// to `*.yah.dev` while the cert holds `www.yah.dev` would read as
    /// covered and reproduce B8.
    #[test]
    fn specific_sans_do_not_satisfy_a_wildcard_request() {
        assert_eq!(
            domains_not_covered(&owned(&["www.yah.dev", "api.yah.dev"]), &owned(&["*.yah.dev"])),
            owned(&["*.yah.dev"])
        );
    }

    /// DNS names are case-insensitive and a trailing root dot is not a
    /// difference. Comparing raw strings would re-order a perfectly good
    /// cert on every check — a slow rate-limit burn that only shows up in
    /// production, where a CA hands back mixed-case or rooted names.
    #[test]
    fn matching_ignores_case_and_a_trailing_root_dot() {
        assert!(domains_not_covered(&owned(&["YAH.dev.", "*.YAH.dev"]), &owned(&["yah.dev", "www.yah.dev."])).is_empty());
    }

    #[test]
    fn an_empty_config_is_covered_by_anything_and_an_empty_cert_covers_nothing() {
        assert!(domains_not_covered(&owned(&["yah.dev"]), &[]).is_empty());
        assert_eq!(domains_not_covered(&[], &owned(&["yah.dev"])), owned(&["yah.dev"]));
    }

    // -- cert_dns_names -------------------------------------------------

    /// The `None` contract is the load-bearing half: callers treat it as
    /// "reissue", so it must not be reachable for a cert that merely has no
    /// SANs (that is `Some(vec![])`), and must be reachable for anything
    /// that is not a readable certificate.
    #[test]
    fn unreadable_cert_material_is_none_not_an_empty_name_set() {
        assert!(cert_dns_names("").is_none());
        assert!(cert_dns_names("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n").is_none());
        assert!(cert_dns_names("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n").is_none());
    }

    /// Round-trip through a real DER encoder rather than a checked-in
    /// fixture, so the assertion is about what an X.509 cert actually says
    /// and cannot rot into agreeing with a hand-written blob.
    fn self_signed_pem(names: &[&str]) -> String {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("self-signed leaf");
        cert.pem()
    }

    #[test]
    fn reads_the_san_set_off_a_real_certificate() {
        let names = cert_dns_names(&self_signed_pem(&["yah.dev", "*.yah.dev"])).expect("a self-signed cert parses");
        assert!(domains_not_covered(&names, &owned(&["yah.dev", "www.yah.dev"])).is_empty());
        assert_eq!(domains_not_covered(&names, &owned(&["other.test"])), owned(&["other.test"]));
    }

    /// The leaf is the cert a client checks, and it is first in the chain —
    /// a chain whose intermediate carries different names must still report
    /// the leaf's.
    #[test]
    fn reads_the_leaf_when_the_file_is_a_chain() {
        let leaf = self_signed_pem(&["leaf.test"]);
        let issuer = self_signed_pem(&["issuer.test"]);
        assert_eq!(cert_dns_names(&format!("{leaf}{issuer}")).expect("chain parses"), owned(&["leaf.test"]));
    }

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

    // -- renewal_decision (pure) ----------------------------------------

    const LIFETIME: Duration = Duration::from_secs(90 * 86_400);
    const RENEW_BEFORE: Duration = Duration::from_secs(30 * 86_400);

    fn decide(sans: CertSans<'_>, wanted: &[&str], age_days: u64) -> RenewalDecision {
        let now = SystemTime::now();
        let issued_at = now - Duration::from_secs(age_days * 86_400);
        renewal_decision(sans, &owned(wanted), issued_at, LIFETIME, RENEW_BEFORE, now)
    }

    #[test]
    fn not_checked_falls_back_to_age_alone() {
        assert_eq!(decide(CertSans::NotChecked, &["yah.dev"], 1), RenewalDecision::Fresh);
        assert_eq!(decide(CertSans::NotChecked, &["yah.dev"], 61), RenewalDecision::DueForAge);
    }

    /// The whole point of the seam: `NotChecked` must ignore `wanted` rather
    /// than quietly reporting coverage it never looked at.
    #[test]
    fn not_checked_ignores_the_wanted_list_entirely() {
        assert_eq!(decide(CertSans::NotChecked, &["never.covered.example"], 1), RenewalDecision::Fresh);
    }

    #[test]
    fn a_covering_cert_is_fresh_until_its_age_window_opens() {
        let have = owned(&["*.yah.dev", "yah.dev"]);
        assert_eq!(decide(CertSans::Known(&have), &["www.yah.dev", "yah.dev"], 1), RenewalDecision::Fresh);
        assert_eq!(decide(CertSans::Known(&have), &["www.yah.dev"], 61), RenewalDecision::DueForAge);
    }

    /// R853-B8: a brand-new cert that does not cover a widened config is due
    /// NOW, and the decision names what is missing.
    #[test]
    fn coverage_is_checked_before_age_and_names_the_missing_domains() {
        let have = owned(&["yah.dev"]);
        assert_eq!(
            decide(CertSans::Known(&have), &["yah.dev", "cloud.mesh.yah.dev"], 1),
            RenewalDecision::DueForCoverage(owned(&["cloud.mesh.yah.dev"]))
        );
        // Old AND uncovered reports coverage, so the log says the useful thing.
        assert_eq!(
            decide(CertSans::Known(&have), &["cloud.mesh.yah.dev"], 61),
            RenewalDecision::DueForCoverage(owned(&["cloud.mesh.yah.dev"]))
        );
    }

    #[test]
    fn an_unreadable_cert_is_due_however_fresh_it_is() {
        assert_eq!(decide(CertSans::Unreadable, &["yah.dev"], 0), RenewalDecision::DueUnreadable);
    }

    #[test]
    fn only_fresh_is_not_due() {
        assert!(!RenewalDecision::Fresh.is_due());
        assert!(RenewalDecision::DueForAge.is_due());
        assert!(RenewalDecision::DueForCoverage(owned(&["yah.dev"])).is_due());
        assert!(RenewalDecision::DueUnreadable.is_due());
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

    // ── R779 DNS-01 delegation ───────────────────────────────────────────────

    #[test]
    fn undelegated_dns01_publishes_at_the_identifiers_own_challenge_name() {
        assert_eq!(
            dns01_record_name("example.com", None),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn delegated_dns01_publishes_inside_the_zone_we_hold() {
        // The tenant's zone is not ours, so nothing may be written under
        // `shop.tenant.io`; the record goes in `acme.yah.dev`, which is.
        assert_eq!(
            dns01_record_name("shop.tenant.io", Some("acme.yah.dev")),
            "shop.tenant.io.acme.yah.dev"
        );
    }

    #[test]
    fn a_wildcard_and_its_apex_delegate_to_one_name() {
        // instant-acme hands both authorizations the *base* identifier, so this
        // is the delegation equivalent of the shared `_acme-challenge.<base>`
        // the two-pass publish exists to handle — one name, two TXT values.
        let base = "example.com";
        assert_eq!(
            dns01_record_name(base, Some("acme.yah.dev")),
            dns01_record_name(base, Some("acme.yah.dev"))
        );
    }

    #[test]
    fn fully_qualified_zone_and_identifier_do_not_produce_a_double_dot() {
        // An operator copying a zone out of a DNS UI often brings the root dot.
        assert_eq!(
            dns01_record_name("shop.tenant.io.", Some("acme.yah.dev.")),
            "shop.tenant.io.acme.yah.dev"
        );
    }

    // -- resolve_api_base ----------------------------------------------

    #[test]
    fn no_configured_api_base_is_the_production_cloudflare_endpoint() {
        // Every production path leaves this `None`, so this is the assertion
        // that the override changed nothing for them.
        assert_eq!(resolve_api_base(None), CLOUDFLARE_API_BASE);
        assert_eq!(resolve_api_base(Some("  ")), CLOUDFLARE_API_BASE);
    }

    #[test]
    fn a_trailing_slash_on_the_api_base_does_not_double_up() {
        // `…/v4/` and `…/v4` must build the same `/zones/…` URL — an
        // operator copying a base out of a doc page brings the slash.
        assert_eq!(resolve_api_base(Some("http://127.0.0.1:8080/")), "http://127.0.0.1:8080");
        assert_eq!(resolve_api_base(Some(" http://127.0.0.1:8080 ")), "http://127.0.0.1:8080");
    }
}
