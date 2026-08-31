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
//! ## One listener serves one cert — and that is the tenant boundary (R777)
//!
//! The consequence of the section above is worth stating as a rule rather than
//! leaving as an implication: **this process can serve exactly one certificate
//! chain, so a second tenant gets a second passway process, not a second cert
//! in this one.** That is a decision, re-taken deliberately by the R777 spike
//! on 2026-08-15, not a limitation waiting to be lifted. Before proposing a
//! SAN set that spans two tenants' hostnames, or a backend switch to reach
//! SNI, read W267 §"One listener, one cert — and that is the tenant boundary",
//! which holds the full comparison. The short form:
//!
//! - **SNI cert selection IS reachable** — but only on pingora's
//!   openssl/boringssl backend, where `TlsSettings::with_callbacks` succeeds
//!   (`pingora-core-0.8.1/src/listeners/tls/boringssl_openssl/mod.rs:92`) and
//!   `TlsAccept::certificate_callback` can read
//!   `ssl.servername(NameType::HOST_NAME)` and install a chain with
//!   `ext::ssl_use_certificate`. pingora's own `test_async_cert`
//!   (`src/protocols/tls/boringssl_openssl/server.rs:170`) is the worked
//!   example. Verified, so nobody re-checks it — and still rejected: it
//!   re-introduces `openssl-sys`, which `deny.toml` bans by name and which
//!   W169's musl audit names as a blocker for the musl-static build this
//!   binary ships as.
//! - **The isolation argument, not the plumbing, is what decides it.** This is
//!   the most exposed process in the fleet. One passway holding N tenants'
//!   private keys makes one RCE a cross-tenant key compromise; one passway per
//!   tenant makes it one tenant's. Cert issuance inherits the same split —
//!   one issuer per process holds one tenant's DNS-01 zone credential, where a
//!   shared listener would need one issuer holding every tenant's.
//! - **It is affordable because the process is small.** Measured on the live
//!   fleet 2026-08-15: 9.8 MB RSS on `us-south-001` (1 core, 961 MB box),
//!   13.2 MB on `us-east-001` (6 cores) — flat across core count because
//!   `main.rs` pins `conf.threads = 1`. Per-tenant deployment turns that into
//!   a per-tenant cost, so read the comment on that line before raising it.
//! - **If per-hostname certs are ever needed inside ONE tenant** (where the
//!   isolation argument does not apply and a wildcard will not stretch), the
//!   move is to teach pingora's *rustls* listener a
//!   `ResolvesServerCert` — rustls supports it natively, pingora just never
//!   exposes it — not to change TLS backends. W267 has the patch shape.
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
//!
//! @yah:relay(R777, "passway serves exactly one cert: pingora boringssl/openssl SNI callbacks vs one listener per tenant")
//! @yah:status(review)
//! @yah:at(2026-08-16T03:32:14Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("ANSWERED - this spike is closed, no code change. The six investigation bullets below were the questions; the verdict is OPTION B: a second tenant gets a second passway process, not a second cert in this one. Full comparison in W267 section 'One listener, one cert - and that is the tenant boundary (R777, 2026-08-15)'.")
//! @yah:handoff("VERDICT: OPTION B. A second tenant gets a second passway process, not a second cert in this one. Zero code change - the fleet is already in this shape (us-east-001 and us-south-001 run two independent passway processes with two different certs, split deliberately so two nodes asking for an identical SAN set do not share Let's Encrypt's 5/week duplicate-cert bucket), and W305/R742-F2 already shipped the declaration form ([[ingress]] edges naming provider + machines + hostnames). Deliverable is the decision, recorded in three places.")
//! @yah:verify("cargo doc --no-deps -p passway: clean. 3 warnings, all pre-existing private-intra-doc-link warnings in acme.rs and hardening.rs, none from this pass; the new [`crate::tls`] link from host.rs resolves.")
//! @yah:handoff("THE UNVERIFIED HALF IS NOW VERIFIED, and the answer is YES: pingora's openssl/boringssl backend does reach SNI. listeners/tls/boringssl_openssl/mod.rs:92 implements with_callbacks(cb) -> Ok(TlsSettings{..}) (vs rustls/mod.rs:113 which is unconditionally Err), and pingora's own test test_async_cert at protocols/tls/boringssl_openssl/server.rs:170-205 is a complete worked SNI-to-cert example: TlsAccept::certificate_callback reads ssl.servername(ssl::NameType::HOST_NAME) then installs the chain via ext::ssl_use_certificate / ext::ssl_use_private_key, with handshake_with_callback (same file 49-77) genuinely pausing at cert-needed and resuming. So option A is dead on COST, not on API - and that is worth knowing precisely, because 'we checked and it does not work' would have been the wrong reason to record.")
//! @yah:handoff("OPTION A's DECIDING COST, read not inferred: it re-introduces openssl-sys (or boring-sys plus a C++/cmake cross toolchain). W169's musl audit names openssl-sys as one of exactly TWO crates blocking musl-static for 19 of 59 root workspace members - and passway ships as a musl static-pie cross-built from macOS (the 0.8.22 roll onto east/south records that exact command in .yah/services/yah-marketing/mirrors/cloud.toml). It also reverses deny.toml's by-name ban on openssl / openssl-sys / boring / boring-sys and the R594-S1 spike verdict. The real decider is isolation, though, not the toolchain: passway is the most exposed process in the fleet, so one passway holding N tenants' private keys makes one RCE a cross-tenant key compromise.")
//! @yah:handoff("THE MULTI-TENANT CERT-SOURCE QUESTION, answered explicitly as the ticket demanded: option B dissolves it. One process, one tenant, one W273 elected issuer, one tenant's DNS-01 zone credential - by construction, no N-issuers-one-store and no shared-credential shape. Option A would have forced one of those two, and the second (one issuer holding N tenants' zone credentials) is strictly WORSE than the CT-log leak the operator rejected on 2026-08-15: a CT leak publishes one tenant's hostnames, a shared DNS-01 token forfeits control of every tenant's domain.")
//! @yah:handoff("OPTION A2 - the option the ticket did not name, recorded because it is the right answer if B's premise breaks. rustls resolves certs per-SNI natively via ServerConfig::builder(..).with_cert_resolver(Arc<dyn ResolvesServerCert>); pingora just never exposes it. Two small patches would: pingora-rustls re-exports ResolvesServerCert (its re-export block at lib.rs:28-34 currently does not - checked), and pingora-core's rustls TlsSettings gains an optional resolver branched against with_single_cert in build(). Stays all-rustls, musl-clean and deny.toml-clean, and gets a LIVE cert swap with no process restart - strictly better than A on rotation. Cost: forking the one dep pinned FOR its CVE remediation (CVE-2025-4366 / RUSTSEC-2025-0037 is why >=0.8.1). Upstream it rather than carry it. Trigger to reach for A2: many hostnames needing INDEPENDENT certs inside ONE tenant, where the isolation argument does not apply. Not live today - a wildcard covers it (*.yah.dev already serves issues.yah.dev and passway-test.yah.dev off one chain).")
//! @yah:handoff("ALSO ANSWERED (the ticket asked): would A let R600-F7/F9's graceful-upgrade machinery be deleted? No - only partly. Socket custody is ALSO how passway takes a BINARY upgrade without dropping the listener, so the kamaji SocketCustodian + kamaji-proto YubabaToKamaji::GracefulUpgrade wire message stay. A would only remove 'yubaba secret_reload' as a TRIGGER of it. A partial simplification of shipped machinery across three crates, not a deletion - so it does not offset A's costs.")
//! @yah:handoff("WHERE THE DECISION LANDED (three places, doc is canon): (1) .yah/docs/working/W267-sovereign-public-ingress.md new section 'One listener, one cert - and that is the tenant boundary (R777, 2026-08-15)' holds the full comparison, A's verified mechanics, A2's patch shape, and B's concrete fleet cost. (2) oss/passway/crates/passway/src/tls.rs module doc gains 'One listener serves one cert - and that is the tenant boundary (R777)' at the code site, so the next person to propose a two-tenant SAN set reads why before editing. (3) oss/passway/crates/passway/src/host.rs:12-27 'Why not SNI' paragraph annotated - it stays correct, but now records that R777 re-weighed the backend switch and that B shrinks what the SNI-vs-Host domain-fronting cross-check would buy.")
//! @yah:verify("cargo test -p passway --lib = 99 passed / 0 failed. Doc-only pass, no behaviour touched.")
//! @yah:handoff("OPERATOR CONDITION (2026-08-15): B accepted IF a per-tenant passway is austere on memory. MEASURED on the two live production processes, not estimated: us-south-001 (1 core, 961 MB box) = 9.8 MB RSS / 9.8 MB PSS / 0 swap, 6 threads. us-east-001 (6 cores, 11.7 GB) = 13.2 MB RSS / 13.2 MB PSS / 0 swap, 7 threads, 3.5 days uptime. So ~10 MB per tenant, and CRUCIALLY it does not scale with core count.")
//! @yah:handoff("WHY IT IS FLAT ACROSS CORE COUNT, and the one change this pass made: pingora's ServerConf::default() sets threads: 1 PER SERVICE (pingora-core/src/server/configuration/mod.rs:137) and passway never raised it to nproc. main.rs now pins conf.threads = 1 EXPLICITLY - behaviourally a no-op today, but Cargo.toml requires pingora = '>=0.8.1', an UNBOUNDED range, so a future release changing that default would multiply the per-tenant footprint across every passway on the fleet at once and silently. The comment at that line states the per-tenant multiplier so a future throughput tune is a deliberate N-tenants-wide decision, not an inherited accident.")
//! @yah:handoff("THE PLANNING CONSEQUENCE, and the honest caveats. Memory is NOT the scarce resource under option B - PUBLIC IPs are. us-south-001 has ~581 MB available and could hold dozens of passway processes; it has one public IP. Cost tenant fan-out in IPs, not RAM. CAVEATS, stated rather than buried: (a) both measured processes are live but LOW-TRAFFIC, so ~10 MB is a floor - connection buffers scale with concurrent connections, which is a per-NODE property, not per-tenant; (b) raising threads for throughput stays legitimate, it is just now an N-tenants-wide decision to make on purpose and re-measure.")
//! @yah:verify("cargo test --manifest-path oss/passway/Cargo.toml -p passway --lib = 99 passed / 0 failed after the conf.threads pin. clippy --all-targets: 3 warnings, ALL pre-existing and in files this pass never touched (auth.rs:84 result_unit_err, path.rs:164 manual case-insensitive compare, proxy.rs:263 manual_option_zip); main.rs is clean.")
//! @yah:handoff("OPERATOR FOLLOW-UP 2026-08-15: can per-domain passways go COLD with kamaji spinning them up on demand, since a free host could accumulate 10k idle domains? Answered in W267 section 'Scaling B to a free tier: cold passways behind an SNI demux (sketch, not designed)'. Short form: the idle-COST question dissolves - kamaji's on-demand JIT tier already exists and is proven (R599-F6, oss/kamaji/crates/kamaji/src/jit.rs): kamaji permanently holds the workload's listen socket via SocketCustodian, forks on first connection with the socket as fd 3 under the LISTEN_FDS=1 socket-activation convention, and re-arms when the child self-reaps on idle TTL, with zero dropped connections because pending conns sit in the kernel accept queue. Its own doc: an idle workload 'costs nothing but the held fd'. So 10k cold domains is 10k fds, not 10k processes.")
//! @yah:handoff("THE MISSING PIECE for that shape, and it corrects my own earlier planning note on this ticket: an SNI DEMULTIPLEXER, which does not exist anywhere in the tree (grepped oss/ crates/ app/ for ClientHello / SNI passthrough - zero hits). Cold-start alone does NOT solve :443 contention, because kamaji's JIT still holds one socket per workload and two cannot both be :443 on one IP. What removes the per-domain IP cost is one hot process on :443 that peeks the ClientHello, reads SNI, and SPLICES the raw TCP stream to the right per-domain passway without terminating TLS. That preserves the R777 verdict rather than eroding it - the hot demux holds NO private key and sees NO plaintext, so the cross-tenant-RCE argument is untouched. With a demux, one IP fronts all 10k and IPs stop being the scarce resource; my earlier 'public IPs are the scarce resource' note holds only in the no-demux shape.")
//! @yah:handoff("THREE WALLS at 10k, none of them memory, recorded so a free-tier design starts from them. (1) CERT STORAGE, the hard one: W273/R600-F1 puts cluster secrets in raft WardenState, and oss/yubaba/crates/yubaba/src/raft/store.rs:5 states the assumption outright - 'State is tiny (KB-scale) so we can afford to rewrite the full file on every mutation' - with persist() at line 249 doing exactly that (serde_json::to_string of the whole state) and the snapshot an in-memory Cursor<Vec<u8>> of the same. R600-F1's handoff says 'PEM is a few KB so this stays within the KB-scale snapshot budget'. At 10k domains that is ~40 MB rewritten IN FULL on every single PutSecret, on every node. The assumption breaks; a free tier needs a different cert store, not a bigger raft. (2) FIRST-REQUEST LATENCY: acme::ensure_cert_on_disk blocks startup BEFORE the listener exists, so a cold passway for a never-issued domain stalls a client mid-handshake through a full ACME issuance - issuance must move off the connection path. (3) ACME ISSUANCE RATE for the initial 10k fill - per-account new-order limits, NOT W273's duplicate-SAN bucket, which is a different limit; check Let's Encrypt's current published numbers rather than inheriting W273's.")
//! @yah:handoff("WHAT PASSWAY ITSELF WOULD NEED to ride kamaji's JIT tier - neither half exists today: (a) adopt an inherited fd 3 instead of binding fresh (main.rs calls add_tls_with_settings(&listen, ..), and pingora's only fd-inheritance path is its own SCM_RIGHTS upgrade protocol, not systemd socket activation); (b) self-reap on an idle TTL, since kamaji deliberately does not own idle detection - jit.rs says the runtime does. mesofact-serve already implements both via socket_activation_listener; passway does not. NOTE this is SKETCH ONLY, deliberately not designed and not started under R777 - the spike's own verdict (option B) is unchanged and reinforced by it.")
//! @yah:handoff("FOLLOW-UP FILED: R779 (spike) - 'Free-tier ingress at 10k domains: SNI demux + cold per-domain passway, on-demand TLS, cert store off raft'. Operator corrected this ticket's framing on 2026-08-15: the three items R777 recorded as 'walls' are SOLVED PROBLEMS that hosting companies far below Amazon/Google funding have shipped for years, and calling them walls set the wrong weight. W267's section was rewritten to match - they are three SELECTION decisions, with Caddy/certmagic named as the closest open-source prior art (N unknown domains, cert each, issued on first handshake behind an allowlist gate, pluggable cert storage) which answers two of the three outright. R777's own verdict is unaffected.")

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
