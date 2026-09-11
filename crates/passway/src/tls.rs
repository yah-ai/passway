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
//! [`AlpnPolicy::H2AndHttp11`] — the default — sets ALPN to prefer HTTP/2
//! with HTTP/1.1 as fallback, satisfying V0 MUST #1's "HTTP/1.1+HTTP/2 on a
//! TLS listener". R870-T21 made it opt-OUT per door
//! ([`AlpnPolicy::Http11Only`], `PASSWAY_ALPN=http/1.1`) for a door fronting
//! a protocol that cannot exist over HTTP/2 at all; see [`AlpnPolicy`].
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
//! 3. As soon as the new process has **bound `upgrade_sock`**, the
//!    supervisor sends `SIGQUIT` to the *old* process's pid (read from
//!    `PASSWAY_PID_FILE`).
//! 4. The old process hands its listening fds to the new one over
//!    `upgrade_sock` and drains in-flight connections; the new process —
//!    already running with the fresh cert files ACME wrote — takes over.
//!
//! Step 3 used to read "once the new process logs that it's up (past
//! `server.bootstrap()`)", which is **impossible** — `bootstrap()` is
//! precisely where the replacement blocks waiting to receive, so it is never
//! "up" beforehand. Corrected on R870-T3, which built the supervisor and
//! found out. The window is also small: the receive gives up after
//! `MAX_RETRY`(5) × `RETRY_INTERVAL`(1s) and `Bootstrap` then
//! `std::process::exit(1)`s, so a late `SIGQUIT` kills the replacement.
//! Waiting on the socket path is exact — pingora's receiver creates it on
//! entry and unlinks it on both exits.
//!
//! ## On a systemd door, systemd is that supervisor (R870-T3)
//!
//! And it needs one thing pingora cannot give it: `Type=simple` equates the
//! unit with the pid it exec'd, so the old process's exit at the end of step
//! 4 deactivates the unit and — under the default `KillMode=control-group` —
//! kills the replacement. The drop-in
//! `app/yah/cli/resources/passway-graceful-upgrade.conf` makes the unit
//! `Type=notify` + `NotifyAccess=all` with an `ExecReload=` pointing at
//! `passway-graceful-upgrade`, and [`crate::sd_notify`] sends the
//! `MAINPID=`/`READY=1` datagram that moves systemd's main pid onto the
//! replacement. `systemctl reload <unit>` is then the entire rotation —
//! including the one yubaba's `cert_materialize` runs as
//! `YUBABA_CERT_FILES_RELOAD_CMD`, where the value used to be
//! `systemctl restart` and dropped every connection on :443.
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
//!
//! @yah:ticket(R870-T3, "Zero-downtime cert install on a systemd door: wire the PASSWAY_UPGRADE handoff so a rotation does not drop connections")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-09-06T07:55:53Z)
//! @yah:phase(P2)
//! @yah:parent(R870)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:depends_on(R600-F10)
//! @yah:handoff("SHIPPED. `systemctl reload <unit>` is now a zero-downtime process swap on a systemd passway door. Three pieces: (1) NEW oss/passway/crates/passway/src/sd_notify.rs — the MAINPID=/READY=1 datagram, ~60 lines, no new dependency, inert unless $NOTIFY_SOCKET is set; main.rs sends it just before run_forever(). (2) NEW app/yah/cli/resources/passway-graceful-upgrade — the ExecReload= helper: spawn a replacement with PASSWAY_UPGRADE=true, wait for it to BIND PASSWAY_UPGRADE_SOCK, SIGQUIT the old pid, then block until systemd's MainPID is the replacement. (3) NEW app/yah/cli/resources/passway-graceful-upgrade.conf — the drop-in carrying Type=notify + NotifyAccess=all + ExecReload= + TimeoutStartSec=300 + Restart=always.")
//! @yah:verify("cargo test --manifest-path oss/passway/Cargo.toml -p passway --lib = 138 passed / 0 failed (8 new, sd_notify, incl. a real datagram round-trip through a bound UnixDatagram). --test main = 28 passed. cargo build -p passway --bins clean. cargo clippy -p passway --all-targets = 3 warnings, ALL pre-existing and in files this pass never touched (auth.rs result_unit_err, path.rs case-insensitive compare, proxy.rs manual_option_zip).")
//! @yah:gotcha("THE ONE UNVERIFIED LINK, stated plainly: nothing here has been run against systemd or against Linux. The camp is darwin; pingora's fd transfer is cfg(target_os = \"linux\") and the MAINPID handover needs a real service manager. What IS exercised on darwin: the notify datagram end-to-end against a bound socket, and the helper's four refusal paths run as a real `sh` process (they all exit before anything is spawned). The specific claim I could not test is that systemd accepts a MAINPID= datagram from a process that is not yet the main one, during SERVICE_RELOAD, under NotifyAccess=all. If it does not, the helper times out and says exactly that, and Restart=always turns the torn handoff into a RestartSec blip rather than a dark :443.")
//! @yah:next("ALL THREE FILING BULLETS ARE ANSWERED; they are replaced rather than kept because the first now states the opposite of what shipped. (1) The reload command is `systemctl reload <unit>`, not `systemctl restart` — R600-F10's own next list has been corrected to match. (2) No second handoff path was added: the helper drives pingora's existing upgrade socket, exactly as socket_activation.rs does for LISTEN_FDS, and refuses outright when both are in play. (3) THE COLD PATH NEEDS NONE OF THIS, checked rather than assumed: kamaji's SocketCustodian never releases the listener across a fork (oss/kamaji/crates/kamaji/src/jit.rs module doc — 'does **not** release the socket; it loops back to (1) and re-arms', 'zero dropped connections'), so a cold passway's replacement is a fork against a socket the supervisor still holds. The helper refuses a LISTEN_FDS door and says so in the refusal message; there is one mechanism per tier, not one mechanism built twice.")
//! @yah:handoff("WIDER THAN THE TITLE — four discovered fixes, all in this pass. (a) THE SIGNAL CONTRACT WAS WRONG and had been since R594-F7: both tls.rs and main.rs said the supervisor SIGQUITs 'once the new process is up (past server.bootstrap())', which is impossible — bootstrap() is where the replacement blocks waiting to receive. The real trigger is 'has bound upgrade_sock', and the window is ~5s (MAX_RETRY 5 x RETRY_INTERVAL 1s, then Bootstrap exit(1)s). Corrected at both sites; the helper waits on the socket path, which pingora creates on entry and unlinks on both exits. (b) yubaba cert_materialize.rs: RELOAD_CMD_ENV's doc said 'e.g. systemctl restart passway' — now says reload, and why. (c) THE RELEASE RAIL carries the helper: publish-yubaba-release.sh stages it (the one non-ELF member, outside the ELF assertion loop) + layout assertion; control_plane_install.{sh,rs} install it on its own conditional with a rollback anchor and a content assertion; roll-node.sh keys and asserts its hash like every other member. The DROP-IN deliberately does not ride the roll — it lands in /etc/systemd/system/&lt;unit&gt;.service.d/, the unit name differs per door, and a roll must never rewrite a door's unit configuration; two tests hold that split. (d) roll-node.sh's and control_plane_install.sh's operator-facing text said a restart is the only activation verb; both now name the reload.")
//! @yah:verify("cargo test -p yah --test main camp_systemd_unit_emit = 13 passed (4 new: the drop-in's four directives; the helper's step ORDER — spawn &lt; wait-for-socket &lt; SIGQUIT &lt; wait-for-MainPID; the ships-in-tarball/drop-in-is-node-state split; and the four refusal paths run as a real `sh` process). cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-workload-spec --lib control_plane_install = 12 passed (1 new). cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib cert_materialize = 8 passed. `sh -n` + shellcheck -s sh on the helper: clean. `bash -n` on roll-node.sh and publish-yubaba-release.sh: clean; shellcheck on both reports only pre-existing SC2012/SC2029/SC3040/SC3043 in hunks this pass never touched.")
//! @yah:verify("THE LIVE REHEARSAL, not run, so whoever holds the authorization does not re-derive it. On ONE door, in a window where a blip is acceptable: (1) roll the node so /usr/local/bin/passway-graceful-upgrade and the new passway are present; (2) confirm the door's env pins PASSWAY_UPGRADE_SOCK to a per-instance path — unset it is pingora's shared /tmp/pingora_upgrade.sock and every door runs two passways; (3) install app/yah/cli/resources/passway-graceful-upgrade.conf as /etc/systemd/system/&lt;unit&gt;.service.d/, `systemctl daemon-reload`, then ONE `systemctl restart &lt;unit&gt;` and watch `journalctl -u &lt;unit&gt; -f` for 'passway: notified systemd READY with MAINPID=&lt;pid&gt;' within a second of the listener line — if it is absent, remove the drop-in and daemon-reload before debugging rather than leaving a front door restart-looping; (4) THE ACTUAL TEST: start a slow request against the door (`curl --limit-rate` or a long download), run `systemctl reload &lt;unit&gt;`, and assert three things — the in-flight request completes, no connection is refused during the swap, and `systemctl show -p MainPID` names a NEW pid while `systemctl is-active` stayed active throughout. (5) Only then set YUBABA_CERT_FILES_RELOAD_CMD=`systemctl reload &lt;unit&gt;` in that node's yubaba drop-in.")
//! @yah:gotcha("THE DROP-IN'S OWN PRECONDITION UNDERCOUNTED THE PASSWAYS — corrected in the file 2026-09-08 by @Ashguard:coffee (R600-F10, session:c431ac51), who is a consumer of this conf rather than its author. app/yah/cli/resources/passway-graceful-upgrade.conf said an unset PASSWAY_UPGRADE_SOCK is contended by \"two passways — every live door runs the apex one plus passway-mesh\". It is THREE. Measured, not reasoned: `systemctl list-units --type=service --all \"passway*\"` on us-east-001 (debian@51.81.85.145) returns passway-demux.service, passway-mesh.service AND passway-test.service, all active/running. passway-demux is the one the text missed. So the shared /tmp/pingora_upgrade.sock is contended three ways and a reload is correspondingly likelier to hand its listeners to the wrong process. The conf now says so and tells the installer to COUNT rather than trust the number — south was not counted and must not be assumed to match east. ALSO MEASURED IN THE SAME PASS: there is no /etc/systemd/system/passway*.service.d directory on us-east-001 at all, so no door on that node carries this drop-in and every activation there is still a connection-dropping `systemctl restart`. @Ashguard:libra hit that firsthand during the 2026-09-08 mesh recovery — repointing the mesh doors dropped connections precisely because this conf is not installed on them. The mesh doors are a demonstrated customer for it, not a hypothetical one.")
//! @yah:verify("ACTIVATED AND PROVEN ON BOTH LIVE DOORS 2026-09-08 by @Ashguard:dragon. Drop-in installed at /etc/systemd/system/passway-test.service.d/ (east) and /etc/systemd/system/passway.service.d/ (south); one connection-dropping restart each, both came up Type=notify clean (\"notified systemd READY with MAINPID\"), ACME skipped issuance (cert fresh). Then a REAL reload under load on south: 120 sequential https://yah.dev/ requests against 127.0.0.1:443 while `systemctl reload passway.service` ran. Result 119x200 / 1x503, MainPID 2809164 -> 2809418, unit stayed active. Journal shows the handover working exactly as designed: \"Trying to send socks\" -> \"listener sockets sent\" -> replacement listening on /run/passway-test-upgrade.sock -> SIGQUIT to the old pid -> \"passway.service main pid is now 2809418; 2809164 is draining\". Upgrade socks are pinned per-instance on both nodes (passway-test/passway = /run/passway-test-upgrade.sock, passway-mesh = /run/passway-mesh-upgrade.sock), so the three-way contention this ticket's conf warns about does not apply here.")
//! @yah:gotcha("RELOAD IS ZERO-CONNECTION-DROP BUT NOT ZERO-ERROR: measured 1x503 in 120 requests across a reload on us-south-001, 2026-09-08. Not a torn handover — the listener transfer succeeded and no connection was refused or reset. The 503 comes from the REPLACEMENT process, which starts with an EMPTY upstream set: passway re-runs upstream discovery from scratch on every start (PASSWAY_UPSTREAM_SOURCE=yubaba, polling /service-records?ready=true for ident yah-marketing), so for roughly one second after it takes the socket it is serving with nothing healthy behind it. The old process has already had SIGQUIT by then, so there is nothing to fall back to. Consequence for the thing this drop-in exists for: every unattended cert rotation will emit a short 503 burst on that origin, which is much better than dropping connections but is NOT the \"costs nothing\" the conf header claims. The fix shape is to hold READY=1 / the socket handover until the first upstream health poll has produced at least one ready backend, i.e. make discovery part of the readiness gate rather than a background service started after it.")

use std::net::SocketAddr;

use pingora::listeners::tls::TlsSettings;
use pingora::protocols::ALPN;

/// How passway terminates TLS for its public listener.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// **No TLS at all** — a cleartext HTTP listener, and the one variant
    /// here that is not a trust boundary. Reachable only through
    /// [`parse_listener_tls_mode`], which refuses it on anything but a
    /// loopback bind; see that function for the whole argument.
    Plaintext,
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

/// The env var naming the listener's TLS mode. Three values, spelled below.
pub const TLS_MODE_ENV: &str = "PASSWAY_TLS_MODE";

/// Which of [`TlsMode`]'s three shapes [`TLS_MODE_ENV`] selects, before the
/// cert paths (which `plaintext` does not have) are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerTlsMode {
    /// `PASSWAY_TLS_MODE=plaintext` — [`TlsMode::Plaintext`].
    Plaintext,
    /// Unset, empty, or `manual` — [`TlsMode::Manual`].
    Manual,
    /// `PASSWAY_TLS_MODE=acme` — [`TlsMode::Acme`], configured further by
    /// [`crate::acme::parse_acme_config`].
    Acme,
}

/// Decide the listener's TLS mode, and refuse a cleartext one anywhere it
/// would be a trust boundary (R870-F23).
///
/// ## Why passway has a cleartext mode at all
///
/// R870's *inner door* is a passway process a service runs in front of its
/// own components, on loopback, behind that service's public door. It exists
/// to do one thing the public door cannot: split one hostname across several
/// independently-deployed units by URL path. It is not reachable from the
/// network, and the hop it terminates has already been decrypted by the
/// public door one process earlier on the same box.
///
/// Before this, `main()` terminated TLS unconditionally, so an inner door
/// needed a certificate for `127.0.0.1`. That is worse than it sounds, and
/// the reason is measurable rather than aesthetic: **no CA issues for a
/// loopback address**, so the cert has to be self-signed — and pingora's
/// `HttpPeer` defaults to `verify_cert: true`
/// (`pingora-core-0.8.1/src/upstreams/peer.rs:479`), which passway never
/// overrides. So "keep TLS everywhere" does not buy safety here; it buys a
/// second, *worse* change — a way to switch off upstream certificate
/// verification on a public-facing door, which is a real trust-boundary knob,
/// in exchange for encrypting a hop that never leaves the loopback interface.
/// Operator call, 2026-09-09: take the cleartext loopback listener instead.
///
/// ## The invariant, and why it is checked here rather than documented
///
/// A cleartext mode is only ever safe because of a property of the *bind
/// address*, and an operator remembering not to misconfigure it is not a
/// property. So this function refuses, at boot, every combination that would
/// put cleartext where something other than the local machine could reach it:
///
/// - the bind must be a literal loopback socket address (`127.0.0.0/8`,
///   `::1`). `0.0.0.0:443` — the default — is refused, and so is a name this
///   function cannot resolve to an address it can inspect;
/// - `PASSWAY_TLS_CERT` / `PASSWAY_TLS_KEY` must be unset, so a door that was
///   configured as a public one does not become cleartext by adding a
///   variable rather than by removing two;
/// - socket activation (`LISTEN_FDS`) is refused outright: the socket was
///   bound by the supervisor, so `PASSWAY_LISTEN` is a *lookup key* there and
///   not evidence of what the listener is actually bound to — the invariant
///   would be unverifiable exactly where it matters most.
///
/// Each of those is a boot failure naming what to change. None of them is a
/// warning: a door that half-honours this would serve cleartext publicly,
/// which is the single outcome the mode must not be able to produce.
pub fn parse_listener_tls_mode(
    get: impl Fn(&str) -> Option<String>,
    listen: &str,
) -> Result<ListenerTlsMode, String> {
    let raw = get(TLS_MODE_ENV).unwrap_or_default();
    match raw.trim() {
        "" | "manual" => return Ok(ListenerTlsMode::Manual),
        "acme" => return Ok(ListenerTlsMode::Acme),
        "plaintext" => {}
        other => {
            return Err(format!(
                "{TLS_MODE_ENV} {other:?}: expected `manual` (the default — leave it unset), \
                 `acme`, or `plaintext` (a loopback-only inner door, see \
                 PASSWAY_PATH_ROUTES_FILE)"
            ))
        }
    }

    if get("LISTEN_FDS").is_some() {
        return Err(format!(
            "{TLS_MODE_ENV}=plaintext with LISTEN_FDS set: the listening socket was bound by \
             the supervisor, so PASSWAY_LISTEN is only the key this process looks it up by and \
             proves nothing about what it is bound to. A cleartext listener is allowed solely \
             because its bind is loopback, and that cannot be checked here — start this door \
             without socket activation, or terminate TLS on it"
        ));
    }

    for var in ["PASSWAY_TLS_CERT", "PASSWAY_TLS_KEY"] {
        if get(var).is_some_and(|v| !v.trim().is_empty()) {
            return Err(format!(
                "{TLS_MODE_ENV}=plaintext but {var} is also set — a door configured to serve a \
                 certificate must not become cleartext by ADDING one variable. Unset {var} (and \
                 its pair) if this really is a loopback inner door; otherwise drop \
                 {TLS_MODE_ENV}"
            ));
        }
    }

    let addr: SocketAddr = listen.parse().map_err(|_| {
        format!(
            "{TLS_MODE_ENV}=plaintext but PASSWAY_LISTEN {listen:?} is not a literal socket \
             address, so this process cannot prove the bind is loopback. Write it as an IP and \
             port — `127.0.0.1:<port>` or `[::1]:<port>`"
        )
    })?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "{TLS_MODE_ENV}=plaintext but PASSWAY_LISTEN {listen:?} is not loopback. Cleartext \
             is allowed only on a listener nothing off this machine can reach; bind \
             `127.0.0.1:<port>` or `[::1]:<port>`, or terminate TLS on this door"
        ));
    }
    Ok(ListenerTlsMode::Plaintext)
}

/// The env var a door sets to narrow its ALPN offer. See [`AlpnPolicy`].
pub const ALPN_ENV: &str = "PASSWAY_ALPN";

/// Which application protocols a door offers in the TLS handshake.
///
/// ## Why this is opt-OUT and not a uniform "always h2" (R870-T21)
///
/// HTTP/2 has no upgrade mechanism *at all*. RFC 9113 §8.2.2 forbids the
/// `Connection` and `Upgrade` headers outright, so a protocol that is
/// negotiated by an HTTP/1.1 `Upgrade:` handshake — Tailscale's TS2021
/// (`Upgrade: tailscale-control-protocol`), and WebSocket's RFC 6455 form —
/// **cannot be carried over an h2 connection**, no matter what passway does
/// with hop-by-hop headers downstream of the handshake. There is no fallback
/// once ALPN has picked `h2`: the request arrives at the upstream stripped of
/// the very header that defines it.
///
/// That asymmetry cost real diagnosis time on 2026-09-09. It is not that an
/// h2 client *fails* — it is that its failure is byte-for-byte
/// indistinguishable from the three-day mesh outage R870-B14 had just fixed:
/// the same `No Upgrade header in TS2021 request` line in headscale's stderr,
/// the same 500. The A/B that settles it is per-origin `curl --http1.1` vs
/// default; a rolling courier had to run it to discover its own probe was the
/// thing generating the log lines it was using as the health signal.
///
/// So the door that grants meshes offers [`AlpnPolicy::Http11Only`]: a client
/// there can only negotiate the one protocol TS2021 can actually use, and the
/// ambiguous failure mode does not exist to be diagnosed. Every other door
/// keeps the default — h2 is a real win for ordinary web traffic and nothing
/// about this makes it wrong there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlpnPolicy {
    /// `h2` preferred, `http/1.1` accepted. The default, and correct for every
    /// door fronting ordinary web traffic.
    #[default]
    H2AndHttp11,
    /// `http/1.1` only. For a door fronting a protocol that only exists over
    /// HTTP/1.1 — see this type's doc. An h2-only client is then refused
    /// during the handshake (rustls answers `no_application_protocol`)
    /// instead of reaching the upstream with its `Upgrade:` header gone.
    Http11Only,
}

impl AlpnPolicy {
    /// The pingora ALPN offer this policy installs on the listener.
    pub fn alpn(self) -> ALPN {
        match self {
            AlpnPolicy::H2AndHttp11 => ALPN::H2H1,
            AlpnPolicy::Http11Only => ALPN::H1,
        }
    }
}

/// Read [`ALPN_ENV`]. Unset or empty is [`AlpnPolicy::H2AndHttp11`], which is
/// the pre-R870-T21 behaviour exactly.
///
/// Exactly two values are accepted, spelled as the ALPN protocol identifiers
/// that go on the wire so the env file needs no glossary. An unrecognized
/// value is a boot failure rather than a silent fallback to the default: a
/// typo'd opt-out that quietly leaves h2 on is the failure this whole
/// mechanism exists to remove.
pub fn parse_alpn_policy(get: impl Fn(&str) -> Option<String>) -> Result<AlpnPolicy, String> {
    let Some(raw) = get(ALPN_ENV).filter(|s| !s.trim().is_empty()) else {
        return Ok(AlpnPolicy::default());
    };
    let normalized: Vec<String> = raw
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    match normalized
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["h2", "http/1.1"] => Ok(AlpnPolicy::H2AndHttp11),
        ["http/1.1"] => Ok(AlpnPolicy::Http11Only),
        _ => Err(format!(
            "{ALPN_ENV} {raw:?}: expected `h2,http/1.1` (the default — leave it unset) or \
             `http/1.1` (opt out of HTTP/2 on a door whose protocol needs an HTTP/1.1 \
             `Upgrade:` handshake). Offering `h2` alone is deliberately not accepted: it \
             refuses every ordinary HTTP/1.1 client."
        )),
    }
}

/// Build a rustls-backed [`TlsSettings`] for `mode`, offering the ALPN
/// protocols `alpn` names (V0 MUST #1: HTTP/1.1 **and** HTTP/2 on the TLS
/// listener — narrowed per door by R870-T21, see [`AlpnPolicy`]).
///
/// `Manual` and `Acme` are handled identically here on purpose — see this
/// module's doc for why the ACME automation can't and doesn't reach this
/// function at all; it only ever sees "read this cert_path/key_path pair".
///
/// @yah:ticket(R870-T21, "passway-mesh advertises h2 in ALPN, but TS2021 can only ever work over HTTP/1.1")
/// @yah:status(review)
/// @yah:at(2026-09-09T08:30:39Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R870)
/// @yah:severity(low)
/// @yah:next("DECIDE WHETHER THIS IS A BUG AT ALL - it may be correct HTTP/2 semantics rather than a defect, and that is the first question. Option A: leave it, document the h2/HTTP-1.1 asymmetry at the enable_h2 call site so the next diagnostician does not lose ten minutes to it. Option B: make h2 opt-out per door and disable it on passway-mesh, so a mesh client can only ever negotiate the protocol TS2021 actually needs. Option C: nothing, on the grounds that no real client does this.")
/// @yah:verify("Reproduce per-origin with --resolve, never through round-robin DNS: curl --http1.1 vs default against https://cloud.mesh.yah.dev/ts2021 with Upgrade + Connection headers, sampling headscale's No-Upgrade count on us-south-001 either side. Expect delta 0 for --http1.1 and delta 1 per request for h2.")
/// @yah:gotcha("MEASURED 2026-09-09 during the R870-B14 roll, and it cost real diagnosis time. build_tls_settings calls settings.enable_h2() unconditionally (tls.rs:240), so EVERY door including passway-mesh offers h2 ahead of http/1.1 in ALPN. HTTP/2 has no Upgrade mechanism at all - RFC 9113 8.2.2 forbids the Connection and Upgrade headers outright - so a client that negotiates h2 to cloud.mesh.yah.dev cannot carry a TS2021 upgrade offer no matter what passway does with hop-by-hop headers. Proven per-origin: the same POST with Upgrade: tailscale-control-protocol + Connection: upgrade returns 500 over h2 and 400 over --http1.1, and only the h2 form adds a `No Upgrade header in TS2021 request` line to headscale's stderr. THIS IS NOT AN R870-B14 REGRESSION and does not affect the fleet: real tailscaled speaks HTTP/1.1 for TS2021, which is why every node re-registered within seconds of the B14 roll. It is a latent seam on the door that grants meshes, and it makes an h2 client's failure indistinguishable from the three-day outage B14 just fixed.")
/// @yah:handoff("DECIDED AND SHIPPED: option B, with option A's documentation folded in. Leader's call, recorded because the ticket asked 'is this a bug at all' first: it is not a broken client (real tailscaled speaks HTTP/1.1 for TS2021), it is an AMBIGUITY — an h2 client's failure is byte-for-byte the three-day outage R870-B14 just fixed, same `No Upgrade header in TS2021 request` line, same 500. A comment only helps whoever reads it; making the mesh door incapable of negotiating h2 removes the failure mode structurally. WHAT LANDED, four files, all uncommitted in the working tree at anchor e714a29f: (1) oss/passway/crates/passway/src/tls.rs — new `AlpnPolicy` enum (H2AndHttp11 = Default, Http11Only), `ALPN_ENV`/`parse_alpn_policy`, and `build_tls_settings(mode, alpn)` now takes the policy and calls `settings.set_alpn(alpn.alpn())` instead of the unconditional `enable_h2()`. Signature changed rather than a parallel constructor added, per the below-v1.0.0 rule; there is exactly ONE call site tree-wide (grepped) and it is fixed. (2) src/main.rs — env-table row + parse + pass-through. (3) app/yah/cli/resources/passway-mesh.env — `PASSWAY_ALPN=http/1.1` with the RFC-9113 reason and an explicit 'do NOT copy this to an apex or tenant door'. (4) app/yah/cli/tests/camp_systemd_unit_emit.rs — the template contract test now asserts it.")
/// @yah:handoff("VERIFIED FIRST, as instructed: passway-mesh IS a dedicated instance fronting only the mesh control plane, on all three doors, so turning h2 off there is not a regression for any web client. Read live 2026-09-09, not inferred: /etc/passway-mesh.env on us-east-001 (debian@51.81.85.145), us-south-001 (root@45.32.194.254) and us-west-001 (debian@15.204.89.240) each declare exactly ONE upstream key, `PASSWAY_UPSTREAMS=cloud.mesh.yah.dev=<addr>` (east+west -> 45.32.194.254:443 remote, south -> 127.0.0.1:8080 co-located), on loopback :8444. Ordinary web traffic is on OTHER processes entirely — each node runs 6 passways (passway-demux, passway-http-router, passway-mesh, passway-noisetable, passway-scrabcake, and passway.service/passway-test.service). The demux routes file on south (/var/lib/passway/routes/demux.routes) sends only the exact SNI `cloud.mesh.yah.dev` to :8444; `*.yah.dev` goes to the apex on :8443, so even the door's second SAN `<node>.origin.yah.dev` never lands here.")
/// @yah:handoff("AND THE ONE THING THAT COULD HAVE MADE THIS WRONG, checked rather than assumed: headscale's gRPC API needs HTTP/2, and killing h2 in front of it would break it. It is NOT behind this door — /var/lib/yah-cloud/headscale/config.yaml on us-south-001 has `listen_addr: 127.0.0.1:8080` (the door's only upstream) but `grpc_listen_addr: 127.0.0.1:50443` and `metrics_listen_addr: 127.0.0.1:9090`, neither of which the door or the demux ever reaches. Embedded DERP is `derp.server.enabled: false`, so TS2021 is the only Upgrade-based protocol behind this door at all. Nothing behind passway-mesh consumes h2.")
/// @yah:verify("cargo test --manifest-path oss/passway/Cargo.toml -p passway --lib = 197 passed / 0 failed, 6 of them new in tls::tests. The opt-out is tested over the pure settings-construction path with no live door: default-when-unset (the assertion that makes this opt-OUT rather than a behaviour change for every existing door), empty/whitespace = default, `http/1.1` -> AlpnPolicy::Http11Only -> ALPN::H1, the explicit `h2,http/1.1` spelling incl. whitespace and case, and unrecognized values (`h2` alone, `http/1.0`, `http/1.1,h2`, `,`) rejected as a boot failure rather than silently falling back to the default. cargo build -p passway --bins clean. cargo clippy -p passway --lib --bins = 3 warnings, ALL pre-existing and in files this pass never touched (auth.rs result_unit_err, path.rs manual case-insensitive compare, proxy.rs manual_option_zip). cargo test -p yah --test main camp_systemd_unit_emit = 14 passed / 0 failed (1 new assertion inside the_mesh_front_door_is_enabled_loopback_only_and_owns_no_second_port).")
/// @yah:verify("THE 258/0 BASELINE COULD NOT BE MATCHED AS A NUMBER, and the reason is a peer's file, not my change — stated plainly rather than reported as a pass. `cargo test -p passway` (all targets) FAILS TO BUILD the `main` integration target: oss/passway/crates/passway/tests/path_routes_file.rs, untracked and mid-flight from @Glimmerstone:griffin (R870-T18), does not compile — error[E0509] `cannot move out of type Door, which implements the Drop trait` at :259:61 and :294:61 (`door.0.wait_with_output()`, door.0 being a tokio::process::Child). I did not touch it: my diff is src/tls.rs, src/main.rs, and two files under app/yah/cli/, nothing under passway/tests/. So the 43+32 integration halves of the baseline are UNRUN by me; the 183->197 lib half is green and includes peers' 8 new lib tests plus my 6. Told @Glimmerstone:griffin directly via party.chat with the exact error. Re-run `cargo test --manifest-path oss/passway/Cargo.toml -p passway` once T18 lands to close the baseline out.")
/// @yah:verify("THE LIVE A/B IN THIS TICKET'S OWN verify WAS DELIBERATELY NOT RE-RUN, and the health signal is untouched. The R870-B14 courier already measured it (500 over h2 / 400 over --http1.1, +1 No-Upgrade line per h2 request) and this change is UNROLLED, so re-running would have proven nothing new while dirtying the exact counter the operator is using as the mesh-health assertion. Instead I confirmed the premise with a probe that generates NO HTTP request at all: `openssl s_client -connect <door ip>:443 -servername cloud.mesh.yah.dev -alpn h2,http/1.1 </dev/null`, per-origin against all three door IPs. All three answer `ALPN protocol: h2` with subject=/CN=cloud.mesh.yah.dev — the premise, confirmed on every door rather than one. COUNTER LEFT WHERE I FOUND IT: /var/lib/yah/kamaji/native/headscale/stderr.log on us-south-001 read 5313 with last line 2026-09-09T08:02:27Z before my probes and 5313 with the same last line after. ZERO of those 5313 lines are mine. (Note for the next sampler: the count is in that kamaji log file, not in journalctl — headscale is a kamaji workload here, not a systemd unit, and `journalctl | grep -c` returns 0.) POST-ROLL, the same openssl probe is the check: `-alpn h2` alone should FAIL the handshake with no_application_protocol, and `-alpn h2,http/1.1` should answer `http/1.1`.")
/// @yah:gotcha("UNROLLED, DELIBERATELY — this is source-only and NOTHING on the fleet has changed. Operator's call: the three doors were already rolled twice on 2026-09-09 (R870-T10's holding reader as hotship 0.8.36-h10, then R870-B14's Upgrade fix as passway sha da64b48e built from anchor 5f4c7b8b plus hardening.rs), the mesh had been healthy under an hour, and a third same-day roll of the door that grants meshes is not worth a low-severity latent seam. All three doors still answer `ALPN protocol: h2` for cloud.mesh.yah.dev as of this writing.")
/// @yah:gotcha("WHAT ROLLING IT WOULD TAKE, and the trap in doing it half-way. It is TWO changes and the env one alone is a SILENT NO-OP: a passway that predates this commit does not read PASSWAY_ALPN at all, so setting `PASSWAY_ALPN=http/1.1` in /etc/passway-mesh.env on a door running today's binary changes nothing and looks done. Both halves, per door (east debian@51.81.85.145, south root@45.32.194.254, west debian@15.204.89.240): (1) build passway from this source and ship the binary; (2) add `PASSWAY_ALPN=http/1.1` to /etc/passway-mesh.env — the line and its rationale are already in the template at app/yah/cli/resources/passway-mesh.env, which is what the doors are rendered from; (3) activate. Verify per-origin with the zero-traffic probe in this ticket's verify list, NOT with an HTTP request. Rollback is deleting the env line and activating again — the new binary with PASSWAY_ALPN unset is byte-identical in behaviour to the old one, which is the whole point of making it opt-out.")
/// @yah:gotcha("HOW THIS INTERACTS WITH THE STANDING R870-T3 GAP, which I was told not to pick up and did not: passway-mesh carries no T3 drop-in on ANY door (re-measured by the B14 courier, noted at tls.rs:203 — there is no /etc/systemd/system/passway-mesh.service.d/ anywhere), so activating step (3) above is a connection-DROPPING `systemctl restart passway-mesh`, not a `systemctl reload`. That is the interaction: with the T3 drop-in installed this roll would be a zero-drop reload of the door that grants meshes; without it, every future ALPN or cert change on that door costs a restart. It does not block this change — an ALPN change needs a new process either way — it just sets the price of landing it. Installing the drop-in is still its own restart plus a Type=notify conversion, and remains out of scope here.")
/// @yah:gotcha("A DESIGN POINT WORTH NOT RE-LITIGATING: `parse_alpn_policy` rejects `h2` alone and rejects `http/1.1,h2`. The first is rejected because an h2-only door refuses every ordinary HTTP/1.1 client; the second because it would be a genuinely different offer (http/1.1 preferred) that pingora's ALPN enum cannot express — accepting it as a synonym for the default would be a lie in the config file. An unrecognized value is a boot panic rather than a fallback to the default, because a typo'd opt-out that quietly leaves h2 on reintroduces exactly the indistinguishable failure this ticket exists to remove.")
/// @yah:verify("LEADER CLOSING THE UNRUN BASELINE (session:abde2cbb, 2026-09-09). This ticket honestly reported that it could not match the 258/0 passway baseline because oss/passway/crates/passway/tests/path_routes_file.rs (untracked, mid-flight from R870-T18) failed to build with error[E0509] cannot move out of type Door, and that the 43+32 integration halves were therefore UNRUN. That is now closed with evidence this ticket did not have: after T18 landed, I ran cargo test --manifest-path oss/passway/Cargo.toml -p passway myself and got 197 lib + 43 + 35 integration = 275 passed / 0 failed. So the integration targets do build, the halves this ticket left unrun are green, and the 197 lib figure it did report is confirmed inside a fully-building suite. Nothing here needed re-doing; the gap was a peer timing artifact, exactly as diagnosed.")
/// @yah:verify("LEADER CONTENT VERIFICATION (session:abde2cbb): the opt-out landed as described — `pub enum AlpnPolicy` at oss/passway/crates/passway/src/tls.rs:262 and `pub fn parse_alpn_policy` at :292, i.e. a changed signature rather than a parallel constructor beside the old unconditional enable_h2(), which is what the below-v1.0.0 rule asked for. Combined with my earlier run of the full passway suite at 275 passed / 0 failed, this ticket is verified on both axes despite its own baseline having been blocked by a peer timing artifact at the time it ran.")
pub fn build_tls_settings(mode: &TlsMode, alpn: AlpnPolicy) -> pingora::Result<TlsSettings> {
    let (cert_path, key_path) = match mode {
        // Unreachable through `main()`, which branches on the variant before
        // it gets here (a plaintext listener is `add_tcp`, not
        // `add_tls_with_settings`). An `Err` rather than a panic so a future
        // caller that gets the branch wrong fails to *start* with the reason,
        // which is the same outcome every other error on this path has.
        TlsMode::Plaintext => {
            return Err(pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "build_tls_settings called on TlsMode::Plaintext — a cleartext listener has no \
                 certificate to build settings from; the caller should have added a plain TCP \
                 listener instead",
            ))
        }
        TlsMode::Manual { cert_path, key_path } => (cert_path, key_path),
        TlsMode::Acme { cert_path, key_path } => (cert_path, key_path),
    };
    let mut settings = TlsSettings::intermediate(cert_path, key_path)?;
    // `set_alpn(ALPN::H2H1)` is exactly what `enable_h2()` does (pingora-core
    // 0.8.1 `listeners/tls/rustls/mod.rs`); going through `set_alpn` is what
    // makes the H1-only case expressible at all.
    settings.set_alpn(alpn.alpn());
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An env getter over a fixed `(key, value)` table — nothing else is set.
    fn env<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    const LOOPBACK: &str = "127.0.0.1:8443";

    #[test]
    fn an_unset_tls_mode_is_manual_and_the_public_default_bind_stays_allowed() {
        // The assertion that makes R870-F23 opt-IN: every door on the fleet
        // today leaves PASSWAY_TLS_MODE unset, on 0.0.0.0:443, and must be
        // unaffected — including by the loopback guard, which must not run.
        assert_eq!(
            parse_listener_tls_mode(env(&[]), "0.0.0.0:443").unwrap(),
            ListenerTlsMode::Manual
        );
        assert_eq!(
            parse_listener_tls_mode(env(&[("PASSWAY_TLS_MODE", "manual")]), "0.0.0.0:443").unwrap(),
            ListenerTlsMode::Manual
        );
        assert_eq!(
            parse_listener_tls_mode(env(&[("PASSWAY_TLS_MODE", "acme")]), "0.0.0.0:443").unwrap(),
            ListenerTlsMode::Acme
        );
    }

    #[test]
    fn plaintext_is_accepted_on_a_loopback_bind_in_both_families() {
        for listen in [LOOPBACK, "127.0.0.2:9000", "[::1]:8443"] {
            assert_eq!(
                parse_listener_tls_mode(env(&[("PASSWAY_TLS_MODE", "plaintext")]), listen).unwrap(),
                ListenerTlsMode::Plaintext,
                "{listen} is loopback"
            );
        }
    }

    #[test]
    fn plaintext_on_a_reachable_bind_is_a_boot_failure() {
        // The invariant the mode exists under. `0.0.0.0:443` is the DEFAULT
        // bind, so this is the exact misconfiguration a door would fall into
        // by setting one variable and forgetting the other.
        for listen in ["0.0.0.0:443", "0.0.0.0:8443", "10.0.0.4:8443", "[::]:443"] {
            let err = parse_listener_tls_mode(env(&[("PASSWAY_TLS_MODE", "plaintext")]), listen)
                .expect_err("{listen} is publicly reachable");
            assert!(err.contains("not loopback"), "{listen}: {err}");
        }
    }

    #[test]
    fn plaintext_on_an_unparseable_bind_is_refused_rather_than_resolved() {
        // A hostname could resolve to a loopback address, or could not, and
        // this process is not the place that finds out. Refuse: the mode is
        // safe only when the bind is *provably* loopback.
        for listen in ["localhost:8443", "inner.local:8443", "8443"] {
            let err = parse_listener_tls_mode(env(&[("PASSWAY_TLS_MODE", "plaintext")]), listen)
                .expect_err("not a literal socket address");
            assert!(err.contains("not a literal socket address"), "{listen}: {err}");
        }
    }

    #[test]
    fn plaintext_beside_a_configured_certificate_is_refused() {
        for var in ["PASSWAY_TLS_CERT", "PASSWAY_TLS_KEY"] {
            let err = parse_listener_tls_mode(
                env(&[("PASSWAY_TLS_MODE", "plaintext"), (var, "/etc/passway/tenant.crt")]),
                LOOPBACK,
            )
            .expect_err("a door with a cert must not go cleartext by adding a variable");
            assert!(err.contains(var), "{var}: {err}");
        }
    }

    #[test]
    fn plaintext_under_socket_activation_is_refused_because_the_bind_is_unprovable() {
        let err = parse_listener_tls_mode(
            env(&[("PASSWAY_TLS_MODE", "plaintext"), ("LISTEN_FDS", "1")]),
            LOOPBACK,
        )
        .expect_err("PASSWAY_LISTEN is only a lookup key under LISTEN_FDS");
        assert!(err.contains("LISTEN_FDS"), "{err}");
    }

    #[test]
    fn a_misspelled_tls_mode_is_a_boot_failure_not_a_silent_manual() {
        for raw in ["plaintxt", "PLAINTEXT", "none", "cleartext", "http"] {
            let err = parse_listener_tls_mode(env(&[("PASSWAY_TLS_MODE", raw)]), LOOPBACK)
                .expect_err("unrecognized mode");
            assert!(err.contains("expected `manual`"), "{raw}: {err}");
        }
    }

    #[test]
    fn build_tls_settings_refuses_the_plaintext_variant_rather_than_panicking() {
        assert!(build_tls_settings(&TlsMode::Plaintext, AlpnPolicy::default()).is_err());
    }

    /// An env getter where [`ALPN_ENV`] holds `value` and nothing else is set.
    fn alpn_env(value: Option<&'static str>) -> impl Fn(&str) -> Option<String> {
        move |k: &str| {
            (k == ALPN_ENV)
                .then_some(value)
                .flatten()
                .map(str::to_string)
        }
    }

    #[test]
    fn the_default_is_h2_with_http11_fallback() {
        // Every existing door is unset, and must keep the exact pre-R870-T21
        // offer. This is the assertion that makes the change opt-OUT.
        assert_eq!(parse_alpn_policy(alpn_env(None)).unwrap(), AlpnPolicy::H2AndHttp11);
        assert_eq!(AlpnPolicy::default(), AlpnPolicy::H2AndHttp11);
        assert_eq!(AlpnPolicy::H2AndHttp11.alpn(), ALPN::H2H1);
    }

    #[test]
    fn an_empty_value_is_the_default_not_an_error() {
        // A systemd EnvironmentFile line left as `PASSWAY_ALPN=` is absence.
        for raw in ["", "   ", "\t\n"] {
            assert_eq!(
                parse_alpn_policy(alpn_env(Some(raw))).unwrap(),
                AlpnPolicy::H2AndHttp11,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_door_can_opt_out_of_h2() {
        // The whole point: the mesh door offers ONLY http/1.1, so a client
        // there cannot negotiate a protocol TS2021 can never use.
        let policy = parse_alpn_policy(alpn_env(Some("http/1.1"))).unwrap();
        assert_eq!(policy, AlpnPolicy::Http11Only);
        assert_eq!(policy.alpn(), ALPN::H1);
    }

    #[test]
    fn the_default_can_also_be_spelled_out_explicitly() {
        for raw in ["h2,http/1.1", " h2 , http/1.1 ", "H2,HTTP/1.1"] {
            assert_eq!(
                parse_alpn_policy(alpn_env(Some(raw))).unwrap(),
                AlpnPolicy::H2AndHttp11,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn an_unrecognized_value_is_a_boot_failure_not_a_silent_default() {
        // A typo'd opt-out that quietly leaves h2 on would reintroduce the
        // exact indistinguishable failure this ticket removes — and `h2`
        // alone is rejected because it refuses every HTTP/1.1 client.
        // `,` is in this list on purpose: it is a typo, not absence. Only a
        // wholly blank value reads as "the operator did not set this".
        for raw in ["http/1.0", "h2", "http/1.1,h2", "none", "true", ","] {
            let err = parse_alpn_policy(alpn_env(Some(raw))).unwrap_err();
            assert!(err.contains(ALPN_ENV) && err.contains(raw), "{raw:?}: {err}");
        }
    }

    #[test]
    fn ordering_is_not_a_free_synonym() {
        // `http/1.1,h2` would be a DIFFERENT offer (http/1.1 preferred), and
        // pingora's ALPN enum cannot express it. Rejected rather than
        // silently treated as the h2-preferring default.
        assert!(parse_alpn_policy(alpn_env(Some("http/1.1,h2"))).is_err());
    }
}
