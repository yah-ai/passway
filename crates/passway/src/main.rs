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
//! | `PASSWAY_UPSTREAMS` | comma-separated backend list, optionally `<hostname>=` prefixed to give each fronted service its own set. R858-T1: honoured under `PASSWAY_UPSTREAM_SOURCE=yubaba` too, as a static pin that beats discovery for the hostnames it names | empty (fail-ready 503) |
//! | `PASSWAY_YUBABA_URL` | base URL of the yubaba to discover upstreams from, e.g. `http://100.64.0.2:7443`. R844-F23: optionally `<hostname>=` prefixed, and repeating a hostname ADDS a yubaba — one per node the workload is placed on | required if `PASSWAY_UPSTREAM_SOURCE=yubaba` |
//! | `PASSWAY_YUBABA_IDENT` | R844-B6: workload ident whose service records become this proxy's backends. A node hosts several workloads and the endpoint answers for all of them, so without this passway would adopt every Ready record on the node. R844-F20: optionally `<hostname>=` prefixed, exactly like `PASSWAY_UPSTREAMS`, to give each fronted hostname its own discovered set | required if `PASSWAY_UPSTREAM_SOURCE=yubaba` |
//! | `PASSWAY_YUBABA_TIMEOUT_SECS` | per-request timeout for a discovery poll | `5` |
//! | `PASSWAY_UPSTREAM_TLS` | speak TLS to upstreams. Bare `true`/`false` is the process-wide default; R858-T1 also accepts the `<hostname>=` fan-in form (`cloud.mesh.yah.dev=true,*=false`) to give one fronted service its own scheme. An unrecognized value is a boot failure, not `false` | `false` (mesh is already encrypted) |
//! | `PASSWAY_UPSTREAM_SNI` | SNI to present when upstream TLS is on. Bare string (process-wide) or the same `<hostname>=` fan-in form | empty |
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
//! ## A hostname may be discovered from SEVERAL yubabas (R844-F23)
//!
//! Per-host discovery still could not front a workload placed on more than one
//! node, because `PASSWAY_YUBABA_URL` named exactly one yubaba for the whole
//! door and a yubaba's service records are strictly node-local (R844-B11). The
//! records for a two-node placement live in two stores; one poll sees one of
//! them and the other half of the fleet is invisible.
//!
//! The operator settled this on 2026-09-04 (W267): **poll N, don't replicate.**
//! Discovery stays node-local and raft grows no service-record map; instead
//! `PASSWAY_YUBABA_URL` takes the same `<hostname>=` fan-in grammar, and
//! **repeating a hostname ADDS a URL**, exactly as it does in
//! `PASSWAY_UPSTREAMS`:
//!
//! ```text
//! PASSWAY_YUBABA_URL=yah.dev=http://100.64.0.3:7443,\
//!                    yah.dev=http://100.64.0.2:7443
//! PASSWAY_YUBABA_IDENT=yah.dev=yah-marketing
//! ```
//!
//! The door polls each, unions the records matching that hostname's ident, and
//! hands the union to the same per-host round-robin and `TcpHealthCheck` as
//! before. A poll that fails holds **that node's** last-known-good set and
//! still unions it with its peers' fresh answers — see `discovery.rs`, where
//! the rule and its two failure modes are stated in full.
//!
//! `PASSWAY_YUBABA_IDENT` is untouched by this: still one ident per hostname,
//! still an error to repeat one. N URLs is a set, N idents is a guess.
//!
//! A bare `PASSWAY_YUBABA_URL=http://host:7443` remains the catch-all every
//! hostname falls back to, so every deployed door is unchanged, and
//! `*=http://host:7443` says it on purpose. Mixing bare and prefixed entries is
//! rejected for the reason it is everywhere else.
//!
//! ## One door, two upstream schemes, two upstream sources (R858-T1)
//!
//! Putting the headscale coordination server behind a passway front door broke
//! two assumptions at once, both of which were "the whole door does this":
//!
//! **How to reach the upstream.** Headscale terminates its own Let's Encrypt
//! TLS on :443, so `cloud.mesh.yah.dev` needs `tls=true` with its own SNI,
//! while the bundle upstream on the same door is plain HTTP on a
//! kamaji-allocated port. `PASSWAY_UPSTREAM_TLS` / `PASSWAY_UPSTREAM_SNI`
//! therefore take the same `<hostname>=` fan-in grammar as everything else:
//!
//! ```text
//! PASSWAY_UPSTREAM_TLS=cloud.mesh.yah.dev=true,*=false
//! PASSWAY_UPSTREAM_SNI=cloud.mesh.yah.dev=cloud.mesh.yah.dev
//! ```
//!
//! The bare form (`PASSWAY_UPSTREAM_TLS=true`) still means what it always did
//! — the default for every set that names no scheme of its own — so no
//! deployed door changes behavior. The one difference from the other fan-in
//! variables: a bare entry here is the *process-wide default*, not the
//! catch-all set's value, because that is what the bare form has always meant.
//! `*=<value>` names the catch-all set specifically.
//!
//! **Where the addresses come from.** `PASSWAY_UPSTREAM_SOURCE=yubaba` now
//! honours a non-empty `PASSWAY_UPSTREAMS` alongside discovery, merged per
//! hostname. This is not a fallback: a yubaba's service records are strictly
//! per-node (R844-B11 — a record's `mesh_ip` must equal the answering node's
//! own mesh address), so a door polling its local yubaba can never discover a
//! workload placed on another node. Such an upstream is pinned statically,
//! resolved at the control plane, while every other hostname on the same door
//! keeps following placement. On a hostname both name, **the static pin wins**
//! and the pinned hostname is logged as a warning — an explicit operator pin
//! beating an inferred one is the least surprising rule, and it is the only
//! direction that leaves an override possible at all.
//! `PASSWAY_UPSTREAM_SOURCE=static` ignores the discovery variables exactly as
//! before.
//!
//! @yah:relay(R853, "R779 outward actions: publish the pingora fork upstream, put the demux on :443 in front of the live origins, and settle the ACME order budget")
//! @yah:at(2026-09-03T06:33:30Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Split out of R779 at its P8 close-out. R779's code is complete and verified; these three are the actions that make it REACH the world, and every one of them is outward-facing (a public PR, a change to live yah.dev origins, a request to a third party) rather than something a session should do unsupervised. They were sitting as @yah:next prose on R779, which would have been stripped from source when R779 archived — filed as real tickets so they survive it. Design canon: .yah/docs/working/W267-sovereign-public-ingress.md.")
//! @yah:notify_on(R858-T3, "R858-T3 is in review: appliance ownership no longer aliases raft leadership, so leadership on us-west-001 is movable and a yubaba restart there no longer moves headscale. That is the gate acme_issuer.rs's R853 gotcha names — 'the fix is correct and unit-tested but UNOBSERVED LIVE, and stays that way until R858-T3 makes leadership movable'. Two caveats before treating the fleet ACME issuer as live: (1) T3 is CODE ONLY, nothing rolled — it takes effect on a node only once that node runs a build containing it; (2) the roll itself must NOT drain us-west-001 with POST /raft/transfer-leader, because that drain executes on the OLD binary (FollowsRaftLeader) and still tears headscale down. See R858-T3's gotchas for the read-only precondition check.")
//!
//! @yah:ticket(R853-T1, "Upstream the seed-listen-fds patch to cloudflare/pingora, then drop the fork pin")
//! @yah:status(review)
//! @yah:at(2026-09-05T18:22:45Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:blocked_on(operator)
//! @yah:gotcha("Patching pingora-core ALONE fails confusingly: pingora-error / pingora-http end up duplicated registry-vs-fork and the types stop unifying, giving E0308 everywhere. All 14 pingora crates in the graph must come from the same source. Also: a cold build of oss/passway now REQUIRES network access to github.com/yah-ai/pingora — an offline machine gets a resolution failure, not a compile error. The rev is public, so it is a reachability question, not a permissions one. Recorded in oss/passway/patches/README.md.")
//! @yah:next("THE OPERATOR ACTION, BY HAND — decided 2026-09-04: the issue and PR go from the operator's own GitHub account, not from a session and not from yah-human. Maintainers are wary of AI-authored contributions right now and cloudflare/pingora already says it may not review timely, so a bot-shaped drive-by is the wrong first impression. No agent files the issue, pushes a branch, or opens the PR. Everything else is prepared: oss/passway/patches/UPSTREAM.md holds the terse issue text, the terse PR text, the sequence, and the CONTRIBUTING constraint (a new public Server method is not exempt from issue-before-PR; no CLA).")
//! @yah:gotcha("The carried patches/pingora-0.8.1-seed-listen-fds.patch does NOT apply to cloudflare/pingora main — do not send it. `git merge-tree --merge-base=719ef6c <main> 2f52d94` conflicts in 2 of 3 files: main made Bootstrap::listen_fds a non-optional ListenFds live from Bootstrap::new, rewrote load_fds, and added set_expected_listen_addrs/close_unclaimed pruning. Use patches/pingora-main-seed-listen-fds.patch (rebased + verified 2026-09-04 against 09696b51bc59315353d96686355861604d0bb48c). It is SMALLER: the seeded_fds staging field is unnecessary when the table already exists. Also: upstream `cargo fmt --all --check` REJECTS the 0.8.1 hunk's one-line `.or_err_with(BindError, || format!(..))?` — it must be brace-wrapped. Nothing in this workspace runs upstream rustfmt over the vendored tree, which is why that went unnoticed for a week.")
//! @yah:handoff("Agent half of the upstreaming is DONE; the outward half is deliberately parked with the operator. Rebased the seed-listen-fds patch from tag 0.8.1 onto cloudflare/pingora main (09696b51bc59315353d96686355861604d0bb48c) — necessary, not optional: 2 of the 3 hunks conflict against main. Landed oss/passway/patches/pingora-main-seed-listen-fds.patch (155 lines) and oss/passway/patches/UPSTREAM.md (the rebase rationale, the verification record, the sequence, and terse ready-to-send issue + PR text).")
//! @yah:handoff("The rebase is smaller than the carried patch. On main Bootstrap::listen_fds is a non-optional ListenFds live from Bootstrap::new, so the seeded_fds: Option<Fds> staging field the 0.8.1 patch needed disappears — Bootstrap::seed_fd writes straight into listen_fds. load_fds now merges the upgrade socket's fds into that table instead of overwriting it (Fds::deserialize inserts by bind, so an upgrade fd still wins for a bind that was also seeded; with nothing seeded the table is empty there, so it is a no-op for existing users). Added a unit test, seeded_fds_land_in_the_table_services_read, asserting both that a seeded fd is reachable through get_fds and that an unclaimed one is closed by the existing set_expected_listen_addrs pruning.")
//! @yah:handoff("DISCOVERED AND FIXED, outside the ticket title: three places asserted crates/passway is `default = [\\\"socket-activation\\\"]`. It is `default = []` — R779 reverted it on 2026-08-31 and the docs never caught up. Corrected in patches/README.md (step 1, plus a note that the 2026-08-29 'on by default' verification run describes a two-day window), in this ticket's @yah:next, and in .yah/docs/working/W267-sovereign-public-ingress.md with a dated supersession block under the 'fork is live' section. The consequence matters: the old text says the [patch] block and the default must move together on upstreaming, and only the [patch] block and deny.toml's allow-git line actually do.")
//! @yah:handoff("Also grounded the sequence against upstream's own rules rather than the ticket's prose. cloudflare/pingora .github/CONTRIBUTING.md requires an issue before a non-trivial PR and a new public Server method is not exempt, so it is issue-then-PR, not PR. No CLA. No existing issue or PR upstream covers socket activation / LISTEN_FDS / seeding an inherited listener (searched 2026-09-04).")
//! @yah:handoff("Tree anchor at handoff: 6f193f90c6533329877804577c02d75ca57b2f98 — the shared tree as I left it. Diff against it (`git diff 6f193f90c6533329877804577c02d75ca57b2f98..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test -p pingora-core --lib against a pristine `git archive` of cloudflare/pingora main + the rebased patch: 543 passed, 0 failed, 1 ignored, including seeded_fds_land_in_the_table_services_read.")
//! @yah:verify("cargo fmt --all -- --check clean. This is upstream CI's first step and it caught a real violation in the carried hunk (the one-line .or_err_with(BindError, || format!(..))? has to be brace-wrapped) — fixed in the rebased patch, still present in the 0.8.1 one.")
//! @yah:verify("cargo clippy -p pingora-core --all-targets: no warnings.")
//! @yah:verify("git apply --check -v of patches/pingora-main-seed-listen-fds.patch against a fresh git archive of 09696b51: all three files clean.")
//! @yah:verify("cloudflare/pingora main fetched by URL (git fetch --no-tags https://github.com/cloudflare/pingora main) — no remote added to external/pingora, no checkout, no working-tree change in that clone. All build work ran in /tmp/pingora-main with RUSTC_WRAPPER= so cargo-orphan-gc never saw a throwaway target dir.")
//! @yah:assumes("That the rebase stays valid only as long as cloudflare/pingora main stays near 09696b51 (2026-08-25). If it drifts, regenerate rather than hand-fix — the recipe is at the bottom of patches/UPSTREAM.md.")
//! @yah:assumes("That the fork pin therefore stays indefinitely. Its live cost is the one already recorded: a cold build of oss/passway needs network reachability to github.com/yah-ai/pingora, and deny.toml carries an allow-git carve-out for it.")
//! @yah:gotcha("CALIBRATION on the \"cold build REQUIRES network access to github.com/yah-ai/pingora\" gotcha above — it is narrower than it reads and should not be weighed as a cost of keeping the fork. cargo caches a rev-pinned git dep in ~/.cargo/git/db after the first fetch, same as a registry crate, so it only bites a machine that has NEVER fetched that rev AND is offline. Verified 2026-09-04: `cargo metadata --offline` in oss/passway exits 0 on this machine with pingora-03eaeba7ff380de6 present in ~/.cargo/git/db. The real cost of the fork is not availability, it is (a) crates.io consumers, see the next gotcha, and (b) a rebase per pingora release.")
//! @yah:gotcha("THE CRATES.IO CONSUMER IS ALREADY BROKEN, and this is live, not hypothetical: `passway` is published (0.8.32 / 0.8.30 / 0.8.29 / 0.8.26 / 0.8.22, 63 downloads, checked 2026-09-04). `cargo install passway --features socket-activation` cannot compile for anyone — the workspace [patch.crates-io] is not in the published .crate and does not propagate, so a consumer resolves stock pingora 0.8.1, which has no Server::seed_listen_fd (2f52d94 is the commit that adds it, a child of the 0.8.1 release commit 719ef6c). main.rs:906 calls it under #[cfg(feature = \"socket-activation\")]. So the feature is reachable only from this monorepo, by construction, for as long as the fork pin exists.")
//! @yah:next("UNEXPLORED THIRD OPTION that would delete the fork instead of upstreaming it — surfaced 2026-09-04, NOT built, needs an operator call before anyone spends on it. pingora already exposes everything needed to hand it a socket, publicly, on stock crates.io 0.8.1: `pingora_core::server::Fds` is `pub use`d from mod.rs:50 with `new`/`add`/`send_to_sock` all pub, and on 0.8.1 `Opt::upgrade` drives exactly ONE thing in Bootstrap — `load_fds(true)` -> `get_from_sock` (bootstrap_services.rs:148,170-174); mod.rs:283's send side fires on SIGQUIT regardless of the flag, so it is passway's existing behaviour already. Direction is inverted from the obvious guess: the RECEIVING process binds and listens on upgrade_sock (get_fds_from unlinks, binds, retries), the sender connects. So passway could take fd 3, set O_NONBLOCK on it itself (which also removes the need for the l4.rs from_raw_fd hunk), and hand it to its own Server over the upgrade socket using only public API. No fork, no [patch] block, no allow-git, no rebase treadmill, and `cargo install passway --features socket-activation` would work. UNVERIFIED and the reasons it might not fly: get_from_sock's retry loop errors into `std::process::exit(1)` from bootstrap() if no peer connects, and doing the send in-process means a thread racing the receiver's bind — a real timing dance, not obviously safe. A spike should build it against stock 0.8.1 before anyone believes it.")
//! @yah:next("THE AGENT HALF IS DONE, and not by upstreaming — R853-F6 deleted the fork on 2026-09-04 instead of waiting for it. oss/passway/Cargo.toml's [patch.crates-io] block is gone, deny.toml's allow-git is [], the lockfile has zero git+https entries, `cargo deny check` reports sources ok, and `default = [\"socket-activation\"]` is restored with `cargo publish --dry-run` passing. passway now hands the inherited socket to its own Server over pingora's EXISTING upgrade socket (crates/passway/src/socket_activation.rs), which needs no pingora API that stock crates.io 0.8.1 lacks. So nothing in this repo is waiting on the PR any more. What is left here is only the outward half, and it is now a contribution on its merits rather than a dependency: `seed_listen_fd` is a nicer API than making an application speak SCM_RIGHTS to itself, and unlike the upgrade-socket route it would work on non-Linux. If it never lands, nothing breaks.")
//! @yah:gotcha("SUPERSEDED 2026-09-04 by R853-F6 — the two gotchas above about the fork (all-14-crates, and the cold-build network reachability) describe a fork this repo no longer carries. Keep them only as history for whoever reads patches/README.md; they are not live constraints. The one live fact they contained that still matters is the crates.io one: a [patch.crates-io] block never propagates to consumers, which is why the forked build worked in the monorepo while `cargo install passway --features socket-activation` could not compile for anyone. That is now fixed.")
//! @yah:handoff("CLOSED BY OPERATOR DECISION 2026-09-05, not by upstreaming: drop the fork, delete the patches, send no PR. R853-F6 had already removed the dependency (passway hands the inherited socket to its own Server over pingora's existing upgrade socket, stock crates.io 0.8.1), so nothing in this repo was waiting on cloudflare/pingora. With the fork gone there was nothing left to upstream on our own behalf. Deleted all four tracked files in oss/passway/patches/ (README.md, UPSTREAM.md, pingora-0.8.1-seed-listen-fds.patch, pingora-main-seed-listen-fds.patch) and the now-empty directory. Fully recoverable: `git show be2680f4:oss/passway/patches/<file>` — be2680f4508dcf7087415fb70d7b4d6cf1816132 is the last commit touching them.")
//! @yah:handoff("ANSWERED THE OPERATOR'S QUESTION ('I thought we forked on false info?') AND THE ANSWER IS NO — recorded in source because the shape of this close-out invites the wrong conclusion forever after. The upgrade-socket route was NOT missed. W267 §'Step 4b' weighed it in writing on 2026-08-28, in the same bullet list as the fork: 'passway sends fd 3 to itself through pingora's public Fds::send_to_sock while bootstrapping with Opt::upgrade = true. Zero fork, but it rides the upgrade wire format, the socket-path retry loop, and a thread racing bootstrap. Works; points the wrong way. Rejected.' The operator then chose the fork explicitly ('take the robust long-term route, a temporary pingora fork is acceptable', W267:467). No API fact was misread — `pub use transfer_fd::Fds` at server/mod.rs:50 with new/add/send_to_sock/get_from_sock all pub was true then and is true now; I re-read it in ~/.cargo/registry pingora-core-0.8.1 rather than trusting the annotation.")
//! @yah:handoff("WHAT ACTUALLY REVERSED IT, two pieces of evidence that did not exist on 2026-08-28. (1) R853-S5 BUILT the rejected option instead of reasoning about it — 10/10 runs on linux/aarch64, with an FDSPIKE_BLOCKING=1 control proving supervisor-side O_NONBLOCK substitutes for the fork's l4.rs hunk. The 'thread racing bootstrap' worry was real but absorbed by both sides' retry loops. (2) The fork's price was discovered to be higher than quoted: [patch.crates-io] does not propagate into a published .crate, so `cargo install passway --features socket-activation` could not compile for ANY crates.io consumer — which is what forced default back to [] on 2026-08-31. So: a sound decision reversed on new evidence, not a mistake on bad information. Worth keeping straight, because 'we forked on false info' would be the wrong lesson to carry into the next fork-vs-workaround call.")
//! @yah:handoff("RE-POINTED EVERY LIVE REFERENCE TO THE DELETED PATH so nothing dangles — found with rg, four sites, all outside any peer's dirty files. crates/passway/src/socket_activation.rs:13-38 (rewrote the module header's fork paragraph with the history above), oss/passway/Cargo.toml:22-31 (same, in the do-not-reintroduce-[patch] comment), spikes/R853-S5-upgrade-socket-handoff/README.md:14-31 (added a settled-2026-09-04/05 banner; its ../../patches/UPSTREAM.md link now carries the SHA), and .yah/docs/working/W267-sovereign-public-ingress.md:3127 + :3142 (two yah://file/ links into patches/ that would have 404'd in the Architecture tab, converted to `git show` pointers). The remaining patches/ mentions in main.rs are inside this ticket's own @yah: block and F6's, i.e. they strip on archive.")
//! @yah:verify("Fork absence re-confirmed after the deletions, not assumed: `rg -c 'git\\+https' oss/passway/Cargo.lock` = zero entries; oss/passway/Cargo.toml carries no [patch.crates-io] block; deny.toml's allow-git = [].")
//! @yah:verify("`cargo metadata --manifest-path oss/passway/Cargo.toml --no-deps --offline` exits 0 after the Cargo.toml comment edit and still lists exactly passway / passway-acme / passway-demux — the edited manifest parses and the member set is unchanged.")
//! @yah:verify("The four deleted files were all tracked (`git ls-files oss/passway/patches/` listed them) and committed at be2680f4, so the deletion is recoverable rather than destructive. Verified before deleting, not after.")
//! @yah:verify("`pub use transfer_fd::Fds` at server/mod.rs:50 and pub fn new/add/send_to_sock/get_from_sock in transfer_fd/mod.rs:39,45,64,74 read directly from ~/.cargo/registry/src/index.crates.io-*/pingora-core-0.8.1 — stock crates.io source, which is what makes the 'nothing was misread' claim above grounded rather than inherited.")
//! @yah:verify("`rg 'patches/UPSTREAM|patches/README|patches/pingora-'` tree-wide returns only (a) the SHA-carrying pointers I wrote and (b) annotation text inside R853-T1's and R853-F6's own @yah: blocks, which strips on archive. No dangling live reference remains.")
//! @yah:gotcha("The non-Linux escape hatch is now a git-history lookup, not a file. Adoption via the upgrade socket is cfg(target_os = \"linux\") upstream, so if passway ever needs socket activation on darwin/BSD the only route is still adding an fd-adoption API to pingora. Do not rewrite those hunks from scratch: `git show be2680f4:oss/passway/patches/pingora-main-seed-listen-fds.patch` is the version already rebased onto cloudflare/pingora main 09696b51 with tests (543/543 incl. seeded_fds_land_in_the_table_services_read), fmt and clippy verified. It rots as main moves — regenerate from it rather than hand-fixing. This is recorded at the code site too (main.rs's F6 gotcha).")
//! @yah:handoff("FORK FULLY GONE 2026-09-05, both halves, done by the operator by hand — `gh repo delete` is hard_deny under session tool policy, so no agent could execute it regardless of authorization. Verified after the fact rather than taken on report: `gh api repos/yah-ai/pingora` returns HTTP 404, and `external/pingora` (the gitignored machine-local clone of it) is no longer on disk. Before it went: 0 forks, 0 stars, 0 open issues, one yah-authored branch — yah/seed-listen-fds-0.8.1 at 2f52d944c832089bad6bd847b868d5c9f37fb201, tag 0.8.1 plus our patch. Nothing was lost that is not still in this tree at `git show be2680f4:oss/passway/patches/`.")
//! @yah:handoff("SO THE WHOLE FORK STORY IS CLOSED: no [patch.crates-io] block, no deny.toml allow-git entry, no carried patches directory, no GitHub fork, no local clone, and no upstream PR. oss/passway builds against stock crates.io pingora 0.8.1 and `cargo install passway --features socket-activation` works for a crates.io consumer again, which it had not since 2026-08-28. The surviving mentions of `yah-ai/pingora` in this tree are all deliberate history — the comment blocks in oss/passway/Cargo.toml and crates/passway/Cargo.toml explaining why a [patch] block must not be reintroduced, the R853-S5 spike README, and annotation prose on this ticket and F6 that strips when they archive. None is a live reference; verified by rg.")
//!
//! @yah:ticket(R853-F6, "Move socket-activation onto pingora's upgrade socket and delete the fork")
//! @yah:status(review)
//! @yah:at(2026-09-04T23:14:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R853)
//! @yah:depends_on(R853-S5)
//! @yah:gotcha("LIVE COLLISION AT FILING TIME, 2026-09-04 — do not start without re-checking. @Glimmerstone:polaris (session:9f8108d4, courier under R858) was at phase=working running `cargo test --manifest-path oss/passway/Cargo.toml` when this was filed, and `oss/passway/crates/passway/src/main.rs` carried 561 uncommitted insertions from R858-T1 (\"Move cloud.mesh.yah.dev behind the passway front doors\") — including hunks INSIDE `fn main()`, which is exactly where this ticket edits. proxy.rs, routing.rs, tests/common/mod.rs and the crate README were staged-modified too. Re-run camp.roster + `git status --short oss/passway/` and confirm R858-T1 is terminal before touching main.rs.")
//! @yah:next("SEQUENCE THIS IN TWO STEPS so the disruptive half is one atomic edit at the end. The new mechanism uses ONLY public API that exists in BOTH stock crates.io pingora 0.8.1 and the fork, so it compiles and tests fine with the [patch.crates-io] block still in place. Step 1 (safe alongside a peer): rewrite the socket-activation path in main.rs and the two tests, verify green with the fork still pinned. Step 2 (only when nobody else is building passway): delete the 14-crate [patch.crates-io] block from oss/passway/Cargo.toml and the allow-git line from deny.toml. Step 2 forces a full re-resolve and rebuild of all 14 pingora crates, so landing it under a peer's running `cargo test` breaks their run with failures that look like nothing to do with them.")
//! @yah:next("THE EDIT, at main.rs:902-915 (current working-tree numbering, which already includes R858-T1's shift). Replace the `server.seed_listen_fd(listen.as_str(), fd)` call with: set O_NONBLOCK on the inherited fd via fcntl(F_GETFL/F_SETFL) — this replaces the fork's listeners/l4.rs hunk and is proven load-bearing by the spike's FDSPIKE_BLOCKING=1 control; set ServerConf::upgrade_sock to a private per-process path and Opt::upgrade = true BEFORE Server::new_with_opt_and_conf; spawn a thread doing Fds::new() / add(listen.clone(), fd) / send_to_sock(path); then server.bootstrap() on the main thread, which is the receiving half. Sender must be off-thread because bootstrap() blocks in the receive. Working reference implementation with the exact API calls: oss/passway/spikes/R853-S5-upgrade-socket-handoff/src/main.rs.")
//! @yah:next("PLATFORM GATE, decided by the spike, not optional: pingora's fd transfer is Linux-only on 0.8.1 and main alike (get_fds_from returns Err(ECONNREFUSED) off-Linux and Bootstrap::bootstrap does std::process::exit(1) on that). So cfg(target_os = \"linux\") the handoff, and on other unix keep the existing loud failure rather than letting pingora exit(1) with an opaque message. crates/passway/tests/socket_activation.rs and tests/jit_cold_start.rs both need the same gate — both pass on this darwin camp today, and both stop running here. That lost local coverage is the accepted cost of the trade (operator call, 2026-09-04); note there is no CI backstop, since no workflow in this repo has an on:push trigger.")
//! @yah:next("FEATURE FLAG: flip crates/passway/Cargo.toml back to `default = [\"socket-activation\"]` as part of step 2. The reason it was reverted to [] on 2026-08-31 disappears with the fork — `cargo publish --verify` builds the tarball standalone where the workspace [patch] never applied, which is exactly why the default-on feature failed verification; against stock pingora it compiles. Keep the feature rather than deleting it: removing a feature name from a published crate (passway is live on crates.io at 0.8.32) is a breaking change for anyone passing it, and keeping it preserves a way to build passway without the socket-activation path. Also rewrite the feature's doc comment, which still says \"without the fork the feature does not compile, by design\" — that becomes false.")
//! @yah:notify_on(R858-T1, "R858-T1's in-flight rewrite of oss/passway/crates/passway/src/main.rs (561 uncommitted insertions, hunks inside fn main()) is what blocked R853-F6 from starting. Now that it is terminal, re-check `git status --short oss/passway/` and camp.roster for any other live session building passway, then take R853-F6 step 1.")
//! @yah:handoff("Filed and fully specified, NOT started — yielded on a live shared-tree collision rather than hand-fighting the file. Everything needed to execute is in this ticket's @yah:next entries plus the working reference implementation at oss/passway/spikes/R853-S5-upgrade-socket-handoff/src/main.rs.")
//! @yah:handoff("Operator decided ADOPT on 2026-09-04, after R853-S5 came back positive: passway moves onto pingora's own upgrade socket and the fork goes. The accepted cost is that socket-activation becomes Linux-only, so tests/socket_activation.rs and tests/jit_cold_start.rs stop running on this darwin camp.")
//! @yah:handoff("Collision surfaced on BOTH rails as the shared-tree trait requires: a party.chat steer to @Glimmerstone:vortex (session:25272272, R858 leader) naming the incoming Cargo.toml/deny.toml change and offering to park F6 entirely if they prefer, and a durable @yah:notify_on(R858-T1) on this ticket so the next agent to open it is woken when R858-T1 goes terminal instead of polling.")
//! @yah:handoff("Tree anchor at handoff: 6f193f90c6533329877804577c02d75ca57b2f98 — the shared tree as I left it. Diff against it (`git diff 6f193f90c6533329877804577c02d75ca57b2f98..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("Before starting: camp.roster shows no live session building oss/passway, and `git status --short oss/passway/` shows main.rs clean of R858-T1's insertions.")
//! @yah:verify("After step 1, with the [patch] block still pinned: cargo test --manifest-path oss/passway/Cargo.toml green, and the rewritten socket_activation test still proves adoption the same way — fd bound to port A, announced under the bind string for port B, A answers and B refuses.")
//! @yah:verify("After step 2: `cargo tree -i pingora-core` shows a registry source and no git source; `cargo deny check sources` passes with the allow-git line gone; `cargo publish --dry-run -p passway` succeeds with default = [\\\"socket-activation\\\"].")
//! @yah:gotcha("I GOT THE COST OF THIS TRADE WRONG WHEN I PITCHED IT, and the correction matters more than the trade. I told the operator that adopting the fork-free route would cost `tests/socket_activation.rs` running on the darwin camp, claiming the file \"carries no cfg gate today and passes here\". It does carry one — not in the file, in tests/main.rs, which declares both `mod socket_activation` and `mod jit_cold_start` under `#[cfg(all(unix, feature = \"socket-activation\"))]`. Since R779 set `default = []` on 2026-08-31, that feature was off on every default build, so BOTH tests had been compiling on nothing for four days while the suite reported all-green. The coverage I offered up as the price of this change had already been lost, by the default flip, and nobody noticed because a dark test and a passing test look identical in the summary line. Verified by content, not inference: `cargo test -p passway --test main -- --list` returned 26 tests with no name matching socket_activation / jit_cold / inherited / cold_start.")
//! @yah:gotcha("NET EFFECT ON COVERAGE IS THEREFORE POSITIVE, not negative, which is the opposite of how this ticket was sold. Before F6: both tests dark everywhere, because the feature was off by default. After F6: `default = [\"socket-activation\"]` is restored (its only reason for being `[]` was that the fork broke `cargo publish --verify`, and the fork is gone), so both tests are live on Linux and correctly cfg'd off on darwin, where pingora's SCM_RIGHTS helpers do not exist. The darwin camp still cannot run them — that part of the original claim stands — but it could not run them before this change either. A dark test reporting green is the failure mode to watch for here; tests/main.rs now carries a comment saying so.")
//! @yah:handoff("DONE — passway carries no pingora fork. crates/passway/src/socket_activation.rs hands the inherited LISTEN_FDS socket to passway's own Server over pingora's EXISTING upgrade socket, the only public seam into its listener fd table. Removed: the 14-crate [patch.crates-io] block from oss/passway/Cargo.toml, and deny.toml's allow-git entry (now []). Restored: default = [\\\"socket-activation\\\"] in crates/passway/Cargo.toml.")
//! @yah:handoff("The mechanism lives in the LIBRARY, not in main.rs, which is a change from how the ticket was specified. spawn_fd_handoff had to be reachable from tests/socket_activation.rs, and a binary crate is not importable from an integration test — so it is passway::socket_activation, and main.rs calls it. socket_activation_fd() stayed in main.rs: reading LISTEN_FDS/LISTEN_PID out of the process environment is a binary concern, transferring an fd is not.")
//! @yah:handoff("Two guards main.rs did not have before, both failing loudly rather than binding fresh behind a supervisor's back: a non-Linux build refuses if LISTEN_FDS is set, rather than letting pingora's own load_fds hit ECONNREFUSED and exit(1) with a message about graceful upgrades; and PASSWAY_UPGRADE=true together with LISTEN_FDS is now rejected outright, because ServerConf has exactly one upgrade_sock and a seed transfer landing on the real one would race the predecessor passway's send.")
//! @yah:handoff("Docs corrected wherever they described the fork as load-bearing: patches/README.md gained a header saying nothing in it is applied any more, patches/UPSTREAM.md now frames the cloudflare PR as optional rather than blocking, and W267's 'the fork is live' subsection carries a dated supersession block. R853-T1's annotation was updated too — its 'agent half' is complete, reached by deleting the fork rather than by upstreaming.")
//! @yah:verify("Linux (rust:1-bookworm, aarch64 container, stock crates.io pingora): cargo test -p passway --test main = 28 passed / 0 failed, INCLUDING socket_activation::inherited_listening_socket_is_adopted_under_the_bind_string and jit_cold_start::cold_start_through_the_demux_forks_serves_and_reaps. Those two are the whole point and had not run since 2026-08-31.")
//! @yah:verify("darwin: cargo test --workspace = 219 passed / 0 failed / 1 ignored, with the two Linux-only modules correctly cfg'd out.")
//! @yah:verify("Fork actually gone, checked three independent ways: Cargo.lock has 0 `git+https` entries; `cargo tree -i pingora-core --depth 0` prints a bare `pingora-core v0.8.1` with no git URL; `cargo deny check` returns advisories ok, bans ok, licenses ok, sources ok with allow-git = [].")
//! @yah:verify("cargo publish --dry-run -p passway PASSES with default = [\\\"socket-activation\\\"] — built standalone from the packaged tarball, which is precisely the gate that failed on 2026-08-31 and forced default = []. This is the crates.io-consumer breakage fixed, verified rather than argued.")
//! @yah:verify("clippy on Linux (where the module actually compiles — on darwin it is cfg'd out and clippy never sees it): zero warnings from socket_activation.rs and zero from the test binary. The 3 remaining passway lib warnings are pre-existing and not from this ticket.")
//! @yah:verify("Formatting deliberately NOT run. `cargo fmt --all -- --check` reaches through path deps into oss/cheers, which is how 827 uncommitted lines were destroyed here on 2026-08-28; and the passway crate has never been fmt-clean (36 diffs in acme.rs alone). Checked instead that this ticket adds no new debt: src/socket_activation.rs does not appear in `cargo fmt -p passway --check` output at all, and the diffs near my edits are pre-existing lines.")
//! @yah:gotcha("Adoption is Linux-only now and the tests say so in their headers. If passway ever needs socket activation on another platform, the ONLY route is adding an fd-adoption API to pingora upstream — seed_listen_fd is cfg(unix), the upgrade socket is cfg(target_os = \\\"linux\\\"). The prepared hunks for that PR lived in patches/, deleted 2026-09-05 on R853-T1; recover them with `git show be2680f4:oss/passway/patches/pingora-main-seed-listen-fds.patch` (rebased onto cloudflare/pingora main 09696b51, tests+fmt verified) rather than rewriting from scratch. Note the rebase rots — regenerate if main has moved.")

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
use passway::routing::{build_host_router, HostKey, UpstreamOpts, UpstreamSet, CATCH_ALL_LABEL};
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
///
/// @yah:ticket(R853-S5, "Can passway adopt an inherited fd through stock pingora's upgrade socket, deleting the fork?")
/// @yah:at(2026-09-04T22:48:10Z)
/// @yah:kind(spike)
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R853)
/// @yah:gotcha("FOUND BEFORE WRITING ANY CODE, and it caps what this spike can deliver: pingora's fd transfer is LINUX-ONLY, on 0.8.1 and on main alike. `get_fds_from` under `#[cfg(not(target_os = \"linux\"))]` logs \"Upgrade is not currently supported outside of Linux platforms\" and returns Err(ECONNREFUSED) (transfer_fd/mod.rs:181-192 at 719ef6c, :218-229 at 09696b51); the matching `send_fds_to` returns Ok(0) and silently sends nothing. Since `Bootstrap::bootstrap` does `std::process::exit(1)` on a load_fds error, taking this route on macOS would hard-exit the process. So the fork-free path is Linux-only by construction, and no amount of passway-side code fixes it — the receiving half is pingora's.")
/// @yah:gotcha("WHAT THAT ACTUALLY COSTS is smaller than it first looks, and the distinction is the whole decision: the loss is a LOCAL TEST, not a deployment capability. passway's socket activation exists to ride kamaji's on-demand JIT tier, which runs on the Linux fleet; nothing deploys it on darwin. But crates/passway/tests/socket_activation.rs carries no cfg gate today and passes on this darwin camp, so the fork-free path would gate it to Linux and this camp would stop exercising the cold-start path locally — and there is no CI to catch it either (no workflow in this repo has an on:push trigger, see CLAUDE.md). Weigh it as \"lose a dev-machine integration test, regain crates.io consumers + delete the treadmill\", not as \"lose macOS support\".")
/// @yah:next("THE MECHANISM TO PROVE, narrow on purpose: can ONE process hand a listening fd to its OWN pingora Server over the upgrade socket without deadlocking? Direction is inverted from the obvious guess — the RECEIVER binds and listens on conf.upgrade_sock (get_fds_from unlinks the path, binds, then retries accept: MAX_RETRY 5 at RETRY_INTERVAL 1s on 0.8.1) and the SENDER connects. So passway would: set O_NONBLOCK on the inherited fd 3 itself (which also retires the l4.rs from_raw_fd hunk, the third of the three), set Opt::upgrade = true, spawn a thread that builds a `Fds`, `add(bind_string, fd)` and retry-connects `send_to_sock(upgrade_sock)`, then call server.bootstrap() on the main thread. Everything it touches is public on stock 0.8.1: `pingora_core::server::Fds` is `pub use`d at mod.rs:50 with new/add/send_to_sock pub, and Opt::upgrade drives exactly one thing in Bootstrap — load_fds(true) -> get_from_sock (bootstrap_services.rs:148,170-174). mod.rs:283's send side fires on SIGQUIT regardless of the flag, so it is passway's existing behaviour and unaffected.")
/// @yah:next("RULED OUT ALREADY, so nobody re-derives it: there is no other public seam. pingora-core 0.8.1's Listeners API (listeners/mod.rs) exposes tcp/uds/tls/add_tcp/add_tcp_with_settings/add_uds/add_tls/add_tls_with_settings/add_address/add_endpoint and ServerAddress is Tcp(String, Option<TcpSocketOptions>) | Uds(..) — no fd variant, no listener-from-fd constructor anywhere. Server::listen_fds() is private. The upgrade socket is the ONLY public way into the fd table without the fork.")
/// @yah:handoff("VERDICT: IT WORKS. A process can hand a listening fd to its OWN pingora Server over the upgrade socket, using only public API on STOCK crates.io pingora-core 0.8.1 (Cargo.lock resolves source = registry+.../crates.io-index, checksum 6a7ffe2f5acf9f94fd255cfd1438866bc9124f8f0c7d42562bd3f853df2094b7 — no fork, no [patch.crates-io]). Probe kept at oss/passway/spikes/R853-S5-upgrade-socket-handoff/ (detached from the workspace by an empty [workspace] table; `cargo metadata` at the passway root still lists only passway/passway-acme/passway-demux, so it costs the build nothing). Evidence, rust:1-bookworm linux/aarch64, 2026-09-04: single run PASS — the socket handed over is bound to port A but announced under the bind string for port B which nothing ever binds, and A answered while B refused (Connection refused), so pingora adopted rather than bound fresh. 10 consecutive runs: 10 PASS / 0 FAIL, so the sender-thread-vs-bootstrap-receive timing dance is not flaky — both sides retry (send_fds_to tolerates ENOENT/ECONNREFUSED, get_fds_from tolerates EAGAIN, 5 x 1s each on 0.8.1) and that absorbs the skew.")
/// @yah:handoff("THE THIRD HUNK IS RETIRED BY THE SUPERVISOR SIDE, and this was proved with a control rather than assumed. FDSPIKE_BLOCKING=1 skips the fcntl(F_SETFL, O_NONBLOCK) on the fd before handing it over: the run then FAILS exactly as predicted — nothing is ever served on port A and the client gets WouldBlock (EAGAIN, os error 11) until the 10s deadline. With the flag set it passes. So a std-bound (blocking) socket really does stall the worker on first accept, and setting O_NONBLOCK on OUR OWN fd before the handoff is a complete substitute for the fork's listeners/l4.rs from_raw_fd hunk. Note passway's own tests/jit_cold_start.rs:271 already sets the held socket non-blocking supervisor-side, so this is the established pattern here, not a new one.")
/// @yah:next("THE CALL THIS SPIKE EXISTS TO FEED, for the operator, not for a session to take unilaterally: adopt the fork-free route in passway, or keep the fork? Adopting deletes oss/passway/Cargo.toml's [patch.crates-io] block (14 crates), deny.toml's allow-git line, the rebase-per-pingora-release treadmill, and today's broken `cargo install passway --features socket-activation`; it also makes the cloudflare/pingora PR (R853-T1) optional rather than load-bearing. It costs gating crates/passway/tests/socket_activation.rs to Linux, since pingora's fd transfer is Linux-only — see the gotchas. If adopted, the shape is: passway sets O_NONBLOCK on the inherited fd 3 itself, sets Opt::upgrade = true and ServerConf::upgrade_sock to a private path, spawns a thread that does Fds::new()/add(bind_string, fd)/send_to_sock(path), then calls server.bootstrap() on the main thread. main.rs:902-915 is the site; the seed_listen_fd call at :906 goes away.")
/// @yah:handoff("Spike answered, positively. Probe committed at oss/passway/spikes/R853-S5-upgrade-socket-handoff/ (Cargo.toml + src/main.rs + README.md), detached from the passway workspace by an empty [workspace] table so it builds nothing and publishes nothing — `cargo metadata` at the passway root still lists only passway / passway-acme / passway-demux. The 867M container-built target/ was removed; `target` is already covered by .gitignore:6, so a future run cannot leak it into a commit.")
/// @yah:handoff("Also ruled out and recorded so nobody re-derives it: the upgrade socket is the ONLY public way into pingora's fd table without the fork. listeners/mod.rs exposes tcp/uds/tls/add_tcp/add_tcp_with_settings/add_uds/add_tls/add_tls_with_settings/add_address/add_endpoint, ServerAddress is Tcp(String, Option<TcpSocketOptions>) | Uds(..) with no fd variant, and Server::listen_fds() is private.")
/// @yah:verify("Built and run in rust:1-bookworm, linux/aarch64, from the committed in-repo copy: PASS, exit 0. Port A (the transferred socket) answered; port B (the bind string, never bound) refused with Connection refused — the control that distinguishes adoption from binding fresh.")
/// @yah:verify("10 consecutive runs: 10 PASS / 0 FAIL. The sender-thread-vs-bootstrap-receive handoff is not flaky.")
/// @yah:verify("FDSPIKE_BLOCKING=1 control run FAILS as designed (nothing served, WouldBlock / EAGAIN os error 11), proving the supervisor-side O_NONBLOCK is load-bearing and is a complete substitute for the fork's listeners/l4.rs hunk.")
/// @yah:verify("Cargo.lock resolves pingora-core 0.8.1 to source = registry+https://github.com/rust-lang/crates.io-index, checksum 6a7ffe2f5acf9f94fd255cfd1438866bc9124f8f0c7d42562bd3f853df2094b7 — stock crates.io, no fork, no [patch.crates-io].")
/// @yah:assumes("Verified on 0.8.1 only. main also carries the Linux-only cfg on the transfer helpers, but the spike was not re-run against main — if passway ever bumps pingora, re-run the probe rather than assuming it carries.")
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

/// Parse `PASSWAY_YUBABA_URL` into the yubabas to poll per fronted hostname
/// (R844-F23).
///
/// The same `<hostname>=<value>` fan-in grammar as its two siblings, and
/// **additive like [`parse_upstream_sets`], not exclusive like
/// [`parse_ident_sets`]** — repeating a hostname ADDS a URL to its set:
///
/// ```text
/// http://100.64.0.3:7443                      # catch-all, the pre-F23 form
/// *=http://100.64.0.3:7443                    # the same, said explicitly
/// yah.dev=http://100.64.0.3:7443,yah.dev=http://100.64.0.2:7443
/// ```
///
/// That split is not an inconsistency, it is the shape of the thing being
/// named. A hostname has exactly one workload behind it, so two idents for it
/// is a guess — but that workload may be PLACED ON N NODES, and since the
/// service-record store is node-local (R844-B11) its records are only visible
/// to N polls. N URLs is a set; N idents is not.
///
/// A hostname with no entry of its own falls back to the catch-all, which is
/// what keeps a bare `PASSWAY_YUBABA_URL=http://host:7443` meaning exactly
/// what it always did for every hostname on the door. Mixing bare and prefixed
/// entries is the [`parse_upstream_sets`] error for the same reason: an
/// unprefixed entry is a catch-all, and a catch-all is typed on purpose.
///
/// Not folded into [`parse_upstream_sets`] despite the identical control flow:
/// that one *warns and skips* an unparsable address, because a set short one
/// backend still serves, while a URL that cannot be read leaves its hostname
/// with nothing to poll at all and has to be a boot failure.
fn parse_yubaba_url_sets(raw: &str) -> Result<Vec<(HostKey, Vec<String>)>, String> {
    let mut sets: BTreeMap<HostKey, Vec<String>> = BTreeMap::new();
    let mut bare: Vec<&str> = Vec::new();
    let mut keyed: Vec<&str> = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        // Split on the FIRST '=' only: a base URL has no query string, and
        // anything after the first '=' belongs to the value regardless.
        let (key, url) = match entry.split_once('=') {
            Some((host, url)) => {
                let host = host.trim();
                if host == CATCH_ALL_LABEL {
                    (HostKey::CatchAll, url.trim())
                } else if host.is_empty() {
                    return Err(format!(
                        "PASSWAY_YUBABA_URL entry {entry:?} has an empty hostname"
                    ));
                } else {
                    keyed.push(host);
                    (HostKey::Host(host.to_string()), url.trim())
                }
            }
            None => {
                bare.push(entry);
                (HostKey::CatchAll, entry)
            }
        };
        if url.is_empty() {
            return Err(format!(
                "PASSWAY_YUBABA_URL entry {entry:?} names no yubaba to poll"
            ));
        }
        let urls = sets.entry(key).or_default();
        // A repeat of the same URL is an operator typo, not a second node —
        // polling one yubaba twice would double-count its records.
        if !urls.iter().any(|u| u == url) {
            urls.push(url.to_string());
        }
    }

    if !bare.is_empty() && !keyed.is_empty() {
        return Err(format!(
            "PASSWAY_YUBABA_URL mixes unprefixed entries ({bare:?}) with host-prefixed ones \
             ({keyed:?}). An unprefixed entry means \"discover every hostname's backends from \
             this yubaba\", which on a host-routed front door is a catch-all — write it as \
             \"*=<url>\" if that is what you meant, or give it a hostname prefix."
        ));
    }

    Ok(sets.into_iter().collect())
}

/// A setting that is either stated once for the whole door (the bare form) or
/// per fronted hostname (the `<hostname>=<value>` fan-in form) — R858-T1.
///
/// The two upstream-scheme variables (`PASSWAY_UPSTREAM_TLS`,
/// `PASSWAY_UPSTREAM_SNI`) differ from `PASSWAY_UPSTREAMS` /
/// `PASSWAY_YUBABA_IDENT` in one way: their bare form has to keep meaning
/// "every set", because that is what every deployed door already writes. So a
/// bare entry lands in `global` (the proxy-wide default) rather than becoming
/// the catch-all *set's* value, and `*=<value>` remains the way to say "the
/// catch-all set specifically".
#[derive(Debug, Default, PartialEq, Eq)]
struct HostScoped<T> {
    /// The bare `VAR=value` form: the process-wide default for every set that
    /// has no entry of its own. `None` when the variable was empty or used the
    /// fan-in form.
    global: Option<T>,
    per_host: BTreeMap<HostKey, T>,
}

/// The `<hostname>=<value>` fan-in parser shared by the two upstream-scheme
/// variables, with the same rules [`parse_upstream_sets`] and
/// [`parse_ident_sets`] enforce: `*=` is the explicit catch-all, an empty
/// hostname is an error, mixing bare and prefixed entries is an error, and a
/// repeated hostname is an error rather than a silent pick.
///
/// `parse_value` turns one raw value into `T` or explains why it cannot.
fn parse_host_scoped<T, F>(var: &str, raw: &str, parse_value: F) -> Result<HostScoped<T>, String>
where
    F: Fn(&str) -> Result<T, String>,
{
    let mut out = HostScoped {
        global: None,
        per_host: BTreeMap::new(),
    };
    let mut bare: Vec<&str> = Vec::new();
    let mut keyed: Vec<&str> = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match entry.split_once('=') {
            Some((host, value)) => {
                let host = host.trim();
                let key = if host == CATCH_ALL_LABEL {
                    HostKey::CatchAll
                } else if host.is_empty() {
                    return Err(format!("{var} entry {entry:?} has an empty hostname"));
                } else {
                    keyed.push(host);
                    HostKey::Host(host.to_string())
                };
                let value =
                    parse_value(value.trim()).map_err(|e| format!("{var} entry {entry:?}: {e}"))?;
                if out.per_host.insert(key.clone(), value).is_some() {
                    return Err(format!(
                        "{var} names {key:?} twice. A hostname has exactly one upstream \
                         scheme; two values for it has no meaning that is not a guess."
                    ));
                }
            }
            None => {
                bare.push(entry);
                out.global =
                    Some(parse_value(entry).map_err(|e| format!("{var} value {entry:?}: {e}"))?);
            }
        }
    }

    if !bare.is_empty() && !keyed.is_empty() {
        return Err(format!(
            "{var} mixes an unprefixed value ({bare:?}) with host-prefixed ones ({keyed:?}). \
             An unprefixed value is the process-wide default for every set — say it as \
             \"*=<value>\" if you meant the catch-all set specifically, or give every entry \
             a hostname prefix."
        ));
    }
    if bare.len() > 1 {
        return Err(format!(
            "{var} has more than one unprefixed value ({bare:?}); it is a single \
             process-wide default."
        ));
    }

    Ok(out)
}

/// Parse `PASSWAY_UPSTREAM_TLS` — bare `true`/`false` (the process-wide form
/// every deployed door uses) or the per-host fan-in form.
///
/// Rejects a value that is neither `true` nor `false` instead of reading it as
/// `false` the way the pre-R858 `== "true"` comparison did. A typo'd
/// `PASSWAY_UPSTREAM_TLS=yes` meaning "plaintext" is the silent-wrong-answer
/// shape this binary already refuses for `PASSWAY_UPSTREAM_SOURCE`, and it
/// fails as a connection reset against a TLS-only upstream — the operator
/// would debug the backend.
fn parse_upstream_tls(raw: &str) -> Result<HostScoped<bool>, String> {
    parse_host_scoped("PASSWAY_UPSTREAM_TLS", raw, |v| {
        match v.to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("expected \"true\" or \"false\", got {other:?}")),
        }
    })
}

/// Parse `PASSWAY_UPSTREAM_SNI` — bare hostname (process-wide) or the per-host
/// fan-in form, e.g. `cloud.mesh.yah.dev=cloud.mesh.yah.dev`.
///
/// An empty value is accepted only in the bare form (where it is today's
/// default and means "no SNI"); `<hostname>=` with nothing after it is an
/// error, since writing the prefix at all says a specific SNI was intended.
fn parse_upstream_sni(raw: &str) -> Result<HostScoped<String>, String> {
    parse_host_scoped("PASSWAY_UPSTREAM_SNI", raw, |v| {
        if v.is_empty() {
            Err("names no SNI; omit the entry to inherit the process-wide default".to_string())
        } else {
            Ok(v.to_string())
        }
    })
}

/// The upstream scheme for one set, or `None` to inherit the proxy-wide
/// default (R858-T1).
///
/// `None` rather than "the default, materialized" so the router keeps a set
/// that was never configured distinguishable from one explicitly configured to
/// match the default — the proxy resolves it in one place
/// (`PassProxy::default_upstream_opts`) instead of two.
fn upstream_opts_for(
    key: &HostKey,
    tls: &HostScoped<bool>,
    sni: &HostScoped<String>,
) -> Option<UpstreamOpts> {
    let tls_override = tls.per_host.get(key);
    let sni_override = sni.per_host.get(key);
    if tls_override.is_none() && sni_override.is_none() {
        return None;
    }
    Some(UpstreamOpts {
        tls: *tls_override.or(tls.global.as_ref()).unwrap_or(&false),
        sni: sni_override
            .or(sni.global.as_ref())
            .cloned()
            .unwrap_or_default(),
    })
}

/// Which family serves a given [`HostKey`] once a discovery door also carries
/// static pins (R858-T1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetOrigin {
    /// An explicit `PASSWAY_UPSTREAMS` address list.
    Static,
    /// A `PASSWAY_YUBABA_IDENT` discovery poller.
    Discovered,
}

/// The result of merging static pins over discovered sets.
#[derive(Debug, PartialEq, Eq)]
struct MergedSets {
    /// Every set to build, sorted by [`HostKey`], with the family that won it.
    sets: Vec<(HostKey, SetOrigin)>,
    /// Hostnames a static pin took away from discovery. The caller warns once
    /// per entry — an operator who pinned a host that discovery also answers
    /// for should be told which of the two is live.
    overridden: Vec<HostKey>,
}

/// Merge an explicit `PASSWAY_UPSTREAMS` set list over a discovered one
/// (R858-T1).
///
/// Needed because a door can require both at once: `yah.dev` follows kamaji's
/// placement and must be discovered, while `cloud.mesh.yah.dev` points at a
/// workload placed on a *different* node — which local discovery can never
/// see, since a yubaba's service records are strictly per-node (R844-B11: a
/// record's `mesh_ip` must equal the answering node's own mesh address). So
/// the remote one is a static pin resolved at the control plane.
///
/// On a collision the STATIC pin wins: an explicit operator pin beating an
/// inferred one is the least surprising rule, and it is the only direction
/// that leaves the operator a way to override discovery at all.
fn merge_static_over_discovered(
    static_keys: &[HostKey],
    discovered_keys: &[HostKey],
) -> MergedSets {
    let mut sets: BTreeMap<HostKey, SetOrigin> = discovered_keys
        .iter()
        .map(|k| (k.clone(), SetOrigin::Discovered))
        .collect();
    let mut overridden = Vec::new();
    for key in static_keys {
        if sets.insert(key.clone(), SetOrigin::Static) == Some(SetOrigin::Discovered) {
            overridden.push(key.clone());
        }
    }
    MergedSets {
        sets: sets.into_iter().collect(),
        overridden,
    }
}

/// Pick the [`UpstreamSource`]s from `PASSWAY_UPSTREAM_SOURCE` (R594-F8),
/// one per fronted hostname (R594-F10), each carrying its own upstream scheme
/// (R858-T1).
///
/// Panics on an unrecognized value rather than silently falling back to
/// `static`: a typo'd source name that quietly yields an empty static list
/// looks exactly like "yubaba has no ready upstreams", and the operator would
/// debug the wrong half of the system. Fail loudly at boot instead.
///
/// Every decision this makes beyond reading the environment lives in the pure
/// functions above — [`parse_upstream_sets`], [`parse_ident_sets`],
/// [`merge_static_over_discovered`], [`upstream_opts_for`] — because this
/// function itself reads `std::env` and panics, and is therefore untestable.
fn build_upstream_sources(tls: &HostScoped<bool>, sni: &HostScoped<String>) -> Vec<UpstreamSet> {
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
                let key = HostKey::CatchAll;
                let opts = upstream_opts_for(&key, tls, sni);
                return vec![UpstreamSet::new(
                    key,
                    Arc::new(StaticUpstreams::new(Vec::new())) as Arc<dyn UpstreamSource>,
                )
                .with_opts(opts)];
            }
            for (key, addrs) in &sets {
                log::info!("upstream set {key:?}: {addrs:?}");
            }
            sets.into_iter()
                .map(|(key, addrs)| {
                    let opts = upstream_opts_for(&key, tls, sni);
                    UpstreamSet::new(
                        key,
                        Arc::new(StaticUpstreams::new(addrs)) as Arc<dyn UpstreamSource>,
                    )
                    .with_opts(opts)
                })
                .collect()
        }
        "yubaba" => {
            let raw_url = std::env::var("PASSWAY_YUBABA_URL")
                .expect("PASSWAY_YUBABA_URL is required with PASSWAY_UPSTREAM_SOURCE=yubaba");
            // R844-F23: one hostname may name SEVERAL yubabas, one per node its
            // workload is placed on, because the record store is node-local.
            let yubabas: BTreeMap<HostKey, Vec<String>> = parse_yubaba_url_sets(&raw_url)
                .unwrap_or_else(|e| panic!("invalid PASSWAY_YUBABA_URL: {e}"))
                .into_iter()
                .collect();
            if yubabas.is_empty() {
                panic!(
                    "PASSWAY_YUBABA_URL is set but names no yubaba to poll — see \
                     PASSWAY_UPSTREAM_SOURCE=yubaba in this binary's module docs"
                );
            }
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
            // R858-T1: a discovery door may ALSO carry static pins. Not a
            // fallback and not a migration — some upstreams simply cannot be
            // discovered locally (see `merge_static_over_discovered`), so the
            // two coexist per HostKey on one door.
            let pinned: BTreeMap<HostKey, Vec<SocketAddr>> =
                parse_upstream_sets(&env_or("PASSWAY_UPSTREAMS", ""))
                    .unwrap_or_else(|e| panic!("invalid PASSWAY_UPSTREAMS: {e}"))
                    .into_iter()
                    .collect();
            let discovered: BTreeMap<HostKey, String> = sets.into_iter().collect();
            let merged = merge_static_over_discovered(
                &pinned.keys().cloned().collect::<Vec<_>>(),
                &discovered.keys().cloned().collect::<Vec<_>>(),
            );
            for key in &merged.overridden {
                log::warn!(
                    "PASSWAY_UPSTREAMS pins {key:?}, which PASSWAY_YUBABA_IDENT also names — \
                     the static pin wins and discovery is not run for that hostname"
                );
            }

            // R844-F20: one discovery source PER FRONTED HOSTNAME, not one flat
            // set adopted as the catch-all. That flat shape is why a door
            // fronting several hostnames could not use discovery at all and had
            // to be TOLD its backends statically — which is the literal port pin
            // R844 exists to delete, relocated from a TOML file into an
            // operator's terminal.
            merged
                .sets
                .into_iter()
                .map(|(key, origin)| {
                    let source: Arc<dyn UpstreamSource> = match origin {
                        SetOrigin::Static => {
                            let addrs = pinned.get(&key).cloned().unwrap_or_default();
                            log::info!("upstream set {key:?} (static pin): {addrs:?}");
                            Arc::new(StaticUpstreams::new(addrs))
                        }
                        SetOrigin::Discovered => {
                            // This hostname's own yubabas if it names any,
                            // else the catch-all — which is what keeps a bare
                            // `PASSWAY_YUBABA_URL=<url>` the single source for
                            // every hostname, exactly as before R844-F23.
                            let base_urls = yubabas
                                .get(&key)
                                .or_else(|| yubabas.get(&HostKey::CatchAll))
                                .cloned()
                                .unwrap_or_else(|| {
                                    panic!(
                                        "PASSWAY_YUBABA_IDENT names {key:?} but \
                                         PASSWAY_YUBABA_URL gives it no yubaba to poll and \
                                         declares no \"*=\" catch-all"
                                    )
                                });
                            let config = YubabaDiscoveryConfig {
                                base_urls,
                                ident: discovered.get(&key).cloned().unwrap_or_default(),
                                timeout: env_secs("PASSWAY_YUBABA_TIMEOUT_SECS", 5),
                            };
                            log::info!(
                                "upstream discovery for {key:?}: polling {:?} for records of \
                                 ident {:?} every PASSWAY_UPDATE_INTERVAL_SECS",
                                config.urls(),
                                config.ident
                            );
                            Arc::new(YubabaUpstreams::new(&config))
                        }
                    };
                    let opts = upstream_opts_for(&key, tls, sni);
                    UpstreamSet::new(key, source).with_opts(opts)
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

    // R858-T1: bare `true`/`false` is still the process-wide default; the
    // fan-in form gives a single set (headscale, which terminates its own TLS)
    // a scheme different from the door's.
    let upstream_tls = parse_upstream_tls(&env_or("PASSWAY_UPSTREAM_TLS", ""))
        .unwrap_or_else(|e| panic!("invalid PASSWAY_UPSTREAM_TLS: {e}"));
    let upstream_sni = parse_upstream_sni(&env_or("PASSWAY_UPSTREAM_SNI", ""))
        .unwrap_or_else(|e| panic!("invalid PASSWAY_UPSTREAM_SNI: {e}"));
    let upstream_sources = build_upstream_sources(&upstream_tls, &upstream_sni);
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
    let graceful_upgrade = env_or("PASSWAY_UPGRADE", "false") == "true";

    // R779 / R853-F6: socket activation. When a supervisor (kamaji's on-demand
    // JIT tier, or a systemd .socket unit) hands us an already-listening socket
    // as fd 3 under the LISTEN_FDS convention, transfer it into pingora's fd
    // table so it accepts on that socket instead of binding `PASSWAY_LISTEN`
    // fresh. The bind string must match `listen` exactly — that is the key
    // pingora looks up.
    //
    // The transfer rides pingora's own upgrade-socket protocol, which is why
    // this repoints `conf.upgrade_sock` and forces `Opt::upgrade`: `load_fds`
    // only runs under that flag. Both are set before the `Server` is built
    // because `Bootstrap` copies them out of `Opt`/`ServerConf` at construction.
    // Typed explicitly and `mut`-allowed because the only assignment lives
    // behind two cfgs: without them there is nothing for inference to chew on
    // and nothing that mutates it.
    #[allow(unused_mut)]
    let mut fd_handoff: Option<std::thread::JoinHandle<Result<usize, String>>> = None;
    if let Some(fd) = socket_activation_fd() {
        // Fail loudly rather than bind fresh, in every branch below: a
        // supervisor that handed us a socket expects us to accept on it, and a
        // second listener on the same address would either EADDRINUSE or
        // silently split traffic.
        #[cfg(not(feature = "socket-activation"))]
        panic!(
            "LISTEN_FDS is set (fd {fd}) but this passway was built without the `socket-activation` feature — see crates/passway/Cargo.toml [features]"
        );

        // pingora's fd transfer is Linux-only on 0.8.1 and on main alike:
        // off-Linux `get_fds_from` returns ECONNREFUSED and `Bootstrap` answers
        // that with `std::process::exit(1)`. Say so here rather than letting
        // pingora exit(1) with a message about graceful upgrades.
        #[cfg(all(feature = "socket-activation", not(target_os = "linux")))]
        panic!(
            "LISTEN_FDS is set (fd {fd}) but pingora's fd transfer is Linux-only, so socket activation cannot work on this platform — run passway without LISTEN_FDS, or on Linux"
        );

        #[cfg(all(feature = "socket-activation", target_os = "linux"))]
        {
            // One `upgrade_sock`, so one use of it. A process cannot both
            // receive a socket from a supervisor and receive one from a
            // predecessor passway.
            assert!(
                !graceful_upgrade,
                "PASSWAY_UPGRADE=true and LISTEN_FDS are mutually exclusive: both use pingora's upgrade socket, and the seed transfer would race the predecessor's send"
            );
            log::info!("passway: adopting inherited LISTEN_FDS socket (fd {fd}) for {listen}");
            let (seed_sock, handle) = passway::socket_activation::spawn_fd_handoff(
                listen.as_str(),
                fd,
            )
            .unwrap_or_else(|e| panic!("preparing inherited fd {fd} for handoff failed: {e}"));
            conf.upgrade_sock = seed_sock;
            fd_handoff = Some(handle);
        }
    }

    let opt = Opt {
        upgrade: graceful_upgrade || fd_handoff.is_some(),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(opt), conf);
    // The receiving half: binds `conf.upgrade_sock`, accepts the transfer.
    server.bootstrap();
    if let Some(handle) = fd_handoff {
        match handle.join() {
            Ok(Ok(_)) => log::info!("passway: inherited socket transferred to the listener table"),
            // `bootstrap()` returning means the receive succeeded, so a sender
            // error here is a torn half-state, not a benign race.
            Ok(Err(e)) => panic!("handing the inherited socket to pingora failed: {e}"),
            Err(_) => panic!("the inherited-socket handoff thread panicked"),
        }
    }

    // One health-checked, round-robin load balancer per fronted hostname
    // (R594-F10). Every returned background service must be added to the
    // server below, or its set's discovery/health timers never fire.
    let (router, lb_services) =
        build_host_router(upstream_sources, health_check_interval, update_interval);

    // The bare-form globals become the proxy-wide default, applied to every
    // set that declared no override of its own (R858-T1).
    let mut proxy = PassProxy::routed(router).with_upstream_tls(
        upstream_tls.global.unwrap_or(false),
        upstream_sni.global.unwrap_or_default(),
    );
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

    // ── PASSWAY_YUBABA_URL, N per host (R844-F23) ────────────────────────────

    fn urls(raw: &str) -> Vec<(HostKey, Vec<String>)> {
        parse_yubaba_url_sets(raw).expect("a valid PASSWAY_YUBABA_URL")
    }

    fn one(host: HostKey, url: &str) -> Vec<(HostKey, Vec<String>)> {
        vec![(host, vec![url.to_string()])]
    }

    /// Backwards compatibility, asserted FIRST because it is what the change
    /// rests on: every door deployed before F23 writes one bare URL, and that
    /// keeps meaning "poll this yubaba for every hostname".
    #[test]
    fn a_bare_yubaba_url_is_still_the_catch_all() {
        assert_eq!(
            urls("http://100.64.0.3:7443"),
            one(HostKey::CatchAll, "http://100.64.0.3:7443")
        );
    }

    #[test]
    fn a_star_prefixed_yubaba_url_says_catch_all_on_purpose() {
        assert_eq!(
            urls("*=http://100.64.0.3:7443"),
            urls("http://100.64.0.3:7443")
        );
    }

    /// The shape `yah cloud apply` renders for a multi-node placement
    /// (R844-F23): bare entries are the catch-all and repeating one ADDS, so a
    /// plain comma-list means "every hostname on this door discovers from
    /// these nodes" without a single hostname prefix.
    #[test]
    fn a_bare_list_adds_every_yubaba_to_the_catch_all() {
        assert_eq!(
            urls("http://100.64.0.3:7443,http://100.64.0.4:7443"),
            vec![(
                HostKey::CatchAll,
                vec![
                    "http://100.64.0.3:7443".to_string(),
                    "http://100.64.0.4:7443".to_string(),
                ]
            )]
        );
    }

    /// A hostname with no entry of its own falls back to the catch-all — the
    /// resolution `build_upstream_sources` performs, and what lets an
    /// unprefixed list serve a door whose idents ARE per hostname.
    #[test]
    fn a_hostname_with_no_url_entry_of_its_own_falls_back_to_the_catch_all() {
        let sets: BTreeMap<HostKey, Vec<String>> =
            urls("http://100.64.0.3:7443,http://100.64.0.4:7443")
                .into_iter()
                .collect();
        let key = HostKey::Host("analytics.yah.dev".into());
        assert!(!sets.contains_key(&key));
        assert_eq!(
            sets.get(&HostKey::CatchAll).expect("the catch-all is set").len(),
            2
        );
    }

    /// The `://` in a URL must not confuse the FIRST-`=` split, and the bare
    /// form has no `=` at all — the two halves of "this grammar reads URLs".
    #[test]
    fn host_prefixes_give_each_hostname_its_own_yubaba() {
        assert_eq!(
            urls("yah.dev=http://100.64.0.3:7443, analytics.yah.dev=http://100.64.0.9:7443"),
            vec![
                (
                    HostKey::Host("analytics.yah.dev".into()),
                    vec!["http://100.64.0.9:7443".to_string()]
                ),
                (
                    HostKey::Host("yah.dev".into()),
                    vec!["http://100.64.0.3:7443".to_string()]
                ),
            ]
        );
    }

    /// **The R844-F23 grammar decision.** Additive like `PASSWAY_UPSTREAMS`,
    /// NOT exclusive like `PASSWAY_YUBABA_IDENT`: a workload placed on two
    /// nodes has its records split across two node-local stores, so its
    /// hostname names two yubabas.
    #[test]
    fn a_repeated_hostname_adds_a_yubaba_rather_than_erroring() {
        assert_eq!(
            urls("yah.dev=http://100.64.0.3:7443,yah.dev=http://100.64.0.2:7443"),
            vec![(
                HostKey::Host("yah.dev".into()),
                vec![
                    "http://100.64.0.3:7443".to_string(),
                    "http://100.64.0.2:7443".to_string(),
                ]
            )]
        );
    }

    /// The other half of that decision, and it is deliberate rather than an
    /// oversight: N URLs is a set, N idents is a guess about which wins. A
    /// future edit "making them consistent" has to delete this assertion.
    #[test]
    fn the_ident_grammar_stays_exclusive_while_the_url_grammar_is_additive() {
        assert!(
            parse_ident_sets("yah.dev=yah-marketing,yah.dev=yah-analytics").is_err(),
            "one hostname is fronted by exactly one workload"
        );
        assert!(
            parse_yubaba_url_sets("yah.dev=http://100.64.0.3:7443,yah.dev=http://100.64.0.2:7443")
                .is_ok(),
            "but that workload may be placed on several nodes"
        );
    }

    /// Polling one yubaba twice would double-count its records, which skews the
    /// round-robin. An operator's duplicated entry is a typo, not a node.
    #[test]
    fn the_same_yubaba_named_twice_is_polled_once() {
        assert_eq!(
            urls("yah.dev=http://100.64.0.3:7443,yah.dev=http://100.64.0.3:7443"),
            one(HostKey::Host("yah.dev".into()), "http://100.64.0.3:7443")
        );
    }

    #[test]
    fn mixing_bare_and_prefixed_yubaba_urls_is_a_boot_failure() {
        let err = parse_yubaba_url_sets("http://100.64.0.3:7443,yah.dev=http://100.64.0.2:7443")
            .expect_err("an accidental catch-all must not be guessed at");
        assert!(err.contains("*=<url>"), "{err}");
    }

    /// Unlike the address grammar, which warns and skips: a set short one
    /// backend still serves, but a hostname with nothing to poll never
    /// discovers anything and would look like "yubaba has no records".
    #[test]
    fn an_empty_yubaba_url_is_rejected_rather_than_skipped() {
        let err = parse_yubaba_url_sets("yah.dev=").expect_err("an empty URL polls nothing");
        assert!(err.contains("no yubaba to poll"), "{err}");
        assert!(parse_yubaba_url_sets("=http://100.64.0.3:7443").is_err());
    }

    #[test]
    fn whitespace_and_empty_entries_are_tolerated_in_the_url_grammar_too() {
        assert_eq!(
            urls(" yah.dev = http://100.64.0.3:7443 , , "),
            one(HostKey::Host("yah.dev".into()), "http://100.64.0.3:7443")
        );
        assert!(parse_yubaba_url_sets("  ,  ").unwrap().is_empty());
    }

    // ---- R858-T1: per-host upstream scheme ----------------------------------

    #[test]
    fn a_bare_tls_value_is_the_process_wide_default() {
        // The pre-R858 form, and what every deployed door writes.
        let tls = parse_upstream_tls("true").unwrap();
        assert_eq!(tls.global, Some(true));
        assert!(tls.per_host.is_empty());

        let tls = parse_upstream_tls("false").unwrap();
        assert_eq!(tls.global, Some(false));
    }

    #[test]
    fn an_unset_tls_value_leaves_the_default_unstated() {
        // `env_or(.., "")` when the variable is absent — the door then keeps
        // the plaintext-to-upstream default from `PassProxy::routed`.
        let tls = parse_upstream_tls("").unwrap();
        assert_eq!(tls.global, None);
        assert!(tls.per_host.is_empty());
    }

    #[test]
    fn a_bare_tls_value_is_case_insensitive_but_not_a_free_for_all() {
        assert_eq!(parse_upstream_tls("TRUE").unwrap().global, Some(true));
        // `yes` used to read as `false` (the `== "true"` comparison), which is
        // the silent wrong answer this rejects.
        let err = parse_upstream_tls("yes").expect_err("not a boolean");
        assert!(err.contains("\"true\" or \"false\""), "{err}");
    }

    #[test]
    fn tls_takes_the_same_fan_in_grammar_as_the_address_list() {
        let tls = parse_upstream_tls("cloud.mesh.yah.dev=true,*=false").unwrap();
        assert_eq!(tls.global, None);
        assert_eq!(
            tls.per_host
                .get(&HostKey::Host("cloud.mesh.yah.dev".into())),
            Some(&true)
        );
        assert_eq!(tls.per_host.get(&HostKey::CatchAll), Some(&false));
    }

    #[test]
    fn mixing_a_bare_tls_value_with_prefixed_ones_is_rejected() {
        let err = parse_upstream_tls("true,cloud.mesh.yah.dev=false")
            .expect_err("bare + prefixed is ambiguous");
        assert!(err.contains("mixes"), "{err}");
    }

    #[test]
    fn a_repeated_hostname_in_the_tls_grammar_is_an_error_not_a_silent_pick() {
        let err = parse_upstream_tls("yah.dev=true,yah.dev=false").expect_err("repeated hostname");
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn an_empty_hostname_is_rejected_in_the_tls_grammar_too() {
        assert!(parse_upstream_tls("=true").is_err());
    }

    #[test]
    fn sni_takes_a_bare_string_or_the_fan_in_form() {
        assert_eq!(
            parse_upstream_sni("edge.example.com").unwrap().global,
            Some("edge.example.com".to_string())
        );
        let sni = parse_upstream_sni("cloud.mesh.yah.dev=cloud.mesh.yah.dev").unwrap();
        assert_eq!(
            sni.per_host
                .get(&HostKey::Host("cloud.mesh.yah.dev".into())),
            Some(&"cloud.mesh.yah.dev".to_string())
        );
        // Unset stays unset rather than becoming an empty SNI entry.
        assert_eq!(parse_upstream_sni("").unwrap().global, None);
    }

    #[test]
    fn a_prefixed_sni_entry_with_no_value_is_rejected() {
        let err = parse_upstream_sni("cloud.mesh.yah.dev=").expect_err("names no SNI");
        assert!(err.contains("names no SNI"), "{err}");
    }

    #[test]
    fn a_set_with_no_override_inherits_the_proxy_wide_default() {
        let tls = parse_upstream_tls("true").unwrap();
        let sni = parse_upstream_sni("edge.example.com").unwrap();
        // `None` = "ask the proxy", which is where the bare globals landed.
        assert_eq!(upstream_opts_for(&HostKey::CatchAll, &tls, &sni), None);
        assert_eq!(
            upstream_opts_for(&HostKey::Host("yah.dev".into()), &tls, &sni),
            None
        );
    }

    #[test]
    fn a_per_host_override_wins_and_fills_the_other_half_from_the_default() {
        let tls = parse_upstream_tls("cloud.mesh.yah.dev=true,*=false").unwrap();
        let sni = parse_upstream_sni("cloud.mesh.yah.dev=cloud.mesh.yah.dev").unwrap();

        assert_eq!(
            upstream_opts_for(&HostKey::Host("cloud.mesh.yah.dev".into()), &tls, &sni),
            Some(UpstreamOpts {
                tls: true,
                sni: "cloud.mesh.yah.dev".into()
            })
        );
        // The catch-all named a TLS value but no SNI, so it gets the empty
        // one — which is the only sensible pairing with `tls: false`.
        assert_eq!(
            upstream_opts_for(&HostKey::CatchAll, &tls, &sni),
            Some(UpstreamOpts {
                tls: false,
                sni: String::new()
            })
        );
    }

    #[test]
    fn an_sni_only_override_still_inherits_the_global_tls_flag() {
        let tls = parse_upstream_tls("true").unwrap();
        let sni = parse_upstream_sni("a.example.com=a.internal").unwrap();
        assert_eq!(
            upstream_opts_for(&HostKey::Host("a.example.com".into()), &tls, &sni),
            Some(UpstreamOpts {
                tls: true,
                sni: "a.internal".into()
            })
        );
    }

    // ---- R858-T1: static pins alongside discovery ---------------------------

    #[test]
    fn discovery_and_static_pins_coexist_per_hostname() {
        let merged = merge_static_over_discovered(
            &[HostKey::Host("cloud.mesh.yah.dev".into())],
            &[HostKey::Host("yah.dev".into())],
        );
        assert_eq!(
            merged.sets,
            vec![
                (
                    HostKey::Host("cloud.mesh.yah.dev".into()),
                    SetOrigin::Static
                ),
                (HostKey::Host("yah.dev".into()), SetOrigin::Discovered),
            ]
        );
        assert!(merged.overridden.is_empty());
    }

    #[test]
    fn a_static_pin_wins_a_hostname_discovery_also_names() {
        let merged = merge_static_over_discovered(
            &[HostKey::Host("yah.dev".into())],
            &[
                HostKey::Host("yah.dev".into()),
                HostKey::Host("analytics.yah.dev".into()),
            ],
        );
        assert_eq!(
            merged.sets,
            vec![
                (
                    HostKey::Host("analytics.yah.dev".into()),
                    SetOrigin::Discovered
                ),
                (HostKey::Host("yah.dev".into()), SetOrigin::Static),
            ]
        );
        // Named, so the caller can warn about the hostname specifically —
        // a silent pick is what this grammar refuses everywhere else.
        assert_eq!(merged.overridden, vec![HostKey::Host("yah.dev".into())]);
    }

    #[test]
    fn no_static_pins_leaves_discovery_exactly_as_it_was() {
        let discovered = vec![
            HostKey::Host("yah.dev".into()),
            HostKey::Host("analytics.yah.dev".into()),
        ];
        let merged = merge_static_over_discovered(&[], &discovered);
        assert_eq!(
            merged.sets,
            vec![
                (
                    HostKey::Host("analytics.yah.dev".into()),
                    SetOrigin::Discovered
                ),
                (HostKey::Host("yah.dev".into()), SetOrigin::Discovered),
            ]
        );
        assert!(merged.overridden.is_empty());
    }

    #[test]
    fn a_catch_all_pin_and_a_catch_all_discovery_collide_like_any_other_key() {
        let merged = merge_static_over_discovered(&[HostKey::CatchAll], &[HostKey::CatchAll]);
        assert_eq!(merged.sets, vec![(HostKey::CatchAll, SetOrigin::Static)]);
        assert_eq!(merged.overridden, vec![HostKey::CatchAll]);
    }
}
