# passway/patches — carried pingora changes

passway pins `pingora = ">=0.8.1"` from crates.io. Anything here is a change
pingora needs that upstream does not have yet: each patch is small, applies
to the named tag, and is meant to be sent to `cloudflare/pingora` — the fork
is a waiting room, not a home.

## `pingora-0.8.1-seed-listen-fds.patch` (R779, W267 §"Free-tier ingress at 10k domains")

Adds `Server::seed_listen_fd(bind, fd)` (+ `Bootstrap::seed_fd`) so a server
can adopt an already-listening socket handed to it by a supervisor — systemd
socket activation, or kamaji's on-demand JIT tier, which holds the socket and
forks the workload on the first connection with the socket as fd 3 under
`LISTEN_FDS=1`. pingora's only fd-inheritance path was its own upgrade socket
(`SCM_RIGHTS` from a previous pingora), filled by a private function; this
patch lets the application seed the same table before `bootstrap()`. It also
makes `listeners::l4::from_raw_fd` set the adopted fd non-blocking — an fd
bound by the std library is blocking, and tokio's `from_std` does not change
that, so without it the first accept would stall a worker (caught by
`tests/socket_activation.rs`).

Three files, ~90 lines including doc comments. Behaviour without the API
call is unchanged; fds received over the upgrade socket still win for the
same bind.

### Using it

1. Fork: `github.com/yah-ai/pingora`, branch `yah/seed-listen-fds-0.8.1`
   = tag `0.8.1` + this patch (`git apply patches/pingora-0.8.1-seed-listen-fds.patch`
   from the fork's root).

   **Status 2026-08-29 — LANDED.** The branch is pushed:
   `refs/heads/yah/seed-listen-fds-0.8.1` on `github.com/yah-ai/pingora` is
   `2f52d944c832089bad6bd847b868d5c9f37fb201`, cut off tag `0.8.1`
   (`8782f349`). The `[patch.crates-io]` block below is **committed** in
   `oss/passway/Cargo.toml` pinning that full rev, and
   `crates/passway`'s `default` is `["socket-activation"]`. The local clone
   at `external/pingora` is gitignored and therefore machine-local, which is
   why the block uses `git =` + `rev` and never a `path` into it.

   Steps 2–3 below are the historical recipe; they are already applied. What
   remains is step 4 (upstream), and until that lands neither the block nor
   the default may be removed — the feature does not compile against
   crates.io pingora.
2. In `oss/passway/Cargo.toml` add — **every** pingora crate in the graph,
   not just `pingora-core`, or `pingora-error` / `pingora-http` get
   duplicated (registry vs fork) and the types stop unifying:

   ```toml
   [patch.crates-io]
   pingora                = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-cache          = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-core           = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-error          = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-header-serde   = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-http           = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-ketama         = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-load-balancing = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-lru            = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-pool           = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-proxy          = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-runtime        = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-rustls         = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   pingora-timeout        = { git = "https://github.com/yah-ai/pingora", branch = "yah/seed-listen-fds-0.8.1" }
   ```

   Pin the full `rev = "2f52d944c832089bad6bd847b868d5c9f37fb201"` rather
   than `branch` — a moving branch in a `[patch]` block makes the build
   non-reproducible.
3. Build passway with `--features socket-activation` (now `default`). The
   feature is what gates the `seed_listen_fd` call and
   `tests/socket_activation.rs`; without the fork it does not compile, by
   design.
4. Upstream: open the PR against `cloudflare/pingora` `main` (the same three
   hunks apply; on `main`, `Bootstrap::listen_fds` is already a non-optional
   `ListenFds`, so `load_fds` merges into it instead of replacing). When it
   lands and ships, drop the `[patch]` block and this file's entry.

Verified three times. 2026-08-28, twice: first with the patch applied to the
0.8.1 tarball via a local `path =` patch block; then against the **fork branch
itself** (`external/pingora` at `2f52d94`, all 14 crates patched to that
checkout via `cargo --config`, so the committed `oss/passway/Cargo.toml` was
never touched). 2026-08-29, once more against the **pushed** rev through the
committed `[patch]` block — i.e. resolving over the network the way any other
machine in the camp will — with `socket-activation` on by default: workspace
libs 104 + 19 + 9, integration 26/26, clippy `--all-targets` at the same three
pre-existing warnings. All runs: passway lib 104/104, integration 26/26 including
`socket_activation::inherited_listening_socket_is_adopted_under_the_bind_string`
(the fd handed in is bound to port A but seeded under bind string `:B`; the
request answered on A can only have come through the inherited socket).
