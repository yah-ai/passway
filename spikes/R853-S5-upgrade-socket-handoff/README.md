# R853-S5 — hand pingora a listening fd without the fork

**Verdict: it works.** A process can hand a listening socket to its *own*
pingora `Server` over pingora's upgrade socket, using only public API on
**stock crates.io `pingora-core` 0.8.1**. No `Server::seed_listen_fd`, no
fork, no `[patch.crates-io]`.

This directory is deliberately **not** a workspace member — `oss/passway`'s
`[workspace] members` lists only `crates/*`, so nothing here is built,
published, or linted by the passway workspace. It is the executable record of
the spike, kept because re-deriving it is expensive and the decision it feeds
is not yet made.

## Why this matters

> **Settled 2026-09-04/05.** passway took the route this spike proves
> (R853-F6), and the fork and its carried patches are both deleted (R853-T1).
> What follows is the state of play *at the time of the spike*, kept as the
> record of why it was run.

passway's `socket-activation` feature currently needs three hunks that only
exist on `github.com/yah-ai/pingora`. Carrying that fork costs:

- `oss/passway/Cargo.toml`'s `[patch.crates-io]` block, all 14 pingora crates;
- `oss/passway/deny.toml`'s `allow-git` carve-out;
- a rebase every pingora release (0.8.1 → `main` is 190 commits and **2 of the
  3 hunks conflict** — the rebase writeup was at `../../patches/UPSTREAM.md`,
  deleted 2026-09-05, recoverable at
  `git show be2680f4:oss/passway/patches/UPSTREAM.md`);
- and, live today, a broken `cargo install passway --features socket-activation`
  for anyone on crates.io, because `[patch.crates-io]` is not in the published
  `.crate` and does not propagate.

All four went away at once when passway adopted this route.

## What it proves, and how

Same unambiguous shape as `crates/passway/tests/socket_activation.rs`: the
socket handed over is bound to **port A**, but announced to pingora under the
bind string for **port B**, which nothing ever binds. pingora keys its fd table
by the bind string and never inspects the fd's real address — so a request
answered on A can only have arrived through the transferred socket. The control
is that **B must refuse**: if pingora had bound fresh it would be listening
there, and the port-A answer would prove nothing.

Direction is the opposite of the intuitive guess, and is the one thing to get
right when reading the code: the **receiver** (the server, under
`Opt::upgrade = true`) unlinks, binds and listens on `ServerConf::upgrade_sock`,
then `accept()`s with retries. The **sender** connects. So the sender must run
off the main thread while `bootstrap()` blocks on the receive. Both sides
retry — `send_fds_to` tolerates `ENOENT`/`ECONNREFUSED` and `get_fds_from`
tolerates `EAGAIN`, each 5 × 1s on 0.8.1 — so the startup skew is absorbed.

Everything it touches is public on stock 0.8.1:
`pingora_core::server::Fds` is `pub use`d from `server/mod.rs:50` with
`new`/`add`/`send_to_sock`, and `Opt::upgrade` drives exactly one thing in
`Bootstrap` — `load_fds(true)` → `get_from_sock`.

## Results (2026-09-04, `rust:1-bookworm`, linux/aarch64)

| run | result |
|---|---|
| single run | **PASS** — port A answered, port B refused |
| 10 consecutive runs | **10 PASS / 0 FAIL** — the in-process handoff is not flaky |
| `FDSPIKE_BLOCKING=1` control | **FAIL as designed** — nothing served, `WouldBlock` |

That last row is the point of the `O_NONBLOCK` line in `main.rs`. A socket
bound by the std library is blocking; pingora's `listeners::l4::from_raw_fd`
does not set `O_NONBLOCK` and tokio's `from_std` does not either, so the first
accept stalls a worker. On the fork that is fixed *inside* pingora — the third
of the three carried hunks. Here it is done on our own fd before handing it
over, which is why that hunk is not needed either. The control run is the proof
that it is load-bearing rather than cargo-culted.

## The constraint that caps this

**pingora's fd transfer is Linux-only, on 0.8.1 and on `main` alike.** Under
`#[cfg(not(target_os = "linux"))]`, `get_fds_from` logs "Upgrade is not
currently supported outside of Linux platforms" and returns `Err(ECONNREFUSED)`;
`send_fds_to` returns `Ok(0)` and silently sends nothing. `Bootstrap::bootstrap`
calls `std::process::exit(1)` on a `load_fds` error, so taking this route on
macOS would hard-exit the process. No passway-side code fixes that — the
receiving half is pingora's.

What that actually costs is **a local test, not a deployment capability**:
socket activation exists to ride kamaji's on-demand JIT tier, which runs on the
Linux fleet, and nothing deploys passway on darwin. But
`crates/passway/tests/socket_activation.rs` carries no cfg gate today and
passes on this darwin camp, so adopting this would gate it to Linux and the
camp would stop exercising the cold-start path locally — with no CI to catch it
either (no workflow in this repo has an `on: push` trigger).

## Running it

Needs Linux. From this directory, with a container runtime:

```sh
docker run --rm -v "$PWD":/work -w /work rust:1-bookworm sh -c '
  apt-get update -qq && apt-get install -y -qq cmake >/dev/null 2>&1
  cargo build
  ./target/debug/fdspike                        # expect PASS, exit 0
  FDSPIKE_BLOCKING=1 timeout 30 ./target/debug/fdspike   # expect FAIL, exit 1
'
```

`cmake` is needed only because `libz-ng-sys` builds zlib-ng from source; it is
not related to what is being tested.
