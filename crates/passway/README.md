# passway

[![crates.io](https://img.shields.io/crates/v/passway.svg)](https://crates.io/crates/passway)
[![docs.rs](https://docs.rs/passway/badge.svg)](https://docs.rs/passway)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A sovereign public-ingress **L7 reverse proxy** built on
[pingora](https://docs.rs/pingora) (Cloudflare's own edge-proxy framework). It
terminates TLS, load-balances round-robin over a health-checked upstream set,
verifies edge auth via [`cheers-verify`](https://crates.io/crates/cheers-verify),
hardens against request smuggling, and answers a `/health` endpoint a
floating-IP or DNS health check can gate on.

The thesis: **run the same machinery Cloudflare runs, on a VPS you rent** —
keep your own IPs and TLS termination instead of handing the edge to a managed
CDN.

## Run it

`passway` ships a binary configured entirely from the environment:

```bash
PASSWAY_LISTEN=0.0.0.0:443 \
PASSWAY_TLS_CERT=/etc/passway/fullchain.pem \
PASSWAY_TLS_KEY=/etc/passway/privkey.pem \
PASSWAY_UPSTREAMS=10.0.0.1:8080,10.0.0.2:8080 \
  passway
```

| Variable | Meaning | Default |
|---|---|---|
| `PASSWAY_LISTEN` | TLS listener address | `0.0.0.0:443` |
| `PASSWAY_TLS_CERT` | PEM cert chain path | required |
| `PASSWAY_TLS_KEY` | PEM private key path | required |
| `PASSWAY_UPSTREAMS` | comma-separated backend list, optionally `<hostname>=` prefixed (see below) | empty (fail-ready 503) |
| `PASSWAY_UPSTREAM_TLS` | speak TLS to upstreams — bare `true`/`false`, or `<hostname>=` prefixed to give one fronted service its own scheme | `false` |
| `PASSWAY_UPSTREAM_SNI` | SNI when upstream TLS is on — bare string, or the same `<hostname>=` prefixed form | empty |
| `PASSWAY_HEALTH_PATH` | readiness path | `/health` |
| `PASSWAY_HEALTH_CHECK_INTERVAL_SECS` | TCP health-check cadence | `5` |
| `PASSWAY_UPDATE_INTERVAL_SECS` | upstream re-poll cadence | `30` |
| `PASSWAY_AUTH_PUBLIC_KEY_FILE` | raw 32-byte Ed25519 public key path | unset (auth off) |
| `PASSWAY_AUTH_KID` | the `kid` this deployment trusts | required with a key |
| `PASSWAY_AUTH_ISS` | expected PASETO `iss` | required with a key |
| `PASSWAY_AUTH_AUD` | expected PASETO `aud` | required with a key |
| `PASSWAY_AUTH_REQUIRED_PREFIXES` | path prefixes requiring a bearer | empty (anonymous) |

Auth is off until `PASSWAY_AUTH_PUBLIC_KEY_FILE` is set; an empty upstream set
fails *ready* (reports `/health` unready) rather than crashing, so a cold start
is not an outage.

### Fronting several services from one node

Prefix an entry with `<hostname>=` to give that hostname its own upstream set;
repeat the hostname to add addresses to it. Requests are routed by authority
(`Host` / `:authority`), and each set is round-robined and health-checked
independently:

```bash
PASSWAY_UPSTREAMS=marketing.example.com=10.0.0.1:8080,\
marketing.example.com=10.0.0.2:8080,\
analytics.example.com=10.0.0.3:9000
```

An authority no entry names gets a 503 — never another service's backends. To
serve unmatched authorities anyway, declare a catch-all explicitly with the
reserved `*=` prefix. Unprefixed entries are the single-set form and become the
catch-all; *mixing* unprefixed and `<hostname>=` entries is rejected at boot,
because an accidental catch-all on a multi-tenant front door is a cross-tenant
leak waiting to happen. On a host-routed instance `/health` also reports a
per-hostname `upstreams_by_host` breakdown.

Routing is on the HTTP authority, not TLS SNI: pingora's rustls backend does
not surface the negotiated server name to the proxy (see `src/host.rs`).

## Use it as a library

The binary is the thinnest possible wiring of a reusable library. Embed the
proxy in your own `pingora::server::Server`:

- `PassProxy` — the `pingora::proxy::ProxyHttp` request path (routing, auth
  gate, hardening, `/health`).
- `UpstreamSource` / `StaticUpstreams` — the pluggable upstream seam; implement
  `UpstreamSource` to feed peers from your own control plane.
- `HostRouter` / `build_host_router` — the host → upstream-set map above that
  seam, for one node fronting several services.
- `CheersAuth` / `RouteAuthPolicy` — `cheers-verify` wiring and per-route auth
  policy.
- `TlsMode` — TLS listener configuration (bring-your-own-cert today, with an
  ACME hook documented for a follow-up).

The `hardening` and `health` modules are pure, independently testable functions
over `http::HeaderMap` — hop-by-hop header stripping and
Content-Length/Transfer-Encoding conflict rejection.

## Trust boundary

`passway` terminates public, untrusted, unauthenticated traffic. It fails closed
on ambiguity (auth, smuggling-shaped requests) and pins `pingora >= 0.8.1`
(request-smuggling fix RUSTSEC-2025-0037). `rustls` is the only TLS backend it
ever links — never boringssl/openssl (see `deny.toml`'s explicit bans).

## Minimum supported Rust version

Rust 1.85.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual-licensed as above, without any additional terms or conditions.
