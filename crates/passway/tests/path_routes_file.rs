//! Integration test: a **real passway binary**, configured through R870-T18's
//! `PASSWAY_PATH_ROUTES_FILE`, path-routing to two upstreams.
//!
//! `tests/path_routing.rs` proves the *mechanism* — it builds a `PathRouter`
//! in-process and drives a `pingora::Server` with it. That is deliberately not
//! the gate this file exists for. R870-F15 could not run the live gates in its
//! own verify list because nothing could *configure* a passway process with a
//! `PathRouter` at all; what is under test here is that the configuration
//! reaches the mechanism in a forked `passway` process that read a file off
//! disk, resolved a mount table from it, and served two different components
//! on one hostname.
//!
//! So this file asserts through the binary's own front door: a TLS listener,
//! an HTTP client that resolves the hostname to it, and two independent fake
//! upstreams that tag their responses. If the env-var name, the JSON field
//! spellings, the strategy selection in `main()` or the wiring into
//! `PassProxy::path_routed` were wrong, everything here fails — none of which
//! an in-process test can see.
//!
//! Not covered here, and not coverable here: "a single-component service
//! produces no inner door at all". That is a property of the *config
//! generator* (the `service.toml` + domain-manifest join, R870-T18 scope item
//! 3, filed separately) — passway proxies whatever table it is handed and has
//! no view of how many components a service declares. What this file can
//! assert, and does, is the misconfiguration next door: a table alongside the
//! host-routed grammars is refused at boot rather than half-honoured.

use crate::common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

const TENANT: &str = "noisetable.test";

/// Hand-rolled scratch dir — this crate does not take `tempfile` (see
/// `Cargo.toml`'s dev-dependencies note); same idiom as
/// `tests/jit_cold_start.rs`.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "passway-path-routes-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Mint the self-signed leaf the door serves. The door under test terminates
/// TLS unconditionally (`TlsMode::Manual` is the default and `main()` always
/// calls `add_tls_with_settings`), so even a loopback inner door needs a
/// cert — see this ticket's handoff note.
fn write_leaf(scratch: &Scratch) -> (PathBuf, PathBuf) {
    let cert = scratch.path("tenant.crt");
    let key = scratch.path("tenant.key");
    let rcgen::CertifiedKey {
        cert: leaf,
        signing_key,
    } = rcgen::generate_simple_self_signed(vec![TENANT.to_string()]).expect("self-signed leaf");
    std::fs::write(&cert, leaf.pem()).expect("write cert");
    std::fs::write(&key, signing_key.serialize_pem()).expect("write key");
    (cert, key)
}

/// Fork a real `passway`. `kill_on_drop` is what reaps it, so a test that
/// leaves the returned handle bound for its duration cannot leak a listener.
fn spawn_door(
    scratch: &Scratch,
    listen: SocketAddr,
    extra: &[(&str, String)],
) -> tokio::process::Child {
    let (cert, key) = write_leaf(scratch);
    let mut cmd = tokio::process::Command::new(PathBuf::from(env!("CARGO_BIN_EXE_passway")));
    cmd.env("PASSWAY_LISTEN", listen.to_string())
        .env("PASSWAY_TLS_CERT", cert)
        .env("PASSWAY_TLS_KEY", key)
        // Both default into /tmp under a fixed name; two concurrent runs on
        // this shared machine would fight over them.
        .env("PASSWAY_PID_FILE", scratch.path("pingora.pid"))
        .env("PASSWAY_UPGRADE_SOCK", scratch.path("pingora_upgrade.sock"))
        // The default is 5s, which would leave every mount unready for most of
        // this test's budget.
        .env("PASSWAY_HEALTH_CHECK_INTERVAL_SECS", "1")
        // A test runner's ambient environment must not decide the strategy.
        .env_remove("PASSWAY_UPSTREAM_SOURCE")
        .env_remove("PASSWAY_UPSTREAMS")
        .env_remove("PASSWAY_YUBABA_URL")
        .env_remove("PASSWAY_YUBABA_IDENT")
        .env_remove("PASSWAY_PATH_ROUTES_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn passway")
}

fn client(listen: SocketAddr) -> reqwest::Client {
    reqwest::Client::builder()
        // The leaf is self-signed and its name is never in DNS; under test is
        // the mount table, not PKI.
        .danger_accept_invalid_certs(true)
        .resolve(TENANT, listen)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build TLS client")
}

/// A cold door plus pingora's first health tick is legitimately slow, and a
/// 503 inside that window is the window rather than a failure. Anything still
/// not 200 at the deadline is the failure.
async fn get_until_ok(client: &reqwest::Client, path: &str) -> reqwest::Response {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(resp) = client.get(format!("https://{TENANT}{path}")).send().await {
            if resp.status().is_success() {
                return resp;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("GET {path} never returned 200 through the forked door within 20s");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn tag(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("x-upstream-tag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>")
        .to_string()
}

/// THE GATE R870-F15 COULD NOT RUN. One forked `passway` binary, one hostname,
/// two components, a mount table it learned from a file — and the three
/// behaviours that table is supposed to produce:
///
/// 1. `/` reaches the site upstream and `/app/` reaches the app upstream, so
///    the split serving works through the real configuration path;
/// 2. `/application` falls to the ROOT mount, never to `/app` — the naive
///    `starts_with` bug, disproven against a live listener rather than in
///    process;
/// 3. the `/app` mount's COOP/COEP pair lands on `/app`'s responses and on
///    nothing else — the header-ownership seam that, got wrong, makes
///    `SharedArrayBuffer` silently undefined.
#[tokio::test]
async fn a_forked_passway_configured_by_file_serves_two_mounts_on_one_hostname() {
    let scratch = Scratch::new("serves");
    let site = common::spawn_fake_upstream("site").await;
    let app = common::spawn_fake_upstream("app").await;

    let routes = scratch.path("path.routes.json");
    std::fs::write(
        &routes,
        format!(
            r#"{{ "schema_version": 1,
                  "routes": [
                    {{ "mount": "", "upstreams": ["{site}"] }},
                    {{ "mount": "/app", "upstreams": ["{app}"],
                       "headers": {{
                         "cross-origin-opener-policy": "same-origin",
                         "cross-origin-embedder-policy": "require-corp"
                       }} }}
                  ] }}"#
        ),
    )
    .expect("write routes file");

    let listen = common::free_addr();
    let _door = spawn_door(
        &scratch,
        listen,
        &[(
            "PASSWAY_PATH_ROUTES_FILE",
            routes.display().to_string(),
        )],
    );
    let client = client(listen);

    let root = get_until_ok(&client, "/").await;
    assert_eq!(tag(&root), "site", "the root mount must reach the site bundle");
    assert!(
        root.headers().get("cross-origin-opener-policy").is_none(),
        "/app's headers must not leak onto the root mount's responses"
    );

    let app_resp = get_until_ok(&client, "/app/").await;
    assert_eq!(tag(&app_resp), "app", "/app/ must reach the app bundle");
    assert_eq!(
        app_resp
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|v| v.to_str().ok()),
        Some("same-origin"),
    );
    assert_eq!(
        app_resp
            .headers()
            .get("cross-origin-embedder-policy")
            .and_then(|v| v.to_str().ok()),
        Some("require-corp"),
    );

    let adjacent = get_until_ok(&client, "/application").await;
    assert_eq!(
        tag(&adjacent),
        "site",
        "/application must fall to the root mount, never to /app"
    );
}

/// One passway is one routing strategy. A door configured with both a mount
/// table and a host table must refuse to start rather than silently honour one
/// of them — the operator's other half would be dead config, and which half
/// died would only be visible as requests reaching the wrong component.
#[tokio::test]
async fn a_door_configured_with_both_strategies_refuses_to_start() {
    let scratch = Scratch::new("both");
    let upstream = common::spawn_fake_upstream("site").await;

    let routes = scratch.path("path.routes.json");
    std::fs::write(
        &routes,
        format!(r#"{{"schema_version": 1, "routes": [{{"mount": "", "upstreams": ["{upstream}"]}}]}}"#),
    )
    .expect("write routes file");

    let door = spawn_door(
        &scratch,
        common::free_addr(),
        &[
            ("PASSWAY_PATH_ROUTES_FILE", routes.display().to_string()),
            ("PASSWAY_UPSTREAMS", upstream.to_string()),
        ],
    );

    let out = tokio::time::timeout(Duration::from_secs(30), door.wait_with_output())
        .await
        .expect("a door configured with both strategies must exit, not serve")
        .expect("collect the refused door's output");
    assert!(
        !out.status.success(),
        "expected a non-zero exit; got {:?}",
        out.status
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("PASSWAY_PATH_ROUTES_FILE") && said.contains("PASSWAY_UPSTREAMS"),
        "the refusal must name both halves so the operator knows which to unset; said: {said}"
    );
}

/// A table that cannot be read is a boot failure, not a door that comes up
/// 503ing every path — the two are indistinguishable from outside, and only
/// one of them is attributable.
#[tokio::test]
async fn a_door_pointed_at_an_unreadable_table_refuses_to_start() {
    let scratch = Scratch::new("missing");
    let door = spawn_door(
        &scratch,
        common::free_addr(),
        &[(
            "PASSWAY_PATH_ROUTES_FILE",
            scratch.path("nope.json").display().to_string(),
        )],
    );

    let out = tokio::time::timeout(Duration::from_secs(30), door.wait_with_output())
        .await
        .expect("a door with no readable table must exit, not serve")
        .expect("collect the refused door's output");
    assert!(!out.status.success(), "expected a non-zero exit");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("PASSWAY_PATH_ROUTES_FILE"),
        "the refusal must name the variable that pointed at the missing file; said: {said}"
    );
}

// ── R870-F23: the cleartext inner door ───────────────────────────────────────

/// Fork a real `passway` in `PASSWAY_TLS_MODE=plaintext`. Deliberately NOT a
/// flag on [`spawn_door`]: that helper writes and passes a leaf, and a door
/// carrying `PASSWAY_TLS_CERT` is exactly what the mode refuses. Two spawners
/// is the honest shape — a cleartext door has no certificate at any point.
fn spawn_plaintext_door(
    scratch: &Scratch,
    listen: SocketAddr,
    routes: &std::path::Path,
) -> tokio::process::Child {
    let mut cmd = tokio::process::Command::new(PathBuf::from(env!("CARGO_BIN_EXE_passway")));
    cmd.env("PASSWAY_TLS_MODE", "plaintext")
        .env("PASSWAY_LISTEN", listen.to_string())
        .env("PASSWAY_PATH_ROUTES_FILE", routes)
        .env("PASSWAY_PID_FILE", scratch.path("pingora.pid"))
        .env("PASSWAY_UPGRADE_SOCK", scratch.path("pingora_upgrade.sock"))
        .env("PASSWAY_HEALTH_CHECK_INTERVAL_SECS", "1")
        .env_remove("PASSWAY_TLS_CERT")
        .env_remove("PASSWAY_TLS_KEY")
        .env_remove("PASSWAY_UPSTREAM_SOURCE")
        .env_remove("PASSWAY_UPSTREAMS")
        .env_remove("PASSWAY_YUBABA_URL")
        .env_remove("PASSWAY_YUBABA_IDENT")
        .env_remove("LISTEN_FDS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn().expect("spawn plaintext passway")
}

async fn get_plaintext_until_ok(
    client: &reqwest::Client,
    listen: SocketAddr,
    path: &str,
) -> reqwest::Response {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(resp) = client.get(format!("http://{listen}{path}")).send().await {
            if resp.status().is_success() {
                return resp;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("GET {path} never returned 200 through the cleartext door within 20s");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// THE MODE R870-F23'S OPERATOR CALL AUTHORIZED, proven through the binary.
///
/// The whole point of the inner tier is that it costs a process and nothing
/// else — no certificate, no renewal story, no loopback handshake. This is the
/// assertion that it actually does: a real passway with NO cert configured at
/// all serves the same two-mount split, with the same per-mount headers, over
/// cleartext HTTP on loopback.
#[tokio::test]
async fn a_cleartext_inner_door_serves_the_same_mount_table_with_no_certificate() {
    let scratch = Scratch::new("plaintext");
    let site = common::spawn_fake_upstream("site").await;
    let app = common::spawn_fake_upstream("app").await;

    let routes = scratch.path("inner.routes.json");
    std::fs::write(
        &routes,
        format!(
            r#"{{ "schema_version": 1,
                  "routes": [
                    {{ "mount": "", "upstreams": ["{site}"] }},
                    {{ "mount": "/app", "upstreams": ["{app}"],
                       "headers": {{ "cross-origin-opener-policy": "same-origin" }} }}
                  ] }}"#
        ),
    )
    .expect("write routes file");

    let listen = common::free_addr();
    let _door = spawn_plaintext_door(&scratch, listen, &routes);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build plain client");

    let root = get_plaintext_until_ok(&client, listen, "/").await;
    assert_eq!(tag(&root), "site");
    assert!(
        root.headers().get("cross-origin-opener-policy").is_none(),
        "the root mount declares no headers and must gain none"
    );

    let mounted = get_plaintext_until_ok(&client, listen, "/app/").await;
    assert_eq!(tag(&mounted), "app");
    assert_eq!(
        mounted
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|v| v.to_str().ok()),
        Some("same-origin"),
    );
}

/// The invariant that makes the mode safe, asserted against the binary rather
/// than only against the parser: a cleartext door bound anywhere reachable
/// does not start. `0.0.0.0` is the DEFAULT bind, so this is the single
/// misconfiguration that turns an inner door into a public cleartext one.
#[tokio::test]
async fn a_cleartext_door_on_a_reachable_bind_refuses_to_start() {
    let scratch = Scratch::new("plaintext-public");
    let routes = scratch.path("inner.routes.json");
    std::fs::write(&routes, r#"{"schema_version":1,"routes":[{"mount":"","upstreams":["127.0.0.1:1"]}]}"#)
        .expect("write routes file");

    let door = spawn_plaintext_door(&scratch, "0.0.0.0:0".parse().unwrap(), &routes);
    let out = tokio::time::timeout(Duration::from_secs(30), door.wait_with_output())
        .await
        .expect("a cleartext door on a public bind must exit, not serve")
        .expect("collect the refused door's output");
    assert!(!out.status.success(), "expected a non-zero exit");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("not loopback"),
        "the refusal must name the bind as the reason; said: {said}"
    );
}
