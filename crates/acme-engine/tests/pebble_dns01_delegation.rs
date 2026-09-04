//! R779-P8 — proves the DNS-01 **challenge-delegation record name** against a
//! real CA.
//!
//! [`acme_engine::dns01_record_name`] is the whole onboarding contract: whatever
//! it returns is exactly what a tenant CNAMEs `_acme-challenge.<their domain>`
//! to. Its unit tests pin the string, but a string only matters if a CA
//! actually resolves it — a name that drifts by one label passes every unit
//! test in the crate and fails every tenant. This test closes that gap by
//! standing up [Pebble][pebble] (Let's Encrypt's test ACME server) plus
//! `pebble-challtestsrv` (its mock DNS server), installing *the tenant's half*
//! of the contract as a CNAME, and letting Pebble's validation authority follow
//! it to wherever this engine really published.
//!
//! [pebble]: https://github.com/letsencrypt/pebble
//!
//! ## What it asserts
//!
//! 1. Ordering `tenant.example.test` with `delegate_zone: Some("acme.test")`
//!    completes, and the returned chain's leaf carries that identifier.
//! 2. The publisher was asked for the record name `dns01_record_name` derives —
//!    which is also the CNAME target installed in step (0), so a completed
//!    order *is* the proof that the CA followed the delegation to where we
//!    wrote. The expected name is obtained by CALLING `dns01_record_name`,
//!    never by hand-writing it: a hand-written expectation drifting alongside
//!    the function is precisely the bug this test exists to catch.
//! 3. The negative: with `delegate_zone: None` (a separate identifier, so
//!    Pebble's authz reuse cannot skip the challenge) the publish lands at
//!    `_acme-challenge.<identifier>` and no CNAME is involved.
//!
//! ## Why `#[ignore]` by default
//!
//! It pulls and runs two containers. `cargo test` stays hermetic; run it with:
//!
//! ```bash
//! cargo test --manifest-path oss/passway/Cargo.toml -p passway-acme \
//!     --test pebble_dns01_delegation -- --ignored --nocapture
//! ```
//!
//! Even under `--ignored` it **skips with a printed reason** rather than
//! failing when Docker is absent, the images will not pull, or
//! `PASSWAY_SKIP_DOCKER_TESTS` is set — so a CI box without a daemon is quiet
//! instead of red.
//!
//! ## The two hooks this test exists on the other side of
//!
//! Neither of these has any production caller; both default to `None` and every
//! deployed path is byte-identical to what it was before they existed.
//!
//! - [`acme_engine::AcmeChallengeKind::Dns01Cloudflare::api_base`] — the DNS-01
//!   publisher POSTs `/zones/{zone}/dns_records` to this base instead of the
//!   real Cloudflare API. This test points it at a ~150-line Cloudflare-shaped
//!   shim ([`Shim`]) that forwards each record into challtestsrv and answers in
//!   the exact JSON shape the engine's response parser requires.
//! - [`acme_engine::IssueConfig::directory_root_cert`] — Pebble serves its
//!   directory over a privately-signed cert, so without a private root to trust
//!   the ACME client cannot complete a single request. The root is extracted
//!   from the image at setup ([`PEBBLE_MINICA_PATH`]); note it is deliberately
//!   *not* the issuance root at the management interface's `/roots/0`, which
//!   signs nothing on the wire here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use acme_engine::{dns01_record_name, AcmeChallengeKind, AcmeDirectory, IssueConfig, Issued};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PEBBLE_IMAGE: &str = "ghcr.io/letsencrypt/pebble:latest";
const CHALLTESTSRV_IMAGE: &str = "ghcr.io/letsencrypt/pebble-challtestsrv:latest";

/// In-image path of the CA that signs Pebble's own HTTPS listener — see the
/// long note in [`Stack::start`] for why this is not `/roots/0`.
const PEBBLE_MINICA_PATH: &str = "/test/certs/pebble.minica.pem";

/// The zone the delegated challenge TXT is published into — stands in for the
/// zone the fleet actually holds (`acme.yah.dev` in production).
const DELEGATE_ZONE: &str = "acme.test";

// ---------------------------------------------------------------------------
// Preflight: skip, don't fail, when the host can't run this
// ---------------------------------------------------------------------------

/// `None` (with a printed reason) when this host cannot run the stack. Checked
/// before anything is created, so a skip leaves no containers behind.
fn docker_available() -> bool {
    if std::env::var_os("PASSWAY_SKIP_DOCKER_TESTS").is_some() {
        println!("[skip] PASSWAY_SKIP_DOCKER_TESTS is set");
        return false;
    }
    match Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            println!(
                "[skip] docker daemon not usable: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            println!("[skip] docker not on PATH: {e}");
            return false;
        }
    }
    for image in [PEBBLE_IMAGE, CHALLTESTSRV_IMAGE] {
        // Already local? Then no network is needed at all.
        let present = Command::new("docker")
            .args(["image", "inspect", image])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if present {
            continue;
        }
        match Command::new("docker").args(["pull", "--quiet", image]).output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                println!(
                    "[skip] cannot pull {image}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                return false;
            }
            Err(e) => {
                println!("[skip] cannot pull {image}: {e}");
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The container stack
// ---------------------------------------------------------------------------

/// Pebble + challtestsrv on their own Docker network, torn down by [`Drop`] —
/// which runs on a panicking assertion too, so a failing test never strands
/// containers. Names carry a per-run suffix so concurrent sessions on this
/// shared working tree don't collide, and every published port is `:0` (the
/// kernel picks), read back out of `docker port`.
struct Stack {
    tag: String,
    /// Host address of Pebble's ACME directory endpoint.
    acme_port: u16,
    /// Host address of challtestsrv's management API (`/set-txt`, `/set-cname`).
    challtestsrv_port: u16,
    /// Holds the extracted CA PEM handed to `directory_root_cert`. Kept by
    /// value (not just its path) so the tempdir outlives the test body.
    root_pem: tempfile::TempDir,
}

impl Stack {
    async fn start() -> Result<Self, String> {
        let tag = format!(
            "r779-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        let network = format!("{tag}-net");
        let cts = format!("{tag}-cts");
        let pebble = format!("{tag}-pebble");

        // Everything that can fail without leaving Docker state behind happens
        // first; from the `network create` on, the guard exists so every `?`
        // below tears the stack down on its way out.
        let root_pem = tempfile::tempdir().map_err(|e| e.to_string())?;
        run_docker(&["network", "create", &network])?;
        let mut stack = Stack { tag, acme_port: 0, challtestsrv_port: 0, root_pem };

        run_docker(&[
            "run", "-d", "--name", &cts, "--network", &network,
            "-p", "127.0.0.1:0:8055",
            CHALLTESTSRV_IMAGE,
            // A default A record keeps challtestsrv from NXDOMAINing lookups
            // this test doesn't install; DNS-01 only reads the TXT.
            "-defaultIPv4", "127.0.0.1",
        ])?;
        run_docker(&[
            "run", "-d", "--name", &pebble, "--network", &network,
            "-p", "127.0.0.1:0:14000",
            // Drop the deliberate validation-authority jitter, and the 5% of
            // good nonces Pebble rejects by default. instant-acme retries a bad
            // nonce, so this is flake reduction rather than a correctness
            // dependency — but a CA test that fails 5% of the time gets muted.
            "-e", "PEBBLE_VA_NOSLEEP=1",
            "-e", "PEBBLE_WFE_NONCEREJECT=0",
            PEBBLE_IMAGE,
            "-config", "/test/config/pebble-config.json",
            // Every challenge lookup goes to the mock resolver, which is what
            // makes a `.test` identifier resolvable at all.
            "-dnsserver", &format!("{cts}:8053"),
        ])?;

        stack.acme_port = published_port(&pebble, "14000/tcp")?;
        stack.challtestsrv_port = published_port(&cts, "8055/tcp")?;

        // Pebble has TWO unrelated CAs, and `directory_root_cert` wants the
        // less obvious one. The management interface's `/roots/0` serves the
        // *issuance* root, freshly generated per boot — that is what signs the
        // certs Pebble hands out, and it does NOT sign Pebble's own HTTPS
        // listener. The directory endpoint presents a static `localhost` cert
        // signed by the `minica` CA baked into the image, so trusting
        // `/roots/0` still fails the ACME connection with a bare
        // `client error (Connect)` (verified: `curl --cacert <roots/0>` on
        // `/dir` exits 60, `--cacert pebble.minica.pem` returns 200).
        //
        // `docker cp` reads it straight out of the image's filesystem — that
        // works on a distroless image, where `docker run --entrypoint sh` and
        // `docker exec` do not.
        let root_path = stack.root_cert_path();
        run_docker(&["cp", &format!("{pebble}:{PEBBLE_MINICA_PATH}"), &root_path]).map_err(|e| {
            format!("could not extract {PEBBLE_MINICA_PATH} from {PEBBLE_IMAGE} — the image layout may have changed: {e}")
        })?;

        // Readiness is a bare TCP accept, deliberately: `docker run -d`
        // returns before Pebble binds, so *something* has to gate the first
        // order, but anything that speaks HTTPS here would be a second ACME
        // client with its own TLS configuration standing between the test and
        // the thing under test. The real client (instant-acme, over hyper)
        // does the handshake and the first request itself, and its failures
        // are the ones worth reading.
        let dir_addr = format!("127.0.0.1:{}", stack.acme_port);
        poll_until(Duration::from_secs(30), || {
            let dir_addr = dir_addr.clone();
            async move { TcpStream::connect(&dir_addr).await.ok().map(|_| ()) }
        })
        .await
        .ok_or_else(|| {
            // A dead container and an unreachable port look identical from the
            // client side, so name which one it was rather than making the next
            // reader re-run the stack by hand.
            let state = run_docker(&["inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}}", &pebble])
                .unwrap_or_else(|e| e);
            let logs = Command::new("docker")
                .args(["logs", "--tail", "20", &pebble])
                .output()
                .map(|o| {
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    )
                })
                .unwrap_or_default();
            format!("pebble never accepted a connection on {dir_addr} (container: {state})\n{logs}")
        })?;

        Ok(stack)
    }

    fn directory_url(&self) -> String {
        // Pebble derives the directory's advertised URLs from the request Host
        // header, so an ephemeral published port round-trips correctly.
        //
        // `127.0.0.1`, deliberately not `localhost`: the port is published on
        // the IPv4 loopback only, and `localhost` resolves to `::1` first —
        // hyper's connector surfaces that as a bare `Connection refused`
        // instead of falling back, so the whole run fails before the first
        // ACME request. Pebble's listener cert carries `IP Address:127.0.0.1`
        // alongside `DNS:localhost`, so verification is unaffected.
        format!("https://127.0.0.1:{}/dir", self.acme_port)
    }

    fn root_cert_path(&self) -> String {
        self.root_pem.path().join("pebble-minica.pem").display().to_string()
    }

    fn challtestsrv_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.challtestsrv_port)
    }

    /// Install the *tenant's* half of the delegation contract: the CNAME an
    /// onboarding page tells a domain owner to create.
    async fn set_cname(&self, host: &str, target: &str) -> Result<(), String> {
        challtestsrv_post(
            &self.challtestsrv_base(),
            "set-cname",
            &serde_json::json!({ "host": fqdn(host), "target": fqdn(target) }),
        )
        .await
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // Best-effort and unconditional: this runs while unwinding a failed
        // assertion too. `-f` because the containers are still running.
        let _ = Command::new("docker")
            .args(["rm", "-f", &format!("{}-cts", self.tag), &format!("{}-pebble", self.tag)])
            .output();
        let _ = Command::new("docker").args(["network", "rm", &format!("{}-net", self.tag)]).output();
    }
}

fn run_docker(args: &[&str]) -> Result<String, String> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("docker {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "docker {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Read back the ephemeral host port Docker chose for `container_port`.
fn published_port(container: &str, container_port: &str) -> Result<u16, String> {
    let mapping = run_docker(&["port", container, container_port])?;
    mapping
        .lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .and_then(|p| p.trim().parse().ok())
        .ok_or_else(|| format!("could not parse `docker port {container} {container_port}`: {mapping:?}"))
}

/// Retry `f` every 200 ms until it yields `Some` or `budget` elapses.
async fn poll_until<T, F, Fut>(budget: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + budget;
    loop {
        if let Some(v) = f().await {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// challtestsrv's management API answers 200 on success and 404 for an unknown
/// endpoint, so a non-2xx here is a real failure rather than a shrug.
async fn challtestsrv_post(base: &str, endpoint: &str, body: &serde_json::Value) -> Result<(), String> {
    let resp = reqwest::Client::new()
        .post(format!("{base}/{endpoint}"))
        .json(body)
        .send()
        .await
        .map_err(|e| format!("challtestsrv {endpoint}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("challtestsrv {endpoint}: HTTP {}", resp.status()));
    }
    Ok(())
}

/// challtestsrv keys its mock zone on fully-qualified names.
fn fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

// ---------------------------------------------------------------------------
// The Cloudflare-shaped shim
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ShimState {
    /// `record_id -> record name`, so a DELETE can clear the right TXT.
    records: HashMap<String, String>,
    /// Every name the engine asked to publish at, in order. The assertion
    /// surface: this is what proves *where* we wrote.
    published: Vec<String>,
}

/// A ~150-line stand-in for the two Cloudflare endpoints the DNS-01 publisher
/// uses, forwarding each record into challtestsrv so Pebble can resolve it.
///
/// Hand-rolled on `tokio::net` in the shape of `sni-demux`'s accept loop rather
/// than pulling an HTTP-server crate into a trust-boundary workspace: the whole
/// contract is two routes and one JSON body.
struct Shim {
    addr: SocketAddr,
    state: Arc<Mutex<ShimState>>,
}

impl Shim {
    async fn start(challtestsrv_base: String) -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let state = Arc::new(Mutex::new(ShimState::default()));
        let task_state = Arc::clone(&state);
        tokio::spawn(async move {
            let ids = AtomicU64::new(1);
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let state = Arc::clone(&task_state);
                let base = challtestsrv_base.clone();
                let id = ids.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(e) = serve_one(sock, state, base, id).await {
                        eprintln!("[shim] {e}");
                    }
                });
            }
        });
        Ok(Self { addr, state })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn published(&self) -> Vec<String> {
        self.state.lock().unwrap().published.clone()
    }
}

/// One request, one response, then close. `Connection: close` on the way out
/// keeps this to a single request per connection — reqwest honours it, and a
/// keep-alive loop would buy nothing for two calls per order.
async fn serve_one(
    mut sock: TcpStream,
    state: Arc<Mutex<ShimState>>,
    challtestsrv_base: String,
    seq: u64,
) -> Result<(), String> {
    // Read headers, then exactly `Content-Length` more bytes. Bounded by the
    // read budget below so a malformed request can't spin.
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            return Err("request head exceeded 16 KiB".to_string());
        }
        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before a complete request head".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed mid-body".to_string());
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let (status, payload) =
        route(&method, &path, &body, &state, &challtestsrv_base, seq).await;
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    sock.write_all(response.as_bytes()).await.map_err(|e| e.to_string())?;
    sock.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// The two Cloudflare routes the engine calls, and nothing else — an
/// unrecognised path 404s so a URL-shape regression in the engine shows up as a
/// failed order rather than a silent pass.
async fn route(
    method: &str,
    path: &str,
    body: &[u8],
    state: &Arc<Mutex<ShimState>>,
    challtestsrv_base: &str,
    seq: u64,
) -> (&'static str, String) {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (method, segments.as_slice()) {
        // POST /zones/{zone_id}/dns_records
        ("POST", ["zones", _zone, "dns_records"]) => {
            let parsed: serde_json::Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(e) => return ("400 Bad Request", format!(r#"{{"success":false,"errors":["{e}"]}}"#)),
            };
            let (Some(name), Some(content)) =
                (parsed["name"].as_str(), parsed["content"].as_str())
            else {
                return ("400 Bad Request", r#"{"success":false,"errors":["name/content required"]}"#.to_string());
            };
            if let Err(e) = challtestsrv_post(
                challtestsrv_base,
                "set-txt",
                &serde_json::json!({ "host": fqdn(name), "value": content }),
            )
            .await
            {
                return ("502 Bad Gateway", format!(r#"{{"success":false,"errors":["{e}"]}}"#));
            }
            let record_id = format!("rec{seq}");
            {
                let mut guard = state.lock().unwrap();
                guard.records.insert(record_id.clone(), name.to_string());
                guard.published.push(name.to_string());
            }
            // Exactly the shape `cloudflare_create_txt`'s parser requires.
            ("200 OK", format!(r#"{{"success":true,"result":{{"id":"{record_id}"}}}}"#))
        }
        // DELETE /zones/{zone_id}/dns_records/{record_id}
        ("DELETE", ["zones", _zone, "dns_records", record_id]) => {
            let name = state.lock().unwrap().records.remove(*record_id);
            let Some(name) = name else {
                return ("404 Not Found", r#"{"success":false,"errors":["no such record"]}"#.to_string());
            };
            if let Err(e) = challtestsrv_post(
                challtestsrv_base,
                "clear-txt",
                &serde_json::json!({ "host": fqdn(&name) }),
            )
            .await
            {
                return ("502 Bad Gateway", format!(r#"{{"success":false,"errors":["{e}"]}}"#));
            }
            ("200 OK", format!(r#"{{"success":true,"result":{{"id":"{record_id}"}}}}"#))
        }
        _ => (
            "404 Not Found",
            format!(r#"{{"success":false,"errors":["unrouted {method} {path}"]}}"#),
        ),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Assertions on the issued chain
// ---------------------------------------------------------------------------

/// The DNS SANs on the chain's leaf. Parsing rather than substring-matching the
/// PEM: an identifier appearing *somewhere* in the chain (an issuer name, a
/// second SAN) would satisfy a `contains` and prove nothing.
fn leaf_dns_names(chain_pem: &str) -> Vec<String> {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes())
        .expect("issued chain is not valid PEM");
    let (_, cert) =
        X509Certificate::from_der(&pem.contents).expect("leaf certificate is not valid DER");
    cert.subject_alternative_name()
        .expect("malformed SAN extension")
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(n) => Some((*n).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Build the `IssueConfig` for one order against the running stack. Every field
/// that is not the thing under test is held constant between the two cases.
fn issue_config(
    stack: &Stack,
    shim: &Shim,
    account_dir: &tempfile::TempDir,
    token_file: &std::path::Path,
    domain: &str,
    delegate_zone: Option<&str>,
) -> IssueConfig {
    IssueConfig {
        domains: vec![domain.to_string()],
        contact_email: "ops@example.test".to_string(),
        directory: AcmeDirectory::Custom(stack.directory_url()),
        // Shared across both cases on purpose: one account, so the second
        // order exercises the cached-credentials path too.
        account_cache_path: account_dir.path().join("acme-account.json").display().to_string(),
        challenge: AcmeChallengeKind::Dns01Cloudflare {
            token_file: token_file.display().to_string(),
            // The shim ignores the zone id; it is still carried through the
            // URL, so a wrong one would 404 at `route`.
            zone_id: "test-zone".to_string(),
            delegate_zone: delegate_zone.map(str::to_string),
            api_base: Some(shim.base_url()),
        },
        // challtestsrv serves a publish immediately — there is no
        // authoritative edge to propagate to.
        dns01_propagation_delay: Duration::from_millis(200),
        // The hook this whole test hangs on: Pebble's per-boot root.
        directory_root_cert: Some(stack.root_cert_path()),
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires docker; run with --ignored"]
async fn pebble_validates_the_delegated_record_name_we_publish_at() {
    if !docker_available() {
        return;
    }
    let stack = Stack::start().await.expect("pebble stack");
    let shim = Shim::start(stack.challtestsrv_base()).await.expect("cloudflare shim");
    let account_dir = tempfile::tempdir().unwrap();
    let token_dir = tempfile::tempdir().unwrap();
    let token_file = token_dir.path().join("cf-token");
    // The engine reads a token file unconditionally; the shim never checks it.
    std::fs::write(&token_file, "test-token\n").unwrap();
    let tokens: acme_engine::ChallengeTokens = Default::default();

    // -- case 1: delegated ------------------------------------------------
    //
    // The tenant's domain. Its zone is emphatically NOT one we hold — that is
    // the entire premise of delegation.
    let delegated_domain = "tenant.example.test";
    // DERIVED, never hand-written. If `dns01_record_name` changes, the CNAME
    // this test installs changes with it, and a real CA re-proves the new name.
    let expected_name = dns01_record_name(delegated_domain, Some(DELEGATE_ZONE));

    // The tenant's half of the contract, exactly as an onboarding page states
    // it: `_acme-challenge.<their domain>` CNAME -> whatever we publish at.
    stack
        .set_cname(&format!("_acme-challenge.{delegated_domain}"), &expected_name)
        .await
        .expect("install the tenant CNAME");

    let issued: Issued = acme_engine::issue(
        &issue_config(
            &stack,
            &shim,
            &account_dir,
            &token_file,
            delegated_domain,
            Some(DELEGATE_ZONE),
        ),
        &tokens,
    )
    .await
    .unwrap_or_else(|e| panic!("delegated issuance for {delegated_domain} failed: {e}"));

    assert!(
        leaf_dns_names(&issued.cert_chain_pem).iter().any(|n| n == delegated_domain),
        "the leaf must carry the tenant identifier; SANs were {:?}",
        leaf_dns_names(&issued.cert_chain_pem)
    );
    assert!(
        !issued.key_pem.is_empty(),
        "issuance returned a chain with no private key"
    );
    // The load-bearing assertion. Pebble resolved `_acme-challenge.<domain>`,
    // followed the CNAME, and found a matching TXT — so the name below is not
    // merely what we intended to publish at, it is the name a CA validated.
    assert!(
        shim.published().contains(&expected_name),
        "the publisher must write at the delegated name {expected_name:?}, but it wrote {:?}",
        shim.published()
    );
    assert!(
        !shim.published().iter().any(|n| n.starts_with("_acme-challenge.")),
        "under delegation nothing may be written into the tenant's own zone; wrote {:?}",
        shim.published()
    );

    // -- case 2: the negative, undelegated --------------------------------
    //
    // A DIFFERENT identifier: Pebble reuses a valid authorization ~50% of the
    // time, so reordering the same name could skip the challenge entirely and
    // record no publish at all.
    let plain_domain = "plain.example.test";
    let plain_expected = dns01_record_name(plain_domain, None);
    let before = shim.published().len();

    let issued = acme_engine::issue(
        &issue_config(&stack, &shim, &account_dir, &token_file, plain_domain, None),
        &tokens,
    )
    .await
    .unwrap_or_else(|e| panic!("undelegated issuance for {plain_domain} failed: {e}"));

    assert!(
        leaf_dns_names(&issued.cert_chain_pem).iter().any(|n| n == plain_domain),
        "the leaf must carry the undelegated identifier; SANs were {:?}",
        leaf_dns_names(&issued.cert_chain_pem)
    );
    let newly_published = &shim.published()[before..];
    assert!(
        newly_published.contains(&plain_expected),
        "without a delegate zone the publish lands at {plain_expected:?}, but it wrote {newly_published:?}"
    );
    assert_eq!(
        plain_expected, "_acme-challenge.plain.example.test",
        "the undelegated contract is the RFC-8555 name in the identifier's own zone"
    );
}
