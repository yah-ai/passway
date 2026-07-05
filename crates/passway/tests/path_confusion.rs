//! Integration test: path-confusion auth-bypass vectors
//! (R594-F4 adversarial-review FIX 1 + FIX 2).
//!
//! Every vector the reviewer named must be either GATED (401) or REJECTED
//! (400) — never anonymously proxied through to the upstream (which would
//! show up as a 200 with the `x-upstream-tag` header). These go over a raw
//! TCP socket, not reqwest, because reqwest/hyper normalize the URL
//! client-side (collapsing `//`, `/../`, etc.) before it would ever reach
//! the proxy — the exact normalization gap the fix closes.

mod common;

use std::time::Duration;

use cheers_core::{PrincipalId, Scope};
use cheers_verify::PasetoV4PublicVerifier;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::{PublicToken, V4};

use passway::auth::{CheersAuth, RouteAuthPolicy};

const ISS: &str = "https://passway.test";
const AUD: &str = "https://backend.test";
const KID: &str = "test-kid-1";

fn keypair() -> AsymmetricKeyPair<V4> {
    AsymmetricKeyPair::<V4>::generate().expect("keypair generation")
}

fn pubkey_bytes(kp: &AsymmetricKeyPair<V4>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(kp.public.as_bytes());
    out
}

fn mint_valid(kp: &AsymmetricKeyPair<V4>) -> String {
    let claims = cheers_core::McpClaims::new(
        ISS,
        AUD,
        PrincipalId::user("alice"),
        0,
        4_000_000_000, // exp far in the future
        "jti-1",
        vec![Scope::CloudRead],
    );
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    let footer = format!(r#"{{"kid":"{KID}"}}"#).into_bytes();
    PublicToken::sign(&kp.secret, &payload, Some(&footer), None).expect("sign token")
}

/// Boot a proxy with policy `require_auth("/admin")` + `allow_anonymous("/public")`
/// and a single healthy upstream. Returns (proxy addr, valid bearer token).
async fn setup() -> (std::net::SocketAddr, String) {
    let kp = keypair();
    let verifier = PasetoV4PublicVerifier::from_public_key(&pubkey_bytes(&kp)).unwrap();
    let auth = CheersAuth::new(verifier, KID, ISS, AUD);
    let policy = RouteAuthPolicy::new()
        .require_auth("/admin")
        .allow_anonymous("/public");

    let upstream = common::spawn_fake_upstream("backend").await;
    let (proxy, lb_background) = common::build_proxy_with_auth(vec![upstream], auth, policy);
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    // Wait for the fake upstream to be marked healthy so the anonymous /public
    // and authed /admin positive controls aren't masked by a spurious 503.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if common::raw_get(listen, "/health", &[]).await == 200 {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("fake upstream never became healthy");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    (listen, mint_valid(&kp))
}

/// Assert a vector is NOT anonymously proxied: it must come back 400
/// (rejected) or 401 (gated), never 200 (reached the upstream).
async fn assert_blocked(addr: std::net::SocketAddr, target: &str) {
    let status = common::raw_get(addr, target, &[]).await;
    assert!(
        status == 400 || status == 401,
        "vector {target:?} must be gated (401) or rejected (400), got {status} \
         (200 would mean it was anonymously proxied to the protected upstream)"
    );
}

#[tokio::test]
async fn case_variant_is_not_a_bypass() {
    let (addr, _tok) = setup().await;
    assert_blocked(addr, "/Admin/secret").await;
    assert_blocked(addr, "/ADMIN/secret").await;
}

#[tokio::test]
async fn duplicate_slash_is_not_a_bypass() {
    let (addr, _tok) = setup().await;
    assert_blocked(addr, "//admin/secret").await;
}

#[tokio::test]
async fn dot_segment_is_not_a_bypass() {
    let (addr, _tok) = setup().await;
    assert_blocked(addr, "/./admin/secret").await;
}

#[tokio::test]
async fn parent_traversal_out_of_anonymous_carveout_is_not_a_bypass() {
    let (addr, _tok) = setup().await;
    // The nastiest one: matches allow_anonymous("/public") on the raw prefix,
    // but resolves into the protected /admin.
    assert_blocked(addr, "/public/../admin/secret").await;
}

#[tokio::test]
async fn encoded_parent_traversal_is_not_a_bypass() {
    let (addr, _tok) = setup().await;
    assert_blocked(addr, "/public/%2e%2e/admin/secret").await;
}

#[tokio::test]
async fn encoded_slash_is_rejected() {
    let (addr, _tok) = setup().await;
    // %2f inside a segment is genuinely ambiguous -> 400 (fail closed),
    // whether the surrounding prefix is protected or anonymous.
    assert_eq!(common::raw_get(addr, "/admin%2fsecret", &[]).await, 400);
    assert_eq!(common::raw_get(addr, "/public/foo%2fbar", &[]).await, 400);
}

#[tokio::test]
async fn double_encoded_dot_traversal_is_rejected() {
    let (addr, _tok) = setup().await;
    // %252e%252e decodes once to a literal %2e%2e (inert to our normalizer),
    // matches the anonymous /public carve-out on canonical form, but a
    // double-decoding upstream would resolve the forwarded raw path to
    // /admin. Must fail closed (400), symmetric with the encoded-slash case.
    assert_eq!(
        common::raw_get(addr, "/public/%252e%252e/admin/secret", &[]).await,
        400
    );
}

#[tokio::test]
async fn non_utf8_path_is_rejected() {
    let (addr, _tok) = setup().await;
    // A lone 0xFF byte in the request target (FIX 2). Built as raw bytes
    // since it isn't valid UTF-8. Must not be anonymously proxied — either
    // our UTF-8 guard rejects it (400) or pingora's own parser refuses it
    // (400 / connection closed = status 0). The one thing it must never be
    // is 200.
    let mut req = b"GET /".to_vec();
    req.push(0xff);
    req.extend_from_slice(b"admin HTTP/1.1\r\nHost: passway.test\r\nConnection: close\r\n\r\n");
    let status = common::send_raw(addr, &req).await;
    assert!(
        status == 400 || status == 0,
        "non-UTF-8 path must be rejected/refused, never proxied; got {status}"
    );
}

// ── Positive controls: the fix must not break normal routing ─────────────

#[tokio::test]
async fn protected_route_without_token_is_401() {
    let (addr, _tok) = setup().await;
    assert_eq!(common::raw_get(addr, "/admin/secret", &[]).await, 401);
}

#[tokio::test]
async fn protected_route_with_valid_token_reaches_upstream() {
    let (addr, token) = setup().await;
    let auth = format!("Bearer {token}");
    let status = common::raw_get(addr, "/admin/secret", &[("Authorization", &auth)]).await;
    assert_eq!(status, 200, "a valid bearer must still reach the upstream");
}

#[tokio::test]
async fn anonymous_route_still_proxies() {
    let (addr, _tok) = setup().await;
    assert_eq!(
        common::raw_get(addr, "/public/data", &[]).await,
        200,
        "an anonymous route must still be proxied normally"
    );
}
