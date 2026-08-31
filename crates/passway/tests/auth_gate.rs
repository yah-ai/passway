//! Integration test: cheers-verify edge auth on an auth-required route
//! (R594-F4 V0 MUST #3; VERIFY list item 3) — a missing or invalid PASETO
//! v4.public bearer is rejected (401), a valid one reaches the upstream.
//! Also proves the anonymous-by-default posture: an unlisted route is
//! reachable with no bearer at all.

use crate::common;

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

fn mint(kp: &AsymmetricKeyPair<V4>, kid: &str, iss: &str, aud: &str, exp: i64) -> String {
    let claims = cheers_core::McpClaims::new(
        iss,
        aud,
        PrincipalId::user("alice"),
        0,
        exp,
        "test-jti-1",
        vec![Scope::CloudRead],
    );
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    let footer = format!(r#"{{"kid":"{kid}"}}"#).into_bytes();
    PublicToken::sign(&kp.secret, &payload, Some(&footer), None).expect("sign token")
}

async fn setup() -> (reqwest::Client, String, AsymmetricKeyPair<V4>) {
    let kp = keypair();
    let verifier = PasetoV4PublicVerifier::from_public_key(&pubkey_bytes(&kp)).unwrap();
    let auth = CheersAuth::new(verifier, KID, ISS, AUD);
    let policy = RouteAuthPolicy::new().require_auth("/private");

    let upstream = common::spawn_fake_upstream("backend").await;
    let (proxy, lb_background) = common::build_proxy_with_auth(vec![upstream], auth, policy);
    let listen = common::free_addr();
    common::start_proxy(proxy, lb_background, listen);

    let client = reqwest::Client::new();
    let base = format!("http://{listen}");

    // Wait for the fake upstream to be marked ready so a successful auth
    // check isn't masked by a spurious 503.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(resp) = client.get(format!("{base}/health")).send().await {
            if resp.status() == 200 {
                break;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("fake upstream never became healthy");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    (client, base, kp)
}

#[tokio::test]
async fn missing_bearer_on_protected_route_is_401() {
    let (client, base, _kp) = setup().await;
    let resp = client
        .get(format!("{base}/private/data"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn invalid_bearer_on_protected_route_is_401() {
    let (client, base, _kp) = setup().await;
    let resp = client
        .get(format!("{base}/private/data"))
        .header("Authorization", "Bearer not-a-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn expired_bearer_on_protected_route_is_401() {
    let (client, base, kp) = setup().await;
    let expired = mint(&kp, KID, ISS, AUD, 1); // exp=1s past epoch: long expired
    let resp = client
        .get(format!("{base}/private/data"))
        .header("Authorization", format!("Bearer {expired}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn wrong_audience_bearer_on_protected_route_is_401() {
    let (client, base, kp) = setup().await;
    let wrong_aud = mint(&kp, KID, ISS, "https://someone-else.test", 4_000_000_000);
    let resp = client
        .get(format!("{base}/private/data"))
        .header("Authorization", format!("Bearer {wrong_aud}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn valid_bearer_on_protected_route_reaches_upstream() {
    let (client, base, kp) = setup().await;
    let token = mint(&kp, KID, ISS, AUD, 4_000_000_000); // exp far in the future
    let resp = client
        .get(format!("{base}/private/data"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-upstream-tag").unwrap(),
        "backend"
    );
}

#[tokio::test]
async fn unlisted_route_is_anonymous_by_default() {
    let (client, base, _kp) = setup().await;
    let resp = client.get(format!("{base}/public")).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "an unlisted route must not require auth (anonymous by default)"
    );
}
