//! Audience-isolation integration tests for the VTC service.
//!
//! CLAUDE.md identifies VTA-vs-VTC audience isolation as a load-bearing
//! invariant: a JWT minted with `aud = "VTA"` MUST NOT authenticate
//! against a VTC route. The complementary test on the VTA side lives
//! in `vta-service/tests/api_integration.rs`. Both run the assertion
//! through the full route stack so a future refactor that, say,
//! normalises audiences before validation surfaces immediately.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use vti_common::auth::jwt::JwtKeys;

use vtc_service::test_support::TestVtc;

async fn build_test_router() -> (axum::Router, Arc<JwtKeys>, TestVtc) {
    let vtc = TestVtc::builder()
        .vtc_did("did:key:z6MkTestVTC")
        .build()
        .await;
    (vtc.router.clone(), vtc.jwt_keys.clone(), vtc)
}

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn vta_audience_token_rejected_by_vtc_route() {
    let (router, _vtc_keys, _dir) = build_test_router().await;

    // Mint a token whose `aud` claim is "VTA". The VTC's JwtKeys was
    // configured with `audience = "VTC"`, so this foreign-audience
    // token must be rejected at decode time.
    let foreign_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTA").unwrap();
    let claims = foreign_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        format!("sess-{}", uuid::Uuid::new_v4()),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let foreign_token = foreign_keys.encode(&claims).expect("encode");

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", "https://trusttasks.org/spec/acl/list/0.1")
        .header("Authorization", format!("Bearer {foreign_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "VTA-audience JWT must be rejected by VTC routes"
    );
}

#[tokio::test]
async fn unknown_audience_token_rejected_by_vtc_route() {
    // Defence-in-depth: any audience that isn't "VTC" must be rejected,
    // not just the well-known "VTA" string. A future "VTM" service or
    // an attacker-supplied token with a custom audience must never
    // authenticate.
    let (router, _vtc_keys, _dir) = build_test_router().await;

    let foreign_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "EVIL-V99").unwrap();
    let claims = foreign_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        format!("sess-{}", uuid::Uuid::new_v4()),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let foreign_token = foreign_keys.encode(&claims).expect("encode");

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", "https://trusttasks.org/spec/acl/list/0.1")
        .header("Authorization", format!("Bearer {foreign_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn no_token_rejected_by_vtc_route() {
    let (router, _, _dir) = build_test_router().await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header("Trust-Task", "https://trusttasks.org/spec/acl/list/0.1")
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing Authorization header must be rejected"
    );
}

#[tokio::test]
async fn missing_trust_task_header_returns_400() {
    let (router, _, _dir) = build_test_router().await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "TrustTaskMissing");
}

#[tokio::test]
async fn mismatched_trust_task_header_returns_415() {
    let (router, _, _dir) = build_test_router().await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/acl")
        .header(
            "Trust-Task",
            // Any well-formed URI the mount does not bind. Deliberately not a
            // real task — this asserts the mismatch path, so it must not start
            // passing if the task it names is ever wired here.
            "https://trusttasks.org/openvtc/vtc/not-a-real-task/1.0",
        )
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn health_is_exempt_from_trust_task() {
    let (router, _, _dir) = build_test_router().await;

    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(status, StatusCode::OK);
}
