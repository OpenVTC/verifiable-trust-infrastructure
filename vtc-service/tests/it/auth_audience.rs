//! Audience-isolation integration tests for the VTC service.
//!
//! CLAUDE.md identifies VTA-vs-VTC audience isolation as a load-bearing
//! invariant: a JWT minted with `aud = "VTA"` MUST NOT authenticate
//! against a VTC route. The complementary test on the VTA side lives
//! in `vta-service/tests/api_integration.rs`.
//!
//! The access-token extractor is exercised through a probe route
//! (`common::session_probe`): `GET /v1/auth/whoami`, which these tests used,
//! became a signed document answered for a session's bound key (#1641), and
//! no other route is a plain token check. The `Trust-Task` header gate is
//! exercised on `auth/refresh/0.1`, one of the few header-gated routes left.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use vti_common::auth::jwt::JwtKeys;

use vtc_service::test_support::TestVtc;

use crate::common::session_probe::probe;

async fn build_test_vtc() -> TestVtc {
    TestVtc::builder()
        .vtc_did("did:key:z6MkTestVTC")
        .build()
        .await
}

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn foreign_token(audience: &str) -> String {
    let foreign_keys: Arc<JwtKeys> =
        Arc::new(JwtKeys::from_ed25519_bytes(&[0x42u8; 32], audience).unwrap());
    let claims = foreign_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        format!("sess-{}", uuid::Uuid::new_v4()),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    foreign_keys.encode(&claims).expect("encode")
}

#[tokio::test]
async fn vta_audience_token_rejected_by_vtc_route() {
    let vtc = build_test_vtc().await;
    // The VTC's JwtKeys was configured with `audience = "VTC"`, so this
    // foreign-audience token must be rejected at decode time.
    let token = foreign_token("VTA");
    let (status, _) = probe(&vtc, &[("Authorization", format!("Bearer {token}"))]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "VTA-audience JWT must be rejected by VTC routes"
    );
}

#[tokio::test]
async fn unknown_audience_token_rejected_by_vtc_route() {
    // Defence-in-depth: any audience that isn't "VTC" must be rejected,
    // not just the well-known "VTA" string.
    let vtc = build_test_vtc().await;
    let token = foreign_token("EVIL-V99");
    let (status, _) = probe(&vtc, &[("Authorization", format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn no_token_rejected_by_vtc_route() {
    let vtc = build_test_vtc().await;
    let (status, _) = probe(&vtc, &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing Authorization header must be rejected"
    );
}

#[tokio::test]
async fn a_vtc_audience_token_is_admitted() {
    let vtc = build_test_vtc().await;
    let token = vtc.admin_token().await;
    let (status, body) = probe(&vtc, &[("Authorization", format!("Bearer {token}"))]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn missing_trust_task_header_returns_400() {
    let vtc = build_test_vtc().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, body) = request(&vtc.router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "TrustTaskMissing");
}

#[tokio::test]
async fn mismatched_trust_task_header_returns_415() {
    let vtc = build_test_vtc().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/refresh")
        .header(
            "Trust-Task",
            // Any well-formed URI the mount does not bind. Deliberately not a
            // real task — this asserts the mismatch path, so it must not start
            // passing if the task it names is ever wired here.
            "https://trusttasks.org/openvtc/vtc/not-a-real-task/1.0",
        )
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _body) = request(&vtc.router, req).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn health_is_exempt_from_trust_task() {
    let vtc = build_test_vtc().await;
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&vtc.router, req).await;
    assert_eq!(status, StatusCode::OK);
}
