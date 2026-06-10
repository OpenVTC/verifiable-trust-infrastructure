//! Integration coverage for `GET /v1/status-lists/{purpose}`
//! (Phase 2 M2.11).
//!
//! Verifies:
//! - Route serves the seeded status-list VC.
//! - Trust-Task header is **not** required (verifier-facing
//!   exemption).
//! - Unknown purpose → 404.
//! - 503 path when the credential signer isn't initialised.

mod common;

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use vtc_service::credentials::LocalSigner;
use vtc_service::status_list;
use vtc_service::test_support::TestVtc;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";

struct Fixture {
    router: axum::Router,
    signer: Arc<LocalSigner>,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture(with_signer: bool) -> Fixture {
    // The signer is held by the fixture and used to verify the served VC,
    // so it must be the exact instance the AppState issues with.
    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));
    let mut builder = TestVtc::builder()
        .with_audit(true)
        .with_public_url(PUBLIC_URL);
    if with_signer {
        builder = builder.with_credential_signer(signer.clone());
    }
    let vtc = builder.build().await;

    // Seed both status lists like `server::run` does at boot.
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&vtc.state.status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    Fixture {
        router: vtc.router.clone(),
        signer,
        _vtc: vtc,
    }
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        let raw = String::from_utf8_lossy(&bytes);
        panic!("response body was not JSON ({e}): {raw}")
    })
}

/// GET without a Trust-Task header returns the status-list VC.
/// Confirms the route_exempt path is wired.
#[tokio::test]
async fn show_returns_signed_vc_without_trust_task_header() {
    let fix = build_fixture(true).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/revocation")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Cache-Control: no-store header set per spec §6.2.
    let headers = resp.headers().clone();
    assert_eq!(
        headers.get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store"),
    );

    let body = body_json(resp.into_body()).await;

    // Shape: VC with the BitstringStatusListCredential type.
    let types = body["type"].as_array().expect("type array");
    assert!(types.iter().any(|t| t == "VerifiableCredential"));
    assert!(types.iter().any(|t| t == "BitstringStatusListCredential"));

    // Subject details.
    assert_eq!(body["credentialSubject"]["statusPurpose"], "revocation");
    assert_eq!(body["credentialSubject"]["type"], "BitstringStatusList");
    assert!(body["credentialSubject"]["encodedList"].is_string());

    // Proof verifies against the signer used in the fixture.
    let vc: affinidi_vc::VerifiableCredential = serde_json::from_value(body).unwrap();
    fix.signer.verify(&vc).expect("status-list VC must verify");
}

/// `suspension` purpose is also served (both purposes seeded
/// at boot).
#[tokio::test]
async fn show_serves_suspension_purpose() {
    let fix = build_fixture(true).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/suspension")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["credentialSubject"]["statusPurpose"], "suspension");
}

/// An unknown purpose value returns 404.
#[tokio::test]
async fn show_unknown_purpose_returns_404() {
    let fix = build_fixture(true).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/disco")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// When the credential signer is `None` (daemon not yet
/// provisioned), the route returns 500 with a "signer not
/// initialised" message. `AppError::Internal` maps to 500 in
/// the workspace.
#[tokio::test]
async fn show_returns_5xx_when_signer_missing() {
    let fix = build_fixture(false).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/status-lists/revocation")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_server_error(),
        "expected 5xx when signer missing, got {}",
        resp.status()
    );
}
