//! Smoke coverage for `vtc_service::test_support` itself — the harness
//! the rest of the integration suite (and downstream `vti-harness`)
//! builds on. Pins the `TestVtc` builder, token minting, and the
//! `MockVtc` listening server.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use vtc_service::test_support::{MockVtc, TestVtc, build_test_vtc};

/// `build_test_vtc()` yields a router whose `/health` endpoint answers —
/// the cheapest proof the `AppState` is wired and the router assembles.
#[tokio::test]
async fn build_test_vtc_serves_health() {
    let tv = build_test_vtc().await;
    let resp = tv
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A minted admin token authenticates against an admin-gated route (here
/// the session row + JWT are both produced by `TestVtc::token`).
#[tokio::test]
async fn minted_admin_token_is_accepted() {
    let tv = TestVtc::builder().build().await;
    let token = tv.admin_token().await;

    // `GET /v1/admin/config` is AdminAuth-gated; with a valid admin token
    // it must not 401/403. (200 or any non-auth status is fine here — we
    // only assert the auth gate let us through.)
    let resp = tv
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/admin/config")
                .header("trust-task", "https://trusttasks.org/spec/config/show/0.1")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// Opting into signers makes the credential + install signers present, so
/// the routes that 503 without them are unblocked.
#[tokio::test]
async fn with_signers_populates_credential_and_install_signers() {
    let tv = TestVtc::builder()
        .with_signers(true)
        .with_public_url("http://vtc.test")
        .build()
        .await;
    assert!(tv.state.credential_signer.is_some());
    assert!(tv.state.install_signer.is_some());
    assert!(tv.state.webauthn.is_some());
}

/// `MockVtc` binds a real loopback port and serves `/health` over HTTP.
#[tokio::test]
async fn mock_vtc_serves_over_http() {
    let mock = MockVtc::start().await;
    let url = format!("{}/health", mock.base_url());
    let resp = reqwest::get(&url).await.expect("GET /health");
    assert_eq!(resp.status(), StatusCode::OK);
    mock.shutdown().await;
}
