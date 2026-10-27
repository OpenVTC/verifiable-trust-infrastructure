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

/// A minted admin token authenticates against a session-gated route (here
/// the session row + JWT are both produced by `TestVtc::token`).
#[tokio::test]
async fn minted_admin_token_is_accepted() {
    let tv = TestVtc::builder().build().await;
    let token = tv.admin_token().await;

    // The access-token extractor every session-gated handler takes
    // (`common::session_probe`). Without a token it refuses — proof the gate
    // is there, so the second request's answer says something about the
    // token. With the minted admin token it admits the caller.
    let (anonymous, _) = crate::common::session_probe::probe(&tv, &[]).await;
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED);

    let (status, body) =
        crate::common::session_probe::probe(&tv, &[("authorization", format!("Bearer {token}"))])
            .await;
    assert_eq!(status, StatusCode::OK, "{body}");
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
