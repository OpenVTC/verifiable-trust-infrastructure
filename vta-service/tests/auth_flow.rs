//! Integration tests for the VTA authentication flow.
//!
//! Pre-consolidation, this file held three "tests" that were actually
//! JSON serde round-trips and a `did.split('#')` tautology — none of
//! them touched the `/auth/challenge` / `/auth/` / `/auth/refresh`
//! route layer. They were deleted in the same commit that consolidated
//! the integration-test scaffolding into `vta_service::test_support`,
//! and replaced with the real route-level tests below.
//!
//! What's covered:
//! - `POST /auth/challenge` issues a session_id + challenge for an
//!   ACL-permitted DID; the session is persisted under the returned
//!   session_id with the same challenge bytes.
//! - `POST /auth/refresh` rejects malformed and unknown refresh
//!   tokens with 401 (regression-pin against silent 500s).
//! - `TestAppContext` exposes the keyspaces auth tests need —
//!   surface check so future contributors don't have to grep.
//!
//! What's NOT covered (intentional — needs real DID resolver):
//! - Full sign-then-verify against the challenge in `POST /auth/`.
//!   That round-trip lives in the e2e suite where a real signing
//!   admin DID + DID resolver are available.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
    (status, json)
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        // Stamp a stable client IP so the per-IP rate limiter doesn't
        // throttle this test in a `cargo test --workspace` parallel
        // run that interleaves with the rate-limit test.
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// `POST /auth/challenge` returns a session_id + challenge nonce and
/// persists the challenge so the matching `POST /auth/` can look it up.
/// Requires an ACL entry — the challenge endpoint is gated on caller
/// being in the ACL (otherwise an attacker could enumerate session
/// state by spamming challenge requests for arbitrary DIDs).
#[tokio::test]
async fn challenge_endpoint_issues_session_and_persists_it() {
    let (router, ctx) = build_test_app().await;

    let did = "did:key:z6MkChallengeTester";
    // Pre-grant the DID admin access so it passes the ACL check.
    let entry = vti_common::acl::AclEntry {
        did: did.into(),
        role: vti_common::acl::Role::Admin,
        label: None,
        allowed_contexts: vec![],
        created_at: 1,
        created_by: "test".into(),
        expires_at: None,
        kind: Default::default(),
        capabilities: vec![],
        device: None,
        version: 0,
    };
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");

    let (status, body) = request(&router, post_json("/auth/challenge", json!({"did": did}))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "challenge issuance must succeed for an ACL-permitted DID; got body: {body}"
    );

    // Canonical wire shape: { challenge, sessionId, expiresAt } per
    // spec/auth/challenge/0.1#response — no `data` envelope.
    let session_id = body["sessionId"].as_str().expect("sessionId in response");
    let challenge = body["challenge"].as_str().expect("challenge in response");
    assert!(
        body["expiresAt"].as_str().is_some(),
        "canonical shape includes expiresAt: {body}"
    );
    assert!(!session_id.is_empty(), "session_id must be non-empty");
    assert!(!challenge.is_empty(), "challenge must be non-empty");

    // The session row must be persisted so the matching `POST /auth/`
    // can later look it up. Read it back directly via the test
    // context; this is exactly what the auth handler does internally.
    let session_row = vti_common::auth::session::get_session(&ctx.sessions_ks, session_id)
        .await
        .expect("session lookup");
    let session = session_row.expect("session row was persisted");
    assert_eq!(
        session.did, did,
        "persisted session must record the DID that requested the challenge"
    );
    assert_eq!(
        session.challenge, challenge,
        "persisted challenge must match the one returned to the client (so `/auth/` can verify the signature against the same nonce the client signed)"
    );
}

/// `POST /auth/refresh` with a malformed refresh token returns 401, not
/// 500. Pre-fix-bundle, a parse-failure on the refresh token bubbled
/// up as an internal error; this test pins the user-facing 401 so a
/// future refactor doesn't regress error mapping.
#[tokio::test]
async fn refresh_endpoint_rejects_malformed_token_with_401() {
    let (router, _ctx) = build_test_app().await;

    let (status, _body) = request(
        &router,
        post_json(
            "/auth/refresh",
            json!({"refresh_token": "not-a-real-refresh-token"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "malformed refresh token must surface as 401, not 500"
    );
}

/// `POST /auth/refresh` with an unknown but well-shaped token also
/// returns 401. Confirms the lookup-miss path doesn't leak distinct
/// error info.
#[tokio::test]
async fn refresh_endpoint_rejects_unknown_token_with_401() {
    let (router, _ctx) = build_test_app().await;

    // 32 bytes of base64url is the right shape for a refresh token but
    // refers to no stored session.
    let (status, _body) = request(
        &router,
        post_json(
            "/auth/refresh",
            json!({"refresh_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unknown refresh token must surface as 401"
    );
}

/// Smoke check: `TestAppContext` exposes the keyspaces these tests need
/// so future auth-flow regressions can be added with similarly small
/// boilerplate.
#[tokio::test]
async fn test_app_context_exposes_required_keyspaces() {
    let (_router, ctx) = build_test_app().await;
    let _: &TestAppContext = &ctx;
    // The fields below are what auth tests need; if any of these
    // disappears from `TestAppContext`, this assertion forces an
    // explicit fix-up of the helper rather than a silent test failure
    // in a downstream file.
    let _sessions = ctx.sessions_ks.clone();
    let _acl = ctx.acl_ks.clone();
    let _jwt = ctx.jwt_keys.clone();
}
