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

/// POST a raw string body (the `/auth/` handler reads `body: String`
/// directly, so the DIDComm envelope goes on the wire verbatim).
fn post_raw(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "text/plain")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(body))
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
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
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

/// Regression pin for FTL-28605 (VTA-001): a remote unauthenticated
/// attacker must not be able to obtain an admin JWT by POSTing a
/// **plaintext** DIDComm message with a forged `from` field.
///
/// The attack: the challenge + session_id handed out by
/// `/auth/challenge` are public, and `atm.unpack` parses a plaintext
/// DIDComm envelope (a JSON with a `type` field but no JWE/JWS layer),
/// returning an attacker-controlled `from` with `authenticated: false`.
/// The `/auth/` handler previously discarded that metadata and trusted
/// `msg.from` as the proven signer, so `from: <admin DID>` echoing the
/// public challenge minted an admin token.
///
/// The fix rejects any envelope that isn't authenticated + encrypted
/// (legitimate clients authcrypt via `pack_encrypted`). This test wires
/// a real (offline) ATM so the request reaches `atm.unpack` and the new
/// guard — *not* the "ATM not configured" short-circuit — then drives
/// the exact exploit and asserts a 401 attributable to the guard.
#[tokio::test]
async fn plaintext_didcomm_with_forged_sender_is_rejected() {
    use vta_service::test_support::{TestAppOptions, build_offline_atm, build_test_app_with};

    let (router, ctx) = build_test_app_with(TestAppOptions {
        atm: Some(build_offline_atm().await),
        ..Default::default()
    })
    .await;

    let admin_did = "did:key:z6MkForgedAdminTarget";
    let entry = vti_common::acl::AclEntry::new(admin_did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");

    // Step 1 — obtain the public challenge + session_id for the target
    // admin DID (no secret involved; the endpoint is pre-auth).
    let (status, body) = request(
        &router,
        post_json("/auth/challenge", json!({"did": admin_did})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge issuance: {body}");
    let session_id = body["sessionId"].as_str().expect("sessionId");
    let challenge = body["challenge"].as_str().expect("challenge");

    // Step 2 — craft a plaintext DIDComm message forging `from` = admin
    // DID. No encryption, no signature; `body` (not `payload`) means it
    // is a DIDComm envelope, not a Trust Task, so it reaches `atm.unpack`.
    let forged = json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
        "from": admin_did,
        "to": ["did:key:z6MkVtaServiceUnderTest"],
        "body": { "challenge": challenge, "session_id": session_id },
    });

    let (status, body) = request(&router, post_raw("/auth/", forged.to_string())).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a plaintext DIDComm message with a forged sender must be rejected, not issued an admin JWT; got body: {body}"
    );
    // The 401 must come from the authcrypt guard, not the ATM-not-configured
    // short-circuit — otherwise the test would pass without exercising the fix.
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("authenticated (authcrypt) DIDComm envelope"),
        "401 must be attributable to the plaintext/authcrypt guard, got: {body}"
    );
    assert!(
        body.get("tokens").is_none() && body.get("access_token").is_none(),
        "no token may be issued for a forged plaintext message: {body}"
    );

    // The challenge session must remain unconsumed (still in
    // ChallengeSent), so the forged attempt didn't advance auth state.
    let session = vti_common::auth::session::get_session(&ctx.sessions_ks, session_id)
        .await
        .expect("session lookup")
        .expect("challenge session still present");
    assert_eq!(
        session.state,
        vti_common::auth::session::SessionState::ChallengeSent,
        "forged authenticate attempt must not transition the session to Authenticated"
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

/// Regression pin for FTL-28605 on the refresh path: a plaintext
/// DIDComm `auth/refresh/0.1` envelope must be rejected by the same
/// authcrypt guard as `/auth/`. The opaque refresh token is the primary
/// credential, but the DIDComm path binds `msg.from` to the session DID
/// inside `handle_refresh`; accepting a plaintext (forgeable) sender
/// would defeat that binding, so the envelope must be authcrypt.
///
/// A DIDComm envelope carries `body` (not `payload`), so it falls past
/// `try_refresh_trust_task` to `atm.unpack` and hits the guard. No valid
/// refresh token is needed — the guard runs before the token is read.
#[tokio::test]
async fn plaintext_didcomm_refresh_is_rejected() {
    use vta_service::test_support::{TestAppOptions, build_offline_atm, build_test_app_with};

    let (router, _ctx) = build_test_app_with(TestAppOptions {
        atm: Some(build_offline_atm().await),
        ..Default::default()
    })
    .await;

    let forged = json!({
        "id": "attacker-supplied-id",
        "typ": "application/didcomm-plain+json",
        "type": "https://trusttasks.org/spec/auth/refresh/0.1",
        "from": "did:key:z6MkForgedAdminTarget",
        "to": ["did:key:z6MkVtaServiceUnderTest"],
        "body": { "refresh_token": "stolen-or-guessed-token" },
    });

    let (status, body) = request(&router, post_raw("/auth/refresh", forged.to_string())).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a plaintext DIDComm refresh must be rejected by the authcrypt guard; got: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("authenticated (authcrypt) DIDComm envelope"),
        "401 must be attributable to the refresh authcrypt guard, got: {body}"
    );
    assert!(
        body.get("tokens").is_none(),
        "no token may be issued for a forged plaintext refresh: {body}"
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
