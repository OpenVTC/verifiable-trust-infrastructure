//! Integration test for the **jti pin** — an access token authenticates only
//! while its `jti` matches the session's `token_id`. Minting a fresh token
//! rotates `token_id`, so every previously-issued token for the same session is
//! superseded. This is the mechanism that keeps a session revocable even when
//! its `session_id` does not rotate. Sessions with an unset `token_id` (legacy
//! rows, intrinsic-sender sessions) are unaffected — the pin is opt-in.
//!
//! Exercises the real `AuthClaims` extractor through the trust-task dispatcher.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

async fn seed_admin_acl(ctx: &TestAppContext, did: &str) {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
}

async fn seed_session(ctx: &TestAppContext, session_id: &str, did: &str, token_id: Option<&str>) {
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(format!("rt-{session_id}")),
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: token_id.map(str::to_string),
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();
}

/// A `whoami` request bearing `did`/`session_id`/`jti`; returns the HTTP status
/// the extractor + dispatcher produced.
async fn whoami_status(
    ctx: &TestAppContext,
    router: &axum::Router,
    did: &str,
    session_id: &str,
    jti: &str,
) -> StatusCode {
    let claims = ctx
        .jwt_keys
        .new_claims(
            did.into(),
            session_id.into(),
            "admin".into(),
            vec![],
            900,
            false,
        )
        .with_jti(jti);
    let token = ctx.jwt_keys.encode(&claims).unwrap();
    let doc = serde_json::json!({
        "id": "urn:uuid:jti-pin-itest",
        "type": "https://trusttasks.org/spec/auth/whoami/0.1",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn matching_jti_authenticates_but_superseded_jti_is_rejected() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkPinned";
    seed_admin_acl(&ctx, did).await;
    seed_session(&ctx, "sess-pin", did, Some("jti-A")).await;

    // Matching jti → authenticated (the route runs).
    let ok = whoami_status(&ctx, &router, did, "sess-pin", "jti-A").await;
    assert_eq!(
        ok,
        StatusCode::OK,
        "token whose jti matches token_id must authenticate"
    );

    // Superseded jti (a token minted before the last rotation) → 401.
    let stale = whoami_status(&ctx, &router, did, "sess-pin", "jti-OLD").await;
    assert_eq!(
        stale,
        StatusCode::UNAUTHORIZED,
        "token whose jti != session.token_id must be rejected as superseded"
    );
}

#[tokio::test]
async fn unpinned_session_accepts_any_jti() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkLegacy";
    seed_admin_acl(&ctx, did).await;
    // token_id: None — a legacy / intrinsic-sender session; the pin is skipped.
    seed_session(&ctx, "sess-legacy", did, None).await;

    let any = whoami_status(&ctx, &router, did, "sess-legacy", "whatever").await;
    assert_eq!(
        any,
        StatusCode::OK,
        "a session with no token_id must not enforce the pin (back-compat)"
    );
}
