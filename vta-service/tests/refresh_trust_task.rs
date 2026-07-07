//! Integration test for **refresh via an `auth/refresh/0.1` Trust Task over
//! REST** — the transport-agnostic refresh path that completes the mobile REST
//! auth loop (login lands in `authenticate_trust_task.rs`).
//!
//! Refresh carries **no proof**: the opaque refresh token in the payload is the
//! bearer credential (OAuth2 §10.4), verified server-side by the rotating
//! reverse-index. So this exercises route → `TrustTask` parse → canonical
//! `handle_refresh` → token rotation, with no signing ceremony.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{
    Session, SessionState, now_epoch, store_refresh_index, store_session,
};

async fn seed_admin_acl(ctx: &TestAppContext, did: &str) {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
}

/// Seed an authenticated session with a live refresh token + its reverse index.
async fn seed_authenticated_session(
    ctx: &TestAppContext,
    did: &str,
    refresh_token: &str,
) -> String {
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(refresh_token.to_string()),
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session)
        .await
        .expect("store session");
    store_refresh_index(&ctx.sessions_ks, refresh_token, &session_id)
        .await
        .expect("store refresh index");
    session_id
}

fn refresh_doc(refresh_token: &str) -> Vec<u8> {
    json!({
        "id": "urn:uuid:refresh-itest-1",
        "type": "https://trusttasks.org/spec/auth/refresh/0.1",
        "issuer": "did:key:z6MkRefresher",
        "recipient": "did:key:z6MkTestVTA",
        "payload": { "refreshToken": refresh_token },
    })
    .to_string()
    .into_bytes()
}

fn post(uri: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.9")
        .body(Body::from(body))
        .unwrap()
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes).to_string()}));
    (status, v)
}

#[tokio::test]
async fn trust_task_refresh_rotates_tokens() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkRefresher";
    let old_token = "refresh-tok-itest-aaaa";
    seed_admin_acl(&ctx, did).await;
    seed_authenticated_session(&ctx, did, old_token).await;

    let (status, body) = send(&router, post("/auth/refresh", refresh_doc(old_token))).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Trust Task refresh must succeed: {body}"
    );
    // TT request → TT `#response` doc (tokens + session under `payload`).
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("/auth/refresh/0.1#response")),
        "response is a TT #response doc: {body}"
    );
    assert_eq!(body["payload"]["session"]["subject"], did, "{body}");
    assert!(
        body["payload"]["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "a fresh access token is issued: {body}"
    );
    // RFC 6749 §10.4 rotation: a new refresh token, different from the old one.
    let new_token = body["payload"]["tokens"]["refreshToken"]
        .as_str()
        .expect("rotated refresh token");
    assert_ne!(new_token, old_token, "refresh token must rotate: {body}");

    // The presented token works exactly once — a replay is rejected.
    let (replay_status, _) = send(&router, post("/auth/refresh", refresh_doc(old_token))).await;
    assert_eq!(
        replay_status,
        StatusCode::UNAUTHORIZED,
        "a consumed refresh token must not refresh again"
    );
}

#[tokio::test]
async fn trust_task_refresh_rejects_unknown_token() {
    let (router, _ctx) = build_test_app().await;
    let (status, _) = send(
        &router,
        post("/auth/refresh", refresh_doc("refresh-tok-never-issued")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unknown refresh token must be rejected"
    );
}
