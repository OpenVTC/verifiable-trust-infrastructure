//! Integration test for `auth/whoami/0.1` — session introspection over the
//! trust-task dispatcher (bearer-authed, like revoke-session).
//!
//! The point of whoami is to surface the **live** session state: a bearer
//! token minted at AAL1 keeps saying `acr=aal1` until it's refreshed, but if
//! the session was stepped up to AAL2 in the meantime, whoami reports the
//! current `acr` (read from the session, not the stale token) plus
//! freshly-resolved roles/scopes — without re-issuing any token.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

async fn seed_admin_acl(ctx: &TestAppContext, did: &str, contexts: Vec<String>) {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_contexts(contexts)
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
}

#[tokio::test]
async fn whoami_reports_live_session_acr_not_stale_token() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkWhoamiSubject";
    let session_id = "sess-whoami-1";
    seed_admin_acl(&ctx, did, vec!["ctx1".into()]).await;

    // The session has been stepped up to AAL2 (e.g. via approve-response).
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into(), "passkey".into()],
        acr: "aal2".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    // The bearer token, however, was minted BEFORE the step-up: no `with_aal`,
    // so its `acr` is stale (empty / AAL1).
    let claims = ctx.jwt_keys.new_claims(
        did.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    let doc = json!({
        "id": "urn:uuid:whoami-itest-1",
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
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(status, StatusCode::OK, "whoami must succeed: {v}");
    let s = &v["payload"]["session"];
    assert_eq!(s["subject"], did, "{v}");
    assert_eq!(s["id"], session_id, "{v}");
    // The live session acr (aal2) — NOT the stale token's (aal1/empty).
    assert_eq!(
        s["acr"], "aal2",
        "whoami must report the session's current acr, not the token's: {v}"
    );
    assert!(
        s["amr"].as_array().unwrap().iter().any(|m| m == "passkey"),
        "live amr should include the step-up factor: {v}"
    );
    // Freshly-resolved authority from the ACL.
    assert!(
        v["payload"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "admin"),
        "{v}"
    );
    assert!(
        v["payload"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "ctx:ctx1"),
        "scopes mirror the access-token `ctx:<id>` form: {v}"
    );
    // issuedAt / expiresAt are present timestamps.
    assert!(s["issuedAt"].as_str().is_some(), "{v}");
    assert!(s["expiresAt"].as_str().is_some(), "{v}");
}

#[tokio::test]
async fn whoami_without_bearer_is_unauthorized() {
    let (router, _ctx) = build_test_app().await;
    let doc = json!({
        "id": "urn:uuid:whoami-itest-2",
        "type": "https://trusttasks.org/spec/auth/whoami/0.1",
        "issuer": "did:key:z6MkAnon",
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "whoami requires a bearer token (the dispatcher is authed)"
    );
}
