//! Integration tests for runtime **step-up policy management** — the REST
//! `GET`/`PUT /step-up/policy` surface and the `auth/step-up/policy/0.2`
//! trust-task, exercised through the real router → bearer auth → operation →
//! config persistence path.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::build_test_app;
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

/// The recipient DID `build_test_app` configures as the VTA's own `vta_did`.
const TEST_VTA_DID: &str = "did:key:z6MkTestVTA";

/// Store an authenticated session and mint a bearer token for `did` with the
/// given role / contexts. Empty `contexts` + `admin` role ⇒ super-admin.
async fn token_for(
    ctx: &vta_service::test_support::TestAppContext,
    did: &str,
    session_id: &str,
    role: &str,
    contexts: Vec<String>,
) -> String {
    let session = Session {
        session_id: session_id.to_string(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();
    let claims = ctx.jwt_keys.new_claims(
        did.to_string(),
        session_id.to_string(),
        role.to_string(),
        contexts,
        900,
        false,
    );
    ctx.jwt_keys.encode(&claims).unwrap()
}

async fn put_policy(router: &axum::Router, token: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri("/step-up/policy")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn super_admin_sets_and_reads_self_policy_via_rest() {
    let (router, ctx) = build_test_app().await;
    let token = token_for(&ctx, "did:key:z6MkSuper", "sess-su-1", "admin", vec![]).await;

    // Set a `self` floor — never a lockout risk, so it applies with no approver.
    let (status, body) = put_policy(
        &router,
        &token,
        json!({ "enabled": true, "floors": [{ "operation": "*", "mode": "self" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true, "{body}");
    assert_eq!(body["floors"][0]["operation"], "*", "{body}");
    assert_eq!(body["floors"][0]["mode"], "self", "{body}");
    // Default materialized on the response.
    assert_eq!(
        body["floors"][0]["allowAal1IfNonEscalating"], false,
        "{body}"
    );

    // The live config now reflects it (so the gate enforces it).
    assert!(ctx.config.read().await.auth.step_up.enabled);

    // GET reads the same effective policy back.
    let req = Request::builder()
        .method("GET")
        .uri("/step-up/policy")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let got: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(got["enabled"], true);
    assert_eq!(got["floors"][0]["mode"], "self");
}

#[tokio::test]
async fn enabling_delegated_floor_without_approver_is_lockout_refused() {
    let (router, ctx) = build_test_app().await;
    let token = token_for(&ctx, "did:key:z6MkSuper", "sess-su-2", "admin", vec![]).await;

    let (status, body) = put_policy(
        &router,
        &token,
        json!({ "enabled": true, "floors": [{ "operation": "acl/grant", "mode": "delegated" }] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "expected lockoutRefused: {body}"
    );
    assert!(
        serde_json::to_string(&body).unwrap().contains("approver"),
        "error should explain the missing approver: {body}"
    );
    // Refused → prior (disabled) policy still in force.
    assert!(!ctx.config.read().await.auth.step_up.enabled);
}

#[tokio::test]
async fn unknown_operation_is_rejected() {
    let (router, _ctx) = build_test_app().await;
    let token = token_for(&_ctx, "did:key:z6MkSuper", "sess-su-3", "admin", vec![]).await;

    let (status, body) = put_policy(
        &router,
        &token,
        json!({ "enabled": true, "floors": [{ "operation": "acl/teleport", "mode": "self" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn enabling_delegated_floor_with_an_approver_succeeds() {
    let (router, ctx) = build_test_app().await;
    let token = token_for(&ctx, "did:key:z6MkSuper", "sess-su-5", "admin", vec![]).await;

    // Register an ACL entry that carries a delegated approver (allowed at AAL1
    // while the policy is still disabled). Now a delegated floor is satisfiable.
    let create = json!({
        "did": "did:key:z6MkSomeUser",
        "role": "application",
        "step_up_approver": "did:key:z6MkApproverPhone"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/acl")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "acl create should succeed at AAL1"
    );

    // Enabling the delegated floor now passes the lockout check.
    let (status, body) = put_policy(
        &router,
        &token,
        json!({ "enabled": true, "floors": [{ "operation": "acl/grant", "mode": "delegated" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["floors"][0]["mode"], "delegated", "{body}");
    assert!(ctx.config.read().await.auth.step_up.enabled);
}

#[tokio::test]
async fn non_super_admin_cannot_set_policy() {
    let (router, ctx) = build_test_app().await;
    // Admin role but scoped to a context ⇒ NOT super-admin.
    let token = token_for(
        &ctx,
        "did:key:z6MkScopedAdmin",
        "sess-scoped-1",
        "admin",
        vec!["ctx1".to_string()],
    )
    .await;

    let (status, _body) = put_policy(
        &router,
        &token,
        json!({ "enabled": true, "floors": [{ "operation": "*", "mode": "self" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!ctx.config.read().await.auth.step_up.enabled);
}

#[tokio::test]
async fn trust_task_path_sets_policy() {
    let (router, ctx) = build_test_app().await;
    let token = token_for(&ctx, "did:key:z6MkSuper", "sess-su-4", "admin", vec![]).await;

    let doc = json!({
        "id": "stepup-policy-itest-1",
        "type": "https://trusttasks.org/spec/auth/step-up/policy/0.2",
        "issuer": "did:key:z6MkSuper",
        "recipient": TEST_VTA_DID,
        "payload": {
            "enabled": true,
            "floors": [
                { "operation": "*", "mode": "self" },
                { "operation": "acl/swap-key", "mode": "self", "allowAal1IfNonEscalating": true }
            ]
        }
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

    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v["type"], "https://trusttasks.org/spec/auth/step-up/policy/0.2#response",
        "{v}"
    );
    assert_eq!(v["payload"]["enabled"], true, "{v}");
    // Canonicalized: the swap-key carve-out is materialized.
    let floors = v["payload"]["floors"].as_array().expect("floors array");
    assert!(
        floors
            .iter()
            .any(|f| f["operation"] == "acl/swap-key" && f["allowAal1IfNonEscalating"] == true),
        "{v}"
    );
    assert!(ctx.config.read().await.auth.step_up.enabled);
}

#[tokio::test]
async fn non_super_admin_trust_task_is_not_authorized() {
    let (router, ctx) = build_test_app().await;
    let token = token_for(
        &ctx,
        "did:key:z6MkScopedAdmin",
        "sess-scoped-2",
        "admin",
        vec!["ctx1".to_string()],
    )
    .await;

    let doc = json!({
        "id": "stepup-policy-itest-2",
        "type": "https://trusttasks.org/spec/auth/step-up/policy/0.2",
        "issuer": "did:key:z6MkScopedAdmin",
        "recipient": TEST_VTA_DID,
        "payload": { "enabled": true, "floors": [{ "operation": "*", "mode": "self" }] }
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

    assert_ne!(status, StatusCode::OK, "{v}");
    assert!(
        serde_json::to_string(&v)
            .unwrap()
            .contains("not_authorized"),
        "{v}"
    );
    assert!(!ctx.config.read().await.auth.step_up.enabled);
}
