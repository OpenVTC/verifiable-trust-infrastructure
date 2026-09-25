//! `/v1/admin/invites` — the error codes `vtc/admin/invites/{create,revoke}`
//! declare (#1600), read from the generated bindings.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::install::InstallTokenSigner;
use vtc_service::test_support::TestVtc;

const CREATE_TASK: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const REVOKE_TASK: &str = "https://trusttasks.org/spec/vtc/admin/invites/revoke/0.1";

const CREATE_INVITE_ERR_TTL_TOO_LONG: &str =
    trust_tasks_rs::specs::vtc::admin::invites::create::v0_1::error_codes::TTL_TOO_LONG.code;
const REVOKE_INVITE_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::admin::invites::revoke::v0_1::error_codes::NOT_FOUND.code;

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

async fn build() -> (TestVtc, String) {
    let vtc = TestVtc::builder()
        .vtc_did("did:webvh:vtc.example.com:abc")
        .with_public_url("https://vtc.example.com")
        .with_install_signer(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
        .build()
        .await;
    let token = vtc.admin_token().await;
    // The invitee already holds a (scoped) admin entry, so these mints take the
    // path that writes no ACL entry. A mint that *creates* one confers
    // unrestricted admin and needs a step-up and another admin's consent
    // (VTI-APV-014) — `unrestricted_admin_consent.rs` covers that. These tests
    // are about the error codes.
    vtc_service::acl::store_acl_entry(
        &vtc.state.acl_ks,
        &vtc_service::acl::VtcAclEntry {
            did: "did:key:z6MkInvitee".into(),
            role: vtc_service::acl::VtcRole::Admin,
            label: None,
            allowed_contexts: vec!["ctx-a".into()],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    (vtc, token)
}

async fn call(
    vtc: &TestVtc,
    token: &str,
    method: &str,
    uri: &str,
    task: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = vtc
        .router
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Over 24 hours is `ttlTooLong`; a zero TTL is the same 400 without a code,
/// because the specification declares only the upper bound. Statuses
/// unchanged (400, 400), and the 24-hour boundary itself still mints.
#[tokio::test]
async fn the_create_task_answers_with_the_code_its_spec_declares() {
    let (vtc, token) = build().await;
    let create = |ttl: u64| json!({ "did": "did:key:z6MkInvitee", "ttlSeconds": ttl });

    let (status, body) = call(
        &vtc,
        &token,
        "POST",
        "/v1/admin/invites",
        CREATE_TASK,
        Some(create(24 * 60 * 60 + 1)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        rest_error_code(&body),
        CREATE_INVITE_ERR_TTL_TOO_LONG,
        "{body}"
    );

    let (status, body) = call(
        &vtc,
        &token,
        "POST",
        "/v1/admin/invites",
        CREATE_TASK,
        Some(create(0)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(rest_error_code(&body), "", "zero is not ttlTooLong: {body}");

    let (status, body) = call(
        &vtc,
        &token,
        "POST",
        "/v1/admin/invites",
        CREATE_TASK,
        Some(create(24 * 60 * 60)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// An unknown `jti` is `notFound`, status unchanged (404). A revoked invite
/// is gone, so revoking it again is the same `notFound`.
#[tokio::test]
async fn the_revoke_task_answers_with_the_code_its_spec_declares() {
    let (vtc, token) = build().await;

    let (status, body) = call(
        &vtc,
        &token,
        "DELETE",
        &format!("/v1/admin/invites/{}", uuid::Uuid::new_v4()),
        REVOKE_TASK,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        rest_error_code(&body),
        REVOKE_INVITE_ERR_NOT_FOUND,
        "{body}"
    );

    let (status, minted) = call(
        &vtc,
        &token,
        "POST",
        "/v1/admin/invites",
        CREATE_TASK,
        Some(json!({ "did": "did:key:z6MkInvitee" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let uri = format!("/v1/admin/invites/{}", minted["jti"].as_str().unwrap());

    let (status, body) = call(&vtc, &token, "DELETE", &uri, REVOKE_TASK, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&vtc, &token, "DELETE", &uri, REVOKE_TASK, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        rest_error_code(&body),
        REVOKE_INVITE_ERR_NOT_FOUND,
        "{body}"
    );
}
