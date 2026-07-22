//! Integration coverage for the canonical `acl/*` surface (phase 2d).
//!
//! The URI swap is the least interesting part. What needs pinning is
//! the behaviour the canonical tasks promise and VTC did not previously
//! implement: a compare-and-swap on role changes, scope *reduction*
//! that isn't a full removal, and a grant that refuses to be used as a
//! back door for role changes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::test_support::TestVtc;

const LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const SHOW: &str = "https://trusttasks.org/spec/acl/show/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";

struct Fixture {
    router: axum::Router,
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    Fixture {
        router: vtc.router.clone(),
        vtc,
    }
}

async fn admin_token(fix: &Fixture) -> String {
    fix.vtc.token("did:key:z6MkAdmin", "admin", vec![]).await
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

async fn call(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"));
    if body.is_some() {
        b = b.header("Content-Type", "application/json");
    }
    let req = b
        .body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

async fn grant(fix: &Fixture, token: &str, subject: &str, role: &str, scopes: Value) -> StatusCode {
    call(
        fix,
        "POST",
        "/v1/acl",
        GRANT,
        token,
        Some(json!({ "entry": { "subject": subject, "role": role, "scopes": scopes } })),
    )
    .await
    .0
}

#[tokio::test]
async fn entries_use_canonical_names_and_rfc3339_timestamps() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    assert_eq!(
        grant(
            &fix,
            &token,
            "did:key:z6MkAlice",
            "member",
            json!(["ctx-a"])
        )
        .await,
        StatusCode::CREATED
    );

    let (status, body) = call(&fix, "GET", "/v1/acl", LIST, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("truncated").is_some(),
        "truncated required: {body}"
    );

    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["subject"] == "did:key:z6MkAlice")
        .expect("granted entry present");
    assert_eq!(entry["scopes"], json!(["ctx-a"]));
    assert!(
        entry["createdAt"].as_str().unwrap().contains('T'),
        "createdAt must be RFC3339: {entry}"
    );
    for old in ["did", "allowed_contexts", "created_at"] {
        assert!(entry.get(old).is_none(), "{old} must be gone: {entry}");
    }
}

/// Canonical: a grant against an existing subject with a *different*
/// role must be refused and point at change-role. Otherwise grant is a
/// silent bypass of the compare-and-swap guard.
#[tokio::test]
async fn grant_refuses_to_change_an_existing_role() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    assert_eq!(
        grant(&fix, &token, "did:key:z6MkBob", "member", json!(["ctx-a"])).await,
        StatusCode::CREATED
    );

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkBob", "role": "moderator", "scopes": ["ctx-a"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("change-role"),
        "the refusal should name the right task: {body}"
    );
}

/// Re-granting the *same* role is how canonical expresses "the entry
/// the maintainer should hold" — it rewrites scopes/label.
#[tokio::test]
async fn grant_with_the_same_role_rewrites_the_entry() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(
        &fix,
        &token,
        "did:key:z6MkCarol",
        "member",
        json!(["ctx-a"]),
    )
    .await;

    let (status, body) = call(
        &fix,
        "POST",
        "/v1/acl",
        GRANT,
        &token,
        Some(json!({ "entry": { "subject": "did:key:z6MkCarol", "role": "member", "scopes": ["ctx-a", "ctx-b"] } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rewrite, not create: {body}");
    assert_eq!(body["scopes"], json!(["ctx-a", "ctx-b"]));
    assert!(
        body["updatedAt"].as_str().is_some(),
        "a rewrite must stamp updatedAt: {body}"
    );
    assert_eq!(body["updatedBy"], "did:key:z6MkAdmin");
}

#[tokio::test]
async fn change_role_enforces_the_from_role_guard() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkDan", "member", json!(["ctx-a"])).await;

    // Stale read: caller believes Dan is a moderator.
    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkDan",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "moderator", "toRole": "admin" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a mismatched fromRole must not apply: {body}"
    );

    // Correct fromRole applies.
    let (status, body) = call(
        &fix,
        "PATCH",
        "/v1/acl/did:key:z6MkDan",
        CHANGE_ROLE,
        &token,
        Some(json!({ "fromRole": "member", "toRole": "moderator" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"], "moderator");
    assert!(body["updatedAt"].as_str().is_some(), "{body}");
}

/// Canonical revoke has two modes. `scopes` reduces; omitting it
/// removes. Conflating them would strip more authority than asked.
#[tokio::test]
async fn revoke_with_scopes_reduces_rather_than_removes() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(
        &fix,
        &token,
        "did:key:z6MkErin",
        "member",
        json!(["ctx-a", "ctx-b"]),
    )
    .await;

    let (status, _) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkErin?scopes=ctx-a",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The entry must survive, minus that one scope.
    let (status, body) = call(&fix, "GET", "/v1/acl/did:key:z6MkErin", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::OK, "entry must survive: {body}");
    assert_eq!(body["scopes"], json!(["ctx-b"]));
}

#[tokio::test]
async fn revoke_without_scopes_removes_the_entry() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkFred", "member", json!(["ctx-a"])).await;

    let (status, _) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkFred",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = call(&fix, "GET", "/v1/acl/did:key:z6MkFred", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Emptying an entry's scope set would leave an *unscoped* entry —
/// which is how a community-wide (super) grant is spelled. Revoking
/// must never widen authority.
#[tokio::test]
async fn revoking_every_scope_is_refused_rather_than_unscoping() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    grant(&fix, &token, "did:key:z6MkGina", "member", json!(["ctx-a"])).await;

    let (status, body) = call(
        &fix,
        "DELETE",
        "/v1/acl/did:key:z6MkGina?scopes=ctx-a",
        REVOKE,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, body) = call(&fix, "GET", "/v1/acl/did:key:z6MkGina", SHOW, &token, None).await;
    assert_eq!(status, StatusCode::OK, "entry must be untouched: {body}");
    assert_eq!(body["scopes"], json!(["ctx-a"]));
}

#[tokio::test]
async fn each_verb_rejects_a_siblings_task() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    // GET /v1/acl bound to acl/list must not accept acl/grant.
    let (status, _) = call(&fix, "GET", "/v1/acl", GRANT, &token, None).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn list_filters_and_paginates() {
    let fix = build().await;
    let token = admin_token(&fix).await;
    for who in ["did:key:z6MkP1", "did:key:z6MkP2", "did:key:z6MkP3"] {
        grant(&fix, &token, who, "member", json!(["ctx-a"])).await;
    }
    grant(
        &fix,
        &token,
        "did:key:z6MkQ1",
        "moderator",
        json!(["ctx-b"]),
    )
    .await;

    // Role filter actually filters.
    let (_, body) = call(&fix, "GET", "/v1/acl?role=moderator", LIST, &token, None).await;
    let subjects: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, vec!["did:key:z6MkQ1"], "{body}");

    // Paging, and the cursor must not survive a filter change.
    let (_, page1) = call(
        &fix,
        "GET",
        "/v1/acl?scope=ctx-a&pageSize=1",
        LIST,
        &token,
        None,
    )
    .await;
    assert_eq!(page1["truncated"], true, "{page1}");
    let cursor = page1["cursor"].as_str().expect("cursor").to_string();

    let (status, _) = call(
        &fix,
        "GET",
        &format!("/v1/acl?scope=ctx-a&pageSize=1&cursor={cursor}"),
        LIST,
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "same filters resume");

    let (status, body) = call(
        &fix,
        "GET",
        &format!("/v1/acl?scope=ctx-b&pageSize=1&cursor={cursor}"),
        LIST,
        &token,
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a cursor must not carry across a filter change: {body}"
    );
}
