//! Integration coverage for `GET /v1/audit` — canonical
//! `spec/audit/list/0.1` (phase 2b(ii)).
//!
//! What matters here is not the URI swap but the three things the
//! repoint introduced: the canonical response/envelope shape, filters
//! that are actually applied (rather than accepted and ignored), and a
//! cursor that refuses to be reused under a different filter set.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const LIST_TASK: &str = "https://trusttasks.org/spec/audit/list/0.1";
const PROFILE_TASK: &str = "https://trusttasks.org/spec/vtc/community/profile/update/0.1";

struct Fixture {
    router: axum::Router,
    state: AppState,
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

async fn super_admin_token(fix: &Fixture) -> String {
    fix.vtc.token("did:key:z6MkAdmin", "admin", vec![]).await
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

async fn list(fix: &Fixture, token: &str, query: &str) -> (StatusCode, Value) {
    let uri = if query.is_empty() {
        "/v1/audit".to_string()
    } else {
        format!("/v1/audit?{query}")
    };
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Trust-Task", LIST_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

/// Emit real `CommunityProfileUpdated` envelopes through a live route.
async fn seed(fix: &Fixture, token: &str, count: usize) {
    let profile = vtc_service::community::CommunityProfile::new(
        "did:webvh:vtc.example.com:abc",
        "Example Community",
    );
    vtc_service::community::store_profile(&fix.state.community_ks, &profile)
        .await
        .unwrap();
    for i in 0..count {
        let req = Request::builder()
            .method("PUT")
            .uri("/v1/community/profile")
            .header("Trust-Task", PROFILE_TASK)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"name":"Rename {i}"}}"#)))
            .unwrap();
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "seed write {i}");
    }
}

#[tokio::test]
async fn response_and_entries_are_the_canonical_shape() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 2).await;

    let (status, body) = list(&fix, &token, "").await;
    assert_eq!(status, StatusCode::OK);

    // Canonical response envelope, not the old Paginated wrapper.
    assert!(body.get("entries").is_some(), "entries: {body}");
    assert!(body.get("truncated").is_some(), "truncated: {body}");
    assert!(
        body.get("items").is_none() && body.get("next_cursor").is_none(),
        "the pre-migration Paginated shape must be gone: {body}"
    );

    let entry = &body["entries"][0];
    for field in ["eventId", "recordedAt", "action", "schemaVersion"] {
        assert!(entry.get(field).is_some(), "{field} missing: {entry}");
    }
    // Maintainer-specific fields moved under ext — canonical
    // AuditEnvelope is additionalProperties:false.
    assert!(entry.get("actor_did_hash").is_none(), "{entry}");
    assert!(entry.get("timestamp").is_none(), "{entry}");
    assert!(
        entry["ext"]["vtc"].get("actorDidHash").is_some(),
        "keyed hash should ride in ext: {entry}"
    );
    // action is the serde tag; detail is the variant payload.
    assert_eq!(entry["action"], "CommunityProfileUpdated");
    assert!(entry["detail"].is_object(), "{entry}");
}

/// `verify` reports `head` as hex; a caller comparing it against the
/// newest entry's `entryHash` must not have to reconcile encodings.
#[tokio::test]
async fn entry_hashes_are_hex_matching_audit_verify_head() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 2).await;

    let (_, list_body) = list(&fix, &token, "").await;
    let newest = list_body["entries"][0]["entryHash"].as_str().unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/v1/audit/verify")
        .header("Trust-Task", "https://trusttasks.org/spec/audit/verify/0.1")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (_, verify_body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;

    assert_eq!(
        verify_body["head"].as_str().unwrap(),
        newest,
        "audit/verify head and audit/list entryHash must agree"
    );
}

#[tokio::test]
async fn action_filter_is_actually_applied() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 3).await;

    let (status, body) = list(&fix, &token, "action=CommunityProfileUpdated").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["entries"].as_array().unwrap().is_empty());

    // A filter that matches nothing must return nothing — not the
    // unfiltered log.
    let (status, body) = list(&fix, &token, "action=NoSuchEvent").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["entries"].as_array().unwrap().is_empty(),
        "an unmatched action filter must not fall back to everything: {body}"
    );
    assert_eq!(body["truncated"], false);
    assert!(body.get("cursor").is_none() || body["cursor"].is_null());
}

#[tokio::test]
async fn actor_filter_is_actually_applied() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 2).await;

    let (_, body) = list(&fix, &token, "actor=did:key:z6MkAdmin").await;
    assert!(!body["entries"].as_array().unwrap().is_empty());

    let (_, body) = list(&fix, &token, "actor=did:key:z6MkSomeoneElse").await;
    assert!(
        body["entries"].as_array().unwrap().is_empty(),
        "unmatched actor filter must return nothing: {body}"
    );
}

#[tokio::test]
async fn time_window_filters_are_applied() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 2).await;

    // Everything was written just now, so a window that closes in the
    // past must be empty and one that opens in the past must not be.
    let (_, past) = list(&fix, &token, "to=2000-01-01T00:00:00Z").await;
    assert!(
        past["entries"].as_array().unwrap().is_empty(),
        "`to` in the far past should exclude everything: {past}"
    );

    let (_, since) = list(&fix, &token, "from=2000-01-01T00:00:00Z").await;
    assert!(!since["entries"].as_array().unwrap().is_empty());
}

/// Canonical defines `outcome` and `contextId`; VTC tracks neither.
/// Accepting them silently would hand back unfiltered rows to a caller
/// who believes they filtered.
#[tokio::test]
async fn unsupported_filters_are_refused_not_ignored() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 1).await;

    for q in ["outcome=denied", "contextId=ctx-1"] {
        let (status, body) = list(&fix, &token, q).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{q} must be refused, got {status}: {body}"
        );
        // The refusal has to name the offending filter, or an operator
        // cannot tell which of their filters this maintainer dropped.
        let msg = body["error"].as_str().unwrap_or_default();
        let named = q.split('=').next().unwrap();
        assert!(msg.contains(named), "error should name `{named}`: {body}");
    }
}

/// Canonical: "A consumer that supplies a `cursor` MUST NOT also change
/// the filters, which are bound into the cursor's position." Changing
/// them mid-pagination would silently skip entries.
#[tokio::test]
async fn a_cursor_cannot_be_replayed_under_different_filters() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 4).await;

    // Page 1 of 2, filtered.
    let (status, page1) = list(&fix, &token, "action=CommunityProfileUpdated&pageSize=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page1["truncated"], true, "expected more pages: {page1}");
    let cursor = page1["cursor"].as_str().expect("cursor").to_string();

    // Same filters → resumes.
    let (status, page2) = list(
        &fix,
        &token,
        &format!("action=CommunityProfileUpdated&pageSize=1&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "same filters must resume: {page2}");

    // Different filters, same cursor → rejected.
    let (status, body) = list(
        &fix,
        &token,
        &format!("action=MemberAdded&pageSize=1&cursor={cursor}"),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a cursor must not carry across a filter change: {body}"
    );

    // Dropping the filter entirely is also a change.
    let (status, body) = list(&fix, &token, &format!("pageSize=1&cursor={cursor}")).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "dropping the filter must invalidate the cursor: {body}"
    );
}

#[tokio::test]
async fn truncated_reflects_matching_entries_not_raw_rows() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed(&fix, &token, 3).await;

    // A filter matching nothing, with rows still unread behind the
    // page: `truncated` must be false, or the caller pages forever
    // into an empty tail believing results were withheld.
    let (_, body) = list(&fix, &token, "action=NoSuchEvent&pageSize=1").await;
    assert_eq!(body["truncated"], false, "{body}");
}

#[tokio::test]
async fn non_super_admin_is_refused() {
    let fix = build().await;
    let token = fix.vtc.token("did:key:z6MkReader", "reader", vec![]).await;
    let (status, _) = list(&fix, &token, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
