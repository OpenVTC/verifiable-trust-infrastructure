//! Integration coverage for `GET /v1/audit/verify` — the audit
//! hash-chain verification surface (#537 tier 3).
//!
//! The chain itself is unit-tested in `vti_common::audit::envelope`;
//! what matters here is that the endpoint walks the *store* in the
//! right order, reports honest counters, and actually catches a
//! tampered row rather than rubber-stamping whatever it reads.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const VERIFY_TASK: &str = "https://trusttasks.org/spec/audit/verify/0.1";
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

/// Super-admin = Admin role with empty `allowed_contexts`.
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

async fn verify(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri("/v1/audit/verify")
        .header("Trust-Task", VERIFY_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    body_value(fix.router.clone().oneshot(req).await.unwrap()).await
}

/// Write some real audit envelopes by exercising a route that emits
/// them, so the chain under test is one the daemon actually produced.
async fn seed_audit_rows(fix: &Fixture, token: &str, count: usize) {
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
        assert_eq!(resp.status(), StatusCode::OK, "seed write {i} succeeded");
    }
}

#[tokio::test]
async fn empty_log_verifies_vacuously() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    let (status, body) = verify(&fix, &token).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], true);
    assert_eq!(body["entriesExamined"], 0);
    assert_eq!(body["entriesVerified"], 0);
    // Nothing chainable seen, so there is no head to report.
    assert!(body.get("head").is_none() || body["head"].is_null());
}

#[tokio::test]
async fn a_real_chain_verifies_and_reports_its_head() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], true, "body: {body}");

    let verified = body["entriesVerified"].as_u64().unwrap();
    assert!(
        verified >= 3,
        "at least the three seeded writes: {verified}"
    );
    assert_eq!(
        body["entriesExamined"], body["entriesVerified"],
        "a v2-only store must have nothing skipped"
    );
    assert_eq!(body["legacySkipped"], 0);
    assert_eq!(body["unparseableSkipped"], 0);
    assert!(
        body["head"].as_str().is_some_and(|h| h.len() == 64),
        "head is a hex-encoded SHA-256"
    );
}

#[tokio::test]
async fn a_tampered_envelope_is_caught() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 3).await;

    // Rewrite one stored envelope's payload in place, leaving its
    // `entry_hash` as written — exactly what an adversary editing the
    // store would produce.
    let mut rows = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    let (key, value) = rows.into_iter().next().expect("at least one envelope");
    let mut env: Value = serde_json::from_slice(&value).unwrap();
    env["actorDidPlain"] = json!("did:key:z6MkNotWhoActedAtAll");
    // `actor_did_plain` is excluded from chain_digest (RTBF), so to
    // actually break the digest we must alter a covered field.
    env["timestamp"] = json!("2020-01-01T00:00:00Z");
    fix.state
        .audit_ks
        .insert_raw(key, serde_json::to_vec(&env).unwrap())
        .await
        .unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK, "tamper is a finding, not an error");
    assert_eq!(body["verified"], false, "body: {body}");
    let brk = &body["chainBreak"];
    assert!(!brk.is_null(), "a break must be reported: {body}");
    assert!(
        brk["kind"] == "tamperedEntry" || brk["kind"] == "brokenLink",
        "unexpected break kind: {brk}"
    );
}

#[tokio::test]
async fn a_dropped_envelope_breaks_the_link() {
    let fix = build().await;
    let token = super_admin_token(&fix).await;
    seed_audit_rows(&fix, &token, 4).await;

    // Delete a middle row — the classic "cover my tracks" edit.
    let mut rows = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    assert!(rows.len() >= 3, "need a middle row to drop");
    let (key, _) = rows.remove(rows.len() / 2);
    fix.state.audit_ks.remove(key).await.unwrap();

    let (status, body) = verify(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified"], false, "body: {body}");
    assert_eq!(body["chainBreak"]["kind"], "brokenLink");
}

#[tokio::test]
async fn non_super_admin_is_refused() {
    let fix = build().await;
    // Context-scoped admin: Admin role, but not community-wide.
    let scoped = fix
        .vtc
        .token("did:key:z6MkScoped", "admin", vec!["some-ctx".into()])
        .await;
    let (status, _) = verify(&fix, &scoped).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the audit chain is the community-wide god view"
    );
}
