//! Integration coverage for `GET /v1/health/diagnostics`.
//!
//! Exercises the full router stack — Trust-Task header → auth
//! extractor → handler → registry storage — through
//! `Router::oneshot`.
//!
//! Phase 3 M3.8.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::registry::{SyncJob, SyncJobKind, SyncJobState, store_sync_job};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const DIAGNOSTICS_TASK: &str = "https://trusttasks.org/openvtc/vtc/health/diagnostics/1.0";

struct Fixture {
    router: axum::Router,
    state: AppState,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

async fn token_for(fix: &Fixture, role: &str) -> String {
    fix.vtc.token("did:key:z6MkAdmin", role, vec![]).await
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

fn get(uri: &str, task: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn diagnostics_empty_queue_reports_zero_counts() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    let resp = fix
        .router
        .clone()
        .oneshot(get("/v1/health/diagnostics", DIAGNOSTICS_TASK, &token))
        .await
        .unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["queue_depth"], 0);
    assert_eq!(v["rtbf_batched_count"], 0);
    assert_eq!(v["failed_count"], 0);
    // Default RegistryHealth state is "degraded" (no successful
    // probe yet).
    assert_eq!(v["registry_status"], "degraded");
    assert!(
        v.get("oldest_pending_age_seconds")
            .is_none_or(|x| x.is_null()),
        "empty queue → no oldest_pending_age"
    );
}

#[tokio::test]
async fn diagnostics_reports_pending_rtbf_and_failed_counts() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    // Pending dispatchable.
    let pending = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zP");
    store_sync_job(&fix.state.sync_queue_ks, &pending)
        .await
        .unwrap();

    // RTBF-batched (future-dated next_attempt_at).
    let mut rtbf = SyncJob::fresh(SyncJobKind::DeleteMember, "did:key:zR");
    rtbf.next_attempt_at = chrono::Utc::now() + chrono::Duration::hours(20);
    rtbf.rtbf_batched = true;
    store_sync_job(&fix.state.sync_queue_ks, &rtbf)
        .await
        .unwrap();

    // Failed (terminal).
    let mut failed = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zF");
    failed.state = SyncJobState::Failed;
    failed.last_error = Some("permanent error from upstream".into());
    store_sync_job(&fix.state.sync_queue_ks, &failed)
        .await
        .unwrap();

    let resp = fix
        .router
        .clone()
        .oneshot(get("/v1/health/diagnostics", DIAGNOSTICS_TASK, &token))
        .await
        .unwrap();
    let (status, v) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Pending (1) + RTBF-pending (1) = queue_depth 2; Failed
    // sits outside the active queue.
    assert_eq!(v["queue_depth"], 2);
    assert_eq!(v["rtbf_batched_count"], 1);
    assert_eq!(v["failed_count"], 1);
    // Pending (dispatchable) job's age is surfaced; RTBF row
    // doesn't count toward "stuck" SLI.
    assert!(v["oldest_pending_age_seconds"].is_number());
}

#[tokio::test]
async fn diagnostics_requires_admin_role() {
    let fix = build().await;
    // `reader` is a valid VTC ACL role but not admin —
    // AdminAuth must reject.
    let reader_token = token_for(&fix, "reader").await;

    let resp = fix
        .router
        .clone()
        .oneshot(get(
            "/v1/health/diagnostics",
            DIAGNOSTICS_TASK,
            &reader_token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin must be rejected"
    );
}

#[tokio::test]
async fn diagnostics_requires_trust_task_header() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/health/diagnostics")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing Trust-Task header must 400"
    );
}
