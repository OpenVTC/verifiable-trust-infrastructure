//! Integration coverage for the trust-registry operator surface.
//!
//! `vtc/registry/sync-jobs/{list,retry,discard}/0.1` as signed documents
//! through the full router stack — the document endpoint, the spine, the
//! signer's ACL row, handler, fjall.
//!
//! The eligibility rule is the thing worth pinning. Both this surface and the
//! offline `vtc sync-jobs` CLI refuse to move a row the reconciler still owns,
//! and they refuse in *different ways* — the CLI prints and skips, retry
//! reports a `skipped` entry, discard returns 409 — so a shared unit test
//! cannot cover it. These are the wire-level half.

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};

use common::signed::{admin, call, error_code, party_with_role};
use vtc_service::acl::VtcRole;

use vtc_service::registry::{SyncJob, SyncJobKind, SyncJobState, get_sync_job, store_sync_job};
use vtc_service::test_support::TestVtc;

const LIST: &str = "https://trusttasks.org/spec/vtc/registry/sync-jobs/list/0.1";
const RETRY: &str = "https://trusttasks.org/spec/vtc/registry/sync-jobs/retry/0.1";
const DISCARD: &str = "https://trusttasks.org/spec/vtc/registry/sync-jobs/discard/0.1";

/// `task` signed by an unrestricted administrator: the reply's status and
/// `payload` — the `#response` payload, or the `trust-task-error` one.
async fn send(vtc: &TestVtc, task: &str, payload: Value) -> (StatusCode, Value) {
    let admin = admin(vtc).await;
    let (status, doc) = call(vtc, &admin, task, payload).await;
    (status, doc["payload"].clone())
}

fn failed(kind: SyncJobKind, did: &str) -> SyncJob {
    let mut job = SyncJob::fresh(kind, did);
    job.state = SyncJobState::Failed;
    job.attempts = 17;
    job.last_attempted_at = Some(chrono::Utc::now());
    job.last_error = Some("registry rejected registry/record/put: unsupportedType".into());
    job
}

/// A failed job lists with the member DID in the clear and no `nextAttemptAt`
/// — the spec forbids giving a terminal row a schedule it does not have, and
/// the stored row keeps a stale one from its last backoff.
#[tokio::test]
async fn a_failed_job_lists_without_claiming_a_next_attempt() {
    let vtc = TestVtc::builder().build().await;

    let mut job = failed(SyncJobKind::PublishMember, "did:key:z6MkStranded");
    job.next_attempt_at = chrono::Utc::now() + chrono::Duration::days(1);
    store_sync_job(&vtc.state.sync_queue_ks, &job)
        .await
        .unwrap();

    let (status, v) = send(&vtc, LIST, json!({ "state": "failed" })).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let items = v["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["memberDid"], "did:key:z6MkStranded");
    assert_eq!(items[0]["state"], "failed");
    assert_eq!(items[0]["kind"], "publishMember");
    assert!(
        items[0].get("nextAttemptAt").is_none(),
        "a failed job must not claim a schedule: {v}"
    );
    assert!(items[0]["purgeDueAt"].is_string(), "{v}");
}

/// Retry moves a failed row and the reconciler will dispatch it: the attempt
/// budget resets and the error clears, which is what `is_dispatchable` reads.
#[tokio::test]
async fn retry_requeues_a_failed_job() {
    let vtc = TestVtc::builder().build().await;

    let job = failed(SyncJobKind::PublishMember, "did:key:z6MkStranded");
    store_sync_job(&vtc.state.sync_queue_ks, &job)
        .await
        .unwrap();

    let (status, v) = send(&vtc, RETRY, json!({ "jobId": job.id.to_string() })).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["requeued"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["requeued"][0]["memberDid"], "did:key:z6MkStranded");
    assert!(v["skipped"].as_array().unwrap().is_empty(), "{v}");

    let back = get_sync_job(&vtc.state.sync_queue_ks, job.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.state, SyncJobState::Pending);
    assert_eq!(back.attempts, 0);
    assert!(back.is_dispatchable(chrono::Utc::now()));
}

/// A job the reconciler still owns is reported, not moved — and not raised as
/// an error, so one ineligible row cannot defeat a bulk retry.
#[tokio::test]
async fn retry_reports_a_live_job_as_skipped_rather_than_failing() {
    let vtc = TestVtc::builder().build().await;

    let mut live = SyncJob::fresh(SyncJobKind::UpdateMember, "did:key:z6MkBusy");
    live.state = SyncJobState::InFlight;
    live.attempts = 3;
    store_sync_job(&vtc.state.sync_queue_ks, &live)
        .await
        .unwrap();

    let (status, v) = send(&vtc, RETRY, json!({ "jobId": live.id.to_string() })).await;
    assert_eq!(status, StatusCode::OK, "reported, not an error: {v}");
    assert!(v["requeued"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(v["skipped"][0]["reason"], "notFailed", "{v}");

    let back = get_sync_job(&vtc.state.sync_queue_ks, live.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.attempts, 3, "untouched");
    assert_eq!(back.state, SyncJobState::InFlight);
}

/// A job that vanished between the operator reading the list and pressing the
/// button is `notFound` — an ordinary race, not a failure.
#[tokio::test]
async fn retry_reports_an_unknown_job_as_not_found() {
    let vtc = TestVtc::builder().build().await;

    let (status, v) = send(
        &vtc,
        RETRY,
        json!({ "jobId": uuid::Uuid::new_v4().to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["skipped"][0]["reason"], "notFound", "{v}");
}

/// `allFailed` moves every terminal row and leaves live ones alone.
#[tokio::test]
async fn retry_all_failed_moves_only_terminal_rows() {
    let vtc = TestVtc::builder().build().await;

    for i in 0..3 {
        let job = failed(SyncJobKind::PublishMember, &format!("did:key:z6MkDead{i}"));
        store_sync_job(&vtc.state.sync_queue_ks, &job)
            .await
            .unwrap();
    }
    let live = SyncJob::fresh(SyncJobKind::UpdateMember, "did:key:z6MkBusy");
    store_sync_job(&vtc.state.sync_queue_ks, &live)
        .await
        .unwrap();

    let (status, v) = send(&vtc, RETRY, json!({ "allFailed": true })).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["requeued"].as_array().unwrap().len(), 3, "{v}");
    assert!(v["skipped"].as_array().unwrap().is_empty(), "{v}");

    let back = get_sync_job(&vtc.state.sync_queue_ks, live.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.attempts, 0, "the pending row was never a target");
    assert_eq!(back.state, SyncJobState::Pending);
}

/// Neither member is a well-formed request. The schema's `oneOf` is what stops
/// a client that dropped `jobId` from silently performing a bulk retry, so an
/// empty payload must be refused rather than defaulted.
#[tokio::test]
async fn retry_refuses_a_payload_naming_neither_target() {
    let vtc = TestVtc::builder().build().await;

    let job = failed(SyncJobKind::PublishMember, "did:key:z6MkStranded");
    store_sync_job(&vtc.state.sync_queue_ks, &job)
        .await
        .unwrap();

    let (_, v) = send(&vtc, RETRY, json!({})).await;
    assert_eq!(
        v["code"], "malformedRequest",
        "an empty payload must not be readable as 'retry everything': {v}"
    );

    let back = get_sync_job(&vtc.state.sync_queue_ks, job.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.state, SyncJobState::Failed, "nothing moved");
}

/// Discard deletes a terminal row and names the member it cost.
#[tokio::test]
async fn discard_deletes_a_failed_job_and_names_the_member() {
    let vtc = TestVtc::builder().build().await;

    let job = failed(SyncJobKind::PublishMember, "did:key:z6MkStranded");
    store_sync_job(&vtc.state.sync_queue_ks, &job)
        .await
        .unwrap();

    let (status, v) = send(&vtc, DISCARD, json!({ "jobId": job.id.to_string() })).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["memberDid"], "did:key:z6MkStranded", "{v}");

    assert!(
        get_sync_job(&vtc.state.sync_queue_ks, job.id)
            .await
            .unwrap()
            .is_none(),
        "the row is gone",
    );
}

/// Discard refuses anything the reconciler still owns. Unlike retry it raises
/// rather than reports: the request names exactly one job, so there is no
/// partial outcome to describe.
#[tokio::test]
async fn discard_refuses_a_live_job() {
    let vtc = TestVtc::builder().build().await;

    let mut live = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:z6MkBusy");
    live.state = SyncJobState::InFlight;
    store_sync_job(&vtc.state.sync_queue_ks, &live)
        .await
        .unwrap();

    let (_, v) = send(&vtc, DISCARD, json!({ "jobId": live.id.to_string() })).await;
    assert_eq!(v["code"], "taskFailed", "{v}");
    assert_eq!(v["details"]["reason"], "conflict", "{v}");

    assert!(
        get_sync_job(&vtc.state.sync_queue_ks, live.id)
            .await
            .unwrap()
            .is_some(),
        "the row survives",
    );
}

/// The whole surface is admin-gated. It names members in the clear and
/// re-asserts membership to a third party, so a member is not enough.
#[tokio::test]
async fn the_surface_requires_an_admin() {
    let vtc = TestVtc::builder().build().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    for (task, payload) in [(LIST, json!({})), (RETRY, json!({ "allFailed": true }))] {
        let (_, doc) = call(&vtc, &member, task, payload).await;
        assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
    }
}
