//! The document endpoint's size limits, through the real router.
//!
//! Each Trust Task type declares its largest document
//! (`vtc_service::trust_tasks::size`, 64 KiB unless its specification needs
//! more, in force only once the type is served). A document over its type's
//! limit is refused before it is parsed, with a framework `trust-task-error`;
//! the HTTPS door's own body cap is the largest any served type accepts, and
//! the rest of the unauthenticated chain keeps its 64 KiB cap.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use vtc_service::test_support::TestVtc;

const MEMBERS_UPDATE: &str = "https://trusttasks.org/spec/vtc/members/update/0.1";
const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const KIB: usize = 1024;

/// A document of `type_uri`, padded to exactly `len` bytes.
fn document_of(type_uri: &str, len: usize) -> String {
    let head = format!(r#"{{"id":"urn:uuid:size","type":"{type_uri}","payload":{{"pad":""#);
    let tail = r#""}}"#;
    let body = format!("{head}{}{tail}", "x".repeat(len - head.len() - tail.len()));
    assert_eq!(body.len(), len);
    body
}

async fn post(vtc: &TestVtc, uri: &str, body: String) -> (StatusCode, Option<Value>) {
    post_with(vtc, uri, None, body).await
}

async fn post_with(
    vtc: &TestVtc,
    uri: &str,
    task: Option<&str>,
    body: String,
) -> (StatusCode, Option<Value>) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(task) = task {
        req = req.header("Trust-Task", task);
    }
    let req = req.body(Body::from(body)).unwrap();
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).ok())
}

/// No type this build declares a raised limit for is served yet
/// (`policy/upsert`, `did/register`), so the HTTPS door admits no more than the
/// default: a body over it is refused before it is buffered, whatever type it
/// claims. The spine's own refusal — the one TSP and DIDComm meet — is pinned
/// in `trust_tasks::size`.
#[tokio::test]
async fn the_https_door_buffers_no_more_than_the_largest_served_type_accepts() {
    let vtc = TestVtc::builder().build().await;
    for (type_uri, len) in [
        (MEMBERS_UPDATE, 64 * KIB + 1),
        (POLICY_UPSERT, 128 * KIB),
        (MEMBERS_UPDATE, 1024 * KIB + 1),
    ] {
        let (status, _) = post(&vtc, "/v1/trust-tasks", document_of(type_uri, len)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{type_uri} at {len}");
    }
}

#[tokio::test]
async fn a_document_within_the_default_is_not_refused_for_its_size() {
    let vtc = TestVtc::builder().build().await;
    let (_, doc) = post(
        &vtc,
        "/v1/trust-tasks",
        document_of(MEMBERS_UPDATE, 64 * KIB),
    )
    .await;
    let payload = &doc.expect("a trust-task-error document")["payload"];
    assert!(
        payload["details"]["maxBytes"].is_null(),
        "refused for its size: {payload}"
    );
}

/// The document endpoint's raised cap is its own: the other unauthenticated
/// routes keep theirs.
#[tokio::test]
async fn the_rest_of_the_unauthenticated_chain_keeps_its_cap() {
    let vtc = TestVtc::builder().build().await;
    let (status, _) = post_with(
        &vtc,
        "/v1/auth/challenge",
        Some("https://trusttasks.org/spec/auth/challenge/0.1"),
        document_of(MEMBERS_UPDATE, 64 * KIB + 1),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
