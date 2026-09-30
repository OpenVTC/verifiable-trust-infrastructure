//! The document endpoint's size limits, through the real router.
//!
//! Each Trust Task type declares its largest document
//! (`vtc_service::trust_tasks::size`, 64 KiB unless its specification needs
//! more, in force only once the type is served, and only for an issuer with
//! standing). A document over its limit is refused before it is parsed, with a
//! framework `trust-task-error`;
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

/// The HTTPS door buffers no more than the largest limit any served type
/// accepts (`did/register`'s 1 MiB): a body over it is refused before it is
/// buffered, whatever type it claims.
#[tokio::test]
async fn the_https_door_buffers_no_more_than_the_largest_served_type_accepts() {
    let vtc = TestVtc::builder().build().await;
    for (type_uri, len) in [
        (MEMBERS_UPDATE, 1024 * KIB + 1),
        (POLICY_UPSERT, 1024 * KIB + 1),
    ] {
        let (status, _) = post(&vtc, "/v1/trust-tasks", document_of(type_uri, len)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{type_uri} at {len}");
    }
}

/// Below the door's cap the spine decides. A raised type's document from no
/// known issuer — this one names none — is held to the default, and refused
/// for its size before it is parsed further.
#[tokio::test]
async fn a_raised_type_from_no_known_issuer_is_held_to_the_default() {
    let vtc = TestVtc::builder().build().await;
    let (status, doc) = post(
        &vtc,
        "/v1/trust-tasks",
        document_of(POLICY_UPSERT, 128 * KIB),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let payload = &doc.expect("a trust-task-error document")["payload"];
    assert_eq!(payload["code"], "malformedRequest", "{payload}");
    assert_eq!(payload["details"]["maxBytes"], 64 * KIB, "{payload}");
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
///
/// `/v1/auth/challenge`'s dedicated REST mount is gone since #1858
/// (`vta_sdk::auth_light` signs `auth/challenge/0.1` against
/// `POST /v1/trust-tasks` instead); `/v1/auth/refresh` stays — it also renews
/// the admin console's cookie session — and sits on the same `Trust-Task`-
/// gated, governed unauth chain with the same body cap.
#[tokio::test]
async fn the_rest_of_the_unauthenticated_chain_keeps_its_cap() {
    let vtc = TestVtc::builder().build().await;
    let (status, _) = post_with(
        &vtc,
        "/v1/auth/refresh",
        Some("https://trusttasks.org/spec/auth/refresh/0.1"),
        document_of(MEMBERS_UPDATE, 64 * KIB + 1),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
