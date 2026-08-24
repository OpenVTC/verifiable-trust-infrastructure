//! Integration coverage for `GET /v1/ceremonies`.
//!
//! The route had **no HTTP-level test at all** before #1094, which is how it
//! shipped a top-level array past a published schema that wraps it — the same
//! gap that hid the `endorsements/show` drift in #1093. Exercises the full
//! router stack: Trust-Task header → auth extractor → handler.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::test_support::TestVtc;

const CEREMONIES_TASK: &str = "https://trusttasks.org/spec/vtc/ceremonies/list/0.1";

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

/// The response is `{ceremonies: […]}`, not a bare array.
///
/// Asserts the top level is an *object* and that the array is absent from it,
/// so removing the envelope fails the test rather than passing on a payload
/// that merely contains the right manifests.
#[tokio::test]
async fn list_wraps_the_manifests_in_a_ceremonies_envelope() {
    let vtc = TestVtc::builder().build().await;
    let token = vtc.token("did:key:z6MkAdmin", "admin", vec![]).await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/ceremonies")
        .header("Trust-Task", CEREMONIES_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = body_value(vtc.router.clone().oneshot(req).await.unwrap()).await;

    assert_eq!(status, StatusCode::OK, "got {body}");
    assert!(body.is_object(), "must not be a bare array: {body}");

    let ceremonies = body["ceremonies"]
        .as_array()
        .unwrap_or_else(|| panic!("`ceremonies` must be an array: {body}"));
    let purposes: Vec<&str> = ceremonies
        .iter()
        .map(|c| c["purpose"].as_str().unwrap())
        .collect();
    assert_eq!(purposes, ["directory", "join", "removal", "roleChange"]);
}

/// Unauthenticated callers get nothing — the manifests are admin-UI metadata,
/// not a public surface.
#[tokio::test]
async fn list_requires_a_session() {
    let vtc = TestVtc::builder().build().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/ceremonies")
        .header("Trust-Task", CEREMONIES_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = vtc.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
