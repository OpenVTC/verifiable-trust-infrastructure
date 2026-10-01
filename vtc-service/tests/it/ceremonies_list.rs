//! Integration coverage for the signed `vtc/ceremonies/list/0.1` document.
//!
//! The route had **no HTTP-level test at all** before #1094, which is how it
//! shipped a top-level array past a published schema that wraps it — the same
//! gap that hid the `endorsements/show` drift in #1093. Exercises the full
//! router stack: the document endpoint → the spine → the signer's ACL row →
//! handler.


use axum::http::StatusCode;
use serde_json::json;
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{admin, call, error_code, post, unsigned};
use vtc_service::test_support::TestVtc;

const CEREMONIES_TASK: &str = "https://trusttasks.org/spec/vtc/ceremonies/list/0.1";

/// The response is `{ceremonies: […]}`, not a bare array.
///
/// Asserts the top level is an *object* and that the array is absent from it,
/// so removing the envelope fails the test rather than passing on a payload
/// that merely contains the right manifests.
#[tokio::test]
async fn list_wraps_the_manifests_in_a_ceremonies_envelope() {
    let vtc = TestVtc::builder().build().await;
    let admin = admin(&vtc).await;
    let (status, doc) = call(&vtc, &admin, CEREMONIES_TASK, json!({})).await;
    let body = &doc["payload"];

    assert_eq!(status, StatusCode::OK, "got {doc}");
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

/// Callers the community does not know get nothing — the manifests are
/// admin-UI metadata, not a public surface.
#[tokio::test]
async fn list_requires_a_known_signer() {
    let vtc = TestVtc::builder().build().await;
    let (_, doc) = post(&vtc, &unsigned(&Party::new(), CEREMONIES_TASK, json!({}))).await;
    assert_eq!(error_code(&doc), Some("proofRequired"), "{doc}");
    let (_, doc) = call(&vtc, &Party::new(), CEREMONIES_TASK, json!({})).await;
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
}
