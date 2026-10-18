//! The community theme (`vtc/community/theme/{show,update}/0.1`): read by
//! anyone, written by an administrator, checked against the theme profile,
//! with a dry run that stores nothing.

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::common::signed::{
    admin, assert_conforms, call, error_code, party_with_role, payload, post, unsigned,
};
use vtc_service::acl::VtcRole;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

const SHOW: &str = "https://trusttasks.org/spec/vtc/community/theme/show/0.1";
const UPDATE: &str = "https://trusttasks.org/spec/vtc/community/theme/update/0.1";
const THEME_UPDATE_ERR_OUTSIDE_PROFILE: &str = "vtc/community/theme/update:outsideProfile";

/// A refusal's declared code.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

async fn vtc() -> TestVtc {
    TestVtc::builder().with_audit(true).build().await
}

/// `theme/show` with no issuer and no proof — how a sign-in page asks, before
/// the visitor has any identity (show item 1).
async fn anonymous_show(vtc: &TestVtc) -> (StatusCode, Value) {
    let recipient = vtc
        .state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| TEST_VTC_DID.to_string());
    let (status, doc) = post(
        vtc,
        &json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": SHOW,
            "recipient": recipient,
            "issuedAt": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "payload": {},
        }),
    )
    .await;
    if status == StatusCode::OK {
        assert_conforms(SHOW, &doc);
    }
    (status, doc)
}

#[tokio::test]
async fn the_theme_is_read_by_anyone_and_empty_until_set() {
    let vtc = vtc().await;
    let (status, doc) = anonymous_show(&vtc).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["stylesheet"], "");
    assert!(payload(&doc).get("updatedAt").is_none(), "{doc}");
}

#[tokio::test]
async fn a_theme_is_checked_dry_run_stored_and_removed() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let css = "/* Forest */\n:root { --brand: #0a7f5c; }";
    let stored = "\n:root { --brand: #0a7f5c; }";

    // A dry run answers what would be stored — comment removed — and stores
    // nothing (update items 4 and 5).
    let (status, doc) = call(
        &vtc,
        &admin,
        UPDATE,
        json!({ "stylesheet": css, "dryRun": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["stylesheet"], stored);
    assert_eq!(payload(&doc)["stored"], false);
    assert!(payload(&doc).get("updatedAt").is_none(), "{doc}");
    assert_eq!(payload(&anonymous_show(&vtc).await.1)["stylesheet"], "");

    // Stored, and read back by anyone.
    let (_, doc) = call(&vtc, &admin, UPDATE, json!({ "stylesheet": css })).await;
    assert_eq!(payload(&doc)["stored"], true, "{doc}");
    assert!(payload(&doc)["updatedAt"].is_string(), "{doc}");
    let (_, shown) = anonymous_show(&vtc).await;
    assert_eq!(payload(&shown)["stylesheet"], stored);
    assert!(payload(&shown)["updatedAt"].is_string(), "{shown}");

    // Storing what is stored changes nothing (item 6).
    let (_, doc) = call(&vtc, &admin, UPDATE, json!({ "stylesheet": css })).await;
    assert_eq!(payload(&doc)["stored"], false, "{doc}");

    // Removed.
    let (_, doc) = call(&vtc, &admin, UPDATE, json!({ "stylesheet": "" })).await;
    assert_eq!(payload(&doc)["stored"], true, "{doc}");
    assert_eq!(payload(&anonymous_show(&vtc).await.1)["stylesheet"], "");
}

#[tokio::test]
async fn a_theme_outside_the_profile_is_refused_where_it_breaks_it() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let (status, doc) = call(
        &vtc,
        &admin,
        UPDATE,
        json!({ "stylesheet": ".card {\n  color: red;\n  display: none;\n}", "dryRun": true }),
    )
    .await;
    assert!(status.is_client_error(), "{status} {doc}");
    assert_eq!(
        tt_error_code(&doc),
        Some(THEME_UPDATE_ERR_OUTSIDE_PROFILE),
        "{doc}"
    );
    let details = &doc["payload"]["details"];
    assert_eq!(
        (&details["line"], &details["column"], &details["rule"]),
        (&json!(3), &json!(3), &json!("P8")),
        "{doc}"
    );
}

#[tokio::test]
async fn only_an_administrator_changes_the_theme() {
    let vtc = vtc().await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (status, doc) = call(
        &vtc,
        &member,
        UPDATE,
        json!({ "stylesheet": "", "dryRun": true }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
    let (status, doc) = post(
        &vtc,
        &unsigned(&member, UPDATE, json!({ "stylesheet": "" })),
    )
    .await;
    assert!(
        status.is_client_error() && error_code(&doc).is_some(),
        "{status} {doc}"
    );
}
