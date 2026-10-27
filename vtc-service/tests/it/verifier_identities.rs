//! `vtc/oid4vp/identities/list/0.1` on the signed door (#1988): what the
//! console's Wallet verifier page reads.

use axum::http::StatusCode;
use serde_json::json;

use crate::common::signed::{admin, call, error_code, party_with_role};
use vtc_service::acl::VtcRole;
use vtc_service::test_support::{TestVtc, oid4vp_test_eudi_identity, oid4vp_test_identity};

const LIST: &str = "https://trusttasks.org/spec/vtc/oid4vp/identities/list/0.1";

/// An administrator sees each identity, what is wrong with it, and nothing
/// secret; a swiyu identity with no statement and an EUDI one with no
/// certificate are told apart by code.
#[tokio::test]
async fn an_administrator_reads_each_identity_and_its_problems() {
    let swiyu = oid4vp_test_identity("swiyu", 0x51);
    let mut eudi = oid4vp_test_eudi_identity("eudi", 0x52);
    // Installed, its certificate not yet.
    eudi.x5c = None;
    let secret = swiyu.private_key_multibase.clone().unwrap();
    let vtc = TestVtc::builder()
        .with_public_url("https://vtc.example")
        .with_oid4vp_identity(swiyu.clone())
        .with_oid4vp_identity(eudi)
        .build()
        .await;
    let admin = admin(&vtc).await;

    let (status, doc) = call(&vtc, &admin, LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(error_code(&doc), None, "{doc}");
    let payload = &doc["payload"];
    assert!(!doc.to_string().contains(&secret), "never a private key");
    assert_eq!(payload["problems"], json!([]));

    let ids = payload["identities"].as_array().unwrap();
    let by_id = |id: &str| ids.iter().find(|i| i["id"] == id).unwrap();
    let eudi = by_id("eudi");
    assert_eq!(eudi["usable"], false);
    assert_eq!(eudi["problems"][0]["code"], "certificateMissing");
    let swiyu_row = by_id("swiyu");
    assert_eq!(swiyu_row["usable"], true, "{swiyu_row}");
    assert_eq!(
        swiyu_row["isDefault"], true,
        "the only identity with a client id"
    );
    assert_eq!(swiyu_row["custody"], "cached");
    assert_eq!(swiyu_row["problems"][0]["code"], "identityStatementMissing");
    assert_eq!(
        swiyu_row["clientId"],
        format!("decentralized_identifier:{}", swiyu.did.unwrap())
    );
}

/// Without an https public URL no wallet can reach the community: one
/// community-wide problem, and nothing usable.
#[tokio::test]
async fn no_public_url_makes_nothing_usable() {
    let vtc = TestVtc::builder()
        .with_oid4vp_identity(oid4vp_test_identity("swiyu", 0x53))
        .build()
        .await;
    let admin = admin(&vtc).await;
    let (status, doc) = call(&vtc, &admin, LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["payload"]["problems"][0]["code"], "noPublicUrl");
    assert_eq!(doc["payload"]["identities"][0]["usable"], false);
}

/// Consumer rule 1: only the configuration administrators.
#[tokio::test]
async fn a_signer_without_config_admin_is_refused() {
    let vtc = TestVtc::builder().build().await;
    let moderator = party_with_role(&vtc, VtcRole::Moderator, &[]).await;
    let (_, doc) = call(&vtc, &moderator, LIST, json!({})).await;
    assert_eq!(error_code(&doc), Some("permissionDenied"), "{doc}");
}
