//! `did-management/did/register/0.1` — a self-hosted community installs a
//! delivered log for its own DID (Keyring VTI-35), as a signed Trust Task.
//! The verification rules themselves are unit-tested in `did_log_install`;
//! this covers the task: authority, slot, and that an accepted log is what
//! `/.well-known/did.jsonl` then serves.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::prelude::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_client::VtcClient;
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::{MockVtc, TestVtc};
use vti_rooms_dtg::test_support::Party;

const TASK: &str = "https://trusttasks.org/spec/did-management/did/register/0.1";
const HOST: &str = "vtc.example.com";

/// A signed log for `did:webvh:<scid>:vtc.example.com`: genesis plus one
/// entry adding a TSP service — the VTI-35 change.
async fn mint() -> (String, Vec<String>) {
    let (_, key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
    let pk = key.get_public_keymultibase().unwrap();
    let document = json!({
        "id": "{DID}",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "{DID}#key-0", "type": "Multikey", "controller": "{DID}",
            "publicKeyMultibase": pk,
        }],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
    });
    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
        ..Default::default()
    };
    let then = chrono::Utc::now() - chrono::Duration::minutes(10);
    let config = CreateDIDConfig::builder()
        .address(format!("https://{HOST}/"))
        .authorization_key(key.clone())
        .did_document(document)
        .parameters(parameters)
        .version_time(then.fixed_offset())
        .build()
        .unwrap();
    let created = create_did(config).await.unwrap();
    let did = created.did().to_string();
    let mut state = DIDWebVHState::from_log_entries(vec![created.log_entry().clone()]);
    state.validate().unwrap().assert_complete().unwrap();
    let mut doc = state.log_entries().last().unwrap().get_state().clone();
    doc["service"] = json!([{ "id": format!("{did}#tsp"), "type": "TSPTransport",
                              "serviceEndpoint": "did:example:mediator" }]);
    state.update_document(doc, &key).await.unwrap();
    let lines = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect();
    (did, lines)
}

fn log(lines: &[String]) -> String {
    format!("{}\n", lines.join("\n"))
}

async fn vtc_serving(did: &str, served: &str) -> TestVtc {
    let vtc = TestVtc::builder().vtc_did(did).build().await;
    let dir = vtc.data_dir().join("did");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{HOST}.jsonl")), served).unwrap();
    vtc
}

/// The task signed by `from`: `200` and the response payload, or the status
/// the retired route answered the refusal with and its payload.
async fn post(vtc: &TestVtc, from: &Party, body: Value) -> (StatusCode, Value) {
    let (_, doc) = common::signed::call(vtc, from, TASK, body).await;
    let payload = doc["payload"].clone();
    if common::signed::error_code(&doc).is_some() {
        return (common::legacy::legacy_status(&payload), payload);
    }
    (StatusCode::OK, payload)
}

async fn served(vtc: &TestVtc) -> String {
    let res = vtc
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/did.jsonl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

fn register(did_data: &str) -> Value {
    json!({ "path": ".well-known", "method": "webvh", "didData": did_data })
}

/// The VTI-35 case end to end: the new entry is served, with no restart.
#[tokio::test]
async fn a_delivered_extension_is_served() {
    let (did, lines) = mint().await;
    let vtc = vtc_serving(&did, &log(&lines[..1])).await;
    let token = common::signed::admin(&vtc).await;

    let (status, body) = post(&vtc, &token, register(&log(&lines))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["record"]["versionCount"], 2);
    assert_eq!(body["record"]["didId"], did);
    assert_eq!(body["record"]["mnemonic"], ".well-known");
    assert_eq!(served(&vtc).await, log(&lines));

    // Again: idempotent.
    let (status, body) = post(&vtc, &token, register(&log(&lines))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(served(&vtc).await, log(&lines));
}

/// Only a super-admin delivers — and the log still has to verify.
#[tokio::test]
async fn a_non_admin_is_refused() {
    let (did, lines) = mint().await;
    let vtc = vtc_serving(&did, &log(&lines[..1])).await;
    let token = common::signed::party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (status, _) = post(&vtc, &token, register(&log(&lines))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(served(&vtc).await, log(&lines[..1]));
}

/// The served log cannot move backwards.
#[tokio::test]
async fn a_shorter_log_is_a_conflict() {
    let (did, lines) = mint().await;
    let vtc = vtc_serving(&did, &log(&lines)).await;
    let token = common::signed::admin(&vtc).await;
    let (status, body) = post(&vtc, &token, register(&log(&lines[..1]))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(served(&vtc).await, log(&lines));
}

/// One slot: the root the DID resolves at.
#[tokio::test]
async fn another_slot_is_refused() {
    let (did, lines) = mint().await;
    let vtc = vtc_serving(&did, &log(&lines[..1])).await;
    let token = common::signed::admin(&vtc).await;
    let body = json!({ "path": "somewhere", "method": "webvh", "didData": log(&lines) });
    let (status, body) = post(&vtc, &token, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(served(&vtc).await, log(&lines[..1]));
}

/// A community whose DID has a path is published by a DID host; a copy here
/// would never be what resolvers read.
#[tokio::test]
async fn a_hosted_community_is_not_self_hosted() {
    let (_, lines) = mint().await;
    let vtc = TestVtc::builder()
        .vtc_did("did:webvh:QmScid:dids.example.com:community")
        .build()
        .await;
    let token = common::signed::admin(&vtc).await;
    let (status, body) = post(&vtc, &token, register(&log(&lines))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// Over the wire, as `cnm did-log install` does it over HTTPS: a document
/// signed by the operator and addressed to the community's DID (not the
/// VTA's — a VTC refuses that).
#[tokio::test]
async fn vtc_client_authenticates_and_installs() {
    let (did, lines) = mint().await;
    let vtc = vtc_serving(&did, &log(&lines[..1])).await;

    let seed = [0x35u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let admin = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let private_key = multibase::encode(multibase::Base::Base58Btc, &buf);
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: admin.clone(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: 1,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let mock = MockVtc::start_with(vtc).await;
    let base = format!("{}/v1", mock.base_url());
    let key = vtc_client::HolderKey::from_did_key(&admin, &private_key).unwrap();
    let client = VtcClient::with_key(&base, &did, key);
    let payload: vtc_client::did_register::v0_1::Payload =
        serde_json::from_value(register(&log(&lines))).unwrap();
    let response = client.install_did_log(&payload).await.expect("install");
    assert_eq!(response.record.version_count, 2);
    assert_eq!(served(&mock.vtc).await, log(&lines));
    mock.shutdown().await;
}
