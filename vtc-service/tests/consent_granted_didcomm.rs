//! The requester of an unrestricted-admin grant is told, over a real mediator,
//! when another admin's consent comes through (`task-consent/granted/0.1`).
//!
//! The unit and route tests show the consent loop works; they cannot show the
//! notice leaves. A `send` returning `Ok` means only that the mediator took
//! the frame (R1.1), so the only evidence is a peer holding the document.
//!
//! Requires `--features didcomm-harness`; CI runs it.

#![cfg(feature = "didcomm-harness")]

use std::time::Duration;

use serde_json::{Value, json};

use vtc_service::acl::admin_consent::{self, Decided, Operation};
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtcDidcomm;

const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const GRANTED: &str = "https://trusttasks.org/spec/task-consent/granted/0.1";

async fn unrestricted_admin(mock: &MockVtcDidcomm, did: &str) {
    store_acl_entry(
        &mock.vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed admin");
}

/// Once the threshold is met the requester gets a signed notice, threaded on
/// the correlator its refusal carried, naming the digest it is waiting on.
#[tokio::test]
async fn vti_apv_014_the_requester_is_told_when_consent_is_granted() {
    let mock = MockVtcDidcomm::start().await;
    let requester = mock.connect_registry_peer().await;
    let requester_did = requester.did().to_string();
    let approver_did = "did:key:z6MkGrantedNoticeApprover";
    unrestricted_admin(&mock, &requester_did).await;
    unrestricted_admin(&mock, approver_did).await;

    let payload = json!({
        "entry": { "subject": "did:key:z6MkNewAdmin", "role": "admin", "scopes": [] }
    });
    let refusal = match admin_consent::require(
        &mock.vtc.state,
        &requester_did,
        "did:key:z6MkNewAdmin",
        Operation {
            type_uri: GRANT,
            payload: &payload,
        },
        "Make did:key:z6MkNewAdmin an unrestricted administrator",
    )
    .await
    {
        Err(vti_common::error::AppError::ApprovalRequired { details, .. }) => details,
        other => panic!("expected consent to be required, got {other:?}"),
    };

    let decision: trust_tasks_rs::specs::task_consent::decision::v0_1::Payload =
        serde_json::from_value(json!({
            "challenge": refusal["challenge"],
            "payloadDigest": refusal["payloadDigest"],
            "decision": "approve",
        }))
        .expect("decision payload");
    match admin_consent::decide(&mock.vtc.state, approver_did, &decision).await {
        Ok(Decided::Granted { .. }) => {}
        other => panic!("expected a grant, got {other:?}"),
    }

    let doc = requester
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the granted notice reached the requester");
    assert_eq!(
        doc.get("type").and_then(Value::as_str),
        Some(GRANTED),
        "{doc}"
    );
    assert_eq!(
        doc.get("issuer").and_then(Value::as_str),
        Some(mock.vtc_did()),
        "{doc}"
    );
    assert_eq!(
        doc.get("threadId"),
        refusal.get("correlator"),
        "threaded on the correlator the refusal handed out, not on the digest: {doc}"
    );
    let p = doc.get("payload").expect("payload");
    assert_eq!(p["status"], "granted");
    assert_eq!(p["payloadDigest"], refusal["payloadDigest"]);
    assert_eq!(p["taskType"], GRANT);
    assert!(doc.get("proof").is_some(), "signed: {doc}");
}
