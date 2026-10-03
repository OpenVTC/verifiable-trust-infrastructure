//! A step-up passkey change notice actually reaches the member, over a real
//! mediator (`spec/vtc/members/step-up-passkey-notice/0.1`).
//!
//! What this pins that the unit tests
//! (`ceremony::step_up_passkey_notice::tests`) cannot: those assert the
//! payload shape and that it validates against the published schema. They say
//! nothing about whether the notice can *leave* — whether it is signed with a
//! key the member can check, packed in the envelope type a conformant peer
//! accepts, and whether `by` actually distinguishes an administrator's
//! invite/revoke from the member's own.
//!
//! Requires `--features transport-harness`; CI runs it.

#![cfg(feature = "transport-harness")]

use std::time::Duration;

use serde_json::{Value, json};
use trust_tasks_rs::specs::auth::passkey::enroll::invite::v0_2 as invite;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::finish::v0_1 as redeem_finish;
use trust_tasks_rs::specs::auth::passkey::enroll::redeem::start::v0_1 as redeem_start;
use trust_tasks_rs::specs::auth::passkey::revoke::finish::v0_2 as revoke_finish;
use trust_tasks_rs::specs::auth::passkey::revoke::start::v0_2 as revoke_start;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::step_up_passkey;
use vtc_service::test_support::MockVtcTransport;

use crate::common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.test";
const WAIT: Duration = Duration::from_secs(20);
const NOTICE_TYPE: &str = "https://trusttasks.org/spec/vtc/members/step-up-passkey-notice/0.1";

async fn seed(mock: &MockVtcTransport, did: &str, role: VtcRole) {
    store_acl_entry(
        &mock.vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            admin: role.implied_authority(),
            delegated_by: None,
            role,
            label: None,
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed ACL row");
}

/// A webauthn-rs result as the browser's published JSON.
fn published(v: impl serde::Serialize) -> Value {
    fn strip_nulls(v: &mut Value) {
        if let Value::Object(map) = v {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(strip_nulls);
        }
    }
    let mut v = serde_json::to_value(v).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("extensions");
    obj.insert("clientExtensionResults".into(), json!({}));
    strip_nulls(&mut v);
    v
}

fn payload_of(doc: &Value) -> &Value {
    doc.get("payload").expect("notice carries a payload")
}

/// An administrator's invite, redeemed by `member_did`, driving the real
/// business logic directly (as `crate::step_up_passkey_tasks::dispatch` would
/// after verifying the signed document's proof — proof verification is
/// covered elsewhere). Returns the bound credential's hex id and the soft
/// authenticator holding its key, for a later revoke.
async fn enrol(
    mock: &MockVtcTransport,
    member_did: &str,
    admin_did: &str,
) -> (String, SoftEd25519Authenticator) {
    let invite_payload: invite::Payload =
        serde_json::from_value(json!({ "subject": member_did, "purpose": "stepUp" })).unwrap();
    let issued = step_up_passkey::issue_invite(&mock.vtc.state, admin_did, &invite_payload)
        .await
        .expect("issue the invite");

    let start_payload: redeem_start::Payload = serde_json::from_value(json!({
        "token": String::from(issued.invite.token),
        "claimCode": String::from(issued.claim_code),
    }))
    .unwrap();
    let started = step_up_passkey::redeem_start(&mock.vtc.state, member_did, &start_payload)
        .await
        .expect("redeem start");
    let started = serde_json::to_value(&started).unwrap();

    let mut key = SoftEd25519Authenticator::new();
    let ccr: CreationChallengeResponse =
        serde_json::from_value(json!({ "publicKey": started["options"] })).unwrap();
    let (cred, _) = key.register(&ccr, RP_ORIGIN);

    let finish_payload: redeem_finish::Payload = serde_json::from_value(json!({
        "enrollmentId": started["enrollmentId"],
        "credential": published(&cred),
    }))
    .unwrap();
    let finished =
        step_up_passkey::redeem_finish(&mock.vtc.state, Some(member_did), &finish_payload)
            .await
            .expect("redeem finish");

    (String::from(finished.credential_id), key)
}

#[tokio::test]
async fn enrolling_for_a_member_notifies_them_with_by_the_admin() {
    let mock = MockVtcTransport::start().await;
    let member = mock.connect_registry_peer().await;
    let member_did = member.did().to_string();
    let admin_did = "did:key:zEnrolNoticeAdmin";
    seed(&mock, &member_did, VtcRole::Member).await;
    seed(&mock, admin_did, VtcRole::Admin).await;

    enrol(&mock, &member_did, admin_did).await;

    let doc = member
        .next_trust_task(WAIT)
        .await
        .expect("the enrol notice reached the member");
    assert_eq!(doc.get("type").and_then(Value::as_str), Some(NOTICE_TYPE));
    assert_eq!(
        doc.get("issuer").and_then(Value::as_str),
        Some(mock.vtc_did()),
        "issued by the community"
    );
    let p = payload_of(&doc);
    assert_eq!(p.get("event").and_then(Value::as_str), Some("enrolled"));
    assert_eq!(
        p.get("did").and_then(Value::as_str),
        Some(member_did.as_str())
    );
    assert_eq!(
        p.get("by").and_then(Value::as_str),
        Some(admin_did),
        "an invite is always an administrator acting — the takeover-prompt signal"
    );
    assert!(
        doc.get("proof").is_some(),
        "signed, so the member can show it to somebody else"
    );

    member.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn a_self_revoke_notifies_the_member_with_by_themselves() {
    let mock = MockVtcTransport::start().await;
    let member = mock.connect_registry_peer().await;
    let member_did = member.did().to_string();
    let admin_did = "did:key:zSelfRevokeNoticeAdmin";
    seed(&mock, &member_did, VtcRole::Member).await;
    seed(&mock, admin_did, VtcRole::Admin).await;

    let (credential_id, mut key) = enrol(&mock, &member_did, admin_did).await;
    // Consume the enrol notice so it cannot be mistaken for the revoke one.
    member
        .next_trust_task(WAIT)
        .await
        .expect("the enrol notice reached the member");

    let start_payload: revoke_start::Payload =
        serde_json::from_value(json!({ "credentialId": credential_id })).unwrap();
    let started = step_up_passkey::revoke_start(&mock.vtc.state, &member_did, &start_payload)
        .await
        .expect("revoke start");
    let started = serde_json::to_value(&started).unwrap();
    let rcr: RequestChallengeResponse =
        serde_json::from_value(json!({ "publicKey": started["uvOptions"] })).unwrap();
    let assertion = key.authenticate(&rcr, RP_ORIGIN);

    let finish_payload: revoke_finish::Payload = serde_json::from_value(json!({
        "revocationId": started["revocationId"],
        "uvCredential": published(&assertion),
    }))
    .unwrap();
    step_up_passkey::revoke_finish(&mock.vtc.state, &member_did, &finish_payload)
        .await
        .expect("self-revoke succeeds");

    let doc = member
        .next_trust_task(WAIT)
        .await
        .expect("the revoke notice reached the member");
    let p = payload_of(&doc);
    assert_eq!(p.get("event").and_then(Value::as_str), Some("revoked"));
    assert_eq!(
        p.get("did").and_then(Value::as_str),
        Some(member_did.as_str())
    );
    assert_eq!(
        p.get("by").and_then(Value::as_str),
        Some(member_did.as_str()),
        "a self-revoke: by equals did, so the recipient recognises their own action"
    );

    member.shutdown().await;
    mock.shutdown().await;
}

/// The notice could not even be built — no VTC DID configured to sign and
/// issue it as. That must not be confused with the revoke itself failing: the
/// credential is already gone and durable, and the member just finds out
/// about it late (or from the admin console) rather than not at all.
#[tokio::test]
async fn a_notice_that_cannot_be_queued_does_not_block_the_revoke() {
    let mock = MockVtcTransport::start().await;
    let member = mock.connect_registry_peer().await;
    let member_did = member.did().to_string();
    let admin_did = "did:key:zBrokenNoticeAdmin";
    seed(&mock, &member_did, VtcRole::Member).await;
    seed(&mock, admin_did, VtcRole::Admin).await;

    let (credential_id, mut key) = enrol(&mock, &member_did, admin_did).await;
    member
        .next_trust_task(WAIT)
        .await
        .expect("the enrol notice reached the member");

    let start_payload: revoke_start::Payload =
        serde_json::from_value(json!({ "credentialId": credential_id.clone() })).unwrap();
    let started = step_up_passkey::revoke_start(&mock.vtc.state, &member_did, &start_payload)
        .await
        .expect("revoke start");
    let started = serde_json::to_value(&started).unwrap();
    let rcr: RequestChallengeResponse =
        serde_json::from_value(json!({ "publicKey": started["uvOptions"] })).unwrap();
    let assertion = key.authenticate(&rcr, RP_ORIGIN);

    // Break the one thing `step_up_passkey_notice::try_send` needs before it
    // can build anything to queue: no VTC DID to issue the notice as.
    mock.vtc.state.config.write().await.vtc_did = None;

    let finish_payload: revoke_finish::Payload = serde_json::from_value(json!({
        "revocationId": started["revocationId"],
        "uvCredential": published(&assertion),
    }))
    .unwrap();
    let finished = step_up_passkey::revoke_finish(&mock.vtc.state, &member_did, &finish_payload)
        .await
        .expect("the revoke itself still succeeds — a notice problem is not a revoke problem");
    assert_eq!(String::from(finished.credential_id), credential_id);

    let stray = member.next_trust_task(Duration::from_secs(5)).await;
    assert!(
        stray.is_none(),
        "no notice was ever queued, so none arrives: {stray:?}"
    );

    member.shutdown().await;
    mock.shutdown().await;
}
