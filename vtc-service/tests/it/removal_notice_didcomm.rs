//! A removed member is actually told, over a real mediator.
//!
//! What this pins that the unit tests cannot: those assert the payload shape
//! and that it validates against the published schema. They say nothing about
//! whether the notice can *leave* — whether the document is signed with a key
//! the member can check, whether it is packed in the envelope type a conformant
//! peer accepts, and whether it survives the trip through a mediator to a DID
//! that is no longer a member of anything.
//!
//! That last part is the whole feature. A removal notice that a removed member
//! cannot receive is indistinguishable from the silence this replaced, and a
//! `send` returning `Ok` means only that the mediator accepted the frame (R1.1)
//! — so the only thing that demonstrates the feature works is a peer holding
//! the document.
//!
//! Requires `--features didcomm-harness`; CI runs it.

#![cfg(feature = "didcomm-harness")]

use std::time::Duration;

use serde_json::Value;

use vta_sdk::protocols::members::MEMBER_REMOVAL_NOTICE_TYPE;
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::ceremony::{purge_member, remove_inner};
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::MockVtcDidcomm;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Install the workspace default policies, as `server::run` does at boot.
///
/// `remove_inner` consults `removal.rego` and an empty policy set fails closed
/// — which is why the purge test does not need this and the removal ones do:
/// a purge deliberately skips the removal policy.
async fn install_policies(mock: &MockVtcDidcomm) {
    vtc_service::policy::default::install_defaults(
        &mock.vtc.state.policies_ks,
        &mock.vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");
}

/// Seed `did` as a current member with an ACL row, so a removal has something
/// to remove.
async fn seed_member(mock: &MockVtcDidcomm, did: &str, role: VtcRole) {
    let state = &mock.vtc.state;
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed ACL row");
    store_member(&state.members_ks, &Member::fresh(did))
        .await
        .expect("seed member row");
}

/// The notice payload out of a captured trust-task envelope.
fn payload_of(doc: &Value) -> &Value {
    doc.get("payload").expect("notice carries a payload")
}

#[tokio::test]
async fn an_admin_removal_reaches_the_member_signed() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let member = mock.connect_registry_peer().await;
    let member_did = member.did().to_string();
    let admin_did = "did:key:zRemovalAdmin";

    install_policies(&mock).await;
    seed_member(&mock, &member_did, VtcRole::Member).await;
    seed_member(&mock, admin_did, VtcRole::Admin).await;

    remove_inner(
        &mock.vtc.state,
        admin_did,
        &member_did,
        None,
        "Repeated code-of-conduct breach.".to_string(),
    )
    .await
    .expect("admin removal succeeds");

    let doc = member
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the removal notice reached the removed member");

    assert_eq!(
        doc.get("type").and_then(Value::as_str),
        Some(MEMBER_REMOVAL_NOTICE_TYPE),
        "the document inside the envelope is the notice"
    );
    assert_eq!(
        doc.get("issuer").and_then(Value::as_str),
        Some(mock.vtc_did()),
        "issued by the community, so the member knows who removed them"
    );

    let p = payload_of(&doc);
    assert_eq!(
        p.get("did").and_then(Value::as_str),
        Some(member_did.as_str())
    );
    assert_eq!(p.get("code").and_then(Value::as_str), Some("adminRemoved"));
    assert_eq!(
        p.get("decidedBy").and_then(Value::as_str),
        Some(admin_did),
        "names the deciding administrator — 'the community removed you' is unappealable"
    );
    assert_eq!(
        p.get("reason").and_then(Value::as_str),
        Some("Repeated code-of-conduct breach."),
        "the operator's reason reaches the member, not just the audit log"
    );
    assert!(
        p.get("decidedAt").and_then(Value::as_str).is_some(),
        "the decision has to be placeable in time"
    );

    // The point of the proof is that the member can forward this to somebody
    // else. Unsigned, it would evidence nothing once detached from the
    // authcrypt channel that delivered it.
    let proof = doc.get("proof").expect("notice is signed");
    assert_eq!(
        proof.get("type").and_then(Value::as_str),
        Some("DataIntegrityProof")
    );
    assert!(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty()),
        "a proof with no proofValue is not a proof"
    );

    member.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn a_purge_says_it_was_a_purge() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let member = mock.connect_registry_peer().await;
    let member_did = member.did().to_string();
    let super_admin = "did:key:zPurgeSuperAdmin";

    seed_member(&mock, &member_did, VtcRole::Member).await;

    purge_member(&mock.vtc.state, super_admin, &member_did)
        .await
        .expect("purge succeeds");

    let doc = member
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the purge notice reached the purged member");

    let p = payload_of(&doc);
    assert_eq!(
        p.get("code").and_then(Value::as_str),
        Some("purged"),
        "distinguishable from adminRemoved — a purge skipped the removal policy, \
         which changes what recourse the member has"
    );
    assert_eq!(p.get("disposition").and_then(Value::as_str), Some("purge"));
    assert!(
        p.get("reason").is_none(),
        "no reason was given, and an absent reason is not an empty one"
    );

    member.shutdown().await;
    mock.shutdown().await;
}

/// A member who chose to leave already has their receipt. Sending a removal
/// notice as well would tell them they were removed, which is a different and
/// worse thing to be told.
#[tokio::test]
async fn a_self_leave_sends_no_removal_notice() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let member = mock.connect_registry_peer().await;
    let member_did = member.did().to_string();

    install_policies(&mock).await;
    seed_member(&mock, &member_did, VtcRole::Member).await;

    // actor == target: the member removing themselves.
    remove_inner(
        &mock.vtc.state,
        &member_did,
        &member_did,
        None,
        String::new(),
    )
    .await
    .expect("self-leave succeeds");

    // Short window on purpose: this asserts an absence, and a long one only
    // makes the suite slow without making the assertion stronger. The positive
    // tests above establish that a notice sent on this path arrives well inside
    // it, so a timeout here means nothing was sent rather than nothing arrived
    // yet.
    let stray = member.next_trust_task(Duration::from_secs(5)).await;
    assert!(
        stray.is_none(),
        "a self-leave must not produce a removal notice, got: {stray:?}"
    );

    member.shutdown().await;
    mock.shutdown().await;
}
