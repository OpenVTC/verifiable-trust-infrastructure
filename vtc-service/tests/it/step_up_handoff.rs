//! The step-up hand-off — `auth/step-up/requests/show/0.1`, VTI-LNK-125 –
//! VTI-LNK-131.
//!
//! A key the subject delegated (an assistant's, here a console key) is refused
//! a gated act with the step-up inline and a single-use handle beside it. The
//! subject's wallet reads the handle with a fresh `did:key`, gets the request
//! as a document this community signs to the subject plus the operation as
//! received, answers as the subject, and the delegated key's identical resend
//! goes through.

use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::VtcRole;
use vtc_service::test_support::TestVtc;

use crate::common::signed::{call, error_code, party_with_role, payload, post, signed_to};

const RP_ORIGIN: &str = "https://vtc.example.com";
const INVITE: &str = "https://trusttasks.org/spec/auth/step-up/approver/invite/0.2";
const ATTEST: &str = "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1";
const APPROVE: &str = "https://trusttasks.org/spec/auth/step-up/approve-response/0.7";
const APPROVE_REQUEST: &str = "https://trusttasks.org/spec/auth/step-up/approve-request/0.5";
const SHOW: &str = "https://trusttasks.org/spec/auth/step-up/requests/show/0.1";
const NOT_FOUND: &str = "auth/step-up/requests/show:notFound";

async fn vtc() -> TestVtc {
    TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_audit(true)
        .with_signers(true)
        .build()
        .await
}

async fn vtc_did(vtc: &TestVtc) -> String {
    vtc.state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .expect("the test VTC has a DID")
}

/// An administrator with a step-up approver, and a console key delegated to act
/// for them — the shape of an assistant over `vtc-mcp`.
async fn delegated_admin(vtc: &TestVtc) -> (Party, Party, Party) {
    let admin = party_with_role(vtc, VtcRole::Admin, &[]).await;
    let approver = Party::new();
    vtc_service::acl::approver::bind_for_test(&vtc.state, &admin.did, &approver.did)
        .await
        .unwrap();
    let delegated = Party::new();
    let now = chrono::Utc::now();
    vtc_service::acl::console_key::store_delegation(
        &vtc.state.console_keys_ks,
        &vtc_service::acl::console_key::ConsoleKeyDelegation {
            console_did: delegated.did.clone(),
            admin_did: admin.did.clone(),
            scope: vtc_service::acl::console_key::DelegationScope::Console,
            label: Some("assistant".into()),
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        },
    )
    .await
    .unwrap();
    (admin, approver, delegated)
}

/// `reader`'s `requests/show` for `handle`, carrying the handle as
/// `parentThreadId` too (VTI-LNK-054).
async fn show(vtc: &TestVtc, reader: &Party, handle: &str) -> Value {
    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        SHOW,
        json!({ "handle": handle }),
        &reader.did,
        &vtc_did(vtc).await,
    )
    .unwrap();
    doc.parent_thread_id = Some(handle.to_string());
    let key =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&reader.did, &reader.secret_multibase)
            .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    post(vtc, &serde_json::to_value(doc).unwrap()).await.1
}

/// The approver's statement over `request`, carried in the approve-response
/// the subject signs.
async fn approve(vtc: &TestVtc, subject: &Party, approver: &Party, request: &Value) -> Value {
    let audience = vtc_did(vtc).await;
    let statement = signed_to(
        approver,
        &audience,
        ATTEST,
        json!({
            "purpose": "stepUp",
            "subject": subject.did,
            "audience": audience,
            "challenge": request["challenge"],
            "boundTo": request["boundTo"],
        }),
    )
    .await;
    call(
        vtc,
        subject,
        APPROVE,
        json!({
            "subject": request["subject"],
            "challenge": request["challenge"],
            "decision": "approved",
            "evidence": { "kind": "approverSigned", "statement": statement },
        }),
    )
    .await
    .1
}

#[tokio::test]
async fn vti_lnk_130_a_delegated_keys_step_up_is_answered_from_the_subjects_wallet() {
    let vtc = vtc().await;
    let community = vtc_did(&vtc).await;
    let (admin, approver, delegated) = delegated_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let op_payload = json!({ "subject": member.did });
    let doc = signed_to(&delegated, &community, INVITE, op_payload.clone()).await;

    // Refused, with the step-up inline and the hand-off beside it.
    let (_, first) = post(&vtc, &doc).await;
    assert_eq!(error_code(&first), Some("permissionDenied"), "{first}");
    let details = &first["payload"]["details"];
    let inline = details["stepUpRequest"].clone();
    let handoff = details["stepUpHandoff"].clone();
    assert_eq!(handoff["show"], SHOW, "{details}");
    let handle = handoff["handle"].as_str().expect("a handle").to_string();
    assert_eq!(handle.len(), 22, "a 16-byte handle (VTI-LNK-126)");
    assert!(handoff["expiresAt"].is_string());

    // The wallet reads it with a key made for this exchange.
    let reader = Party::new();
    let shown = show(&vtc, &reader, &handle).await;
    assert!(error_code(&shown).is_none(), "{shown}");
    let request_doc = &payload(&shown)["request"];
    assert_eq!(request_doc["type"], APPROVE_REQUEST);
    assert_eq!(request_doc["issuer"], community);
    assert_eq!(
        request_doc["recipient"], admin.did,
        "addressed to the subject"
    );
    assert_eq!(request_doc["payload"], inline, "the request given inline");
    assert!(
        request_doc["proof"]["verificationMethod"]
            .as_str()
            .is_some_and(|vm| vm.starts_with(&format!("{community}#"))),
        "signed by the community: {request_doc}"
    );
    let operation = &payload(&shown)["operation"];
    assert_eq!(operation["type"], INVITE);
    assert_eq!(
        operation["payload"], op_payload,
        "the operation as received"
    );

    // The wallet can recompute the binding from what it was shown.
    let recomputed = vtc_service::acl::bound_step_up::wire_digest(
        operation["type"].as_str().unwrap(),
        &operation["payload"],
        inline["challenge"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(json!(recomputed), inline["boundTo"]);

    // Read once (consumer item 1).
    let again = show(&vtc, &Party::new(), &handle).await;
    assert_eq!(error_code(&again), Some(NOT_FOUND), "{again}");

    // The subject answers; the delegated key's identical resend goes through.
    let ack = approve(&vtc, &admin, &approver, &request_doc["payload"]).await;
    assert_eq!(payload(&ack)["status"], "recorded", "{ack}");
    let (_, done) = post(&vtc, &doc).await;
    assert!(error_code(&done).is_none(), "{done}");
    assert!(payload(&done)["claimCode"].is_string(), "{done}");
}

#[tokio::test]
async fn vti_lnk_126_every_handle_that_answers_nothing_gets_the_same_refusal() {
    let vtc = vtc().await;
    let community = vtc_did(&vtc).await;
    let (admin, approver, delegated) = delegated_admin(&vtc).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;

    // Never minted.
    let unknown = show(&vtc, &Party::new(), "AAAAAAAAAAAAAAAAAAAAAA").await;
    assert_eq!(error_code(&unknown), Some(NOT_FOUND), "{unknown}");

    // Minted, but its step-up answered before anyone read it.
    let doc = signed_to(
        &delegated,
        &community,
        INVITE,
        json!({ "subject": member.did }),
    )
    .await;
    let (_, first) = post(&vtc, &doc).await;
    let inline = first["payload"]["details"]["stepUpRequest"].clone();
    let handle = first["payload"]["details"]["stepUpHandoff"]["handle"]
        .as_str()
        .unwrap()
        .to_string();
    let ack = approve(&vtc, &admin, &approver, &inline).await;
    assert_eq!(payload(&ack)["status"], "recorded", "{ack}");
    let settled = show(&vtc, &Party::new(), &handle).await;
    assert_eq!(error_code(&settled), Some(NOT_FOUND), "{settled}");
    assert_eq!(settled["payload"]["message"], unknown["payload"]["message"]);
}

#[tokio::test]
async fn no_hand_off_where_only_a_passkey_could_answer() {
    let vtc = vtc().await;
    // An administrator with neither an approver nor a passkey is refused
    // without a ceremony at all; one with only approvers gets a hand-off
    // (above). The enrolment step-up never carries one: it reaches only its
    // requester.
    let admin = party_with_role(&vtc, VtcRole::Admin, &[]).await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let doc = signed_to(
        &admin,
        &vtc_did(&vtc).await,
        INVITE,
        json!({ "subject": member.did }),
    )
    .await;
    let (_, first) = post(&vtc, &doc).await;
    assert!(
        first["payload"]["details"].get("stepUpHandoff").is_none(),
        "{first}"
    );
}
