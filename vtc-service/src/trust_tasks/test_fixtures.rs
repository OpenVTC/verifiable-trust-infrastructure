//! The signed-document fixtures the trust-task tests share (#2579).
//!
//! Every family's tests build, sign and dispatch documents the same way, so
//! they do it with these rather than each module keeping its own copy — two
//! harnesses for one binding would diverge, and the first thing to drift would
//! be what "signed" means. Hoisted out of `members_admin_tests`, where they
//! were first written and from which nine other test modules imported them.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_rooms_dtg::test_support::Party;
use vti_trust_task_server::TrustTaskOutcome;

use crate::acl::{VtcRole, store_acl_entry};
use crate::test_support::{TEST_VTC_DID, TestVtc, seeded_acl_entry};
use crate::trust_tasks::{JoinAuthCtx, dispatch_trust_task_core};

pub(crate) async fn seed_acl(vtc: &TestVtc, did: &str, role: VtcRole, contexts: Vec<String>) {
    let admin = crate::acl::legacy_seed_authority(&role, &contexts);
    store_acl_entry(&vtc.state.acl_ks, &seeded_acl_entry(did, role, admin))
        .await
        .expect("seed ACL row");
}

/// The document as a real producer builds it — `issuer`, `recipient` and
/// `issuedAt` set by the SDK's own builder — but unsigned.
pub(crate) fn unsigned(from: &Party, type_uri: &str, payload: Value) -> TrustTask<Value> {
    vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, TEST_VTC_DID)
        .expect("build the document")
}

pub(crate) async fn sign(from: &Party, mut doc: TrustTask<Value>) -> TrustTask<Value> {
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .expect("a did:key names its own verification method");
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .expect("sign the document");
    doc
}

pub(crate) async fn signed(from: &Party, type_uri: &str, payload: Value) -> TrustTask<Value> {
    sign(from, unsigned(from, type_uri, payload)).await
}

pub(crate) async fn dispatch(vtc: &TestVtc, doc: &TrustTask<Value>) -> TrustTaskOutcome {
    let body = serde_json::to_vec(doc).expect("a document serialises");
    dispatch_trust_task_core(&vtc.state, &JoinAuthCtx::rest(), &body).await
}

/// As [`dispatch`], delivered over DIDComm with the document's issuer as
/// the authcrypt sender — for the tasks served only end to end.
pub(crate) async fn dispatch_didcomm(vtc: &TestVtc, doc: &TrustTask<Value>) -> TrustTaskOutcome {
    let body = serde_json::to_vec(doc).expect("a document serialises");
    let sender = doc
        .issuer
        .clone()
        .expect("the test document names its issuer");
    dispatch_trust_task_core(&vtc.state, &JoinAuthCtx::didcomm(sender), &body).await
}

pub(crate) fn body_of(out: &TrustTaskOutcome) -> Value {
    serde_json::from_slice(&out.body).unwrap_or(Value::Null)
}

/// The `code` of a `trust-task-error` reply, or `None` when the reply is a
/// success document.
pub(crate) fn error_code(out: &TrustTaskOutcome) -> Option<String> {
    body_of(out)
        .pointer("/payload/code")?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn payload_of(out: &TrustTaskOutcome) -> Value {
    body_of(out)
        .pointer("/payload")
        .cloned()
        .unwrap_or(Value::Null)
}

/// Validate a success reply's payload against the task's published
/// `#response` schema.
///
/// The router-level `response_conformance` layer that guards every REST
/// route keys on the `Trust-Task` **header**, which the document endpoint
/// does not use — so it does not reach these replies, and this is what
/// stands in for it. It matters most for `update`, whose arm answers with
/// the route's own `MemberEnvelope` rather than the generated type: a drift
/// between the two would otherwise be invisible until a client hit it.
pub(crate) fn assert_conforms<R: trust_tasks_rs::validate::ValidatedPayload>(
    out: &TrustTaskOutcome,
) {
    let payload = payload_of(out);
    R::validate_value(&payload)
        .unwrap_or_else(|e| panic!("response does not match its published schema: {e}\n{payload}"));
}
