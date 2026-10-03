//! The administrator action list — consent-gated operations park and complete
//! on the N-th approval (**VTI-APV-017**), over **VTI-APV-014** (unrestricted
//! grants), **-019** (reductions), **-020** (threshold lowering) and
//! **VTI-VTC-022** (authority policy).
//!
//! Each test drives the signed-document door end to end: the requester's
//! operation-bound gesture, the parked answer (`trust-task-next-step/0.1`),
//! `vtc/admin/actions/{list,show,cancel}` and the approvers'
//! `task-consent/decision/0.2`. Design: `docs/05-design-notes/vtc-action-list.md`.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::admin_actions::ActionRecord;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::{
    Gesturer, decide, decision_payload, parked_action, show_action, step_up_request,
};
use crate::common::signed::{error_code, post, signed};
use vtc_service::admin_actions::codes::*;

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";
const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const CREATE_INVITE: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";
const CANCEL: &str = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.1";
const ACKNOWLEDGE: &str = "https://trusttasks.org/spec/vtc/admin/actions/acknowledge/0.1";
const DECISION_V0_1: &str = "https://trusttasks.org/spec/task-consent/decision/0.1";
const DECISION_V0_2: &str = "https://trusttasks.org/spec/task-consent/decision/0.2";
const NEXT_STEP: &str = "https://trusttasks.org/spec/trust-task-next-step/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/admin/actions/show/0.1";
const THRESHOLD_KEY: &str = "acl.unrestricted_admin_consent_threshold";

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .with_install_signer(std::sync::Arc::new(
            vtc_service::install::InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

fn row(did: &str, role: VtcRole, scopes: &[&str]) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        admin: vtc_service::acl::legacy_seed_authority(&role, scopes),
        delegated_by: None,
        role,
        label: None,
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

async fn seed(fix: &Fixture, role: VtcRole, scopes: &[&str]) -> Party {
    let party = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&party.did, role, scopes))
        .await
        .unwrap();
    party
}

/// An unrestricted admin with no passkey — enough to approve, which is a
/// signed decision.
async fn admin(fix: &Fixture) -> Party {
    seed(fix, VtcRole::Admin, &[]).await
}

/// An unrestricted admin who holds a passkey, so can make the gesture.
async fn requester(fix: &mut Fixture) -> Party {
    let party = admin(fix).await;
    fix.gesturer.enrol(&fix.vtc, &party.did).await;
    party
}

async fn entry(fix: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&fix.vtc.state.acl_ks, did).await.unwrap()
}

fn grant_unrestricted(subject: &str) -> Value {
    json!({ "entry": { "subject": subject, "role": "admin", "scopes": [] } })
}

/// Send `doc` as `by`, answer the gesture it asks for, and return the reply
/// that follows: for a gated act, the parked answer.
async fn submit(fix: &mut Fixture, by: &Party, doc: &Value) -> (StatusCode, Value) {
    let (status, reply) = post(&fix.vtc, doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, doc).await
}

/// [`submit`], held to having parked: the action's id.
async fn park(fix: &mut Fixture, by: &Party, doc: &Value) -> String {
    let (status, reply) = submit(fix, by, doc).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    parked_action(&reply).unwrap_or_else(|| panic!("parked: {reply}"))
}

async fn action(fix: &Fixture, who: &Party, id: &str) -> Value {
    let (status, reply) = show_action(&fix.vtc, who, id).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["payload"]["action"].clone()
}

async fn list(fix: &Fixture, who: &Party, view: &str) -> Value {
    let (status, reply) = post(&fix.vtc, &signed(who, LIST, json!({ "view": view })).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    crate::common::signed::assert_conforms(LIST, &reply);
    reply["payload"].clone()
}

async fn patch_threshold(fix: &Fixture, by: &Party, n: u64) -> Value {
    let (status, reply) = post(
        &fix.vtc,
        &signed(by, PATCH, json!({ "overrides": { THRESHOLD_KEY: n } })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["payload"].clone()
}

async fn record(fix: &Fixture, id: &str) -> ActionRecord {
    fix.vtc
        .state
        .admin_actions_ks
        .get(format!("action:{id}"))
        .await
        .unwrap()
        .expect("the action is stored")
}

async fn put_record(fix: &Fixture, rec: &ActionRecord) {
    fix.vtc
        .state
        .admin_actions_ks
        .insert(format!("action:{}", rec.id), rec)
        .await
        .unwrap();
}

/// Every audit row of `variant`.
async fn audit_rows(fix: &Fixture, variant: &str) -> Vec<vti_common::audit::AuditEnvelope> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter(|env| env.event.variant_name() == variant)
        .collect()
}

async fn consent_stages(fix: &Fixture, stage: &str) -> usize {
    audit_rows(fix, "TaskConsentRecorded")
        .await
        .iter()
        .filter(|env| match &env.event {
            vti_common::audit::AuditEvent::TaskConsentRecorded(d) => d.stage == stage,
            _ => false,
        })
        .count()
}

// ─── parking ─────────────────────────────────────────────────────────────

/// VTI-APV-017 / §9.1 item 4: a gated operation is not refused. Once its
/// gesture is spent it is parked, and the requester is answered with a
/// `trust-task-next-step/0.1` — `proceed`, expecting `vtc/admin/actions/show`
/// with the action's id — that the published schema admits.
#[tokio::test]
async fn vti_apv_017_a_gated_operation_is_parked_with_a_next_step() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let subject = Party::new();
    let grant = signed(&a, GRANT, grant_unrestricted(&subject.did)).await;

    // The gesture first: nobody else is asked yet.
    let (status, reply) = post(&fix.vtc, &grant).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(step_up_request(&reply).is_some(), "{reply}");
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;

    let (status, reply) = post(&fix.vtc, &grant).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    assert_eq!(reply["type"], NEXT_STEP, "{reply}");
    assert_eq!(reply["issuer"], TEST_VTC_DID);
    assert_eq!(reply["recipient"], a.did.as_str());
    assert_eq!(reply["threadId"], grant["id"], "on the request's thread");
    assert!(reply["proof"].is_object(), "signed: {reply}");
    let p = &reply["payload"];
    {
        use trust_tasks_rs::validate::ValidatedPayload as _;
        trust_tasks_rs::specs::trust_task_next_step::v0_1::Payload::validate_value(p)
            .unwrap_or_else(|e| panic!("the next step conforms: {e}\n{p}"));
    }
    assert_eq!(p["continuation"], "proceed");
    assert_eq!(p["expects"][0]["typeUri"], SHOW);
    assert_eq!(p["inResponseTo"]["id"], grant["id"]);
    assert_eq!(p["inResponseTo"]["typeUri"], GRANT);
    assert!(
        p["message"]
            .as_str()
            .unwrap()
            .starts_with("Sent for approval"),
        "{p}"
    );
    let id = p["expects"][0]["hint"]["actionId"].as_str().unwrap();
    assert!(entry(&fix, &subject.did).await.is_none(), "nothing written");

    // A redelivery of the same document is the recorded answer, not a second
    // action (VTI-OPS-025).
    let (status, again) = post(&fix.vtc, &grant).await;
    assert!(status.is_success(), "{again}");
    assert_eq!(parked_action(&again).as_deref(), Some(id));
    // The same operation in a fresh document finds the open action.
    let fresh = signed(&a, GRANT, grant_unrestricted(&subject.did)).await;
    let (_, again) = post(&fix.vtc, &fresh).await;
    assert_eq!(parked_action(&again).as_deref(), Some(id), "{again}");

    let shown = action(&fix, &a, id).await;
    assert_eq!(shown["status"], "open");
    assert_eq!(shown["kind"], "acl.grant.authority");
    assert_eq!(shown["callerRole"], "requester");
    assert_eq!(shown["threshold"], 1);
    assert!(shown.get("challenge").is_none(), "never for the requester");
    assert_eq!(shown["payload"], grant["payload"]);
    assert_eq!(
        shown["summary"]["fields"]["subject"]["value"],
        subject.did.as_str()
    );
    crate::common::signed::assert_conforms(SHOW, &json!({ "payload": { "action": shown } }));
    assert_eq!(consent_stages(&fix, "parked").await, 1);
}

// ─── N-of-M completion ───────────────────────────────────────────────────

/// N = 1: the approval completes the operation, exactly once.
#[tokio::test]
async fn vti_apv_017_the_first_approval_completes_an_n_of_1_action_exactly_once() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let grant = signed(&a, GRANT, grant_unrestricted(&subject.did)).await;
    let id = park(&mut fix, &a, &grant).await;

    let theirs = action(&fix, &b, &id).await;
    assert_eq!(theirs["callerRole"], "approver");
    let payload = decision_payload(&theirs, "approve");
    let decision = signed(&b, DECISION_V0_2, payload.clone()).await;
    let (status, ack) = post(&fix.vtc, &decision).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert_eq!(ack["payload"]["actionId"], id.as_str());
    assert_eq!(
        ack["payload"]["ext"]["org.openvtc"]["actionStatus"],
        "completed"
    );
    crate::common::signed::assert_conforms(DECISION_V0_2, &ack);

    let written = entry(&fix, &subject.did).await.expect("written");
    assert!(written.is_community_admin());
    let done = action(&fix, &a, &id).await;
    assert_eq!(done["status"], "completed");
    assert_eq!(done["closedReason"], "thresholdMet");
    assert_eq!(done["approvals"][0]["subject"], b.did.as_str());
    assert_eq!(
        done["ext"]["org.openvtc"]["result"]["entry"]["subject"],
        subject.did.as_str()
    );

    // Once: the same decision in a fresh document finds nothing to approve,
    // and the operation ran a single time.
    let again = signed(&b, DECISION_V0_2, payload).await;
    let (_, reply) = post(&fix.vtc, &again).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:noPending"),
        "{reply}"
    );
    assert_eq!(consent_stages(&fix, "completed").await, 1);
    assert_eq!(audit_rows(&fix, "AclGranted").await.len(), 1);
}

/// N = 2: the first approval is recorded, the second completes it.
#[tokio::test]
async fn vti_apv_017_an_n_of_2_action_completes_on_the_second_approval() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let c = admin(&fix).await;
    patch_threshold(&fix, &a, 2).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    assert_eq!(action(&fix, &a, &id).await["threshold"], 2);

    let (_, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "pending", "{ack}");
    assert_eq!(ack["payload"]["approvals"], 1);
    assert_eq!(ack["payload"]["needed"], 2);
    assert!(entry(&fix, &subject.did).await.is_none());
    let mid = action(&fix, &a, &id).await;
    assert_eq!(mid["approversRemaining"], 1, "{mid}");
    // An approver who has approved is not asked again.
    assert!(action(&fix, &b, &id).await.get("challenge").is_none());

    let (_, ack) = decide(&fix.vtc, &c, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert!(
        entry(&fix, &subject.did)
            .await
            .unwrap()
            .is_community_admin()
    );
    assert_eq!(action(&fix, &a, &id).await["status"], "completed");
}

/// Two N-th approvals arriving together: the operation runs once. The status
/// leaves `open` under the lock, so one of them finds nothing to approve.
#[tokio::test]
async fn vti_apv_017_concurrent_final_approvals_execute_once() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let c = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let db = signed(
        &b,
        DECISION_V0_2,
        decision_payload(&action(&fix, &b, &id).await, "approve"),
    )
    .await;
    let dc = signed(
        &c,
        DECISION_V0_2,
        decision_payload(&action(&fix, &c, &id).await, "approve"),
    )
    .await;
    let ((sb, rb), (sc, rc)) = tokio::join!(post(&fix.vtc, &db), post(&fix.vtc, &dc));
    let granted = [&rb, &rc]
        .iter()
        .filter(|r| r["payload"]["status"] == "granted")
        .count();
    assert_eq!(
        granted, 1,
        "exactly one completes it: {sb} {rb} / {sc} {rc}"
    );
    let refused: Vec<_> = [&rb, &rc]
        .into_iter()
        .filter_map(|r| tt_error_code(r))
        .collect();
    assert_eq!(refused, vec!["task-consent/decision:noPending"]);
    assert_eq!(audit_rows(&fix, "AclGranted").await.len(), 1);
    assert_eq!(consent_stages(&fix, "completed").await, 1);
}

// ─── deny, cancel, expiry ────────────────────────────────────────────────

/// One deny closes the action for everyone ("`deny` aborts the pending
/// request"). The other approver finds nothing to approve.
#[tokio::test]
async fn one_deny_closes_the_action_for_everyone() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let c = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let cs = action(&fix, &c, &id).await;

    let mut deny = decision_payload(&action(&fix, &b, &id).await, "deny");
    deny["reason"] = json!("not without a conversation first");
    let (status, ack) = post(&fix.vtc, &signed(&b, DECISION_V0_2, deny).await).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "denied");

    let (_, reply) = post(
        &fix.vtc,
        &signed(&c, DECISION_V0_2, decision_payload(&cs, "approve")).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:noPending"),
        "{reply}"
    );
    let closed = action(&fix, &a, &id).await;
    assert_eq!(closed["status"], "declined");
    assert_eq!(closed["closedReason"], "declined");
    assert_eq!(
        closed["ext"]["org.openvtc"]["closedMessage"],
        "not without a conversation first"
    );
    assert_eq!(closed["ext"]["org.openvtc"]["closedBy"], b.did.as_str());
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// The requester withdraws their own action; nobody else can.
#[tokio::test]
async fn the_requester_cancels_and_nobody_else_can() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let bs = action(&fix, &b, &id).await;

    let (_, reply) = post(
        &fix.vtc,
        &signed(&b, CANCEL, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(CANCEL_NOT_REQUESTER), "{reply}");

    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            CANCEL,
            json!({ "actionId": id, "reason": "wrong person" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    crate::common::signed::assert_conforms(CANCEL, &reply);
    assert_eq!(reply["payload"]["action"]["status"], "cancelled");
    assert_eq!(
        reply["payload"]["action"]["closedReason"],
        "cancelledByRequester"
    );

    let (_, reply) = post(
        &fix.vtc,
        &signed(&a, CANCEL, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(CANCEL_NOT_OPEN), "{reply}");
    let (_, reply) = post(
        &fix.vtc,
        &signed(&b, DECISION_V0_2, decision_payload(&bs, "approve")).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:noPending")
    );
    let (_, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            CANCEL,
            json!({ "actionId": "act-00000000000000000000" }),
        )
        .await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(CANCEL_NOT_FOUND), "{reply}");
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// VTI-APV-008: an action past its `expiresAt` is never executable.
#[tokio::test]
async fn vti_apv_008_an_expired_action_cannot_be_approved() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let bs = action(&fix, &b, &id).await;
    // 72 hours by default.
    let rec = record(&fix, &id).await;
    assert_eq!(rec.expires_at - rec.created_at, 72 * 3600);

    let mut lapsed = rec;
    lapsed.expires_at = lapsed.created_at.saturating_sub(1);
    put_record(&fix, &lapsed).await;

    let (_, reply) = post(
        &fix.vtc,
        &signed(&b, DECISION_V0_2, decision_payload(&bs, "approve")).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:noPending")
    );
    let closed = action(&fix, &a, &id).await;
    assert_eq!(closed["status"], "expired");
    assert_eq!(closed["closedReason"], "expired");
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// `acl.action_lifetime` binds actions raised after it changes, within its
/// bounds; an open action keeps the `expiresAt` it was raised with.
#[tokio::test]
async fn the_action_lifetime_is_configurable_within_bounds() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let first = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    let before = record(&fix, &first).await.expires_at;

    let reply = post(
        &fix.vtc,
        &signed(
            &a,
            PATCH,
            json!({ "overrides": { "acl.action_lifetime": 60 } }),
        )
        .await,
    )
    .await
    .1;
    assert_eq!(
        reply["payload"]["rejected"][0]["key"], "acl.action_lifetime",
        "below 15 minutes is refused: {reply}"
    );
    let reply = post(
        &fix.vtc,
        &signed(
            &a,
            PATCH,
            json!({ "overrides": { "acl.action_lifetime": 3600 } }),
        )
        .await,
    )
    .await
    .1;
    assert_eq!(
        reply["payload"]["applied"][0], "acl.action_lifetime",
        "{reply}"
    );

    let second = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    let rec = record(&fix, &second).await;
    assert_eq!(rec.expires_at - rec.created_at, 3600);
    assert_eq!(record(&fix, &first).await.expires_at, before, "unchanged");
}

// ─── invalidation (§4.4) and the re-check at completion ──────────────────

/// The requester stops being an unrestricted admin: their action is cancelled.
#[tokio::test]
async fn an_action_is_invalidated_when_the_requester_loses_authority() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &row(&a.did, VtcRole::Admin, &["ctx-a"]),
    )
    .await
    .unwrap();
    let closed = action(&fix, &b, &id).await;
    assert_eq!(closed["status"], "cancelled", "{closed}");
    assert_eq!(closed["closedReason"], "invalidated");
}

/// Somebody else edits the subject's entry: the approvers would no longer be
/// approving what they saw.
#[tokio::test]
async fn an_action_is_invalidated_when_its_pinned_state_moves() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = seed(&fix, VtcRole::Member, &[]).await;
    let promote = signed(
        &a,
        CHANGE_ROLE,
        json!({ "subject": subject.did, "fromRole": "member", "toRole": "admin" }),
    )
    .await;
    let id = park(&mut fix, &a, &promote).await;
    let bs = action(&fix, &b, &id).await;

    let mut edited = row(&subject.did, VtcRole::Member, &[]);
    edited.label = Some("renamed".into());
    store_acl_entry(&fix.vtc.state.acl_ks, &edited)
        .await
        .unwrap();

    let (_, reply) = post(
        &fix.vtc,
        &signed(&b, DECISION_V0_2, decision_payload(&bs, "approve")).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:noPending")
    );
    let closed = action(&fix, &a, &id).await;
    assert_eq!(closed["status"], "cancelled");
    assert_eq!(closed["closedReason"], "invalidated");
    assert_eq!(
        entry(&fix, &subject.did).await.unwrap().role,
        VtcRole::Member
    );
}

/// The approver set can no longer reach the threshold (VTI-APV-009 on a live
/// action): cancelled. One approver of several losing standing only stops
/// counting.
#[tokio::test]
async fn an_action_is_invalidated_when_its_approvers_cannot_reach_the_threshold() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let c = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;

    // b approves, then loses standing: dropped from the count, still open.
    patch_threshold(&fix, &a, 1).await;
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&b.did, VtcRole::Member, &[]))
        .await
        .unwrap();
    let open = action(&fix, &a, &id).await;
    assert_eq!(open["status"], "open", "{open}");
    assert_eq!(open["ext"]["org.openvtc"]["approverCount"], 1);

    // c goes too: nobody is left to approve.
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &c.did)
        .await
        .unwrap();
    let closed = action(&fix, &a, &id).await;
    assert_eq!(closed["status"], "cancelled", "{closed}");
    assert_eq!(closed["closedReason"], "invalidated");
}

/// A stale action fails closed at completion. Its document was signed by a
/// console key acting for the requester; the key is revoked while the action
/// waits. Nothing about the action itself moved, so it is still open — but
/// executing it re-resolves the signer, which no longer acts for anybody, so
/// the approval that meets the threshold fails it and writes nothing.
#[tokio::test]
async fn vti_apv_017_a_stale_action_fails_closed_at_completion() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let console = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix.vtc.state.console_keys_ks,
        &fix.vtc.state.acl_ks,
        &console.did,
        &a.did,
        None,
        None,
    )
    .await
    .unwrap();
    let subject = Party::new();
    // Signed by the console key; the gesture is the admin's own.
    let grant = signed(&console, GRANT, grant_unrestricted(&subject.did)).await;
    let id = park(&mut fix, &a, &grant).await;
    assert_eq!(action(&fix, &b, &id).await["requester"], a.did.as_str());

    vtc_service::acl::console_key::revoke_delegation(
        &fix.vtc.state.console_keys_ks,
        &console.did,
        &a.did,
    )
    .await
    .unwrap();
    assert_eq!(action(&fix, &a, &id).await["status"], "open");

    let (status, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(
        ack["payload"]["ext"]["org.openvtc"]["actionStatus"],
        "failed"
    );
    let failed = action(&fix, &a, &id).await;
    assert_eq!(failed["status"], "failed", "{failed}");
    assert_eq!(failed["closedReason"], "failedRecheck");
    assert!(entry(&fix, &subject.did).await.is_none(), "nothing written");
}

// ─── who may decide ──────────────────────────────────────────────────────

/// A decision signed by a delegated console key is refused: an approval is the
/// approver's own attestation, never a console key's.
#[tokio::test]
async fn a_console_key_signed_decision_is_refused() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let console = Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix.vtc.state.console_keys_ks,
        &fix.vtc.state.acl_ks,
        &console.did,
        &b.did,
        None,
        None,
    )
    .await
    .unwrap();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    // The console key may read b's list…
    let bs = action(&fix, &console, &id).await;
    assert_eq!(bs["callerRole"], "approver");
    // …but not decide for them.
    let (status, reply) = post(
        &fix.vtc,
        &signed(&console, DECISION_V0_2, decision_payload(&bs, "approve")).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(tt_error_code(&reply), Some("permissionDenied"), "{reply}");
    assert_eq!(action(&fix, &a, &id).await["status"], "open");
}

/// VTI-APV-007: the requester never counts. VTI-APV-006: a scoped admin or a
/// member cannot decide.
#[tokio::test]
async fn vti_apv_006_007_only_another_unrestricted_admin_decides() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let scoped = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    let member = seed(&fix, VtcRole::Member, &[]).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    let bs = action(&fix, &b, &id).await;
    let payload = decision_payload(&bs, "approve");

    let (_, reply) = post(&fix.vtc, &signed(&a, DECISION_V0_2, payload.clone()).await).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:requesterExcluded"),
        "{reply}"
    );
    let (_, reply) = post(
        &fix.vtc,
        &signed(&scoped, DECISION_V0_2, payload.clone()).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:notAnApprover"),
        "{reply}"
    );
    let (_, reply) = post(
        &fix.vtc,
        &signed(&member, DECISION_V0_2, payload.clone()).await,
    )
    .await;
    assert!(tt_error_code(&reply).is_some(), "{reply}");

    // A decision naming another action is refused.
    let mut wrong = payload;
    wrong["actionId"] = json!("act-ffffffffffffffffffffffffffffffff");
    let (_, reply) = post(&fix.vtc, &signed(&b, DECISION_V0_2, wrong).await).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:actionMismatch"),
        "{reply}"
    );
    assert_eq!(action(&fix, &a, &id).await["status"], "open");
}

/// `approverSigned` evidence that is no statement is refused with a typed
/// reason; evidence is never ignored. The accepted and refused statements are
/// `action_list_a2.rs::vti_apv_017_approver_signed_decision_evidence_is_verified`.
#[tokio::test]
async fn approver_signed_evidence_is_refused_not_ignored() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    let mut payload = decision_payload(&action(&fix, &b, &id).await, "approve");
    payload["evidence"] = json!({ "kind": "approverSigned", "statement": {} });
    let (_, reply) = post(&fix.vtc, &signed(&b, DECISION_V0_2, payload).await).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:evidenceInvalid"),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["reason"], "statementInvalid");
    assert_eq!(action(&fix, &a, &id).await["status"], "open");
}

/// The approver's own passkey, over their challenge, as additional evidence on
/// a 0.2 decision: verified, user verification required, and the approval
/// counts. A passkey assertion over some other challenge is refused.
#[tokio::test]
async fn webauthn_evidence_is_verified_against_the_approvers_passkey() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let mut approver_keys = Gesturer::new();
    approver_keys.enrol(&fix.vtc, &b.did).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let bs = action(&fix, &b, &id).await;
    let challenge = bs["challenge"].as_str().unwrap();

    let mut bad = decision_payload(&bs, "approve");
    bad["evidence"] = json!({
        "kind": "webauthn",
        "assertion": approver_keys.assert_over(&fix.vtc, b"not the challenge").await,
    });
    let (_, reply) = post(&fix.vtc, &signed(&b, DECISION_V0_2, bad).await).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("task-consent/decision:evidenceInvalid"),
        "{reply}"
    );

    let mut good = decision_payload(&bs, "approve");
    good["evidence"] = json!({
        "kind": "webauthn",
        "assertion": approver_keys.assert_over(&fix.vtc, challenge.as_bytes()).await,
    });
    let (status, ack) = post(&fix.vtc, &signed(&b, DECISION_V0_2, good).await).await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert!(
        entry(&fix, &subject.did)
            .await
            .unwrap()
            .is_community_admin()
    );
}

// ─── abuse limits (§7a.1) ────────────────────────────────────────────────

/// Open actions per requester are capped; the refusal comes before any
/// gesture is asked for.
#[tokio::test]
async fn the_open_actions_per_requester_cap_is_enforced() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let reply = post(
        &fix.vtc,
        &signed(
            &a,
            PATCH,
            json!({ "overrides": { "acl.action_max_open_per_requester": 1 } }),
        )
        .await,
    )
    .await
    .1;
    assert_eq!(
        reply["payload"]["applied"][0],
        "acl.action_max_open_per_requester"
    );
    park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;

    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    assert!(status.is_client_error(), "{reply}");
    assert!(
        step_up_request(&reply).is_none(),
        "no gesture asked: {reply}"
    );
    assert!(
        reply
            .to_string()
            .contains("acl.action_max_open_per_requester"),
        "{reply}"
    );
}

/// After a decline the same requester cannot raise the same kind of action
/// against the same subject until the cooldown passes.
#[tokio::test]
async fn a_declined_request_cannot_be_raised_again_during_the_cooldown() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let (_, ack) = decide(&fix.vtc, &b, &id, "deny").await;
    assert_eq!(ack["payload"]["status"], "denied");

    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    assert!(status.is_client_error(), "{reply}");
    assert!(
        reply.to_string().contains("acl.action_decline_cooldown"),
        "{reply}"
    );
    // Another subject is unaffected.
    park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
}

/// More than three actions by one requester in ten minutes is a `Critical`
/// audit row, and every approver's card says so.
#[tokio::test]
async fn a_burst_of_actions_is_audited_critical_and_flagged() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let mut last = String::new();
    for _ in 0..4 {
        last = park(
            &mut fix,
            &a,
            &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
        )
        .await;
    }
    let rows = audit_rows(&fix, "AdminActionBurst").await;
    assert_eq!(rows.len(), 1, "the fourth crosses the line");
    assert_eq!(
        rows[0].event.severity(),
        vti_common::audit::AuditSeverity::Critical
    );
    let card = action(&fix, &b, &last).await;
    assert_eq!(card["ext"]["org.openvtc"]["burst"], true, "{card}");
    assert_eq!(card["requesterOpenActions"], 4);
}

// ─── the list ────────────────────────────────────────────────────────────

/// Who sees what: the requester its own, the approvers what waits for them
/// (with their own challenge), an unrestricted subject as an observer; a
/// scoped admin nothing, and a member is no administrator at all. The badge
/// counts span the whole list.
#[tokio::test]
async fn the_list_shows_each_caller_what_is_theirs_to_see() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let c = admin(&fix).await;
    let scoped = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    let member = seed(&fix, VtcRole::Member, &[]).await;
    // A reduction of c: b approves, c only observes.
    let id = park(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": c.did })).await,
    )
    .await;

    let mine = list(&fix, &a, "requestedByMe").await;
    assert_eq!(mine["counts"]["requestedByMe"], 1);
    assert_eq!(mine["counts"]["waitingForMe"], 0);
    assert_eq!(mine["actions"][0]["actionId"], id.as_str());

    let waiting = list(&fix, &b, "waitingForMe").await;
    assert_eq!(waiting["counts"]["waitingForMe"], 1);
    assert_eq!(waiting["actions"][0]["kind"], "acl.reduce.authority");
    let ca = waiting["actions"][0]["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    let subjects = list(&fix, &c, "waitingForMe").await;
    assert_eq!(
        subjects["counts"]["waitingForMe"], 0,
        "the subject never decides"
    );
    let all = list(&fix, &c, "all").await;
    assert_eq!(all["actions"][0]["callerRole"], "observer");

    assert_eq!(list(&fix, &scoped, "all").await["actions"], json!([]));
    let (_, reply) = post(
        &fix.vtc,
        &signed(&member, LIST, json!({ "view": "all" })).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(LIST_NOT_ADMINISTRATOR),
        "{reply}"
    );
    let (_, reply) = post(
        &fix.vtc,
        &signed(&member, SHOW, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(SHOW_NOT_ADMINISTRATOR),
        "{reply}"
    );
    let (_, reply) = post(
        &fix.vtc,
        &signed(&scoped, SHOW, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(SHOW_NOT_FOUND), "{reply}");

    // `since` is for history only, and a cursor is bound to its view.
    let (_, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            LIST,
            json!({ "view": "all", "since": "2026-01-01T00:00:00Z" }),
        )
        .await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(LIST_INVALID_FILTER));
    let (_, reply) = post(
        &fix.vtc,
        &signed(&a, LIST, json!({ "view": "all", "cursor": "bogus" })).await,
    )
    .await;
    assert_eq!(tt_error_code(&reply), Some(LIST_INVALID_CURSOR));

    // Completed, it leaves the waiting list and enters history.
    let (_, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert!(ca.len() >= 16);
    assert_eq!(
        list(&fix, &b, "waitingForMe").await["counts"]["waitingForMe"],
        0
    );
    let history = list(&fix, &a, "history").await;
    assert_eq!(history["actions"][0]["status"], "completed");
}

/// `acknowledge` exists before anything raises an acknowledge item: an
/// approval action answers `notAcknowledgeable`.
#[tokio::test]
async fn an_approval_action_is_not_acknowledgeable() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    let (_, reply) = post(
        &fix.vtc,
        &signed(&b, ACKNOWLEDGE, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(ACKNOWLEDGE_NOT_ACKNOWLEDGEABLE),
        "{reply}"
    );
    let (_, reply) = post(
        &fix.vtc,
        &signed(
            &b,
            ACKNOWLEDGE,
            json!({ "actionId": "act-00000000000000000000" }),
        )
        .await,
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some(ACKNOWLEDGE_NOT_FOUND),
        "{reply}"
    );
}

// ─── every act kind ──────────────────────────────────────────────────────

/// VTI-APV-019: removing another unrestricted admin parks for an approver who
/// is neither party, and completes on that approval.
#[tokio::test]
async fn vti_apv_019_a_reduction_parks_and_completes() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let subject = admin(&fix).await;
    let third = admin(&fix).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": subject.did })).await,
    )
    .await;
    assert_eq!(action(&fix, &a, &id).await["kind"], "acl.reduce.authority");
    let (_, ack) = decide(&fix.vtc, &third, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert!(entry(&fix, &subject.did).await.is_none());
}

/// VTI-APV-020: lowering the threshold parks at the threshold as it stands.
#[tokio::test]
async fn vti_apv_020_a_threshold_lowering_parks_and_completes() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let c = admin(&fix).await;
    patch_threshold(&fix, &a, 2).await;
    let id = park(
        &mut fix,
        &a,
        &signed(&a, PATCH, json!({ "overrides": { THRESHOLD_KEY: 1 } })).await,
    )
    .await;
    let shown = action(&fix, &a, &id).await;
    assert_eq!(shown["kind"], "config.threshold.lower");
    assert_eq!(shown["summary"]["fields"]["threshold"]["value"], 1);
    decide(&fix.vtc, &b, &id, "approve").await;
    let (_, ack) = decide(&fix.vtc, &c, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert_eq!(
        vtc_service::acl::admin_consent::threshold(&fix.vtc.state)
            .await
            .unwrap(),
        1
    );
}

/// VTI-VTC-022: replacing an authority policy parks, and the approval runs it.
#[tokio::test]
async fn vti_vtc_022_an_authority_policy_change_parks_and_completes() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let src = "package vtc.removal\nimport rego.v1\n\
               default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n";
    let id = park(
        &mut fix,
        &a,
        &signed(
            &a,
            UPSERT,
            json!({ "name": "removal", "module": src, "ext": { "org.openvtc.purpose": "removal" } }),
        )
        .await,
    )
    .await;
    assert_eq!(
        action(&fix, &a, &id).await["kind"],
        "policy.authority.change"
    );
    let (_, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    let done = action(&fix, &a, &id).await;
    assert_eq!(done["status"], "completed", "{done}");
    let pid = done["ext"]["org.openvtc"]["result"]["policy"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let id = park(
        &mut fix,
        &a,
        &signed(&a, ACTIVATE, json!({ "id": pid, "purpose": "removal" })).await,
    )
    .await;
    let (_, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert_eq!(
        vtc_service::policy::get_active_policy_id(
            &fix.vtc.state.active_policies_ks,
            vtc_service::policy::PolicyPurpose::Removal,
        )
        .await
        .unwrap()
        .map(|u| u.to_string()),
        Some(pid)
    );
}

/// An admin invite parks; on approval the requester reads the claim code once.
#[tokio::test]
async fn vti_apv_014_an_invite_parks_and_its_secret_is_read_once() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let invitee = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, CREATE_INVITE, json!({ "did": invitee.did })).await,
    )
    .await;
    assert_eq!(action(&fix, &a, &id).await["kind"], "admin.invite.create");
    decide(&fix.vtc, &b, &id, "approve").await;
    assert!(
        entry(&fix, &invitee.did)
            .await
            .unwrap()
            .is_community_admin()
    );

    let first = action(&fix, &a, &id).await;
    assert!(
        first["ext"]["org.openvtc"]["result"]["installUrl"].is_string(),
        "{first}"
    );
    let second = action(&fix, &a, &id).await;
    assert!(
        second["ext"]["org.openvtc"].get("result").is_none(),
        "shown once: {second}"
    );
}

/// A community with one unrestricted admin has nobody to approve. It is told
/// how to add one before being asked for a gesture.
#[tokio::test]
async fn a_sole_admin_is_told_how_to_add_a_second_before_any_gesture() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, GRANT, grant_unrestricted(&Party::new().did)).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(step_up_request(&reply).is_none(), "{reply}");
    let message = reply.to_string();
    assert!(message.contains("vtc acl add"), "names the fix: {message}");
    assert!(message.contains("VTI-APV-018"), "{message}");
}

/// An administrative grant conferring nothing authority-conferring — a
/// moderator — takes the gesture alone (VTI-APV-018 gates only the
/// authority-conferring).
#[tokio::test]
async fn a_scoped_admin_grant_needs_no_approval() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let subject = Party::new();
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": subject.did, "role": "moderator", "scopes": [] } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        !entry(&fix, &subject.did)
            .await
            .unwrap()
            .is_community_admin()
    );
}

/// VTI-APV-009: a threshold the community cannot meet is refused when written.
#[tokio::test]
async fn vti_apv_009_an_unmeetable_threshold_is_refused_when_written() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let reply = patch_threshold(&fix, &a, 2).await;
    assert_eq!(reply["rejected"][0]["key"], THRESHOLD_KEY, "{reply}");
    let _c = admin(&fix).await;
    let reply = patch_threshold(&fix, &a, 2).await;
    assert_eq!(reply["applied"][0], THRESHOLD_KEY, "{reply}");
}

/// The approver's side as `cnm consent approve <file>` runs it: the VTC-signed
/// request for their slot (pushed, and carried on `show`) verifies through
/// `vta_sdk::task_consent`, and the 0.1 decision built from it completes the
/// action.
#[tokio::test]
async fn vti_apv_014_a_signed_request_is_answered_through_the_sdk() {
    use vta_sdk::task_consent::{ConsentRequest, extract_requests};
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let subject = Party::new();
    let id = park(
        &mut fix,
        &a,
        &signed(&a, GRANT, grant_unrestricted(&subject.did)).await,
    )
    .await;
    let bs = action(&fix, &b, &id).await;
    let request = bs["ext"]["org.openvtc"]["consentRequest"].clone();
    let requests = extract_requests(&request);
    assert_eq!(requests.len(), 1, "{bs}");
    assert_eq!(requests[0]["recipient"], b.did.as_str());
    assert_eq!(requests[0]["payload"]["challenge"], bs["challenge"]);

    let resolver = resolver_knowing_the_vtc(&fix).await;
    let verified = ConsentRequest::new(requests[0].clone())
        .verify(TEST_VTC_DID, &b.did, &resolver, chrono::Utc::now())
        .await
        .expect("the VTC's own request verifies");
    let decision = verified.decision(true, Some("checked")).unwrap();
    let (status, ack) = post(
        &fix.vtc,
        &signed(&b, DECISION_V0_1, serde_json::to_value(&decision).unwrap()).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    let _: vta_sdk::task_consent::decision::Response =
        serde_json::from_value(ack["payload"].clone()).expect("the 0.1 response type");
    assert!(entry(&fix, &subject.did).await.is_some());
}

/// A resolver that knows the test VTC's DID document, as an approver's resolver
/// would learn it from the network.
async fn resolver_knowing_the_vtc(fix: &Fixture) -> vta_sdk::trust_task_proof::TrustTaskVmResolver {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    let signer = fix.vtc.state.credential_signer.as_ref().expect("signers");
    let vm = signer.assertion_method_id().to_string();
    let multikey = affinidi_crypto::did_key::ed25519_pub_to_did_key(
        signer.public_bytes().try_into().expect("an Ed25519 key"),
    )
    .trim_start_matches("did:key:")
    .to_string();
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": TEST_VTC_DID,
        "verificationMethod": [{
            "id": vm, "type": "Multikey", "controller": TEST_VTC_DID,
            "publicKeyMultibase": multikey,
        }],
        "assertionMethod": [vm],
        "authentication": [vm],
    });
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("local DID cache");
    client
        .add_did_document(
            TEST_VTC_DID,
            serde_json::from_value(doc).expect("fixture document"),
        )
        .await;
    vta_sdk::trust_task_proof::TrustTaskVmResolver::new(client)
}

// ─── attrition (VTI-APV-009): ending an unrestricted admin ─────────────────

/// `acl/revoke` of an unrestricted admin that would strand the threshold is
/// refused, names the fix, and writes nothing — before any gesture.
#[tokio::test]
async fn vti_apv_009_a_revoke_that_would_strand_the_threshold_is_refused() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let _b = admin(&fix).await;
    let c = admin(&fix).await;
    patch_threshold(&fix, &a, 2).await;
    let (status, body) = post(
        &fix.vtc,
        &signed(&a, REVOKE, json!({ "subject": c.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.to_string().contains("config/patch"), "{body}");
    assert!(entry(&fix, &c.did).await.is_some());
}

/// At the default threshold a two-admin community can still remove one of
/// them: nobody else is left to approve, so the gesture is enough — after the
/// cooling-off (VTI-APV-019, `vtc-action-list.md` §8.2).
#[tokio::test]
async fn a_two_admin_community_can_still_remove_one_at_the_default_threshold() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, body) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = parked_action(&body).expect("cooling off");
    assert!(entry(&fix, &b.did).await.is_some());
    let mut rec = record(&fix, &id).await;
    rec.cooling_off_until = Some(1);
    put_record(&fix, &rec).await;
    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
    assert!(entry(&fix, &b.did).await.is_none());
}
