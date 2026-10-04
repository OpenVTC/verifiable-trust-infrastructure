//! **Suspension during a cooling-off**, and **remove now** in
//! single-administrator mode (`docs/05-design-notes/vtc-action-list.md` §8.2,
//! §8.5).
//!
//! - A reduction of another administrator that nobody but the requester and
//!   the subject could consent to waits out a cooling-off (VTI-APV-019). From
//!   the moment it is raised until it lands or is cancelled, the subject is
//!   **suspended**: its entry authorizes nothing — no act, no approval, no
//!   counter-removal — while the row is kept, so a cancellation restores it
//!   exactly. It still sees the action about itself.
//! - The suspension is derived from the open action and persisted beside the
//!   entry in a crash-safe order, so a restart neither loses nor invents one.
//! - In single-administrator mode (VTI-APV-022) the requester may land a
//!   reduction **now** — or land an open cooling-off now — on a typed
//!   confirmation and a gesture bound to the immediate operation
//!   (VTI-APV-015), audited at `Critical`.
//!
//! Every request here is a signed Trust Task through the one spine REST,
//! DIDComm and TSP share.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_common::audit::{AuditEvent, AuditSeverity};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::admin_actions::ActionRecord;
use vtc_service::ceremony::authority_reduced_notice::sent_for_test as notices;
use vtc_service::test_support::TestVtc;

use crate::common::second_party::{Gesturer, parked_action, show_action, step_up_request};
use crate::common::signed::{assert_conforms, error_code, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const ACL_SHOW: &str = "https://trusttasks.org/spec/acl/show/0.2";
const LIST: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";
const SHOW_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/show/0.2";
const CANCEL_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/cancel/0.2";
const DECISION_V0_2: &str = "https://trusttasks.org/spec/task-consent/decision/0.2";

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture(single_admin_mode: bool) -> Fixture {
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
    // Host configuration, as `config.toml` would set it at start.
    vtc.state.config.write().await.acl.single_admin_mode = single_admin_mode;
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

/// An unrestricted administrator.
async fn admin(fix: &Fixture) -> Party {
    let party = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &VtcAclEntry {
            did: party.did.clone(),
            admin: vtc_service::acl::legacy_seed_authority::<&str>(&VtcRole::Admin, &[]),
            delegated_by: None,
            role: VtcRole::Admin,
            label: None,
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
    party
}

/// An unrestricted administrator with a passkey to make the gesture.
async fn requester(fix: &mut Fixture) -> Party {
    let party = admin(fix).await;
    fix.gesturer.enrol(&fix.vtc, &party.did).await;
    party
}

async fn entry(fix: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&fix.vtc.state.acl_ks, did).await.unwrap()
}

/// Send `doc`, answering a step-up with `by`'s passkey: the reply after.
async fn submit(fix: &mut Fixture, by: &Party, doc: &Value) -> (StatusCode, Value) {
    let (status, reply) = post(&fix.vtc, doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, doc).await
}

/// `a` asks to revoke `b`'s entry; it parks for its cooling-off.
async fn cool_off(fix: &mut Fixture, a: &Party, b: &Party) -> String {
    let (status, reply) = submit(
        fix,
        a,
        &signed(a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    assert!(
        reply["payload"]["ext"]["org.openvtc"]["coolingOffUntil"].is_string(),
        "{reply}"
    );
    parked_action(&reply).expect("parked")
}

/// `a`'s revocation of `b`, asking to land now with `confirm`.
async fn revoke_now(a: &Party, b: &Party, confirm: &str, action_id: Option<&str>) -> Value {
    let mut immediate = json!({ "confirm": confirm });
    if let Some(id) = action_id {
        immediate["actionId"] = json!(id);
    }
    signed(
        a,
        REVOKE,
        json!({ "subject": b.did, "ext": { "org.openvtc": { "immediate": immediate } } }),
    )
    .await
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

async fn show_v0_2(fix: &Fixture, who: &Party, id: &str) -> Value {
    let (status, reply) = post(
        &fix.vtc,
        &signed(who, SHOW_V0_2, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(SHOW_V0_2, &reply);
    reply["payload"]["action"].clone()
}

async fn audit_events(fix: &Fixture) -> Vec<AuditEvent> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .map(|e| e.event)
        .collect()
}

/// Every `SingleAdminMode { event: reductionImmediate }` row.
async fn immediate_rows(fix: &Fixture) -> Vec<vti_common::audit::SingleAdminModeData> {
    audit_events(fix)
        .await
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::SingleAdminMode(d) if d.event == "reductionImmediate" => {
                assert_eq!(
                    AuditEvent::SingleAdminMode(d.clone()).severity(),
                    AuditSeverity::Critical
                );
                Some(d)
            }
            _ => None,
        })
        .collect()
}

async fn unopposed_rows(fix: &Fixture) -> usize {
    audit_events(fix)
        .await
        .into_iter()
        .filter(|e| {
            matches!(e, AuditEvent::AuthorityReducedUnopposed(_))
                && e.severity() == AuditSeverity::Critical
        })
        .count()
}

/// A refusal that names the suspension and the action holding it.
fn assert_suspended_refusal(reply: &Value, action_id: &str) {
    assert_eq!(error_code(reply), Some("permissionDenied"), "{reply}");
    let text = reply.to_string();
    assert!(text.contains("suspended pending its removal"), "{reply}");
    assert!(text.contains(action_id), "names the action: {reply}");
}

// ─── suspension (§8.2) ────────────────────────────────────────────────────

/// From the moment the cooling-off is raised the subject's entry authorizes
/// nothing, every privileged verb is refused naming the action and when it
/// lands, the row is kept and shown as suspended — and the subject still
/// sees the action about itself. When it lands, the entry goes and the
/// suspension with it.
#[tokio::test]
async fn cooling_off_suspends_subject_until_it_lands() {
    let mut fix = fixture(false).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = cool_off(&mut fix, &a, &b).await;

    let held = entry(&fix, &b.did).await.expect("kept until it lands");
    let s = held.suspension.clone().expect("suspended");
    assert_eq!(s.action_id, id);
    assert_eq!(s.requester, a.did);
    for c in vtc_service::acl::Capability::ALL {
        assert!(!held.can(c, None), "{c:?}");
    }
    // The row is untouched: still the administrator it was.
    assert!(held.is_administrator());
    assert!(
        held.admin
            .can(vtc_service::acl::Capability::RolesAssign, None)
    );

    // A privileged verb: refused, saying why and until when.
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &b,
            GRANT,
            json!({ "entry": { "subject": Party::new().did, "role": "moderator", "scopes": [] } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_suspended_refusal(&reply, &id);
    // Reading the ACL is privileged too.
    let (_, reply) = post(
        &fix.vtc,
        &signed(&b, ACL_SHOW, json!({ "subject": a.did })).await,
    )
    .await;
    assert_suspended_refusal(&reply, &id);

    // What it may still do: see the action about itself (VTI-APV-019).
    let (status, listed) = post(&fix.vtc, &signed(&b, LIST, json!({ "view": "all" })).await).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(
        listed["payload"]["ext"]["org.openvtc"]["coolingOffAgainstMe"][0]["actionId"],
        id.as_str()
    );
    let seen = show_v0_2(&fix, &b, &id).await;
    assert_eq!(seen["callerRole"], "subject", "{seen}");
    assert_eq!(
        seen["ext"]["org.openvtc"]["subjectSuspended"]["subject"],
        b.did.as_str(),
        "{seen}"
    );

    // Another administrator reading the ACL sees it marked.
    let (status, shown) = post(
        &fix.vtc,
        &signed(&a, ACL_SHOW, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_conforms(ACL_SHOW, &shown);
    let marked = &shown["payload"]["entry"]["ext"]["org.openvtc"]["suspended"];
    assert_eq!(marked["actionId"], id.as_str(), "{shown}");
    assert!(marked["landsAt"].is_string(), "{shown}");

    // It lands: the entry and the suspension go together.
    let mut rec = record(&fix, &id).await;
    rec.cooling_off_until = Some(1);
    put_record(&fix, &rec).await;
    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
    assert!(entry(&fix, &b.did).await.is_none(), "landed");
    assert!(
        vtc_service::acl::storage::get_suspension(&fix.vtc.state.acl_ks, &b.did)
            .await
            .unwrap()
            .is_none()
    );
}

/// Cancelling restores the subject exactly: the same row, no suspension, and
/// its authority back.
#[tokio::test]
async fn cancelled_cooling_off_restores_subject() {
    let mut fix = fixture(false).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let before = entry(&fix, &b.did).await.unwrap();
    let id = cool_off(&mut fix, &a, &b).await;
    assert!(entry(&fix, &b.did).await.unwrap().is_suspended());

    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, CANCEL_V0_2, json!({ "actionId": id })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let after = entry(&fix, &b.did).await.unwrap();
    assert!(after.suspension.is_none(), "{after:?}");
    assert_eq!(after, before, "restored exactly");
    assert!(after.can(vtc_service::acl::Capability::RolesAssign, None));
    // And it acts again.
    let (status, reply) = post(
        &fix.vtc,
        &signed(&b, ACL_SHOW, json!({ "subject": a.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

/// A suspended subject cannot act, cannot approve an action it held a slot
/// on, and cannot answer with a counter-removal — which no longer lands the
/// earlier request: the subject never gets to act at all (§8.2). Its own
/// pending request is invalidated with its authority.
#[tokio::test]
async fn suspended_subject_cannot_act_approve_or_counter_remove() {
    let mut fix = fixture(false).await;
    let a = requester(&mut fix).await;
    let b = requester(&mut fix).await;
    // Before: A asks to make D an administrator, which waits on B; B asks to
    // make E one, which waits on A.
    let d = Party::new();
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": d.did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    let waits_on_b = parked_action(&reply).unwrap();
    let (status, reply) = submit(
        &mut fix,
        &b,
        &signed(
            &b,
            GRANT,
            json!({ "entry": { "subject": Party::new().did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    let bs_own = parked_action(&reply).unwrap();

    let removal = cool_off(&mut fix, &a, &b).await;

    // B approves A's grant with the challenge its slot was issued: refused.
    let rec = record(&fix, &waits_on_b).await;
    let slot = rec.approvers.iter().find(|s| s.did == b.did).unwrap();
    let decision = json!({
        "challenge": slot.challenge,
        "payloadDigest": vti_common::task_consent::wire_digest(&rec.type_uri, &rec.payload, &slot.challenge).unwrap(),
        "decision": "approve",
        "actionId": waits_on_b,
    });
    let (status, reply) = post(&fix.vtc, &signed(&b, DECISION_V0_2, decision).await).await;
    assert!(!status.is_success(), "{reply}");
    assert!(entry(&fix, &d.did).await.is_none(), "nothing granted");
    assert_ne!(
        record(&fix, &waits_on_b).await.status,
        vtc_service::admin_actions::Status::Completed
    );

    // B answers with a counter-removal of A: refused as suspended, and A's
    // removal of B is not hurried — it still waits out its cooling-off.
    let (status, reply) = post(
        &fix.vtc,
        &signed(&b, REVOKE, json!({ "subject": a.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_suspended_refusal(&reply, &removal);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(entry(&fix, &a.did).await.is_some());
    assert!(entry(&fix, &b.did).await.is_some(), "not hurried");
    let still = record(&fix, &removal).await;
    assert!(still.cooling_off_until.unwrap() > vti_common::auth::session::now_epoch());

    // B's own request is invalidated: its requester authorizes nothing now.
    let (_, shown) = show_action(&fix.vtc, &a, &bs_own).await;
    assert_eq!(shown["payload"]["action"]["status"], "cancelled", "{shown}");
    assert_eq!(
        shown["payload"]["action"]["closedReason"], "invalidated",
        "{shown}"
    );
}

/// The suspension is held in the store, not in memory, in an order that a
/// crash cannot turn into an open cooling-off whose subject still acts — and
/// what start runs (`reconcile_suspensions`) repairs whichever half a crash
/// left: a marker with no open action is lifted, an open action with no
/// marker suspends its subject again.
#[tokio::test]
async fn suspension_survives_restart() {
    let mut fix = fixture(false).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = cool_off(&mut fix, &a, &b).await;
    let acl = &fix.vtc.state.acl_ks;

    // Persisted beside the entry: a fresh read, as after a restart, finds it.
    let marker = vtc_service::acl::storage::get_suspension(acl, &b.did)
        .await
        .unwrap()
        .expect("persisted");
    assert_eq!(marker.action_id, id);

    // A crash that lost the marker but kept the open action: start puts the
    // subject back under suspension before anything is served.
    vtc_service::acl::storage::remove_suspension(acl, &b.did)
        .await
        .unwrap();
    assert!(!entry(&fix, &b.did).await.unwrap().is_suspended());
    vtc_service::admin_actions::reconcile_suspensions(&fix.vtc.state)
        .await
        .unwrap();
    assert_eq!(
        entry(&fix, &b.did)
            .await
            .unwrap()
            .suspension
            .unwrap()
            .action_id,
        id
    );

    // A crash between writing a marker and the action that would hold it:
    // a marker with no open action is lifted.
    let c = admin(&fix).await;
    vtc_service::acl::storage::put_suspension(
        acl,
        &c.did,
        &vtc_service::acl::Suspension {
            action_id: "act-never-written".into(),
            lands_at: u64::MAX,
            requester: a.did.clone(),
        },
    )
    .await
    .unwrap();
    assert!(entry(&fix, &c.did).await.unwrap().is_suspended());
    vtc_service::admin_actions::reconcile_suspensions(&fix.vtc.state)
        .await
        .unwrap();
    assert!(!entry(&fix, &c.did).await.unwrap().is_suspended());
    assert!(
        entry(&fix, &b.did).await.unwrap().is_suspended(),
        "B's holds"
    );

    // A crash after the action closed but before its marker was lifted: the
    // marker outlives no open action.
    let mut rec = record(&fix, &id).await;
    rec.status = vtc_service::admin_actions::Status::Cancelled;
    put_record(&fix, &rec).await;
    vtc_service::admin_actions::reconcile_suspensions(&fix.vtc.state)
        .await
        .unwrap();
    assert!(!entry(&fix, &b.did).await.unwrap().is_suspended());
}

/// A suspended entry stops counting toward the attrition guard: with B
/// suspended, A is the only live holder of `vtc.roles.assign`, so ending A
/// is refused as ending the last one — before, B counted and it was not.
/// And a second cooling-off on a subject already suspended is refused rather
/// than raced.
#[tokio::test]
async fn suspension_never_leaves_no_live_unrestricted_entry() {
    use vtc_service::acl::admin_consent::{check_attrition, role_assigners};
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let now = vti_common::auth::session::now_epoch();
    check_attrition(&fix.vtc.state, &a.did)
        .await
        .expect("two live: either may go");

    let _ = cool_off(&mut fix, &a, &b).await;
    assert_eq!(
        role_assigners(&fix.vtc.state, now).await.unwrap(),
        vec![a.did.clone()],
        "B is suspended: not counted"
    );
    // Only A is live now, and the guard refuses to end A: the suspended
    // entry does not count toward what would remain.
    let refused = check_attrition(&fix.vtc.state, &a.did).await.unwrap_err();
    assert!(
        refused.to_string().contains("last administrator"),
        "{refused}"
    );

    // One cooling-off per subject: another reduction of B waits for that one.
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did, "reason": "again" })).await,
    )
    .await;
    assert!(!status.is_success(), "{reply}");
    assert_eq!(reply["payload"]["details"]["reason"], "conflict", "{reply}");
    assert!(reply.to_string().contains("already cooling off"), "{reply}");
}

// ─── remove now, single-administrator mode (§8.5) ──────────────────────────

/// In single-administrator mode, a removal with `ext.org.openvtc.immediate`
/// and the subject's DID typed as confirmation lands at once on a gesture
/// bound to that immediate operation: no cooling-off, no suspension window,
/// a `Critical` `reductionImmediate` row before the write, the unopposed
/// reduction at `Critical`, the subject told, and the history entry marked.
#[tokio::test]
async fn single_admin_remove_now_lands_at_once_with_bound_step_up_and_confirmation() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let doc = revoke_now(&a, &b, &b.did, None).await;

    // The gesture is asked for, bound to this operation.
    let (_, first) = post(&fix.vtc, &doc).await;
    assert!(step_up_request(&first).is_some(), "{first}");
    assert!(
        entry(&fix, &b.did).await.is_some(),
        "nothing without the gesture"
    );

    let (status, reply) = submit(&mut fix, &a, &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &b.did).await.is_none(), "landed at once");

    let rows = immediate_rows(&fix).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].requirement.as_deref(), Some("VTI-APV-019"));
    assert_eq!(rows[0].task.as_deref(), Some(REVOKE));
    assert!(rows[0].resource.is_none(), "landed no cooling-off");
    assert_eq!(unopposed_rows(&fix).await, 1);
    let told = notices(&b.did);
    assert_eq!(told.len(), 1, "{told:?}");
    assert_eq!(told[0]["agreement"], "unopposed");

    // In the history, marked as landed now.
    let (_, listed) = post(
        &fix.vtc,
        &signed(&a, LIST, json!({ "view": "history" })).await,
    )
    .await;
    let landed = listed["payload"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["typeUri"] == REVOKE)
        .unwrap_or_else(|| panic!("in the history: {listed}"))
        .clone();
    assert_eq!(landed["status"], "completed");
    assert_eq!(
        landed["ext"]["org.openvtc"]["landedNow"]["by"],
        a.did.as_str(),
        "{landed}"
    );
}

/// Without single-administrator mode, "now" is refused before any gesture,
/// naming the cooling-off and that the mode is set on the host.
#[tokio::test]
async fn remove_now_refused_when_mode_off() {
    let mut fix = fixture(false).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, reply) = post(&fix.vtc, &revoke_now(&a, &b, &b.did, None).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(
        step_up_request(&reply).is_none(),
        "no gesture asked: {reply}"
    );
    let text = reply.to_string();
    assert!(text.contains("single-administrator mode"), "{reply}");
    assert!(text.contains("single_admin_mode"), "host-set: {reply}");
    assert!(text.contains("acl.removal_cooling_off"), "{reply}");
    assert!(entry(&fix, &b.did).await.is_some());
    assert!(immediate_rows(&fix).await.is_empty());
    let _ = &mut fix;
}

/// A confirmation that is neither the subject's DID nor the action's id is
/// refused before the gesture: a slip costs nothing.
#[tokio::test]
async fn remove_now_refused_on_wrong_confirmation() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let other = Party::new();
    let (status, reply) = post(&fix.vtc, &revoke_now(&a, &b, &other.did, None).await).await;
    assert!(!status.is_success(), "{reply}");
    assert!(
        step_up_request(&reply).is_none(),
        "no gesture asked: {reply}"
    );
    assert!(
        reply.to_string().contains("confirmation does not match"),
        "{reply}"
    );
    assert!(entry(&fix, &b.did).await.is_some());

    // Malformed: refused, never read as the delayed removal.
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            REVOKE,
            json!({ "subject": b.did, "ext": { "org.openvtc": { "immediate": true } } }),
        )
        .await,
    )
    .await;
    assert!(!status.is_success(), "{reply}");
    assert!(parked_action(&reply).is_none(), "{reply}");
    assert!(entry(&fix, &b.did).await.is_some());
}

/// The gesture is bound to the exact operation (VTI-APV-015): one made for
/// the delayed removal is not spent on the immediate one, and one made for
/// the immediate removal is not spent on the delayed one.
#[tokio::test]
async fn remove_now_gesture_not_spendable_on_delayed_removal_and_vice_versa() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;

    // A gesture for the delayed removal...
    let delayed = signed(&a, REVOKE, json!({ "subject": b.did, "reason": "one" })).await;
    let (_, asked) = post(&fix.vtc, &delayed).await;
    fix.gesturer.gesture(&fix.vtc, &a, &asked).await;
    // ...does not admit the immediate one.
    let immediate = signed(
        &a,
        REVOKE,
        json!({ "subject": b.did, "reason": "one",
                "ext": { "org.openvtc": { "immediate": { "confirm": b.did } } } }),
    )
    .await;
    let (_, reply) = post(&fix.vtc, &immediate).await;
    assert!(step_up_request(&reply).is_some(), "asked again: {reply}");
    assert!(entry(&fix, &b.did).await.is_some());

    // A gesture for the immediate removal...
    let immediate = signed(
        &a,
        REVOKE,
        json!({ "subject": b.did, "reason": "two",
                "ext": { "org.openvtc": { "immediate": { "confirm": b.did } } } }),
    )
    .await;
    let (_, asked) = post(&fix.vtc, &immediate).await;
    fix.gesturer.gesture(&fix.vtc, &a, &asked).await;
    // ...does not admit the delayed one: it asks again rather than parking.
    let delayed = signed(&a, REVOKE, json!({ "subject": b.did, "reason": "two" })).await;
    let (_, reply) = post(&fix.vtc, &delayed).await;
    assert!(step_up_request(&reply).is_some(), "asked again: {reply}");
    assert!(parked_action(&reply).is_none(), "{reply}");
    assert!(entry(&fix, &b.did).await.is_some());
    assert!(!entry(&fix, &b.did).await.unwrap().is_suspended());
}

/// "Land now" on an open cooling-off: the same operation, sent again with
/// `immediate` naming the action and its id typed as confirmation, lands it
/// now — the action closes `landedAfterCoolingOff`, marked landed now, and
/// the subject's suspension ends with its entry. A different operation
/// cannot borrow the action's id.
#[tokio::test]
async fn land_now_on_open_cooling_off() {
    let mut fix = fixture(true).await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let id = cool_off(&mut fix, &a, &b).await;
    assert!(entry(&fix, &b.did).await.unwrap().is_suspended());

    // Not the operation that is cooling off.
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            REVOKE,
            json!({ "subject": b.did, "reason": "different",
                    "ext": { "org.openvtc": { "immediate": { "confirm": id, "actionId": id } } } }),
        )
        .await,
    )
    .await;
    assert!(!status.is_success(), "{reply}");
    assert!(step_up_request(&reply).is_none(), "{reply}");
    assert!(reply.to_string().contains("different operation"), "{reply}");

    let (status, reply) = submit(&mut fix, &a, &revoke_now(&a, &b, &id, Some(&id)).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &b.did).await.is_none(), "landed now");
    assert!(
        vtc_service::acl::storage::get_suspension(&fix.vtc.state.acl_ks, &b.did)
            .await
            .unwrap()
            .is_none()
    );
    let done = show_v0_2(&fix, &a, &id).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["closedReason"], "landedAfterCoolingOff", "{done}");
    assert_eq!(
        done["ext"]["org.openvtc"]["landedNow"]["by"],
        a.did.as_str()
    );
    let rows = immediate_rows(&fix).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].resource.as_deref(), Some(id.as_str()), "names it");
    assert_eq!(unopposed_rows(&fix).await, 1);
}
