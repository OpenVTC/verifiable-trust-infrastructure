//! **VTI-ACL-052** — a subject modifying its own entry, through the router.
//!
//! > A subject MUST NOT modify its own entry, except: 1. by the self-service
//! > rotation; 2. to change the entry's human-readable label and nothing else
//! > […]; or 3. in single-administrator mode (VTI-APV-022), where the
//! > subject's entry has unrestricted act scope […].
//!
//! Item 1 is `acl/swap-key` (`rotation.rs`). Items 2 and 3 are here, on the
//! `acl/update` doors at 0.1 and 0.2 and on `vtc/members/update`; the same
//! decision over DIDComm and TSP is `trust_tasks::acl_tasks` tests.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_common::audit::{AuditEvent, AuditSeverity};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{
    AdminAuthority, AdminRole, VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry,
};
use vtc_service::test_support::TestVtc;

use crate::common::second_party::{Gesturer, parked_action, step_up_request};
use crate::common::signed::{post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.2";
const UPDATE_V0_1: &str = "https://trusttasks.org/spec/acl/update/0.1";
const SHOW: &str = "https://trusttasks.org/spec/acl/show/0.2";
const GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const MEMBER_UPDATE: &str = "https://trusttasks.org/spec/vtc/members/update/0.1";

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
    vtc.state.config.write().await.acl.single_admin_mode = single_admin_mode;
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

async fn seed(fix: &Fixture, admin: AdminAuthority) -> Party {
    let party = Party::new();
    let role = if admin.admin_role == Some(AdminRole::CommunityAdmin) {
        VtcRole::Admin
    } else {
        VtcRole::Member
    };
    let mut e = VtcAclEntry::new(party.did.clone(), role, admin, "did:key:vtc-install");
    e.created_at = 0;
    store_acl_entry(&fix.vtc.state.acl_ks, &e).await.unwrap();
    party
}

/// A community administrator with the full ceiling — unrestricted.
async fn admin(fix: &Fixture) -> Party {
    seed(fix, AdminAuthority::community_admin()).await
}

/// A community administrator with a passkey to make a gesture.
async fn admin_with_passkey(fix: &mut Fixture) -> Party {
    let p = admin(fix).await;
    fix.gesturer.enrol(&fix.vtc, &p.did).await;
    p
}

async fn entry(fix: &Fixture, did: &str) -> VtcAclEntry {
    get_acl_entry(&fix.vtc.state.acl_ks, did)
        .await
        .unwrap()
        .expect("entry")
}

/// Send `doc` as `by`, answering the gesture it asks for; the reply after.
async fn submit(fix: &mut Fixture, by: &Party, doc: &Value) -> (StatusCode, Value) {
    let (status, reply) = post(&fix.vtc, doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, doc).await
}

async fn audit_rows(fix: &Fixture) -> Vec<AuditEvent> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .map(|env| env.event)
        .collect()
}

/// The `SingleAdminMode` rows recording a self-edit (VTI-ACL-052 item 3).
async fn self_edit_rows(fix: &Fixture) -> Vec<vti_common::audit::SingleAdminModeData> {
    audit_rows(fix)
        .await
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::SingleAdminMode(d) if d.event == "selfEditWaived" => {
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

fn message(reply: &Value) -> String {
    reply["payload"]["message"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| reply.to_string())
}

/// Narrow the approve axis: the entry keeps unrestricted act scope (a
/// `community-admin`, acting everywhere, full ceiling).
fn narrow_approve(subject: &str) -> Value {
    json!({
        "subject": subject,
        "approve": { "scope": "none" },
        "approveCapabilities": { "scope": "none" },
    })
}

// ─── item 2: the label ───────────────────────────────────────────────────

/// VTI-ACL-052 item 2: a subject changes its own label, with no gesture and
/// in any mode. The change is audited as self-set, the entry carries the mark,
/// and another administrator reading it is shown the label as self-set.
#[tokio::test]
async fn vti_acl_052_subject_may_relabel_own_entry() {
    let fix = fixture(false).await;
    let a = admin(&fix).await;
    let b = admin(&fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            UPDATE,
            json!({ "subject": a.did, "label": "Glenn's laptop" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let after = entry(&fix, &a.did).await;
    assert_eq!(after.label.as_deref(), Some("Glenn's laptop"));
    assert!(after.label_set_by_subject);
    assert_eq!(
        after.admin,
        AdminAuthority::community_admin(),
        "nothing else"
    );

    let row = audit_rows(&fix)
        .await
        .into_iter()
        .find_map(|e| match e {
            AuditEvent::MemberUpdated(d) => Some(d),
            _ => None,
        })
        .expect("the change is audited");
    assert!(row.fields_changed.contains(&"label".to_string()), "{row:?}");
    assert!(
        row.changes
            .iter()
            .any(|c| c.field == "labelSetBySubject" && c.new == Some(json!(true))),
        "{row:?}"
    );

    let (status, reply) = post(
        &fix.vtc,
        &signed(&b, SHOW, json!({ "subject": a.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["payload"]["entry"]["ext"]["org.openvtc"]["labelSetBySubject"], true,
        "shown to another party as self-set: {reply}"
    );
}

/// VTI-ACL-052 item 2 on `acl/update/0.1` and `vtc/members/update`: the same
/// decision on every door that can write the label.
#[tokio::test]
async fn vti_acl_052_subject_may_relabel_own_entry_on_every_door() {
    let fix = fixture(false).await;
    let a = admin(&fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            UPDATE_V0_1,
            json!({ "subject": a.did, "label": "phone" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(entry(&fix, &a.did).await.label.as_deref(), Some("phone"));
    assert!(entry(&fix, &a.did).await.label_set_by_subject);

    vtc_service::members::store_member(
        &fix.vtc.state.members_ks,
        &vtc_service::members::Member::fresh(a.did.clone()),
    )
    .await
    .unwrap();
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            MEMBER_UPDATE,
            json!({ "did": a.did, "label": "tablet" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let after = entry(&fix, &a.did).await;
    assert_eq!(after.label.as_deref(), Some("tablet"));
    assert!(after.label_set_by_subject);

    // The role is still refused there, saying the label is what is allowed.
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, MEMBER_UPDATE, json!({ "did": a.did, "role": "member" })).await,
    )
    .await;
    assert!(!status.is_success(), "{reply}");
}

/// Another administrator setting the label clears the self-set mark.
#[tokio::test]
async fn vti_acl_052_a_label_set_by_another_is_not_self_set() {
    let mut fix = fixture(false).await;
    let a = admin(&fix).await;
    let b = admin_with_passkey(&mut fix).await;
    post(
        &fix.vtc,
        &signed(&a, UPDATE, json!({ "subject": a.did, "label": "mine" })).await,
    )
    .await;
    assert!(entry(&fix, &a.did).await.label_set_by_subject);
    let (status, reply) = submit(
        &mut fix,
        &b,
        &signed(&b, UPDATE, json!({ "subject": a.did, "label": "theirs" })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let after = entry(&fix, &a.did).await;
    assert_eq!(after.label.as_deref(), Some("theirs"));
    assert!(!after.label_set_by_subject);
}

/// VTI-ACL-052: a label change carrying any other change is refused whole,
/// and the refusal says what the subject may do.
#[tokio::test]
async fn vti_acl_052_label_with_other_field_refused() {
    let fix = fixture(false).await;
    let a = admin(&fix).await;
    let mut payload = narrow_approve(&a.did);
    payload["label"] = json!("sneaky");
    let (status, reply) = post(&fix.vtc, &signed(&a, UPDATE, payload).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(message(&reply).contains("label yourself"), "{reply}");
    let after = entry(&fix, &a.did).await;
    assert_eq!(after.label, None);
    assert_eq!(after.admin, AdminAuthority::community_admin());
}

// ─── item 3: single-administrator mode ───────────────────────────────────

/// VTI-ACL-052 item 3: in single-administrator mode an administrator whose
/// entry is unrestricted edits its own entry — even beside another
/// unrestricted administrator (one person, many identifiers, VTI-APV-022) —
/// on its gesture bound to the operation, audited at `Critical`.
#[tokio::test]
async fn vti_acl_052_single_admin_unrestricted_may_edit_self_with_step_up() {
    let mut fix = fixture(true).await;
    let a = admin_with_passkey(&mut fix).await;
    let _b = admin(&fix).await;
    let doc = signed(&a, UPDATE, narrow_approve(&a.did)).await;
    let (status, reply) = submit(&mut fix, &a, &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(parked_action(&reply).is_none(), "{reply}");
    let after = entry(&fix, &a.did).await;
    assert!(!after.admin.approve.is_all(), "written: {after:?}");
    let rows = self_edit_rows(&fix).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].requirement.as_deref(), Some("VTI-ACL-052"));
    assert_eq!(rows[0].task.as_deref(), Some(UPDATE));
    assert!(rows[0].digest.is_some());
}

/// VTI-ACL-052 item 3: the gesture is required — without it nothing is
/// written and nothing is recorded as done.
#[tokio::test]
async fn vti_acl_052_single_admin_self_edit_refused_without_step_up() {
    let mut fix = fixture(true).await;
    let a = admin_with_passkey(&mut fix).await;
    let (status, reply) = post(&fix.vtc, &signed(&a, UPDATE, narrow_approve(&a.did)).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(step_up_request(&reply).is_some(), "asks for one: {reply}");
    assert!(entry(&fix, &a.did).await.admin.approve.is_all());
    assert!(self_edit_rows(&fix).await.is_empty());
}

/// VTI-ACL-052 item 3: an edit that would leave no entry with unrestricted
/// act scope is refused — and allowed once another such entry exists.
#[tokio::test]
async fn vti_acl_052_single_admin_self_edit_refused_when_it_leaves_no_unrestricted_entry() {
    let mut fix = fixture(true).await;
    let a = admin_with_passkey(&mut fix).await;
    let narrow = json!({
        "subject": a.did,
        "capabilities": { "scope": "listed", "grants": [{ "capability": "vtc.members.manage" }] },
    });
    let (status, reply) = submit(&mut fix, &a, &signed(&a, UPDATE, narrow.clone()).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(
        message(&reply).contains("no entry holding unrestricted act scope"),
        "{reply}"
    );
    assert_eq!(
        entry(&fix, &a.did).await.admin,
        AdminAuthority::community_admin()
    );
    assert!(self_edit_rows(&fix).await.is_empty());

    // An expiry would end the only one too.
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            UPDATE,
            json!({ "subject": a.did, "expiresAt": "2099-01-01T00:00:00Z" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(entry(&fix, &a.did).await.expires_at, None);

    // With another unrestricted entry, the same narrowing leaves one.
    let _b = admin(&fix).await;
    let (status, reply) = submit(&mut fix, &a, &signed(&a, UPDATE, narrow).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_ne!(
        entry(&fix, &a.did).await.admin,
        AdminAuthority::community_admin()
    );
    assert_eq!(self_edit_rows(&fix).await.len(), 1);
}

/// VTI-ACL-052: outside single-administrator mode a subject's own entry is
/// refused beyond its label, as before — another administrator makes it.
#[tokio::test]
async fn vti_acl_052_single_admin_self_edit_refused_when_mode_off() {
    let mut fix = fixture(false).await;
    let a = admin_with_passkey(&mut fix).await;
    let _b = admin(&fix).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, UPDATE, narrow_approve(&a.did)).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(
        step_up_request(&reply).is_none(),
        "refused before any gesture"
    );
    assert!(message(&reply).contains("label yourself"), "{reply}");
    assert!(entry(&fix, &a.did).await.admin.approve.is_all());
}

/// VTI-ACL-052 item 3 applies only to an entry with unrestricted act scope: a
/// moderator in single-administrator mode is refused, as before.
#[tokio::test]
async fn vti_acl_052_single_admin_self_edit_refused_when_subject_not_unrestricted() {
    let mut fix = fixture(true).await;
    let _a = admin(&fix).await;
    let m = seed(&fix, AdminAuthority::for_role(AdminRole::Moderator)).await;
    fix.gesturer.enrol(&fix.vtc, &m.did).await;
    let (status, reply) = submit(
        &mut fix,
        &m,
        &signed(&m, UPDATE, narrow_approve(&m.did)).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(message(&reply).contains("yours is not"), "{reply}");
    assert!(self_edit_rows(&fix).await.is_empty());
}

// ─── VTI-APV-022: one person, many identifiers ──────────────────────────

/// VTI-APV-022: the mode waives second-party consent whether or not other
/// administrators' entries exist — another administrator's entry is no second
/// party, so an authority-conferring grant runs on the requester's gesture.
#[tokio::test]
async fn vti_apv_022_consent_is_waived_beside_other_administrators() {
    let mut fix = fixture(true).await;
    let a = admin_with_passkey(&mut fix).await;
    let _b = admin(&fix).await;
    let subject = Party::new();
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(
            &a,
            GRANT,
            json!({ "entry": { "subject": subject.did, "role": "admin", "scopes": [] } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "executes at once: {reply}");
    assert!(parked_action(&reply).is_none(), "{reply}");
    assert!(entry(&fix, &subject.did).await.is_community_admin());
    let waived = audit_rows(&fix)
        .await
        .into_iter()
        .filter(|e| matches!(e, AuditEvent::SingleAdminMode(d) if d.event == "consentWaived"))
        .count();
    assert_eq!(waived, 1);
}

/// VTI-APV-022 / VTI-APV-019: in the mode a reduction of another administrator
/// is not parked for a third party's consent even where one exists; it keeps
/// the unopposed path's cooling-off, a delay rather than a consent.
#[tokio::test]
async fn vti_apv_022_a_reduction_cools_off_instead_of_waiting_for_consent() {
    let mut fix = fixture(true).await;
    let a = admin_with_passkey(&mut fix).await;
    let b = admin(&fix).await;
    let _c = admin(&fix).await;
    let (status, reply) = submit(
        &mut fix,
        &a,
        &signed(&a, REVOKE, json!({ "subject": b.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "cooling off: {reply}");
    let id = parked_action(&reply).expect("parked");
    assert!(
        reply.to_string().contains("coolingOffUntil"),
        "a cooling-off, not a consent: {reply}"
    );
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &b.did)
            .await
            .unwrap()
            .is_some()
    );

    // And it lands when the cooling-off ends, the third administrator's entry
    // notwithstanding.
    let key = format!("action:{id}");
    let mut rec: vtc_service::admin_actions::ActionRecord = fix
        .vtc
        .state
        .admin_actions_ks
        .get(key.clone())
        .await
        .unwrap()
        .expect("stored");
    rec.cooling_off_until = Some(1);
    fix.vtc
        .state
        .admin_actions_ks
        .insert(key, &rec)
        .await
        .unwrap();
    vtc_service::admin_actions::sweep_once(&fix.vtc.state)
        .await
        .unwrap();
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &b.did)
            .await
            .unwrap()
            .is_none(),
        "landed: {:?}",
        fix.vtc
            .state
            .admin_actions_ks
            .get::<vtc_service::admin_actions::ActionRecord>(format!("action:{id}"))
            .await
            .unwrap()
            .map(|r| (r.status, r.closed_message))
    );
}
