//! The stop-gaps that keep one administrator from undoing VTI-APV-014 one step
//! at a time (`docs/05-design-notes/vtc-action-list.md` §7b, §8.1):
//!
//! 1. **VTI-APV-019** — removing, demoting or narrowing an administrator takes
//!    the requester's operation-bound passkey gesture; ending *another*
//!    unrestricted admin's authority also takes the consent of an unrestricted
//!    admin who is neither the requester nor the subject. With nobody else left
//!    (two unrestricted admins in all) the gesture suffices, and the act is
//!    audited at `Critical` with the subject told.
//! 2. **VTI-APV-020** — lowering `acl.unrestricted_admin_consent_threshold`, by
//!    `config/patch` or `vtc/config/import`, takes consent at the threshold as
//!    it stands. Raising it stays immediate.
//! 3. **VTI-VTC-022** — `policy/upsert` and `policy/activate` are for an
//!    unrestricted admin only, and a purpose that decides authority also takes
//!    the gesture and another unrestricted admin's consent.
//! 4. `vtc/members/admin-remove` checks the actor covers the subject's entry,
//!    as `acl/revoke` does (VTI-ACL-050).

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::test_support::TestVtc;

use crate::common::second_party::{
    Gesturer, decide, decision_payload, parked_action, show_action, step_up_request,
};
use crate::common::signed::{error_code, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.1";
const CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
const ADMIN_REMOVE: &str = "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";
const PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const IMPORT: &str = "https://trusttasks.org/spec/vtc/config/import/0.1";
const EXPORT: &str = "https://trusttasks.org/spec/vtc/config/export/0.1";
const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";
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
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        vtc_service::status_list::ensure_initial(
            &vtc.state.status_lists_ks,
            purpose,
            format!("{RP_ORIGIN}/v1/status-lists/{purpose}"),
        )
        .await
        .unwrap();
    }
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
        resource_grants: Vec::new(),
    }
}

async fn seed(fix: &Fixture, role: VtcRole, scopes: &[&str]) -> Party {
    let party = Party::new();
    store_acl_entry(&fix.vtc.state.acl_ks, &row(&party.did, role, scopes))
        .await
        .unwrap();
    party
}

/// An unrestricted admin with no passkey — enough to be removed, or to consent.
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

/// Every audit row of `variant`, with its severity.
async fn audit_rows(fix: &Fixture, variant: &str) -> Vec<vti_common::audit::AuditSeverity> {
    fix.vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter(|env| env.event.variant_name() == variant)
        .map(|env| env.event.severity())
        .collect()
}

fn assert_step_up(status: StatusCode, reply: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(error_code(reply), Some("permissionDenied"), "{reply}");
    assert!(
        step_up_request(reply).is_some(),
        "the refusal carries the ceremony: {reply}"
    );
}

/// The operation was parked for approval (VTI-APV-017): its action's id.
fn assert_parked(status: StatusCode, reply: &Value) -> String {
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    parked_action(reply).unwrap_or_else(|| panic!("parked as an action: {reply}"))
}

/// The action as `who` sees it.
async fn action(fix: &Fixture, who: &Party, id: &str) -> Value {
    let (status, reply) = show_action(&fix.vtc, who, id).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["payload"]["action"].clone()
}

// ─── 1. VTI-APV-019: removing, demoting, narrowing an administrator ─────────

/// Removing another unrestricted admin needs the requester's gesture, then the
/// consent of an admin who is neither party. The subject's own approval does
/// not count.
#[tokio::test]
async fn vti_apv_019_removing_an_unrestricted_admin_needs_a_third_party() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let subject = admin(&fix).await;
    let third = admin(&fix).await;
    let revoke = signed(&a, REVOKE, json!({ "subject": subject.did })).await;

    // Without the gesture: refused, nothing removed.
    let (status, reply) = post(&fix.vtc, &revoke).await;
    assert_step_up(status, &reply);
    assert!(entry(&fix, &subject.did).await.is_some());
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;

    // With it: parked for somebody other than the subject.
    let (status, reply) = post(&fix.vtc, &revoke).await;
    let id = assert_parked(status, &reply);
    assert!(
        entry(&fix, &subject.did).await.is_some(),
        "nothing removed yet"
    );
    let theirs = action(&fix, &third, &id).await;
    assert_eq!(theirs["callerRole"], "approver", "{theirs}");
    assert!(theirs["challenge"].is_string(), "{theirs}");
    let subjects = action(&fix, &subject, &id).await;
    assert_eq!(
        subjects["callerRole"], "observer",
        "the subject is never asked"
    );
    assert!(subjects.get("challenge").is_none(), "{subjects}");

    // The subject answering with the approver's challenge is refused.
    let stolen = signed(
        &subject,
        "https://trusttasks.org/spec/task-consent/decision/0.2",
        decision_payload(&theirs, "approve"),
    )
    .await;
    let (_, refused) = post(&fix.vtc, &stolen).await;
    assert_eq!(
        error_code(&refused),
        Some("task-consent/decision:notAnApprover"),
        "{refused}"
    );

    let (status, ack) = decide(&fix.vtc, &third, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    assert!(
        entry(&fix, &subject.did).await.is_none(),
        "removed on approval"
    );
    assert_eq!(action(&fix, &a, &id).await["status"], "completed");
    assert!(
        audit_rows(&fix, "AuthorityReducedUnopposed")
            .await
            .is_empty(),
        "a consented removal is not an unopposed one"
    );
}

/// The two-admin rule: with nobody but requester and subject, the requester's
/// gesture is enough — a compromised co-admin must stay removable — after a
/// cooling-off both can see (`vtc-action-list.md` §8.2), and the removal is
/// audited at `Critical` when it lands. The cooling-off itself is
/// `action_list_a2.rs`; here it is set to zero.
#[tokio::test]
async fn vti_apv_019_a_two_admin_removal_takes_the_step_up_and_is_audited_critical() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &a,
            PATCH,
            json!({ "overrides": { "acl.removal_cooling_off": 0 } }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let revoke = signed(&a, REVOKE, json!({ "subject": b.did })).await;

    let (status, reply) = post(&fix.vtc, &revoke).await;
    assert_step_up(status, &reply);
    assert!(entry(&fix, &b.did).await.is_some());

    let (status, reply) = fix.gesturer.send_through(&fix.vtc, &a, &[], &revoke).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &b.did).await.is_none());
    assert_eq!(
        audit_rows(&fix, "AuthorityReducedUnopposed").await,
        vec![vti_common::audit::AuditSeverity::Critical],
        "exactly one Critical row"
    );
}

/// A scoped admin's removal takes the gesture and nothing else; a
/// non-admin's takes neither.
#[tokio::test]
async fn vti_apv_019_removing_a_scoped_admin_takes_the_gesture_and_a_non_admin_nothing() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let scoped = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    let moderator = seed(&fix, VtcRole::Moderator, &["ctx-a"]).await;

    let revoke = signed(&a, REVOKE, json!({ "subject": scoped.did })).await;
    let (status, reply) = post(&fix.vtc, &revoke).await;
    assert_step_up(status, &reply);
    let (status, reply) = fix.gesturer.send_through(&fix.vtc, &a, &[], &revoke).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &scoped.did).await.is_none());

    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, REVOKE, json!({ "subject": moderator.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unchanged for a non-admin: {reply}");
}

/// An expired admin entry is not authority any more; removing it is unchanged.
#[tokio::test]
async fn vti_apv_019_removing_an_expired_admin_is_unchanged() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let lapsed = Party::new();
    let mut r = row(&lapsed.did, VtcRole::Admin, &[]);
    r.expires_at = Some(1);
    store_acl_entry(&fix.vtc.state.acl_ks, &r).await.unwrap();
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, REVOKE, json!({ "subject": lapsed.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

/// A demotion through `acl/change-role` is a reduction: the gesture, then a
/// third party's consent for an unrestricted subject.
#[tokio::test]
async fn vti_apv_019_demoting_an_unrestricted_admin_needs_a_third_party() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let subject = admin(&fix).await;
    let third = admin(&fix).await;
    let demote = signed(
        &a,
        CHANGE_ROLE,
        json!({ "subject": subject.did, "fromRole": "admin", "toRole": "member" }),
    )
    .await;

    let (status, reply) = post(&fix.vtc, &demote).await;
    assert_step_up(status, &reply);
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;
    let (status, reply) = post(&fix.vtc, &demote).await;
    let id = assert_parked(status, &reply);
    assert_eq!(
        entry(&fix, &subject.did).await.unwrap().role,
        VtcRole::Admin
    );

    let (status, ack) = decide(&fix.vtc, &third, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(
        entry(&fix, &subject.did).await.unwrap().role,
        VtcRole::Member
    );
}

/// Narrowing an unrestricted admin — here, putting an expiry on a permanent
/// entry with `acl/update` — is a reduction too.
#[tokio::test]
async fn vti_apv_019_narrowing_an_unrestricted_admin_needs_a_third_party() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let subject = admin(&fix).await;
    let third = admin(&fix).await;
    let narrow = signed(
        &a,
        UPDATE,
        json!({ "subject": subject.did, "expiresAt": "2099-01-01T00:00:00Z" }),
    )
    .await;

    let (status, reply) = post(&fix.vtc, &narrow).await;
    assert_step_up(status, &reply);
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;
    let (status, reply) = post(&fix.vtc, &narrow).await;
    let id = assert_parked(status, &reply);
    assert_eq!(entry(&fix, &subject.did).await.unwrap().expires_at, None);

    let (status, ack) = decide(&fix.vtc, &third, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(
        entry(&fix, &subject.did)
            .await
            .unwrap()
            .expires_at
            .is_some()
    );
}

/// `vtc/members/admin-remove` of an administrator takes the gesture too. The
/// default removal policy refuses removing an admin outright, so this
/// community has activated one that allows it — which is exactly the case
/// where the host's own gate is all that is left.
#[tokio::test]
async fn vti_apv_019_admin_remove_of_an_admin_takes_the_gesture() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&a.did))
        .await
        .unwrap();
    let target = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&target.did))
        .await
        .unwrap();
    allow_every_removal(&fix).await;

    let remove = signed(&a, ADMIN_REMOVE, json!({ "did": target.did })).await;
    let (status, reply) = post(&fix.vtc, &remove).await;
    assert_step_up(status, &reply);
    assert!(entry(&fix, &target.did).await.is_some(), "nothing removed");

    let (status, reply) = fix.gesturer.send_through(&fix.vtc, &a, &[], &remove).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &target.did).await.is_none());
}

/// Activate a removal policy that allows every removal, straight into the
/// store — the way a community that replaced the default would hold it.
async fn allow_every_removal(fix: &Fixture) {
    use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    let src = "package vtc.removal\nimport rego.v1\n\
               default decision := {\"effect\": \"allow\", \"with\": {\"disposition\": \"tombstone\"}}\n";
    let id = uuid::Uuid::new_v4();
    let sha: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(src.as_bytes()).into()
    };
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::Removal,
            rego_source: src.into(),
            sha256: sha,
            activated_at: Some(chrono::Utc::now()),
            author_did: "did:key:test".into(),
            created_at: chrono::Utc::now(),
            version: 99,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(
        &fix.vtc.state.active_policies_ks,
        PolicyPurpose::Removal,
        id,
    )
    .await
    .unwrap();
}

// ─── 4. admin-remove checks cover (VTI-ACL-050) ────────────────────────────

/// A moderator — `vtc.members.manage`, no `vtc.roles.assign` — cannot remove
/// a member who holds administrative authority, which only a holder of
/// `vtc.roles.assign` covering it may touch: the check `acl/revoke` has always
/// made, now on this verb too.
#[tokio::test]
async fn vti_acl_050_admin_remove_refuses_a_subject_the_actor_does_not_cover() {
    let fix = fixture().await;
    let scoped = seed(&fix, VtcRole::Moderator, &[]).await;
    let straddler = seed(&fix, VtcRole::Moderator, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&straddler.did))
        .await
        .unwrap();

    let (status, reply) = post(
        &fix.vtc,
        &signed(&scoped, ADMIN_REMOVE, json!({ "did": straddler.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(error_code(&reply), Some("permissionDenied"), "{reply}");
    assert!(entry(&fix, &straddler.did).await.is_some());
    assert!(
        !get_member(&fix.vtc.state.members_ks, &straddler.did)
            .await
            .unwrap()
            .unwrap()
            .is_removed()
    );

    // A member holding no administrative authority is still the actor's to
    // remove, policy permitting.
    let inside = seed(&fix, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&inside.did))
        .await
        .unwrap();
    let (status, reply) = post(
        &fix.vtc,
        &signed(&scoped, ADMIN_REMOVE, json!({ "did": inside.did })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

// ─── 2. VTI-APV-020: lowering the consent threshold ────────────────────────

/// Three unrestricted admins with the threshold raised to 2. Raising takes no
/// gesture and no consent.
async fn threshold_two(fix: &mut Fixture) -> (Party, Party, Party) {
    let a = requester(fix).await;
    let b = admin(fix).await;
    let c = admin(fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, PATCH, json!({ "overrides": { THRESHOLD_KEY: 2 } })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "raising is immediate: {reply}");
    assert_eq!(reply["payload"]["applied"][0], THRESHOLD_KEY, "{reply}");
    (a, b, c)
}

async fn live_threshold(fix: &Fixture) -> u64 {
    vtc_service::acl::admin_consent::threshold(&fix.vtc.state)
        .await
        .unwrap()
}

#[tokio::test]
async fn vti_apv_020_lowering_the_threshold_needs_consent_at_the_current_threshold() {
    let mut fix = fixture().await;
    let (a, b, c) = threshold_two(&mut fix).await;
    let lower = signed(&a, PATCH, json!({ "overrides": { THRESHOLD_KEY: 1 } })).await;

    let (status, reply) = post(&fix.vtc, &lower).await;
    assert_step_up(status, &reply);
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;

    let (status, reply) = post(&fix.vtc, &lower).await;
    let id = assert_parked(status, &reply);
    assert_eq!(
        action(&fix, &a, &id).await["threshold"],
        2,
        "N is the threshold as it stands"
    );
    assert_eq!(live_threshold(&fix).await, 2, "nothing written yet");

    // One approval of two is not enough.
    let (_, ack) = decide(&fix.vtc, &b, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "pending", "{ack}");
    assert_eq!(live_threshold(&fix).await, 2);

    let (_, ack) = decide(&fix.vtc, &c, &id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    let done = action(&fix, &a, &id).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        done["ext"]["org.openvtc"]["result"]["applied"][0], THRESHOLD_KEY,
        "{done}"
    );
    assert_eq!(live_threshold(&fix).await, 1);
}

/// An import that lowers the threshold takes the same gate on apply; a
/// preview writes nothing and asks nothing.
#[tokio::test]
async fn vti_apv_020_an_import_lowering_the_threshold_needs_consent() {
    let mut fix = fixture().await;
    let (a, b, c) = threshold_two(&mut fix).await;

    let (status, exported) = post(&fix.vtc, &signed(&a, EXPORT, json!({})).await).await;
    assert_eq!(status, StatusCode::OK, "{exported}");
    let mut document = exported["payload"]["document"].clone();
    document["configOverrides"][THRESHOLD_KEY] = json!(1);

    let (status, preview) = post(
        &fix.vtc,
        &signed(
            &a,
            IMPORT,
            json!({ "document": document, "confirm": false }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a preview asks nothing: {preview}");

    let apply = signed(&a, IMPORT, json!({ "document": document, "confirm": true })).await;
    let (status, reply) = post(&fix.vtc, &apply).await;
    assert_step_up(status, &reply);
    assert_eq!(live_threshold(&fix).await, 2);

    let (status, reply) = fix
        .gesturer
        .send_through(&fix.vtc, &a, &[&b, &c], &apply)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(live_threshold(&fix).await, 1);
}

// ─── 3. VTI-VTC-022: policy is role-gated ──────────────────────────────────

fn module(purpose: &str, source: &str) -> Value {
    json!({ "name": purpose, "module": source, "ext": { "org.openvtc.purpose": purpose } })
}

const REMOVAL_POLICY: &str = "package vtc.removal\nimport rego.v1\n\
    default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n";
const DIRECTORY_POLICY: &str = "package vtc.directory\nimport rego.v1\n\
    default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"closed\"}}\n";

/// A scoped admin can no longer replace or activate any policy.
#[tokio::test]
async fn vti_vtc_022_a_scoped_admin_cannot_change_policy() {
    let fix = fixture().await;
    let scoped = seed(&fix, VtcRole::Admin, &["ctx-a"]).await;
    for purpose_module in [
        module("directory", DIRECTORY_POLICY),
        module("removal", REMOVAL_POLICY),
    ] {
        let (status, reply) = post(&fix.vtc, &signed(&scoped, UPSERT, purpose_module).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
        assert_eq!(error_code(&reply), Some("permissionDenied"), "{reply}");
    }
    let active = vtc_service::policy::get_active_policy_id(
        &fix.vtc.state.active_policies_ks,
        vtc_service::policy::PolicyPurpose::Removal,
    )
    .await
    .unwrap()
    .unwrap();
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &scoped,
            ACTIVATE,
            json!({ "id": active.to_string(), "purpose": "removal" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
}

/// A policy that decides authority — here, removal — takes the gesture and
/// another unrestricted admin's consent to upload, and again to activate.
#[tokio::test]
async fn vti_vtc_022_an_authority_policy_needs_a_second_party() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = admin(&fix).await;

    let upload = signed(&a, UPSERT, module("removal", REMOVAL_POLICY)).await;
    let (status, reply) = post(&fix.vtc, &upload).await;
    assert_step_up(status, &reply);
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;
    let (status, reply) = post(&fix.vtc, &upload).await;
    let action_id = assert_parked(status, &reply);
    let (_, ack) = decide(&fix.vtc, &b, &action_id, "approve").await;
    assert_eq!(ack["payload"]["status"], "granted", "{ack}");
    let done = action(&fix, &a, &action_id).await;
    assert_eq!(done["status"], "completed", "{done}");
    let id = done["ext"]["org.openvtc"]["result"]["policy"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let activate = signed(&a, ACTIVATE, json!({ "id": id, "purpose": "removal" })).await;
    let (status, reply) = post(&fix.vtc, &activate).await;
    assert_step_up(status, &reply);
    let (status, reply) = fix
        .gesturer
        .send_through(&fix.vtc, &a, &[&b], &activate)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        vtc_service::policy::get_active_policy_id(
            &fix.vtc.state.active_policies_ks,
            vtc_service::policy::PolicyPurpose::Removal,
        )
        .await
        .unwrap()
        .map(|u| u.to_string()),
        Some(id)
    );
}

/// A sole unrestricted admin has nobody to consent to an authority policy, and
/// is told so before being asked for a gesture.
#[tokio::test]
async fn vti_vtc_022_a_sole_admin_cannot_change_an_authority_policy_alone() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, UPSERT, module("removal", REMOVAL_POLICY)).await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(step_up_request(&reply).is_none(), "{reply}");
    assert!(
        reply.to_string().contains("VTI-VTC-022"),
        "names the requirement: {reply}"
    );
}

/// A policy that decides no authority is gated by role alone: an unrestricted
/// admin changes it at once.
#[tokio::test]
async fn vti_vtc_022_a_community_rule_is_gated_by_role_only() {
    let fix = fixture().await;
    let a = admin(&fix).await;
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, UPSERT, module("directory", DIRECTORY_POLICY)).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let id = reply["payload"]["policy"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, reply) = post(
        &fix.vtc,
        &signed(&a, ACTIVATE, json!({ "id": id, "purpose": "directory" })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}
