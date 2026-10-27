//! Direct admission (`ceremony::admission`): **Add a member**
//! (`vtc/members/admit/0.1`) and **Make this a membership**
//! (`vtc/members/make-membership/0.1`), through the signed-document door.
//!
//! Both bypass the join criteria, so both are decided by the community's
//! `admission` policy, which may refer them to the action list for another
//! holder of `vtc.members.manage` (`Act::DirectAdmission`). Covered here: the
//! write each makes (ACL entry, member record, credentials — and, for a
//! membership made of an existing entry, the entry left untouched), every
//! refusal before the policy, the role bound (`vtc-admin-roles.md` §6.3, the
//! invitation rule), the gesture an administrative role takes (VTI-OPS-051),
//! a referral parked and completed by a second administrator (VTI-APV-017),
//! a policy refusal, and the audit trail. That a membership made this way
//! signs in to the member portal is in `member_portal_oob.rs`.

use affinidi_status_list::StatusPurpose;
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{Value, json};
use vti_common::audit::AuditEvent;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::ceremony::admission::codes;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::policy::model::{Policy, PolicyPurpose};
use vtc_service::policy::storage::{set_active_policy_id, store_policy};
use vtc_service::test_support::TestVtc;

use crate::common::second_party::{Gesturer, decide, parked_action, show_action, step_up_request};
use crate::common::signed::{party_with_role, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const ADMIT: &str = "https://trusttasks.org/spec/vtc/members/admit/0.1";
const MAKE: &str = "https://trusttasks.org/spec/vtc/members/make-membership/0.1";

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
    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
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

/// A community administrator with a passkey for the gestures it is asked for.
async fn admin(fix: &mut Fixture) -> Party {
    let p = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    fix.gesturer.enrol(&fix.vtc, &p.did).await;
    p
}

/// Make the `admission` policy `src` (package `vtc.admission`) the active one —
/// as an administrator would, through the consent its change takes; written
/// directly here because the change is not what these tests are about.
async fn activate_admission_policy(fix: &Fixture, src: &str) {
    use sha2::{Digest, Sha256};
    let id = uuid::Uuid::new_v4();
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::Admission,
            rego_source: src.into(),
            sha256: Sha256::digest(src.as_bytes()).into(),
            activated_at: Some(Utc::now()),
            author_did: "did:key:test".into(),
            created_at: Utc::now(),
            version: 2,
            name: None,
            description: None,
        },
    )
    .await
    .unwrap();
    set_active_policy_id(
        &fix.vtc.state.active_policies_ks,
        PolicyPurpose::Admission,
        id,
    )
    .await
    .unwrap();
}

const REFER_ALL: &str = "package vtc.admission\nimport rego.v1\n\
    default decision := {\"effect\": \"refer\", \"with\": {\"queue\": \"second-admin\"}}\n";

/// Send `doc` as `by`, answering the one gesture it may ask for.
async fn submit(fix: &mut Fixture, by: &Party, doc: &Value) -> (StatusCode, Value) {
    let (status, reply) = post(&fix.vtc, doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, doc).await
}

async fn send(fix: &mut Fixture, by: &Party, task: &str, payload: Value) -> (StatusCode, Value) {
    let doc = signed(by, task, payload).await;
    submit(fix, by, &doc).await
}

fn tt_error_code(reply: &Value) -> &str {
    reply["payload"]["code"].as_str().unwrap_or_default()
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

async fn direct_admissions(fix: &Fixture) -> Vec<vti_common::audit::MemberAdmittedDirectlyData> {
    audit_rows(fix)
        .await
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::MemberAdmittedDirectly(d) => Some(d),
            _ => None,
        })
        .collect()
}

async fn is_active_member(fix: &Fixture, did: &str) -> bool {
    vtc_service::member_portal::active::active_member(&fix.vtc.state, did)
        .await
        .unwrap()
        .is_some()
}

// ─── Make this a membership ─────────────────────────────────────────────────

/// The bootstrap administrator — an Admin ACL entry and no member record — is
/// no active member, so the member portal refuses it. Making its entry a
/// membership writes the record and issues the credentials, and leaves the
/// entry byte for byte as it was.
#[tokio::test]
async fn make_membership_gives_a_bootstrap_admin_a_membership_and_leaves_its_entry() {
    let mut fix = fixture().await;
    let bootstrap = admin(&mut fix).await;
    let before = get_acl_entry(&fix.vtc.state.acl_ks, &bootstrap.did)
        .await
        .unwrap()
        .unwrap();
    assert!(!is_active_member(&fix, &bootstrap.did).await);

    // The administrator makes its own entry a membership: no authority moves,
    // so the default policy admits it and no gesture is asked for.
    let (status, reply) = send(
        &mut fix,
        &bootstrap,
        MAKE,
        json!({ "subject": bootstrap.did, "reason": "the founder is a member too" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let p = &reply["payload"];
    assert_eq!(p["status"], "admitted");
    assert_eq!(p["role"], "admin");
    assert_eq!(p["approval"], "policyAllowed");
    assert_eq!(p["returning"], false);
    assert!(p["vmc"]["id"].is_string() && p["roleVac"]["id"].is_string());

    let after = get_acl_entry(&fix.vtc.state.acl_ks, &bootstrap.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&after).unwrap(),
        serde_json::to_value(&before).unwrap(),
        "the entry's role, authority, grants and label are untouched"
    );
    let member = get_member(&fix.vtc.state.members_ks, &bootstrap.did)
        .await
        .unwrap()
        .expect("a member record");
    assert!(member.current_vmc_id.is_some() && member.current_role_vac_id.is_some());
    assert!(member.status_list_index.is_some());
    assert!(is_active_member(&fix, &bootstrap.did).await);

    let rows = direct_admissions(&fix).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].action, "make-membership");
    assert_eq!(rows[0].approval, "policyAllowed");
    assert_eq!(
        rows[0].reason.as_deref(),
        Some("the founder is a member too")
    );
    assert!(
        audit_rows(&fix)
            .await
            .iter()
            .any(|e| matches!(e, AuditEvent::MemberAdded(_))),
        "the admission writes the trail every admission writes"
    );

    // A second time is a duplicate membership.
    let (_, again) = send(
        &mut fix,
        &bootstrap,
        MAKE,
        json!({ "subject": bootstrap.did }),
    )
    .await;
    assert_eq!(tt_error_code(&again), codes::MAKE_ALREADY_MEMBER, "{again}");
}

/// Every refusal before the policy: no entry, an application entry, a removed
/// member's record, an expired entry, and a caller without
/// `vtc.members.manage`.
#[tokio::test]
async fn make_membership_refusals() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;

    let stranger = Party::new();
    let (_, r) = send(&mut fix, &actor, MAKE, json!({ "subject": stranger.did })).await;
    assert_eq!(tt_error_code(&r), codes::MAKE_NO_ENTRY, "{r}");

    // An application entry: git rights for a non-member.
    let bridge = Party::new();
    store_acl_entry(
        &fix.vtc.state.acl_ks,
        &VtcAclEntry::new(
            bridge.did.clone(),
            VtcRole::Application,
            vtc_service::acl::AdminAuthority::none(),
            "did:key:test",
        ),
    )
    .await
    .unwrap();
    let (_, r) = send(&mut fix, &actor, MAKE, json!({ "subject": bridge.did })).await;
    assert_eq!(tt_error_code(&r), codes::MAKE_APPLICATION_ENTRY, "{r}");

    // A former member, removed and then granted access again.
    let former = party_with_role(&fix.vtc, VtcRole::Moderator, &[]).await;
    let mut tomb = Member::fresh(&former.did);
    tomb.tombstone();
    store_member(&fix.vtc.state.members_ks, &tomb)
        .await
        .unwrap();
    let (_, r) = send(&mut fix, &actor, MAKE, json!({ "subject": former.did })).await;
    assert_eq!(tt_error_code(&r), codes::MAKE_REMOVED_MEMBER, "{r}");
    assert!(
        r["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("was removed")),
        "{r}"
    );
    assert!(
        get_member(&fix.vtc.state.members_ks, &former.did)
            .await
            .unwrap()
            .unwrap()
            .is_removed(),
        "the tombstone is not overwritten"
    );

    // An expired entry authorizes nothing, so there is nothing to make a
    // membership of.
    let lapsed = Party::new();
    let mut entry = VtcAclEntry::new(
        lapsed.did.clone(),
        VtcRole::Member,
        vtc_service::acl::AdminAuthority::none(),
        "did:key:test",
    );
    entry.expires_at = Some(1);
    store_acl_entry(&fix.vtc.state.acl_ks, &entry)
        .await
        .unwrap();
    let (_, r) = send(&mut fix, &actor, MAKE, json!({ "subject": lapsed.did })).await;
    assert_eq!(tt_error_code(&r), codes::MAKE_ENTRY_NOT_LIVE, "{r}");

    // A credential officer holds no vtc.members.manage.
    let officer = party_with_role(&fix.vtc, VtcRole::Issuer, &[]).await;
    let (status, r) = send(&mut fix, &officer, MAKE, json!({ "subject": actor.did })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert!(
        get_member(&fix.vtc.state.members_ks, &actor.did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(direct_admissions(&fix).await.is_empty());
}

// ─── Add a member ───────────────────────────────────────────────────────────

/// An administrator adds a DID as a member, with a label: the same ACL entry,
/// member record and credentials a completed join leaves.
#[tokio::test]
async fn add_a_member_admits_with_credentials_and_label() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let newcomer = Party::new();

    let (status, reply) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": newcomer.did, "role": "member", "label": "Ada" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["role"], "member");
    assert_eq!(reply["payload"]["label"], "Ada");

    let entry = get_acl_entry(&fix.vtc.state.acl_ks, &newcomer.did)
        .await
        .unwrap()
        .expect("an ACL entry");
    assert_eq!(entry.role, VtcRole::Member);
    assert_eq!(entry.label.as_deref(), Some("Ada"));
    assert_eq!(entry.created_by, actor.did);
    assert!(!entry.is_administrator());
    assert!(is_active_member(&fix, &newcomer.did).await);
    let rows = direct_admissions(&fix).await;
    assert_eq!(rows[0].action, "add");
    assert_eq!(rows[0].label.as_deref(), Some("Ada"));

    // Now it has an entry, and a membership.
    let (_, again) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": newcomer.did, "role": "member" }),
    )
    .await;
    assert_eq!(tt_error_code(&again), codes::ADMIT_HAS_ENTRY, "{again}");
    // An entry with no membership is pointed at make-membership.
    let other = admin(&mut fix).await;
    let (_, r) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": other.did, "role": "member" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), codes::ADMIT_HAS_ENTRY, "{r}");
    assert!(
        r["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("vtc/members/make-membership")),
        "{r}"
    );
}

/// A former member (removed record, no entry) is re-admitted, as a rejoin
/// would, and recorded as returning.
#[tokio::test]
async fn add_a_member_readmits_a_former_member() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let former = Party::new();
    let mut tomb = Member::fresh(&former.did);
    tomb.tombstone();
    store_member(&fix.vtc.state.members_ks, &tomb)
        .await
        .unwrap();

    let (status, reply) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": former.did, "role": "member" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["returning"], true);
    assert!(is_active_member(&fix, &former.did).await);
    assert!(direct_admissions(&fix).await[0].returning);
}

/// A DID with a live member record and no entry is already a member: *Add a
/// member* refuses rather than issue a second membership.
#[tokio::test]
async fn add_a_member_refuses_a_live_member_record() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let member = Party::new();
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&member.did))
        .await
        .unwrap();
    let (_, r) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": member.did, "role": "member" }),
    )
    .await;
    assert_eq!(tt_error_code(&r), codes::ADMIT_ALREADY_MEMBER, "{r}");
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &member.did)
            .await
            .unwrap()
            .is_none()
    );
}

/// The payloads are read against their published schemas before anything else
/// (trust-tasks-tf #784): a `subject` that is no DID or is over 2048
/// characters, and a `role` over 128, are a malformed document — not a role
/// the community refuses. Nothing is written by any of them.
#[tokio::test]
async fn admission_payloads_out_of_schema_are_malformed() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let long_did = format!("did:key:z{}", "a".repeat(2048 - "did:key:z".len() + 1));
    assert_eq!(long_did.chars().count(), 2049);
    let target = Party::new();
    for (task, payload, what) in [
        (
            ADMIT,
            json!({ "subject": "not-a-did", "role": "member" }),
            "admit subject without did:",
        ),
        (
            ADMIT,
            json!({ "subject": long_did, "role": "member" }),
            "admit subject over 2048",
        ),
        (
            ADMIT,
            json!({ "subject": target.did, "role": "r".repeat(129) }),
            "admit role over 128",
        ),
        (
            ADMIT,
            json!({ "subject": target.did, "role": "member", "label": "  " }),
            "admit blank label",
        ),
        (
            ADMIT,
            json!({ "subject": target.did, "role": "member", "reason": "x".repeat(1025) }),
            "admit reason over 1024",
        ),
        (
            ADMIT,
            json!({ "subject": target.did, "role": "member", "surprise": true }),
            "admit unknown member",
        ),
        (
            MAKE,
            json!({ "subject": "not-a-did" }),
            "make subject without did:",
        ),
        (
            MAKE,
            json!({ "subject": long_did }),
            "make subject over 2048",
        ),
    ] {
        let (status, r) = send(&mut fix, &actor, task, payload).await;
        assert!(!status.is_success(), "{what}: {r}");
        assert_eq!(tt_error_code(&r), "malformedRequest", "{what}: {r}");
    }

    // At 128 characters the role is in schema, and an unknown one is the
    // community's refusal.
    let (_, r) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": target.did, "role": "r".repeat(128) }),
    )
    .await;
    assert_eq!(tt_error_code(&r), codes::ADMIT_ROLE_NOT_PERMITTED, "{r}");

    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(direct_admissions(&fix).await.is_empty());
}

/// A role beyond `member` is assigning a role (`vtc.roles.assign`), bounded by
/// the actor's own entry; `admin` and `application` are never seated; an
/// unknown role is refused. Nothing is written by any of them.
#[tokio::test]
async fn add_a_member_role_is_bounded_by_the_actors_authority() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    // A moderator holds vtc.members.manage and not vtc.roles.assign.
    let moderator = party_with_role(&fix.vtc, VtcRole::Moderator, &[]).await;
    fix.gesturer.enrol(&fix.vtc, &moderator.did).await;

    let target = Party::new();
    for (who, role) in [
        (&moderator, "moderator"),
        (&actor, "admin"),
        (&actor, "application"),
        (&actor, "overlord"),
    ] {
        let (_, r) = send(
            &mut fix,
            who,
            ADMIT,
            json!({ "subject": target.did, "role": role }),
        )
        .await;
        assert_eq!(
            tt_error_code(&r),
            codes::ADMIT_ROLE_NOT_PERMITTED,
            "{role}: {r}"
        );
    }
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
            .await
            .unwrap()
            .is_none()
    );

    // The moderator may add members.
    let (status, r) = send(
        &mut fix,
        &moderator,
        ADMIT,
        json!({ "subject": target.did, "role": "member" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");

    // Without vtc.members.manage there is nothing to add with.
    let officer = party_with_role(&fix.vtc, VtcRole::Issuer, &[]).await;
    let (status, r) = send(
        &mut fix,
        &officer,
        ADMIT,
        json!({ "subject": Party::new().did, "role": "member" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
}

/// A role carrying administrative authority takes the requester's gesture
/// bound to the one admission (VTI-OPS-051) before anything is written.
#[tokio::test]
async fn add_a_member_at_an_administrative_role_takes_a_bound_gesture() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let target = Party::new();
    let doc = signed(
        &actor,
        ADMIT,
        json!({ "subject": target.did, "role": "moderator" }),
    )
    .await;

    let (_, first) = post(&fix.vtc, &doc).await;
    assert!(step_up_request(&first).is_some(), "{first}");
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
            .await
            .unwrap()
            .is_none()
    );

    let (status, reply) = submit(&mut fix, &actor, &doc).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let entry = get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.role, VtcRole::Moderator);
    assert!(entry.is_administrator());
}

// ─── Governance: the admission policy ───────────────────────────────────────

/// A community whose `admission` policy refers direct admissions: the add is
/// parked (after the requester's gesture), nothing is written, the requester
/// cannot approve it, and another holder of `vtc.members.manage` approving it
/// runs it (VTI-APV-017).
#[tokio::test]
async fn a_referring_policy_parks_an_add_for_another_administrators_approval() {
    let mut fix = fixture().await;
    activate_admission_policy(&fix, REFER_ALL).await;
    let requester = admin(&mut fix).await;
    let approver = party_with_role(&fix.vtc, VtcRole::Moderator, &[]).await;
    let target = Party::new();

    let doc = signed(
        &requester,
        ADMIT,
        json!({ "subject": target.did, "role": "member", "reason": "vouched for" }),
    )
    .await;
    let (_, parked) = submit(&mut fix, &requester, &doc).await;
    let action_id = parked_action(&parked).unwrap_or_else(|| panic!("not parked: {parked}"));
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
            .await
            .unwrap()
            .is_none()
    );

    let (_, shown) = show_action(&fix.vtc, &approver, &action_id).await;
    let action = &shown["payload"]["action"];
    assert_eq!(action["kind"], "member.admit", "{shown}");
    assert_eq!(action["status"], "open");
    assert_eq!(
        action["summary"]["title"],
        "Add {subject} as a member, holding {role}"
    );

    // The requester is no approver of their own admission: the action holds
    // no challenge for them to answer.
    let (_, own) = show_action(&fix.vtc, &requester, &action_id).await;
    assert!(own["payload"]["action"]["challenge"].is_null(), "{own}");

    let (status, ack) = decide(&fix.vtc, &approver, &action_id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    let (_, done) = show_action(&fix.vtc, &requester, &action_id).await;
    assert_eq!(done["payload"]["action"]["status"], "completed", "{done}");
    assert!(is_active_member(&fix, &target.did).await);
    let rows = direct_admissions(&fix).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].approval, "approved");
    assert_eq!(rows[0].action_id.as_deref(), Some(action_id.as_str()));
}

/// Make-membership under the same policy: the bootstrap administrator asks for
/// its own, and only somebody else can approve it.
#[tokio::test]
async fn a_referring_policy_parks_make_membership_and_the_subject_cannot_approve_it() {
    let mut fix = fixture().await;
    activate_admission_policy(&fix, REFER_ALL).await;
    let bootstrap = admin(&mut fix).await;
    let co_admin = admin(&mut fix).await;

    let doc = signed(&bootstrap, MAKE, json!({ "subject": bootstrap.did })).await;
    let (_, parked) = submit(&mut fix, &bootstrap, &doc).await;
    let action_id = parked_action(&parked).unwrap_or_else(|| panic!("not parked: {parked}"));
    assert!(!is_active_member(&fix, &bootstrap.did).await);

    let (_, shown) = show_action(&fix.vtc, &co_admin, &action_id).await;
    assert_eq!(shown["payload"]["action"]["kind"], "member.makeMembership");

    let (status, ack) = decide(&fix.vtc, &co_admin, &action_id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(is_active_member(&fix, &bootstrap.did).await);
}

/// With nobody else holding `vtc.members.manage`, a referral cannot be met and
/// is refused before any gesture is asked for.
#[tokio::test]
async fn a_referral_nobody_can_approve_is_refused_before_the_gesture() {
    let mut fix = fixture().await;
    activate_admission_policy(&fix, REFER_ALL).await;
    let only = admin(&mut fix).await;
    let doc = signed(
        &only,
        ADMIT,
        json!({ "subject": Party::new().did, "role": "member" }),
    )
    .await;
    let (status, reply) = post(&fix.vtc, &doc).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(step_up_request(&reply).is_none(), "{reply}");
}

/// A policy that refuses is the community's answer, with its code.
#[tokio::test]
async fn a_refusing_policy_refuses_with_its_code() {
    let mut fix = fixture().await;
    activate_admission_policy(
        &fix,
        "package vtc.admission\nimport rego.v1\n\
         default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"closed\"}}\n",
    )
    .await;
    let actor = admin(&mut fix).await;
    let target = Party::new();
    let (status, r) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": target.did, "role": "member" }),
    )
    .await;
    assert!(!status.is_success(), "{r}");
    assert_eq!(tt_error_code(&r), codes::ADMIT_DENIED_BY_POLICY, "{r}");
    assert!(r["payload"]["message"].as_str().unwrap().contains("closed"));
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
            .await
            .unwrap()
            .is_none()
    );

    // Making a membership is decided by the same policy, under its own code.
    let (status, r) = send(&mut fix, &actor, MAKE, json!({ "subject": actor.did })).await;
    assert!(!status.is_success(), "{r}");
    assert_eq!(tt_error_code(&r), codes::MAKE_DENIED_BY_POLICY, "{r}");
    assert!(!is_active_member(&fix, &actor.did).await);
}

/// A policy may not choose the role: an `allow` naming another one is vetoed
/// by the host.
#[tokio::test]
async fn a_policy_naming_another_role_is_vetoed() {
    let mut fix = fixture().await;
    activate_admission_policy(
        &fix,
        "package vtc.admission\nimport rego.v1\n\
         default decision := {\"effect\": \"allow\", \"with\": {\"role\": \"admin\"}}\n",
    )
    .await;
    let actor = admin(&mut fix).await;
    let target = Party::new();
    let (status, r) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": target.did, "role": "member" }),
    )
    .await;
    assert!(!status.is_success(), "{r}");
    assert_eq!(tt_error_code(&r), codes::ADMIT_DENIED_BY_POLICY, "{r}");
    assert!(
        r["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("admission-role"),
        "{r}"
    );
    assert!(
        get_acl_entry(&fix.vtc.state.acl_ks, &target.did)
            .await
            .unwrap()
            .is_none()
    );
}

/// The ACL listing says which entries have a membership, in `ext` — what the
/// console's *Make this a membership* reads.
#[tokio::test]
async fn the_acl_listing_marks_entries_without_a_membership() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let member = Party::new();
    let (status, r) = send(
        &mut fix,
        &actor,
        ADMIT,
        json!({ "subject": member.did, "role": "member" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");

    let doc = signed(
        &actor,
        "https://trusttasks.org/spec/acl/list/0.2",
        json!({}),
    )
    .await;
    let (status, list) = post(&fix.vtc, &doc).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let membership = |did: &str| {
        list["payload"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["subject"] == did)
            .map(|e| e["ext"]["org.openvtc"]["membership"].clone())
    };
    assert_eq!(membership(&actor.did), Some(json!("none")));
    assert_eq!(membership(&member.did), Some(json!("active")));
    crate::common::signed::assert_conforms("https://trusttasks.org/spec/acl/list/0.2", &list);
}

/// The spine enforces the document requirements the two specifications
/// declare (a proof, among them): an unsigned one is refused before it
/// reaches the handler.
#[tokio::test]
async fn an_unsigned_admission_is_refused_by_the_spine() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    for (task, payload) in [
        (
            ADMIT,
            json!({ "subject": Party::new().did, "role": "member" }),
        ),
        (MAKE, json!({ "subject": actor.did })),
    ] {
        let doc = crate::common::signed::unsigned(&actor, task, payload);
        let (status, reply) = post(&fix.vtc, &doc).await;
        assert!(!status.is_success(), "{reply}");
        assert_eq!(tt_error_code(&reply), "proofRequired", "{reply}");
    }
    assert!(!is_active_member(&fix, &actor.did).await);
}

/// Single-administrator mode (VTI-APV-022): nobody else to approve a referred
/// admission, so the requester's bound gesture stands in for the approval, and
/// the record says it was waived.
#[tokio::test]
async fn single_administrator_mode_waives_a_referral_on_the_requesters_gesture() {
    let mut fix = fixture().await;
    fix.vtc.state.config.write().await.acl.single_admin_mode = true;
    activate_admission_policy(&fix, REFER_ALL).await;
    let only = admin(&mut fix).await;
    let (status, reply) = send(&mut fix, &only, MAKE, json!({ "subject": only.did })).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["approval"], "waived");
    assert!(is_active_member(&fix, &only.did).await);
    assert_eq!(direct_admissions(&fix).await[0].approval, "waived");
}
