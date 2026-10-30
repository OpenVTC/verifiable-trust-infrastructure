//! `vtc/members/role/set/0.1` — an administrator moves a subject's community
//! role, compare-and-swapped on the role it holds, through the signed door.
//!
//! Each declared refusal is driven here and witnessed in
//! `trust_tasks::error_code_census`; the completed move is checked for what the
//! specification says it carries: the administrative authority the role
//! implies (item 8), the role credential (item 16) and the audit row (item 18),
//! and a promotion conferring `vtc.roles.assign` parked for another
//! administrator's approval (item 13, **VTI-APV-018**).

use affinidi_status_list::StatusPurpose;
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{Value, json};
use vti_common::audit::AuditEvent;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{
    AdminAuthority, AdminRole, CapRef, Capability, CapabilityGrant, CapabilityScope, VtcRole,
    get_acl_entry, store_acl_entry,
};
use vtc_service::members::{Member, store_member};
use vtc_service::policy::model::{Policy, PolicyPurpose};
use vtc_service::policy::storage::{set_active_policy_id, store_policy};
use vtc_service::test_support::TestVtc;
use vtc_service::trust_tasks::member_role_tasks::codes;

use crate::common::second_party::{Gesturer, decide, parked_action, step_up_request};
use crate::common::signed::{party_with_role, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const ROLE_SET: &str = "https://trusttasks.org/spec/vtc/members/role/set/0.1";

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

async fn admin(fix: &mut Fixture) -> Party {
    let p = party_with_role(&fix.vtc, VtcRole::Admin, &[]).await;
    fix.gesturer.enrol(&fix.vtc, &p.did).await;
    p
}

/// A member with a member record.
async fn member(fix: &Fixture) -> Party {
    let p = party_with_role(&fix.vtc, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&p.did))
        .await
        .unwrap();
    p
}

/// Send a move, answering the bound gesture it asks for once.
async fn send(fix: &mut Fixture, by: &Party, payload: Value) -> (StatusCode, Value) {
    let doc = signed(by, ROLE_SET, payload).await;
    let (status, reply) = post(&fix.vtc, &doc).await;
    if step_up_request(&reply).is_none() {
        return (status, reply);
    }
    fix.gesturer.gesture(&fix.vtc, by, &reply).await;
    post(&fix.vtc, &doc).await
}

fn tt_error_code(reply: &Value) -> &str {
    reply["payload"]["code"].as_str().unwrap_or_default()
}

fn move_of(subject: &str, from: &str, to: &str) -> Value {
    json!({ "subject": subject, "fromRole": from, "toRole": to })
}

async fn role_of(fix: &Fixture, did: &str) -> VtcRole {
    get_acl_entry(&fix.vtc.state.acl_ks, did)
        .await
        .unwrap()
        .unwrap()
        .role
}

/// Items 3 and 4: an unknown subject is `notFound`; a role the community does
/// not recognise is `roleNotRecognized`, naming it; `application`, onto or off
/// an entry, is `roleNotAssignable`.
#[tokio::test]
async fn role_set_refuses_unknown_subjects_and_unassignable_roles() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let subject = member(&fix).await;

    let nobody = Party::new();
    let (_, r) = send(
        &mut fix,
        &actor,
        move_of(&nobody.did, "member", "moderator"),
    )
    .await;
    assert_eq!(tt_error_code(&r), codes::ROLE_SET_NOT_FOUND, "{r}");

    let (_, r) = send(
        &mut fix,
        &actor,
        move_of(&subject.did, "member", "overlord"),
    )
    .await;
    assert_eq!(
        tt_error_code(&r),
        codes::ROLE_SET_ROLE_NOT_RECOGNIZED,
        "{r}"
    );
    assert_eq!(r["payload"]["details"]["offendingRole"], "overlord", "{r}");

    let (_, r) = send(
        &mut fix,
        &actor,
        move_of(&subject.did, "member", "application"),
    )
    .await;
    assert_eq!(
        tt_error_code(&r),
        codes::ROLE_SET_ROLE_NOT_ASSIGNABLE,
        "{r}"
    );

    let app = party_with_role(&fix.vtc, VtcRole::Application, &[]).await;
    let (_, r) = send(&mut fix, &actor, move_of(&app.did, "application", "member")).await;
    assert_eq!(
        tt_error_code(&r),
        codes::ROLE_SET_ROLE_NOT_ASSIGNABLE,
        "{r}"
    );

    assert_eq!(role_of(&fix, &subject.did).await, VtcRole::Member);
    assert_eq!(role_of(&fix, &app.did).await, VtcRole::Application);
}

/// Item 5: a stale `fromRole` is `stateMismatch`, naming the role the entry
/// holds in `details.currentRole`, and asks for no gesture.
#[tokio::test]
async fn role_set_state_mismatch_names_the_current_role() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let subject = member(&fix).await;

    let doc = signed(&actor, ROLE_SET, move_of(&subject.did, "issuer", "admin")).await;
    let (_, r) = post(&fix.vtc, &doc).await;
    assert_eq!(tt_error_code(&r), codes::ROLE_SET_STATE_MISMATCH, "{r}");
    assert_eq!(r["payload"]["details"]["currentRole"], "member", "{r}");
    assert!(step_up_request(&r).is_none(), "{r}");
    assert_eq!(role_of(&fix, &subject.did).await, VtcRole::Member);
}

/// Item 9: the resulting entry must lie within the requester's own authority.
/// A requester holding `vtc.roles.assign` and nothing else cannot move a
/// member to `moderator`, whose implied authority it does not hold.
#[tokio::test]
async fn role_set_is_bounded_by_the_requesters_own_authority() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let mut narrowed = get_acl_entry(&fix.vtc.state.acl_ks, &actor.did)
        .await
        .unwrap()
        .unwrap();
    narrowed.admin = AdminAuthority {
        capabilities: CapabilityScope::Listed {
            grants: vec![CapabilityGrant::from(CapRef::all(Capability::RolesAssign))],
        },
        ..AdminAuthority::for_role(AdminRole::CommunityAdmin)
    };
    store_acl_entry(&fix.vtc.state.acl_ks, &narrowed)
        .await
        .unwrap();
    let subject = member(&fix).await;

    let (_, r) = send(
        &mut fix,
        &actor,
        move_of(&subject.did, "member", "moderator"),
    )
    .await;
    assert_eq!(
        tt_error_code(&r),
        codes::ROLE_SET_DELEGATION_EXCEEDS_GRANTER,
        "{r}"
    );
    assert!(r["payload"]["details"]["axes"].is_array(), "{r}");
    assert_eq!(role_of(&fix, &subject.did).await, VtcRole::Member);
}

/// Item 10 (VTI-APV-009): a move ending the subject's `vtc.roles.assign` that
/// would leave too few holders for the consent threshold is refused, before
/// anyone is asked for a gesture.
#[tokio::test]
async fn vti_apv_009_role_set_refuses_to_end_the_last_role_assigners() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let colleague = admin(&mut fix).await;
    fix.vtc
        .state
        .config
        .write()
        .await
        .acl
        .unrestricted_admin_consent_threshold = 2;

    let doc = signed(&actor, ROLE_SET, move_of(&colleague.did, "admin", "member")).await;
    let (_, r) = post(&fix.vtc, &doc).await;
    assert_eq!(tt_error_code(&r), codes::ROLE_SET_LAST_ROLE_ASSIGNER, "{r}");
    assert!(step_up_request(&r).is_none(), "{r}");
    assert_eq!(role_of(&fix, &colleague.did).await, VtcRole::Admin);
}

/// Item 11: the community's role-change policy refuses with
/// `deniedByPolicy`, and nothing moves.
#[tokio::test]
async fn role_set_a_refusing_policy_refuses_with_its_code() {
    use sha2::{Digest, Sha256};
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let subject = member(&fix).await;

    let src = "package vtc.role_change\nimport rego.v1\n\
               default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n";
    let id = uuid::Uuid::new_v4();
    store_policy(
        &fix.vtc.state.policies_ks,
        &Policy {
            id,
            purpose: PolicyPurpose::RoleChange,
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
        PolicyPurpose::RoleChange,
        id,
    )
    .await
    .unwrap();

    let (_, r) = send(
        &mut fix,
        &actor,
        move_of(&subject.did, "member", "custom:editor"),
    )
    .await;
    assert_eq!(tt_error_code(&r), codes::ROLE_SET_DENIED_BY_POLICY, "{r}");
    assert_eq!(role_of(&fix, &subject.did).await, VtcRole::Member);
}

/// Items 8, 16 and 18: a move to `moderator` carries the administrative role
/// it implies, re-issues the role credential and is audited with both roles,
/// the authority before and after, how it was allowed and why.
#[tokio::test]
async fn role_set_moves_the_role_its_authority_and_credential_and_audits_it() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let subject = member(&fix).await;

    let mut payload = move_of(&subject.did, "member", "moderator");
    payload["reason"] = json!("runs the events programme");
    let (status, r) = send(&mut fix, &actor, payload).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    crate::common::signed::assert_conforms(ROLE_SET, &r);
    let p = &r["payload"];
    assert_eq!(p["role"], "moderator", "{r}");
    assert_eq!(p["previousRole"], "member", "{r}");
    assert_eq!(p["changed"], true, "{r}");
    assert_eq!(p["approval"], "policyAllowed", "{r}");
    assert_eq!(p["entry"]["role"], "moderator", "{r}");
    assert_eq!(p["entry"]["updatedBy"], actor.did.as_str(), "{r}");
    assert!(p["roleVac"].is_object(), "{r}");

    let rows: Vec<AuditEvent> = fix
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .map(|env| env.event)
        .collect();
    let set = rows
        .iter()
        .find_map(|e| match e {
            AuditEvent::CommunityRoleSet(d) => Some(d),
            _ => None,
        })
        .expect("the move is audited");
    assert_eq!(set.from_role, "member");
    assert_eq!(set.to_role, "moderator");
    assert_eq!(set.approval, "policyAllowed");
    assert_ne!(set.authority_before, set.authority_after);
    assert_eq!(set.reason.as_deref(), Some("runs the events programme"));
}

/// Items 12 and 13 (VTI-OPS-051, VTI-APV-018): a promotion to `admin` confers
/// `vtc.roles.assign`, so after the requester's bound gesture it is parked for
/// another holder's approval, and executes on it — answered `approved`.
#[tokio::test]
async fn vti_apv_018_role_set_promotion_to_admin_is_parked_then_approved() {
    let mut fix = fixture().await;
    let actor = admin(&mut fix).await;
    let approver = admin(&mut fix).await;
    let subject = member(&fix).await;

    let (_, r) = send(&mut fix, &actor, move_of(&subject.did, "member", "admin")).await;
    let action_id = parked_action(&r).expect("parked for another administrator");
    assert_eq!(role_of(&fix, &subject.did).await, VtcRole::Member);

    let (status, ack) = decide(&fix.vtc, &approver, &action_id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(role_of(&fix, &subject.did).await, VtcRole::Admin);
    let entry = get_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.admin.admin_role, Some(AdminRole::CommunityAdmin));
}
