//! Role-based administration, phase C2 (`docs/05-design-notes/vtc-admin-roles.md`
//! §6.2, §6.3, §7): custom roles, approver sets read off approve authority,
//! a departed granter's grants reviewed in the action list, and a subject
//! rolling its own entry to a new key.
//!
//! Every test drives the signed-document door (`POST /v1/trust-tasks`) as an
//! administrator's client does, through the requester's operation-bound
//! gesture and other administrators' decisions where the act asks for them.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::roles::codes::*;
use vtc_service::acl::roles::{self, RoleDefinition};
use vtc_service::acl::{
    AdminAuthority, AdminRole, CapRef, Capability, CapabilityScope, VtcAclEntry, VtcActScope,
    VtcRole, get_acl_entry, store_acl_entry,
};
use vtc_service::admin_actions::ActionRecord;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::{Gesturer, decide};
use crate::common::signed::{error_code, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const DEFINE: &str = "https://trusttasks.org/spec/vtc/roles/define/0.1";
const LIST: &str = "https://trusttasks.org/spec/vtc/roles/list/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/roles/show/0.1";
const DELETE: &str = "https://trusttasks.org/spec/vtc/roles/delete/0.1";
const GRANT_V0_2: &str = "https://trusttasks.org/spec/acl/grant/0.2";
const REVOKE_V0_2: &str = "https://trusttasks.org/spec/acl/revoke/0.2";
const SWAP_KEY: &str = "https://trusttasks.org/spec/acl/swap-key/0.1";

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
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
    Fixture {
        vtc,
        gesturer: Gesturer::new(),
    }
}

fn row(did: &str, admin: AdminAuthority, delegated_by: Option<&str>) -> VtcAclEntry {
    VtcAclEntry {
        did: did.to_string(),
        role: VtcRole::implied_by(admin.admin_role.as_ref()),
        label: None,
        admin,
        delegated_by: delegated_by.map(str::to_string),
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
        resource_grants: Vec::new(),
    }
}

async fn seed_as(fix: &Fixture, did: &str, admin: AdminAuthority, by: Option<&str>) {
    store_acl_entry(&fix.vtc.state.acl_ks, &row(did, admin, by))
        .await
        .unwrap();
}

async fn seed(fix: &Fixture, admin: AdminAuthority) -> Party {
    let p = Party::new();
    seed_as(fix, &p.did, admin, None).await;
    p
}

/// A community administrator who holds a passkey, so can make the gesture.
async fn requester(fix: &mut Fixture) -> Party {
    let p = seed(fix, AdminAuthority::community_admin()).await;
    fix.gesturer.enrol(&fix.vtc, &p.did).await;
    p
}

async fn entry(fix: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&fix.vtc.state.acl_ks, did).await.unwrap()
}

/// Send as `by` through any gesture, then the approvals of `approvers`.
async fn through(
    fix: &mut Fixture,
    by: &Party,
    approvers: &[&Party],
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let doc = signed(by, uri, payload).await;
    fix.gesturer
        .send_through(&fix.vtc, by, approvers, &doc)
        .await
}

fn events_team() -> Value {
    json!({
        "name": "events-team",
        "description": "Runs the public pages and event invitations.",
        "ceiling": [
            { "capability": "vtc.surface.admin" },
            { "capability": "vtc.invitations.manage" },
        ],
        "approveScope": [{ "capability": "vtc.invitations.manage" }],
        "reason": "delegating event operations",
    })
}

fn stored_role(name: &str, ceiling: &[&str]) -> RoleDefinition {
    RoleDefinition {
        name: name.into(),
        description: None,
        ceiling: ceiling
            .iter()
            .map(|c| c.parse::<CapRef>().unwrap())
            .collect(),
        approve_scope: Vec::new(),
        created_at: 0,
        created_by: "did:key:zSomeone".into(),
        updated_at: None,
        updated_by: None,
    }
}

fn custom_authority(name: &str) -> AdminAuthority {
    let mut a = AdminAuthority::for_role(AdminRole::Custom(name.into()));
    a.act = VtcActScope::All;
    a.capabilities = CapabilityScope::Ceiling;
    a
}

async fn actions_of_kind(fix: &Fixture, kind: &str) -> Vec<ActionRecord> {
    fix.vtc
        .state
        .admin_actions_ks
        .prefix_iter_raw(b"action:".to_vec())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<ActionRecord>(&v).ok())
        .filter(|r| r.kind == kind)
        .collect()
}

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

// ─── custom roles ────────────────────────────────────────────────────────

/// §6.2 end to end: a custom role is defined only through the action list,
/// then granted, and bounds its holder to exactly its ceiling (VTI-ACL-010,
/// -030), resolved from the stored definition.
#[tokio::test]
async fn a_custom_role_defined_through_the_action_list_bounds_its_holders() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = seed(&fix, AdminAuthority::community_admin()).await;

    // Nothing is stored before the second administrator approves.
    let (status, reply) = through(&mut fix, &a, &[&b], DEFINE, events_team()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["role"]["name"], "events-team");
    assert_eq!(reply["payload"]["role"]["builtIn"], false);
    let def = roles::get(&fix.vtc.state.acl_ks, "events-team")
        .await
        .unwrap()
        .expect("defined");
    assert_eq!(def.created_by, a.did);
    assert_eq!(actions_of_kind(&fix, "acl.role.define").await.len(), 1);
    assert_eq!(audit_rows(&fix, "AdminRoleDefined").await.len(), 1);

    // Granted like any built-in role.
    let s = Party::new();
    let (status, reply) = through(
        &mut fix,
        &a,
        &[&b],
        GRANT_V0_2,
        json!({ "entry": {
            "subject": s.did,
            "role": "events-team",
            "act": { "scope": "all" },
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" },
            "approve": { "scope": "all" },
            "approveCapabilities": { "scope": "ceiling" },
        }}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let held = entry(&fix, &s.did).await.unwrap();
    assert!(held.can(Capability::SurfaceAdmin, None));
    assert!(held.can(Capability::InvitationsManage, None));
    assert!(!held.can(Capability::MembersManage, None));
    assert!(!held.can(Capability::RolesAssign, None));
    assert!(held.can_approve(&CapRef::all(Capability::InvitationsManage)));
    assert!(!held.can_approve(&CapRef::all(Capability::SurfaceAdmin)));

    // The list names it beside the built-ins; show counts its holder.
    let (_, listed) = post(&fix.vtc, &signed(&s, LIST, json!({})).await).await;
    let names: Vec<&str> = listed["payload"]["roles"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert!(names.contains(&"community-admin") && names.contains(&"events-team"));
    let (_, shown) = post(
        &fix.vtc,
        &signed(&s, SHOW, json!({"name": "events-team"})).await,
    )
    .await;
    assert_eq!(shown["payload"]["holders"], 1, "{shown}");
}

/// `vtc/roles/define/0.1`'s declared codes, each refused before anyone is
/// asked for a gesture.
#[tokio::test]
async fn vtc_roles_define_refuses_with_its_declared_codes() {
    let fix = fixture().await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let send = |payload: Value| {
        let (vtc, a) = (&fix.vtc, &a);
        async move { post(vtc, &signed(a, DEFINE, payload).await).await.1 }
    };

    let mut p = events_team();
    p["name"] = json!("moderator");
    let reply = send(p).await;
    assert_eq!(tt_error_code(&reply), Some(DEFINE_BUILT_IN_ROLE), "{reply}");

    let mut p = events_team();
    p["ceiling"] = json!([{ "capability": "vtc.everything" }]);
    let reply = send(p).await;
    assert_eq!(
        tt_error_code(&reply),
        Some(DEFINE_UNKNOWN_CAPABILITY),
        "{reply}"
    );
    assert_eq!(
        reply["payload"]["details"]["capabilities"],
        json!(["vtc.everything"])
    );

    let mut p = events_team();
    p["ceiling"] = json!([{ "capability": "git.commit.sign" }]);
    let reply = send(p).await;
    assert_eq!(
        tt_error_code(&reply),
        Some(DEFINE_ADDITIVE_CAPABILITY),
        "{reply}"
    );

    roles::put(
        &fix.vtc.state.acl_ks,
        &stored_role("events-team", &["vtc.surface.admin"]),
    )
    .await
    .unwrap();
    let reply = send(events_team()).await;
    assert_eq!(tt_error_code(&reply), Some(DEFINE_EXISTS), "{reply}");

    let mut p = events_team();
    p["name"] = json!("nobody-team");
    p["replaces"] = json!(true);
    let reply = send(p).await;
    assert_eq!(tt_error_code(&reply), Some(DEFINE_NOT_FOUND), "{reply}");

    // VTI-ACL-042 / -071: a definer cannot put in a role what it lacks.
    let mut narrow = AdminAuthority::community_admin();
    narrow.capabilities = CapabilityScope::listed(
        [
            "vtc.roles.assign",
            "vtc.approvals.admin",
            "vtc.surface.admin",
        ]
        .iter()
        .map(|c| c.parse::<CapRef>().unwrap().into())
        .collect(),
    )
    .unwrap();
    let d = seed(&fix, narrow).await;
    let mut p = events_team();
    p["name"] = json!("auditors-plus");
    p["ceiling"] =
        json!([{ "capability": "vtc.surface.admin" }, { "capability": "vtc.audit.read" }]);
    let reply = post(&fix.vtc, &signed(&d, DEFINE, p).await).await.1;
    assert_eq!(
        tt_error_code(&reply),
        Some(DEFINE_EXCEEDS_DEFINER_AUTHORITY),
        "{reply}"
    );
    assert_eq!(
        reply["payload"]["details"]["capabilities"],
        json!(["vtc.audit.read"])
    );
    assert!(
        roles::get(&fix.vtc.state.acl_ks, "auditors-plus")
            .await
            .unwrap()
            .is_none()
    );
}

/// `vtc/roles/delete/0.1` refuses a built-in, an unknown and a held role
/// (`inUse`, with the count); `show` refuses an unknown one. An unheld role is
/// deleted through the action list.
#[tokio::test]
async fn vtc_roles_delete_refuses_a_held_role_and_deletes_an_unheld_one() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let b = seed(&fix, AdminAuthority::community_admin()).await;

    let reply = post(
        &fix.vtc,
        &signed(&a, DELETE, json!({"name": "auditor"})).await,
    )
    .await
    .1;
    assert_eq!(tt_error_code(&reply), Some(DELETE_BUILT_IN_ROLE), "{reply}");
    let reply = post(
        &fix.vtc,
        &signed(&a, DELETE, json!({"name": "nobody"})).await,
    )
    .await
    .1;
    assert_eq!(tt_error_code(&reply), Some(DELETE_NOT_FOUND), "{reply}");
    let reply = post(&fix.vtc, &signed(&a, SHOW, json!({"name": "nobody"})).await)
        .await
        .1;
    assert_eq!(tt_error_code(&reply), Some(SHOW_NOT_FOUND), "{reply}");

    roles::put(
        &fix.vtc.state.acl_ks,
        &stored_role("events-team", &["vtc.surface.admin"]),
    )
    .await
    .unwrap();
    let holder = seed(&fix, custom_authority("events-team")).await;
    let reply = post(
        &fix.vtc,
        &signed(&a, DELETE, json!({"name": "events-team"})).await,
    )
    .await
    .1;
    assert_eq!(tt_error_code(&reply), Some(DELETE_IN_USE), "{reply}");
    assert_eq!(reply["payload"]["details"]["holders"], 1);

    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &holder.did)
        .await
        .unwrap();
    let (status, reply) =
        through(&mut fix, &a, &[&b], DELETE, json!({"name": "events-team"})).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["deleted"], "events-team");
    assert!(
        roles::get(&fix.vtc.state.acl_ks, "events-team")
            .await
            .unwrap()
            .is_none()
    );
}

/// VTI-ACL-011: an entry naming a role the community has no definition for
/// confers nothing — no capability, no sign-in — and cannot be granted.
#[tokio::test]
async fn vti_acl_011_an_entry_naming_an_unknown_role_confers_nothing() {
    let fix = fixture().await;
    let ghost = seed(&fix, custom_authority("ghost-role")).await;
    let e = entry(&fix, &ghost.did).await.unwrap();
    assert!(Capability::ALL.into_iter().all(|c| !e.can(c, None)));
    assert!(!e.is_administrator());
    assert!(vtc_service::acl::auth_role_for(&e).is_err());

    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let s = Party::new();
    let reply = post(
        &fix.vtc,
        &signed(
            &a,
            GRANT_V0_2,
            json!({ "entry": {
                "subject": s.did,
                "role": "ghost-role",
                "act": { "scope": "all" },
                "keys": { "scope": "none" },
                "capabilities": { "scope": "ceiling" },
            }}),
        )
        .await,
    )
    .await
    .1;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/grant:roleNotRecognized"),
        "{reply}"
    );
    assert!(entry(&fix, &s.did).await.is_none());
}

// ─── approver sets from approve authority ───────────────────────────────

/// VTI-ACL-041: a least-privilege approver — act `none`, an approve scope —
/// is the approver a grant and a reduction need, though it holds nothing. A
/// role definition it approves fails closed, though: a role's ceiling is
/// bounded by what its defining administrators hold (`vtc/roles/define`
/// item 4).
#[tokio::test]
async fn vti_acl_041_a_least_privilege_approver_decides_grants_and_reductions() {
    let mut fix = fixture().await;
    let a = requester(&mut fix).await;
    let approver = seed(&fix, AdminAuthority::for_role(AdminRole::Approver)).await;

    let s = Party::new();
    let (status, reply) = through(
        &mut fix,
        &a,
        &[&approver],
        GRANT_V0_2,
        json!({ "entry": {
            "subject": s.did,
            "role": "community-admin",
            "act": { "scope": "all" },
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" },
            "approve": { "scope": "all" },
            "approveCapabilities": { "scope": "ceiling" },
        }}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &s.did).await.unwrap().is_community_admin());

    let (status, reply) = through(
        &mut fix,
        &a,
        &[&approver],
        REVOKE_V0_2,
        json!({ "subject": s.did, "revocation": { "kind": "entry" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(entry(&fix, &s.did).await.is_none());

    let (status, reply) = through(&mut fix, &a, &[&approver], DEFINE, events_team()).await;
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert!(
        reply.to_string().contains("approver"),
        "the refusal names the approver whose authority fell short: {reply}"
    );
    assert!(
        roles::get(&fix.vtc.state.acl_ks, "events-team")
            .await
            .unwrap()
            .is_none()
    );
}

// ─── a departed granter's grants (§6.3) ──────────────────────────────────

/// The granter `g` leaves; `s`, whose authority `g` delegated, is raised for
/// review as one action in the action list. Returns its id.
async fn depart(fix: &Fixture, g: &Party) -> String {
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &g.did)
        .await
        .unwrap();
    vtc_service::acl::delegation::on_granter_changed(&fix.vtc.state, &g.did, None)
        .await
        .unwrap();
    let items = actions_of_kind(fix, "acl.grants.review").await;
    assert_eq!(items.len(), 1, "one review item for the departed granter");
    assert_eq!(items[0].subject, g.did);
    items[0].id.clone()
}

/// VTI-ACL-071: approving the review re-affirms the grants under the
/// approver's own authority.
#[tokio::test]
async fn vti_acl_071_approving_a_review_reaffirms_the_grants() {
    let fix = fixture().await;
    let g = seed(&fix, AdminAuthority::community_admin()).await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let s = Party::new();
    seed_as(
        &fix,
        &s.did,
        AdminAuthority::for_role(AdminRole::Moderator),
        Some(&g.did),
    )
    .await;
    let id = depart(&fix, &g).await;

    let (status, ack) = decide(&fix.vtc, &a, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    let after = entry(&fix, &s.did).await.unwrap();
    assert_eq!(after.delegated_by.as_deref(), Some(a.did.as_str()));
    assert_eq!(after.admin, AdminAuthority::for_role(AdminRole::Moderator));
    assert!(
        vtc_service::acl::delegation::review_for(&fix.vtc.state, &s.did)
            .await
            .unwrap()
            .is_none()
    );
}

/// Declining withdraws them at once; the membership and community role stay.
#[tokio::test]
async fn vti_acl_071_declining_a_review_withdraws_the_grants() {
    let fix = fixture().await;
    let g = seed(&fix, AdminAuthority::community_admin()).await;
    let a = seed(&fix, AdminAuthority::community_admin()).await;
    let s = Party::new();
    seed_as(
        &fix,
        &s.did,
        AdminAuthority::for_role(AdminRole::Moderator),
        Some(&g.did),
    )
    .await;
    let id = depart(&fix, &g).await;

    let (status, ack) = decide(&fix.vtc, &a, &id, "deny").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    let after = entry(&fix, &s.did).await.unwrap();
    assert_eq!(after.admin, AdminAuthority::none());
    assert_eq!(after.role, VtcRole::Moderator, "the community role stays");
}

/// Letting it lapse leaves the withdrawal to the sweeper, the backstop — and
/// an expired granter departs as surely as a removed one.
#[tokio::test]
async fn vti_acl_071_a_lapsed_review_is_withdrawn_by_the_sweeper() {
    let fix = fixture().await;
    let g = Party::new();
    let mut expired = row(&g.did, AdminAuthority::community_admin(), None);
    expired.expires_at = Some(1);
    store_acl_entry(&fix.vtc.state.acl_ks, &expired)
        .await
        .unwrap();
    let _a = seed(&fix, AdminAuthority::community_admin()).await;
    let s = Party::new();
    seed_as(
        &fix,
        &s.did,
        AdminAuthority::for_role(AdminRole::Moderator),
        Some(&g.did),
    )
    .await;

    // The sweeper notices the expired granter and raises the review.
    vtc_service::acl::delegation::sweep(&fix.vtc.state)
        .await
        .unwrap();
    assert_eq!(actions_of_kind(&fix, "acl.grants.review").await.len(), 1);
    let mut review = vtc_service::acl::delegation::review_for(&fix.vtc.state, &s.did)
        .await
        .unwrap()
        .expect("under review");
    // Nobody decides; the deadline passes.
    review.deadline = 1;
    fix.vtc
        .state
        .admin_actions_ks
        .insert(format!("delegation-review:{}", s.did), &review)
        .await
        .unwrap();
    vtc_service::acl::delegation::sweep(&fix.vtc.state)
        .await
        .unwrap();
    assert_eq!(
        entry(&fix, &s.did).await.unwrap().admin,
        AdminAuthority::none()
    );
}

// ─── rolling an entry to a new key ───────────────────────────────────────

async fn swap(vtc: &TestVtc, by: &Party, payload: Value) -> Value {
    post(vtc, &signed(by, SWAP_KEY, payload).await).await.1
}

fn signing_key(p: &Party) -> ed25519_dalek::SigningKey {
    let (_, bytes) = multibase::decode(&p.secret_multibase).unwrap();
    let seed: [u8; 32] = bytes[..32].try_into().unwrap();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn link_proof(new: &Party, aud: &str, ttl: u64) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    vta_sdk::protocols::acl_management::swap::build_swap_presentation(
        &signing_key(new),
        &new.did,
        aud,
        now,
        ttl,
        None,
    )
}

/// VTI-CLT-025 – 032: a subject rolls its own entry to a new key. The
/// successor carries exactly the predecessor's authority, the delegations it
/// made follow it, the rotation is audited, and the old key has no standing.
#[tokio::test]
async fn vti_clt_025_a_subject_rolls_its_entry_to_a_new_key_with_its_authority_exactly() {
    let fix = fixture().await;
    let r = Party::new();
    let mut before = row(
        &r.did,
        AdminAuthority::community_admin(),
        Some("did:key:zGranter"),
    );
    before.label = Some("primary".into());
    before.expires_at = Some(4_102_444_800);
    store_acl_entry(&fix.vtc.state.acl_ks, &before)
        .await
        .unwrap();
    let d = Party::new();
    seed_as(
        &fix,
        &d.did,
        AdminAuthority::for_role(AdminRole::Moderator),
        Some(&r.did),
    )
    .await;

    let n = Party::new();
    let (status, reply) = post(
        &fix.vtc,
        &signed(
            &r,
            SWAP_KEY,
            json!({
                "currentSubject": r.did,
                "newSubject": n.did,
                "linkProof": link_proof(&n, TEST_VTC_DID, 300),
                "reason": "key-rotation",
            }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["previousSubject"], r.did.as_str());
    assert_eq!(reply["payload"]["entry"]["subject"], n.did.as_str());

    assert!(
        entry(&fix, &r.did).await.is_none(),
        "the old key has no entry"
    );
    let after = entry(&fix, &n.did).await.unwrap();
    assert_eq!(after.admin, before.admin, "authority exactly preserved");
    assert_eq!(after.label, before.label);
    assert_eq!(after.expires_at, before.expires_at);
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(after.created_by, before.created_by);
    assert_eq!(after.delegated_by, before.delegated_by);
    assert_eq!(
        entry(&fix, &d.did).await.unwrap().delegated_by.as_deref(),
        Some(n.did.as_str()),
        "a rotation is not a departure: delegations follow the key"
    );
    assert_eq!(audit_rows(&fix, "AclKeyRotated").await.len(), 1);
    assert!(actions_of_kind(&fix, "acl.grants.review").await.is_empty());
}

/// VTI-CLT-026 – 030: refused unless the subject itself asks and the new key
/// proves it consents — and a refusal moves nothing.
#[tokio::test]
async fn vti_clt_027_a_rotation_needs_the_subject_and_the_new_keys_proof() {
    let fix = fixture().await;
    let r = seed(&fix, AdminAuthority::community_admin()).await;
    let other = seed(&fix, AdminAuthority::community_admin()).await;
    let n = Party::new();
    let body = |proof: Value| {
        let mut p = json!({ "currentSubject": r.did, "newSubject": n.did });
        if !proof.is_null() {
            p["linkProof"] = proof;
        }
        p
    };
    let good = json!(link_proof(&n, TEST_VTC_DID, 300));

    // Another administrator cannot roll someone else's entry.
    let reply = swap(&fix.vtc, &other, body(good.clone())).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:notHolder"),
        "{reply}"
    );
    // The new key's consent is required.
    let reply = swap(&fix.vtc, &r, body(Value::Null)).await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:linkProofRequired"),
        "{reply}"
    );
    // …made by the new key itself,
    let stranger = Party::new();
    let reply = swap(
        &fix.vtc,
        &r,
        body(json!(link_proof(&stranger, TEST_VTC_DID, 300))),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:linkProofInvalid"),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["reason"], "subject_mismatch");
    // …addressed to this community,
    let reply = swap(
        &fix.vtc,
        &r,
        body(json!(link_proof(&n, "did:web:elsewhere", 300))),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:linkProofInvalid"),
        "{reply}"
    );
    // …and short-lived.
    let reply = swap(
        &fix.vtc,
        &r,
        body(json!(link_proof(&n, TEST_VTC_DID, 86_400))),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:linkProofInvalid"),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["reason"], "expired");
    // The new key may not already hold an entry.
    let reply = swap(
        &fix.vtc,
        &r,
        json!({
            "currentSubject": r.did,
            "newSubject": other.did,
            "linkProof": link_proof(&other, TEST_VTC_DID, 300),
        }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:subjectAlreadyInUse"),
        "{reply}"
    );
    // A signer with no entry has nothing to roll.
    let nobody = Party::new();
    let reply = swap(
        &fix.vtc,
        &nobody,
        json!({
            "currentSubject": nobody.did,
            "newSubject": n.did,
            "linkProof": good,
        }),
    )
    .await;
    assert_eq!(
        tt_error_code(&reply),
        Some("acl/swap-key:subjectNotFound"),
        "{reply}"
    );

    assert_eq!(
        entry(&fix, &r.did).await.unwrap().admin,
        AdminAuthority::community_admin(),
        "nothing moved"
    );
    assert!(entry(&fix, &n.did).await.is_none());
    assert!(audit_rows(&fix, "AclKeyRotated").await.is_empty());
}

// ─── single-administrator mode (VTI-APV-022) ─────────────────────────────

/// In single-administrator mode, with nobody but the requester able to
/// approve, defining and deleting a custom role runs on the requester's bound
/// gesture — the consent waived and audited `Critical`, like every other
/// consent kind — and parks nothing.
#[tokio::test]
async fn vti_apv_022_a_sole_admin_defines_and_deletes_a_role_on_their_own_gesture() {
    let mut fix = fixture().await;
    fix.vtc.state.config.write().await.acl.single_admin_mode = true;
    let a = requester(&mut fix).await;

    let (status, reply) = through(&mut fix, &a, &[], DEFINE, events_team()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["payload"]["role"]["name"], "events-team");
    assert!(
        roles::get(&fix.vtc.state.acl_ks, "events-team")
            .await
            .unwrap()
            .is_some()
    );

    let (status, reply) = through(&mut fix, &a, &[], DELETE, json!({"name": "events-team"})).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        roles::get(&fix.vtc.state.acl_ks, "events-team")
            .await
            .unwrap()
            .is_none()
    );

    let waived: Vec<_> = audit_rows(&fix, "SingleAdminMode")
        .await
        .into_iter()
        .filter_map(|env| match env.event {
            vti_common::audit::AuditEvent::SingleAdminMode(d) => Some(d),
            _ => None,
        })
        .filter(|d| d.event == "consentWaived")
        .collect();
    assert_eq!(waived.len(), 2, "each waiver audited");
    assert!(
        actions_of_kind(&fix, "acl.role.define")
            .await
            .iter()
            .chain(actions_of_kind(&fix, "acl.role.delete").await.iter())
            .all(|r| r.status != vtc_service::admin_actions::Status::Open),
        "nothing waits for approval"
    );
}

/// The mode waives nothing while another holder could approve: the
/// definition parks as without it (VTI-APV-022 item 2).
#[tokio::test]
async fn vti_apv_022_a_role_still_parks_when_another_admin_could_approve() {
    let mut fix = fixture().await;
    fix.vtc.state.config.write().await.acl.single_admin_mode = true;
    let a = requester(&mut fix).await;
    let _b = seed(&fix, AdminAuthority::community_admin()).await;
    let doc = signed(&a, DEFINE, events_team()).await;
    let (_, reply) = post(&fix.vtc, &doc).await;
    fix.gesturer.gesture(&fix.vtc, &a, &reply).await;
    let (status, reply) = post(&fix.vtc, &doc).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{reply}");
    assert!(crate::common::second_party::parked_action(&reply).is_some());
    assert!(
        roles::get(&fix.vtc.state.acl_ks, "events-team")
            .await
            .unwrap()
            .is_none()
    );
}
