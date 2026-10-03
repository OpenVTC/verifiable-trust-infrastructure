//! Role-based administration at the VTC (`docs/05-design-notes/vtc-admin-roles.md`,
//! phase C1): every administrative operation is gated on the **capability** it
//! needs (§4), held through an administrative role's ceiling (§6.1), and
//! granting is bounded by the granter's own entry (§6.3).
//!
//! - The §4 gate table, driven through the signed-document door for each
//!   built-in role: a role is allowed exactly the operations its ceiling covers
//!   and refused the rest (**VTI-ACL-030**, **-034**).
//! - A qualified repo manager is confined to its namespace (**VTI-ACL-035**).
//! - The `acl/*/0.2` granting bounds (**VTI-ACL-031**, **-033**, **-042**,
//!   **-053**, **-071**, **VTI-OPS-050**), each refused with its declared code.
//! - Granting an authority-conferring capability parks for the consent of its
//!   other holders (**VTI-APV-018**).
//! - The last holder of `vtc.roles.assign` is never removed (**VTI-APV-009**).
//! - 0.1 ↔ 0.2: a 0.1 reader sees what 0.1 can express and is refused the
//!   rest (`acl/_shared/0.2` CONVENTIONS §8).
//! - Console sign-in admits every administrative role.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{
    AdminAuthority, AdminRole, CapRef, Capability, CapabilityGrant, CapabilityScope, VtcAclEntry,
    VtcRole, get_acl_entry, store_acl_entry,
};
use vtc_service::test_support::TestVtc;

use crate::common::signed::{error_code, post, signed};

const GRANT_V2: &str = "https://trusttasks.org/spec/acl/grant/0.2";
const UPDATE_V2: &str = "https://trusttasks.org/spec/acl/update/0.2";
const SHOW_V2: &str = "https://trusttasks.org/spec/acl/show/0.2";
const LIST_V2: &str = "https://trusttasks.org/spec/acl/list/0.2";
const REVOKE_V2: &str = "https://trusttasks.org/spec/acl/revoke/0.2";
const CHANGE_ROLE_V2: &str = "https://trusttasks.org/spec/acl/change-role/0.2";
const SHOW_V1: &str = "https://trusttasks.org/spec/acl/show/0.1";
const LIST_V1: &str = "https://trusttasks.org/spec/acl/list/0.1";
const GRANT_V1: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const UPDATE_V1: &str = "https://trusttasks.org/spec/acl/update/0.1";

async fn fixture() -> TestVtc {
    let vtc = TestVtc::builder()
        .with_public_url("https://vtc.example.com")
        .with_signers(true)
        .with_audit(true)
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .expect("install default policies");
    vtc
}

fn entry(did: &str, role: VtcRole, admin: AdminAuthority) -> VtcAclEntry {
    VtcAclEntry {
        did: did.into(),
        role,
        label: None,
        admin,
        delegated_by: None,
        created_at: 0,
        created_by: "did:key:vtc-install".into(),
        updated_at: None,
        updated_by: None,
        expires_at: None,
    }
}

async fn party_with(vtc: &TestVtc, admin: AdminAuthority) -> Party {
    let p = Party::new();
    store_acl_entry(&vtc.state.acl_ks, &entry(&p.did, VtcRole::Member, admin))
        .await
        .unwrap();
    p
}

fn listed(caps: &[&str]) -> CapabilityScope {
    CapabilityScope::listed(
        caps.iter()
            .map(|c| CapabilityGrant::from(c.parse::<CapRef>().unwrap()))
            .collect(),
    )
    .unwrap()
}

/// A repo manager for `github.com/acme`, as §6.1 sketches one.
fn repo_manager_for_acme() -> AdminAuthority {
    let mut a = AdminAuthority::for_role(AdminRole::RepoManager);
    a.capabilities = listed(&[
        "git.repo.manage@git-ns:github.com/acme",
        "git.ns.admin@git-ns:github.com/acme",
    ]);
    a.approve_capabilities = listed(&["git.repo.manage@git-ns:github.com/acme"]);
    a
}

/// Whether a reply asks for the granter's passkey gesture. These parties hold
/// no passkey, so the refusal names the gesture they cannot give (with one, it
/// carries the ceremony as `details.stepUpRequest` — `signed_step_up.rs`).
fn asks_gesture(doc: &Value) -> bool {
    error_code(doc) == Some("permissionDenied")
        && doc["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("step-up required"))
}

/// Whether a reply is the capability gate's refusal for `cap`.
fn refused_for(doc: &Value, cap: Capability) -> bool {
    error_code(doc) == Some("permissionDenied")
        && doc["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains(cap.as_str()))
}

// ─── the §4 gate table ───────────────────────────────────────────────────

/// One administrative operation and the capability §4 says gates it.
struct Gate {
    task: &'static str,
    cap: Capability,
}

const GATES: &[Gate] = &[
    Gate {
        task: "https://trusttasks.org/spec/config/show/0.1",
        cap: Capability::ConfigAdmin,
    },
    Gate {
        task: "https://trusttasks.org/spec/audit/list/0.1",
        cap: Capability::AuditRead,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/backup/export/0.1",
        cap: Capability::BackupExport,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/admin/invites/list/0.1",
        cap: Capability::RolesAssign,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/members/update/0.1",
        cap: Capability::MembersManage,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/join-requests/decide/0.1",
        cap: Capability::JoinDecide,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/community/profile/update/0.1",
        cap: Capability::SurfaceAdmin,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/vetting/auto-grant/update/0.1",
        cap: Capability::VettingManage,
    },
    Gate {
        task: "https://trusttasks.org/spec/did-management/did/register/0.1",
        cap: Capability::DidAdmin,
    },
    Gate {
        task: "https://trusttasks.org/spec/vtc/invitations/list/0.1",
        cap: Capability::InvitationsManage,
    },
];

/// What each built-in role holds, written out from `vtc-admin-roles.md` §6.1
/// rather than read from the code under test.
fn holds(role: &AdminRole, cap: Capability) -> bool {
    use Capability as C;
    match role {
        AdminRole::CommunityAdmin => cap.as_str().starts_with("vtc."),
        AdminRole::Moderator => {
            matches!(cap, C::MembersManage | C::JoinDecide | C::InvitationsManage)
        }
        AdminRole::VettingLead => cap == C::VettingManage,
        AdminRole::CredentialOfficer => {
            matches!(cap, C::CredentialsIssue | C::CredentialsRevoke)
        }
        AdminRole::Auditor => cap == C::AuditRead,
        AdminRole::RepoManager | AdminRole::Approver | AdminRole::Custom(_) => false,
    }
}

/// VTI-ACL-030 / VTI-ACL-034: every built-in role is allowed exactly the
/// operations its ceiling covers and refused the rest, at the capability gate
/// — table-driven over §4's "Gates" column.
#[tokio::test]
async fn vti_acl_030_each_built_in_role_is_allowed_exactly_its_capabilities() {
    let vtc = fixture().await;
    for role in AdminRole::BUILT_IN {
        let admin = if role == AdminRole::RepoManager {
            repo_manager_for_acme()
        } else {
            AdminAuthority::for_role(role.clone())
        };
        let party = party_with(&vtc, admin).await;
        for gate in GATES {
            let (_, reply) = post(&vtc, &signed(&party, gate.task, json!({})).await).await;
            let refused = refused_for(&reply, gate.cap);
            assert_eq!(
                refused,
                !holds(&role, gate.cap),
                "{role} on {} ({}): {reply}",
                gate.task,
                gate.cap
            );
        }
    }
}

/// An entry with no administrative role is refused every gate, whatever its
/// community role says (VTI-ACL-010: a role is a ceiling, never a grant).
#[tokio::test]
async fn vti_acl_010_the_community_role_alone_confers_nothing() {
    let vtc = fixture().await;
    let p = Party::new();
    store_acl_entry(
        &vtc.state.acl_ks,
        &entry(&p.did, VtcRole::Admin, AdminAuthority::none()),
    )
    .await
    .unwrap();
    for gate in GATES {
        let (status, reply) = post(&vtc, &signed(&p, gate.task, json!({})).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {reply}", gate.task);
    }
}

/// VTI-ACL-030: narrowing an entry below its role's ceiling takes the
/// capability away at the next decision.
#[tokio::test]
async fn vti_acl_030_a_narrowed_entry_holds_only_what_it_lists() {
    let vtc = fixture().await;
    let mut admin = AdminAuthority::community_admin();
    admin.capabilities = listed(&["vtc.audit.read"]);
    let p = party_with(&vtc, admin).await;
    for gate in GATES {
        let (_, reply) = post(&vtc, &signed(&p, gate.task, json!({})).await).await;
        assert_eq!(
            refused_for(&reply, gate.cap),
            gate.cap != Capability::AuditRead,
            "{}: {reply}",
            gate.task
        );
    }
}

// ─── qualifiers ──────────────────────────────────────────────────────────

/// VTI-ACL-035: a qualified repo manager is confined to its namespace — it
/// holds the capability inside `acme` and nowhere else, and nothing
/// community-wide.
#[tokio::test]
async fn vti_acl_035_a_qualified_repo_manager_is_confined_to_its_namespace() {
    let vtc = fixture().await;
    let p = party_with(&vtc, repo_manager_for_acme()).await;
    let e = get_acl_entry(&vtc.state.acl_ks, &p.did)
        .await
        .unwrap()
        .unwrap();
    let inside = "git-repo:github.com/acme/r#4211".parse().unwrap();
    let ns = "git-ns:github.com/acme".parse().unwrap();
    let other = "git-ns:github.com/other".parse().unwrap();
    assert!(e.can(Capability::GitRepoManage, Some(&inside)));
    assert!(e.can(Capability::GitRepoManage, Some(&ns)));
    assert!(!e.can(Capability::GitRepoManage, Some(&other)));
    assert!(!e.can(Capability::GitRepoManage, None));
    assert!(!e.can(Capability::GitNsAdmin, Some(&other)));

    // The ACL lists it under a resource filter read actingIn, and not under
    // another namespace.
    let admin = party_with(&vtc, AdminAuthority::community_admin()).await;
    let (_, reply) = post(
        &vtc,
        &signed(
            &admin,
            LIST_V2,
            json!({
                "capability": "git.repo.manage",
                "resource": "git-repo:github.com/acme/r#4211",
                "direction": "actingIn",
            }),
        )
        .await,
    )
    .await;
    let subjects: Vec<&str> = reply["payload"]["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|e| e["subject"].as_str())
        .collect();
    assert!(subjects.contains(&p.did.as_str()), "{reply}");
    assert!(
        subjects.contains(&admin.did.as_str()),
        "unqualified covers it: {reply}"
    );
    let (_, reply) = post(
        &vtc,
        &signed(
            &admin,
            LIST_V2,
            json!({
                "capability": "git.repo.manage",
                "resource": "git-ns:github.com/other",
                "direction": "actingIn",
            }),
        )
        .await,
    )
    .await;
    assert!(
        !reply["payload"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["subject"] == p.did),
        "{reply}"
    );
}

// ─── granting bounds (acl/grant/0.2) ─────────────────────────────────────

fn grant_v2(subject: &str, role: &str, capabilities: Value) -> Value {
    json!({ "entry": {
        "subject": subject,
        "role": role,
        "act": {"scope": "all"},
        "keys": {"scope": "none"},
        "capabilities": capabilities,
        "approve": {"scope": "none"},
    }})
}

/// The declared codes of `acl/grant/0.2`, each refused with its own code and
/// nothing written (VTI-ACL-031, -032, -033, -071, -053, VTI-OPS-050).
#[tokio::test]
async fn vti_acl_071_the_granting_bounds_refuse_with_their_codes() {
    let vtc = fixture().await;
    let ca = party_with(&vtc, AdminAuthority::community_admin()).await;
    let subject = Party::new();

    // VTI-ACL-031: outside the role's ceiling.
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(
                &subject.did,
                "moderator",
                json!({"scope": "listed", "grants": [{"capability": "vtc.config.admin"}]}),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:capabilityOutsideCeiling"),
        "{reply}"
    );

    // VTI-ACL-032: unknown.
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(
                &subject.did,
                "moderator",
                json!({"scope": "listed", "grants": [{"capability": "vtc.everything"}]}),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:unknownCapability"),
        "{reply}"
    );

    // Unknown role.
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(&subject.did, "godmode", json!({"scope": "ceiling"})),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:roleNotRecognized"),
        "{reply}"
    );

    // VTI-VTC-010: a community has no contexts.
    let mut contexts = grant_v2(&subject.did, "auditor", json!({"scope": "ceiling"}));
    contexts["entry"]["act"] = json!({"scope": "contexts", "contexts": ["ctx-a"]});
    let (_, reply) = post(&vtc, &signed(&ca, GRANT_V2, contexts).await).await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:invalidActScope"),
        "{reply}"
    );

    // VTI-ACL-071: a granter lacking a capability cannot grant it.
    let mut narrow = AdminAuthority::community_admin();
    narrow.capabilities = listed(&["vtc.roles.assign", "vtc.members.manage"]);
    let narrow = party_with(&vtc, narrow).await;
    let (_, reply) = post(
        &vtc,
        &signed(
            &narrow,
            GRANT_V2,
            grant_v2(&subject.did, "auditor", json!({"scope": "ceiling"})),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:delegationExceedsGranter"),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["axes"], json!(["capabilities"]));

    // VTI-ACL-033: additive needs an unrestricted granter.
    let mut narrow_with_export = AdminAuthority::community_admin();
    narrow_with_export.capabilities = listed(&["vtc.roles.assign", "vtc.backup.export"]);
    let granter = party_with(&vtc, narrow_with_export).await;
    let (_, reply) = post(
        &vtc,
        &signed(
            &granter,
            GRANT_V2,
            grant_v2(
                &subject.did,
                "auditor",
                json!({"scope": "listed", "grants": [
                    {"capability": "vtc.audit.read"},
                    {"capability": "vtc.backup.export", "additive": true},
                ]}),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:additiveRequiresUnrestricted"),
        "{reply}"
    );

    // VTI-ACL-042: approve authority wider than the granter's.
    let mut no_approve = AdminAuthority::community_admin();
    no_approve.approve = vtc_service::acl::VtcActScope::None;
    no_approve.approve_capabilities = CapabilityScope::None;
    let no_approve = party_with(&vtc, no_approve).await;
    let mut approving = grant_v2(&subject.did, "moderator", json!({"scope": "ceiling"}));
    approving["entry"]["approve"] = json!({"scope": "all"});
    approving["entry"]["approveCapabilities"] = json!({"scope": "ceiling"});
    let (_, reply) = post(&vtc, &signed(&no_approve, GRANT_V2, approving).await).await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:approveWiderThanGranter"),
        "{reply}"
    );

    // VTI-OPS-050: nobody grants themselves anything.
    let (status, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(&ca.did, "auditor", json!({"scope": "ceiling"})),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");

    assert!(
        get_acl_entry(&vtc.state.acl_ks, &subject.did)
            .await
            .unwrap()
            .is_none(),
        "nothing was written"
    );
}

/// VTI-ACL-053: no grant outlives its granter.
#[tokio::test]
async fn vti_acl_053_a_grant_cannot_outlive_its_granter() {
    let vtc = fixture().await;
    let p = Party::new();
    let mut e = entry(&p.did, VtcRole::Admin, AdminAuthority::community_admin());
    e.expires_at = Some(vtc_service::auth::session::now_epoch() + 3600);
    store_acl_entry(&vtc.state.acl_ks, &e).await.unwrap();
    let subject = Party::new();
    let (_, reply) = post(
        &vtc,
        &signed(
            &p,
            GRANT_V2,
            grant_v2(&subject.did, "auditor", json!({"scope": "ceiling"})),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/grant:delegationExceedsGranter"),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["axes"], json!(["expiresAt"]));
}

/// A grant that confers nothing authority-conferring needs the granter's bound
/// gesture only; a write that widens nothing lands without one, with the
/// granter recorded as `delegatedBy` (§6.3).
#[tokio::test]
async fn a_grant_records_its_granter_as_delegated_by() {
    let vtc = fixture().await;
    let ca = party_with(&vtc, AdminAuthority::community_admin()).await;
    let subject = Party::new();
    let doc = signed(
        &ca,
        GRANT_V2,
        grant_v2(&subject.did, "auditor", json!({"scope": "ceiling"})),
    )
    .await;
    let (status, reply) = post(&vtc, &doc).await;
    // Widening administrative authority asks for a gesture bound to it.
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(asks_gesture(&reply), "{reply}");
    assert!(
        get_acl_entry(&vtc.state.acl_ks, &subject.did)
            .await
            .unwrap()
            .is_none()
    );

    // An existing auditor's label, amended: nothing widens, so no gesture,
    // and the writer is recorded as the granter it is now bounded by.
    let auditor = party_with(&vtc, AdminAuthority::for_role(AdminRole::Auditor)).await;
    let (status, reply) = post(
        &vtc,
        &signed(
            &ca,
            UPDATE_V2,
            json!({ "subject": auditor.did, "label": "audit desk" }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let written = get_acl_entry(&vtc.state.acl_ks, &auditor.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(written.delegated_by.as_deref(), Some(ca.did.as_str()));
    assert_eq!(written.label.as_deref(), Some("audit desk"));
}

// ─── authority-conferring grants park (VTI-APV-018) ──────────────────────

/// VTI-APV-018: granting an authority-conferring capability parks for the
/// consent of its other holders; with none, it is refused before any gesture
/// (VTI-APV-009 at raise time). A grant of `vtc.roles.assign` by the only
/// community administrator cannot happen alone.
#[tokio::test]
async fn vti_apv_018_an_authority_conferring_grant_needs_another_holder() {
    let vtc = fixture().await;
    let ca = party_with(&vtc, AdminAuthority::community_admin()).await;
    let subject = Party::new();
    let (status, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(
                &subject.did,
                "community-admin",
                json!({"scope": "listed", "grants": [{"capability": "vtc.roles.assign"}]}),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    let message = reply["payload"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("vtc.roles.assign"), "{reply}");
    assert!(message.contains("VTI-APV-018"), "{reply}");
    assert!(
        !asks_gesture(&reply),
        "no gesture is asked for a consent nobody can give: {reply}"
    );

    // A moderator is no approver of it: holding nothing authority-conferring,
    // it does not count.
    party_with(&vtc, AdminAuthority::for_role(AdminRole::Moderator)).await;
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(
                &subject.did,
                "community-admin",
                json!({"scope": "listed", "grants": [{"capability": "vtc.roles.assign"}]}),
            ),
        )
        .await,
    )
    .await;
    assert!(
        reply["payload"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("VTI-APV-018"),
        "{reply}"
    );

    // A second community administrator is: the grant now asks the requester's
    // gesture (the step before parking).
    party_with(&vtc, AdminAuthority::community_admin()).await;
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V2,
            grant_v2(
                &subject.did,
                "community-admin",
                json!({"scope": "listed", "grants": [{"capability": "vtc.roles.assign"}]}),
            ),
        )
        .await,
    )
    .await;
    assert!(asks_gesture(&reply), "{reply}");
}

// ─── attrition ───────────────────────────────────────────────────────────

/// VTI-APV-009: the last holder of `vtc.roles.assign` is never removed.
#[tokio::test]
async fn vti_apv_009_the_last_role_assigner_is_never_removed() {
    let vtc = fixture().await;
    let ca = party_with(&vtc, AdminAuthority::community_admin()).await;
    // The other "administrator" holds everything but vtc.roles.assign, so it
    // covers nothing and cannot act; the attrition check is what refuses.
    let mut other = AdminAuthority::community_admin();
    other.capabilities = listed(&["vtc.audit.read"]);
    let _ = party_with(&vtc, other).await;
    assert!(
        vtc_service::acl::admin_consent::check_attrition(&vtc.state, &ca.did)
            .await
            .is_err(),
        "removing the only holder of vtc.roles.assign is refused"
    );
    let second = party_with(&vtc, AdminAuthority::community_admin()).await;
    assert!(
        vtc_service::acl::admin_consent::check_attrition(&vtc.state, &ca.did)
            .await
            .is_ok()
    );
    // And the revoke door says so with its declared code.
    vtc_service::acl::delete_acl_entry(&vtc.state.acl_ks, &second.did)
        .await
        .unwrap();
    let another = party_with(&vtc, AdminAuthority::community_admin()).await;
    vtc_service::acl::delete_acl_entry(&vtc.state.acl_ks, &another.did)
        .await
        .unwrap();
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            REVOKE_V2,
            json!({ "subject": ca.did, "revocation": {"kind": "entry"} }),
        )
        .await,
    )
    .await;
    assert!(error_code(&reply).is_some(), "{reply}");
}

// ─── reading, 0.1 ↔ 0.2 ──────────────────────────────────────────────────

/// `acl/_shared/0.2` CONVENTIONS §8: 0.2 states every axis; 0.1 shows only
/// what it can express and refuses the rest rather than render it lossily.
#[tokio::test]
async fn a_0_1_reader_sees_only_what_0_1_can_express() {
    let vtc = fixture().await;
    let ca = party_with(&vtc, AdminAuthority::community_admin()).await;
    // Conventional: a community administrator whose community role is admin.
    let conventional = Party::new();
    store_acl_entry(
        &vtc.state.acl_ks,
        &entry(
            &conventional.did,
            VtcRole::Admin,
            AdminAuthority::community_admin(),
        ),
    )
    .await
    .unwrap();
    // Not expressible at 0.1: a member holding the auditor role.
    let auditor = party_with(&vtc, AdminAuthority::for_role(AdminRole::Auditor)).await;

    let (_, reply) = post(
        &vtc,
        &signed(&ca, SHOW_V2, json!({ "subject": auditor.did })).await,
    )
    .await;
    let e = &reply["payload"]["entry"];
    assert_eq!(e["role"], "auditor", "{reply}");
    assert_eq!(e["act"], json!({"scope": "all"}));
    assert_eq!(e["capabilities"], json!({"scope": "ceiling"}));
    assert_eq!(e["keys"], json!({"scope": "none"}));
    assert_eq!(e["ext"]["org.openvtc"]["communityRole"], "member");

    let (_, reply) = post(
        &vtc,
        &signed(&ca, SHOW_V1, json!({ "subject": auditor.did })).await,
    )
    .await;
    assert!(error_code(&reply).is_some(), "0.1 refuses it: {reply}");
    let (_, reply) = post(
        &vtc,
        &signed(&ca, SHOW_V1, json!({ "subject": conventional.did })).await,
    )
    .await;
    assert_eq!(reply["payload"]["entry"]["role"], "admin", "{reply}");
    assert_eq!(reply["payload"]["entry"]["scopes"], json!([]));

    let (_, reply) = post(&vtc, &signed(&ca, LIST_V1, json!({})).await).await;
    let subjects: Vec<&str> = reply["payload"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["subject"].as_str())
        .collect();
    assert!(subjects.contains(&conventional.did.as_str()));
    assert!(!subjects.contains(&auditor.did.as_str()), "{reply}");

    let (_, reply) = post(&vtc, &signed(&ca, LIST_V2, json!({})).await).await;
    let subjects: Vec<&str> = reply["payload"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["subject"].as_str())
        .collect();
    assert!(subjects.contains(&auditor.did.as_str()), "{reply}");

    // A 0.1 write to an entry 0.1 cannot express is refused too.
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            UPDATE_V1,
            json!({ "subject": auditor.did, "label": "x" }),
        )
        .await,
    )
    .await;
    assert!(error_code(&reply).is_some(), "{reply}");
    // And a 0.1 grant naming contexts is refused (VTI-VTC-010).
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            GRANT_V1,
            json!({ "entry": { "subject": Party::new().did, "role": "member", "scopes": ["ctx-a"] } }),
        )
        .await,
    )
    .await;
    assert!(error_code(&reply).is_some(), "{reply}");
}

/// Reading the ACL takes an administrative role of any kind; a member is
/// refused.
#[tokio::test]
async fn reading_the_acl_takes_an_administrative_role() {
    let vtc = fixture().await;
    let auditor = party_with(&vtc, AdminAuthority::for_role(AdminRole::Auditor)).await;
    let (status, reply) = post(&vtc, &signed(&auditor, LIST_V2, json!({})).await).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let member = party_with(&vtc, AdminAuthority::none()).await;
    let (status, _) = post(&vtc, &signed(&member, LIST_V2, json!({})).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// `acl/update/0.2` refuses narrowing `act` with its declared code — a
/// narrowing of act is a revocation — and `acl/change-role/0.2` holds its
/// compare-and-swap.
#[tokio::test]
async fn update_and_change_role_at_0_2_hold_their_declared_refusals() {
    let vtc = fixture().await;
    let ca = party_with(&vtc, AdminAuthority::community_admin()).await;
    let auditor = party_with(&vtc, AdminAuthority::for_role(AdminRole::Auditor)).await;
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            UPDATE_V2,
            json!({ "subject": auditor.did, "act": {"scope": "none"} }),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/update:narrowingNotPermitted"),
        "{reply}"
    );
    let (_, reply) = post(
        &vtc,
        &signed(
            &ca,
            CHANGE_ROLE_V2,
            json!({ "subject": auditor.did, "fromRole": "moderator", "toRole": "approver" }),
        )
        .await,
    )
    .await;
    assert_eq!(
        error_code(&reply),
        Some("acl/change-role:stateMismatch"),
        "{reply}"
    );
    assert_eq!(reply["payload"]["details"]["currentRole"], "auditor");
}

// ─── console sign-in ─────────────────────────────────────────────────────

/// Console sign-in admits every administrative role, not only a community
/// administrator — what each may do is read from its entry at every
/// operation.
#[tokio::test]
async fn console_sign_in_admits_every_administrative_role() {
    let vtc = fixture().await;
    for role in AdminRole::BUILT_IN {
        let p = party_with(&vtc, AdminAuthority::for_role(role.clone())).await;
        let (auth_role, contexts) = vtc_service::acl::resolve_auth_role(&vtc.state.acl_ks, &p.did)
            .await
            .unwrap_or_else(|e| panic!("{role} must sign in: {e}"));
        assert_eq!(auth_role, vtc_service::acl::Role::Admin, "{role}");
        assert!(contexts.is_empty(), "{role}: a VTC entry holds no contexts");
    }
    let member = party_with(&vtc, AdminAuthority::none()).await;
    assert!(
        vtc_service::acl::resolve_auth_role(&vtc.state.acl_ks, &member.did)
            .await
            .is_err()
    );
}
