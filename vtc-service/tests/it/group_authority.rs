//! Groups carrying authority (`vtc/groups/bindings/add` `grants` and `role`
//! bindings, VTI-DIR-100 – 105): what such a group confers is written onto each
//! member's access-control entry, and every change to it is a grant or a
//! reduction with the consent either takes (VTI-DIR-104).
//!
//! The groups are written directly (no credentials, so the community's VTA is
//! never asked); every change to them goes through the signed-document door
//! with the requester's bound gesture and, where it confers or takes away an
//! authority-conferring capability, another administrator's approval.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{
    AdminAuthority, CapRef, Capability, CapabilityGrant, CapabilityScope, VtcAclEntry, VtcRole,
};
use vtc_service::config::GroupsConfig;
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::{Gesturer, parked_action, step_up_request};
use crate::common::signed::{call, error_code, seed_role, signed};

use trust_tasks_rs::specs::vtc::groups as g;

const BINDINGS_ADD_ERR_GROUP_NOT_ELIGIBLE: &str =
    g::bindings::add::v0_1::error_codes::GROUP_NOT_ELIGIBLE.code;
const BINDINGS_ADD_ERR_UNKNOWN_CAPABILITY: &str =
    g::bindings::add::v0_1::error_codes::UNKNOWN_CAPABILITY.code;
const BINDINGS_ADD_ERR_UNKNOWN_ROLE: &str = g::bindings::add::v0_1::error_codes::UNKNOWN_ROLE.code;
const BINDINGS_ADD_ERR_EXCEEDS_BINDER_AUTHORITY: &str =
    g::bindings::add::v0_1::error_codes::EXCEEDS_BINDER_AUTHORITY.code;
const ADD_ERR_EXCEEDS_ROLE_CEILING: &str =
    g::members::add::v0_1::error_codes::EXCEEDS_ROLE_CEILING.code;
const UPDATE_ERR_AUTHORITY_GROUP_LOCKED: &str =
    g::update::v0_1::error_codes::AUTHORITY_GROUP_LOCKED.code;

const RP_ORIGIN: &str = "https://vtc.example.com";
const SPEC: &str = "https://trusttasks.org/spec/vtc/groups";

fn task(name: &str) -> String {
    format!("{SPEC}/{name}/0.1")
}

/// A `trust-task-error` reply's code — the census reads witnesses by this name.
fn tt_error_code(doc: &Value) -> &str {
    error_code(doc).unwrap_or_default()
}

struct Fixture {
    vtc: TestVtc,
    gesturer: Gesturer,
    /// A community administrator: makes the bindings and membership changes.
    admin: Party,
    /// Another community administrator, who approves them.
    approver: Party,
}

async fn fixture() -> Fixture {
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .with_groups(GroupsConfig {
            context: Some("vtc".into()),
            ..Default::default()
        })
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    let mut gesturer = Gesturer::new();
    let admin = crate::common::signed::admin(&vtc).await;
    gesturer.enrol(&vtc, &admin.did).await;
    let approver = crate::common::signed::admin(&vtc).await;
    gesturer.enrol(&vtc, &approver.did).await;
    Fixture {
        vtc,
        gesturer,
        admin,
        approver,
    }
}

/// `who`'s directory entry, made by reading their own card.
async fn entry_of(vtc: &TestVtc, who: &Party) -> String {
    let (status, doc) = call(
        vtc,
        who,
        "https://trusttasks.org/spec/vtc/directory/card/show/0.1",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    doc["payload"]["card"]["entryId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn acl(vtc: &TestVtc, did: &str) -> VtcAclEntry {
    vtc_service::acl::get_acl_entry(&vtc.state.acl_ks, did)
        .await
        .unwrap()
        .unwrap()
}

async fn set_authority(vtc: &TestVtc, did: &str, admin: AdminAuthority) {
    let mut e = acl(vtc, did).await;
    e.admin = admin;
    vtc_service::acl::store_acl_entry(&vtc.state.acl_ks, &e)
        .await
        .unwrap();
}

/// `role`'s full ceiling narrowed to `only`.
fn narrowed(role: AdminAuthority, only: Capability) -> AdminAuthority {
    let mut a = role;
    a.capabilities = CapabilityScope::Listed {
        grants: vec![CapabilityGrant::from(CapRef::all(only))],
    };
    a
}

/// A member with a directory entry, holding `admin`.
async fn member_with(fix: &Fixture, admin: AdminAuthority) -> (Party, String) {
    let p = Party::new();
    seed_role(&fix.vtc, &p.did, VtcRole::Member, &[]).await;
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&p.did))
        .await
        .unwrap();
    let entry = entry_of(&fix.vtc, &p).await;
    set_authority(&fix.vtc, &p.did, admin).await;
    (p, entry)
}

/// A community administrator narrowed to `vtc.audit.read`: a ceiling that
/// admits every capability, holding almost none.
fn narrowed_admin() -> AdminAuthority {
    narrowed(AdminAuthority::community_admin(), Capability::AuditRead)
}

/// A static group, written as `vtc/groups/create` would with no credentials.
async fn group(fix: &Fixture, join_policy: &str) -> String {
    let ks = fix.vtc.state.directory.ks();
    let group_id = format!("grp_{}", &uuid::Uuid::new_v4().simple().to_string()[..22]);
    let group: vtc_service::groups::Group = serde_json::from_value(json!({
        "groupId": group_id,
        "groupDid": format!("did:webvh:Qm{group_id}:groups.example"),
        "signingKeyId": "key-1",
        "name": "Working group",
        "joinPolicy": join_policy,
        "visibility": "members",
        "showMembers": "members",
        "issuesCredentials": false,
        "createdAt": "2026-10-20T00:00:00Z",
        "updatedAt": "2026-10-20T00:00:00Z",
    }))
    .unwrap();
    vtc_service::groups::put(ks, &group).await.unwrap();
    group_id
}

impl Fixture {
    /// Send as the administrator, answering every gesture, with the approver
    /// approving whatever is parked.
    async fn as_admin(&mut self, name: &str, payload: Value) -> (StatusCode, Value) {
        let doc = signed(&self.admin, &task(name), payload).await;
        let approver = Party {
            did: self.approver.did.clone(),
            secret_multibase: self.approver.secret_multibase.clone(),
            secret: self.approver.secret.clone(),
        };
        let admin = Party {
            did: self.admin.did.clone(),
            secret_multibase: self.admin.secret_multibase.clone(),
            secret: self.admin.secret.clone(),
        };
        self.gesturer
            .send_through(&self.vtc, &admin, &[&approver], &doc)
            .await
    }

    /// Send as the administrator, answering every gesture, approving nothing:
    /// the reply once no gesture is asked for any more.
    async fn unapproved(&mut self, name: &str, payload: Value) -> (StatusCode, Value) {
        let doc = signed(&self.admin, &task(name), payload).await;
        let admin = Party {
            did: self.admin.did.clone(),
            secret_multibase: self.admin.secret_multibase.clone(),
            secret: self.admin.secret.clone(),
        };
        for _ in 0..4 {
            let (status, reply) = crate::common::signed::post(&self.vtc, &doc).await;
            if step_up_request(&reply).is_some() {
                self.gesturer.gesture(&self.vtc, &admin, &reply).await;
                continue;
            }
            return (status, reply);
        }
        panic!("the gesture never settled");
    }

    async fn add(&mut self, group_id: &str, entry_id: &str) -> (StatusCode, Value) {
        self.as_admin(
            "members/add",
            json!({ "groupId": group_id, "entryId": entry_id }),
        )
        .await
    }

    async fn bind(&mut self, group_id: &str, binding: Value) -> (StatusCode, Value) {
        self.as_admin(
            "bindings/add",
            json!({ "groupId": group_id, "binding": binding, "reason": "the working group" }),
        )
        .await
    }
}

fn grants(caps: &[&str]) -> Value {
    json!({
        "kind": "grants",
        "grants": caps.iter().map(|c| json!({ "capability": c })).collect::<Vec<_>>(),
    })
}

#[tokio::test]
async fn authority_bindings_add_refuses_what_its_specification_declares() {
    let mut fix = fixture().await;

    // Item 3: only a static, closed group carries authority.
    let open = group(&fix, "request").await;
    let (_, b) = fix.bind(&open, grants(&["vtc.invitations.manage"])).await;
    assert_eq!(
        tt_error_code(&b),
        BINDINGS_ADD_ERR_GROUP_NOT_ELIGIBLE,
        "{b}"
    );

    let closed = group(&fix, "closed").await;
    let (_, b) = fix
        .bind(&closed, grants(&["vtc.invitations.manage", "vtc.no-such"]))
        .await;
    assert_eq!(
        tt_error_code(&b),
        BINDINGS_ADD_ERR_UNKNOWN_CAPABILITY,
        "{b}"
    );
    assert_eq!(
        b["payload"]["details"]["capabilities"],
        json!(["vtc.no-such"])
    );

    let (_, b) = fix
        .bind(&closed, json!({ "kind": "role", "role": "no-such-role" }))
        .await;
    assert_eq!(tt_error_code(&b), BINDINGS_ADD_ERR_UNKNOWN_ROLE, "{b}");

    // VTI-ACL-071: a manager of the group binds only what they hold.
    let (moderator, _) = member_with(
        &fix,
        narrowed(
            AdminAuthority::for_role(vtc_service::acl::AdminRole::Moderator),
            Capability::JoinDecide,
        ),
    )
    .await;
    {
        let mut e = acl(&fix.vtc, &moderator.did).await;
        e.resource_grants.push(
            serde_json::from_value(json!({
                "capability": "vtc.groups.manage",
                "resource": format!("group:{closed}"),
                "delegatedBy": fix.admin.did,
                "grantedAt": chrono::Utc::now(),
            }))
            .unwrap(),
        );
        vtc_service::acl::store_acl_entry(&fix.vtc.state.acl_ks, &e)
            .await
            .unwrap();
    }
    let (_, b) = call(
        &fix.vtc,
        &moderator,
        &task("bindings/add"),
        json!({
            "groupId": closed,
            "binding": grants(&["vtc.invitations.manage"]),
            "reason": "invite",
        }),
    )
    .await;
    assert_eq!(
        tt_error_code(&b),
        BINDINGS_ADD_ERR_EXCEEDS_BINDER_AUTHORITY,
        "{b}"
    );
    assert_eq!(
        b["payload"]["details"]["capabilities"],
        json!(["vtc.invitations.manage"])
    );

    // A binding of nothing authority-conferring takes the gesture alone.
    let (status, b) = fix.bind(&closed, grants(&["vtc.invitations.manage"])).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert_eq!(b["payload"]["binding"]["state"], "active");

    // Item 5 of members/add: a member whose role does not admit what the group
    // confers is refused, not given an inert grant.
    let (_, plain_entry) = member_with(&fix, AdminAuthority::none()).await;
    let (_, b) = fix.add(&closed, &plain_entry).await;
    assert_eq!(tt_error_code(&b), ADD_ERR_EXCEEDS_ROLE_CEILING, "{b}");
    assert_eq!(
        b["payload"]["details"]["capabilities"],
        json!(["vtc.invitations.manage"])
    );

    // update item 3: it stays closed.
    let (_, b) = fix
        .as_admin(
            "update",
            json!({ "groupId": closed, "joinPolicy": "open", "reason": "open it" }),
        )
        .await;
    assert_eq!(tt_error_code(&b), UPDATE_ERR_AUTHORITY_GROUP_LOCKED, "{b}");
}

/// VTI-DIR-104: binding an authority-conferring capability is granting it, so
/// it waits for another administrator; adding a member to the group then is a
/// grant to them, and removing them a reduction — each consented.
#[tokio::test]
async fn vti_dir_104_a_groups_authority_changes_only_with_consent() {
    let mut fix = fixture().await;
    let closed = group(&fix, "closed").await;
    let (first, first_entry) = member_with(&fix, narrowed_admin()).await;
    let (_, b) = fix.add(&closed, &first_entry).await;
    assert_eq!(b["payload"]["member"]["state"], "active", "{b}");

    // Parked: nothing is recorded until the approval.
    let (_, reply) = fix
        .unapproved(
            "bindings/add",
            json!({ "groupId": closed, "binding": grants(&["vtc.config.admin"]), "reason": "ops" }),
        )
        .await;
    let pending = parked_action(&reply).unwrap_or_else(|| panic!("parked: {reply}"));
    assert!(
        vtc_service::groups::bindings::of_group(fix.vtc.state.directory.ks(), &closed)
            .await
            .unwrap()
            .is_empty(),
        "held, not recorded"
    );
    assert!(
        !acl(&fix.vtc, &first.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    let (status, ack) =
        crate::common::second_party::decide(&fix.vtc, &fix.approver, &pending, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(
        acl(&fix.vtc, &first.did)
            .await
            .can(Capability::ConfigAdmin, None),
        "provisioned when the approval executed it"
    );

    // Adding a member is a grant to them: held, approved, then theirs.
    let (second, second_entry) = member_with(&fix, narrowed_admin()).await;
    let (_, reply) = fix
        .unapproved(
            "members/add",
            json!({ "groupId": closed, "entryId": second_entry }),
        )
        .await;
    let held = parked_action(&reply).unwrap_or_else(|| panic!("parked: {reply}"));
    assert!(
        !acl(&fix.vtc, &second.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    let (status, ack) =
        crate::common::second_party::decide(&fix.vtc, &fix.approver, &held, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(
        acl(&fix.vtc, &second.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );

    // Removing one is a reduction: held, approved, then gone.
    let (_, reply) = fix
        .unapproved(
            "members/remove",
            json!({ "groupId": closed, "entryId": second_entry }),
        )
        .await;
    let held = parked_action(&reply).unwrap_or_else(|| panic!("parked: {reply}"));
    assert!(
        acl(&fix.vtc, &second.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    let (status, ack) =
        crate::common::second_party::decide(&fix.vtc, &fix.approver, &held, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(
        !acl(&fix.vtc, &second.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    assert!(acl(&fix.vtc, &second.did).await.group_grants.is_empty());

    // Leaving needs nobody's consent: it is their own.
    let (status, b) = call(
        &fix.vtc,
        &first,
        &task("leave"),
        json!({ "groupId": closed }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert!(
        !acl(&fix.vtc, &first.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
}

/// VTI-DIR-104 with VTI-APV-019: removing the binding, or deleting the group,
/// takes the authority from every member — consented where someone else can
/// consent, and recorded `Critical` per member where nobody can.
#[tokio::test]
async fn vti_dir_104_withdrawing_a_groups_authority_is_a_reduction_of_every_member() {
    let mut fix = fixture().await;
    let closed = group(&fix, "closed").await;
    let (member, entry) = member_with(&fix, narrowed_admin()).await;
    fix.add(&closed, &entry).await;
    let (status, b) = fix.bind(&closed, grants(&["vtc.config.admin"])).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    let binding = b["payload"]["binding"]["bindingId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        acl(&fix.vtc, &member.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );

    // Consented: the approver is no member of the group.
    let (_, reply) = fix
        .unapproved(
            "bindings/remove",
            json!({ "groupId": closed, "bindingId": binding, "reason": "done" }),
        )
        .await;
    let held = parked_action(&reply).unwrap_or_else(|| panic!("parked: {reply}"));
    assert!(
        acl(&fix.vtc, &member.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    let (status, ack) =
        crate::common::second_party::decide(&fix.vtc, &fix.approver, &held, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert!(
        !acl(&fix.vtc, &member.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    assert!(
        vtc_service::groups::bindings::of_group(fix.vtc.state.directory.ks(), &closed)
            .await
            .unwrap()
            .is_empty(),
        "the binding, named by nothing, is gone"
    );

    // Unopposed: with the approver gone nobody else could consent, so the
    // gesture suffices and the reduction is recorded `Critical`.
    fix.bind(&closed, grants(&["vtc.config.admin"])).await;
    assert!(
        acl(&fix.vtc, &member.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    vtc_service::acl::delete_acl_entry(&fix.vtc.state.acl_ks, &fix.approver.did)
        .await
        .unwrap();
    let (status, b) = fix
        .unapproved("delete", json!({ "groupId": closed, "reason": "wound up" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert_eq!(b["payload"]["bindingsRemoved"], 1);
    assert!(
        !acl(&fix.vtc, &member.did)
            .await
            .can(Capability::ConfigAdmin, None)
    );
    let unopposed = fix
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .filter(|env| {
            matches!(
                env.event,
                vti_common::audit::AuditEvent::AuthorityReducedUnopposed(_)
            )
        })
        .count();
    assert_eq!(unopposed, 1, "the member's reduction is recorded Critical");
}

/// A member of the group gains by its binding, so they never approve it.
#[tokio::test]
async fn vti_dir_104_a_groups_members_never_approve_what_it_confers() {
    let mut fix = fixture().await;
    let closed = group(&fix, "closed").await;
    // The only other administrator who could approve is a member of the group.
    store_member(&fix.vtc.state.members_ks, &Member::fresh(&fix.approver.did))
        .await
        .unwrap();
    let approver_entry = entry_of(&fix.vtc, &fix.approver).await;
    let (status, b) = fix.add(&closed, &approver_entry).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    let (_, reply) = fix
        .unapproved(
            "bindings/add",
            json!({ "groupId": closed, "binding": grants(&["vtc.config.admin"]), "reason": "ops" }),
        )
        .await;
    assert!(
        parked_action(&reply).is_none(),
        "nobody outside the group could approve it: {reply}"
    );
    assert!(error_code(&reply).is_some(), "{reply}");
    assert!(
        vtc_service::groups::bindings::of_group(fix.vtc.state.directory.ks(), &closed)
            .await
            .unwrap()
            .is_empty()
    );
}
