//! The community's groups (`vtc/groups/*`; design
//! `docs/05-design-notes/vtc-member-directory.md` §9).
//!
//! A group is a VTC record with an identity of its own: the community's VTA
//! mints each group a `did:webvh` from the `vtc-group` template ([`identity`]),
//! and the community issues it an authority credential to issue its members'
//! membership credentials. This community never holds a group key.
//!
//! # Where authority lives
//!
//! Nowhere in this module. Who manages a group is an access-control resource
//! grant — `vtc.groups.manage` qualified `group:<groupId>` — read from the live
//! entry ([`Standing::read`]); a holder of the capability unqualified manages
//! every group. A group's record never decides who may do anything, and a
//! group's membership credential is evidence for others, never for this
//! community's own gates.
//!
//! # Storage
//!
//! In the `directory` keyspace, beside the cards whose `entryId` keys every
//! membership, so one backup carries both and a rotation (which keeps the
//! entry) moves nothing:
//!
//! - `group:<groupId>` — the record;
//! - `gm:<groupId>:<entryId>` and `mg:<entryId>:<groupId>` — a membership, from
//!   either side;
//! - `greq:<requestId>` — a request to join a `request` group;
//! - `group-did:<path>` — the log of a group identity this community serves.
//!
//! - `gopt:<groupId>:<entryId>` — a member's opt-out of a dynamic group.
//!
//! A static group's members are added, join or ask; a dynamic group's are
//! computed from its rule ([`dynamic`]).

pub mod authority;
pub mod bindings;
pub mod credential;
pub mod dynamic;
pub mod identity;
pub mod managers;
pub mod policy;
pub mod renewal;

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::acl::{Capability, ResourceQualifier, VtcAclEntry};
use crate::server::AppState;

/// Who may see a group, or its member list (`GroupAudience`), narrowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Audience {
    /// The group's managers only.
    Admins,
    /// The group's members and managers.
    GroupMembers,
    /// Every active member.
    Members,
}

impl Audience {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admins" => Some(Audience::Admins),
            "groupMembers" => Some(Audience::GroupMembers),
            "members" => Some(Audience::Members),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Audience::Admins => "admins",
            Audience::GroupMembers => "groupMembers",
            Audience::Members => "members",
        }
    }
}

/// Whether a group's membership is explicit or computed (`GroupKind`), fixed
/// for the group's life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupKind {
    /// Added, joined, or granted on request.
    #[default]
    Static,
    /// Computed from its rule over verified facts ([`dynamic`]).
    Dynamic,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupKind::Static => "static",
            GroupKind::Dynamic => "dynamic",
        }
    }
}

/// How a member comes to be in a static group (`JoinPolicy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinPolicy {
    /// Only a manager adds members.
    Closed,
    /// A member asks; a manager decides.
    Request,
    /// A member joins, where the community's `groups` policy allows.
    Open,
}

impl JoinPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "closed" => Some(JoinPolicy::Closed),
            "request" => Some(JoinPolicy::Request),
            "open" => Some(JoinPolicy::Open),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            JoinPolicy::Closed => "closed",
            JoinPolicy::Request => "request",
            JoinPolicy::Open => "open",
        }
    }
}

/// The community's authority credential to a group: what this community keeps
/// of it. Never the credential itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authority {
    /// The credential's `id`.
    pub credential_id: String,
    pub valid_until: DateTime<Utc>,
    /// Its slot in the community's revocation list, flipped when the group is
    /// deleted.
    pub status_list_index: u32,
}

/// A group, as this community stores it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub group_id: String,
    /// The group's own DID, minted by the community's VTA.
    pub group_did: String,
    /// The VTA key the group signs with, by its id there.
    pub signing_key_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Absent on a group stored before dynamic groups were served: static.
    #[serde(default)]
    pub kind: GroupKind,
    /// A dynamic group's `DynamicRule`, as received and checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<Value>,
    /// A static group's. A dynamic one stores `closed` — nobody joins it by
    /// their own act — and answers none.
    pub join_policy: JoinPolicy,
    pub visibility: Audience,
    pub show_members: Audience,
    pub issues_credentials: bool,
    /// Present while the group issues credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Authority>,
    /// The signed authority credential, which a member's group credential
    /// chains to: kept to hand to its members, never answered on a read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_credential: Option<Value>,
    /// Where this community serves the group identity's log, when it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log_path: Option<String>,
    pub created_at: DateTime<Utc>,
    /// The creating administrator's directory entry, where they have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// One member of a group, as stored (`GroupMember`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub group_id: String,
    pub entry_id: String,
    /// `added` | `joined` | `requestApproved`.
    pub source: String,
    pub since: DateTime<Utc>,
    /// `active` | `pending`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_valid_until: Option<DateTime<Utc>>,
}

/// A member's request to join a `request` group (`GroupJoinRequest`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub request_id: String,
    pub group_id: String,
    pub entry_id: String,
    /// The requester's own note, shown to the group's managers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub created_at: DateTime<Utc>,
    /// `pending` | `approved` | `declined` | `withdrawn`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// The manager who decided, by DID: shown to managers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// Why it was declined: the managers', never shown to the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl JoinRequest {
    /// The request as `GroupJoinRequest`: `message` and `decidedBy` only to the
    /// group's managers.
    pub fn wire(&self, to_manager: bool) -> Value {
        let mut out = json!({
            "requestId": self.request_id,
            "groupId": self.group_id,
            "entryId": self.entry_id,
            "createdAt": self.created_at,
            "state": self.state,
        });
        if let Some(at) = self.decided_at {
            out["decidedAt"] = json!(at);
        }
        if to_manager {
            if let Some(m) = &self.message {
                out["message"] = json!(m);
            }
            if let Some(by) = &self.decided_by {
                out["decidedBy"] = json!(by);
            }
        }
        out
    }
}

fn request_key(request_id: &str) -> Vec<u8> {
    format!("greq:{request_id}").into_bytes()
}

/// A fresh request identifier: `greq_` and 22 characters of randomness.
pub fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "greq_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

pub async fn get_request(
    ks: &KeyspaceHandle,
    request_id: &str,
) -> Result<Option<JoinRequest>, AppError> {
    ks.get(request_key(request_id)).await
}

pub async fn put_request(ks: &KeyspaceHandle, r: &JoinRequest) -> Result<(), AppError> {
    ks.insert(request_key(&r.request_id), r).await?;
    changed();
    Ok(())
}

/// Every request, oldest first.
pub async fn all_requests(ks: &KeyspaceHandle) -> Result<Vec<JoinRequest>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(b"greq:".to_vec()).await? {
        if let Ok(r) = serde_json::from_slice::<JoinRequest>(&raw) {
            out.push(r);
        }
    }
    out.sort_by(|a, b| (a.created_at, &a.request_id).cmp(&(b.created_at, &b.request_id)));
    Ok(out)
}

/// `entry_id`'s pending request to `group_id`, if any.
pub async fn pending_request(
    ks: &KeyspaceHandle,
    group_id: &str,
    entry_id: &str,
) -> Result<Option<JoinRequest>, AppError> {
    Ok(all_requests(ks)
        .await?
        .into_iter()
        .find(|r| r.group_id == group_id && r.entry_id == entry_id && r.state == "pending"))
}

/// A member's departure from the community (`members/remove` items 3 – 5, at
/// departure): every membership ends — so its credentials stop renewing — and
/// every pending request is withdrawn.
pub async fn on_departure(ks: &KeyspaceHandle, entry_id: &str) -> Result<usize, AppError> {
    let _guard = crate::directory::WRITE_LOCK.lock().await;
    let memberships = groups_of(ks, entry_id).await?;
    for m in &memberships {
        remove_membership(ks, &m.group_id, entry_id).await?;
    }
    for mut r in all_requests(ks).await? {
        if r.entry_id == entry_id && r.state == "pending" {
            r.state = "withdrawn".into();
            r.decided_at = Some(Utc::now());
            put_request(ks, &r).await?;
        }
    }
    dynamic::forget_opt_outs(ks, None, Some(entry_id)).await?;
    Ok(memberships.len())
}

/// The groups `viewer` shares with members as the directory's `groups`
/// audience sees them: the groups they belong to whose member list they may
/// see. A group that hides its members never reveals, through somebody's card,
/// who is in it.
pub fn audience_groups(state_groups: &[Group], standing: &Standing) -> BTreeSet<String> {
    state_groups
        .iter()
        .filter(|g| standing.member_of.contains(&g.group_id) && standing.sees_members(g))
        .map(|g| g.group_id.clone())
        .collect()
}

/// A fresh group identifier: `grp_` and 22 characters of randomness.
pub fn new_group_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    use base64::Engine as _;
    format!(
        "grp_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Tell open consoles a group changed (the `groups` topic of
/// `vtc/admin/events/subscribe/0.3`). A hint, carrying nothing: each stream's
/// fingerprint decides whether it concerns a group its recipient manages.
fn changed() {
    crate::admin_events::notify(crate::admin_events::Topic::Groups);
    // Who a group's room bindings cover may have moved.
    bindings::kick();
}

fn group_key(group_id: &str) -> Vec<u8> {
    format!("group:{group_id}").into_bytes()
}

fn member_key(group_id: &str, entry_id: &str) -> Vec<u8> {
    format!("gm:{group_id}:{entry_id}").into_bytes()
}

fn by_entry_key(entry_id: &str, group_id: &str) -> Vec<u8> {
    format!("mg:{entry_id}:{group_id}").into_bytes()
}

pub fn did_log_key(path: &str) -> Vec<u8> {
    format!("group-did:{path}").into_bytes()
}

/// The path group identities' logs are served under.
pub const GROUP_DID_PATH: &str = "group-dids";

pub async fn get(ks: &KeyspaceHandle, group_id: &str) -> Result<Option<Group>, AppError> {
    ks.get(group_key(group_id)).await
}

/// Every group, ordered by identifier.
pub async fn all(ks: &KeyspaceHandle) -> Result<Vec<Group>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks.prefix_iter_raw(b"group:".to_vec()).await? {
        match serde_json::from_slice::<Group>(&raw) {
            Ok(g) => out.push(g),
            Err(e) => tracing::warn!(error = %e, "skipping an unreadable group record"),
        }
    }
    out.sort_by(|a, b| a.group_id.cmp(&b.group_id));
    Ok(out)
}

pub async fn put(ks: &KeyspaceHandle, group: &Group) -> Result<(), AppError> {
    ks.insert(group_key(&group.group_id), group).await?;
    changed();
    Ok(())
}

/// Remove a group and every membership of it; its pending requests are
/// withdrawn.
pub async fn remove(ks: &KeyspaceHandle, group_id: &str) -> Result<usize, AppError> {
    for mut r in all_requests(ks).await? {
        if r.group_id == group_id && r.state == "pending" {
            r.state = "withdrawn".into();
            r.decided_at = Some(Utc::now());
            put_request(ks, &r).await?;
        }
    }
    let members = members_of(ks, group_id).await?;
    for m in &members {
        ks.remove(member_key(group_id, &m.entry_id)).await?;
        ks.remove(by_entry_key(&m.entry_id, group_id)).await?;
    }
    ks.remove(group_key(group_id)).await?;
    renewal::forget(ks, group_id).await?;
    dynamic::forget_opt_outs(ks, Some(group_id), None).await?;
    bindings::on_group_deleted(ks, group_id).await?;
    changed();
    Ok(members.len())
}

/// A group's members, active and pending, ordered by entry.
pub async fn members_of(ks: &KeyspaceHandle, group_id: &str) -> Result<Vec<Membership>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks
        .prefix_iter_raw(format!("gm:{group_id}:").into_bytes())
        .await?
    {
        if let Ok(m) = serde_json::from_slice::<Membership>(&raw) {
            out.push(m);
        }
    }
    out.sort_by(|a, b| a.entry_id.cmp(&b.entry_id));
    Ok(out)
}

/// The DIDs of `group_id`'s members, active or pending, read through their
/// directory entries.
pub async fn member_dids(state: &AppState, group_id: &str) -> Result<BTreeSet<String>, AppError> {
    let ks = state.directory.ks();
    let mut out = BTreeSet::new();
    for m in members_of(ks, group_id).await? {
        if let Some(card) = crate::directory::cards::get(ks, &m.entry_id).await? {
            out.insert(card.did);
        }
    }
    Ok(out)
}

/// The groups an entry belongs to, active or pending.
pub async fn groups_of(ks: &KeyspaceHandle, entry_id: &str) -> Result<Vec<Membership>, AppError> {
    let mut out = Vec::new();
    for (_, raw) in ks
        .prefix_iter_raw(format!("mg:{entry_id}:").into_bytes())
        .await?
    {
        if let Ok(m) = serde_json::from_slice::<Membership>(&raw) {
            out.push(m);
        }
    }
    Ok(out)
}

/// One entry's membership of one group.
pub async fn membership(
    ks: &KeyspaceHandle,
    group_id: &str,
    entry_id: &str,
) -> Result<Option<Membership>, AppError> {
    ks.get(member_key(group_id, entry_id)).await
}

/// Record a membership, from both sides.
pub async fn put_membership(ks: &KeyspaceHandle, m: &Membership) -> Result<(), AppError> {
    ks.insert(member_key(&m.group_id, &m.entry_id), m).await?;
    ks.insert(by_entry_key(&m.entry_id, &m.group_id), m).await?;
    changed();
    Ok(())
}

/// End a membership, from both sides.
pub async fn remove_membership(
    ks: &KeyspaceHandle,
    group_id: &str,
    entry_id: &str,
) -> Result<(), AppError> {
    ks.remove(member_key(group_id, entry_id)).await?;
    ks.remove(by_entry_key(entry_id, group_id)).await?;
    changed();
    renewal::forget_credential(ks, group_id, entry_id).await
}

/// What the caller is to a group, read now.
#[derive(Debug, Clone, Default)]
pub struct Standing {
    pub did: String,
    /// The caller's directory entry, where they have one.
    pub entry_id: Option<String>,
    pub active_member: bool,
    pub administrator: bool,
    /// Holds `vtc.groups.manage` unqualified: manages every group, and creates.
    pub manages_all: bool,
    /// The groups whose manager they were appointed, by grant.
    pub manages: BTreeSet<String>,
    /// The groups they belong to, active.
    pub member_of: BTreeSet<String>,
    /// The groups they belong to, pending.
    pub pending_in: BTreeSet<String>,
    /// The dynamic groups they opted out of.
    pub opted_out: BTreeSet<String>,
    entry: Option<VtcAclEntry>,
}

impl Standing {
    /// `did`'s standing, from the live access-control entry, member record and
    /// directory entry.
    pub async fn read(state: &AppState, did: &str) -> Result<Self, AppError> {
        let entry = crate::acl::get_acl_entry(&state.acl_ks, did).await?;
        let active_member = crate::member_portal::active::active_member(state, did)
            .await?
            .is_some();
        let administrator = entry.as_ref().is_some_and(|e| e.is_administrator());
        let manages_all = entry
            .as_ref()
            .is_some_and(|e| e.can(Capability::GroupsManage, None));
        let now = Utc::now();
        let manages = entry
            .as_ref()
            .map(|e| {
                e.resource_grants
                    .iter()
                    .filter(|g| g.capability == Capability::GroupsManage && g.is_live(now))
                    .filter_map(|g| match &g.resource {
                        ResourceQualifier::Group(id) => Some(id.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ks = state.directory.ks();
        let entry_id = crate::directory::cards::entry_of(ks, did).await?;
        let mut member_of = BTreeSet::new();
        let mut pending_in = BTreeSet::new();
        let mut opted_out = BTreeSet::new();
        if let Some(e) = &entry_id
            && active_member
        {
            for m in groups_of(ks, e).await? {
                if m.state == "active" {
                    member_of.insert(m.group_id);
                } else {
                    pending_in.insert(m.group_id);
                }
            }
            opted_out = dynamic::opted_out_of(ks, e).await?;
        }
        Ok(Standing {
            did: did.to_string(),
            entry_id,
            active_member,
            administrator,
            manages_all,
            manages,
            member_of,
            pending_in,
            opted_out,
            entry,
        })
    }

    /// May this caller use the groups' reads at all (`list` item 1)?
    pub fn may_read(&self) -> bool {
        self.active_member || self.administrator
    }

    /// Does this caller manage `group_id`: by holding the capability
    /// unqualified, or at `group:<groupId>`, read from the live entry.
    /// Whether the caller holds `cap` unqualified, read from their live entry.
    pub fn can(&self, cap: Capability) -> bool {
        self.entry.as_ref().is_some_and(|e| e.can(cap, None))
    }

    pub fn manages(&self, group_id: &str) -> bool {
        self.entry.as_ref().is_some_and(|e| {
            e.can(
                Capability::GroupsManage,
                Some(&ResourceQualifier::Group(group_id.to_string())),
            )
        })
    }

    fn in_audience(&self, group: &Group, audience: Audience) -> bool {
        if self.manages(&group.group_id) {
            return true;
        }
        match audience {
            Audience::Admins => false,
            Audience::GroupMembers => self.member_of.contains(&group.group_id),
            Audience::Members => self.may_read(),
        }
    }

    /// May this caller see that `group` exists (`list` item 2)?
    pub fn sees(&self, group: &Group) -> bool {
        self.in_audience(group, group.visibility)
    }

    /// May this caller see `group`'s member list (`list` item 3)?
    pub fn sees_members(&self, group: &Group) -> bool {
        self.sees(group) && self.in_audience(group, group.show_members)
    }

    /// The caller's own standing in `group` (`myMembership`).
    pub fn my_membership(&self, group_id: &str) -> &'static str {
        if self.member_of.contains(group_id) {
            "member"
        } else if self.pending_in.contains(group_id) {
            "pending"
        } else if self.opted_out.contains(group_id) {
            "optedOut"
        } else {
            "none"
        }
    }
}

/// The entries holding `vtc.groups.manage` qualified to `group_id`, by entry:
/// informational, read from the access-control list (`Group.managers`).
pub async fn managers(state: &AppState, group_id: &str) -> Result<Vec<String>, AppError> {
    let wanted = ResourceQualifier::Group(group_id.to_string());
    let now = Utc::now();
    let mut out = BTreeSet::new();
    for entry in crate::acl::list_acl_entries(&state.acl_ks).await? {
        let appointed = entry.resource_grants.iter().any(|g| {
            g.capability == Capability::GroupsManage && g.resource == wanted && g.is_live(now)
        });
        if appointed
            && let Some(e) =
                crate::directory::cards::entry_of(state.directory.ks(), &entry.did).await?
        {
            out.insert(e);
        }
    }
    Ok(out.into_iter().collect())
}

/// `m` as `GroupMember` for `standing`: `credentialId` and
/// `credentialValidUntil` only to the member themselves and to the group's
/// managers. `fields` is the caller's.
pub fn member_wire(m: &Membership, standing: &Standing, fields: Option<Value>) -> Value {
    let mut out = json!({
        "entryId": m.entry_id,
        "source": m.source,
        "since": m.since,
        "state": m.state,
    });
    if let Some(f) = fields {
        out["fields"] = f;
    }
    let own = standing.entry_id.as_deref() == Some(m.entry_id.as_str());
    if own || standing.manages(&m.group_id) {
        if let Some(c) = &m.credential_id {
            out["credentialId"] = json!(c);
        }
        if let Some(u) = m.credential_valid_until {
            out["credentialValidUntil"] = json!(u);
        }
    }
    out
}

/// `group` as `standing` may see it (`Group`): `memberCount` only where the
/// member list is visible, `managers` and `credentialAuthorityValidUntil` only
/// to its managers.
pub async fn wire(state: &AppState, group: &Group, standing: &Standing) -> Result<Value, AppError> {
    let mut out = json!({
        "groupId": group.group_id,
        "groupDid": group.group_did,
        "name": group.name,
        "kind": group.kind.as_str(),
        "visibility": group.visibility.as_str(),
        "showMembers": group.show_members.as_str(),
        "issuesCredentials": group.issues_credentials,
        // A `grants` or `role` binding, in any state (bindings/remove item 4).
        "carriesAuthority": authority::carries_authority(state, &group.group_id).await?,
        "createdAt": group.created_at,
        "updatedAt": group.updated_at,
    });
    if let Some(d) = &group.description {
        out["description"] = json!(d);
    }
    match (&group.kind, &group.rule) {
        (GroupKind::Dynamic, Some(rule)) => out["rule"] = rule.clone(),
        _ => out["joinPolicy"] = json!(group.join_policy.as_str()),
    }
    if let Some(by) = &group.created_by {
        out["createdBy"] = json!(by);
    }
    if standing.sees_members(group) {
        let count = members_of(state.directory.ks(), &group.group_id)
            .await?
            .iter()
            .filter(|m| m.state == "active")
            .count();
        out["memberCount"] = json!(count);
    }
    if standing.manages(&group.group_id) {
        out["managers"] = json!(managers(state, &group.group_id).await?);
        if let Some(a) = &group.authority {
            out["credentialAuthorityValidUntil"] = json!(a.valid_until);
        }
    }
    Ok(out)
}

/// Why a dynamic rule is refused (`ruleInvalid`): the field it names, if any,
/// and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub field: Option<String>,
    pub reason: String,
}

/// Check a `DynamicRule` against the community's field schema (create item 2):
/// every condition reads a verified fact — the community role, an `admin`- or
/// `credential`-sourced field, personhood, the join date — and never a field a
/// member writes, so nobody joins a group by editing their card.
pub fn check_rule(
    rule: &Value,
    schema: &[crate::directory::model::FieldDef],
) -> Result<(), RuleError> {
    use crate::directory::model::{FieldSource, FieldState, FieldType};
    let bad = |field: Option<&str>, reason: &str| RuleError {
        field: field.map(str::to_string),
        reason: reason.to_string(),
    };
    let conditions = rule
        .get("all")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| bad(None, "a rule lists at least one condition under `all`"))?;
    for c in conditions {
        let fact = c.get("fact").and_then(Value::as_str).unwrap_or_default();
        let op = c.get("op").and_then(Value::as_str).unwrap_or_default();
        let field = c.get("field").and_then(Value::as_str);
        let mut date = fact == "joinedAt";
        match (fact, field) {
            ("field", Some(key)) => {
                let def = schema
                    .iter()
                    .find(|f| f.key == key && f.state == FieldState::Active)
                    .ok_or_else(|| bad(Some(key), "the directory has no such field"))?;
                if !matches!(def.source, FieldSource::Admin | FieldSource::Credential) {
                    return Err(bad(
                        Some(key),
                        "a rule reads only verified facts: an administrator- or                          credential-sourced field, never one a member writes",
                    ));
                }
                date = def.kind == FieldType::Date;
            }
            ("field", None) => return Err(bad(None, "a `field` condition names its field")),
            (_, Some(key)) => {
                return Err(bad(Some(key), "only a `field` condition names a field"));
            }
            ("role" | "personhood" | "joinedAt", None) => {}
            _ => return Err(bad(None, "an unknown fact")),
        }
        let value = c.get("value");
        let values = c.get("values");
        let ok = match op {
            "equals" => value.is_some() && values.is_none(),
            "oneOf" => value.is_none() && values.is_some(),
            "exists" => value.is_none() && values.is_none(),
            "before" | "after" => date && value.is_some_and(Value::is_string) && values.is_none(),
            _ => false,
        };
        if !ok {
            return Err(bad(
                field,
                "the operation does not fit the fact, or its value is missing or extra",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audiences_order_narrowest_first() {
        assert!(Audience::Admins < Audience::GroupMembers);
        assert!(Audience::GroupMembers < Audience::Members);
        for a in [Audience::Admins, Audience::GroupMembers, Audience::Members] {
            assert_eq!(Audience::parse(a.as_str()), Some(a));
        }
    }

    #[test]
    fn a_group_identifier_fits_the_specification() {
        let id = new_group_id();
        let re = regress::Regex::new("^grp_[A-Za-z0-9_-]{16,64}$").unwrap();
        assert!(re.find(&id).is_some(), "{id}");
        assert_ne!(id, new_group_id());
    }
}
