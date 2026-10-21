//! What a group **carrying authority** provisions: the capabilities of its
//! `grants` and `role` bindings, written onto each member's access-control
//! entry with the group as their source (**VTI-DIR-100 – 102**,
//! [`crate::acl::group_grant`]).
//!
//! The group itself never answers an authorization question. [`provision`]
//! makes one entry's `groupGrants` what its groups say they should be — every
//! row a capability of an active authority binding of a group the subject is an
//! active member of — and nothing else; every gate then reads the entry
//! (`VtcAclEntry::can`). It is idempotent: the membership tasks call it for the
//! member they change, and the binding reconciler calls [`provision_all`] each
//! pass, so a change the tasks did not reach still settles.
//!
//! # The bounds
//!
//! - **The member's role** (VTI-DIR-102, VTI-DIR-105). A row is written for
//!   every capability the binding confers, and counts only inside the ceiling
//!   of the member's administrative role, at every read. Narrowing the role
//!   inerts it at once; widening it again is a conferral the role change's own
//!   consent sees.
//! - **The binder's holdings** (VTI-DIR-102, VTI-ACL-071). A capability is
//!   provisioned only while the administrator the binding was made under —
//!   its delegator — holds it themselves, at a qualifier at least as wide,
//!   from anything **but** a group: a group cannot be used to manufacture a
//!   capability nobody behind it held, nor keep alive one its binder gave
//!   itself through it. A binder who loses it takes it from every member.
//! - **Static and closed** (VTI-DIR-103). A group whose join policy is not
//!   `closed` provisions nothing, whatever its bindings say.
//!
//! A suspended member keeps their rows: a suspension authorizes nothing while
//! it lasts and leaves the entry exactly as it was for when it is cancelled.

use std::collections::BTreeSet;

use chrono::Utc;
use serde_json::Value;
use vti_common::audit::{AuditEvent, GroupGrantsChangedData};
use vti_common::error::AppError;

use super::bindings::{self, Binding};
use super::{Group, JoinPolicy};
use crate::acl::group_grant::GroupGrant;
use crate::acl::{AdminRole, CapRef, VtcAclEntry, get_acl_entry, store_acl_entry};
use crate::server::AppState;

/// A `grants` or `role` binding's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityBinding {
    Grants(Vec<CapRef>),
    Role(String),
}

impl AuthorityBinding {
    /// The authority binding `spec` is, if it is one. `None` for a room
    /// binding, or for grants this build cannot read (which then provision
    /// nothing).
    pub fn from_spec(spec: &Value) -> Option<Self> {
        match spec.get("kind").and_then(Value::as_str)? {
            "grants" => serde_json::from_value(spec.get("grants")?.clone())
                .ok()
                .map(Self::Grants),
            "role" => spec
                .get("role")
                .and_then(Value::as_str)
                .map(|r| Self::Role(r.to_string())),
            _ => None,
        }
    }
}

/// Whether `spec` is a `grants` or `role` binding — one that makes its group
/// carry authority.
pub fn confers_authority(spec: &Value) -> bool {
    matches!(
        spec.get("kind").and_then(Value::as_str),
        Some("grants" | "role")
    )
}

/// The capabilities a role confers by reference: its ceiling, as stored now
/// for a custom role, each capability the role may hold community-wide or at
/// any qualifier for a built-in one. `None`: no role of that name is defined.
pub async fn role_capabilities(
    state: &AppState,
    name: &str,
) -> Result<Option<Vec<CapRef>>, AppError> {
    let Ok(role) = name.parse::<AdminRole>() else {
        return Ok(None);
    };
    if let AdminRole::Custom(custom) = &role {
        return Ok(crate::acl::roles::get(&state.acl_ks, custom)
            .await?
            .map(|d| d.ceiling));
    }
    Ok(Some(
        role.ceiling()
            .into_iter()
            .filter(|i| i.qualification != crate::acl::capability::Qualification::Required)
            .map(|i| CapRef::all(i.capability))
            .collect(),
    ))
}

/// What `binding` confers, read now. Empty for a role no longer defined.
pub async fn capabilities_of(
    state: &AppState,
    binding: &AuthorityBinding,
) -> Result<Vec<CapRef>, AppError> {
    Ok(match binding {
        AuthorityBinding::Grants(g) => g.clone(),
        AuthorityBinding::Role(name) => role_capabilities(state, name).await?.unwrap_or_default(),
    })
}

/// Whether the groups' binder `entry` holds `cap` themselves — directly or by
/// a resource grant, never through a group (module docs).
pub fn binder_holds(entry: &VtcAclEntry, cap: &CapRef) -> bool {
    let mut own = entry.clone();
    own.group_grants.clear();
    own.holds(cap)
}

/// The administrator a binding was made under: its delegator.
pub fn binder(b: &Binding) -> &str {
    b.delegated_by.as_deref().unwrap_or(&b.created_by)
}

/// Whether `entry` stands as a member whose groups provision onto it: a live,
/// non-`application` entry with a member record that is not removed.
async fn provisionable(state: &AppState, entry: &VtcAclEntry) -> Result<bool, AppError> {
    if entry.is_expired(vti_common::auth::session::now_epoch()) || entry.is_application() {
        return Ok(false);
    }
    Ok(crate::members::get_member(&state.members_ks, &entry.did)
        .await?
        .is_some_and(|m| !m.is_removed()))
}

/// The rows `entry`'s groups say it should hold, with `granted_at` kept from
/// any row it already holds.
async fn desired(state: &AppState, entry: &VtcAclEntry) -> Result<Vec<GroupGrant>, AppError> {
    if !provisionable(state, entry).await? {
        return Ok(Vec::new());
    }
    let ks = state.directory.ks();
    let Some(entry_id) = crate::directory::cards::entry_of(ks, &entry.did).await? else {
        return Ok(Vec::new());
    };
    let now = Utc::now();
    let mut out: Vec<GroupGrant> = Vec::new();
    for m in super::groups_of(ks, &entry_id).await? {
        if m.state != "active" {
            continue;
        }
        let Some(group) = super::get(ks, &m.group_id).await? else {
            continue;
        };
        out.extend(rows_for(state, entry, &group, now).await?);
    }
    Ok(out)
}

/// The rows `group` provisions onto `entry`, a member of it.
async fn rows_for(
    state: &AppState,
    entry: &VtcAclEntry,
    group: &Group,
    now: chrono::DateTime<Utc>,
) -> Result<Vec<GroupGrant>, AppError> {
    if group.join_policy != JoinPolicy::Closed {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for b in bindings::of_group(state.directory.ks(), &group.group_id).await? {
        if b.state != Binding::ACTIVE {
            continue;
        }
        let Some(ab) = AuthorityBinding::from_spec(&b.binding) else {
            continue;
        };
        let binder_did = binder(&b);
        let Some(binder_entry) = get_acl_entry(&state.acl_ks, binder_did).await? else {
            continue;
        };
        for cap in capabilities_of(state, &ab).await? {
            if !binder_holds(&binder_entry, &cap) {
                continue;
            }
            let mut row = GroupGrant {
                capability: cap.capability,
                resource: cap.resource,
                group_id: group.group_id.clone(),
                binding_id: b.binding_id.clone(),
                delegated_by: binder_did.to_string(),
                granted_at: now,
            };
            if let Some(held) = entry.group_grants.iter().find(|g| g.same_row(&row)) {
                row.granted_at = held.granted_at;
            }
            if !out.iter().any(|g: &GroupGrant| g.same_row(&row)) {
                out.push(row);
            }
        }
    }
    Ok(out)
}

/// What one [`provision`] changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub added: Vec<GroupGrant>,
    pub removed: Vec<GroupGrant>,
}

impl Provisioned {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Make `did`'s group grants what its groups say they should be, and audit
/// each group's change by reference. Under the git-namespace write lock, which
/// every `acl/*` write takes to keep the grants it does not own.
pub async fn provision(state: &AppState, did: &str) -> Result<Provisioned, AppError> {
    let changed = {
        let _guard = crate::git_ns::store::write_lock().await;
        let Some(mut entry) = get_acl_entry(&state.acl_ks, did).await? else {
            return Ok(Provisioned::default());
        };
        let want = desired(state, &entry).await?;
        let changed = Provisioned {
            added: want
                .iter()
                .filter(|w| !entry.group_grants.iter().any(|g| g.same_row(w)))
                .cloned()
                .collect(),
            removed: entry
                .group_grants
                .iter()
                .filter(|g| !want.iter().any(|w| w.same_row(g)))
                .cloned()
                .collect(),
        };
        if changed.is_empty() {
            return Ok(changed);
        }
        entry.group_grants = want;
        store_acl_entry(&state.acl_ks, &entry).await?;
        changed
    };
    audit(state, did, &changed).await;
    Ok(changed)
}

/// [`provision`] every entry that holds a group grant or belongs to a group
/// carrying authority. Returns how many entries changed.
pub async fn provision_all(state: &AppState) -> Result<usize, AppError> {
    let ks = state.directory.ks();
    let mut dids: BTreeSet<String> = crate::acl::list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| !e.group_grants.is_empty())
        .map(|e| e.did)
        .collect();
    let mut authority_groups = BTreeSet::new();
    for b in bindings::all(ks).await? {
        if confers_authority(&b.binding) {
            authority_groups.insert(b.group_id);
        }
    }
    for group_id in &authority_groups {
        for m in super::members_of(ks, group_id).await? {
            if let Some(card) = crate::directory::cards::get(ks, &m.entry_id).await? {
                dids.insert(card.did);
            }
        }
    }
    let mut n = 0;
    for did in dids {
        match provision(state, &did).await {
            Ok(p) if !p.is_empty() => n += 1,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "a member's group grants could not be provisioned")
            }
        }
    }
    Ok(n)
}

/// Whether `group_id` carries authority: it has a `grants` or `role` binding
/// in any state (bindings/remove item 4: until the last is gone).
pub async fn carries_authority(state: &AppState, group_id: &str) -> Result<bool, AppError> {
    Ok(bindings::of_group(state.directory.ks(), group_id)
        .await?
        .iter()
        .any(|b| confers_authority(&b.binding)))
}

/// One `GroupGrantsChanged` row per (group, binding) a provisioning touched.
async fn audit(state: &AppState, did: &str, changed: &Provisioned) {
    let Some(writer) = state.audit_writer.as_ref() else {
        tracing::warn!("audit writer not configured: a group grant change is unaudited");
        return;
    };
    let entry_id = crate::directory::cards::entry_of(state.directory.ks(), did)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut sources: BTreeSet<(String, String)> = BTreeSet::new();
    for g in changed.added.iter().chain(&changed.removed) {
        sources.insert((g.group_id.clone(), g.binding_id.clone()));
    }
    for (group_id, binding_id) in sources {
        let of = |rows: &[GroupGrant]| -> Vec<String> {
            rows.iter()
                .filter(|g| g.group_id == group_id && g.binding_id == binding_id)
                .map(|g| g.cap_ref().display())
                .collect()
        };
        let event = AuditEvent::GroupGrantsChanged(GroupGrantsChangedData {
            group_id: group_id.clone(),
            binding_id: binding_id.clone(),
            entry_id: entry_id.clone(),
            added: of(&changed.added),
            removed: of(&changed.removed),
        });
        let community = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .unwrap_or_default();
        if let Err(e) = writer.write(&community, None, event).await {
            tracing::warn!(error = %e, "a group grant change could not be audited");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Capability;
    use serde_json::json;

    #[test]
    fn an_authority_binding_reads_its_terms() {
        assert_eq!(
            AuthorityBinding::from_spec(&json!({
                "kind": "grants",
                "grants": [
                    { "capability": "vtc.invitations.manage" },
                    { "capability": "vtc.groups.manage", "resource": "group:grp_x" },
                ],
            })),
            Some(AuthorityBinding::Grants(vec![
                CapRef::all(Capability::InvitationsManage),
                CapRef::new(
                    Capability::GroupsManage,
                    Some(crate::acl::ResourceQualifier::Group("grp_x".into()))
                ),
            ]))
        );
        assert_eq!(
            AuthorityBinding::from_spec(&json!({ "kind": "role", "role": "custom:moderator" })),
            Some(AuthorityBinding::Role("custom:moderator".into()))
        );
        let room =
            json!({ "kind": "room", "roomId": "did:x", "actions": ["read"], "validFor": "P30D" });
        assert_eq!(AuthorityBinding::from_spec(&room), None);
        assert!(!confers_authority(&room));
    }

    /// VTI-DIR-102: a binder's holdings bound what the group provisions, and a
    /// holding the binder has only through a group does not count.
    #[test]
    fn vti_dir_102_a_binder_holds_only_what_no_group_gave_them() {
        let mut admin = crate::acl::AdminAuthority::community_admin();
        admin.capabilities = crate::acl::CapabilityScope::Listed {
            grants: vec![crate::acl::CapabilityGrant::from(CapRef::all(
                Capability::AuditRead,
            ))],
        };
        let mut binder = VtcAclEntry::new(
            "did:key:zB",
            crate::acl::VtcRole::Member,
            admin,
            "did:key:zI",
        );
        let invite = CapRef::all(Capability::InvitationsManage);
        assert!(binder_holds(&binder, &CapRef::all(Capability::AuditRead)));
        assert!(!binder_holds(&binder, &invite));
        binder.group_grants = vec![GroupGrant {
            capability: Capability::InvitationsManage,
            resource: None,
            group_id: "grp_a".into(),
            binding_id: "gb_a".into(),
            delegated_by: "did:key:zB".into(),
            granted_at: Utc::now(),
        }];
        assert!(binder.holds(&invite));
        assert!(!binder_holds(&binder, &invite));
    }
}
