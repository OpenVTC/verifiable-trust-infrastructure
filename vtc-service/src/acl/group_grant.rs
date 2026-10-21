//! **Group grants** — capabilities a group provisions onto its members'
//! entries, with the group as their source (**VTI-DIR-100 – 102**,
//! `vtc/groups/bindings/add` `grants` and `role` bindings).
//!
//! A group never answers an authorization question. What a group carrying
//! authority confers is written here, onto each member's own entry, by
//! [`crate::groups::authority`], and removed when they leave; every gate still
//! asks [`super::VtcAclEntry::can`], which reads this list beside the role.
//!
//! ## One row per source
//!
//! A row names the capability, the group and binding it came through, and the
//! administrator whose authority the binding was made under (its delegator,
//! VTI-ACL-072). Two groups conferring the same capability make two rows, so
//! one group's departure removes only its own and the capability stays while
//! another source still grants it (VTI-DIR-101). A capability the entry holds
//! directly is no row here at all.
//!
//! ## Bounded by the role, at every read
//!
//! A row confers its capability only inside the ceiling of the entry's
//! administrative role, and only while the entry may act (**VTI-DIR-102**,
//! **VTI-DIR-105**: a group confers capabilities within a ceiling, never the
//! ceiling). The bound is applied when the row is read, not only when it is
//! written, so narrowing the role inerts the row at once and widening it again
//! is a conferral the role change's own consent sees
//! ([`super::admin_consent::newly_conferred`] reads
//! [`super::VtcAclEntry::conferring`]). A row confers nothing to approve:
//! approve scope is its own axis (VTI-ACL-040) and stays a direct assignment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::capability::{AdminAuthority, CapRef, Capability, ResourceQualifier};

/// One capability a group provisions onto an entry (`groupGrants`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupGrant {
    pub capability: Capability,
    /// Absent: community-wide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceQualifier>,
    /// The group it came through — its source.
    pub group_id: String,
    /// The binding that conferred it.
    pub binding_id: String,
    /// The administrator whose authority the binding was made under
    /// (**VTI-ACL-072**).
    pub delegated_by: String,
    pub granted_at: DateTime<Utc>,
}

impl GroupGrant {
    /// The reference this row answers for.
    pub fn cap_ref(&self) -> CapRef {
        CapRef::new(self.capability, self.resource.clone())
    }

    /// Whether this row is in effect for an entry with authority `admin`: the
    /// entry may act, and its role's ceiling admits the capability.
    pub fn in_effect(&self, admin: &AdminAuthority) -> bool {
        admin.act.is_all() && admin.ceiling_admits(&self.cap_ref())
    }

    /// Same capability and qualifier, through the same binding — the identity
    /// a provisioning pass compares rows by.
    pub fn same_row(&self, other: &GroupGrant) -> bool {
        self.capability == other.capability
            && self.resource == other.resource
            && self.group_id == other.group_id
            && self.binding_id == other.binding_id
    }
}

/// The capabilities `grants` confer on an entry with authority `admin` (see
/// [`GroupGrant::in_effect`]).
pub fn effective(admin: &AdminAuthority, grants: &[GroupGrant]) -> Vec<CapRef> {
    grants
        .iter()
        .filter(|g| g.in_effect(admin))
        .map(GroupGrant::cap_ref)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminRole, CapabilityGrant, CapabilityScope, VtcAclEntry, VtcRole};

    fn row(cap: Capability, group: &str) -> GroupGrant {
        GroupGrant {
            capability: cap,
            resource: None,
            group_id: group.into(),
            binding_id: format!("gb_{group}"),
            delegated_by: "did:key:zBinder".into(),
            granted_at: Utc::now(),
        }
    }

    /// A moderator narrowed to `vtc.join.decide` alone.
    fn narrowed_moderator() -> VtcAclEntry {
        let mut admin = AdminAuthority::for_role(AdminRole::Moderator);
        admin.capabilities = CapabilityScope::Listed {
            grants: vec![CapabilityGrant::from(CapRef::all(Capability::JoinDecide))],
        };
        VtcAclEntry::new("did:key:zM", VtcRole::Member, admin, "did:key:zI")
    }

    /// VTI-DIR-100 / VTI-DIR-102: a group's grant is the entry's capability,
    /// within the role's ceiling and nowhere beyond it.
    #[test]
    fn vti_dir_102_a_group_grant_confers_only_inside_the_ceiling() {
        let mut e = narrowed_moderator();
        assert!(!e.can(Capability::InvitationsManage, None));
        e.group_grants = vec![
            row(Capability::InvitationsManage, "grp_a"),
            // Outside a moderator's ceiling: written, and inert.
            row(Capability::RolesAssign, "grp_a"),
        ];
        assert!(e.can(Capability::InvitationsManage, None));
        assert!(!e.can(Capability::RolesAssign, None));
        assert!(e.holds(&CapRef::all(Capability::InvitationsManage)));
        assert!(
            e.capability_list()
                .contains(&"vtc.invitations.manage".to_string())
        );
        assert!(
            !e.capability_list()
                .contains(&"vtc.roles.assign".to_string())
        );
    }

    /// VTI-DIR-105: no role, no ceiling — a group confers nothing on an entry
    /// that holds no administrative role, and nothing while it may not act.
    #[test]
    fn vti_dir_105_a_group_never_supplies_the_ceiling() {
        let mut plain = VtcAclEntry::new(
            "did:key:zP",
            VtcRole::Member,
            AdminAuthority::none(),
            "did:key:zI",
        );
        plain.group_grants = vec![row(Capability::InvitationsManage, "grp_a")];
        assert!(!plain.can(Capability::InvitationsManage, None));

        let mut idle = narrowed_moderator();
        idle.admin.act = crate::acl::VtcActScope::None;
        idle.group_grants = vec![row(Capability::InvitationsManage, "grp_a")];
        assert!(!idle.can(Capability::InvitationsManage, None));
    }

    /// A group grant confers act, never approve (VTI-ACL-040).
    #[test]
    fn a_group_grant_confers_nothing_to_approve() {
        let mut e = narrowed_moderator();
        e.admin.approve = crate::acl::VtcActScope::None;
        e.group_grants = vec![row(Capability::MembersManage, "grp_a")];
        assert!(e.can(Capability::MembersManage, None));
        assert!(!e.can_approve(&CapRef::all(Capability::MembersManage)));
    }

    /// VTI-APV-018: what a group grant confers counts as conferred, so the
    /// consent machinery sees it.
    #[test]
    fn a_conferring_group_grant_is_counted_as_conferred() {
        let mut e = VtcAclEntry::new(
            "did:key:zC",
            VtcRole::Member,
            AdminAuthority::community_admin(),
            "did:key:zI",
        );
        e.admin.capabilities = CapabilityScope::Listed {
            grants: vec![CapabilityGrant::from(CapRef::all(Capability::AuditRead))],
        };
        let before = e.clone();
        e.group_grants = vec![row(Capability::RolesAssign, "grp_a")];
        let now = vti_common::auth::session::now_epoch();
        assert_eq!(
            crate::acl::admin_consent::newly_conferred(Some(&before), &e, now),
            vec![CapRef::all(Capability::RolesAssign)]
        );
        assert_eq!(
            crate::acl::admin_consent::lost_conferring(&e, Some(&before), now),
            vec![CapRef::all(Capability::RolesAssign)]
        );
    }

    #[test]
    fn a_row_round_trips() {
        let mut g = row(Capability::RoomsManage, "grp_a");
        g.resource = Some(ResourceQualifier::Group("grp_b".into()));
        let v = serde_json::to_value(&g).unwrap();
        assert_eq!(v["groupId"], "grp_a");
        assert_eq!(serde_json::from_value::<GroupGrant>(v).unwrap(), g);
    }
}
