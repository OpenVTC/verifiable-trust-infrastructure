//! Who may grant what — `docs/05-design-notes/vtc-admin-roles.md` §6.3 and
//! `acl/_shared/0.2` CONVENTIONS §9.
//!
//! A grant is a **delegation** of the granter's own authority, evaluated against
//! the granter's stored entry — never a session or credential summarising it —
//! and the resulting entry must not exceed the granter on any axis:
//!
//! | Axis | Bound | Refusal |
//! |---|---|---|
//! | each capability | held by the granter, with `vtc.roles.assign`, at a qualifier at least as wide (**VTI-ACL-071**) | `delegationExceedsGranter` |
//! | additive capabilities | the granter is unrestricted (**VTI-ACL-033**) | `additiveRequiresUnrestricted` |
//! | approve scope / approvable capabilities | within the granter's own (**VTI-ACL-042**) | `approveWiderThanGranter` |
//! | act scope | within the granter's | `delegationExceedsGranter` |
//! | expiry | no later than the granter's (**VTI-ACL-053**) | `delegationExceedsGranter` |
//! | role | `community-admin` only from a `community-admin` | `permissionDenied` |
//! | subject | never the granter itself (**VTI-OPS-050**, **VTI-ACL-052**) | `permissionDenied` |
//!
//! "Every axis that can be narrowed can be widened again, so the bound applies
//! to all of them" (CONVENTIONS §9): it is the **whole resulting entry** that is
//! checked, on a rewrite as on a creation. The same containment, read the other
//! way, decides who may modify or remove an entry at all ([`covers_entry`],
//! **VTI-ACL-050**).

use super::capability::{AdminRole, CapRef, Capability, CapabilityScope, CeilingError};
use super::{VtcAclEntry, VtcActScope};

/// Why a granter may not write an entry. Each maps to an `acl/grant/0.2` code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRefusal {
    /// `permissionDenied`.
    PermissionDenied(String),
    /// `delegationExceedsGranter`, naming the axes.
    DelegationExceedsGranter {
        axes: Vec<&'static str>,
        detail: String,
    },
    /// `approveWiderThanGranter`.
    ApproveWiderThanGranter(String),
    /// `additiveRequiresUnrestricted`.
    AdditiveRequiresUnrestricted,
    /// The entry does not fit its role (`roleNotRecognized`,
    /// `capabilityOutsideCeiling`, `additiveWithinCeiling`).
    Ceiling(CeilingError),
}

impl std::fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantRefusal::PermissionDenied(m) => f.write_str(m),
            GrantRefusal::DelegationExceedsGranter { detail, .. } => write!(
                f,
                "{detail} — an entry you write cannot exceed your own (VTI-ACL-071, VTI-ACL-053)"
            ),
            GrantRefusal::ApproveWiderThanGranter(m) => write!(
                f,
                "{m} — you cannot confer approve authority wider than your own (VTI-ACL-042)"
            ),
            GrantRefusal::AdditiveRequiresUnrestricted => f.write_str(
                "an additive capability is granted only by a community administrator holding \
                 the full ceiling (VTI-ACL-033)",
            ),
            GrantRefusal::Ceiling(e) => write!(f, "{e}"),
        }
    }
}

/// Whether `entry` is **unrestricted**: a live `community-admin` with act `all`
/// and its full ceiling — what VTI-ACL-033 asks of a granter of additive
/// capabilities.
#[must_use]
pub fn is_unrestricted(entry: &VtcAclEntry, now: u64) -> bool {
    !entry.is_expired(now)
        && entry.admin.admin_role == Some(AdminRole::CommunityAdmin)
        && entry.admin.act.is_all()
        && entry.admin.capabilities == CapabilityScope::Ceiling
}

/// Whether `granter` holds `c` **and** `vtc.roles.assign` at a qualifier
/// covering it — what granting (or taking away) `c` needs (§6.3).
fn may_assign(granter: &VtcAclEntry, c: &CapRef) -> bool {
    granter.admin.holds(c)
        && granter
            .admin
            .holds(&CapRef::new(Capability::RolesAssign, c.resource.clone()))
}

/// Check that `granter` may write `next` (§6.3, CONVENTIONS §9). `next` is the
/// whole resulting entry. Ceiling validation runs first, so an entry that could
/// never be held is refused for that before the granter is weighed.
pub fn check_write(
    granter: &VtcAclEntry,
    next: &VtcAclEntry,
    now: u64,
) -> Result<(), GrantRefusal> {
    next.admin
        .validate_against_ceiling()
        .map_err(GrantRefusal::Ceiling)?;

    if granter.is_expired(now) {
        return Err(GrantRefusal::PermissionDenied(format!(
            "your ACL entry ({}) has expired; an expired entry confers no authority to grant \
             (VTI-ACL-004)",
            granter.did
        )));
    }
    if granter.did == next.did {
        return Err(GrantRefusal::PermissionDenied(
            "you cannot grant yourself anything (VTI-OPS-050, VTI-ACL-052) — you may change \
             your own entry's label, but any other change must be made by another \
             administrator holding vtc.roles.assign"
                .into(),
        ));
    }
    if !granter.admin.can_any(Capability::RolesAssign) {
        return Err(GrantRefusal::PermissionDenied(format!(
            "{} does not hold vtc.roles.assign, which writing an ACL entry needs (VTI-ACL-030)",
            granter.did
        )));
    }
    if next.admin.admin_role == Some(AdminRole::CommunityAdmin)
        && granter.admin.admin_role != Some(AdminRole::CommunityAdmin)
    {
        return Err(GrantRefusal::PermissionDenied(
            "only a community administrator can make another — the role is above yours".into(),
        ));
    }

    // Additive grants: unrestricted granters only, and held by them too.
    let additive: Vec<CapRef> = match &next.admin.capabilities {
        CapabilityScope::Listed { grants } => grants
            .iter()
            .filter(|g| g.additive)
            .map(|g| g.cap_ref())
            .collect(),
        _ => vec![],
    };
    if !additive.is_empty() && !is_unrestricted(granter, now) {
        return Err(GrantRefusal::AdditiveRequiresUnrestricted);
    }

    let mut axes: Vec<&'static str> = Vec::new();
    let mut detail = Vec::new();

    if next.admin.act.is_all() && !granter.admin.act.is_all() {
        axes.push("act");
        detail.push("act scope all".to_string());
    }
    let beyond: Vec<String> = next
        .admin
        .effective()
        .iter()
        .chain(additive.iter())
        .filter(|c| !may_assign(granter, c))
        .map(CapRef::display)
        .collect();
    if !beyond.is_empty() {
        axes.push("capabilities");
        detail.push(format!(
            "{} (you do not hold them with vtc.roles.assign)",
            beyond.join(", ")
        ));
    }
    if let Some(mine) = granter.expires_at {
        match next.expires_at {
            None => {
                axes.push("expiresAt");
                detail.push(format!("no expiry, where yours is {mine}"));
            }
            Some(theirs) if theirs > mine => {
                axes.push("expiresAt");
                detail.push(format!("an expiry of {theirs}, after your own ({mine})"));
            }
            Some(_) => {}
        }
    }
    if !axes.is_empty() {
        return Err(GrantRefusal::DelegationExceedsGranter {
            axes,
            detail: format!("this entry would hold {}", detail.join("; ")),
        });
    }

    // VTI-ACL-042: approve authority no wider than the granter's own.
    if next.admin.approve.is_all() {
        if !granter.admin.approve.is_all() {
            return Err(GrantRefusal::ApproveWiderThanGranter(
                "this entry would approve, and you approve nothing".into(),
            ));
        }
        let wider: Vec<String> = next
            .admin
            .effective_approvable()
            .iter()
            .filter(|c| !granter.admin.can_approve(c))
            .map(CapRef::display)
            .collect();
        if !wider.is_empty() {
            return Err(GrantRefusal::ApproveWiderThanGranter(format!(
                "this entry would approve {}",
                wider.join(", ")
            )));
        }
    }
    Ok(())
}

/// May `granter` modify or remove `target` at all (**VTI-ACL-050**: an
/// administrator touches only an entry wholly within its own authority)?
///
/// The granter must hold `vtc.roles.assign`, and every capability the target
/// holds or may approve must be one the granter could have granted. A
/// `community-admin` with the full ceiling covers every entry; a repo manager
/// holding `vtc.roles.assign @ git-ns:acme` covers the entries inside `acme`
/// and none other. Nobody covers their own entry.
#[must_use]
pub fn covers_entry(granter: &VtcAclEntry, target: &VtcAclEntry, now: u64) -> bool {
    if granter.is_expired(now) || granter.did == target.did {
        return false;
    }
    if !granter.admin.can_any(Capability::RolesAssign) {
        return false;
    }
    if target.admin.admin_role == Some(AdminRole::CommunityAdmin)
        && granter.admin.admin_role != Some(AdminRole::CommunityAdmin)
    {
        return false;
    }
    // An entry with no administrative authority is any assigner's to manage,
    // provided they may assign community-wide: a qualified assigner manages
    // only the authority inside its qualifier.
    let target_caps = target.admin.effective();
    if target_caps.is_empty() && !granter.admin.can(Capability::RolesAssign, None) {
        return false;
    }
    target_caps.iter().all(|c| may_assign(granter, c))
        && (target.admin.approve == VtcActScope::None
            || (granter.admin.approve.is_all()
                && target
                    .admin
                    .effective_approvable()
                    .iter()
                    .all(|c| granter.admin.can_approve(c))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminAuthority, CapabilityGrant, VtcRole};

    const NOW: u64 = 1_000;

    fn entry(did: &str, admin: AdminAuthority) -> VtcAclEntry {
        VtcAclEntry {
            did: did.into(),
            role: VtcRole::Member,
            label: None,
            admin,
            delegated_by: None,
            created_at: 0,
            created_by: "did:key:zInstall".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
        }
    }

    fn listed(caps: &[&str]) -> CapabilityScope {
        CapabilityScope::listed(
            caps.iter()
                .map(|c| {
                    let r: CapRef = c.parse().unwrap();
                    CapabilityGrant::from(r)
                })
                .collect(),
        )
        .unwrap()
    }

    fn community_admin(did: &str) -> VtcAclEntry {
        entry(did, AdminAuthority::community_admin())
    }

    #[test]
    fn a_community_admin_may_grant_every_built_in_role() {
        let granter = community_admin("did:key:zG");
        for role in AdminRole::BUILT_IN {
            let mut admin = AdminAuthority::for_role(role.clone());
            if role == AdminRole::RepoManager {
                admin.capabilities = listed(&["git.repo.manage@git-ns:github.com/acme"]);
                admin.approve_capabilities = CapabilityScope::None;
            }
            assert_eq!(
                check_write(&granter, &entry("did:key:zS", admin), NOW),
                Ok(()),
                "{role}"
            );
        }
    }

    /// VTI-OPS-050: nobody grants themselves anything.
    #[test]
    fn vti_ops_050_a_self_grant_is_refused() {
        let granter = community_admin("did:key:zG");
        let next = community_admin("did:key:zG");
        assert!(matches!(
            check_write(&granter, &next, NOW),
            Err(GrantRefusal::PermissionDenied(_))
        ));
    }

    /// VTI-ACL-071: a delegation never exceeds the delegator.
    #[test]
    fn vti_acl_071_a_grant_beyond_the_granter_is_refused() {
        // A narrowed community-admin without vtc.audit.read cannot grant an
        // auditor.
        let mut narrow = AdminAuthority::community_admin();
        narrow.capabilities = listed(&["vtc.roles.assign", "vtc.members.manage"]);
        let granter = entry("did:key:zG", narrow);
        let next = entry("did:key:zS", AdminAuthority::for_role(AdminRole::Auditor));
        match check_write(&granter, &next, NOW) {
            Err(GrantRefusal::DelegationExceedsGranter { axes, .. }) => {
                assert_eq!(axes, vec!["capabilities"])
            }
            other => panic!("expected delegationExceedsGranter, got {other:?}"),
        }
    }

    /// §6.3: a repo manager holding `vtc.roles.assign @ git-ns:acme` can make
    /// another repo manager for `acme`, and for nowhere else.
    #[test]
    fn a_qualified_assigner_grants_inside_its_qualifier_only() {
        let mut rm = AdminAuthority::for_role(AdminRole::RepoManager);
        rm.capabilities = CapabilityScope::listed(vec![
            "git.repo.manage@git-ns:github.com/acme"
                .parse::<CapRef>()
                .unwrap()
                .into(),
            CapabilityGrant {
                capability: Capability::RolesAssign,
                resource: Some("git-ns:github.com/acme".parse().unwrap()),
                additive: true,
            },
        ])
        .unwrap();
        rm.approve_capabilities = CapabilityScope::None;
        let granter = entry("did:key:zG", rm);

        let mut acme = AdminAuthority::for_role(AdminRole::RepoManager);
        acme.capabilities = listed(&["git.repo.manage@git-ns:github.com/acme"]);
        acme.approve = VtcActScope::None;
        acme.approve_capabilities = CapabilityScope::None;
        assert_eq!(
            check_write(&granter, &entry("did:key:zS", acme.clone()), NOW),
            Ok(())
        );

        let mut other = acme;
        other.capabilities = listed(&["git.repo.manage@git-ns:github.com/other"]);
        assert!(matches!(
            check_write(&granter, &entry("did:key:zS", other), NOW),
            Err(GrantRefusal::DelegationExceedsGranter { .. })
        ));
    }

    /// VTI-ACL-042: approve authority no wider than the granter's.
    #[test]
    fn vti_acl_042_a_wider_approve_scope_is_refused() {
        let mut no_approve = AdminAuthority::community_admin();
        no_approve.approve = VtcActScope::None;
        no_approve.approve_capabilities = CapabilityScope::None;
        let granter = entry("did:key:zG", no_approve);
        let next = entry("did:key:zS", AdminAuthority::for_role(AdminRole::Moderator));
        assert!(matches!(
            check_write(&granter, &next, NOW),
            Err(GrantRefusal::ApproveWiderThanGranter(_))
        ));
    }

    /// VTI-ACL-053: no grant outlives its granter.
    #[test]
    fn vti_acl_053_a_grant_outliving_the_granter_is_refused() {
        let mut granter = community_admin("did:key:zG");
        granter.expires_at = Some(NOW + 100);
        let mut next = entry("did:key:zS", AdminAuthority::for_role(AdminRole::Moderator));
        match check_write(&granter, &next, NOW) {
            Err(GrantRefusal::DelegationExceedsGranter { axes, .. }) => {
                assert_eq!(axes, vec!["expiresAt"])
            }
            other => panic!("{other:?}"),
        }
        next.expires_at = Some(NOW + 50);
        assert_eq!(check_write(&granter, &next, NOW), Ok(()));
    }

    /// VTI-ACL-031: outside the ceiling is refused with its own code.
    #[test]
    fn vti_acl_031_outside_the_ceiling_is_refused() {
        let granter = community_admin("did:key:zG");
        let mut admin = AdminAuthority::for_role(AdminRole::Moderator);
        admin.capabilities = listed(&["vtc.config.admin"]);
        assert!(matches!(
            check_write(&granter, &entry("did:key:zS", admin), NOW),
            Err(GrantRefusal::Ceiling(CeilingError::OutsideCeiling(_)))
        ));
    }

    /// VTI-ACL-033: additive needs an unrestricted granter.
    #[test]
    fn vti_acl_033_additive_needs_an_unrestricted_granter() {
        let mut narrow = AdminAuthority::community_admin();
        narrow.capabilities = listed(&["vtc.roles.assign", "vtc.backup.export"]);
        let granter = entry("did:key:zG", narrow);
        let mut admin = AdminAuthority::for_role(AdminRole::Auditor);
        admin.capabilities = CapabilityScope::listed(vec![
            CapRef::all(Capability::AuditRead).into(),
            CapabilityGrant {
                capability: Capability::BackupExport,
                resource: None,
                additive: true,
            },
        ])
        .unwrap();
        let next = entry("did:key:zS", admin);
        assert_eq!(
            check_write(&granter, &next, NOW),
            Err(GrantRefusal::AdditiveRequiresUnrestricted)
        );
        assert_eq!(
            check_write(&community_admin("did:key:zU"), &next, NOW),
            Ok(())
        );
    }

    #[test]
    fn only_a_community_admin_covers_one() {
        let ca = community_admin("did:key:zA");
        let other = community_admin("did:key:zB");
        assert!(covers_entry(&ca, &other, NOW));
        assert!(
            !covers_entry(&ca, &ca, NOW),
            "nobody covers their own entry"
        );
        let moderator = entry("did:key:zM", AdminAuthority::for_role(AdminRole::Moderator));
        assert!(!covers_entry(&moderator, &other, NOW));
        let member = entry("did:key:zP", AdminAuthority::none());
        assert!(covers_entry(&ca, &member, NOW));
        assert!(
            !covers_entry(&moderator, &member, NOW),
            "no vtc.roles.assign"
        );
    }
}
