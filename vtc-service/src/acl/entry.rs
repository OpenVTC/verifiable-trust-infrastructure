//! `VtcAclEntry` — the VTC's per-DID auth-gate record.
//!
//! Two things live on one entry, and they are independent
//! (`docs/05-design-notes/vtc-admin-roles.md` §6):
//!
//! - the **community role** ([`super::VtcRole`]: `member`, `moderator`,
//!   `issuer`, `admin`, `custom:*`) — what the subject's membership is, the
//!   role its credentials name. It confers no administrative power on its own.
//! - the **administrative authority** ([`AdminAuthority`]): an administrative
//!   role (a ceiling), an explicit act scope, the capabilities held, an approve
//!   scope and the capabilities it may approve. Every axis is stated
//!   (`acl/_shared/0.2` CONVENTIONS §4); none has a default.
//!
//! Authorization is one question, [`VtcAclEntry::can`]. Nothing reads the
//! shape of a list to decide anything: there are no context lists on a VTC
//! entry (**VTI-VTC-010**), so the empty-list trap the VTA guards against
//! (#746, #769, #770) does not exist here.
//!
//! ## Wire shape
//!
//! Stored under `acl:<did>` in the `acl` keyspace. The administrative axes are
//! flattened into the row (`adminRole`, `act`, `capabilities`, `approve`,
//! `approveCapabilities`). A row written before role-based administration —
//! with `allowed_contexts` and no `act` — does not decode, and so confers
//! nothing: rollout is net-new (`vtc-admin-roles.md` §9), and a backup brings
//! its rows across through [`super::migrate`].

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::VtcRole;
pub use super::capability::AdminAuthority;
use super::capability::{CapRef, Capability, ResourceQualifier};

/// One ACL entry. 1:1 with a [`crate::members::Member`] row by
/// DID, but kept in a separate keyspace because the auth path
/// reads ACL rows on every request and shouldn't pay the cost of
/// loading the richer Member metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VtcAclEntry {
    pub did: String,
    /// The community role: what the subject's membership is. Not authority.
    pub role: VtcRole,
    pub label: Option<String>,
    /// The administrative authority, every axis explicit.
    #[serde(flatten)]
    pub admin: AdminAuthority,
    /// The granter whose authority this entry was delegated from and is
    /// bounded by (`acl/_shared/0.2` `delegatedBy`, **VTI-ACL-071**). Absent on
    /// an entry derived from no granter: the first administrator, an
    /// operator-written recovery entry, a member admitted by a join.
    #[serde(default)]
    pub delegated_by: Option<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Unix-epoch seconds of the last mutation, and who made it.
    ///
    /// `#[serde(default)]` because an entry that has never been modified has
    /// none; this is provenance, not authority.
    #[serde(default)]
    pub updated_at: Option<u64>,
    #[serde(default)]
    pub updated_by: Option<String>,
    /// Unix-epoch seconds at which this entry expires and should be
    /// pruned by the background sweeper. `None` is permanent.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl VtcAclEntry {
    /// A fresh entry with community role `role` and administrative authority
    /// `admin`, created now by `created_by`.
    pub fn new(
        did: impl Into<String>,
        role: VtcRole,
        admin: AdminAuthority,
        created_by: impl Into<String>,
    ) -> Self {
        Self {
            did: did.into(),
            role,
            label: None,
            admin,
            delegated_by: None,
            created_at: vti_common::auth::session::now_epoch(),
            created_by: created_by.into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        }
    }

    /// **The** authorization question (**VTI-ACL-030**, **-036**): may this
    /// entry exercise `cap` on `resource` (`None` = community-wide), now?
    ///
    /// An expired entry can do nothing (**VTI-ACL-004**), and a qualified
    /// capability confers nothing without this live entry for the same subject
    /// — it is a member of the entry, not a right held beside it.
    pub fn can(&self, cap: Capability, resource: Option<&ResourceQualifier>) -> bool {
        !self.is_expired(vti_common::auth::session::now_epoch()) && self.admin.can(cap, resource)
    }

    /// [`Self::can`] at any qualifier — the gate on a read that spans every
    /// resource of the capability's kind.
    pub fn can_any(&self, cap: Capability) -> bool {
        !self.is_expired(vti_common::auth::session::now_epoch()) && self.admin.can_any(cap)
    }

    /// Whether this live entry holds `wanted` at a covering qualifier.
    pub fn holds(&self, wanted: &CapRef) -> bool {
        self.can(wanted.capability, wanted.resource.as_ref())
    }

    /// May this live entry approve an action needing `wanted`
    /// (**VTI-ACL-040**)? Independent of what it may do.
    pub fn can_approve(&self, wanted: &CapRef) -> bool {
        !self.is_expired(vti_common::auth::session::now_epoch()) && self.admin.can_approve(wanted)
    }

    /// Whether this live entry holds an administrative role of any kind —
    /// what console sign-in admits.
    pub fn is_administrator(&self) -> bool {
        !self.is_expired(vti_common::auth::session::now_epoch()) && self.admin.is_administrator()
    }

    /// Whether this is a live `community-admin` holding `vtc.roles.assign`
    /// unqualified — the holders the attrition guard keeps at least one of.
    pub fn is_community_admin(&self) -> bool {
        matches!(
            self.admin.admin_role,
            Some(super::capability::AdminRole::CommunityAdmin)
        ) && self.can(Capability::RolesAssign, None)
    }

    /// The capabilities this entry holds, as `cap[@resource]` strings — what an
    /// audit row or an operator display names. Empty when it may not act.
    pub fn capability_list(&self) -> Vec<String> {
        if self.admin.act.is_all() {
            self.admin.effective().iter().map(CapRef::display).collect()
        } else {
            Vec::new()
        }
    }

    /// Returns `true` once this entry has passed its
    /// `expires_at`. Permanent entries (`None`) never expire.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self.expires_at {
            Some(deadline) => now_unix >= deadline,
            None => false,
        }
    }
}

/// Decode a `VtcAclEntry` from raw bytes. Public so the
/// [`super::storage`] helpers + pagination callers can reuse the
/// same decode path without duplicating the JSON tax.
pub(crate) fn decode(bytes: &[u8]) -> Result<VtcAclEntry, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("VtcAclEntry decode: {e}")))
}

/// Iterate `acl:<did>` rows, decoding each into a `VtcAclEntry`.
/// Helper for `list_acl_entries` + paginated walkers.
pub(crate) async fn iter(ks: &KeyspaceHandle) -> Result<Vec<VtcAclEntry>, AppError> {
    let raw = ks.prefix_iter_raw(b"acl:".to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match decode(&v) {
            Ok(entry) => out.push(entry),
            Err(err) => {
                tracing::warn!(error = %err, "skipping unparseable acl entry");
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::capability::{AdminRole, VtcActScope};
    use serde_json::json;

    #[test]
    fn is_expired_returns_false_for_permanent_entries() {
        let entry = sample_entry(None);
        assert!(!entry.is_expired(u64::MAX));
    }

    #[test]
    fn is_expired_returns_true_after_deadline() {
        let entry = sample_entry(Some(100));
        assert!(!entry.is_expired(50));
        assert!(entry.is_expired(101));
    }

    #[test]
    fn round_trip_through_json() {
        let entry = sample_entry(Some(200));
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed = decode(&bytes).unwrap();
        assert_eq!(parsed, entry);
    }

    /// Net-new rollout (`vtc-admin-roles.md` §9): a row in the old shape —
    /// `allowed_contexts`, no `act` — does not decode, so it confers nothing.
    /// Nothing is derived from the absence of the explicit axes
    /// (VTI-ACL-006…008).
    #[test]
    fn a_pre_role_row_does_not_decode() {
        let legacy = json!({
            "did": "did:key:zAdmin",
            "role": "admin",
            "label": null,
            "allowed_contexts": [],
            "created_at": 0,
            "created_by": "did:key:vtc-install"
        });
        assert!(decode(&serde_json::to_vec(&legacy).unwrap()).is_err());
    }

    #[test]
    fn custom_role_round_trips() {
        let mut entry = sample_entry(None);
        entry.role = VtcRole::custom("editor").unwrap();
        entry.label = Some("badge holder".into());
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed = decode(&bytes).unwrap();
        assert_eq!(parsed.role, VtcRole::Custom("editor".into()));
        assert_eq!(parsed, entry);
    }

    /// The community role confers nothing: an `admin` community role with no
    /// administrative authority can do nothing (VTI-ACL-010).
    #[test]
    fn the_community_role_is_not_authority() {
        let mut e = sample_entry(None);
        e.role = VtcRole::Admin;
        for c in Capability::ALL {
            assert!(!e.can(c, None));
        }
        assert!(!e.is_administrator());
    }

    /// An expired entry can do nothing, whatever it holds (VTI-ACL-004).
    #[test]
    fn an_expired_entry_can_do_nothing() {
        let mut e = sample_entry(Some(1));
        e.admin = AdminAuthority::community_admin();
        assert!(!e.can(Capability::RolesAssign, None));
        assert!(!e.is_administrator());
        e.expires_at = None;
        assert!(e.can(Capability::RolesAssign, None));
        assert!(e.is_community_admin());
    }

    #[test]
    fn a_moderator_is_an_administrator_but_not_a_community_admin() {
        let mut e = sample_entry(None);
        e.admin = AdminAuthority::for_role(AdminRole::Moderator);
        assert!(e.is_administrator());
        assert!(!e.is_community_admin());
        assert_eq!(e.admin.act, VtcActScope::All);
    }

    fn sample_entry(expires_at: Option<u64>) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zSomeMember".into(),
            role: VtcRole::Member,
            label: None,
            admin: AdminAuthority::none(),
            delegated_by: None,
            created_at: 42,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at,
        }
    }
}
