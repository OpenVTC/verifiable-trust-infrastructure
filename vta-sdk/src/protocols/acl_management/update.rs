use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::acl::ApproveScope;

use super::create::CreateAclResultBody;
use super::entry::{Approve, StepUp};

/// Request payload for canonical `acl/update/0.1`.
///
/// **The wire form is the canonical one** (#856): the Rust field names keep
/// their historical spellings, mapped onto the canonical members with serde
/// renames — the same compatibility-layer treatment #842 gave the response
/// via [`super::entry::AclEntry`]. `did` serializes as `subject`,
/// `allowed_contexts` as `scopes`, and the step-up / approve-authority
/// sub-concerns nest under the shared canonical [`StepUp`] / [`Approve`]
/// components rather than flattening into five loosely-related members.
///
/// Carries no `role`: canonical gives the role transition its own
/// task (`acl/change-role/0.1`) so it can be compare-and-swapped
/// against the subject's current role, which is what stops two admins
/// on a stale read from silently overwriting one another on the one
/// attribute where that is a privilege change.
///
/// Patch semantics throughout: `Some` sets, absent leaves unchanged. The
/// canonical spec's explicit-`null` clears (`label`, `expiresAt`,
/// `stepUp.approver`) are not expressible through plain `Option` fields —
/// absent and `null` deserialize identically — so clearing those members is
/// not offered here, consistent with the pre-canonical body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAclBody {
    /// VID of the entry to amend — canonical wire member `subject`.
    #[serde(rename = "subject")]
    pub did: String,
    /// Replacement human-readable label; omitted leaves it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Replacement scope set — canonical wire member `scopes`. Applied
    /// wholesale rather than merged; omitted leaves the set unchanged.
    #[serde(rename = "scopes", default, skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
    /// Replacement expiry — canonical `expiresAt`, RFC 3339 on the wire
    /// (the store keeps epoch seconds; see [`super::entry::to_epoch`]).
    /// Omitted leaves the expiry unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional human-readable rationale, recorded with the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Replacement per-entry step-up configuration — canonical `stepUp`,
    /// the same shared component the response carries. `Some` sets the
    /// members it names; omitted leaves the configuration unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUp>,
    /// Replacement approve-authority — canonical `approve`, the shared
    /// component from [`super::entry`]. Omit to leave it unchanged.
    ///
    /// **Clearing has to be expressible**, and it is: `Some(Approve::default())`
    /// serializes as `"approve": {}` — confers nothing — which is the wire
    /// spelling of "revoke this approver's authority". Before this existed,
    /// the only way to narrow or drop an approve scope was to delete the ACL
    /// entry and recreate it, which leaves the DID with no entry at all if
    /// the recreate fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<Approve>,
}

impl UpdateAclBody {
    /// The delegated step-up approver to set, if the request names one.
    /// `None` leaves it unchanged (the historical flat-field accessor).
    pub fn step_up_approver(&self) -> Option<String> {
        self.step_up.as_ref().and_then(|s| s.approver.clone())
    }

    /// The per-entry step-up override to set (`"self"` | `"delegated"`),
    /// if the request names one. `None` leaves it unchanged.
    pub fn step_up_require(&self) -> Option<String> {
        self.step_up.as_ref().and_then(|s| s.require.clone())
    }

    /// The approve-authority to set. `None` leaves it unchanged; clear is
    /// `Some(ApproveScope::None)` — an explicit value, not absence.
    pub fn approve_scope(&self) -> Option<ApproveScope> {
        self.approve.as_ref().map(Approve::to_scope)
    }
}

pub type UpdateAclResultBody = CreateAclResultBody;
