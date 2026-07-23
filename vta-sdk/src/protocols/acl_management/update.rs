use serde::{Deserialize, Serialize};

use crate::acl::ApproveScope;

use super::create::CreateAclResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAclBody {
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
    /// Set the delegated step-up approver VID. `Some` sets it; `None` leaves
    /// it unchanged (matching the other fields — clearing an existing
    /// approver isn't expressible here, consistent with `label`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
    /// Set the per-entry step-up override (`"self"` | `"delegated"`). `Some`
    /// sets it; `None` leaves it unchanged (consistent with the other fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_require: Option<String>,
    /// Set the approve scope to exactly this value; omit to leave unchanged.
    ///
    /// Unlike the create body — which takes `approve_all_contexts` +
    /// `approve_contexts` as two independent fields — this carries the enum
    /// itself, because **clearing has to be expressible**. With two flat fields
    /// there is no way to distinguish "revoke this approver's authority" from
    /// "leave it alone", and revoking is the case that matters most: before
    /// this existed, the only way to narrow or drop an approve scope was to
    /// delete the ACL entry and recreate it, which leaves the DID with no entry
    /// at all if the recreate fails.
    ///
    /// Clear is `Some(ApproveScope::None)` — an explicit value, not absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_scope: Option<ApproveScope>,
}

pub type UpdateAclResultBody = CreateAclResultBody;
