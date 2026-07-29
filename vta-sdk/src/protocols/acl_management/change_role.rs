//! Wire types for canonical `acl/change-role/0.1`.

use serde::{Deserialize, Serialize};

use super::create::CreateAclResultBody;

/// Request payload for `acl/change-role/0.1`.
///
/// Role is the one ACL attribute where a lost update is a privilege
/// change, so the transition is **state-checked** rather than applied
/// blind: the producer declares the role it believes the subject holds,
/// and a maintainer whose stored role differs rejects the change
/// instead of overwriting.
///
/// Concretely, without this two admins acting on the same stale read —
/// one demoting to `reader`, one promoting to `admin` — would both
/// "succeed", and whichever landed second would silently win. The
/// demotion would disappear with no error anywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChangeRoleBody {
    /// VID of the party whose role is changing.
    pub subject: String,
    /// The role the producer believes the subject currently holds. A
    /// mismatch against the stored role is refused.
    pub from_role: String,
    /// The role to transition the subject to.
    pub to_role: String,
    /// Optional human-readable rationale, recorded with the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response payload — the entry as it stands after the transition.
/// Same shape as `acl/update`'s, so a caller that already handles one
/// handles the other.
pub type ChangeRoleResultBody = CreateAclResultBody;
