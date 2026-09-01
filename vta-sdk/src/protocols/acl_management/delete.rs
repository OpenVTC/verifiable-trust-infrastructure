//! `acl/revoke/0.1` — remove a subject, or withdraw some of its scopes.

use serde::{Deserialize, Serialize};

use super::entry::AclEntry;
use serde_json::Value;

/// `acl/revoke/0.1` request.
///
/// Canonical revoke has two modes: **full removal** (omit `scopes`) and
/// **scope reduction** (list the scopes to withdraw; the entry survives with
/// the rest).
///
/// This maintainer implements full removal only. A request carrying `scopes`
/// is **refused**, not silently treated as a full removal — quietly removing
/// an entire entry when the caller asked to withdraw one scope would take away
/// far more authority than was requested, which is the wrong direction for an
/// operation to guess in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteAclBody {
    /// VID of the subject being revoked. Was `did` before the canonical fold.
    pub subject: String,
    /// Scopes to withdraw instead of removing the entry. Unsupported here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Optional human-readable rationale, recorded with the revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `acl/revoke/0.1` response — the entry as it stood when revoked.
///
/// Returning it rather than a bare `{ deleted: true }` means the audit record
/// and the caller both retain what was actually withdrawn, which a boolean
/// cannot express.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteAclResultBody {
    pub entry: AclEntry,
}
