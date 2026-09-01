//! `acl/list/0.1` — enumerate ACL entries.

use serde::{Deserialize, Serialize};

use super::entry::AclEntry;
use crate::acl::ContextDirection;
use serde_json::Value;

/// `acl/list/0.1` request. Every member is an optional filter.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAclBody {
    /// Only entries with this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Only entries whose scopes relate to this one, per `direction`. Was
    /// `context` before the canonical fold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// How to read `scope`. Omitted means `acting-in`.
    ///
    /// The axis exists because a scope identifier names a subtree, so it asks
    /// two questions: who may act *in* it, and what is granted *beneath* it.
    /// A revocation sweep wants `subtree`; asking `acting-in` returns the
    /// ancestors that keep their authority and omits every leaf grant — short
    /// rather than empty, so it reads as complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<ContextDirection>,
    /// Only entries whose subject VID starts with this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
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

/// `acl/list/0.1` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAclResultBody {
    pub entries: Vec<AclEntry>,
    /// True when more entries match beyond this page.
    ///
    /// Required by the canonical response precisely so that a short page is
    /// never mistaken for the end of the list — the failure that makes a
    /// revocation sweep look complete when it is not.
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
}
