//! `acl/list/0.1` — enumerate ACL entries.

use serde::{Deserialize, Serialize};

use super::entry::AclEntry;
use crate::acl::ContextDirection;

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
