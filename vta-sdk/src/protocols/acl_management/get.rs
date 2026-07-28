//! `acl/show/0.1` — read one ACL entry.

use serde::{Deserialize, Serialize};

use super::entry::AclEntry;

/// `acl/show/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetAclBody {
    /// VID of the entry to read. Was `did` before the canonical fold.
    pub subject: String,
}

/// `acl/show/0.1` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetAclResultBody {
    pub entry: AclEntry,
    /// Entry members the maintainer withheld. Empty when nothing was redacted.
    ///
    /// Reported rather than silently omitted so a caller can tell "this entry
    /// has no label" from "you may not see its label" — which are different
    /// answers, and only one of them means the data is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
}
