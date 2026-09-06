//! `acl/show/0.1` — read one ACL entry.

use serde::{Deserialize, Serialize};

use super::entry::AclEntry;
use serde_json::Value;

/// `acl/show/0.1` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub struct GetAclBody {
    /// VID of the entry to read. Was `did` before the canonical fold.
    pub subject: String,
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

impl GetAclBody {
    /// Build a [`GetAclBody`] from the members the schema requires.
    ///
    /// This type is `#[non_exhaustive]`, so it cannot be built with a struct
    /// literal from outside this crate — a new member added by a later revision
    /// of the schema would break every such literal, which is exactly what
    /// happened when `ext` arrived. The optional members stay public: set them
    /// on the value this returns.
    pub fn new(subject: String) -> Self {
        Self { subject, ext: None }
    }
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
