use serde::{Deserialize, Serialize};

use super::create::CreateAclResultBody;
use crate::acl::ContextDirection;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAclBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Which way [`context`](Self::context) reads along the hierarchy —
    /// `acting-in` (default, entries that may act *in* it), `subtree` (entries
    /// granted at or *beneath* it), or `any`. Absent = `acting-in`, i.e. the
    /// pre-#822 behaviour exactly. Meaningless without `context`, and refused
    /// rather than ignored in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<ContextDirection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAclResultBody {
    pub entries: Vec<CreateAclResultBody>,
}
