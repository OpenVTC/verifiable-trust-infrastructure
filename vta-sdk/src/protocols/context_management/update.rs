use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;
use crate::context_policy::ContextPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateContextBody {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Set this context's policy (super-admin only). Omitted leaves it
    /// unchanged; send [`ContextPolicy::unrestricted`] to clear constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_policy: Option<ContextPolicy>,
}

pub type UpdateContextResultBody = CreateContextResultBody;
