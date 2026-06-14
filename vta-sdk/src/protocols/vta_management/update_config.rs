use serde::{Deserialize, Serialize};

use super::get_config::GetConfigResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateConfigBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

pub type UpdateConfigResultBody = GetConfigResultBody;
