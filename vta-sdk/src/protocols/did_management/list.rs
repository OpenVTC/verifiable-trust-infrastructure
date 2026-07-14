use serde::{Deserialize, Serialize};

use crate::webvh::WebvhDidRecord;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListDidsWebvhBody {
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "context_id")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "server_id")]
    pub server_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListDidsWebvhResultBody {
    pub dids: Vec<WebvhDidRecord>,
}
