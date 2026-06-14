use serde::{Deserialize, Serialize};

use crate::keys::{KeyRecord, KeyStatus};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListKeysBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<KeyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListKeysResultBody {
    pub keys: Vec<KeyRecord>,
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
}
