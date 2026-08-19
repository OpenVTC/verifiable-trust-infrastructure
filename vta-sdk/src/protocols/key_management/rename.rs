use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenameKeyBody {
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    #[serde(rename = "newKeyId", alias = "new_key_id")]
    pub new_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenameKeyResultBody {
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    #[serde(rename = "updatedAt", alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
}
