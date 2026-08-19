use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::KeyStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RevokeKeyBody {
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    /// Optional human-readable rationale, recorded with the revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RevokeKeyResultBody {
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    pub status: KeyStatus,
    #[serde(rename = "updatedAt", alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
}
