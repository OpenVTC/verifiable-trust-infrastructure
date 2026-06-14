use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::KeyStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeKeyBody {
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeKeyResultBody {
    pub key_id: String,
    pub status: KeyStatus,
    pub updated_at: DateTime<Utc>,
}
