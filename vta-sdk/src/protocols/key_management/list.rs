use serde::{Deserialize, Serialize};

use crate::keys::{KeyRecord, KeyStatus};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListKeysBody {
    /// The previous page's `nextCursor`. A custodian refuses one it did not
    /// issue (`keys/list/0.2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<KeyStatus>,
    #[serde(default, alias = "context_id", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListKeysResultBody {
    pub keys: Vec<KeyRecord>,
    /// Present exactly when more records remain; pass it back as the next
    /// request's `cursor`. A sweep that stops while it is present has skipped
    /// every key past the page boundary.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}
