use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Empty request body for the list-seeds operation. Exists so the
/// trust-task envelope's `payload` field has a typed shape; the
/// operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListSeedsBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SeedInfo {
    pub id: u32,
    pub status: String,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "retired_at")]
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListSeedsResultBody {
    pub seeds: Vec<SeedInfo>,
    #[serde(alias = "active_seed_id")]
    pub active_seed_id: u32,
}
