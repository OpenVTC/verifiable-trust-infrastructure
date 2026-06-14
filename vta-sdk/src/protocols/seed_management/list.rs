use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Empty request body for the list-seeds operation. Exists so the
/// trust-task envelope's `payload` field has a typed shape; the
/// operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListSeedsBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SeedInfo {
    pub id: u32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListSeedsResultBody {
    pub seeds: Vec<SeedInfo>,
    pub active_seed_id: u32,
}
