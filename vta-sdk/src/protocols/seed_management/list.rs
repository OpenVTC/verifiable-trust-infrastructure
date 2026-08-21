use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Empty request body for the list-seeds operation. Exists so the
/// trust-task envelope's `payload` field has a typed shape; the
/// operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListSeedsBody {}

/// One seed record as `seeds/list` reports it.
///
/// # The `rename_all` here is load-bearing
///
/// #1000 folded Trust Task payloads to lowerCamelCase per SPEC §4.10 and added
/// the aliases below — but not `rename_all`, without which an alias equal to the
/// field's own name is a no-op. So this stayed snake_case while
/// [`ListSeedsResultBody`] around it moved, and `seeds/list` emitted a body that
/// disagreed with itself:
///
/// ```json
/// {"seeds":[{"id":1,"status":"active","created_at":"…"}],"activeSeedId":1}
/// ```
///
/// That is not a preserved contract, it is half a fold (#1034). Finished here;
/// the aliases now do the Postel job they were written for, so a producer still
/// sending `created_at` keeps decoding.
///
/// `tests/inert_alias_census.rs` is what makes this stick — it fails on any
/// alias that accepts only what would be accepted anyway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
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
