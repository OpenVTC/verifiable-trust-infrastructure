use serde::{Deserialize, Serialize};

/// Empty request body for the get-retention operation. Exists so the
/// trust-task envelope's `payload` field has a typed shape; the
/// operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct GetRetentionBody {}

/// Request body for updating the audit log retention period.
///
/// # `rename_all` here is load-bearing
///
/// #1000 added the alias below without it, which made it a no-op, so this
/// carried on emitting snake_case while [`RetentionResultBody`] — one screen
/// down, same operation — moved. `audit/update-retention` therefore took a
/// snake_case request and returned a camelCase response. Nobody chose that;
/// even the empty [`GetRetentionBody`] had been folded.
///
/// Folded in #1039. Note this is a **request** body, so the direction of risk is
/// the opposite of a response: a client on this version sends `retentionDays`,
/// and an agent that predates the change accepts only `retention_days`. That is
/// the same trade #1000 made for every request body it folded, and it is why
/// this one was held back until it could be taken deliberately rather than
/// inherited from an unrelated fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UpdateRetentionBody {
    /// Number of days to retain audit logs (minimum 1, maximum 365).
    #[serde(alias = "retention_days")]
    pub retention_days: u32,
}

/// Response body for get/update retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetentionResultBody {
    #[serde(alias = "retention_days")]
    pub retention_days: u32,
}
