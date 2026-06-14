use serde::{Deserialize, Serialize};

/// Empty request body for the get-retention operation. Exists so the
/// trust-task envelope's `payload` field has a typed shape; the
/// operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetRetentionBody {}

/// Request body for updating the audit log retention period.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateRetentionBody {
    /// Number of days to retain audit logs (minimum 1, maximum 365).
    pub retention_days: u32,
}

/// Response body for get/update retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RetentionResultBody {
    pub retention_days: u32,
}
