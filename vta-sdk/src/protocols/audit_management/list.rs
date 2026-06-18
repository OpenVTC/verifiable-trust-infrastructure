use serde::{Deserialize, Serialize};

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: u64,
    pub action: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Optional human-readable rationale supplied by the actor (e.g. the
    /// `reason` on a `vault.delete` / `vault.archive`). `#[serde(default)]`
    /// so log rows written before this field existed deserialize cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Request body for listing audit logs with filtering and pagination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct ListAuditLogsBody {
    /// Start of time range (unix epoch seconds, inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    /// End of time range (unix epoch seconds, inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    /// Filter by action type (e.g. "auth.challenge", "key.create").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Filter by actor DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Filter by outcome (e.g. "success", "denied").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Filter by application context ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Page number (1-based, default 1).
    #[serde(default = "default_page")]
    pub page: u64,
    /// Page size (default 50, max 500).
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

fn default_page() -> u64 {
    1
}
fn default_page_size() -> u64 {
    50
}

/// Response body for listing audit logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAuditLogsResultBody {
    pub entries: Vec<AuditLogEntry>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub total_pages: u64,
}
