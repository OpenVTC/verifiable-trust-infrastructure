//! Wire types for canonical `audit/list/0.1`.
//!
//! Two shapes live here and they are deliberately not the same one:
//!
//! - [`AuditLogEntry`] is the **stored row** — what `vta-audit` writes
//!   into the audit keyspace. Its serde shape is a storage format, so
//!   it is frozen: renaming a field here silently orphans every row
//!   already on disk.
//! - [`AuditEnvelope`] is the **wire form** canonical `audit/list`
//!   returns. It is produced from a stored row at the response
//!   boundary via `From<&AuditLogEntry>`.
//!
//! Keeping them separate is what lets the VTA adopt the canonical
//! camelCase envelope without a storage migration.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// A single audit log entry **as stored**. Not the wire form — see
/// [`AuditEnvelope`].
///
/// The serde shape of this struct is the on-disk format for the audit
/// keyspace. Do not add `rename_all`, and add new fields only with
/// `#[serde(default)]` so rows written before the field existed still
/// deserialize.
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

/// Canonical `AuditEnvelope` — the wire form of one audit entry.
///
/// Field names and types follow
/// `spec/audit/_shared/0.1/audit.schema.json`. The VTA populates the
/// subset it tracks; `prevHash` / `entryHash` / `schemaVersion` are
/// absent because this maintainer's log is flat and unchained (the
/// canonical schema requires only `eventId` / `recordedAt` / `action`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditEnvelope {
    /// Stable identifier for this event — the stored row's `id`.
    pub event_id: String,
    /// RFC 3339 wall-clock time the entry was written.
    pub recorded_at: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The stored row's `resource` — the principal or object acted upon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Event-specific payload. Canonical types this as an object, so
    /// the VTA's flat `detail` string and its `channel` (the transport
    /// the action arrived over — a VTA-specific fact with no canonical
    /// envelope field) are carried as members here rather than dropped.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub detail: serde_json::Map<String, serde_json::Value>,
}

impl From<&AuditLogEntry> for AuditEnvelope {
    fn from(row: &AuditLogEntry) -> Self {
        let mut detail = serde_json::Map::new();
        if let Some(reason) = &row.detail {
            detail.insert("reason".into(), reason.clone().into());
        }
        if let Some(channel) = &row.channel {
            detail.insert("channel".into(), channel.clone().into());
        }

        Self {
            event_id: row.id.clone(),
            // `timestamp` is unix seconds and always in range, but a
            // corrupt row must not panic a list call — fall back to the
            // epoch rather than unwrapping.
            recorded_at: Utc
                .timestamp_opt(row.timestamp as i64, 0)
                .single()
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).expect("epoch is valid"))
                .to_rfc3339(),
            action: row.action.clone(),
            outcome: Some(row.outcome.clone()),
            actor: Some(row.actor.clone()),
            target: row.resource.clone(),
            context_id: row.context_id.clone(),
            detail,
        }
    }
}

/// Request payload for canonical `audit/list/0.1`.
///
/// Paging is by opaque continuation `cursor`, not offset: an offset
/// silently skips or repeats rows when entries are appended while a
/// consumer walks the pages, which on an audit log is a correctness
/// bug rather than a cosmetic one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct ListAuditLogsBody {
    /// Return only entries recorded at or after this time (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    /// Return only entries recorded **strictly before** this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    /// Return only entries whose `action` **equals** this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Return only entries whose actor DID equals this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Return only entries whose `outcome` equals this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Return only entries in this trust context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Maximum entries to return in this page. Clamped to `1..=200`;
    /// omitted means 50.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u64>,
    /// Opaque continuation token from a previous response's `cursor`.
    ///
    /// The filters are bound into the cursor, so a consumer continuing
    /// a page must not also change them — doing so is rejected as an
    /// invalid cursor rather than silently answered from a position
    /// that belonged to a different query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Response payload for canonical `audit/list/0.1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAuditLogsResultBody {
    /// The matching entries, newest first.
    pub entries: Vec<AuditEnvelope>,
    /// True when more entries **match** beyond this page.
    pub truncated: bool,
    /// Continuation token for the next page. Present iff `truncated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}
