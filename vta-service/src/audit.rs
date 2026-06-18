//! Structured audit logging for security-relevant operations.
//!
//! Audit events are:
//! 1. Emitted via `tracing` at a dedicated target (`audit`) for log shipping
//! 2. Persisted to the `audit` fjall keyspace for API-based retrieval
//!
//! The `audit!` macro emits the tracing event. Persisting to storage is done
//! via `AuditStore::record()` which should be called alongside the macro in
//! route/handler code.

use vta_sdk::protocols::audit_management::list::AuditLogEntry;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Emit a structured audit event to the tracing subsystem.
///
/// Uses `INFO` for successful outcomes and `ERROR` for failures (e.g. `denied:*`).
macro_rules! audit {
    ($action:expr, actor = $actor:expr, resource = $resource:expr, outcome = $outcome:expr) => {
        if $outcome.starts_with("success") {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::INFO,
                action = $action,
                actor = %$actor,
                resource = %$resource,
                outcome = $outcome,
            );
        } else {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::ERROR,
                action = $action,
                actor = %$actor,
                resource = %$resource,
                outcome = $outcome,
            );
        }
    };
    ($action:expr, actor = $actor:expr, outcome = $outcome:expr) => {
        if $outcome.starts_with("success") {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::INFO,
                action = $action,
                actor = %$actor,
                outcome = $outcome,
            );
        } else {
            ::tracing::event!(
                target: "audit",
                ::tracing::Level::ERROR,
                action = $action,
                actor = %$actor,
                outcome = $outcome,
            );
        }
    };
}

pub(crate) use audit;

/// Persist an audit log entry to the audit keyspace.
///
/// Storage key format: `log:{timestamp_secs}:{uuid}` — enables efficient
/// time-range prefix scans and guarantees uniqueness.
pub async fn record(
    audit_ks: &KeyspaceHandle,
    action: &str,
    actor: &str,
    resource: Option<&str>,
    outcome: &str,
    channel: Option<&str>,
    context_id: Option<&str>,
) -> Result<(), AppError> {
    record_with_detail(
        audit_ks, action, actor, resource, outcome, channel, context_id, None,
    )
    .await
}

/// Like [`record`], but also persists an operator-supplied `detail` (e.g. the
/// `reason` on a `vault.delete`/`vault.archive`). Kept as a separate function
/// so the existing `record(...)` call sites stay untouched.
#[allow(clippy::too_many_arguments)]
pub async fn record_with_detail(
    audit_ks: &KeyspaceHandle,
    action: &str,
    actor: &str,
    resource: Option<&str>,
    outcome: &str,
    channel: Option<&str>,
    context_id: Option<&str>,
    detail: Option<&str>,
) -> Result<(), AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let id = uuid::Uuid::new_v4().to_string();

    let entry = AuditLogEntry {
        id: id.clone(),
        timestamp: now,
        action: action.to_string(),
        actor: actor.to_string(),
        resource: resource.map(String::from),
        outcome: outcome.to_string(),
        channel: channel.map(String::from),
        context_id: context_id.map(String::from),
        detail: detail.map(String::from),
    };

    // Key: zero-padded timestamp for lexicographic time ordering
    let key = format!("log:{:020}:{}", now, id);
    audit_ks.insert(key, &entry).await
}

/// Remove audit log entries older than `retention_days`.
pub async fn cleanup_expired_logs(
    audit_ks: &KeyspaceHandle,
    retention_days: u32,
) -> Result<u64, AppError> {
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(retention_days as u64 * 86400);

    let cutoff_key = format!("log:{:020}:", cutoff);
    let keys = audit_ks.prefix_keys("log:").await?;

    let mut removed = 0u64;
    for key in keys {
        let key_str = String::from_utf8_lossy(&key);
        if key_str.as_ref() < cutoff_key.as_str() {
            audit_ks.remove(key).await?;
            removed += 1;
        } else {
            // Keys are sorted — once we pass the cutoff, stop
            break;
        }
    }

    Ok(removed)
}
