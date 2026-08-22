use std::sync::Arc;
use tokio::sync::RwLock;
use vta_sdk::protocols::audit_management::list::{
    AuditEnvelope, AuditLogEntry, ListAuditLogsBody, ListAuditLogsResultBody,
};
use vta_sdk::protocols::audit_management::retention::RetentionResultBody;
use vti_common::pagination::{Cursor, CursorKey, MAX_LIMIT};

use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Page size used when the caller omits `pageSize`.
const DEFAULT_PAGE_SIZE: u64 = 50;

/// Does this stored row pass every supplied filter?
///
/// `action` and `outcome` match on **equality**, per canonical
/// `audit/list`. They previously matched on substring, which quietly
/// widened a query — asking for `action=vault.delete` also returned
/// `vault.delete_force` — so an operator reading the result could not
/// tell which rows they had actually asked for.
fn matches(params: &ListAuditLogsBody, entry: &AuditLogEntry) -> bool {
    if let Some(from) = params.from
        && (entry.timestamp as i64) < from.timestamp()
    {
        return false;
    }
    // Canonical: `to` is exclusive.
    if let Some(to) = params.to
        && (entry.timestamp as i64) >= to.timestamp()
    {
        return false;
    }
    if let Some(action) = &params.action
        && entry.action != *action
    {
        return false;
    }
    if let Some(actor) = &params.actor
        && entry.actor != *actor
    {
        return false;
    }
    if let Some(outcome) = &params.outcome
        && entry.outcome != *outcome
    {
        return false;
    }
    if let Some(ctx) = &params.context_id
        && entry.context_id.as_deref() != Some(ctx.as_str())
    {
        return false;
    }
    true
}

/// The bytes a cursor is bound to.
///
/// Canonical forbids changing the filters while paging — they are part
/// of the cursor's position — so they are folded into the cursor's
/// HMAC, and resuming under a different filter set fails verification.
/// The caller's DID is bound too, so a leaked cursor is not a
/// cross-principal read (canonical §"Cursor as a capability").
///
/// Length-prefixed so that `action="a&actor=b"` cannot collide with
/// `action="a", actor="b"`.
fn cursor_binding(params: &ListAuditLogsBody, caller_did: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |v: Option<&str>| {
        let bytes = v.unwrap_or("").as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(Some(caller_did));
    field(params.from.map(|t| t.to_rfc3339()).as_deref());
    field(params.to.map(|t| t.to_rfc3339()).as_deref());
    field(params.action.as_deref());
    field(params.actor.as_deref());
    field(params.outcome.as_deref());
    field(params.context_id.as_deref());
    out
}

/// Authorize an audit read.
///
/// The audit log is the whole agent's tail: it holds actor DIDs and
/// actions from **every** trust context. `require_admin` alone tests
/// only the role, so a context-scoped admin — an admin deliberately
/// confined to one context — could read every other context's
/// activity. Canonical states the gate directly: this is the tightest-
/// gated read a maintainer offers, and a context-scoped admin does not
/// qualify for the whole-log tail.
///
/// So: a super-admin reads anything; a scoped admin must name a
/// `contextId` inside their own scope, which the filter then confines
/// the results to.
///
/// Note this deliberately goes through `is_super_admin` /
/// `has_context_access` rather than testing `allowed_contexts`
/// directly — an empty context list means *unrestricted* for an admin
/// and *authorized nowhere* for every other role.
fn authorize(auth: &AuthClaims, params: &ListAuditLogsBody) -> Result<(), AppError> {
    auth.require_admin()?;

    if auth.is_super_admin() {
        return Ok(());
    }

    let Some(ctx) = params.context_id.as_deref() else {
        return Err(AppError::Forbidden(
            "reading the whole audit log requires an unrestricted admin; a context-scoped \
             admin must pass contextId to read that context's entries"
                .into(),
        ));
    };

    if !auth.has_context_access(ctx) {
        return Err(AppError::Forbidden(format!(
            "not authorized to read audit entries for context {ctx}"
        )));
    }

    Ok(())
}

/// List audit logs, newest first, with optional filters and opaque
/// cursor pagination — canonical `audit/list/0.1`.
pub async fn list_audit_logs(
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: &ListAuditLogsBody,
    _channel: &str,
) -> Result<ListAuditLogsResultBody, AppError> {
    authorize(auth, params)?;

    let limit = params
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_LIMIT as u64) as usize;

    let cursor_key = CursorKey::new(audit_ks.clone()).get().await?;
    let binding = cursor_binding(params, &auth.did);
    let resume_from = match &params.cursor {
        Some(wire) => Some(Cursor::decode_bound(wire, &cursor_key, &binding)?),
        None => None,
    };

    // The storage key is `log:{timestamp:020}:{uuid}`, so a
    // lexicographic walk is chronological and the key itself is a
    // stable cursor position — stable under concurrent appends in a
    // way an offset is not.
    //
    // This materialises the whole keyspace per page, as the offset
    // implementation it replaces also did — retention caps how large
    // that gets. The fix, when it is needed, is the cursor-aware
    // `prefix_iter_after` sketched in `vti_common::pagination`'s module
    // docs; it does not change the wire shape, because the cursor is
    // already the storage key this would seek to.
    let mut pairs = audit_ks.prefix_iter_raw("log:").await?;
    pairs.sort_by(|(a, _), (b, _)| b.cmp(a)); // newest first

    // Descending order means "the next page" is everything strictly
    // less than the last key already returned.
    let start = match &resume_from {
        Some(c) => pairs
            .iter()
            .position(|(k, _)| k.as_slice() < c.last_key.as_slice())
            .unwrap_or(pairs.len()),
        None => 0,
    };

    let mut entries: Vec<AuditEnvelope> = Vec::with_capacity(limit);
    let mut last_seen_key: Option<Vec<u8>> = None;
    let mut idx = start;
    while entries.len() < limit && idx < pairs.len() {
        let (key, value) = &pairs[idx];
        match serde_json::from_slice::<AuditLogEntry>(value) {
            Ok(row) => {
                if matches(params, &row) {
                    entries.push(AuditEnvelope::from(&row));
                    last_seen_key = Some(key.clone());
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    key = %String::from_utf8_lossy(key),
                    "skipping unparseable audit row",
                );
            }
        }
        idx += 1;
    }

    // `truncated` must mean "more *matching* entries remain", not "more
    // rows remain": under a filter the tail may hold nothing that
    // matches, and handing back a cursor for an empty next page would
    // read as results being withheld. Scan ahead only as far as the
    // first further match.
    let mut more_matches = false;
    while idx < pairs.len() {
        if let Ok(row) = serde_json::from_slice::<AuditLogEntry>(&pairs[idx].1)
            && matches(params, &row)
        {
            more_matches = true;
            break;
        }
        idx += 1;
    }

    let cursor = if more_matches {
        last_seen_key
            .map(|k| Cursor::new(k, pairs.len() as u64).encode_bound(&cursor_key, &binding))
    } else {
        None
    };

    Ok(ListAuditLogsResultBody {
        entries,
        truncated: cursor.is_some(),
        cursor,
    })
}

/// Get the current audit retention period.
pub async fn get_retention(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    _channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_admin()?;
    let config = config.read().await;
    Ok(RetentionResultBody {
        retention_days: config.audit.retention_days,
    })
}

/// Update the audit retention period (super-admin only).
pub async fn update_retention(
    config: &Arc<RwLock<AppConfig>>,
    // The sink, not the keyspace: this only *writes* one row. Note that the
    // retention period it sets governs the keyspace, which an alternative sink
    // does not necessarily share — see `vta_audit::sink`.
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    retention_days: u32,
    channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_super_admin()?;

    if !(1..=365).contains(&retention_days) {
        return Err(AppError::Validation(
            "retention_days must be between 1 and 365".into(),
        ));
    }

    let (result, contents, path) = {
        let mut config = config.write().await;
        config.audit.retention_days = retention_days;
        let result = RetentionResultBody { retention_days };
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Internal(format!("failed to serialize config: {e}")))?;
        let path = config.config_path.clone();
        (result, contents, path)
    };

    std::fs::write(&path, contents).map_err(AppError::Io)?;
    tracing::info!(channel, retention_days, "audit retention updated");
    audit!(
        "audit.retention_update",
        actor = &auth.did,
        resource = retention_days,
        outcome = "success"
    );
    let _ = audit::record(
        audit,
        "audit.retention_update",
        &auth.did,
        Some(&retention_days.to_string()),
        "success",
        Some(channel),
        None,
    )
    .await;
    Ok(result)
}
