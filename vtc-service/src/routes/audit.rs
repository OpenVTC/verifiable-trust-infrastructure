//! Audit log read endpoint.
//!
//! `GET /v1/audit` — newest-first paginated view of the daemon's
//! audit envelopes. Super-admin only: envelopes carry plaintext
//! actor + target DIDs (until an RTBF override nulls them), which
//! is the same sensitivity tier as the audit keyspace itself.
//!
//! The audit storage key is `<rfc3339-timestamp>:<event_id>` so a
//! lexicographic ascending walk is chronological; we reverse the
//! page so the SPA can show newest-first without a client-side
//! sort. Pagination uses the standard signed-cursor pattern from
//! `vti_common::pagination`, with the twist that "next" means
//! "older than the cursor" — descending order. The cursor's
//! `last_key` is the *smallest* (oldest) key included on the
//! returned page; the next page returns entries strictly less than
//! that key.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;

use vti_common::audit::AuditEnvelope;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, MAX_LIMIT, Paginated};

use crate::auth::SuperAdminAuth;
use crate::server::AppState;
use tracing::info;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Pagination cursor (returned by a previous call).
    pub cursor: Option<String>,
    /// Page size. Clamped to `1..=200`. Defaults to 50.
    pub limit: Option<usize>,
}

/// GET /audit — newest-first paginated audit envelopes. Auth: Super-admin.
#[utoipa::path(
    get, path = "/audit", tag = "audit",
    security(("bearer_jwt" = [])),
    params(AuditQuery),
    responses(
        (status = 200, description = "Paginated audit envelopes", body = Object),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn list_audit(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Paginated<AuditEnvelope>>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_LIMIT);

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let audit_key = audit_writer.active_key().await?;

    let decoded_cursor = match &query.cursor {
        Some(s) => Some(Cursor::decode(s, &audit_key.key)?),
        None => None,
    };

    // Walk the entire audit keyspace, then sort descending so newest
    // entries come first. Linear scan matches `list_policies_paginated`
    // — see `vti_common::pagination` module docs for the long-term
    // plan to push this into the store layer.
    let mut pairs = state.audit_ks.prefix_iter_raw(Vec::new()).await?;
    pairs.sort_by(|(a, _), (b, _)| b.cmp(a));

    // Apply cursor: skip until first key strictly less than
    // `cursor.last_key`. Descending order means "strictly less" =
    // "the next-oldest entry".
    let start = match &decoded_cursor {
        Some(c) => pairs
            .iter()
            .position(|(k, _)| k.as_slice() < c.last_key.as_slice())
            .unwrap_or(pairs.len()),
        None => 0,
    };

    let mut items: Vec<AuditEnvelope> = Vec::with_capacity(limit);
    let mut last_seen_key: Option<Vec<u8>> = None;
    let mut idx = start;
    while items.len() < limit && idx < pairs.len() {
        let (key, value) = &pairs[idx];
        match serde_json::from_slice::<AuditEnvelope>(value) {
            Ok(env) => {
                items.push(env);
                last_seen_key = Some(key.clone());
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    key = %String::from_utf8_lossy(key),
                    "skipping unparseable audit envelope",
                );
            }
        }
        idx += 1;
    }

    let snapshot_id: u64 = pairs.len() as u64;
    let next_cursor = if idx < pairs.len() {
        last_seen_key.map(|k| Cursor::new(k, snapshot_id).encode(&audit_key.key))
    } else {
        None
    };

    info!(
        caller = %auth.0.did,
        count = items.len(),
        has_more = next_cursor.is_some(),
        "audit listed",
    );

    Ok(Json(Paginated {
        items,
        next_cursor,
        total_estimate: None,
    }))
}
