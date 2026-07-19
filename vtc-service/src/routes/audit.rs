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

use vti_common::audit::{AuditEnvelope, ChainBreak, ChainVerifier};
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

/// Result of a chain verification pass.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct VerifyResponse {
    /// Whether every chainable envelope verified.
    pub verified: bool,
    /// Envelopes examined, chainable or not.
    pub entries_examined: usize,
    /// Envelopes that carried a chain link and verified.
    pub entries_verified: usize,
    /// Pre-v2 envelopes skipped as unchainable.
    ///
    /// **Non-zero is a finding on a store that should hold none.**
    /// `verify_chain` skips these rows rather than verifying them, so
    /// they are an insertion point: an envelope forged with
    /// `schemaVersion: 1` passes untouched.
    pub legacy_skipped: usize,
    /// Rows that would not deserialize into an envelope at all. Also
    /// skipped, and also a finding — reported separately from
    /// `legacySkipped` because the cause differs (corruption or a
    /// forward-version row, versus a pre-chain row).
    pub unparseable_skipped: usize,
    /// Head of the verified chain, hex-encoded. `None` when nothing
    /// chainable was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Where the chain broke. Absent when `verified` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_break: Option<ChainBreakReport>,
}

/// A detected break, flattened for the wire.
///
/// `ChainBreak` itself is deliberately not `Serialize` in
/// `vti-common`, so this is the REST projection of it.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ChainBreakReport {
    /// `tamperedEntry` — the envelope's content was altered after it
    /// was written; or `brokenLink` — an entry was reordered,
    /// dropped, or inserted.
    pub kind: String,
    /// Position in the ascending walk, counting skipped rows.
    pub index: usize,
    /// `event_id` of the offending envelope.
    pub event_id: String,
}

/// GET /audit/verify — verify the audit hash chain. Auth: Super-admin.
///
/// Walks the whole audit keyspace in ascending (chronological) key
/// order and folds it through [`ChainVerifier`], so memory stays
/// constant regardless of log size.
///
/// **What a `verified: true` does and does not mean.** The chain
/// links each envelope to its predecessor, so a reorder, drop, or
/// duplicate is detected. It is *not* a signature: `chain_digest` is
/// an unkeyed SHA-256, so an adversary with write access to the store
/// can forge a suffix and restamp every envelope after it, and a
/// truncation to a valid prefix is indistinguishable from a quiet
/// period. Closing that needs signed checkpoints — see
/// `docs/05-design-notes/vtc-audit-checkpoints.md`.
#[utoipa::path(
    get, path = "/audit/verify", tag = "audit",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Chain verification result", body = VerifyResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn verify_audit_chain(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
) -> Result<Json<VerifyResponse>, AppError> {
    // Ascending key order is chronological write order, which is what
    // the verifier requires — note this is the opposite of
    // `list_audit`'s newest-first sort.
    let mut pairs = state.audit_ks.prefix_iter_raw(Vec::new()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut verifier = ChainVerifier::new();
    let mut unparseable = 0usize;
    let mut chain_break = None;

    for (key, value) in &pairs {
        let env = match serde_json::from_slice::<AuditEnvelope>(value) {
            Ok(env) => env,
            Err(err) => {
                // Matches `list_audit`: one bad row must not abort the
                // whole pass. Counted and surfaced, not swallowed.
                unparseable += 1;
                tracing::warn!(
                    error = %err,
                    key = %String::from_utf8_lossy(key),
                    "skipping unparseable audit envelope during verify",
                );
                continue;
            }
        };
        if let Err(brk) = verifier.push(&env) {
            let (kind, index, event_id) = match brk {
                ChainBreak::TamperedEntry { index, event_id } => ("tamperedEntry", index, event_id),
                ChainBreak::BrokenLink { index, event_id } => ("brokenLink", index, event_id),
            };
            chain_break = Some(ChainBreakReport {
                kind: kind.to_string(),
                index,
                event_id: event_id.to_string(),
            });
            break;
        }
    }

    let verified = chain_break.is_none();
    let response = VerifyResponse {
        verified,
        entries_examined: verifier.index(),
        entries_verified: verifier.verified(),
        legacy_skipped: verifier.skipped_legacy(),
        unparseable_skipped: unparseable,
        head: verifier.head().map(hex::encode),
        chain_break,
    };

    // Warn, not info, on failure: a broken audit chain is the kind of
    // thing that should be visible in logs even if nobody is reading
    // the response.
    if verified {
        info!(
            caller = %auth.0.did,
            examined = response.entries_examined,
            verified = response.entries_verified,
            legacy_skipped = response.legacy_skipped,
            "audit chain verified",
        );
    } else {
        tracing::warn!(
            caller = %auth.0.did,
            examined = response.entries_examined,
            chain_break = ?response.chain_break,
            "audit chain verification FAILED",
        );
    }

    Ok(Json(response))
}
