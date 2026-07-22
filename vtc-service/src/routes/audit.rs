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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vti_common::audit::{AuditEnvelope, ChainBreak, ChainVerifier};
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, MAX_LIMIT};

use crate::auth::SuperAdminAuth;
use crate::server::AppState;
use tracing::info;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Return only entries recorded at or after this time.
    pub from: Option<DateTime<Utc>>,
    /// Return only entries recorded strictly before this time.
    pub to: Option<DateTime<Utc>>,
    /// Return only entries whose `action` equals this value — the
    /// event variant name, e.g. `MemberRemoved`.
    pub action: Option<String>,
    /// Return only entries whose actor DID equals this value. Matches
    /// the plaintext, so RTBF-redacted rows are never returned by an
    /// actor filter (canonical requires exactly this).
    pub actor: Option<String>,
    /// Not supported by this maintainer — see [`unsupported_filters`].
    pub outcome: Option<String>,
    /// Not supported by this maintainer — see [`unsupported_filters`].
    pub context_id: Option<String>,
    /// Page size. Clamped to `1..=200`. Defaults to 50.
    pub page_size: Option<usize>,
    /// Pagination cursor (returned by a previous call).
    pub cursor: Option<String>,
}

impl AuditQuery {
    /// Canonical `audit/list` defines `outcome` and `contextId`, but this
    /// maintainer tracks neither: the envelope has no envelope-level
    /// outcome (only one variant carries an `outcome` inside its own
    /// `data`), and the audit log is not partitioned per trust context —
    /// a VTC *is* a single community.
    ///
    /// Accepting and ignoring them would be the dangerous option: a
    /// caller asking for `actor=X&outcome=denied` would receive every
    /// entry for X and could reasonably read that as "no denials". So
    /// they are refused rather than silently dropped.
    fn unsupported_filters(&self) -> Vec<&'static str> {
        let mut bad = Vec::new();
        if self.outcome.is_some() {
            bad.push("outcome");
        }
        if self.context_id.is_some() {
            bad.push("contextId");
        }
        bad
    }

    /// The bytes a cursor is bound to. Canonical forbids changing the
    /// filters while paging — the filters are part of the cursor's
    /// position — so they are folded into the cursor's HMAC. Resuming
    /// with a different filter set fails verification.
    ///
    /// Length-prefixed so that `action="a&actor=b"` cannot collide with
    /// `action="a", actor="b"`.
    fn cursor_binding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |v: Option<&str>| {
            let bytes = v.unwrap_or("").as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        field(self.from.map(|t| t.to_rfc3339()).as_deref());
        field(self.to.map(|t| t.to_rfc3339()).as_deref());
        field(self.action.as_deref());
        field(self.actor.as_deref());
        out
    }

    /// Does this envelope pass every supplied filter?
    fn matches(&self, env: &AuditEnvelope) -> bool {
        if let Some(from) = self.from
            && env.timestamp < from
        {
            return false;
        }
        if let Some(to) = self.to
            && env.timestamp >= to
        {
            return false;
        }
        if let Some(action) = &self.action
            && action_of(env) != action.as_str()
        {
            return false;
        }
        if let Some(actor) = &self.actor
            && env.actor_did_plain.as_deref() != Some(actor.as_str())
        {
            return false;
        }
        true
    }
}

/// The canonical `action` for an envelope: the event's variant name.
///
/// Canonical calls `action` "a maintainer-defined action name", so the
/// variant name is used verbatim rather than being re-spelled into
/// `member.removed` form — that keeps it identical to the `type` tag
/// already on the stored envelope and to what the admin UI filters on.
fn action_of(env: &AuditEnvelope) -> &'static str {
    env.event.variant_name()
}

/// One entry in the canonical `audit/list` response.
///
/// `additionalProperties: false` on the canonical envelope means VTC's
/// extra fields cannot ride along at the top level, so the keyed hashes
/// and the per-variant version move into `ext`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub event_id: String,
    pub recorded_at: String,
    pub action: String,
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub schema_version: u32,
    /// Hex, matching the encoding `audit/verify` uses for `head` — a
    /// caller comparing the two must not have to reconcile hex against
    /// the base64 the stored envelope uses.
    pub prev_hash: String,
    pub entry_hash: String,
    pub detail: serde_json::Value,
    pub ext: serde_json::Value,
}

impl From<&AuditEnvelope> for AuditEntry {
    fn from(env: &AuditEnvelope) -> Self {
        // The stored event is `{"type": Variant, "data": {...}}`; the
        // canonical split is `action` + `detail`.
        let detail = serde_json::to_value(&env.event)
            .ok()
            .and_then(|mut v| v.get_mut("data").map(serde_json::Value::take))
            .unwrap_or(serde_json::Value::Object(Default::default()));

        Self {
            event_id: env.event_id.to_string(),
            recorded_at: env.timestamp.to_rfc3339(),
            action: action_of(env).to_owned(),
            actor: env.actor_did_plain.clone(),
            target: env.target_did_plain.clone(),
            schema_version: env.schema_version,
            prev_hash: hex::encode(env.prev_hash),
            entry_hash: hex::encode(env.entry_hash),
            detail,
            ext: serde_json::json!({
                "vtc": {
                    "eventVersion": env.event_version,
                    "auditKeyId": env.audit_key_id.to_string(),
                    "actorDidHash": hex::encode(env.actor_did_hash),
                    "targetDidHash": env.target_did_hash.map(hex::encode),
                }
            }),
        }
    }
}

/// Canonical `audit/list` response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditListResponse {
    pub entries: Vec<AuditEntry>,
    /// True when more entries match beyond this page; `cursor` is then
    /// present.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
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
) -> Result<Json<AuditListResponse>, AppError> {
    let unsupported = query.unsupported_filters();
    if !unsupported.is_empty() {
        return Err(AppError::Validation(format!(
            "this maintainer does not implement the {} filter(s); \
             refusing rather than returning unfiltered results",
            unsupported.join(", "),
        )));
    }

    let limit = query.page_size.unwrap_or(50).clamp(1, MAX_LIMIT);

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let audit_key = audit_writer.active_key().await?;

    // The filters are bound into the cursor's HMAC, so resuming a page
    // under a different filter set fails as a tampered cursor.
    let binding = query.cursor_binding();
    let decoded_cursor = match &query.cursor {
        Some(s) => Some(Cursor::decode_bound(s, &audit_key.key, &binding)?),
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

    let mut entries: Vec<AuditEntry> = Vec::with_capacity(limit);
    let mut last_seen_key: Option<Vec<u8>> = None;
    let mut idx = start;
    while entries.len() < limit && idx < pairs.len() {
        let (key, value) = &pairs[idx];
        match serde_json::from_slice::<AuditEnvelope>(value) {
            Ok(env) => {
                // Filter *after* deserializing: the predicates read
                // envelope fields, and an unparseable row can't be
                // judged either way (it is skipped below, as before).
                if query.matches(&env) {
                    entries.push(AuditEntry::from(&env));
                    last_seen_key = Some(key.clone());
                }
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

    // `truncated` must mean "more *matching* entries remain", not "more
    // rows remain" — with a filter applied the tail may hold nothing
    // that matches, and handing back a cursor for an empty next page
    // would make a caller believe results were withheld. Scan ahead only
    // until the first further match.
    let mut more_matches = false;
    while idx < pairs.len() {
        if let Ok(env) = serde_json::from_slice::<AuditEnvelope>(&pairs[idx].1)
            && query.matches(&env)
        {
            more_matches = true;
            break;
        }
        idx += 1;
    }

    let snapshot_id: u64 = pairs.len() as u64;
    let cursor = if more_matches {
        last_seen_key.map(|k| Cursor::new(k, snapshot_id).encode_bound(&audit_key.key, &binding))
    } else {
        None
    };

    info!(
        caller = %auth.0.did,
        count = entries.len(),
        has_more = cursor.is_some(),
        "audit listed",
    );

    Ok(Json(AuditListResponse {
        truncated: cursor.is_some(),
        entries,
        cursor,
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
