//! Policy read endpoints — list + show (M2.4.1).
//!
//! Spec §7.1 surfacing. Two admin-only GETs that operators (and the
//! M2.4-adjacent CLI verbs) reach for when inspecting the current
//! policy state. Neither endpoint mutates state.
//!
//! ## Filters on the list endpoint
//!
//! - `purpose` — exact-match on `PolicyPurpose` wire form
//!   (`"join"`, `"removal"`, `"crossCommunityRoles"`, …). Unknown
//!   values surface as 400 via serde.
//! - `status` — `"active"` returns only the row currently pointed
//!   at by `active_policies:<purpose>`; `"archived"` returns every
//!   row that is *not* the current active pointer for its purpose.
//!   Omitted returns every row.
//!
//! Filters are applied **after** pagination — the page boundary is
//! over the entire `policies:*` keyspace and rows that fail the
//! filter are silently dropped from the response. This mirrors the
//! members-list approach (M1.4.1) and trades a slightly noisier
//! cursor for a stable page-size invariant.

use std::collections::HashSet;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vti_common::error::AppError;
use vti_common::pagination::{Cursor, MAX_LIMIT, Paginated};

use crate::auth::AdminAuth;
use crate::policy::{
    Policy, PolicyPurpose, get_active_policy_id, get_policy, list_policies_paginated,
};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Wire shape
// ---------------------------------------------------------------------------

/// Full Policy projection returned by both endpoints. Mirrors the
/// storage row except `sha256` ships as hex (the `hex32` serde
/// adapter is on the storage row already, so the wire shape is
/// already correct here — this struct just adds `isActive` so
/// callers don't need a second round-trip).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResponse {
    #[serde(flatten)]
    pub policy: Policy,
    /// `true` when this row is the currently-active policy for its
    /// purpose. Computed against the `active_policies:<purpose>`
    /// keyspace at response time.
    pub is_active: bool,
}

impl PolicyResponse {
    fn from_policy(policy: Policy, is_active: bool) -> Self {
        Self { policy, is_active }
    }
}

// ---------------------------------------------------------------------------
// GET /v1/policies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPoliciesQuery {
    /// Filter by purpose (wire-form camelCase).
    pub purpose: Option<PolicyPurpose>,
    /// `"active"` — only the row pointed at by each
    /// `active_policies:<purpose>`. `"archived"` — every row that
    /// is *not* the current active pointer. Omitted → all rows.
    pub status: Option<PolicyStatusFilter>,
    /// Pagination cursor (returned by a previous call).
    pub cursor: Option<String>,
    /// Page size. Clamped to `1..=200`.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatusFilter {
    Active,
    Archived,
}

pub async fn list_policies(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Paginated<PolicyResponse>>, AppError> {
    // `status=active` is resolved directly from the per-purpose active
    // pointers, not the paginated keyspace scan. The purpose/status
    // filters below run *after* pagination, so a small `limit` (the
    // simulator's active-policy lookup sends `limit=1`) would drop the
    // active row for every purpose whose row isn't in the first page —
    // surfacing the active policy for one arbitrary purpose only. The
    // active set is at most one row per `PolicyPurpose`, so resolve it
    // deterministically and ignore limit/cursor.
    if matches!(query.status, Some(PolicyStatusFilter::Active)) {
        let mut items = Vec::new();
        for purpose in PolicyPurpose::ALL {
            if query.purpose.is_some_and(|f| f != purpose) {
                continue;
            }
            if let Some(id) = get_active_policy_id(&state.active_policies_ks, purpose).await?
                && let Some(p) = get_policy(&state.policies_ks, id).await?
            {
                items.push(PolicyResponse::from_policy(p, true));
            }
        }
        let total = items.len() as u64;
        return Ok(Json(Paginated {
            items,
            next_cursor: None,
            total_estimate: Some(total),
        }));
    }

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

    let page = list_policies_paginated(
        &state.policies_ks,
        &audit_key,
        decoded_cursor.as_ref(),
        limit,
    )
    .await?;

    // Resolve the set of currently-active policy ids once per page.
    // Cheap: at most 9 entries (one per PolicyPurpose).
    let mut active_ids: HashSet<Uuid> = HashSet::new();
    for purpose in PolicyPurpose::ALL {
        if let Some(id) = get_active_policy_id(&state.active_policies_ks, purpose).await? {
            active_ids.insert(id);
        }
    }

    let purpose_filter = query.purpose;
    let status_filter = query.status;

    let items: Vec<PolicyResponse> = page
        .items
        .into_iter()
        .filter(|p| purpose_filter.is_none_or(|f| p.purpose == f))
        .filter_map(|p| {
            let is_active = active_ids.contains(&p.id);
            match status_filter {
                Some(PolicyStatusFilter::Active) if !is_active => return None,
                Some(PolicyStatusFilter::Archived) if is_active => return None,
                _ => {}
            }
            Some(PolicyResponse::from_policy(p, is_active))
        })
        .collect();

    Ok(Json(Paginated {
        items,
        next_cursor: page.next_cursor,
        total_estimate: page.total_estimate,
    }))
}

// ---------------------------------------------------------------------------
// GET /v1/policies/{id}
// ---------------------------------------------------------------------------

pub async fn show_policy(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyResponse>, AppError> {
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("policy not found: {id}")))?;
    let active_id = get_active_policy_id(&state.active_policies_ks, policy.purpose).await?;
    let is_active = active_id == Some(id);
    Ok(Json(PolicyResponse::from_policy(policy, is_active)))
}
