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
use vti_common::pagination::{Cursor, MAX_LIMIT};

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
#[derive(utoipa::ToSchema)]
pub struct PolicyResponse {
    #[serde(flatten)]
    pub policy: Policy,
    /// `true` when this row is the currently-active policy for its
    /// purpose. Computed against the `active_policies:<purpose>`
    /// keyspace at response time.
    pub is_active: bool,
}

/// Canonical `policy/list` response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyListResponse {
    pub policies: Vec<PolicyModuleResponse>,
    /// Canonical-required: more matching modules exist beyond this page.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Canonical `policy/get` response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyGetResponse {
    pub policy: PolicyModuleResponse,
}

/// Reverse-DNS-namespaced `ext` member carrying this maintainer's
/// **intrinsic** policy purpose (SPEC.md §4.5.1).
///
/// Canonical models purpose as a property of the *activation binding*,
/// not of the module — a module is purpose-agnostic and reusable. VTC
/// cannot follow that: a purpose is baked into the module's own Rego
/// package name and validated at upload, because a module in the wrong
/// package compiles cleanly and then silently denies every request for
/// that ceremony. Inference is not a way out either — only 4 of the 10
/// purposes have an expected package, so 6 could never be derived from
/// the source.
///
/// So the purpose travels in `ext`, which is exactly what the framework
/// reserves for ecosystem-defined members. It is a documented
/// divergence rather than a hidden one: a consumer reading the module
/// can see that this maintainer binds purpose intrinsically.
pub const PURPOSE_EXT_KEY: &str = "org.openvtc.purpose";

/// Canonical `policy/_shared` **PolicyModule**.
///
/// Field mapping from VTC's storage row:
/// - `rego_source` → `module`
/// - `version` (monotone per-purpose revision counter) → `version`,
///   which canonical also uses as the optimistic-concurrency token.
/// - `updatedAt` is the activation time when the row has been
///   activated, else its creation time. A VTC revision is immutable, so
///   activation is the only thing that can change it after write.
/// - `sha256` / `authorDid` / the intrinsic `purpose` have no canonical
///   home and ride in `ext` (the canonical type is
///   `additionalProperties: false`).
///
/// `appliesTo` / `priority` / `enabled` are deliberately **not**
/// emitted: VTC does no `appliesTo`/`priority` selection, and emitting
/// empty values would imply a selection model that isn't there.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyModuleResponse {
    pub id: Uuid,
    pub name: String,
    pub module: String,
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
    pub ext: serde_json::Value,
}

impl From<&Policy> for PolicyModuleResponse {
    fn from(p: &Policy) -> Self {
        Self {
            id: p.id,
            // Rows written before `name` existed fall back to the
            // purpose — the only stable human-meaningful identifier
            // such a row has, and canonical requires `name`.
            name: p
                .name
                .clone()
                .unwrap_or_else(|| p.purpose.as_str().to_owned()),
            module: p.rego_source.clone(),
            version: p.version,
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.activated_at.unwrap_or(p.created_at).to_rfc3339(),
            ext: serde_json::json!({
                PURPOSE_EXT_KEY: p.purpose.as_str(),
                "org.openvtc.sha256": hex::encode(p.sha256),
                "org.openvtc.authorDid": p.author_did,
            }),
        }
    }
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
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListPoliciesQuery {
    /// Filter by purpose (wire-form camelCase). A VTC extension —
    /// canonical has no purpose filter because purpose is not a
    /// property of a module there.
    pub purpose: Option<PolicyPurpose>,
    /// Canonical `policy/list` parameters this maintainer does not
    /// implement. Accepting them silently would tell a caller their
    /// query was narrowed when it was not, so they are refused.
    pub context_id: Option<String>,
    pub enabled_only: Option<bool>,
    /// Canonical page-size name.
    pub page_size: Option<usize>,
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
#[derive(utoipa::ToSchema)]
pub enum PolicyStatusFilter {
    Active,
    Archived,
}

#[utoipa::path(
    get, path = "/policies", tag = "policies",
    security(("bearer_jwt" = [])),
    params(ListPoliciesQuery),
    responses(
        (status = 200, description = "Paginated list of policies", body = PolicyListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_policies(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<PolicyListResponse>, AppError> {
    let mut unsupported = Vec::new();
    if query.context_id.is_some() {
        unsupported.push("contextId");
    }
    if query.enabled_only.is_some() {
        unsupported.push("enabledOnly");
    }
    if !unsupported.is_empty() {
        return Err(AppError::Validation(format!(
            "this maintainer does not implement the {} filter(s): its policy log \
             is not context-partitioned and modules carry no enabled flag. \
             Refusing rather than returning an unfiltered list.",
            unsupported.join(", "),
        )));
    }

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
        return Ok(Json(PolicyListResponse {
            policies: items.iter().map(|r| (&r.policy).into()).collect(),
            truncated: false,
            cursor: None,
        }));
    }

    let limit = query
        .page_size
        .or(query.limit)
        .unwrap_or(50)
        .clamp(1, MAX_LIMIT);

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

    Ok(Json(PolicyListResponse {
        policies: items.iter().map(|r| (&r.policy).into()).collect(),
        truncated: page.next_cursor.is_some(),
        cursor: page.next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// GET /v1/policies/{id}
// ---------------------------------------------------------------------------

#[utoipa::path(
    get, path = "/policies/{id}", tag = "policies",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Policy id")),
    responses(
        (status = 200, description = "Policy", body = PolicyGetResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Policy not found"),
    ),
)]
pub async fn show_policy(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyGetResponse>, AppError> {
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("policy not found: {id}")))?;
    Ok(Json(PolicyGetResponse {
        policy: (&policy).into(),
    }))
}

// ---------------------------------------------------------------------------
// GET /v1/policies/active — canonical `policy/active`
// ---------------------------------------------------------------------------

/// Canonical `policy/active` response: the `(contextId, purpose) →
/// module` bindings currently in force.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActiveBindingsResponse {
    pub bindings: Vec<ActiveBinding>,
}

/// One activation binding. `contextId` is omitted throughout: a VTC is
/// a single community and does not partition its policy set per trust
/// context, so every binding is community-wide.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActiveBinding {
    pub purpose: String,
    pub policy: PolicyModuleResponse,
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ActiveQuery {
    /// Narrow to a single decision slot.
    pub purpose: Option<PolicyPurpose>,
    /// Not implemented — a VTC is not context-partitioned. Refused
    /// rather than ignored, so a caller never reads a community-wide
    /// binding as one scoped to their context.
    pub context_id: Option<String>,
}

#[utoipa::path(
    get, path = "/policies/active", tag = "policies",
    security(("bearer_jwt" = [])),
    params(ActiveQuery),
    responses(
        (status = 200, description = "Active policy bindings", body = ActiveBindingsResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn active_policies(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ActiveQuery>,
) -> Result<Json<ActiveBindingsResponse>, AppError> {
    if query.context_id.is_some() {
        return Err(AppError::Validation(
            "this maintainer does not implement the contextId filter: a VTC is a \
             single community and its policy bindings are community-wide."
                .into(),
        ));
    }

    let mut bindings = Vec::new();
    for purpose in PolicyPurpose::ALL {
        if query.purpose.is_some_and(|f| f != purpose) {
            continue;
        }
        if let Some(id) = get_active_policy_id(&state.active_policies_ks, purpose).await?
            && let Some(p) = get_policy(&state.policies_ks, id).await?
        {
            bindings.push(ActiveBinding {
                purpose: purpose.as_str().to_owned(),
                policy: (&p).into(),
            });
        }
    }
    Ok(Json(ActiveBindingsResponse { bindings }))
}
