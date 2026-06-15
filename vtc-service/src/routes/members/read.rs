//! `GET /v1/members` + `GET /v1/members/{did}` — admin-gated
//! member read endpoints (M1.4.1).
//!
//! The response shape joins the [`crate::members::Member`] metadata
//! row with its matching [`crate::acl::VtcAclEntry`]'s role + label
//! so callers don't need a second round-trip. Phase 1 has no
//! privacy gating beyond `AdminAuth`; spec §12.3's PMF lands in
//! Phase 2+.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use vti_common::pagination::{Cursor, MAX_LIMIT, Paginated};

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, list_acl_entries};
use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::members::{Disposition, Member, get_member, list_members_paginated};
use crate::server::AppState;

/// Wire shape returned by both endpoints. Joins `members:<did>`
/// + `acl:<did>` so a caller doesn't need a second request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct MemberResponse {
    pub did: String,
    pub role: VtcRole,
    pub label: Option<String>,
    pub joined_at: DateTime<Utc>,
    pub publish_consent: bool,
    pub departure_preference: Disposition,
    pub status_list_index: Option<u32>,
    pub current_vmc_id: Option<String>,
    pub current_role_vec_id: Option<String>,
    pub extensions: JsonValue,
    /// Personhood flag (Phase 4 M4.1). Surfaces the Member row's
    /// `personhood` field. Read-only on this response —
    /// `POST /v1/members/{did}/personhood/assert` flips it (M4.3),
    /// `DELETE /v1/members/{did}/personhood` clears it (M4.4),
    /// and renewal-policy downgrade clears it (M4.2.2).
    pub personhood: bool,
    /// Timestamp of the most recent assert. Operator-private —
    /// the value is included on Admin-gated responses (this
    /// route is `AdminAuth`) so operators can audit; the
    /// public member-facing renewal response carries only the
    /// `personhood` flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personhood_asserted_at: Option<DateTime<Utc>>,
}

impl MemberResponse {
    fn from_pair(acl: VtcAclEntry, member: Member) -> Self {
        debug_assert_eq!(
            acl.did, member.did,
            "ACL + Member rows must share their DID — caller is responsible for the join"
        );
        Self {
            did: member.did,
            role: acl.role,
            label: acl.label,
            joined_at: member.joined_at,
            publish_consent: member.publish_consent,
            departure_preference: member.departure_preference,
            status_list_index: member.status_list_index,
            current_vmc_id: member.current_vmc_id,
            current_role_vec_id: member.current_role_vec_id,
            extensions: member.extensions,
            personhood: member.personhood,
            personhood_asserted_at: member.personhood_asserted_at,
        }
    }
}

// ---------------------------------------------------------------------------
// GET /v1/members
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListMembersQuery {
    /// Filter by role, expressed in the same wire form
    /// [`VtcRole`] uses (`"admin"`, `"moderator"`,
    /// `"custom:editor"`, …). Server-side filter applied after
    /// pagination — sibling pages skip rows that don't match.
    /// Future improvement: index by role.
    pub role: Option<String>,
    /// Pagination cursor (returned by a previous call).
    pub cursor: Option<String>,
    /// Page size. Clamped to `1..=200`.
    pub limit: Option<usize>,
}

/// GET /members — paginated member list. Auth: Admin.
#[utoipa::path(
    get, path = "/members", tag = "members",
    security(("bearer_jwt" = [])),
    params(ListMembersQuery),
    responses(
        (status = 200, description = "Paginated member list", body = Paginated<MemberResponse>),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_members(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListMembersQuery>,
) -> Result<Json<Paginated<MemberResponse>>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_LIMIT);

    // Phase 1 reads the audit_key out of AppState's writer. The
    // writer is `Some` for every Phase 0 + Phase 1 path — install
    // bootstrap ensures the initial key exists. A daemon that
    // started before that initial-key derivation would 503 here.
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let audit_key = audit_writer.active_key().await?;

    let decoded_cursor = match &query.cursor {
        Some(s) => Some(Cursor::decode(s, &audit_key.key)?),
        None => None,
    };

    let mut page = list_members_paginated(
        &state.members_ks,
        &audit_key,
        decoded_cursor.as_ref(),
        limit,
    )
    .await?;

    // Join with ACL entries.
    let mut items = Vec::with_capacity(page.items.len());
    for member in page.items.drain(..) {
        match get_acl_entry(&state.acl_ks, &member.did).await? {
            Some(acl) => {
                if let Some(filter) = &query.role
                    && acl.role.to_string() != *filter
                {
                    continue;
                }
                items.push(MemberResponse::from_pair(acl, member));
            }
            None => {
                // Member row without an ACL row would mean an
                // out-of-band corruption. Log + skip rather than
                // 500 — the page should still be returnable.
                tracing::warn!(
                    did = %member.did,
                    "member row has no matching ACL entry; skipping in list response"
                );
            }
        }
    }

    Ok(Json(Paginated {
        items,
        next_cursor: page.next_cursor,
        total_estimate: page.total_estimate,
    }))
}

// ---------------------------------------------------------------------------
// GET /v1/members/{did}
// ---------------------------------------------------------------------------

/// GET /members/{did} — single member. Auth: Admin.
#[utoipa::path(
    get, path = "/members/{did}", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    responses(
        (status = 200, description = "Member record", body = MemberResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn show_member(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<MemberResponse>, AppError> {
    vti_common::identifier::validate_did("did", &did)?;
    let member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let acl = get_acl_entry(&state.acl_ks, &did).await?.ok_or_else(|| {
        // Same out-of-band corruption case as the list path —
        // surface as 404 because the *member* isn't presentable.
        AppError::NotFound(format!("member not found (no ACL row): {did}"))
    })?;
    Ok(Json(MemberResponse::from_pair(acl, member)))
}

/// Unused-listing helper kept to ensure `list_acl_entries` stays
/// linked when the foundation PR's pruning passes try to flag it
/// dead. Will be the production filter path once "list ACL
/// without member metadata" arrives in Phase 2+.
#[allow(dead_code)]
pub(crate) async fn list_admin_dids(state: &AppState) -> Result<Vec<String>, AppError> {
    let entries = list_acl_entries(&state.acl_ks).await?;
    Ok(entries
        .into_iter()
        .filter(|e| matches!(e.role, VtcRole::Admin))
        .map(|e| e.did)
        .collect())
}
