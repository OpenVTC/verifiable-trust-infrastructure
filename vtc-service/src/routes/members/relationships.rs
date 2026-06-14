//! `GET /v1/members/{did}/relationships` — paginated VRC
//! list per member. Phase 4 M4.6.2. Spec §6.1 + §12.3.
//!
//! ## §12.3 departure-handling strip
//!
//! When a community member is **Purge**-removed, their ACL
//! row and Member row are both deleted. VRCs naming a
//! purged party are stripped from this list so the response
//! doesn't surface dangling references to identifiers that
//! no longer exist in the community.
//!
//! `Tombstone` and `Historical` members keep their Member
//! rows (with `removed_at: Some(_)`), so VRCs naming them
//! remain visible. The list path doesn't filter on
//! `removed_at` — operator-uploaded directory policies can
//! layer that if they want.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use vti_common::auth::extractor::AuthClaims;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated};

use crate::acl::get_acl_entry;
use crate::members::get_member;
use crate::relationships::{Relationship, list_for_did};
use crate::server::AppState;

const MAX_LIMIT: usize = 200;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// GET /members/{did}/relationships — paginated VRC list for a member.
/// Auth: any authenticated session.
#[utoipa::path(
    get, path = "/members/{did}/relationships", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID"), ListQuery),
    responses(
        (status = 200, description = "Paginated relationship list", body = Paginated<Relationship>),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not authorised"),
    ),
)]
pub async fn list(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Paginated<Relationship>>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_LIMIT);
    let audit_key = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?
        .active_key()
        .await?;

    let cursor = query
        .cursor
        .as_deref()
        .map(|c| Cursor::decode(c, &audit_key.key))
        .transpose()
        .map_err(|e| AppError::Validation(format!("invalid cursor: {e}")))?;

    let page = list_for_did(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &audit_key,
        &did,
        cursor.as_ref(),
        limit,
    )
    .await?;

    // §12.3 strip: drop rows where the OTHER party (not the
    // path-DID) has been Purge-removed (ACL absent AND Member
    // absent). The path-DID itself is whoever the caller
    // asked about — they're inherently part of the
    // relationship, so we don't strip on their state.
    let mut filtered: Vec<Relationship> = Vec::with_capacity(page.items.len());
    for rel in page.items {
        let other = if rel.issuer_did == did {
            &rel.subject_did
        } else {
            &rel.issuer_did
        };
        let other_purged = get_acl_entry(&state.acl_ks, other).await?.is_none()
            && get_member(&state.members_ks, other).await?.is_none();
        if !other_purged {
            filtered.push(rel);
        }
    }

    Ok(Json(Paginated {
        items: filtered,
        next_cursor: page.next_cursor,
        total_estimate: page.total_estimate,
    }))
}
