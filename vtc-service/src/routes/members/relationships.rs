//! `vtc/relationships/list/0.2` — paginated VRC list per member. Phase 4
//! M4.6.2. Spec §6.1 + §12.3. Signed document only
//! (`trust_tasks::member_tasks`); the bearer REST route it once also served
//! (`GET /v1/members/{did}/relationships`) had no caller once the admin
//! console moved onto the signed door, and was removed.
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

use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated};

use crate::acl::get_acl_entry;
use crate::error::TaskError;
use crate::members::get_member;
use crate::relationships::{Relationship, list_for_did};
use crate::server::AppState;

const MAX_LIMIT: usize = 200;

/// `vtc/relationships/list:notFound` — no member with the supplied DID.
pub const LIST_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::relationships::list::v0_2::error_codes::NOT_FOUND.code;

/// One page of `did`'s relationships — the operation behind the
/// `vtc/relationships/list/0.2` Trust Task. Who may read is the door's
/// decision; this validates the subject, resolves it (`notFound`) and
/// applies the §12.3 strip.
pub(crate) async fn list_inner(
    state: &AppState,
    did: &str,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> Result<Paginated<Relationship>, TaskError> {
    vti_common::identifier::validate_did("did", did)?;
    // `relationships/list:notFound` — no member with this DID. The same
    // predicate the strip below applies to the other party: a DID with neither
    // an ACL entry nor a member row (never admitted, or purged) is nobody
    // here. A departed member's tombstone still counts, and so does their
    // history. This used to answer an empty page, indistinguishable from a
    // member with no relationships.
    if get_acl_entry(&state.acl_ks, did).await?.is_none()
        && get_member(&state.members_ks, did).await?.is_none()
    {
        return Err(TaskError::declared(
            LIST_ERR_NOT_FOUND,
            AppError::NotFound(format!("member not found: {did}")),
        ));
    }
    let limit = limit.unwrap_or(50).clamp(1, MAX_LIMIT);
    let audit_key = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?
        .active_key()
        .await?;

    let cursor = cursor
        .map(|c| Cursor::decode(c, &audit_key.key))
        .transpose()
        .map_err(|e| AppError::Validation(format!("invalid cursor: {e}")))?;

    let page = list_for_did(
        &state.relationships_ks,
        &state.relationships_by_did_ks,
        &audit_key,
        did,
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

    Ok(Paginated {
        items: filtered,
        next_cursor: page.next_cursor,
        total_estimate: page.total_estimate,
    })
}
