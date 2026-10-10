//! What "an active member" means for signing in to the member portal.

use vti_common::auth::session::now_epoch;

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry};
use crate::error::AppError;
use crate::members::{Member, get_member};
use crate::server::AppState;

/// A subject that may hold a member-portal session right now.
#[derive(Debug, Clone)]
pub struct ActiveMember {
    pub entry: VtcAclEntry,
    pub member: Member,
}

/// Read `did`'s live records and return them if `did` is an active member.
///
/// Active means all of:
///
/// - an ACL entry exists and has not expired;
/// - it is not suspended — a cooling-off reduction authorizes nothing until it
///   lands or is cancelled, and signing in is not an exception;
/// - it is not an `application` entry, which is not a membership and never
///   signs in (VTI-ACL-037);
/// - a member record exists and has not been removed (a tombstone is a record
///   of a *former* member).
///
/// The two records are 1:1 by DID, but either can be missing in a partial
/// state, and either missing is "not a member".
pub async fn active_member(state: &AppState, did: &str) -> Result<Option<ActiveMember>, AppError> {
    let Some(entry) = get_acl_entry(&state.acl_ks, did).await? else {
        return Ok(None);
    };
    if entry.is_expired(now_epoch()) || entry.is_suspended() || entry.role == VtcRole::Application {
        return Ok(None);
    }
    let Some(member) = get_member(&state.members_ks, did).await? else {
        return Ok(None);
    };
    if member.is_removed() {
        return Ok(None);
    }
    Ok(Some(ActiveMember { entry, member }))
}

/// [`active_member`], as a gate. One message for every reason: which of the
/// conditions failed is not the caller's to learn.
pub async fn require_active_member(state: &AppState, did: &str) -> Result<ActiveMember, AppError> {
    active_member(state, did)
        .await?
        .ok_or_else(|| AppError::Forbidden("not an active member of this community".into()))
}
