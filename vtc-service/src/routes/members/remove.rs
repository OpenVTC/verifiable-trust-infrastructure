//! A member's own departure (`vtc/members/self-remove/0.1`, M1.11.1 — a
//! signed document only) and an administrator's removal of another
//! (`vtc/members/admin-remove/0.1`, M1.12.1) — the **leave ceremony**.
//!
//! Both paths converge on `remove_inner`, which is the leave instance
//! of the ceremony decision pipeline ([`crate::ceremony`]):
//!
//! 1. **Facts** — `assemble_leave_facts` reads the actor's + subject's
//!    community roles into a purpose-`leave` [`Facts`] (`actor` may
//!    differ from `subject`: an admin removing a member, or a member
//!    removing themselves).
//! 2. **Decide** — the active `removal`-purpose decision policy
//!    (`data.vtc.removal.decision`) returns allow/deny. The default
//!    policy allows self-leave unconditionally and an admin removing a
//!    non-admin; it denies removing an admin.
//! 3. **Effect** — the verdict is applied by the effect executor
//!    ([`execute::apply`] with [`EffectPlan::Depart`]), which owns the
//!    no-last-admin invariant (→ 409, host-enforced), the ACL/Member
//!    deletion + disposition, and the credential revocation.
//!
//! Disposition precedence (resolved here, around the decision): the
//! caller's explicit request wins, then the member's
//! `departure_preference`, then the policy's chosen disposition, then
//! `tombstone`.

use serde::{Deserialize, Serialize};

use vti_common::error::AppError;

use crate::acl::admin_consent::Operation;
use crate::acl::get_acl_entry;
use crate::auth::AuthClaims;

use crate::ceremony::{LeaveOutcome, remove_inner};
use crate::error::TaskError;
use crate::members::Disposition;
use crate::routes::acl::caller_covers_target;
use crate::server::AppState;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RemoveBody {
    #[serde(default)]
    pub disposition: Option<Disposition>,
    /// Optional admin-only reason. Self-remove ignores this (the
    /// member doesn't need to justify their own departure). Capped
    /// at 1024 chars at the route layer.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RemoveResponse {
    pub did: String,
    pub disposition: String,
    pub removed: bool,
}

impl From<LeaveOutcome> for RemoveResponse {
    fn from(o: LeaveOutcome) -> Self {
        Self {
            did: o.did,
            disposition: o.disposition,
            removed: o.removed,
        }
    }
}

const REASON_MAX: usize = 1024;

// ---------------------------------------------------------------------------
// vtc/members/admin-remove — M1.12.1
// ---------------------------------------------------------------------------

/// Apply one `vtc/members/admin-remove/0.1` on behalf of `actor_did` — the
/// whole of the operation, with no transport in it.
///
/// The signed-document arm in [`crate::trust_tasks`] (#1641 phase 2) calls
/// this, on every transport. Every check is here: the DID is well formed, an
/// admin does not remove themselves through the admin verb, the operator
/// `reason` is capped, and the subject's entry is one the actor administers in
/// full.
///
/// The cover check is `acl/revoke`'s (VTI-ACL-050): an administrator of `a`
/// may not remove a subject who also acts in `b`, and only an unrestricted
/// administrator may remove an unrestricted one. Without it this verb relied
/// entirely on the editable removal policy (`vtc-action-list.md` §8.1, hole 3).
/// An entry the actor cannot see at all answers as absent, so the refusal is no
/// oracle.
///
/// `op` is this document's type and payload, which removing an administrator
/// binds its gesture and consent to (VTI-APV-019).
pub(crate) async fn admin_remove_inner(
    state: &AppState,
    actor: &AuthClaims,
    target_did: &str,
    body: RemoveBody,
    op: Operation<'_>,
) -> Result<LeaveOutcome, TaskError> {
    let actor_did = actor.did.as_str();
    vti_common::identifier::validate_did("did", target_did)?;
    if actor_did == target_did {
        return Err(AppError::Validation(
            "use vtc/members/self-remove to remove yourself — \
             vtc/members/admin-remove is for admins removing other members"
                .to_string(),
        )
        .into());
    }
    let reason = body.reason.unwrap_or_default();
    if reason.len() > REASON_MAX {
        return Err(AppError::Validation(format!(
            "reason exceeds {REASON_MAX} chars (got {})",
            reason.len(),
        ))
        .into());
    }
    // Removing a member is `vtc.members.manage` (checked by the door). Removing
    // an **administrator** also takes its administrative authority away, which
    // only an administrator whose entry covers it may do (VTI-ACL-050).
    if let Some(entry) = get_acl_entry(&state.acl_ks, target_did).await?
        && entry.is_administrator()
        && !caller_covers_target(state, actor_did, &entry).await?
    {
        return Err(AppError::Forbidden(format!(
            "{target_did} is an administrator holding authority outside yours — only an \
             administrator holding vtc.roles.assign over everything it holds can remove it \
             (VTI-ACL-050)"
        ))
        .into());
    }
    remove_inner(
        state,
        actor_did,
        target_did,
        body.disposition,
        reason,
        Some(op),
    )
    .await
}

// ---------------------------------------------------------------------------
// DELETE /v1/members/{did}/purge — forceful cleanup (super-admin)
// ---------------------------------------------------------------------------
