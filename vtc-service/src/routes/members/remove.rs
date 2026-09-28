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

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use vti_common::error::AppError;

use crate::auth::AdminAuth;
use crate::ceremony::{LeaveOutcome, remove_inner};
use crate::error::TaskError;
use crate::members::Disposition;
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
/// Both doors call this: the bearer REST route below, and the signed-document
/// arm in [`crate::trust_tasks`] (#1641 phase 2). Every check the REST route
/// used to make inline is here, so neither door can lose one: the DID is well
/// formed, an admin does not remove themselves through the admin verb, and the
/// operator `reason` is capped.
pub(crate) async fn admin_remove_inner(
    state: &AppState,
    actor_did: &str,
    target_did: &str,
    body: RemoveBody,
) -> Result<LeaveOutcome, TaskError> {
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
    remove_inner(state, actor_did, target_did, body.disposition, reason).await
}

/// DELETE /members/{did} — admin removes another member. Auth: Admin.
///
/// **Transitional bearer-token path (#1641).** `vtc/members/admin-remove/0.1`
/// declares `proof` REQUIRED, and the authoritative binding is the signed
/// Trust Task document at `POST /v1/trust-tasks`, where the proof authenticates
/// the administrator and their authority is read from their ACL entry. This
/// route authenticates by bearer JWT and verifies no document proof; it is kept
/// only until the admin console can sign a Trust Task document, and is removed
/// in the same change that gives it that.
#[utoipa::path(
    delete, path = "/members/{did}", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    request_body = RemoveBody,
    responses(
        (status = 200, description = "Member removed", body = RemoveResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin / removal denied by policy"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn admin_remove(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(target_did): Path<String>,
    body: Option<Json<RemoveBody>>,
) -> Result<(StatusCode, Json<RemoveResponse>), TaskError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let outcome = admin_remove_inner(&state, &admin.0.did, &target_did, body).await?;
    Ok((StatusCode::OK, Json(RemoveResponse::from(outcome))))
}

// ---------------------------------------------------------------------------
// DELETE /v1/members/{did}/purge — forceful cleanup (super-admin)
// ---------------------------------------------------------------------------
