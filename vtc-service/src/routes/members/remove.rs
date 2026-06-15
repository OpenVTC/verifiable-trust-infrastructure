//! `DELETE /v1/members/me` (M1.11.1) + `DELETE /v1/members/{did}`
//! (M1.12.1) — the **leave ceremony**.
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

use crate::auth::{AdminAuth, AuthClaims};
use crate::ceremony::{LeaveOutcome, remove_inner};
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
// DELETE /v1/members/me — M1.11.1
// ---------------------------------------------------------------------------

/// DELETE /members/me — self-leave ceremony. Auth: any authenticated member.
#[utoipa::path(
    delete, path = "/members/me", tag = "members",
    security(("bearer_jwt" = [])),
    request_body = RemoveBody,
    responses(
        (status = 200, description = "Member removed", body = RemoveResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Removal denied by policy"),
    ),
)]
pub async fn self_remove(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: Option<Json<RemoveBody>>,
) -> Result<(StatusCode, Json<RemoveResponse>), AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let target_did = auth.did.clone();
    // Self-leave: actor == subject. The decision policy allows this
    // unconditionally (it sees `actor.did == subject.did`); the
    // no-last-admin invariant still applies in the effect stage.
    let outcome = remove_inner(
        &state,
        &auth.did,
        &target_did,
        body.disposition,
        // Self-remove ignores any caller-supplied reason — the
        // departure is the member's own decision and doesn't carry
        // an externally-meaningful justification field.
        String::new(),
    )
    .await?;
    Ok((StatusCode::OK, Json(RemoveResponse::from(outcome))))
}

// ---------------------------------------------------------------------------
// DELETE /v1/members/{did} — M1.12.1 (REST only)
// ---------------------------------------------------------------------------

/// DELETE /members/{did} — admin removes another member. Auth: Admin.
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
) -> Result<(StatusCode, Json<RemoveResponse>), AppError> {
    vti_common::identifier::validate_did("did", &target_did)?;
    if admin.0.did == target_did {
        return Err(AppError::Validation(
            "use DELETE /v1/members/me to remove yourself — \
             DELETE /v1/members/{did} is for admins removing other members"
                .to_string(),
        ));
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let reason = body.reason.unwrap_or_default();
    if reason.len() > REASON_MAX {
        return Err(AppError::Validation(format!(
            "reason exceeds {REASON_MAX} chars (got {})",
            reason.len(),
        )));
    }
    let outcome = remove_inner(&state, &admin.0.did, &target_did, body.disposition, reason).await?;
    Ok((StatusCode::OK, Json(RemoveResponse::from(outcome))))
}
