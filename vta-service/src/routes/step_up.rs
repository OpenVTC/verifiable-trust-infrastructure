//! REST surface for step-up **policy** management.
//!
//! - `GET /step-up/policy` — read the maintainer's current (effective) policy
//!   (any manage-level caller, so operators can inspect posture).
//! - `PUT /step-up/policy` — set the policy (super-admin only).
//!
//! Both reuse [`crate::operations::step_up_policy`], so the REST and the
//! `auth/step-up/policy/0.2` trust-task wire forms agree on validation,
//! canonicalization, persistence, and response shape. This convenience path is
//! what the SDK / `pnm` use; DIDComm / Trust-Task clients use the dispatched
//! trust-task instead.

use axum::Json;
use axum::extract::State;
use serde_json::Value;

use vti_common::auth::extractor::{ManageAuth, SuperAdminAuth};
use vti_common::error::AppError;

use crate::operations::step_up_policy::{
    SetPolicyError, effective_response, policy_from_value, set_step_up_policy,
};
use crate::server::AppState;

/// GET /step-up/policy — read the current effective step-up policy.
#[utoipa::path(
    get, path = "/step-up/policy", tag = "step-up",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Current effective step-up policy", body = serde_json::Value),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks manage-level access"),
    ),
)]
pub async fn get_step_up_policy(
    _auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let policy = state.config.read().await.auth.step_up.clone();
    Ok(Json(effective_response(&policy)))
}

/// PUT /step-up/policy — set the step-up policy (super-admin). Body is the
/// `0.2` policy payload shape (`{ enabled, floors: [...] }`).
#[utoipa::path(
    put, path = "/step-up/policy", tag = "step-up",
    security(("bearer_jwt" = [])),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Updated effective step-up policy", body = serde_json::Value),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn put_step_up_policy(
    _auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let requested = policy_from_value(&body).map_err(AppError::Validation)?;
    let effective = set_step_up_policy(&state.config, &state.acl_ks, requested)
        .await
        .map_err(set_policy_error_to_app)?;
    Ok(Json(effective_response(&effective)))
}

/// Map a policy-set failure onto the HTTP error surface:
/// `unknownOperation` → 400, `lockoutRefused` → 409, store/persist → 500.
fn set_policy_error_to_app(e: SetPolicyError) -> AppError {
    match e {
        SetPolicyError::UnknownOperation(op) => AppError::Validation(format!(
            "unknown operation-class '{op}' (not a gated op or '*')"
        )),
        SetPolicyError::LockoutRefused(msg) => AppError::Conflict(msg),
        SetPolicyError::Store(m) | SetPolicyError::Persistence(m) => AppError::Config(m),
    }
}
