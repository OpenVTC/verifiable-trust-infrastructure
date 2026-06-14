//! REST routes for passkey-as-verificationMethod enrolment.
//!
//! Mounted at:
//!
//! - `POST /did/verification-methods/passkey/challenge`
//! - `POST /did/verification-methods/passkey`
//! - `GET  /did/verification-methods/passkey?did=…`
//! - `DELETE /did/verification-methods/passkey/{fragment}?did=…`
//!
//! All gated by [`AdminAuth`]. Per-DID context membership is asserted
//! inside the operations layer.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use vta_sdk::protocols::did_management::passkey_vms::{
    EnrollPasskeyChallengeResponse, EnrollPasskeySubmitBody, EnrollPasskeySubmitResponse,
    ListPasskeyVmsResponse,
};

use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

/// Runtime gate: refuse every passkey-VM management call when the
/// WebAuthn-RP service is disabled. Without the service entry
/// advertising the RP, any newly-enrolled VM would point at an
/// unreachable surface; refuse rather than persist orphan state.
///
/// Returns `Forbidden` (rather than `Unauthorized`) because the
/// problem is service config, not caller credentials.
async fn ensure_webauthn_enabled(state: &AppState) -> Result<(), AppError> {
    if !state.config.read().await.services.webauthn {
        return Err(AppError::Forbidden(
            "WebAuthn service is disabled on this VTA. Operator: enable with \
             `pnm services webauthn enable --url <url>`."
                .into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PasskeyVmDidQuery {
    pub did: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct EnrollPasskeyChallengeBody {
    pub did: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// POST /did/verification-methods/passkey/challenge — begin passkey-VM enrolment. Auth: admin.
#[utoipa::path(
    post, path = "/did/verification-methods/passkey/challenge", tag = "passkey-vms",
    security(("bearer_jwt" = [])),
    request_body = EnrollPasskeyChallengeBody,
    responses(
        (status = 200, description = "Enrolment challenge", body = EnrollPasskeyChallengeResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin, or WebAuthn is disabled"),
    ),
)]
pub async fn enroll_challenge_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<EnrollPasskeyChallengeBody>,
) -> Result<Json<EnrollPasskeyChallengeResponse>, AppError> {
    ensure_webauthn_enabled(&state).await?;
    let config = state.config.read().await;
    let result = operations::passkey_vms::start_enrollment(
        &state.webvh_ks,
        &state.passkey_vms_ks,
        &config,
        &auth.0,
        &body.did,
        body.label,
    )
    .await?;
    Ok(Json(result))
}

/// POST /did/verification-methods/passkey — finish passkey-VM enrolment. Auth: admin.
#[utoipa::path(
    post, path = "/did/verification-methods/passkey", tag = "passkey-vms",
    security(("bearer_jwt" = [])),
    request_body = EnrollPasskeySubmitBody,
    responses(
        (status = 200, description = "Passkey enrolled", body = EnrollPasskeySubmitResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin, or WebAuthn is disabled"),
    ),
)]
pub async fn enroll_submit_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<EnrollPasskeySubmitBody>,
) -> Result<Json<EnrollPasskeySubmitResponse>, AppError> {
    ensure_webauthn_enabled(&state).await?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let config = state.config.read().await.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::passkey_vms::finish_enrollment(
        &deps,
        &state.passkey_vms_ks,
        &auth.0,
        body,
        vta_did.as_deref(),
        &config,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// GET /did/verification-methods/passkey — list a DID's passkey VMs. Auth: admin.
#[utoipa::path(
    get, path = "/did/verification-methods/passkey", tag = "passkey-vms",
    security(("bearer_jwt" = [])),
    params(PasskeyVmDidQuery),
    responses(
        (status = 200, description = "Passkey verification methods", body = ListPasskeyVmsResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_passkeys_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<PasskeyVmDidQuery>,
) -> Result<Json<ListPasskeyVmsResponse>, AppError> {
    let result = operations::passkey_vms::list_passkeys(&state.webvh_ks, &auth.0, &q.did).await?;
    Ok(Json(result))
}

/// DELETE /did/verification-methods/passkey/{fragment} — revoke a passkey VM. Auth: admin.
#[utoipa::path(
    delete, path = "/did/verification-methods/passkey/{fragment}", tag = "passkey-vms",
    security(("bearer_jwt" = [])),
    params(
        ("fragment" = String, Path, description = "Verification-method fragment"),
        PasskeyVmDidQuery,
    ),
    responses(
        (status = 204, description = "Passkey revoked"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "Passkey VM not found"),
    ),
)]
pub async fn revoke_passkey_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(fragment): Path<String>,
    Query(q): Query<PasskeyVmDidQuery>,
) -> Result<StatusCode, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    operations::passkey_vms::revoke_passkey(
        &deps,
        &auth.0,
        &q.did,
        &fragment,
        vta_did.as_deref(),
        "rest",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
