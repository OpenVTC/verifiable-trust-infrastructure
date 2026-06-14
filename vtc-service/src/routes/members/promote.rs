//! `POST /v1/members/{did}/promote-to-admin/{start,finish}`
//! — M1.6.1.
//!
//! Two-phase step-up UV ceremony that authorises promoting an
//! existing member to `VtcRole::Admin`. Spec §10.4 keeps this
//! path distinct from the generic `PATCH /v1/members/{did}` so
//! admin elevation is the highest-privilege grant the community
//! emits and SIEM rules can target it via the `AdminPromoted`
//! audit variant.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use vti_common::audit::{AdminPromotedData, AuditEvent};
use vti_common::auth::passkey::PasskeyState;
use vti_common::auth::passkey::store::{
    get_passkey_user_by_did, store_auth_state, take_auth_state,
};

use crate::acl::admin::{AdminEntry, get_admin_entry, store_admin_entry};
use crate::acl::{VtcRole, get_acl_entry};
use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::members::get_member;
use crate::server::AppState;

/// Serialises every promote-to-admin write per-target so a
/// concurrent `PATCH /v1/members/{did}` racing the finish step
/// can't smuggle a role mutation in between the
/// already-admin check and the ACL write. Process-wide because
/// fjall isn't multi-process safe (project memory).
static PROMOTE_LOCK: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// /start
// ---------------------------------------------------------------------------

/// Returned by `start` — the operator's existing passkey is the
/// authoriser, so this is a UV authentication challenge against
/// the caller's already-registered credentials. The same shape
/// admin/passkeys/register/start uses for its UV phase.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PromoteStartResponse {
    pub registration_id: Uuid,
    #[schema(value_type = Object)]
    pub options: RequestChallengeResponse,
}

/// POST /members/{did}/promote-to-admin/start — begin step-up UV ceremony.
/// Auth: Admin.
#[utoipa::path(
    post, path = "/members/{did}/promote-to-admin/start", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID being promoted")),
    responses(
        (status = 200, description = "UV challenge issued", body = PromoteStartResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin / has no registered passkeys"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn promote_start(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(target_did): Path<String>,
) -> Result<Json<PromoteStartResponse>, AppError> {
    if auth.0.did == target_did {
        return Err(AppError::Validation(
            "you cannot promote yourself; the promotion endpoint requires a separate admin caller"
                .into(),
        ));
    }

    let webauthn = require_webauthn(&state)?;

    // Pre-flight: confirm the target is an existing member that
    // isn't already an admin. We re-check inside the finish
    // ceremony under the lock; the pre-flight here just avoids
    // running a UV ceremony that can never succeed.
    get_member(&state.members_ks, &target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;
    let target_acl = get_acl_entry(&state.acl_ks, &target_did)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("member not found (no ACL row): {target_did}"))
        })?;
    if matches!(target_acl.role, VtcRole::Admin) {
        return Err(AppError::Conflict(format!(
            "{target_did} is already an admin"
        )));
    }

    // Mint the UV challenge against the caller's registered
    // passkeys — same shape `admin/passkeys/register/start` uses
    // for its UV phase so the operator's authenticator UX is
    // identical.
    let pk_user = get_passkey_user_by_did(&state.passkey_ks, &auth.0.did)
        .await?
        .ok_or_else(|| {
            AppError::Forbidden(format!(
                "caller {} has no registered passkeys; cannot authorise step-up UV",
                auth.0.did
            ))
        })?;
    let (uv_options, uv_state) = webauthn
        .start_passkey_authentication(&pk_user.credentials)
        .map_err(|e| AppError::Internal(format!("webauthn UV start: {e}")))?;
    let registration_id = Uuid::new_v4();
    store_auth_state(&state.passkey_ks, &registration_id.to_string(), &uv_state).await?;

    Ok(Json(PromoteStartResponse {
        registration_id,
        options: uv_options,
    }))
}

// ---------------------------------------------------------------------------
// /finish
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PromoteFinishRequest {
    pub registration_id: Uuid,
    #[schema(value_type = Object)]
    pub uv_response: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PromoteFinishResponse {
    pub did: String,
    pub event_id: Uuid,
}

/// POST /members/{did}/promote-to-admin/finish — complete the promotion.
/// Auth: Admin.
#[utoipa::path(
    post, path = "/members/{did}/promote-to-admin/finish", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID being promoted")),
    request_body = PromoteFinishRequest,
    responses(
        (status = 200, description = "Member promoted to admin", body = PromoteFinishResponse),
        (status = 401, description = "Missing or invalid bearer token / step-up UV failed"),
        (status = 403, description = "Caller is not an admin / promotion denied by policy"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn promote_finish(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(target_did): Path<String>,
    Json(req): Json<PromoteFinishRequest>,
) -> Result<Json<PromoteFinishResponse>, AppError> {
    if auth.0.did == target_did {
        return Err(AppError::Validation("you cannot promote yourself".into()));
    }

    let webauthn = require_webauthn(&state)?;
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // 1. Verify the UV ceremony.
    let uv_state = take_auth_state(&state.passkey_ks, &req.registration_id.to_string())
        .await?
        .ok_or_else(|| AppError::Unauthorized("UV challenge not found or expired".into()))?;
    let uv_result = webauthn
        .finish_passkey_authentication(&req.uv_response, &uv_state)
        .map_err(|_| AppError::Unauthorized("step-up UV failed".into()))?;

    if !uv_result.user_verified() {
        return Err(AppError::Unauthorized(
            "passkey did not assert user verification (UV); cannot authorise admin promotion"
                .into(),
        ));
    }

    let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(uv_result.cred_id()));

    // 2. Critical section: re-check, then run the role-change ceremony.
    let _guard = PROMOTE_LOCK.lock().await;

    let target_acl = get_acl_entry(&state.acl_ks, &target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;
    get_member(&state.members_ks, &target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;

    if matches!(target_acl.role, VtcRole::Admin) {
        return Err(AppError::Conflict(format!(
            "{target_did} is already an admin"
        )));
    }

    // P0.14: route the actual promotion through the role-change ceremony so the
    // operator's `role_change.rego` — plus the host no-last-admin / step-up
    // invariants in the Remint executor — governs the community's
    // highest-privilege grant, instead of a bare ACL write that bypassed
    // policy entirely. The UV ceremony above is the verified step-up, so we
    // pass `step_up = true`: the default policy's "admin with a verified
    // step-up" branch allows, while a tightened policy (quorum/tenure) denies
    // → 403 even after a valid UV. Remint re-mints the role VEC at `admin` and
    // delivers it to the member's wallet.
    let granted = crate::routes::members::update::role_change_via_pipeline(
        &state,
        &auth.0.did,
        &target_did,
        &target_acl.role.to_string(),
        "admin",
        true,
    )
    .await?;

    // Create the admin sister record so the new admin can enrol a
    // device via the existing passkey flow. Empty passkey list
    // until `admin/passkeys/register` runs.
    let already_exists = get_admin_entry(&state.passkey_ks, &target_did)
        .await?
        .is_some();
    if !already_exists {
        store_admin_entry(
            &state.passkey_ks,
            &AdminEntry {
                did: target_did.clone(),
                passkeys: Vec::new(),
                extensions: serde_json::Value::Null,
                created_at: Utc::now(),
            },
        )
        .await?;
    }

    let envelope = audit_writer
        .write(
            &auth.0.did,
            Some(&target_did),
            AuditEvent::AdminPromoted(AdminPromotedData {
                previous_role: granted.previous_role,
                authorising_credential_id: cred_id_hex,
            }),
        )
        .await?;

    Ok(Json(PromoteFinishResponse {
        did: target_did,
        event_id: envelope.event_id,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_webauthn(state: &AppState) -> Result<Arc<Webauthn>, AppError> {
    state.webauthn().cloned().ok_or_else(|| {
        // No 503 variant on AppError — surface as Internal so the
        // operator sees the message verbatim. The actual HTTP
        // status mapping is fine: a missing public_url at runtime
        // is an internal configuration error.
        AppError::Internal(
            "webauthn not configured (public_url unset); promote-to-admin unavailable".into(),
        )
    })
}
