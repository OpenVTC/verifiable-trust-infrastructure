//! Members' step-up passkeys over REST — see [`crate::step_up_passkey`].
//!
//! - `POST /v1/admin/step-up-passkeys/invites` — `auth/passkey/enroll/invite/0.2`
//!   (`purpose: stepUp`). A community administrator, at a stepped-up session.
//! - `GET  /v1/admin/step-up-passkeys` — every member's step-up passkeys, or
//!   one member's (`?subject=`). A community administrator. No published task
//!   lists another subject's credentials, so this route carries no Trust-Task
//!   binding, like the console-key routes.
//! - `POST /v1/admin/step-up-passkeys/revoke/{start,finish}` —
//!   `auth/passkey/revoke/{start,finish}/0.2` with `subject`: an administrator
//!   revokes for the member, verifying with their own passkey.
//! - `POST /v1/step-up-passkeys/redeem/{start,finish}` —
//!   `auth/passkey/enroll/redeem/{start,finish}/0.1`. Unauthenticated: the
//!   invite token and the claim code are the authority, on the rate-limited
//!   chain.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::server::AppState;
use crate::step_up_passkey::{
    self, CredentialMeta, IssuedInvite, RedeemStarted, Redeemed, RevokeStarted, Revoked,
};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = StepUpPasskeyInviteRequest)]
pub struct InviteRequest {
    /// The member invited to enrol a step-up passkey.
    pub subject: String,
    /// `stepUp` — the only purpose this VTC issues by invite. Absent means
    /// `session` in the specification, which this VTC refuses.
    pub purpose: String,
    #[serde(default)]
    pub device_label: Option<String>,
    /// Seconds the invite stays redeemable (default 3600, at most 86400).
    #[serde(default)]
    pub ttl: Option<u64>,
}

#[utoipa::path(
    post, path = "/admin/step-up-passkeys/invites", tag = "admin",
    operation_id = "stepUpPasskeyInvite",
    security(("bearer_jwt" = [])),
    request_body = InviteRequest,
    responses(
        (status = 200, description = "The invite: the URL and, separately, the claim code — returned only here", body = IssuedInvite),
        (status = 403, description = "Not a community administrator, a self-invite, or the session is not stepped up"),
        (status = 404, description = "The subject is not a current member"),
    ),
)]
pub async fn invite(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<InviteRequest>,
) -> Result<Json<IssuedInvite>, AppError> {
    if req.purpose != "stepUp" {
        return Err(AppError::Forbidden(format!(
            "auth/passkey/enroll/invite:purposeNotSupported: this community issues only \
             step-up passkeys by invite (purpose `stepUp`), not `{}`",
            req.purpose
        )));
    }
    // Letting a member mint a second factor is an act of authority: it takes
    // the gesture of a stepped-up session, as widening an admin's does.
    if !crate::acl::elevation::verified(&admin.0, &state.sessions_ks).await {
        return Err(crate::acl::elevation::required(
            "inviting a member to enrol a step-up passkey",
        ));
    }
    Ok(Json(
        step_up_passkey::issue_invite(
            &state,
            &admin.0.did,
            &req.subject,
            req.device_label,
            req.ttl,
        )
        .await?,
    ))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    /// Only this member's step-up passkeys.
    pub subject: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = StepUpPasskeyList)]
pub struct StepUpPasskeyList {
    pub credentials: Vec<CredentialMeta>,
}

#[utoipa::path(
    get, path = "/admin/step-up-passkeys", tag = "admin",
    operation_id = "stepUpPasskeyList",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Members' step-up passkeys", body = StepUpPasskeyList),
        (status = 403, description = "Not a community administrator"),
    ),
)]
pub async fn list(
    admin: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<StepUpPasskeyList>, AppError> {
    if !crate::git_ns::ops::standing(&state, &admin.0.did)
        .await?
        .community_admin
    {
        return Err(AppError::Forbidden(
            "only a community administrator lists members' step-up passkeys".into(),
        ));
    }
    Ok(Json(StepUpPasskeyList {
        credentials: step_up_passkey::list(&state.step_up_passkeys_ks, q.subject.as_deref())
            .await?,
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = StepUpPasskeyRevokeStartRequest)]
pub struct RevokeStartRequest {
    pub credential_id: String,
    /// The member whose step-up passkey it is.
    pub subject: String,
}

#[utoipa::path(
    post, path = "/admin/step-up-passkeys/revoke/start", tag = "admin",
    operation_id = "stepUpPasskeyRevokeStart",
    security(("bearer_jwt" = [])),
    request_body = RevokeStartRequest,
    responses(
        (status = 200, description = "A user-verification ceremony over your own passkeys", body = RevokeStarted),
        (status = 403, description = "Not a community administrator, or no passkey of your own"),
        (status = 404, description = "No such step-up passkey for that member"),
    ),
)]
pub async fn revoke_start(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RevokeStartRequest>,
) -> Result<Json<RevokeStarted>, AppError> {
    Ok(Json(
        step_up_passkey::revoke_start(&state, &admin.0.did, &req.subject, &req.credential_id)
            .await?,
    ))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = StepUpPasskeyRevokeFinishRequest)]
pub struct RevokeFinishRequest {
    pub revocation_id: String,
    #[schema(value_type = Object)]
    pub uv_credential: PublicKeyCredential,
}

#[utoipa::path(
    post, path = "/admin/step-up-passkeys/revoke/finish", tag = "admin",
    operation_id = "stepUpPasskeyRevokeFinish",
    security(("bearer_jwt" = [])),
    request_body = RevokeFinishRequest,
    responses(
        (status = 200, description = "Revoked", body = Revoked),
        (status = 401, description = "Your passkey did not verify"),
        (status = 404, description = "No revocation in progress with this id"),
        (status = 410, description = "The revocation lapsed"),
    ),
)]
pub async fn revoke_finish(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RevokeFinishRequest>,
) -> Result<Json<Revoked>, AppError> {
    Ok(Json(
        step_up_passkey::revoke_finish(
            &state,
            &admin.0.did,
            &req.revocation_id,
            &req.uv_credential,
        )
        .await?,
    ))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = StepUpPasskeyRedeemStartRequest)]
pub struct RedeemStartRequest {
    pub token: String,
    pub claim_code: String,
}

#[utoipa::path(
    post, path = "/step-up-passkeys/redeem/start", tag = "auth",
    operation_id = "stepUpPasskeyRedeemStart",
    request_body = RedeemStartRequest,
    responses(
        (status = 200, description = "The registration the invite authorises", body = RedeemStarted),
        (status = 401, description = "The invite cannot be redeemed with that code"),
        (status = 403, description = "Too many wrong codes: the invite is invalidated"),
    ),
)]
pub async fn redeem_start(
    State(state): State<AppState>,
    Json(req): Json<RedeemStartRequest>,
) -> Result<Json<RedeemStarted>, AppError> {
    if req.token.len() > 512 || req.claim_code.len() > 64 {
        return Err(AppError::Validation("token or claim code too long".into()));
    }
    Ok(Json(
        step_up_passkey::redeem_start(&state, &req.token, &req.claim_code).await?,
    ))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = StepUpPasskeyRedeemFinishRequest)]
pub struct RedeemFinishRequest {
    pub enrollment_id: String,
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
    /// Required exactly when the start returned `uvOptions`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub uv_credential: Option<PublicKeyCredential>,
    #[serde(default)]
    pub device_label: Option<String>,
}

#[utoipa::path(
    post, path = "/step-up-passkeys/redeem/finish", tag = "auth",
    operation_id = "stepUpPasskeyRedeemFinish",
    request_body = RedeemFinishRequest,
    responses(
        (status = 200, description = "The step-up passkey is registered", body = Redeemed),
        (status = 401, description = "An assertion or the attestation did not verify"),
        (status = 404, description = "No redemption in progress, or its invite is gone"),
        (status = 410, description = "The redemption lapsed"),
    ),
)]
pub async fn redeem_finish(
    State(state): State<AppState>,
    Json(req): Json<RedeemFinishRequest>,
) -> Result<Json<Redeemed>, AppError> {
    Ok(Json(
        step_up_passkey::redeem_finish(
            &state,
            &req.enrollment_id,
            &req.credential,
            req.uv_credential.as_ref(),
            req.device_label,
        )
        .await?,
    ))
}
