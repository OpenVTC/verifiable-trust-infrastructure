//! `/v1/admin/passkeys/*` — admin multi-passkey management.
//!
//! Implements **M0.6.3** of the VTC MVP Phase 0 plan (spec §4.3).
//! Every mutation requires a **fresh WebAuthn user-verification
//! ceremony in the same request** on top of the bearer-token auth
//! gate — a stolen session can't persist by binding a new
//! authenticator. The fresh-UV check is implemented as a two-phase
//! ceremony (start returns the UV challenge, finish supplies the
//! UV assertion), mirroring the install-claim pattern.
//!
//! ## Endpoints
//!
//! - `GET  /v1/admin/passkeys` — list (no step-up; reads are safe).
//! - `POST /v1/admin/passkeys/register/start` — initiates dual
//!   ceremonies: a new-device registration challenge **and** a
//!   UV authentication challenge against existing credentials.
//! - `POST /v1/admin/passkeys/register/finish` — verifies both
//!   responses, persists the new credential, emits
//!   `AdminPasskeyRegistered`.
//! - `POST /v1/admin/passkeys/revoke/start` — issues a UV challenge
//!   against existing credentials.
//! - `POST /v1/admin/passkeys/revoke/finish` — verifies UV, removes
//!   the target credential under the last-passkey CAS guard, emits
//!   `AdminPasskeyRevoked`.
//!
//! ## Concurrency invariant
//!
//! All mutations serialise through [`ADMIN_PASSKEY_LOCK`] so the
//! "refuses to leave zero passkeys" check and the matching write
//! happen atomically. Without it two concurrent revokes can both
//! pass the >1 check and both remove a passkey.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;
use vti_common::audit::{AdminPasskeyData, AuditEvent, AuditWriter};
use vti_common::auth::AdminAuth;
use vti_common::auth::passkey::store::{
    get_passkey_user_by_did, store_auth_state, store_credential_mapping, store_passkey_user,
    store_registration_state, take_auth_state, take_registration_state,
};
use vti_common::error::AppError;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn};

use crate::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
use crate::server::AppState;
use crate::webauthn::{finish_passkey_registration, start_passkey_registration};

/// Serialises every passkey mutation per admin DID (in practice
/// per-process since there's only one VTC). The last-passkey CAS
/// check + matching write must be one critical section; without
/// this two concurrent revokes can race past `passkeys.len() > 1`
/// and both succeed.
static ADMIN_PASSKEY_LOCK: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ListResponse {
    /// `credentials`, the name `auth/passkey/list/0.1` publishes. It was
    /// `passkeys` until #1112 — the same object under a name the schema does
    /// not define, so no conforming client could find it.
    pub credentials: Vec<RegisteredCredential>,
}

/// The wire view of a passkey, as `auth/passkey/list/0.1` publishes it.
///
/// Separate from [`RegisteredPasskey`] because that type is a **storage row**:
/// it is `Deserialize`d out of the `admin:<did>` record, so its member names
/// are the on-disk format and renaming them would orphan every passkey already
/// enrolled. The two shapes disagree in exactly the two ways the schema cares
/// about, and both differences are the storage row's to keep:
///
/// - `label` is published as `deviceLabel`, and is **absent** rather than empty
///   when nobody chose one. The schema is explicit that a consumer must not
///   synthesize a label, "because an invented one is indistinguishable from a
///   chosen one to somebody deciding which credential to revoke" — and `""` is
///   an invented one.
/// - `lastUsedAt` is omitted when unset. Sending `null` is a type error against
///   a `date-time` member, and the schema notes it deliberately does not
///   distinguish "never used" from "not tracked", since no binding could carry
///   the difference anyway.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisteredCredential {
    pub credential_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    pub transports: Vec<String>,
    pub registered_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<&RegisteredPasskey> for RegisteredCredential {
    fn from(p: &RegisteredPasskey) -> Self {
        Self {
            credential_id: p.credential_id.clone(),
            device_label: (!p.label.is_empty()).then(|| p.label.clone()),
            transports: p.transports.clone(),
            registered_at: p.registered_at,
            last_used_at: p.last_used_at,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisterStartResponse {
    /// Opaque id the operator passes back to `enroll/finish`.
    ///
    /// `enrollmentId`, the name the task publishes — it was `registrationId`
    /// until #1112.
    pub enrollment_id: String,
    /// The value for `navigator.credentials.create({ publicKey: … })`.
    ///
    /// The **inner** options, not webauthn-rs's `{publicKey: …}` wrapper.
    /// `CredentialCreationOptions` in the published schema describes itself as
    /// "server-issued options for `navigator.credentials.create({ publicKey:
    /// ... })`" — the value that goes *inside* the key, not the object
    /// containing it.
    ///
    /// The wrapper was pure ceremony: the admin SPA unwrapped it with
    /// `start.registerOptions.publicKey` and immediately re-wrapped it as
    /// `create({ publicKey: … })`. Sending the inner object means the client
    /// writes `create({ publicKey: start.options })` and nothing is undone on
    /// the way.
    #[schema(value_type = Object)]
    pub options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
    /// The value for `navigator.credentials.get({ publicKey: … })` for the
    /// step-up assertion against an existing passkey. Unwrapped for the same
    /// reason as `options`.
    #[schema(value_type = Object)]
    pub uv_options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterFinishRequest {
    pub registration_id: String,
    #[schema(value_type = Object)]
    pub register_response: RegisterPublicKeyCredential,
    #[schema(value_type = Object)]
    pub uv_response: PublicKeyCredential,
    /// Operator-supplied label (e.g. `"YubiKey 5C"`).
    pub label: String,
    #[serde(default)]
    pub transports: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisterFinishResponse {
    pub credential_id: String,
    /// The DID this passkey now authenticates.
    ///
    /// Required by `auth/passkey/enroll/finish/0.2` and absent until #1112.
    /// A caller enrolling on behalf of someone else had no way to confirm
    /// *whose* credential it just created — the response named the credential
    /// and not the subject, which is the half that matters for an audit trail.
    pub subject: String,
    /// When the credential was registered. Required by the task, and the same
    /// instant recorded on the stored `RegisteredPasskey`, so a client need
    /// not re-list to learn it.
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RevokeStartRequest {
    pub credential_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeStartResponse {
    pub revocation_id: String,
    #[schema(value_type = Object)]
    /// Unwrapped, as everywhere else in this family — the value for
    /// `navigator.credentials.get({ publicKey: … })`.
    #[schema(value_type = Object)]
    pub uv_options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RevokeFinishRequest {
    pub revocation_id: String,
    #[schema(value_type = Object)]
    pub uv_response: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeFinishResponse {
    pub credential_id: String,
    /// When the credential was revoked.
    pub revoked_at: DateTime<Utc>,
    /// How many passkeys the subject has left.
    ///
    /// Required by `auth/passkey/revoke/finish/0.1` and absent until #1112.
    /// It is the number the caller most needs and the one this endpoint is
    /// uniquely placed to give: the last-passkey guard refuses to leave an
    /// admin at zero, so a client that cannot see the count cannot tell
    /// whether the next revoke will succeed without attempting it.
    pub remaining: usize,
}

// ---------------------------------------------------------------------------
// Storage key helpers
// ---------------------------------------------------------------------------

fn revoke_target_key(revocation_id: &str) -> Vec<u8> {
    format!("revoke_target:{revocation_id}").into_bytes()
}

// ---------------------------------------------------------------------------
// GET list
// ---------------------------------------------------------------------------

#[utoipa::path(
    get, path = "/admin/passkeys",
    operation_id = "adminPasskeyList", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Registered admin passkeys; empty when the                                       caller has enrolled none", body = ListResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list(
    admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ListResponse>, AppError> {
    // No `AdminEntry` means the caller has enrolled no passkeys — an empty
    // collection, not a missing one, so it answers 200 with an empty list.
    //
    // It returned 404 until an operator hit it: an admin who signs in with
    // their VTA wallet (SIOP, `/auth/admin-session`) holds an ACL entry and no
    // passkey enrolment, which is a perfectly ordinary state and the *first*
    // thing such an operator sees on this page. The console rendered the 404 as
    // "FAILED TO LOAD PASSKEYS" directly above its own, correct, "No passkeys
    // registered" empty state — the page contradicting itself about whether
    // anything had gone wrong.
    //
    // 404 is right for `revoke`, which names a credential that must exist.
    // It was never right here.
    let entry = get_admin_entry(&state.passkey_ks, &admin.0.did).await?;
    Ok(Json(ListResponse {
        credentials: entry
            .iter()
            .flat_map(|e| e.passkeys.iter())
            .map(Into::into)
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Register start + finish
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/admin/passkeys/register/start", tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "New-device registration + step-up UV challenges", body = RegisterStartResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "No passkey user for caller"),
    ),
)]
pub async fn register_start(
    admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RegisterStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let did = admin.0.did;

    let pk_user = get_passkey_user_by_did(&state.passkey_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound("no passkey user for caller".into()))?;

    // Step-up UV: ask any existing credential to sign a challenge.
    // `start_passkey_authentication` errors if there are no credentials,
    // which can only happen if the admin entry got out of sync with the
    // PasskeyUser — we surface that as an internal error.
    let (uv_options, uv_state) = webauthn
        .start_passkey_authentication(&pk_user.credentials)
        .map_err(|e| AppError::Internal(format!("webauthn UV start failed: {e}")))?;

    let exclude: Vec<_> = pk_user
        .credentials
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();
    let user_uuid = pk_user.user_uuid;
    let (register_options, reg_state) =
        start_passkey_registration(webauthn, user_uuid, &did, &did, Some(exclude))?;

    let registration_id = Uuid::new_v4().to_string();
    store_registration_state(&state.passkey_ks, &registration_id, &reg_state).await?;
    store_auth_state(&state.passkey_ks, &registration_id, &uv_state).await?;

    info!(%did, %registration_id, "passkey register ceremony started");

    Ok(Json(RegisterStartResponse {
        enrollment_id: registration_id,
        options: register_options.public_key,
        uv_options: uv_options.public_key,
    }))
}

#[utoipa::path(
    post, path = "/admin/passkeys/register/finish", tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = RegisterFinishRequest,
    responses(
        (status = 200, description = "New passkey registered", body = RegisterFinishResponse),
        (status = 401, description = "Missing/invalid bearer token, or step-up UV failed"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn register_finish(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<(StatusCode, Json<RegisterFinishResponse>), AppError> {
    let webauthn = require_webauthn(&state)?;
    let audit_writer = require_audit_writer(&state)?;
    let did = admin.0.did;

    let _guard = ADMIN_PASSKEY_LOCK.lock().await;

    // Take UV state first. A failed UV must NOT consume the
    // registration state — the legitimate operator should be able to
    // retry. The take-then-restore pattern from `webvh-common` (defer
    // the registration-state take until UV verifies) achieves this.
    let uv_state = take_auth_state(&state.passkey_ks, &req.registration_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("no UV challenge in progress".into()))?;
    webauthn
        .finish_passkey_authentication(&req.uv_response, &uv_state)
        .map_err(|_| AppError::Unauthorized("step-up UV failed".into()))?;

    let reg_state = take_registration_state(&state.passkey_ks, &req.registration_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("no registration in progress".into()))?;
    let new_passkey = finish_passkey_registration(webauthn, &req.register_response, &reg_state)?;

    let new_cred_id_hex = passkey_cred_id_hex(&new_passkey);

    // Append the credential to the PasskeyUser used by login.
    let mut pk_user = get_passkey_user_by_did(&state.passkey_ks, &did)
        .await?
        .ok_or_else(|| AppError::Internal("PasskeyUser missing for admin".into()))?;
    pk_user.credentials.push(new_passkey);
    store_passkey_user(&state.passkey_ks, &pk_user).await?;
    store_credential_mapping(&state.passkey_ks, &new_cred_id_hex, pk_user.user_uuid).await?;

    // Mirror into the AdminEntry sister record so the list endpoint
    // can serve operator-friendly metadata without walking the
    // `webauthn-rs` credential blob.
    let mut admin_entry = get_admin_entry(&state.passkey_ks, &did)
        .await?
        .unwrap_or_else(|| AdminEntry::new(did.clone()));
    let registered_at = Utc::now();
    admin_entry.passkeys.push(RegisteredPasskey {
        credential_id: new_cred_id_hex.clone(),
        label: req.label.clone(),
        transports: req.transports.clone(),
        registered_at,
        last_used_at: None,
    });
    store_admin_entry(&state.passkey_ks, &admin_entry).await?;

    audit_writer
        .write(
            &did,
            None,
            AuditEvent::AdminPasskeyRegistered(AdminPasskeyData {
                credential_id_hex: new_cred_id_hex.clone(),
                label: req.label,
                transports: req.transports,
            }),
        )
        .await?;

    info!(%did, credential_id = %new_cred_id_hex, "passkey registered");

    Ok((
        StatusCode::OK,
        Json(RegisterFinishResponse {
            credential_id: new_cred_id_hex,
            subject: did.clone(),
            registered_at,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Revoke start + finish
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/admin/passkeys/revoke/start", tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = RevokeStartRequest,
    responses(
        (status = 200, description = "Step-up UV challenge for the revocation", body = RevokeStartResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "credential_id not registered for this admin"),
    ),
)]
pub async fn revoke_start(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RevokeStartRequest>,
) -> Result<Json<RevokeStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let did = admin.0.did;

    let admin_entry = get_admin_entry(&state.passkey_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound("no admin entry for caller".into()))?;
    if !admin_entry
        .passkeys
        .iter()
        .any(|p| p.credential_id == req.credential_id)
    {
        return Err(AppError::NotFound(
            "credential_id is not registered for this admin".into(),
        ));
    }

    let pk_user = get_passkey_user_by_did(&state.passkey_ks, &did)
        .await?
        .ok_or_else(|| AppError::Internal("PasskeyUser missing for admin".into()))?;
    let (uv_options, uv_state) = webauthn
        .start_passkey_authentication(&pk_user.credentials)
        .map_err(|e| AppError::Internal(format!("webauthn UV start failed: {e}")))?;

    let revocation_id = Uuid::new_v4().to_string();
    store_auth_state(&state.passkey_ks, &revocation_id, &uv_state).await?;
    // Pin the target credential to the revocation id so finish can
    // verify the operator didn't substitute a different credential
    // after seeing the UV challenge.
    state
        .passkey_ks
        .insert_raw(
            revoke_target_key(&revocation_id),
            req.credential_id.into_bytes(),
        )
        .await?;

    info!(%did, %revocation_id, "passkey revoke ceremony started");

    Ok(Json(RevokeStartResponse {
        revocation_id,
        uv_options: uv_options.public_key,
    }))
}

#[utoipa::path(
    post, path = "/admin/passkeys/revoke/finish", tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = RevokeFinishRequest,
    responses(
        (status = 200, description = "Passkey revoked", body = RevokeFinishResponse),
        (status = 401, description = "Missing/invalid bearer token, or step-up UV failed"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "credential_id not registered for this admin"),
        (status = 409, description = "Refusing to leave the admin with zero passkeys"),
    ),
)]
pub async fn revoke_finish(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RevokeFinishRequest>,
) -> Result<Json<RevokeFinishResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let audit_writer = require_audit_writer(&state)?;
    let did = admin.0.did;

    let _guard = ADMIN_PASSKEY_LOCK.lock().await;

    // Take UV state. As with register/finish, a failed UV leaves the
    // pinned target intact so the legitimate operator can retry.
    let uv_state = take_auth_state(&state.passkey_ks, &req.revocation_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("no revoke ceremony in progress".into()))?;
    webauthn
        .finish_passkey_authentication(&req.uv_response, &uv_state)
        .map_err(|_| AppError::Unauthorized("step-up UV failed".into()))?;

    let target_bytes = state
        .passkey_ks
        .get_raw(revoke_target_key(&req.revocation_id))
        .await?
        .ok_or_else(|| AppError::Internal("revocation target missing".into()))?;
    let target_cred_id = String::from_utf8(target_bytes)
        .map_err(|_| AppError::Internal("revocation target malformed".into()))?;
    state
        .passkey_ks
        .remove(revoke_target_key(&req.revocation_id))
        .await?;

    let mut admin_entry = get_admin_entry(&state.passkey_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound("no admin entry for caller".into()))?;

    let before = admin_entry.passkeys.len();
    let revoked = admin_entry
        .passkeys
        .iter()
        .find(|p| p.credential_id == target_cred_id)
        .cloned()
        .ok_or_else(|| {
            AppError::NotFound("credential_id is not registered for this admin".into())
        })?;

    // **Last-passkey CAS guard.** Refuse if this revoke would leave
    // the admin with zero passkeys. Inside the lock so two concurrent
    // revokes can't both pass the > 1 check.
    if before <= 1 {
        return Err(AppError::Conflict(
            "LastPasskeyProtected: refusing to leave admin with zero passkeys".into(),
        ));
    }

    admin_entry
        .passkeys
        .retain(|p| p.credential_id != target_cred_id);
    store_admin_entry(&state.passkey_ks, &admin_entry).await?;

    // Mirror the removal into the PasskeyUser used by login. The
    // credential id on `webauthn-rs`'s `Passkey` is the raw byte
    // form; compare hex-encoded.
    let mut pk_user = get_passkey_user_by_did(&state.passkey_ks, &did)
        .await?
        .ok_or_else(|| AppError::Internal("PasskeyUser missing for admin".into()))?;
    pk_user
        .credentials
        .retain(|p| passkey_cred_id_hex(p) != target_cred_id);
    store_passkey_user(&state.passkey_ks, &pk_user).await?;
    state
        .passkey_ks
        .remove(format!("pk_cred:{target_cred_id}").into_bytes())
        .await?;

    audit_writer
        .write(
            &did,
            None,
            AuditEvent::AdminPasskeyRevoked(AdminPasskeyData {
                credential_id_hex: target_cred_id.clone(),
                label: revoked.label,
                transports: revoked.transports,
            }),
        )
        .await?;

    info!(%did, credential_id = %target_cred_id, "passkey revoked");

    Ok(Json(RevokeFinishResponse {
        credential_id: target_cred_id,
        revoked_at: Utc::now(),
        remaining: admin_entry.passkeys.len(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_webauthn(state: &AppState) -> Result<&Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "WebAuthn not configured (public_url required)".into(),
        })
}

fn require_audit_writer(state: &AppState) -> Result<&AuditWriter, AppError> {
    state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })
}

fn passkey_cred_id_hex(p: &Passkey) -> String {
    hex::encode(<_ as AsRef<[u8]>>::as_ref(p.cred_id()))
}
