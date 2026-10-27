//! An administrator's own login passkeys — `auth/passkey/list/0.1`,
//! `auth/passkey/enroll/{start,finish}/0.2` and
//! `auth/passkey/revoke/{start,finish}/0.1`.
//!
//! Implements **M0.6.3** of the VTC MVP Phase 0 plan (spec §4.3). These are
//! the operations; their only door is the signed-document spine
//! (`trust_tasks::admin_passkey_tasks`), which decides who is asking — the
//! verified signer's administrator row, or the administrator a console key
//! acts for — and hands that DID here. The `/v1/admin/passkeys/*` bearer routes
//! that used to call them are gone (#1641): each of the five specifications
//! declares `proof` REQUIRED.
//!
//! Every mutation requires a **fresh WebAuthn user-verification ceremony in
//! the same request**, on top of the signer's authority — a stolen console
//! key (or, before, a stolen session) can't persist by binding a new
//! authenticator. The fresh-UV check is a two-phase ceremony: start returns the
//! UV challenge, finish supplies the UV assertion.
//!
//! - `list` — the caller's own credentials (no step-up; reads are safe).
//! - `enroll/start` — a new-device registration challenge **and** a UV
//!   challenge against the caller's existing credentials.
//! - `enroll/finish` — verifies both, persists the new credential, emits
//!   `AdminPasskeyRegistered`.
//! - `revoke/start` — a UV challenge against existing credentials, pinned to
//!   the credential to remove.
//! - `revoke/finish` — verifies UV, removes the target under the last-passkey
//!   CAS guard, emits `AdminPasskeyRevoked`.
//!
//! ## Concurrency invariant
//!
//! All mutations serialise through [`ADMIN_PASSKEY_LOCK`] so the
//! "refuses to leave zero passkeys" check and the matching write
//! happen atomically. Without it two concurrent revokes can both
//! pass the >1 check and both remove a passkey.

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::info;
use trust_tasks_rs::specs::auth::passkey::{
    enroll::finish::v0_2 as enroll_finish, enroll::start::v0_2 as enroll_start,
    revoke::finish::v0_1 as revoke_finish, revoke::start::v0_1 as revoke_start,
};
use uuid::Uuid;
use vti_common::audit::{AdminPasskeyData, AuditEvent, AuditWriter};
use vti_common::auth::passkey::store::{
    get_passkey_user_by_did, store_auth_state, store_credential_mapping, store_passkey_user,
    store_registration_state, take_auth_state, take_registration_state,
};
use vti_common::error::AppError;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn};

use crate::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
use crate::error::TaskError;
use crate::server::AppState;
use crate::step_up_passkey::{webauthn_options, webauthn_result};
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
//
// The responses are kept as `ToSchema` types, registered as OpenAPI components
// in `routes::ApiDoc`, because the admin console's wire types are generated
// from them. The requests are the generated `trust_tasks_rs::specs` payloads.

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
#[schema(as = PasskeyListResponse)]
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
    #[schema(value_type = Object)]
    pub options: Value,
    /// The value for `navigator.credentials.get({ publicKey: … })` for the
    /// step-up assertion against an existing passkey. Unwrapped for the same
    /// reason as `options`.
    #[schema(value_type = Object)]
    pub uv_options: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisterFinishResponse {
    pub credential_id: String,
    /// The label the credential was stored with, absent when none was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RevokeStartResponse {
    pub revocation_id: String,
    /// Unwrapped, as everywhere else in this family — the value for
    /// `navigator.credentials.get({ publicKey: … })`.
    #[schema(value_type = Object)]
    pub uv_options: Value,
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
// list
// ---------------------------------------------------------------------------

/// `auth/passkey/list/0.1` — `did`'s own passkeys.
///
/// No `AdminEntry` means the caller has enrolled no passkeys — an empty
/// collection, not a missing one.
///
/// It was a `404` until an operator hit it: an admin who signs in with their
/// VTA wallet holds an ACL entry and no passkey enrolment, which is a perfectly
/// ordinary state and the *first* thing such an operator sees on this page. The
/// console rendered the 404 as "FAILED TO LOAD PASSKEYS" directly above its
/// own, correct, "No passkeys registered" empty state — the page contradicting
/// itself about whether anything had gone wrong.
pub(crate) async fn list(state: &AppState, did: &str) -> Result<ListResponse, TaskError> {
    let entry = get_admin_entry(&state.passkey_ks, did).await?;
    Ok(ListResponse {
        credentials: entry
            .iter()
            .flat_map(|e| e.passkeys.iter())
            .map(Into::into)
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// enroll start + finish
// ---------------------------------------------------------------------------

/// `auth/passkey/enroll/start/0.2` — a new-device registration challenge and a
/// step-up UV challenge against `did`'s existing credentials.
///
/// The payload's optional `deviceLabel` is accepted; the label stored is the
/// one `finish` carries, which is where the console names the device.
pub(crate) async fn register_start(
    state: &AppState,
    did: &str,
    _payload: &enroll_start::Payload,
) -> Result<RegisterStartResponse, TaskError> {
    let webauthn = require_webauthn(state).map_err(|e| {
        TaskError::declared(enroll_start::error_codes::ENROLLMENT_NOT_SUPPORTED.code, e)
    })?;

    // Re-authentication is required to add an authenticator, and there is
    // nothing to re-authenticate against: an administrator who signs in with a
    // wallet holds no passkey here. The first one comes from the install claim
    // or `vtc admin emergency-bootstrap`, out of band.
    let pk_user = get_passkey_user_by_did(&state.passkey_ks, did)
        .await?
        .filter(|u| !u.credentials.is_empty())
        .ok_or_else(|| {
            TaskError::declared(
                enroll_start::error_codes::REAUTH_UNAVAILABLE.code,
                AppError::NotFound("no passkey to re-authenticate with".into()),
            )
        })?;

    // Step-up UV: ask any existing credential to sign a challenge.
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
        start_passkey_registration(webauthn, user_uuid, did, did, Some(exclude))?;

    let registration_id = Uuid::new_v4().to_string();
    store_registration_state(&state.passkey_ks, &registration_id, &reg_state).await?;
    store_auth_state(&state.passkey_ks, &registration_id, &uv_state).await?;

    info!(%did, %registration_id, "passkey register ceremony started");

    Ok(RegisterStartResponse {
        enrollment_id: registration_id,
        options: webauthn_options(&register_options.public_key)?,
        uv_options: webauthn_options(&uv_options.public_key)?,
    })
}

/// `auth/passkey/enroll/finish/0.2` — verify the step-up UV, then the new
/// credential, and bind it to `did`.
///
/// `uvCredential` is optional in the specification (absent for a first
/// enrolment, when there is nothing to re-authenticate against). Here there is
/// no first enrolment — `start` refuses `reauthUnavailable` — so a finish
/// without it is refused before anything is consumed.
pub(crate) async fn register_finish(
    state: &AppState,
    did: &str,
    payload: &enroll_finish::Payload,
) -> Result<RegisterFinishResponse, TaskError> {
    let webauthn = require_webauthn(state)?;
    let audit_writer = require_audit_writer(state)?;
    let enrollment_id = payload.enrollment_id.as_str();
    let uv_response: PublicKeyCredential = payload
        .uv_credential
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("a step-up UV assertion is required".into()))
        .and_then(|uv| {
            webauthn_result(uv)
                .ok_or_else(|| AppError::Unauthorized("the UV assertion does not parse".into()))
        })?;
    let register_response: RegisterPublicKeyCredential = webauthn_result(&payload.credential)
        .ok_or_else(|| {
            TaskError::declared(
                enroll_finish::error_codes::ATTESTATION_INVALID.code,
                AppError::Validation("the new credential does not parse".into()),
            )
        })?;
    let label = payload
        .device_label
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_default();
    let transports = payload.credential.response.transports.clone();

    let _guard = ADMIN_PASSKEY_LOCK.lock().await;

    // Take UV state first. A failed UV must NOT consume the
    // registration state — the legitimate operator should be able to
    // retry. The take-then-restore pattern from `webvh-common` (defer
    // the registration-state take until UV verifies) achieves this.
    let uv_state = take_auth_state(&state.passkey_ks, enrollment_id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                enroll_finish::error_codes::ENROLLMENT_NOT_FOUND.code,
                AppError::NotFound("no enrollment in progress with this id".into()),
            )
        })?;
    webauthn
        .finish_passkey_authentication(&uv_response, &uv_state)
        .map_err(|_| AppError::Unauthorized("step-up UV failed".into()))?;

    let reg_state = take_registration_state(&state.passkey_ks, enrollment_id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                enroll_finish::error_codes::ENROLLMENT_NOT_FOUND.code,
                AppError::NotFound("no enrollment in progress with this id".into()),
            )
        })?;
    let new_passkey = finish_passkey_registration(webauthn, &register_response, &reg_state)
        .map_err(|e| {
            TaskError::declared(enroll_finish::error_codes::ATTESTATION_INVALID.code, e)
        })?;

    let new_cred_id_hex = passkey_cred_id_hex(&new_passkey);

    // Append the credential to the PasskeyUser used by login.
    let mut pk_user = get_passkey_user_by_did(&state.passkey_ks, did)
        .await?
        .ok_or_else(|| AppError::Internal("PasskeyUser missing for admin".into()))?;
    pk_user.credentials.push(new_passkey);
    store_passkey_user(&state.passkey_ks, &pk_user).await?;
    store_credential_mapping(&state.passkey_ks, &new_cred_id_hex, pk_user.user_uuid).await?;

    // Mirror into the AdminEntry sister record so the list can serve
    // operator-friendly metadata without walking the `webauthn-rs`
    // credential blob.
    let mut admin_entry = get_admin_entry(&state.passkey_ks, did)
        .await?
        .unwrap_or_else(|| AdminEntry::new(did.to_string()));
    let registered_at = Utc::now();
    admin_entry.passkeys.push(RegisteredPasskey {
        credential_id: new_cred_id_hex.clone(),
        label: label.clone(),
        transports: transports.clone(),
        registered_at,
        last_used_at: None,
    });
    store_admin_entry(&state.passkey_ks, &admin_entry).await?;

    audit_writer
        .write(
            did,
            None,
            AuditEvent::AdminPasskeyRegistered(AdminPasskeyData {
                credential_id_hex: new_cred_id_hex.clone(),
                label: label.clone(),
                transports,
            }),
        )
        .await?;

    info!(%did, credential_id = %new_cred_id_hex, "passkey registered");

    Ok(RegisterFinishResponse {
        credential_id: new_cred_id_hex,
        device_label: (!label.is_empty()).then_some(label),
        subject: did.to_string(),
        registered_at,
    })
}

// ---------------------------------------------------------------------------
// revoke start + finish
// ---------------------------------------------------------------------------

/// `auth/passkey/revoke/start/0.1` — a step-up UV challenge against `did`'s
/// credentials, pinned to the credential being revoked.
pub(crate) async fn revoke_start(
    state: &AppState,
    did: &str,
    payload: &revoke_start::Payload,
) -> Result<RevokeStartResponse, TaskError> {
    let webauthn = require_webauthn(state)?;
    let credential_id = payload.credential_id.to_string();
    let not_found = || {
        TaskError::declared(
            revoke_start::error_codes::CREDENTIAL_NOT_FOUND.code,
            AppError::NotFound("credentialId is not registered for this admin".into()),
        )
    };

    let admin_entry = get_admin_entry(&state.passkey_ks, did)
        .await?
        .ok_or_else(not_found)?;
    if !admin_entry
        .passkeys
        .iter()
        .any(|p| p.credential_id == credential_id)
    {
        return Err(not_found());
    }

    let pk_user = get_passkey_user_by_did(&state.passkey_ks, did)
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
            credential_id.into_bytes(),
        )
        .await?;

    info!(%did, %revocation_id, "passkey revoke ceremony started");

    Ok(RevokeStartResponse {
        revocation_id,
        uv_options: webauthn_options(&uv_options.public_key)?,
    })
}

/// `auth/passkey/revoke/finish/0.1` — verify the step-up UV and remove the
/// pinned credential, refusing to leave `did` with none.
pub(crate) async fn revoke_finish(
    state: &AppState,
    did: &str,
    payload: &revoke_finish::Payload,
) -> Result<RevokeFinishResponse, TaskError> {
    use revoke_finish::error_codes as codes;

    let webauthn = require_webauthn(state)?;
    let audit_writer = require_audit_writer(state)?;
    let revocation_id = payload.revocation_id.as_str();
    let uv_failed = || {
        TaskError::declared(
            codes::USER_VERIFICATION_FAILED.code,
            AppError::Unauthorized("step-up UV failed".into()),
        )
    };
    let uv_response: PublicKeyCredential =
        webauthn_result(&payload.uv_credential).ok_or_else(uv_failed)?;

    let _guard = ADMIN_PASSKEY_LOCK.lock().await;

    // Take UV state. As with enroll/finish, a failed UV leaves the
    // pinned target intact so the legitimate operator can retry.
    let uv_state = take_auth_state(&state.passkey_ks, revocation_id)
        .await?
        .ok_or_else(|| {
            TaskError::declared(
                codes::REVOCATION_NOT_FOUND.code,
                AppError::NotFound("no revocation in progress with this id".into()),
            )
        })?;
    webauthn
        .finish_passkey_authentication(&uv_response, &uv_state)
        .map_err(|_| uv_failed())?;

    let target_bytes = state
        .passkey_ks
        .get_raw(revoke_target_key(revocation_id))
        .await?
        .ok_or_else(|| AppError::Internal("revocation target missing".into()))?;
    let target_cred_id = String::from_utf8(target_bytes)
        .map_err(|_| AppError::Internal("revocation target malformed".into()))?;
    state
        .passkey_ks
        .remove(revoke_target_key(revocation_id))
        .await?;

    let mut admin_entry = get_admin_entry(&state.passkey_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound("no admin entry for caller".into()))?;

    let before = admin_entry.passkeys.len();
    let revoked = admin_entry
        .passkeys
        .iter()
        .find(|p| p.credential_id == target_cred_id)
        .cloned()
        .ok_or_else(|| {
            AppError::NotFound("credentialId is not registered for this admin".into())
        })?;

    // **Last-passkey CAS guard.** Refuse if this revoke would leave
    // the admin with zero passkeys. Inside the lock so two concurrent
    // revokes can't both pass the > 1 check.
    if before <= 1 {
        return Err(TaskError::declared(
            codes::LAST_CREDENTIAL.code,
            AppError::Conflict(
                "LastPasskeyProtected: refusing to leave admin with zero passkeys".into(),
            ),
        ));
    }

    admin_entry
        .passkeys
        .retain(|p| p.credential_id != target_cred_id);
    store_admin_entry(&state.passkey_ks, &admin_entry).await?;

    // Mirror the removal into the PasskeyUser used by login. The
    // credential id on `webauthn-rs`'s `Passkey` is the raw byte
    // form; compare hex-encoded.
    let mut pk_user = get_passkey_user_by_did(&state.passkey_ks, did)
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
            did,
            None,
            AuditEvent::AdminPasskeyRevoked(AdminPasskeyData {
                credential_id_hex: target_cred_id.clone(),
                label: revoked.label,
                transports: revoked.transports,
            }),
        )
        .await?;

    info!(%did, credential_id = %target_cred_id, "passkey revoked");

    Ok(RevokeFinishResponse {
        credential_id: target_cred_id,
        revoked_at: Utc::now(),
        remaining: admin_entry.passkeys.len(),
    })
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
