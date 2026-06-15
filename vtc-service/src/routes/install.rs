//! `POST /v1/install/claim/{start,finish}` — WebAuthn install
//! ceremony for the very first admin.
//!
//! Implements **M0.5.2** of the VTC MVP Phase 0 plan. The flow:
//!
//! ```text
//! operator  ──install_token──▶  start  ──ccr+did_binding_challenge──▶ operator
//! operator  ──finish(webauthn_response, did_binding_signature)──▶  finish
//! finish    ──admin_did + setup_session_token──▶  operator
//! ```
//!
//! - `start` verifies the install token, takes the install-keyspace
//!   ceremony lock (`InstallTokenStore::start_claim`), and returns a
//!   WebAuthn `CreationChallengeResponse` constrained to Ed25519 via
//!   `vtc_service::webauthn::start_passkey_registration`, which
//!   accepts any algorithm the authenticator can produce
//!   (ES256, RS256, EdDSA).
//! - `finish` verifies the WebAuthn response, derives the candidate
//!   admin `did:key` from the credential's Ed25519 public key,
//!   consumes the install token, persists the passkey, and mints a
//!   short-lived setup-session token consumed by M0.6's
//!   `/v1/admin/bootstrap`.
//!
//! The WebAuthn attestation already proves the operator controls the
//! Ed25519 keypair that materialises the candidate did:key — modelled
//! on `affinidi-webvh-service`'s `enroll_finish` (no extra raw-bytes
//! binding signature). The previous design required a raw Ed25519
//! signature over a server challenge, which is impossible to produce
//! in a real browser (WebAuthn never exposes the private key).
//!
//! Per-row state machine is the only gate on claim. A second
//! `start` on the same token after a successful `finish` returns
//! 401 because the row is now `Consumed`. The earlier global
//! "carve-out" lockdown is gone — each invite carries its own
//! Argon2id-hashed claim secret which `claim_start` verifies
//! before issuing the WebAuthn challenge.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;
use vti_common::auth::passkey::store::{
    PasskeyUser, delete_registration_user, get_registration_user, store_credential_mapping,
    store_passkey_user, store_registration_state, store_registration_user, take_registration_state,
};
use vti_common::error::AppError;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential, Webauthn};

use crate::acl::admin::{AdminEntry, RegisteredPasskey, get_admin_entry, store_admin_entry};
use crate::install::{
    INSTALL_SESSION_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenState, claim_secret,
    mint_install_session_token, parse_install_token,
};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ClaimStartRequest {
    pub install_token: String,
    /// Out-of-band claim code the operator received alongside the
    /// install URL. Required when the persisted token row has a
    /// `claim_secret_hash`; ignored otherwise so legacy tokens
    /// (and tests) keep working. The route handler verifies the
    /// code against the hash before issuing the WebAuthn challenge
    /// — a wrong or missing code returns 401 with discriminated
    /// error codes (`claim_secret_required` / `claim_secret_invalid`).
    #[serde(default)]
    pub claim_secret: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ClaimStartResponse {
    /// Echoes the install token's `jti`. Consumer must pass this
    /// back to `claim/finish` so the server can index the stored
    /// registration state.
    pub registration_id: String,
    /// The WebAuthn `PublicKeyCredentialCreationOptions` payload —
    /// the operator's UA passes this to `navigator.credentials.create()`.
    #[schema(value_type = Object)]
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ClaimFinishRequest {
    pub install_token: String,
    pub registration_id: String,
    #[schema(value_type = Object)]
    pub webauthn_response: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct ClaimFinishResponse {
    pub admin_did: String,
    pub setup_session_token: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/install/claim/start` — begin the WebAuthn install
/// ceremony for the first admin. Unauthenticated.
#[utoipa::path(
    post, path = "/install/claim/start", tag = "install",
    request_body = ClaimStartRequest,
    responses(
        (status = 201, description = "WebAuthn creation challenge", body = ClaimStartResponse),
        (status = 401, description = "Invalid install token or claim secret"),
    ),
)]
pub async fn claim_start(
    State(state): State<AppState>,
    Json(req): Json<ClaimStartRequest>,
) -> Result<(StatusCode, Json<ClaimStartResponse>), AppError> {
    let signer = require_install_signer(&state)?;
    let webauthn = require_webauthn(&state)?;
    let store = &state.install_store;

    let claims = parse_install_token(signer, &req.install_token)?;
    let jti = parse_jti(&claims.jti)?;

    // Per-invite claim secret, verified BEFORE the ceremony lock (P0.21).
    // `start_claim` stamps `claimed_at`, a 300 s concurrency lock; if we
    // verified the secret *after* it, anyone holding only the install URL
    // could grief the legitimate operator by POSTing a wrong code every 5
    // minutes — each attempt would re-arm the lock, then get rejected. So
    // we peek the stored hash (no mutation) and verify first; only a
    // correct (or absent) secret reaches `start_claim`. Discriminated 401
    // codes let the browser surface the right hint (missing vs wrong code).
    // Rows without a hash skip this — covers legacy rows and tests. The
    // authoritative not-found / consumed / expired / concurrency checks
    // stay in `start_claim` below.
    if let Some(stored_hash) = store.peek_secret_hash(&jti).await? {
        let Some(supplied) = req.claim_secret.as_deref() else {
            return Err(AppError::ServiceError {
                status: StatusCode::UNAUTHORIZED,
                message: "claim_secret_required".into(),
            });
        };
        // Argon2id verification is CPU-bound (~50–200 ms); run it on the
        // blocking pool so it doesn't stall the async REST runtime — this is
        // an *unauthenticated* route, so a few concurrent claim-starts must
        // not wedge every other request (P0.10).
        let supplied = supplied.to_string();
        let verified =
            tokio::task::spawn_blocking(move || claim_secret::verify(&supplied, &stored_hash))
                .await
                .map_err(|e| {
                    AppError::Internal(format!("claim-secret verify task failed: {e}"))
                })??;
        if !verified {
            return Err(AppError::ServiceError {
                status: StatusCode::UNAUTHORIZED,
                message: "claim_secret_invalid".into(),
            });
        }
    }

    // Take the ceremony lock. `start_claim` validates `Issued`, not
    // expired; on success the `claimed_at` window is set to "now"
    // so a second concurrent start sees the lock.
    store.start_claim(&jti).await?;

    let user_uuid = jti;
    // Show the operator their admin DID in the authenticator's UI —
    // it's the identity the passkey will authenticate as. Modelled on
    // `affinidi-webvh-service`'s enroll-start which uses `user.did`
    // for both user_name and display_name. No algorithm restriction
    // here so any platform authenticator (Apple iCloud Keychain,
    // Windows Hello, Chrome passkeys, hardware keys) works — the
    // admin DID's shape is fixed in the install token, not derived
    // from the passkey.
    let (ccr, reg_state) = crate::webauthn::start_passkey_registration(
        webauthn,
        user_uuid,
        &claims.admin_did,
        &claims.admin_did,
        None,
    )?;

    // Persist the registration state under `jti` so `claim_finish`
    // can complete the ceremony against the same challenge.
    store_registration_state(&state.passkey_ks, &jti.to_string(), &reg_state).await?;

    // Carry the user UUID forward so the M0.6 bootstrap can look up
    // the PasskeyUser by registration_id without re-deriving it.
    store_registration_user(&state.passkey_ks, &jti.to_string(), &user_uuid).await?;

    info!(jti = %jti, "install claim ceremony started");

    Ok((
        StatusCode::OK,
        Json(ClaimStartResponse {
            registration_id: jti.to_string(),
            options: ccr,
        }),
    ))
}

/// `POST /v1/install/claim/finish` — complete the WebAuthn install
/// ceremony, mint the admin DID + setup-session token. Unauthenticated.
#[utoipa::path(
    post, path = "/install/claim/finish", tag = "install",
    request_body = ClaimFinishRequest,
    responses(
        (status = 200, description = "Admin DID + setup-session token", body = ClaimFinishResponse),
        (status = 401, description = "Invalid install token or registration state"),
    ),
)]
pub async fn claim_finish(
    State(state): State<AppState>,
    Json(req): Json<ClaimFinishRequest>,
) -> Result<(StatusCode, Json<ClaimFinishResponse>), AppError> {
    let signer = require_install_signer(&state)?;
    let webauthn = require_webauthn(&state)?;
    let store = &state.install_store;

    let claims = parse_install_token(signer, &req.install_token)?;
    let jti = parse_jti(&claims.jti)?;
    let reg_id = parse_jti(&req.registration_id)?;
    if reg_id != jti {
        return Err(AppError::Unauthorized(
            "registration_id does not match install token".into(),
        ));
    }

    // Idempotent retry. Consume-first (below) is the security-correct
    // direction, but it leaves an availability sharp edge: a crash —
    // or a dropped response — between consuming the token and returning
    // permanently spends it, stranding the operator without the
    // `setup_session_token` `/admin/bootstrap` needs and with no way to
    // re-run the WebAuthn ceremony (its registration state was already
    // taken). So if the token is already `Consumed` *and* the ceremony
    // actually persisted an admin record, re-derive + re-mint the
    // setup-session token instead of hard-rejecting. The signed install
    // token's own `exp` (validated by `parse_install_token` above) bounds
    // the retry window; `start→finish→start` still rejects the second
    // `start` (it requires `Issued`).
    if let Some(InstallTokenState::Consumed { admin_did, .. }) = store.get_token(&jti).await? {
        let admin_did = admin_did.unwrap_or_else(|| claims.admin_did.clone());
        // Only re-issue if the first call got far enough to persist the
        // admin — otherwise there's nothing to bootstrap against.
        if get_admin_entry(&state.passkey_ks, &admin_did)
            .await?
            .is_some()
        {
            info!(jti = %jti, %admin_did, "install claim finish replayed; re-issuing setup token");
            return issue_setup_session(&state, signer, admin_did, &jti).await;
        }
        return Err(AppError::Unauthorized("install token consumed".into()));
    }

    let reg_state = take_registration_state(&state.passkey_ks, &jti.to_string())
        .await?
        .ok_or_else(|| {
            AppError::Unauthorized(
                "no registration in progress for this install token (start the ceremony first)"
                    .into(),
            )
        })?;

    // Run the WebAuthn ceremony. Any algorithm the authenticator
    // offers is acceptable — the admin DID is carried in the install
    // token, not derived from the passkey, so a platform passkey
    // (Apple iCloud Keychain, Windows Hello, Chrome passkeys, etc.)
    // works regardless of whether it produces ES256, EdDSA, or RS256.
    let passkey = webauthn
        .finish_passkey_registration(&req.webauthn_response, &reg_state)
        .map_err(|e| AppError::Authentication(format!("passkey registration failed: {e}")))?;
    let admin_did = claims.admin_did.clone();

    // Consume the install token (Issued → Consumed). Carve-out stays
    // open until M0.6's bootstrap closes it.
    store.finish_claim(&jti).await?;

    // Persist the passkey + credential mapping so M0.6's bootstrap
    // and subsequent passkey login can find the credential.
    let user_uuid = get_registration_user(&state.passkey_ks, &jti.to_string())
        .await?
        .ok_or_else(|| AppError::Internal("missing registration_user mapping".into()))?;
    delete_registration_user(&state.passkey_ks, &jti.to_string()).await?;
    let user = PasskeyUser {
        user_uuid,
        did: admin_did.clone(),
        display_name: admin_did.clone(),
        credentials: vec![passkey.clone()],
    };
    store_passkey_user(&state.passkey_ks, &user).await?;
    let cred_id_hex = hex::encode(passkey.cred_id().as_ref() as &[u8]);
    store_credential_mapping(&state.passkey_ks, &cred_id_hex, user_uuid).await?;

    // Create or append to the AdminEntry so `GET /v1/admin/passkeys`
    // can list the just-registered device. The first-admin install
    // flow then takes the same AdminEntry through `/v1/admin/bootstrap`;
    // the `vtc admin invite` flow never reaches bootstrap (carve-out
    // already closed by the first admin), so this write is the only
    // place the AdminEntry is populated for invited admins.
    let now = chrono::Utc::now();
    let registered = RegisteredPasskey {
        credential_id: cred_id_hex.clone(),
        label: "install".into(),
        transports: Vec::new(),
        registered_at: now,
        last_used_at: None,
    };
    let admin_entry = match get_admin_entry(&state.passkey_ks, &admin_did).await? {
        Some(mut existing) => {
            // Dedupe by credential_id — a retry of the same ceremony
            // must not double-list the device.
            if !existing
                .passkeys
                .iter()
                .any(|p| p.credential_id == cred_id_hex)
            {
                existing.passkeys.push(registered);
            }
            existing
        }
        None => AdminEntry {
            did: admin_did.clone(),
            passkeys: vec![registered],
            extensions: serde_json::Value::Null,
            created_at: now,
        },
    };
    store_admin_entry(&state.passkey_ks, &admin_entry).await?;

    info!(jti = %jti, %admin_did, "install claim ceremony completed");

    issue_setup_session(&state, signer, admin_did, &jti).await
}

/// Mint the `setup_session_token` for `admin_did` + build the
/// `claim/finish` response. Shared by the first-completion path and the
/// idempotent-replay path so a retry returns a usable token too.
async fn issue_setup_session(
    state: &AppState,
    signer: &InstallTokenSigner,
    admin_did: String,
    jti: &Uuid,
) -> Result<(StatusCode, Json<ClaimFinishResponse>), AppError> {
    let issuer_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "did:key:vtc-install-uninitialised".to_string());

    let setup_session_token = mint_install_session_token(
        signer,
        &issuer_did,
        &admin_did,
        &jti.to_string(),
        INSTALL_SESSION_DEFAULT_TTL_SECS,
    )?;

    Ok((
        StatusCode::OK,
        Json(ClaimFinishResponse {
            admin_did,
            setup_session_token,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_install_signer(state: &AppState) -> Result<&Arc<InstallTokenSigner>, AppError> {
    state
        .install_signer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "install signer not configured (run setup first)".into(),
        })
}

fn require_webauthn(state: &AppState) -> Result<&Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "WebAuthn not configured (public_url required)".into(),
        })
}

fn parse_jti(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s)
        .map_err(|_| AppError::Unauthorized("invalid install token (malformed jti)".into()))
}

// All Ed25519-derivation helpers (extract_ed25519_public_key,
// walk_eddsa_x, decode_x_value, ed25519_pub_to_did_key) lived here
// to project the WebAuthn key into the admin did:key. The redesigned
// flow carries admin_did in the install token, so the helpers are
// no longer needed. Removing them lets the install ceremony accept
// any algorithm the authenticator offers (ES256 from platform
// passkeys, EdDSA from hardware keys, etc.).
