//! `/v1/member/*` — the member portal's routes.
//!
//! Sign-in is by the browser wallet (SIOPv2) or by a portal passkey, and only
//! for an active member; see [`crate::member_portal`] for how these sessions
//! are kept apart from the console's.
//!
//! **Why these are plain REST routes with no Trust Task binding.** They are the
//! browser's own plumbing, the same class as the console's wallet aliases and
//! sign-out: a WebAuthn ceremony (a foreign protocol), the wallet's header-less
//! SIOP round-trip — whose `{type, payload}` body already names the canonical
//! `auth/authenticate/0.1` / `auth/refresh/0.1` — and the cookies a browser
//! keeps its session in, which no Trust Task describes. Nothing here confers
//! or exercises community authority; anything a member *does* in the portal
//! belongs on the Trust Task surface, signed by the member's own DID.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::refresh::v0_1 as refresh_spec;
use uuid::Uuid;
use vta_sdk::protocols::auth::{AuthenticateResponse, ChallengeRequest, ChallengeResponse};
use vti_common::audit::{AuditEvent, MemberPasskeyData};
use vti_common::auth::passkey::store::{
    PasskeyUser, get_all_passkeys, get_passkey_user_by_cred, get_passkey_user_by_did,
    store_auth_state, store_credential_mapping, store_passkey_user, store_registration_state,
    take_auth_state, take_registration_state,
};
use vti_common::auth::session::{
    Session, SessionState, delete_session, now_epoch, store_refresh_index, store_session,
};

use crate::error::AppError;
use crate::member_portal::{
    MEMBER_CSRF_COOKIE, MEMBER_REFRESH_COOKIE, MEMBER_SESSION_COOKIE, MemberAuth,
    MemberAuthBackend, cookies, require_active_member,
};
use crate::server::AppState;

const REFRESH_TASK_URI: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

/// Labels a member gives a passkey are display text, not data: capped so the
/// row stays small.
const PASSKEY_LABEL_MAX: usize = 64;

// ── Wallet SIOPv2 sign-in ───────────────────────────────────────────────────
//
// The portal points the wallet at `<origin>/v1/member/wallet`; the wallet
// appends `/auth/challenge`, `/auth/` and `/auth/refresh` exactly as it does
// for the console's `/v1/wallet`.

/// `POST /v1/member/wallet/auth/challenge`. Answers every caller alike; a
/// session is persisted only for an active member (VTI-SES-006, -007).
pub async fn wallet_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let backend = MemberAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: req.did,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    Ok(Json(resp))
}

/// `POST /v1/member/wallet/auth/`. The SIOP `id_token` envelope only — the
/// verifier is the console's own ([`super::auth::authenticate_siop_with`]),
/// pointed at the member keyspace and backend.
pub async fn wallet_authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let backend = MemberAuthBackend::from_state(&state).await?;
    let resp =
        super::auth::authenticate_siop_with(&state, &body, &state.member_sessions_ks, &backend)
            .await?
            .ok_or_else(|| AppError::Authentication("expected a SIOPv2 id_token sign-in".into()))?;
    info!(did = %resp.session.subject, "member portal sign-in (wallet)");
    Ok(Json(resp))
}

/// `POST /v1/member/wallet/auth/refresh` — the wallet spending the refresh
/// token it was handed, as an `auth/refresh/0.1` document.
pub async fn wallet_refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let doc: TrustTask<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|_| AppError::Authentication("expected an auth/refresh/0.1 document".into()))?;
    if doc.type_uri.to_string() != REFRESH_TASK_URI {
        return Err(AppError::Authentication(
            "expected an auth/refresh/0.1 document".into(),
        ));
    }
    let payload: refresh_spec::Payload = serde_json::from_value(doc.payload)
        .map_err(|e| AppError::Authentication(format!("invalid refresh payload: {e}")))?;
    let backend = MemberAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token: payload.refresh_token.to_string(),
            signer_did: None,
        },
    )
    .await?;
    Ok(Json(resp))
}

// ── Cookie session ──────────────────────────────────────────────────────────

/// Body of `POST /v1/member/session`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberSessionRequest {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Written by hand so neither token reaches a log: a derived `Debug` would
/// print both.
impl std::fmt::Debug for MemberSessionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberSessionRequest")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// What the portal is told about the session it now holds in cookies.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSessionResponse {
    pub session_id: String,
    pub subject: String,
    pub expires_at: u64,
}

/// `POST /v1/member/session` — mirror a member-audience bearer (from the
/// wallet sign-in) into the portal's cookies. Grants nothing the caller does
/// not already hold: a console token fails the audience check here, and the
/// subject must still be an active member.
pub async fn session(
    State(state): State<AppState>,
    Json(req): Json<MemberSessionRequest>,
) -> Result<Response, AppError> {
    let (claims, _session) =
        crate::member_portal::extractor::authenticate_member_token(&state, &req.access_token)
            .await
            .map_err(|_| AppError::Authentication("invalid or expired access token".into()))?;
    require_active_member(&state, &claims.sub).await?;

    let refresh_ttl = state.config.read().await.auth.refresh_token_expiry;
    let access_max_age = claims.exp.saturating_sub(now_epoch()).max(1);
    let csrf_window = if req.refresh_token.is_some() {
        refresh_ttl.max(access_max_age)
    } else {
        access_max_age
    };
    let mut set = vec![
        cookies::session_cookie(&req.access_token, access_max_age),
        cookies::csrf_cookie(&cookies::new_csrf(), csrf_window),
    ];
    if let Some(rt) = &req.refresh_token {
        set.push(cookies::refresh_cookie(rt, refresh_ttl));
    }

    let mut response = Json(MemberSessionResponse {
        session_id: claims.session_id,
        subject: claims.sub,
        expires_at: claims.exp,
    })
    .into_response();
    cookies::append(response.headers_mut(), set)?;
    Ok(response)
}

/// `POST /v1/member/auth/refresh` — renew the portal's cookie session from
/// `vtc_member_refresh`. Rotation, reuse detection and the active-member
/// re-check are the shared handler's, against the member keyspace.
pub async fn cookie_refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let token = cookies::cookie_value(&headers, MEMBER_REFRESH_COOKIE)
        .ok_or_else(|| AppError::Unauthorized("no member refresh cookie".into()))?;
    let backend = MemberAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token: token,
            signer_did: None,
        },
    )
    .await?;

    let refresh_ttl = state.config.read().await.auth.refresh_token_expiry;
    let mut set = vec![cookies::session_cookie(
        &resp.tokens.access_token,
        resp.tokens.expires_in.max(1),
    )];
    if let Some(rt) = &resp.tokens.refresh_token {
        set.push(cookies::refresh_cookie(rt, refresh_ttl));
    }
    // Same CSRF value, longer life — the portal already mirrors it.
    if let Some(csrf) = cookies::cookie_value(&headers, MEMBER_CSRF_COOKIE) {
        set.push(cookies::csrf_cookie(&csrf, refresh_ttl));
    }
    let mut response = Json(MemberSessionResponse {
        session_id: resp.session.id.clone(),
        subject: resp.session.subject.clone(),
        expires_at: now_epoch().saturating_add(resp.tokens.expires_in),
    })
    .into_response();
    cookies::append(response.headers_mut(), set)?;
    Ok(response)
}

/// `POST /v1/member/sign-out` — end the session the portal cookie names (if
/// it still verifies) and clear the cookies. Always `204`: a caller whose
/// session already lapsed is signed out either way.
pub async fn sign_out(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(token) = cookies::cookie_value(&headers, MEMBER_SESSION_COOKIE)
        && let Ok((claims, _)) =
            crate::member_portal::extractor::authenticate_member_token(&state, &token).await
    {
        delete_session(&state.member_sessions_ks, &claims.session_id).await?;
        info!(did = %claims.sub, session_id = %claims.session_id, "member portal sign-out");
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    cookies::append(response.headers_mut(), cookies::cleared())?;
    Ok(response)
}

// ── Who am I ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberCommunity {
    pub name: Option<String>,
    pub logo_url: Option<String>,
    pub did: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberMeResponse {
    pub did: String,
    pub session_id: String,
    pub access_expires_at: u64,
    /// How this session was established: `did` (wallet) or `passkey`.
    pub amr: Vec<String>,
    pub joined_at: DateTime<Utc>,
    /// The member's community role (`member`, `moderator`, …) — what it is,
    /// not a grant of anything in the portal.
    pub role: String,
    pub personhood: bool,
    /// Whether this session may add or remove portal passkeys (wallet-proven).
    pub can_manage_passkeys: bool,
    pub community: MemberCommunity,
}

/// `GET /v1/member/me`.
pub async fn me(
    auth: MemberAuth,
    State(state): State<AppState>,
) -> Result<Json<MemberMeResponse>, AppError> {
    let profile = crate::community::load_profile(&state.community_ks).await?;
    let vtc_did = state.config.read().await.vtc_did.clone();
    Ok(Json(MemberMeResponse {
        can_manage_passkeys: auth.proved_did(),
        did: auth.did,
        session_id: auth.session_id,
        access_expires_at: auth.access_expires_at,
        amr: auth.amr,
        joined_at: auth.member.member.joined_at,
        role: auth.member.entry.role.to_string(),
        personhood: auth.member.member.personhood,
        community: MemberCommunity {
            name: profile
                .as_ref()
                .map(|p| p.name.clone())
                .filter(|n| !n.is_empty()),
            logo_url: profile.as_ref().and_then(|p| p.logo_url.clone()),
            did: vtc_did,
        },
    }))
}

// ── Portal passkeys ─────────────────────────────────────────────────────────

/// Display metadata for a member's portal passkeys, beside the passkey store's
/// own rows (which carry no label). Prefix chosen not to collide with the
/// store's `pk_*` keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyMeta {
    passkeys: Vec<MemberPasskey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPasskey {
    pub credential_id: String,
    pub label: Option<String>,
    pub registered_at: DateTime<Utc>,
}

fn meta_key(did: &str) -> String {
    format!("member_meta:{did}")
}

async fn load_meta(state: &AppState, did: &str) -> Result<PasskeyMeta, AppError> {
    Ok(state
        .member_passkey_ks
        .get::<PasskeyMeta>(meta_key(did))
        .await?
        .unwrap_or_default())
}

fn require_webauthn(state: &AppState) -> Result<&webauthn_rs::prelude::Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::Authentication("passkeys are not configured on this VTC".into()))
}

async fn audit_passkey(
    state: &AppState,
    did: &str,
    stage: &str,
    credential_id: &str,
    label: Option<String>,
) -> Result<(), AppError> {
    let Some(writer) = state.audit_writer.as_ref() else {
        warn!(%did, stage, "audit writer not configured; member passkey change not audited");
        return Ok(());
    };
    writer
        .write(
            did,
            None,
            AuditEvent::MemberPasskeyChanged(MemberPasskeyData {
                stage: stage.into(),
                subject: did.into(),
                credential_id: credential_id.into(),
                label,
            }),
        )
        .await?;
    Ok(())
}

/// `GET /v1/member/passkeys` — the caller's own portal passkeys.
pub async fn list_passkeys(
    auth: MemberAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<MemberPasskey>>, AppError> {
    Ok(Json(load_meta(&state, &auth.did).await?.passkeys))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartResponse {
    pub registration_id: String,
    /// For `navigator.credentials.create({ publicKey: … })`.
    pub options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
}

/// `POST /v1/member/passkeys/register/start` — wallet-proven sessions only
/// ([`MemberAuth::require_proved_did`]).
pub async fn register_start(
    auth: MemberAuth,
    State(state): State<AppState>,
) -> Result<Json<RegisterStartResponse>, AppError> {
    auth.require_proved_did()?;
    let webauthn = require_webauthn(&state)?;
    let existing = get_passkey_user_by_did(&state.member_passkey_ks, &auth.did).await?;
    let (user_uuid, exclude) = match &existing {
        Some(u) => (
            u.user_uuid,
            Some(u.credentials.iter().map(|p| p.cred_id().clone()).collect()),
        ),
        None => (Uuid::new_v4(), None),
    };
    let (options, reg_state) = crate::webauthn::start_passkey_registration(
        webauthn, user_uuid, &auth.did, &auth.did, exclude,
    )?;
    let registration_id = Uuid::new_v4().to_string();
    store_registration_state(&state.member_passkey_ks, &registration_id, &reg_state).await?;
    // Pin the ceremony to its subject and user handle so finish cannot be
    // completed by another member's session.
    state
        .member_passkey_ks
        .insert(
            format!("member_reg:{registration_id}"),
            &(auth.did.clone(), user_uuid),
        )
        .await?;
    Ok(Json(RegisterStartResponse {
        registration_id,
        options: options.public_key,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterFinishRequest {
    pub registration_id: String,
    pub credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
    #[serde(default)]
    pub label: Option<String>,
}

/// `POST /v1/member/passkeys/register/finish`.
pub async fn register_finish(
    auth: MemberAuth,
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<(StatusCode, Json<MemberPasskey>), AppError> {
    auth.require_proved_did()?;
    let webauthn = require_webauthn(&state)?;
    let label = req
        .label
        .map(|l| l.trim().chars().take(PASSKEY_LABEL_MAX).collect::<String>())
        .filter(|l| !l.is_empty());

    let pin_key = format!("member_reg:{}", req.registration_id);
    let pinned: Option<(String, Uuid)> = state.member_passkey_ks.get(pin_key.clone()).await?;
    let Some((pinned_did, user_uuid)) = pinned else {
        return Err(AppError::Unauthorized("no registration in progress".into()));
    };
    if pinned_did != auth.did {
        return Err(AppError::Forbidden(
            "this registration belongs to another session".into(),
        ));
    }
    state.member_passkey_ks.remove(pin_key).await?;
    let reg_state = take_registration_state(&state.member_passkey_ks, &req.registration_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("no registration in progress".into()))?;
    let passkey =
        crate::webauthn::finish_passkey_registration(webauthn, &req.credential, &reg_state)?;
    let credential_id = hex::encode(<_ as AsRef<[u8]>>::as_ref(passkey.cred_id()));

    let mut user = get_passkey_user_by_did(&state.member_passkey_ks, &auth.did)
        .await?
        .unwrap_or_else(|| PasskeyUser {
            user_uuid,
            did: auth.did.clone(),
            display_name: auth.did.clone(),
            credentials: Vec::new(),
        });
    user.credentials.push(passkey);
    store_passkey_user(&state.member_passkey_ks, &user).await?;
    store_credential_mapping(&state.member_passkey_ks, &credential_id, user.user_uuid).await?;

    let entry = MemberPasskey {
        credential_id: credential_id.clone(),
        label: label.clone(),
        registered_at: Utc::now(),
    };
    let mut meta = load_meta(&state, &auth.did).await?;
    meta.passkeys.push(entry.clone());
    state
        .member_passkey_ks
        .insert(meta_key(&auth.did), &meta)
        .await?;

    audit_passkey(&state, &auth.did, "registered", &credential_id, label).await?;
    info!(did = %auth.did, %credential_id, "member portal passkey registered");
    Ok((StatusCode::OK, Json(entry)))
}

/// `DELETE /v1/member/passkeys/{credential_id}` — wallet-proven sessions only.
pub async fn remove_passkey(
    auth: MemberAuth,
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require_proved_did()?;
    let mut meta = load_meta(&state, &auth.did).await?;
    let before = meta.passkeys.len();
    meta.passkeys.retain(|p| p.credential_id != credential_id);
    if meta.passkeys.len() == before {
        return Err(AppError::NotFound("no such passkey".into()));
    }
    if let Some(mut user) = get_passkey_user_by_did(&state.member_passkey_ks, &auth.did).await? {
        user.credentials
            .retain(|p| hex::encode(<_ as AsRef<[u8]>>::as_ref(p.cred_id())) != credential_id);
        store_passkey_user(&state.member_passkey_ks, &user).await?;
    }
    state
        .member_passkey_ks
        .remove(format!("pk_cred:{credential_id}"))
        .await?;
    state
        .member_passkey_ks
        .insert(meta_key(&auth.did), &meta)
        .await?;
    audit_passkey(&state, &auth.did, "removed", &credential_id, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Passkey sign-in ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyLoginStartResponse {
    pub auth_id: String,
    /// For `navigator.credentials.get({ publicKey: … })`.
    pub options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
}

/// `POST /v1/member/passkey-login/start` — a discoverable challenge across
/// portal passkeys only. Unauthenticated: the assertion is the proof.
pub async fn passkey_login_start(
    State(state): State<AppState>,
) -> Result<Json<PasskeyLoginStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let passkeys = get_all_passkeys(&state.member_passkey_ks).await?;
    if passkeys.is_empty() {
        return Err(AppError::Authentication(
            "no member has added a passkey yet — sign in with your wallet first".into(),
        ));
    }
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn auth start failed: {e}")))?;
    let auth_id = Uuid::new_v4().to_string();
    store_auth_state(&state.member_passkey_ks, &auth_id, &auth_state).await?;
    Ok(Json(PasskeyLoginStartResponse {
        auth_id,
        options: rcr.public_key,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyLoginFinishRequest {
    pub auth_id: String,
    pub credential: webauthn_rs::prelude::PublicKeyCredential,
}

/// `POST /v1/member/passkey-login/finish` — verify, re-check active
/// membership, mint a member session (`aal2`), set the portal cookies.
pub async fn passkey_login_finish(
    State(state): State<AppState>,
    Json(req): Json<PasskeyLoginFinishRequest>,
) -> Result<Response, AppError> {
    let webauthn = require_webauthn(&state)?;
    let auth_state = take_auth_state(&state.member_passkey_ks, &req.auth_id)
        .await?
        .ok_or_else(|| AppError::Authentication("sign-in expired; try again".into()))?;
    let result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            warn!(error = %e, "member passkey authentication failed");
            AppError::Authentication("passkey sign-in failed".into())
        })?;
    let cred_id = hex::encode(result.cred_id());
    let mut user = get_passkey_user_by_cred(&state.member_passkey_ks, &cred_id)
        .await?
        .ok_or_else(|| AppError::Authentication("passkey not recognised".into()))?;
    for c in &mut user.credentials {
        c.update_credential(&result);
    }
    store_passkey_user(&state.member_passkey_ks, &user).await?;

    // The passkey proves who; membership is decided now, not at enrolment.
    require_active_member(&state, &user.did).await?;

    let backend = MemberAuthBackend::from_state(&state).await?;
    let session_id = Uuid::new_v4().to_string();
    let amr = vec!["passkey".to_string()];
    let acr = "aal2".to_string();
    let minted = vti_common::auth::handlers::mint_session_tokens(
        &backend,
        &user.did,
        &session_id,
        &crate::acl::Role::Reader,
        &[],
        &amr,
        &acr,
        false,
    )
    .await?;
    store_session(
        &state.member_sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: user.did.clone(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: minted.issued_at,
            last_seen: minted.issued_at,
            refresh_token: Some(minted.refresh_token.clone()),
            refresh_expires_at: Some(minted.refresh_expires_at),
            tee_attested: false,
            amr,
            acr,
            acr_expires_at: None,
            token_id: Some(minted.token_id.clone()),
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    store_refresh_index(
        &state.member_sessions_ks,
        &minted.refresh_token,
        &session_id,
    )
    .await?;
    info!(did = %user.did, %session_id, "member portal sign-in (passkey)");

    let access_max_age = minted.access_expires_at.saturating_sub(now_epoch()).max(1);
    let refresh_max_age = minted.refresh_expires_at.saturating_sub(now_epoch()).max(1);
    let mut response = Json(MemberSessionResponse {
        session_id,
        subject: user.did.clone(),
        expires_at: minted.access_expires_at,
    })
    .into_response();
    cookies::append(
        response.headers_mut(),
        [
            cookies::session_cookie(&minted.access_token, access_max_age),
            cookies::refresh_cookie(&minted.refresh_token, refresh_max_age),
            cookies::csrf_cookie(&cookies::new_csrf(), refresh_max_age),
        ],
    )?;
    Ok(response)
}
