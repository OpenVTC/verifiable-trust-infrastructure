use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vta_sdk::protocols::auth::{
    AuthenticateResponse, ChallengeRequest, ChallengeResponse, Session as WireSession, TokenBundle,
    epoch_to_rfc3339,
};

use crate::acl::{Role, get_acl_entry, is_acl_entry_visible, list_acl_entries, resolve_auth_role};
use crate::auth::session::{
    Session, SessionState, delete_session, get_session, list_sessions, now_epoch,
    store_refresh_index, store_session,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth};
use crate::error::AppError;
use crate::routes::acl::as_vti_acl_entry;
use crate::server::AppState;
use tracing::{info, warn};
use vti_common::store::KeyspaceHandle;

// ---------- POST /auth/challenge ----------

/// Thin dispatcher — every substantive concern (ACL, rate
/// limit, session persistence) lives in the canonical handler.
#[utoipa::path(
    post, path = "/auth/challenge", tag = "auth",
    request_body = ChallengeRequest,
    responses(
        (status = 200, description = "DID-auth challenge nonce", body = ChallengeResponse),
        (status = 401, description = "ACL gate rejected the subject DID"),
    ),
)]
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let backend = crate::auth::VtcAuthBackend::from_state(&state).await?;
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

// ---------- POST /auth/ ----------

/// `POST /v1/auth/` — verify a DIDComm/SIOP/Trust-Task authentication
/// document and issue access + refresh tokens. Unauthenticated.
#[utoipa::path(
    post, path = "/auth/", tag = "auth",
    request_body(content = String, description = "DIDComm envelope, SIOP id_token envelope, or Trust-Task auth document"),
    responses(
        (status = 200, description = "Access + refresh tokens"),
        (status = 401, description = "Authentication failed (bad proof, challenge mismatch, or replay)"),
    ),
)]
pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    Ok(Json(authenticate_and_mint(&state, &body).await?))
}

/// Clock skew tolerance for SIOP `id_token` freshness checks, matching
/// did-hosting-control so a wallet token minted against either service
/// validates identically.
const SIOP_CLOCK_SKEW_SECS: u64 = 60;

/// The VTA-wallet SIOP login envelope: `{ type, payload }` where the
/// payload carries a self-issued `id_token`. Field names are snake_case
/// on the wire (no `rename_all`), matching what the wallet extension and
/// did-hosting-control's `AuthenticatePayload` use.
#[derive(Debug, Deserialize)]
struct SiopAuthEnvelope {
    #[serde(rename = "type")]
    typ: String,
    payload: SiopAuthPayload,
}

#[derive(Debug, Deserialize)]
struct SiopAuthPayload {
    /// Self-issued SIOPv2 id_token (compact EdDSA JWS). Required — its
    /// presence is what distinguishes this from a DIDComm-packed body.
    id_token: String,
    session_id: String,
    #[serde(default)]
    session_pubkey_b58btc: Option<String>,
}

/// Try to authenticate a VTA-wallet SIOP `id_token`.
///
/// Returns `Ok(None)` when `body` is not a SIOP envelope (no
/// `payload.id_token`), so the caller falls through to the DIDComm
/// path. Returns `Ok(Some(_))` on a successfully verified token, or an
/// `Err` when the body *is* a SIOP envelope but verification fails.
///
/// The wallet does the SIOP round-trip internally: it fetched a
/// challenge from `/auth/challenge`, the holder self-issued an
/// `id_token` with `nonce = challenge` and `aud = <this VTC's DID>`,
/// and posted it here. We verify the signature (via the shared
/// `vti_common` verifier), bind `aud` to our own DID and check
/// freshness, then hand the holder DID + nonce to the same canonical
/// `handle_authenticate` the DIDComm path uses — `nonce` becomes the
/// `challenge` the session is matched against.
async fn authenticate_siop(
    state: &AppState,
    body: &str,
) -> Result<Option<AuthenticateResponse>, AppError> {
    // Not a SIOP envelope → fall through to the DIDComm path.
    let Ok(env) = serde_json::from_str::<SiopAuthEnvelope>(body) else {
        return Ok(None);
    };
    if env.typ.as_str() != "https://trusttasks.org/spec/auth/authenticate/0.1"
        || env.payload.id_token.is_empty()
    {
        return Ok(None);
    }

    // SSRF hardening: bind the token's (unverified) `iss` to an existing
    // challenge session *before* resolving it. `verify_siop_id_token`
    // resolves `iss` — an HTTP fetch for did:web/webvh — so without this an
    // unauthenticated caller could steer the daemon into resolving an
    // arbitrary attacker-chosen DID. A session only exists for a DID that
    // passed the ACL gate at challenge time, so resolution is confined to a
    // known, authorised DID. These checks are not authoritative (the holder
    // hasn't proven control of `iss` yet) — `handle_authenticate` below
    // re-verifies everything; they exist purely to gate the network call.
    let unverified_iss = vti_common::auth::parse_unverified_iss(&env.payload.id_token)
        .map_err(|e| AppError::Authentication(format!("id_token: {e}")))?;
    let session = crate::auth::session::get_session(&state.sessions_ks, &env.payload.session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;
    if unverified_iss != session.did {
        return Err(AppError::Authentication(
            "id_token `iss` does not match the challenge session's DID".into(),
        ));
    }

    let resolver = state.did_resolver.as_ref().ok_or_else(|| {
        AppError::Authentication("DID resolver not configured; cannot verify id_token".into())
    })?;

    // Cryptographic verification (signature + self-issuance + key
    // binding). Policy checks (aud, nonce, freshness) are ours below.
    let verified = vti_common::auth::verify_siop_id_token(&env.payload.id_token, resolver)
        .await
        .map_err(|e| AppError::Authentication(format!("id_token verification failed: {e}")))?;

    // Audience binding: the token must be addressed to *this* VTC's DID.
    let vtc_did = {
        let cfg = state.config.read().await;
        cfg.vtc_did.clone()
    }
    .ok_or_else(|| AppError::Authentication("VTC DID not configured".into()))?;
    if verified.audience != vtc_did {
        return Err(AppError::Authentication(
            "id_token `aud` does not match this service".into(),
        ));
    }

    // Freshness window (mirrors did-hosting-control).
    let now = now_epoch();
    if verified.expires_at <= now {
        return Err(AppError::Authentication("id_token has expired".into()));
    }
    if verified.issued_at > now.saturating_add(SIOP_CLOCK_SKEW_SECS) {
        return Err(AppError::Authentication(
            "id_token `iat` is in the future".into(),
        ));
    }
    if verified.issued_at > verified.expires_at {
        return Err(AppError::Authentication(
            "id_token `iat` is after `exp`".into(),
        ));
    }

    // Optional session-bound pubkey must be an Ed25519 multikey.
    if let Some(pk) = env.payload.session_pubkey_b58btc.as_deref()
        && !pk.starts_with("z6Mk")
    {
        return Err(AppError::Authentication(
            "session_pubkey_b58btc must be an Ed25519 multikey (z6Mk… prefix)".into(),
        ));
    }

    let backend = crate::auth::VtcAuthBackend::from_state(state).await?;
    let resp = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id: env.payload.session_id,
            // The SIOP `nonce` is the challenge the session was issued.
            challenge: verified.nonce,
            // The holder DID, proven by the verified signature.
            signer_did: verified.issuer,
            // REST path — no DIDComm `created_time` to thread.
            created_time: None,
            session_pubkey_b58btc: env.payload.session_pubkey_b58btc,
        },
    )
    .await?;
    Ok(Some(resp))
}

/// Core authenticate + mint logic shared by `POST /v1/auth/` and
/// `POST /v1/auth/admin-login`. Both endpoints accept the same
/// DIDComm-packed authentication message; `admin-login`
/// additionally returns `Set-Cookie` headers so the admin SPA can
/// carry a cookie session beside the bearer token.
async fn authenticate_and_mint(
    state: &AppState,
    body: &str,
) -> Result<AuthenticateResponse, AppError> {
    // VTA-wallet SIOP login: a `{ type, payload: { id_token, … } }`
    // envelope. Returns `None` for a DIDComm-packed body, so that path
    // below is left untouched.
    if let Some(resp) = authenticate_siop(state, body).await? {
        return Ok(resp);
    }

    let atm = state
        .atm
        .as_ref()
        .ok_or_else(|| AppError::Authentication("ATM not configured".into()))?;

    let (msg, _metadata) = atm
        .unpack(body)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Canonical Trust-Task URI only; the legacy `affinidi.com/atm/1.0`
    // alias was removed (all VTC clients emit the canonical type).
    if msg.typ.as_str() != "https://trusttasks.org/spec/auth/authenticate/0.1" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    let challenge = msg.body["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?
        .to_string();
    let session_id = msg.body["session_id"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?
        .to_string();

    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;
    let sender_base = sender_did
        .split('#')
        .next()
        .unwrap_or(sender_did)
        .to_string();

    let backend = crate::auth::VtcAuthBackend::from_state(state).await?;
    vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id,
            challenge,
            signer_did: sender_base,
            // Freshness window enforcement: closes M3 — was
            // previously passing `None`, skipping the
            // `created_time` check entirely.
            created_time: msg.created_time,
            session_pubkey_b58btc: None,
        },
    )
    .await
}

// ---------- POST /auth/admin-login ----------

/// `POST /v1/auth/admin-login` (Phase 5 M5.2.3).
///
/// Same DIDComm-packed authentication flow as `POST /v1/auth/`,
/// but the response additionally carries `Set-Cookie` headers so
/// the admin SPA can drive subsequent requests via the cookie
/// session:
///
/// - `vtc_admin_session=<jwt>; Path=/; SameSite=Strict; Secure;
///   HttpOnly` — the access token JWT, scoped to the daemon's
///   whole origin so the browser sends it on `/v1/*` API calls.
///   `HttpOnly` keeps JS from reading it; `SameSite=Strict`
///   prevents cross-site CSRF.
/// - `csrf=<random>; Path=/; SameSite=Strict; Secure` (HttpOnly:
///   **false** so SPA JS can mirror the value to the
///   `X-CSRF-Token` header for the double-submit check in
///   `routing::csrf`).
///
/// Programmatic clients (cnm-cli, DIDComm bridges) keep using
/// `POST /v1/auth/` — same JWT shape, no cookie side effects.
#[utoipa::path(
    post, path = "/auth/admin-login", tag = "auth",
    request_body(content = String, description = "DIDComm/SIOP/Trust-Task authentication document"),
    responses(
        (status = 200, description = "Access + refresh tokens (sets admin session + CSRF cookies)"),
        (status = 401, description = "Authentication failed"),
    ),
)]
pub async fn admin_login(
    State(state): State<AppState>,
    body: String,
) -> Result<axum::response::Response, AppError> {
    use axum::http::HeaderValue;
    use axum::http::header::SET_COOKIE;
    use axum::response::IntoResponse;

    let resp = authenticate_and_mint(&state, &body).await?;

    // Absolute expiry from canonical { session, tokens }: prefer the
    // helper, fall back to tokens.expires_in (sec-from-issuance) for
    // older clients of authenticate_and_mint that emit unparseable
    // issuedAt (shouldn't happen — every minter goes through
    // epoch_to_rfc3339).
    let access_expires_at_epoch = resp
        .access_expires_at_epoch()
        .unwrap_or_else(|| now_epoch().saturating_add(resp.tokens.expires_in));
    let max_age = access_expires_at_epoch.saturating_sub(now_epoch()).max(1);

    // Generate a 32-byte CSRF token, hex-encoded. The cookie is
    // JS-readable (HttpOnly off) so the SPA can echo it back via
    // the `X-CSRF-Token` header on mutating requests.
    use rand::RngExt;
    let mut csrf_bytes = [0u8; 32];
    rand::rng().fill(&mut csrf_bytes);
    let csrf = hex::encode(csrf_bytes);

    let session_cookie = build_session_cookie(&resp.tokens.access_token, max_age);
    let csrf_cookie = build_csrf_cookie(&csrf, max_age);

    let session_cookie_hv = HeaderValue::try_from(session_cookie)
        .map_err(|e| AppError::Internal(format!("invalid session cookie value: {e}")))?;
    let csrf_cookie_hv = HeaderValue::try_from(csrf_cookie)
        .map_err(|e| AppError::Internal(format!("invalid csrf cookie value: {e}")))?;

    let mut response = Json(resp).into_response();
    let headers = response.headers_mut();
    headers.append(SET_COOKIE, session_cookie_hv);
    headers.append(SET_COOKIE, csrf_cookie_hv);

    Ok(response)
}

// ---------- POST /auth/admin-session ----------

/// Request body for [`admin_session`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct AdminSessionRequest {
    /// A valid VTC access token the caller already holds — e.g. from the
    /// VTA-wallet SIOP login, which returns it in `tokens.accessToken`.
    pub access_token: String,
}

/// `POST /v1/auth/admin-session` — exchange a bearer access token for the
/// admin SPA's cookie session.
///
/// The VTA-wallet login path returns a bearer token in the response body
/// (the wallet extension posts the SIOP `id_token` to `/wallet/auth/` and
/// reads `tokens.accessToken`), but the admin SPA drives the API with the
/// `vtc_admin_session` cookie + `csrf` double-submit, not an
/// `Authorization` header. This endpoint bridges the two: it validates the
/// presented token (signature + VTC audience + expiry) and, on success,
/// sets the same `Set-Cookie` pair as [`admin_login`].
///
/// No privilege escalation — the caller must already possess a valid VTC
/// access token, which it could use directly as a bearer; this only mirrors
/// it into the cookie the browser SPA expects. Browser-only by nature: the
/// CSRF layer's same-origin check carries the (cookie-less) first call.
#[utoipa::path(
    post, path = "/auth/admin-session", tag = "auth",
    request_body = AdminSessionRequest,
    responses(
        (status = 204, description = "Admin session + CSRF cookies set"),
        (status = 401, description = "Invalid or expired access token"),
    ),
)]
pub async fn admin_session(
    State(state): State<AppState>,
    Json(req): Json<AdminSessionRequest>,
) -> Result<axum::response::Response, AppError> {
    use axum::http::HeaderValue;
    use axum::http::header::SET_COOKIE;
    use axum::response::IntoResponse;
    use rand::RngExt;

    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Internal("JWT keys not configured".into()))?;

    // Validate the token: signature, VTC audience (audience isolation — a
    // foreign-audience token is rejected here exactly as on every other
    // surface), and expiry. A bad token never sets a cookie.
    let claims = jwt_keys
        .decode(&req.access_token)
        .map_err(|_| AppError::Authentication("invalid or expired access token".into()))?;

    let max_age = claims.exp.saturating_sub(now_epoch()).max(1);

    let mut csrf_bytes = [0u8; 32];
    rand::rng().fill(&mut csrf_bytes);
    let csrf = hex::encode(csrf_bytes);

    let session_cookie = build_session_cookie(&req.access_token, max_age);
    let csrf_cookie = build_csrf_cookie(&csrf, max_age);

    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.append(
        SET_COOKIE,
        HeaderValue::try_from(session_cookie)
            .map_err(|e| AppError::Internal(format!("invalid session cookie value: {e}")))?,
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::try_from(csrf_cookie)
            .map_err(|e| AppError::Internal(format!("invalid csrf cookie value: {e}")))?,
    );
    Ok(response)
}

// ---------- POST /auth/passkey-login/start ----------

/// `POST /v1/auth/passkey-login/start`.
///
/// Browser-friendly login: the admin SPA submits no body, the
/// daemon returns a WebAuthn assertion challenge across every
/// registered passkey (discoverable login — the user picks their
/// device, the browser chooses the matching credential). Modelled
/// on `affinidi-webvh-service::login_start`.
///
/// Unauthenticated by design: the eventual `finish` ceremony
/// proves possession of an enrolled credential, which is the auth.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PasskeyLoginStartResponse {
    pub auth_id: String,
    #[schema(value_type = Object)]
    pub options: webauthn_rs::prelude::RequestChallengeResponse,
}

/// `POST /v1/auth/passkey-login/start` — issue a WebAuthn assertion
/// challenge across every registered passkey. Unauthenticated.
#[utoipa::path(
    post, path = "/auth/passkey-login/start", tag = "auth",
    responses(
        (status = 200, description = "WebAuthn assertion challenge", body = PasskeyLoginStartResponse),
        (status = 401, description = "WebAuthn not configured or no passkeys registered"),
    ),
)]
pub async fn passkey_login_start(
    State(state): State<AppState>,
) -> Result<Json<PasskeyLoginStartResponse>, AppError> {
    use vti_common::auth::passkey::store::{get_all_passkeys, store_auth_state};

    let webauthn = state
        .webauthn
        .as_ref()
        .ok_or_else(|| AppError::Authentication("WebAuthn not configured".into()))?;

    let passkeys = get_all_passkeys(&state.passkey_ks).await?;
    if passkeys.is_empty() {
        warn!("passkey login refused: no passkeys registered");
        return Err(AppError::Authentication(
            "no passkeys registered on this server".into(),
        ));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn auth start failed: {e}")))?;

    let auth_id = Uuid::new_v4().to_string();
    store_auth_state(&state.passkey_ks, &auth_id, &auth_state).await?;

    info!(
        auth_id = %auth_id,
        passkey_count = passkeys.len(),
        "passkey login challenge issued"
    );

    Ok(Json(PasskeyLoginStartResponse {
        auth_id,
        options: rcr,
    }))
}

// ---------- POST /auth/passkey-login/finish ----------

/// `POST /v1/auth/passkey-login/finish`.
///
/// Verifies the WebAuthn assertion, looks up the registered
/// admin DID by credential ID, and mints the cookie session.
/// Sets the same `vtc_admin_session` + `csrf` cookies as
/// `admin_login` does for the DIDComm CLI path. Returns the bearer
/// token in the body for clients that want to also use it
/// programmatically.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PasskeyLoginFinishRequest {
    pub auth_id: String,
    #[schema(value_type = Object)]
    pub credential: webauthn_rs::prelude::PublicKeyCredential,
}

/// `POST /v1/auth/passkey-login/finish` — verify the WebAuthn assertion
/// and mint a cookie session + bearer token. Unauthenticated.
#[utoipa::path(
    post, path = "/auth/passkey-login/finish", tag = "auth",
    request_body = PasskeyLoginFinishRequest,
    responses(
        (status = 200, description = "Access + refresh tokens (sets admin session + CSRF cookies)"),
        (status = 401, description = "Passkey assertion verification failed or credential not registered"),
    ),
)]
pub async fn passkey_login_finish(
    State(state): State<AppState>,
    Json(req): Json<PasskeyLoginFinishRequest>,
) -> Result<axum::response::Response, AppError> {
    use axum::http::HeaderValue;
    use axum::http::header::SET_COOKIE;
    use vti_common::auth::passkey::store::{
        get_passkey_user_by_cred, store_passkey_user, take_auth_state,
    };

    let webauthn = state
        .webauthn
        .as_ref()
        .ok_or_else(|| AppError::Authentication("WebAuthn not configured".into()))?;
    // JWT-keys presence is enforced by `VtcAuthBackend::from_state` at the
    // mint step below (the shared minter owns token issuance now).

    let auth_state = take_auth_state(&state.passkey_ks, &req.auth_id)
        .await?
        .ok_or_else(|| AppError::Authentication("auth state not found or expired".into()))?;

    let auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            warn!(auth_id = %req.auth_id, error = %e, "passkey authentication failed");
            AppError::Authentication(format!("passkey authentication failed: {e}"))
        })?;

    let cred_id_hex = hex::encode(auth_result.cred_id());
    let mut user = get_passkey_user_by_cred(&state.passkey_ks, &cred_id_hex)
        .await?
        .ok_or_else(|| AppError::Authentication("credential not registered".into()))?;

    // Persist credential-counter update (WebAuthn replay protection).
    for cred in &mut user.credentials {
        cred.update_credential(&auth_result);
    }
    store_passkey_user(&state.passkey_ks, &user).await?;

    // Check ACL — the DID must still be authorised; revocation
    // since enrolment is a real path (operator demoted, etc.).
    // Uses the VTC-aware resolver so a demoted-to-VtcRole row yields a
    // clean 403, not a 500 in the VTA-taxonomy deserializer (P0.16).
    let (role, allowed_contexts) = resolve_auth_role(&state.acl_ks, &user.did).await?;

    // Mint access + refresh tokens through the shared minter so the
    // passkey path gets the same `aal2` short access TTL + Authenticated
    // audit as the canonical `/auth/` handler (P1.4) — previously this
    // hand-rolled the mint with the full `aal1` TTL, giving the one
    // token class the hardening protects the longest exposure.
    // Passkey-login: amr=["passkey"], acr="aal2" — the WebAuthn
    // assertion alone is two factors (possession of the authenticator +
    // a user-verification gesture / biometric).
    let backend = crate::auth::VtcAuthBackend::from_state(&state).await?;
    let session_id = Uuid::new_v4().to_string();
    let amr = vec!["passkey".to_string()];
    let acr = "aal2".to_string();
    let minted = vti_common::auth::handlers::mint_session_tokens(
        &backend,
        &user.did,
        &session_id,
        &role,
        &allowed_contexts,
        &amr,
        &acr,
        false,
    )
    .await?;

    // Persist the session record so `/auth/sessions` lists it and
    // refresh-token rotation finds it. AAL is captured so refresh keeps
    // the holder at aal2 instead of dropping to aal1 on every rotation.
    let session = Session {
        session_id: session_id.clone(),
        did: user.did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: minted.issued_at,
        refresh_token: Some(minted.refresh_token.clone()),
        refresh_expires_at: Some(minted.refresh_expires_at),
        tee_attested: false,
        amr: amr.clone(),
        acr: acr.clone(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&state.sessions_ks, &session).await?;
    store_refresh_index(&state.sessions_ks, &minted.refresh_token, &session_id).await?;

    info!(did = %user.did, %session_id, "passkey login successful");

    // Set cookies — same shape as `admin_login`.
    let max_age = minted.access_expires_at.saturating_sub(now_epoch()).max(1);
    let session_cookie = build_session_cookie(&minted.access_token, max_age);

    use rand::RngExt;
    let mut csrf_bytes = [0u8; 32];
    rand::rng().fill(&mut csrf_bytes);
    let csrf = hex::encode(csrf_bytes);
    let csrf_cookie = build_csrf_cookie(&csrf, max_age);

    let resp = AuthenticateResponse {
        session: WireSession {
            id: session_id.clone(),
            subject: user.did.clone(),
            issued_at: epoch_to_rfc3339(minted.issued_at),
            expires_at: epoch_to_rfc3339(minted.access_expires_at),
            amr: amr.clone(),
            acr: acr.clone(),
        },
        tokens: TokenBundle {
            access_token: minted.access_token.clone(),
            refresh_token: Some(minted.refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: minted.access_ttl,
            refresh_expires_in: Some(minted.refresh_expires_at.saturating_sub(minted.issued_at)),
            scope: Vec::new(),
        },
    };

    let mut response = Json(resp).into_response();
    let headers = response.headers_mut();
    headers.append(
        SET_COOKIE,
        HeaderValue::try_from(session_cookie)
            .map_err(|e| AppError::Internal(format!("invalid session cookie: {e}")))?,
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::try_from(csrf_cookie)
            .map_err(|e| AppError::Internal(format!("invalid csrf cookie: {e}")))?,
    );

    Ok(response)
}

/// Build the `vtc_admin_session` cookie value.
///
/// `Path=/` (not `/admin`) so the browser sends the cookie on
/// requests to `/v1/*` — the admin SPA needs the cookie on every
/// authenticated API call, and the API doesn't live under `/admin`.
/// The earlier M5.3.1 design used `Path=/admin` to keep the cookie
/// scoped, but `HttpOnly` already blocks JS exfiltration on any
/// path and `SameSite=Strict` prevents cross-site CSRF — the Path
/// restriction added no security in exchange for breaking the
/// cookie-based SPA-→-API path entirely.
fn build_session_cookie(access_token: &str, max_age: u64) -> String {
    format!(
        "{name}={access_token}; Path=/; Max-Age={max_age}; SameSite=Strict; Secure; HttpOnly",
        name = vti_common::auth::extractor::ADMIN_SESSION_COOKIE,
    )
}

/// Build the companion CSRF cookie. `HttpOnly` is intentionally
/// **not** set — the SPA needs to read this from
/// `document.cookie` and mirror its value into the
/// `X-CSRF-Token` header on every mutating request.
fn build_csrf_cookie(csrf: &str, max_age: u64) -> String {
    format!("csrf={csrf}; Path=/; Max-Age={max_age}; SameSite=Strict; Secure")
}

#[cfg(test)]
mod cookie_format_tests {
    use super::*;

    /// The session cookie is `Path=/` so the browser sends it on
    /// every same-origin request — `/v1/*` (API) and `/admin/*`
    /// (SPA). HttpOnly + SameSite=Strict are what actually
    /// constrain the cookie's reachability; an earlier
    /// `Path=/admin` scoping broke the cookie-based SPA-→-API
    /// path without adding security (HttpOnly already prevents JS
    /// exfiltration on any path).
    #[test]
    fn session_cookie_path_is_root() {
        let c = build_session_cookie("jwt.token.value", 900);
        assert!(c.contains("Path=/;"), "got {c}");
    }

    #[test]
    fn session_cookie_has_security_flags() {
        let c = build_session_cookie("jwt.token.value", 900);
        // All three flags are load-bearing — losing any one is
        // a CSRF / cookie-theft / TLS-stripping regression.
        assert!(c.contains("HttpOnly"), "got {c}");
        assert!(c.contains("Secure"), "got {c}");
        assert!(c.contains("SameSite=Strict"), "got {c}");
    }

    #[test]
    fn csrf_cookie_is_root_scoped_but_not_httponly() {
        let c = build_csrf_cookie("abc123", 900);
        // CSRF cookie is intentionally readable by JS so the
        // SPA can mirror it into `X-CSRF-Token`.
        assert!(c.contains("Path=/"), "got {c}");
        assert!(
            !c.contains("HttpOnly"),
            "CSRF cookie must be JS-readable: {c}"
        );
        assert!(c.contains("Secure"), "got {c}");
        assert!(c.contains("SameSite=Strict"), "got {c}");
    }

    #[test]
    fn session_cookie_uses_canonical_name() {
        let c = build_session_cookie("t", 1);
        assert!(
            c.starts_with(&format!(
                "{}=",
                vti_common::auth::extractor::ADMIN_SESSION_COOKIE
            )),
            "got {c}"
        );
    }
}

// ---------- POST /auth/refresh ----------

/// `POST /v1/auth/refresh` — exchange the presented refresh
/// token for a new access + refresh pair.
///
/// Returns the canonical `AuthenticateResponse { session, tokens }`
/// shape (replaces the legacy `{ sessionId, data: { accessToken,
/// accessExpiresAt } }`). The full token-rotation logic — atomic
/// claim, refresh-expiry check, ACL re-look-up, AAL preservation
/// across rotation, RFC 6749 §10.4 rotation semantics — lives in
/// the canonical handler in vti-common.
#[utoipa::path(
    post, path = "/auth/refresh", tag = "auth",
    request_body(content = String, description = "DIDComm envelope or Trust-Task refresh document"),
    responses(
        (status = 200, description = "Rotated access + refresh tokens"),
        (status = 401, description = "Refresh token not found, revoked, or already used"),
    ),
)]
pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let atm = state
        .atm
        .as_ref()
        .ok_or_else(|| AppError::Authentication("ATM not configured".into()))?;

    let (msg, _metadata) = atm
        .unpack(&body)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Canonical Trust-Task URI only; the legacy
    // `affinidi.com/atm/1.0/authenticate/refresh` alias was removed.
    if msg.typ.as_str() != "https://trusttasks.org/spec/auth/refresh/0.1" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    let refresh_token = msg.body["refresh_token"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?
        .to_string();
    let sender_base = msg
        .from
        .as_deref()
        .map(|s| s.split('#').next().unwrap_or(s).to_string());

    let backend = crate::auth::VtcAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            signer_did: sender_base,
        },
    )
    .await?;
    Ok(Json(resp))
}

// ---------- GET /auth/sessions ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct SessionSummary {
    pub session_id: String,
    pub did: String,
    pub state: SessionState,
    pub created_at: u64,
    pub refresh_expires_at: Option<u64>,
}

impl From<Session> for SessionSummary {
    fn from(s: Session) -> Self {
        Self {
            session_id: s.session_id,
            did: s.did,
            state: s.state,
            created_at: s.created_at,
            refresh_expires_at: s.refresh_expires_at,
        }
    }
}

// ---------- GET /auth/whoami ----------

/// Wire shape returned by `whoami`. Minimal: enough for the admin
/// SPA's nav header to show "Signed in as …" with a role badge,
/// without needing to decode the JWT client-side (the session
/// cookie is HttpOnly).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct WhoamiResponse {
    pub did: String,
    pub role: String,
    pub session_id: String,
    pub access_expires_at: u64,
    pub allowed_contexts: Vec<String>,
}

/// `GET /v1/auth/whoami` — returns the caller's identity claims
/// pulled from the access token. Lets browser SPAs render a
/// "signed in as" indicator without exposing the JWT to JS (the
/// session cookie is HttpOnly by design).
#[utoipa::path(
    get, path = "/auth/whoami", tag = "auth",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Caller identity claims", body = WhoamiResponse),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn whoami(auth: AuthClaims) -> Json<WhoamiResponse> {
    Json(WhoamiResponse {
        did: auth.did,
        role: auth.role.to_string(),
        session_id: auth.session_id,
        access_expires_at: auth.access_expires_at,
        allowed_contexts: auth.allowed_contexts,
    })
}

// ---------- POST /auth/sign-out ----------

/// `POST /v1/auth/sign-out` — revoke the caller's session and
/// expire the cookie pair. The cookies' HttpOnly flag means JS
/// can't clear them itself — only the server can issue
/// `Set-Cookie: ...; Max-Age=0` to delete from the browser's jar.
#[utoipa::path(
    post, path = "/auth/sign-out", tag = "auth",
    security(("bearer_jwt" = [])),
    responses(
        (status = 204, description = "Session revoked and session/CSRF cookies cleared"),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn sign_out(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<axum::response::Response, AppError> {
    use axum::http::HeaderValue;
    use axum::http::header::SET_COOKIE;

    let sessions = state.sessions_ks.clone();
    // Best-effort delete — the session may already have been
    // revoked from another tab. Either way we set the expiry
    // cookies so this browser stops sending the stale JWT.
    let _ = delete_session(&sessions, &auth.session_id).await;
    info!(did = %auth.did, session_id = %auth.session_id, "sign-out");

    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    let session_clear = format!(
        "{name}=; Path=/; Max-Age=0; SameSite=Strict; Secure; HttpOnly",
        name = vti_common::auth::extractor::ADMIN_SESSION_COOKIE,
    );
    let csrf_clear = "csrf=; Path=/; Max-Age=0; SameSite=Strict; Secure".to_string();
    headers.append(
        SET_COOKIE,
        HeaderValue::try_from(session_clear)
            .map_err(|e| AppError::Internal(format!("invalid session cookie: {e}")))?,
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::try_from(csrf_clear)
            .map_err(|e| AppError::Internal(format!("invalid csrf cookie: {e}")))?,
    );
    Ok(response)
}

/// `GET /v1/auth/sessions` — list active sessions visible to the caller.
/// Super-admin sees all; context-admin sees only sessions in their contexts.
#[utoipa::path(
    get, path = "/auth/sessions", tag = "auth",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Active sessions", body = [SessionSummary]),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin/initiator"),
    ),
)]
pub async fn session_list(
    auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionSummary>>, AppError> {
    let sessions = state.sessions_ks.clone();
    let all = list_sessions(&sessions).await?;

    // A super-admin sees the whole roster; a context-admin must only see
    // sessions whose subject DID is an ACL entry visible to them (overlapping
    // contexts). Build the visible-DID set once from the ACL rather than doing
    // a per-session lookup. A session whose subject has no ACL entry (e.g. the
    // entry was deleted out from under it) is visible only to a super-admin.
    let summaries: Vec<SessionSummary> = if auth.0.is_super_admin() {
        all.into_iter().map(SessionSummary::from).collect()
    } else {
        let acl = state.acl_ks.clone();
        let visible: std::collections::HashSet<String> = list_acl_entries(&acl)
            .await?
            .into_iter()
            .filter(|e| is_acl_entry_visible(&auth.0, &as_vti_acl_entry(e)))
            .map(|e| e.did)
            .collect();
        all.into_iter()
            .filter(|s| visible.contains(&s.did))
            .map(SessionSummary::from)
            .collect()
    };
    info!(caller = %auth.0.did, count = summaries.len(), "sessions listed");
    Ok(Json(summaries))
}

// ---------- DELETE /auth/sessions/{session_id} ----------

/// `DELETE /v1/auth/sessions/{session_id}` — revoke a single session
/// (caller's own, or any if admin).
#[utoipa::path(
    delete, path = "/auth/sessions/{session_id}", tag = "auth",
    security(("bearer_jwt" = [])),
    params(("session_id" = String, Path, description = "Session identifier")),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Cannot revoke another user's session"),
        (status = 404, description = "Session not found"),
    ),
)]
pub async fn revoke_session(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let sessions = state.sessions_ks.clone();
    let session = get_session(&sessions, &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("session not found: {session_id}")))?;

    // Allow if caller owns the session or is admin
    if session.did != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "cannot revoke another user's session".into(),
        ));
    }

    delete_session(&sessions, &session_id).await?;
    info!(caller = %auth.did, session_id = %session_id, "session revoked");
    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /auth/sessions?did=X ----------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RevokeByDidQuery {
    pub did: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RevokeByDidResponse {
    pub revoked: u64,
}

/// `DELETE /v1/auth/sessions?did=X` — revoke all sessions for a DID.
/// Super-admin unrestricted; context-admin limited to visible DIDs.
#[utoipa::path(
    delete, path = "/auth/sessions", tag = "auth",
    security(("bearer_jwt" = [])),
    params(("did" = String, Query, description = "Subject DID whose sessions to revoke")),
    responses(
        (status = 200, description = "Sessions revoked", body = RevokeByDidResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller cannot revoke sessions for this DID"),
    ),
)]
pub async fn revoke_sessions_by_did(
    auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<RevokeByDidQuery>,
) -> Result<Json<RevokeByDidResponse>, AppError> {
    // Context-scope: a context-admin may only revoke sessions for a DID whose
    // ACL entry is visible to them (overlapping contexts). Without this any
    // context-admin could revoke a super-admin's or any member's sessions
    // community-wide. Super-admins are unrestricted (and may mop up orphan
    // sessions for a DID with no ACL row).
    if !auth.0.is_super_admin() {
        let acl = state.acl_ks.clone();
        let visible = get_acl_entry(&acl, &query.did)
            .await?
            .as_ref()
            .is_some_and(|e| is_acl_entry_visible(&auth.0, &as_vti_acl_entry(e)));
        if !visible {
            return Err(AppError::Forbidden(
                "cannot revoke sessions for a DID outside your contexts".into(),
            ));
        }
    }

    let sessions = state.sessions_ks.clone();
    let revoked = revoke_sessions_for_did(&sessions, &query.did).await?;

    info!(caller = %auth.0.did, target_did = %query.did, revoked, "sessions revoked by DID");
    Ok(Json(RevokeByDidResponse { revoked }))
}

/// Delete every session whose subject is `did`; returns the count revoked.
///
/// Shared by [`revoke_sessions_by_did`] and the ACL-downgrade path in
/// [`crate::routes::acl::update_acl`], which revokes a demoted admin's live
/// sessions so the still-valid JWT can't outlive the downgrade.
pub(crate) async fn revoke_sessions_for_did(
    sessions: &KeyspaceHandle,
    did: &str,
) -> Result<u64, AppError> {
    let all = list_sessions(sessions).await?;
    let mut revoked = 0u64;
    for session in all {
        if session.did == did {
            delete_session(sessions, &session.session_id).await?;
            revoked += 1;
        }
    }
    Ok(revoked)
}
