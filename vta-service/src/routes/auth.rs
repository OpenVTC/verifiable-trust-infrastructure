//! Passkey-login REST routes.
//!
//! `POST /auth/challenge`, `POST /auth/` (authenticate) and
//! `POST /auth/refresh` used to live here. They are pre-session Trust-Task
//! operations now — `auth/challenge/0.1`, `auth/authenticate/{0.2,0.3}` and
//! `auth/refresh/0.2` — served on `/trust-tasks` by a family-owned dispatch
//! (`trust_tasks::auth::owns` / `dispatch_pre_session`) that runs ahead of the
//! ACL-gated pipeline, exactly like every other Trust Task and over every
//! transport (REST, DIDComm, TSP), rather than on a dedicated unauth REST
//! route reachable only over HTTPS.
//!
//! Passkey login stays REST: it is a WebAuthn ceremony driven from a browser
//! that holds only the bearer token `passkey-login` issues and no DID key
//! with which to sign a Trust Task — the same reason the passkey-VM
//! enrolment routes are the WebAuthn exception in `deprecation::REST_EXCEPTIONS`.

use axum::Json;
use axum::extract::State;
use uuid::Uuid;

use vta_sdk::protocols::auth::AuthenticateResponse;

use crate::acl::check_acl;
use crate::audit::audit;
use crate::auth::session::{Session, SessionState, get_session, now_epoch, store_session};
use crate::error::AppError;
use crate::server::AppState;
use tracing::{info, warn};

// The session routes that sat here — `GET /auth/sessions`,
// `DELETE /auth/sessions/{session_id}` and `DELETE /auth/sessions?did=` — are
// Trust Tasks now, over every transport: `auth/sessions/list/0.1` (the caller's
// own sessions) and `auth/revoke-session/0.2` (one session, all of the caller's,
// or every session of a `subject` the caller may manage — VTI-SES-043,
// VTI-ACL-050). See `trust_tasks::auth`.

// ---------- Passkey login ----------
//
// Per the trust-task migration registry these correspond to:
//   - vta/auth/passkey-login-start/1.0
//   - vta/auth/passkey-login-finish/1.0
//
// They are UNAUTHENTICATED (the user has no session yet) — mounted on the
// same unauth router branch as the pre-session auth family. WebAuthn ceremony,
// not a Trust-Task envelope: see the module doc.

use base64::Engine as _;
use base64::engine::general_purpose;
use vta_sdk::protocols::passkey_login::{
    PasskeyLoginFinishRequest, PasskeyLoginStartRequest, PasskeyLoginStartResponse,
};

use crate::operations::passkey_login::{
    VtaVmResolver, enumerate_passkey_vms, verify_passkey_login,
};

/// POST /auth/passkey-login/start — issue a passkey-bound challenge. Auth: unauthenticated.
#[utoipa::path(
    post, path = "/auth/passkey-login/start", tag = "auth",
    request_body = PasskeyLoginStartRequest,
    responses(
        (status = 200, description = "Passkey login challenge", body = PasskeyLoginStartResponse),
        (status = 403, description = "WebAuthn service disabled or DID not in ACL"),
    ),
)]
pub async fn passkey_login_start(
    State(state): State<AppState>,
    Json(req): Json<PasskeyLoginStartRequest>,
) -> Result<Json<PasskeyLoginStartResponse>, AppError> {
    // Runtime gate: WebAuthn-RP service must be advertised.
    // Returns 403 with a clear message when the service is off so a
    // misconfigured demo doesn't spend operator time on
    // "why isn't login working".
    if !state.config.read().await.services.webauthn {
        return Err(AppError::Forbidden(
            "WebAuthn service is disabled on this VTA.".into(),
        ));
    }

    // ACL gate — same as pre-session auth.
    check_acl(&state.acl_ks, &req.did).await?;

    // Mint challenge.
    let session_id = Uuid::new_v4().to_string();
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);

    // Persist pending session — same shape as the legacy auth challenge
    // so existing JWT-mint plumbing in `passkey_login_finish` can
    // consume it.
    let session = Session {
        session_id: session_id.clone(),
        did: req.did.clone(),
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        // AAL is unknown at challenge time. passkey_login_finish sets
        // it to amr=["did","passkey"], acr="aal2" when the assertion
        // verifies and the session transitions to Authenticated.
        amr: Vec::new(),
        acr: String::new(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&state.sessions_ks, &session).await?;

    // Enumerate the DID's passkey VMs to populate allowCredentials.
    // v0.1 returns empty; browsers fall back to discoverable credentials.
    let allow_credentials = match state.did_resolver.clone() {
        Some(resolver) => {
            let vta_resolver = VtaVmResolver::new(resolver);
            enumerate_passkey_vms(&vta_resolver, &req.did)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|vm| general_purpose::URL_SAFE_NO_PAD.encode(vm.credential_id))
                .collect()
        }
        None => Vec::new(),
    };

    info!(did = %req.did, session_id = %session_id, "passkey login challenge issued");
    audit!(
        "auth.passkey_login_start",
        actor = &req.did,
        resource = &session_id,
        outcome = "success"
    );

    Ok(Json(PasskeyLoginStartResponse {
        session_id,
        challenge,
        allow_credentials,
    }))
}

/// POST /auth/passkey-login/finish — verify the WebAuthn assertion and issue tokens. Auth: unauthenticated.
#[utoipa::path(
    post, path = "/auth/passkey-login/finish", tag = "auth",
    request_body = PasskeyLoginFinishRequest,
    responses(
        (status = 200, description = "Access + refresh tokens", body = AuthenticateResponse),
        (status = 401, description = "Assertion verification failed, challenge expired, or replay"),
        (status = 403, description = "WebAuthn service disabled"),
    ),
)]
pub async fn passkey_login_finish(
    State(state): State<AppState>,
    Json(req): Json<PasskeyLoginFinishRequest>,
) -> Result<Json<AuthenticateResponse>, AppError> {
    // Runtime gate (mirrors `passkey_login_start`).
    if !state.config.read().await.services.webauthn {
        return Err(AppError::Forbidden(
            "WebAuthn service is disabled on this VTA.".into(),
        ));
    }

    let did_resolver = state
        .did_resolver
        .clone()
        .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;

    // 1. Look up pending session.
    let session = get_session(&state.sessions_ks, &req.session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;
    if session.state != SessionState::ChallengeSent {
        warn!(session_id = %req.session_id, "passkey login rejected: session replay");
        return Err(AppError::Authentication(
            "session already authenticated (replay)".into(),
        ));
    }

    // 2. Challenge TTL — gate early so we don't burn a crypto verify on an
    //    expired challenge. (The canonical handler re-checks it too.)
    let challenge_ttl = state.config.read().await.auth.challenge_ttl;
    if now_epoch().saturating_sub(session.created_at) > challenge_ttl {
        warn!(session_id = %req.session_id, "passkey login rejected: challenge expired");
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // 3. Build AssertionPayload.
    let decode = |s: &str, what: &'static str| {
        general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .or_else(|_| general_purpose::URL_SAFE.decode(s.as_bytes()))
            .map_err(|_| AppError::Authentication(format!("{what} is not valid base64url")))
    };
    let assertion = vti_webauthn::AssertionPayload {
        credential_id: decode(&req.credential_id, "credential_id")?,
        authenticator_data: decode(&req.authenticator_data, "authenticator_data")?,
        client_data_json: decode(&req.client_data_json, "client_data_json")?,
        signature: decode(&req.signature, "signature")?,
        verification_method: req.verification_method.clone(),
    };

    // 4. Sanity-check that the assertion is against the DID this
    //    session was issued for — defence in depth before crypto.
    let claimed_did = req
        .verification_method
        .split_once('#')
        .map(|(did, _frag)| did)
        .unwrap_or(&req.verification_method);
    if claimed_did != session.did {
        warn!(
            session_did = %session.did,
            assertion_did = %claimed_did,
            "passkey login rejected: DID mismatch"
        );
        return Err(AppError::Authentication(
            "verification_method DID does not match session DID".into(),
        ));
    }

    // 5. Verify the assertion.
    let public_url = state.config.read().await.public_url.clone();
    let public_url =
        public_url.ok_or_else(|| AppError::Config("public_url not configured".into()))?;
    let config = vti_webauthn::VerifierConfig::from_public_url(&public_url, true)
        .map_err(|e| AppError::Config(format!("invalid public_url: {e}")))?;
    let resolver = VtaVmResolver::new(did_resolver);
    let _verified =
        verify_passkey_login(&assertion, session.challenge.as_bytes(), &resolver, &config)
            .await
            .map_err(|e| AppError::Authentication(format!("assertion verification failed: {e}")))?;

    // 6. Mint tokens through the single canonical authenticate path
    //    (`handle_authenticate_with_aal`) rather than re-deriving the
    //    session/JWT/refresh-token logic here (P1.4). Passkey-login is the
    //    second factor — the DID-key was challenged first via the challenge
    //    endpoint, then this WebAuthn assertion proved possession of a passkey
    //    VM — so we issue `amr=["did","passkey"], acr="aal2"`. The challenge was
    //    already verified cryptographically above (step 5), so we pass the
    //    session's own challenge for the handler's constant-time match. Routing
    //    through the handler also applies the acr-correct (shortened) aal2
    //    access-token TTL, which the bespoke mint here did not.
    let backend = crate::auth::VtaAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_authenticate_with_aal(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id: session.session_id.clone(),
            challenge: session.challenge.clone(),
            signer_did: session.did.clone(),
            created_time: None,
            session_pubkey_b58btc: None,
            audience: vti_common::auth::AudienceBinding::Transport,
        },
        vec!["did".to_string(), "passkey".to_string()],
        "aal2".to_string(),
    )
    .await?;

    info!(did = %session.did, session_id = %session.session_id, "passkey login successful");
    audit!(
        "auth.passkey_login_finish",
        actor = &session.did,
        resource = &session.session_id,
        outcome = "success"
    );

    Ok(Json(resp))
}
