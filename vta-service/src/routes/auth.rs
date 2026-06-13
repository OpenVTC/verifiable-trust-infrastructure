use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::authenticate::v0_1 as authenticate;
use trust_tasks_rs::specs::auth::refresh::v0_1 as refresh;
use uuid::Uuid;

use vta_sdk::protocols::auth::{AuthenticateResponse, ChallengeRequest};

use crate::acl::{Role, check_acl};
use crate::audit::audit;
use crate::auth::session::{
    Session, SessionState, delete_session, get_session, list_sessions, now_epoch, store_session,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth};
use crate::error::AppError;
use crate::server::AppState;
use tracing::{info, warn};

// ---------- POST /auth/challenge ----------

/// POST /auth/challenge — issue a DID-auth challenge nonce for a session. Auth: unauthenticated.
///
/// Thin dispatcher: builds [`vti_common::auth::ChallengeInput`]
/// from the JSON request, builds a [`VtaAuthBackend`] from
/// state, and calls [`vti_common::auth::handlers::handle_challenge`].
/// Everything substantive — ACL gate, per-DID rate limit, TEE
/// attestation hook, session persistence — lives in the
/// canonical handler. The route-layer concerns kept here are
/// just JSON deserialisation and the audit-macro emission
/// (vti-common's default `audit` hook uses `tracing::info!`
/// without VTA's HMAC-actor-hash audit envelope).
pub async fn challenge(State(state): State<AppState>, body: String) -> Result<Response, AppError> {
    // Canonical path: an `auth/challenge/0.1` Trust Task → a TT `#response`
    // document (what `vta-mobile-core::build_auth_challenge` /
    // `parse_auth_challenge_response` speak). Falls through to the flat
    // `{ did }` request used by the SDK / CLI REST clients.
    if let Some(resp) = try_challenge_trust_task(&state, &body).await? {
        return Ok(resp);
    }

    let req: ChallengeRequest = serde_json::from_str(&body)
        .map_err(|e| AppError::Validation(format!("challenge request body: {e}")))?;
    let backend = crate::auth::VtaAuthBackend::from_state(&state).await?;
    let did_for_audit = req.did.clone();
    let resp = vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: req.did,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    audit!(
        "auth.challenge",
        actor = &did_for_audit,
        resource = &resp.session_id,
        outcome = "success"
    );
    Ok(Json(resp).into_response())
}

/// Try to issue a challenge from an `auth/challenge/0.1` Trust Task document,
/// returning a TT `#response` document so the canonical (engine) client can
/// `parse_auth_challenge_response` it. `Ok(None)` ⇒ not such a document, fall
/// through to the flat `{ did }` request.
async fn try_challenge_trust_task(
    state: &AppState,
    body: &str,
) -> Result<Option<Response>, AppError> {
    let doc: TrustTask<Value> = match serde_json::from_str(body) {
        Ok(doc) => doc,
        Err(_) => return Ok(None),
    };
    if doc.type_uri.to_string() != vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1 {
        return Ok(None);
    }
    // Challenge carries no proof; the subject is the document's stated holder.
    // (Same trust model as the flat `{ did }` request — challenge issuance is
    // pre-auth and ACL-gated.)
    let subject = doc
        .payload
        .get("subject")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("auth/challenge payload missing `subject`".into()))?
        .to_string();

    let backend = crate::auth::VtaAuthBackend::from_state(state).await?;
    let resp = vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: subject.clone(),
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    audit!(
        "auth.challenge",
        actor = &subject,
        resource = &resp.session_id,
        outcome = "success"
    );
    // The `challenge/0.1#response` payload — exactly the fields the engine
    // parses (no `teeAttestation`; the generated Response denies unknowns).
    let payload = json!({
        "challenge": resp.challenge,
        "sessionId": resp.session_id,
        "expiresAt": resp.expires_at,
    });
    let response_doc = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    Ok(Some(Json(response_doc).into_response()))
}

// ---------- POST /auth/ ----------

/// Wrap a flat `AuthenticateResponse` as a Trust Task `#response` document
/// addressed back to the requester. Used for callers that sent a TT request
/// doc (authenticate + refresh share the `{ tokens, session }` response
/// payload); `vta-mobile-core::parse_{authenticate,refresh}_response` parse it.
fn tokens_response_doc(request: &TrustTask<Value>, resp: &AuthenticateResponse) -> Response {
    let payload = json!({ "tokens": resp.tokens, "session": resp.session });
    let response_doc = request.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    Json(response_doc).into_response()
}

/// POST /auth/ — verify a signed DIDComm challenge and issue access+refresh tokens. Auth: unauthenticated.
///
/// Dispatcher: unpack the DIDComm envelope (ATM verifies the
/// sender's signature; the resulting `msg.from` is the proven
/// signer DID), extract the challenge + session_id from the
/// message body, hand off to the canonical handler.
pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Response, AppError> {
    // Canonical REST path: a DI-signed `auth/authenticate/0.1` Trust Task
    // document, where the holder's Data-Integrity proof *is* the
    // authentication (no DIDComm packing / mediator required). Tried first so
    // a VTA with no DIDComm transport configured can still authenticate over
    // plain REST. Falls through to the DIDComm envelope path for any body that
    // isn't such a document.
    if let Some(resp) = try_authenticate_trust_task(&state, &body).await? {
        return Ok(resp);
    }

    let atm = state
        .atm
        .as_ref()
        .ok_or_else(|| AppError::Authentication("ATM not configured".into()))?;

    let (msg, _metadata) = atm
        .unpack(&body)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Canonical Trust-Task URI only. The legacy
    // `affinidi.com/atm/1.0/authenticate` alias was removed once the SDK's
    // DIDComm auth path switched to emitting `auth/authenticate/0.1`.
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

    let backend = crate::auth::VtaAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id: session_id.clone(),
            challenge,
            signer_did: sender_base.clone(),
            // DIDComm v2 envelopes carry `created_time` on the
            // ATM-unpacked Message; the canonical handler
            // enforces a 60s freshness window against the
            // session's `created_at`. Closes M3 from the May
            // 2026 security review.
            created_time: msg.created_time,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    audit!(
        "auth.authenticate",
        actor = &sender_base,
        resource = &session_id,
        outcome = "success"
    );
    Ok(Json(resp).into_response())
}

/// Try to authenticate from a DI-signed `auth/authenticate/0.1` Trust Task
/// document (the canonical REST transport).
///
/// Returns:
/// - `Ok(Some(response_doc))` — the body was such a document, its proof
///   verified, and we issued tokens wrapped in a TT `#response` document.
/// - `Ok(None)` — the body is *not* an `auth/authenticate/0.1` Trust Task, so
///   the caller should fall through to the DIDComm-envelope path.
/// - `Err(_)` — the body *was* an authenticate document but is invalid (bad
///   proof, malformed payload, challenge mismatch, …). We don't fall through:
///   the caller's intent was unambiguous, so surface the real failure.
///
/// A DIDComm packed envelope is a JWE/JWS with none of a Trust Task's
/// `id`/`type`/`payload` fields, so it fails the `TrustTask` parse and yields
/// `None` — the two transports are unambiguous on the wire.
async fn try_authenticate_trust_task(
    state: &AppState,
    body: &str,
) -> Result<Option<Response>, AppError> {
    let doc: TrustTask<Value> = match serde_json::from_str(body) {
        Ok(doc) => doc,
        Err(_) => return Ok(None), // not a Trust Task document → DIDComm path
    };
    if doc.type_uri.to_string() != vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1 {
        return Ok(None);
    }

    // From here the caller's intent is unambiguous; failures are real.
    let signer_did = verify_authenticate_proof(&doc).await?;
    let payload: authenticate::Payload = serde_json::from_value(doc.payload.clone())
        .map_err(|e| AppError::Authentication(format!("invalid authenticate payload: {e}")))?;
    let session_id = payload.session_id.to_string();
    let challenge = payload.challenge.to_string();

    let backend = crate::auth::VtaAuthBackend::from_state(state).await?;
    let resp = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id: session_id.clone(),
            challenge,
            signer_did: signer_did.clone(),
            // No DIDComm `created_time`; the single-use, TTL'd challenge bound to
            // the session is the freshness/replay anchor (the canonical handler
            // treats `None` as a no-op freshness check, same as REST SIOPv2).
            created_time: None,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    audit!(
        "auth.authenticate",
        actor = &signer_did,
        resource = &session_id,
        outcome = "success"
    );
    Ok(Some(tokens_response_doc(&doc, &resp)))
}

/// Verify the holder's `eddsa-jcs-2022` Data-Integrity proof on an
/// `auth/authenticate/0.1` document and return the cryptographically-proven
/// signer DID (the base DID of the proof's `verificationMethod`).
///
/// Mirrors the server-side did-signed gate verification in
/// `routes/trust_tasks/step_up.rs::verify_did_signed_gate` (PR #177), but here
/// the subject is *unknown a priori* — it's derived from the proof rather than
/// checked against an expected value. The signer↔session binding is enforced
/// downstream by the canonical handler (`signer_did == session.did`).
/// `did:key` resolution is local (no I/O), matching the mobile holder key.
async fn verify_authenticate_proof(doc: &TrustTask<Value>) -> Result<String, AppError> {
    crate::auth::di_proof::verify_trust_task_proof(doc)
        .await
        .map_err(|e| AppError::Authentication(e.to_string()))
}

// ---------- POST /auth/refresh ----------

/// POST /auth/refresh — exchange a refresh token for a new access token
/// AND a freshly-rotated refresh token. Auth: unauthenticated.
///
/// Implements RFC 6749 §10.4 refresh-token rotation: every successful
/// refresh mints a new refresh token, deletes the old reverse index,
/// and returns the new pair to the caller. The presented token works
/// exactly once. A leaked-then-replayed token surfaces as "refresh
/// token not found" — same shape as a token that was revoked.
///
/// Response shape is the same `AuthenticateResponse` returned by
/// `POST /auth/`, so callers handle login and refresh with one
/// deserialization path.
pub async fn refresh(State(state): State<AppState>, body: String) -> Result<Response, AppError> {
    // Canonical REST path: an `auth/refresh/0.1` Trust Task. Refresh carries no
    // proof — the opaque refresh token in the payload *is* the credential
    // (OAuth2 §10.4 semantics), verified server-side by the rotating
    // reverse-index. Tried first so a VTA with no DIDComm transport configured
    // can still refresh over plain REST. Falls through to the DIDComm-envelope
    // path for any body that isn't such a document.
    if let Some(resp) = try_refresh_trust_task(&state, &body).await? {
        return Ok(resp);
    }

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

    let backend = crate::auth::VtaAuthBackend::from_state(&state).await?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            signer_did: sender_base,
        },
    )
    .await?;
    audit!(
        "auth.refresh",
        actor = &resp.session.subject,
        resource = &resp.session.id,
        outcome = "success"
    );
    Ok(Json(resp).into_response())
}

/// Try to refresh from an `auth/refresh/0.1` Trust Task document (the canonical
/// REST transport).
///
/// Mirrors [`try_authenticate_trust_task`], but refresh carries **no proof**:
/// the opaque refresh token in the payload is the bearer credential, verified
/// by the canonical handler's rotating reverse-index. `signer_did` is therefore
/// `None` — there's no proven signer to bind, and the handler treats `None` as
/// "skip the optional signer-DID check" (the token is sufficient).
///
/// Returns `Ok(None)` when the body isn't an `auth/refresh/0.1` Trust Task (→
/// fall through to the DIDComm path); `Err` when it *is* one but is invalid.
async fn try_refresh_trust_task(
    state: &AppState,
    body: &str,
) -> Result<Option<Response>, AppError> {
    let doc: TrustTask<Value> = match serde_json::from_str(body) {
        Ok(doc) => doc,
        Err(_) => return Ok(None), // not a Trust Task document → DIDComm path
    };
    if doc.type_uri.to_string() != vta_sdk::trust_tasks::TASK_AUTH_REFRESH_0_1 {
        return Ok(None);
    }

    let payload: refresh::Payload = serde_json::from_value(doc.payload.clone())
        .map_err(|e| AppError::Authentication(format!("invalid refresh payload: {e}")))?;
    let refresh_token = payload.refresh_token.to_string();

    let backend = crate::auth::VtaAuthBackend::from_state(state).await?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            signer_did: None,
        },
    )
    .await?;
    audit!(
        "auth.refresh",
        actor = &resp.session.subject,
        resource = &resp.session.id,
        outcome = "success"
    );
    Ok(Some(tokens_response_doc(&doc, &resp)))
}

// ---------- POST /auth/credentials ----------

// ---------- GET /auth/sessions ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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

/// GET /auth/sessions — list all active sessions. Auth: Admin or Initiator.
pub async fn session_list(
    _auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionSummary>>, AppError> {
    let all = list_sessions(&state.sessions_ks).await?;
    let summaries: Vec<SessionSummary> = all.into_iter().map(SessionSummary::from).collect();
    info!(caller = %_auth.0.did, count = summaries.len(), "sessions listed");
    Ok(Json(summaries))
}

// ---------- DELETE /auth/sessions/{session_id} ----------

/// DELETE /auth/sessions/{session_id} — revoke a single session (own or admin). Auth: any authenticated user.
pub async fn revoke_session(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let session = get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("session not found: {session_id}")))?;

    // Allow if caller owns the session or is admin
    if session.did != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "cannot revoke another user's session".into(),
        ));
    }

    delete_session(&state.sessions_ks, &session_id).await?;
    info!(caller = %auth.did, session_id = %session_id, "session revoked");
    audit!(
        "session.revoke",
        actor = &auth.did,
        resource = &session_id,
        outcome = "success"
    );
    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /auth/sessions?did=X ----------

#[derive(Debug, Deserialize)]
pub struct RevokeByDidQuery {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeByDidResponse {
    pub revoked: u64,
}

/// DELETE /auth/sessions?did=X — revoke all sessions for a given DID. Auth: Admin only.
pub async fn revoke_sessions_by_did(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<RevokeByDidQuery>,
) -> Result<Json<RevokeByDidResponse>, AppError> {
    let all = list_sessions(&state.sessions_ks).await?;
    let mut revoked = 0u64;

    for session in all {
        if session.did == query.did {
            delete_session(&state.sessions_ks, &session.session_id).await?;
            revoked += 1;
        }
    }

    info!(caller = %_auth.0.did, target_did = %query.did, revoked, "sessions revoked by DID");
    audit!(
        "session.revoke_by_did",
        actor = &_auth.0.did,
        resource = &query.did,
        outcome = "success"
    );
    Ok(Json(RevokeByDidResponse { revoked }))
}

// ---------- Passkey login ----------
//
// Per the trust-task migration registry these correspond to:
//   - vta/auth/passkey-login-start/1.0
//   - vta/auth/passkey-login-finish/1.0
//
// They are UNAUTHENTICATED (the user has no session yet) — mounted on
// the same router section as `POST /auth/challenge` and `POST /auth/`.
// The trust-task envelope dispatcher at /api/trust-tasks handles only
// authenticated operations.

use base64::Engine as _;
use base64::engine::general_purpose;
use vta_sdk::protocols::passkey_login::{
    PasskeyLoginFinishRequest, PasskeyLoginStartRequest, PasskeyLoginStartResponse,
};

use crate::operations::passkey_login::{
    VtaVmResolver, enumerate_passkey_vms, verify_passkey_login,
};

/// POST /auth/passkey-login/start — issue a passkey-bound challenge. Auth: unauthenticated.
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

    // ACL gate — same as /auth/challenge.
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
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        // AAL is unknown at challenge time. passkey_login_finish sets
        // it to amr=["did","passkey"], acr="aal2" when the assertion
        // verifies and the session transitions to Authenticated.
        amr: Vec::new(),
        acr: String::new(),
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
