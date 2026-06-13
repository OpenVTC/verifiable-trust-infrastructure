//! Canonical `POST /auth/` (authenticate) handler.
//!
//! Flow:
//! 1. Load session by `session_id`; reject if missing or already
//!    `Authenticated` (replay).
//! 2. Constant-time challenge match.
//! 3. Signer DID matches session DID (transport layer must
//!    have produced the verified signer DID via cryptographic
//!    check — `unpack_signed` for DIDComm, JWS verify for REST
//!    SIOPv2).
//! 4. Challenge TTL check.
//! 5. DIDComm `created_time` freshness window check (no-op for
//!    REST transports that pass `created_time: None`).
//! 6. Re-look-up the ACL role (propagates revocation between
//!    challenge and authenticate).
//! 7. Mint access + refresh tokens; populate `amr`/`acr` from the
//!    transport's authentication factors. The first-factor
//!    challenge-response uses `amr=["did"]`, `acr="aal1"`;
//!    step-up flows (passkey-finish, VTA-approval) raise these
//!    at their own handlers.
//! 8. Transition session to `Authenticated`, persist
//!    `(amr, acr, refresh_token, refresh_expires_at)`.
//! 9. Emit `Authenticated` audit event and return canonical
//!    `AuthenticateResponse`.

use vta_sdk::protocols::auth::{
    AuthenticateResponse, Session as WireSession, TokenBundle, epoch_to_rfc3339,
};

use crate::auth::AuthError;
use crate::auth::backend::{AuthBackend, AuthenticateInput, SessionStore};
use crate::auth::session::{SessionState, now_epoch};

/// Default first-factor AMR; the transport layer (or step-up
/// handler) can override by passing different values to
/// `handle_authenticate_with_aal`.
const DEFAULT_AMR: &[&str] = &["did"];
const DEFAULT_ACR: &str = "aal1";

/// Process a `/auth/` request with the default first-factor
/// AAL claims (`amr=["did"]`, `acr="aal1"`).
pub async fn handle_authenticate<B: AuthBackend>(
    backend: &B,
    input: AuthenticateInput,
) -> Result<AuthenticateResponse, B::Error> {
    let amr = DEFAULT_AMR.iter().map(|s| s.to_string()).collect();
    handle_authenticate_with_aal(backend, input, amr, DEFAULT_ACR.into()).await
}

/// Process a `/auth/` request with explicit AAL claims. Step-up
/// flows (passkey-finish, VTA approval) call this with the
/// elevated `(amr, acr)` they're issuing.
pub async fn handle_authenticate_with_aal<B: AuthBackend>(
    backend: &B,
    input: AuthenticateInput,
    amr: Vec<String>,
    acr: String,
) -> Result<AuthenticateResponse, B::Error> {
    // ---- Load + state-check session ----

    let mut session = backend
        .sessions()
        .get_session(&input.session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("get_session failed: {e:?}")))?
        .ok_or(AuthError::SessionNotFound)?;

    if session.state != SessionState::ChallengeSent {
        tracing::warn!(
            session_id = %input.session_id,
            did = %session.did,
            "authenticate rejected: session not in ChallengeSent state (replay)",
        );
        return Err(AuthError::SessionStateMismatch.into());
    }

    // ---- Challenge match (constant time) ----

    if !super::constant_time_challenge_eq(&session.challenge, &input.challenge) {
        tracing::warn!(
            session_id = %input.session_id,
            did = %session.did,
            "authenticate rejected: challenge mismatch",
        );
        return Err(AuthError::ChallengeMismatch.into());
    }

    // ---- Signer-DID-matches-session-DID ----

    if session.did != input.signer_did {
        tracing::warn!(
            session_id = %input.session_id,
            session_did = %session.did,
            signer = %input.signer_did,
            "authenticate rejected: signer DID mismatch",
        );
        return Err(AuthError::SignerMismatch.into());
    }

    // ---- Challenge TTL + DIDComm freshness ----

    let now = now_epoch();
    if now.saturating_sub(session.created_at) > backend.challenge_ttl() {
        tracing::warn!(
            session_id = %input.session_id,
            did = %session.did,
            "authenticate rejected: challenge expired",
        );
        return Err(AuthError::ChallengeExpired.into());
    }

    super::check_freshness(
        input.created_time,
        session.created_at,
        now,
        backend.didcomm_freshness_window(),
    )?;

    // ---- Re-look-up ACL role (propagates revocation) ----

    let role_resolution = backend.check_acl(&session.did).await?;

    // ---- Mint tokens (acr-dependent TTL + Authenticated audit) ----
    //
    // The shared minter centralises the `aal2` short-TTL hardening
    // (M2 from the May 2026 security review — bound the blast radius
    // of a leaked elevated token) so every mint path applies it
    // identically.
    let minted = super::mint::mint_session_tokens(
        backend,
        &session.did,
        &session.session_id,
        &role_resolution.role,
        &role_resolution.contexts,
        &amr,
        &acr,
        session.tee_attested,
    )
    .await?;

    // ---- Transition session + persist refresh index ----

    session.state = SessionState::Authenticated;
    session.refresh_token = Some(minted.refresh_token.clone());
    session.refresh_expires_at = Some(minted.refresh_expires_at);
    session.amr = amr.clone();
    session.acr = acr.clone();
    if let Some(pk) = input.session_pubkey_b58btc {
        session.session_pubkey_b58btc = Some(pk);
    }

    backend
        .sessions()
        .store_session(&session)
        .await
        .map_err(|e| AuthError::Internal(format!("store_session failed: {e:?}")))?;
    backend
        .sessions()
        .store_refresh_index(&minted.refresh_token, &session.session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("store_refresh_index failed: {e:?}")))?;

    // ---- Build canonical response ----

    Ok(AuthenticateResponse {
        session: WireSession {
            id: session.session_id.clone(),
            subject: session.did,
            issued_at: epoch_to_rfc3339(minted.issued_at),
            expires_at: epoch_to_rfc3339(minted.access_expires_at),
            amr,
            acr,
        },
        tokens: TokenBundle {
            access_token: minted.access_token,
            refresh_token: Some(minted.refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: minted.access_ttl,
            refresh_expires_in: Some(backend.refresh_token_ttl()),
            scope: role_resolution
                .contexts
                .into_iter()
                .map(|c| format!("ctx:{c}"))
                .collect(),
        },
    })
}
