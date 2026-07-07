//! Canonical `POST /auth/refresh` handler.
//!
//! Flow:
//! 1. **Atomic claim** of the `refresh_token → session_id`
//!    reverse-index via [`SessionStore::take_session_id_by_refresh`].
//!    Exactly one concurrent caller succeeds per token (cross-replica
//!    safe). Closes the rotation TOCTOU.
//! 2. Load session by the claimed `session_id`.
//! 3. (DIDComm transports) Verify signer DID matches session DID.
//!    REST transports can skip this — the refresh token itself is
//!    the credential.
//! 4. Reject sessions in non-`Authenticated` state.
//! 5. Refresh-token expiry check.
//! 6. Preserve `(amr, acr)` from the pre-rotation session — a
//!    step-upped `aal2` session stays at `aal2` across the rotation
//!    instead of silently dropping to `aal1`.
//! 7. Delete the old session (atomic with index already claimed).
//! 8. Re-look-up ACL role (propagates revocation).
//! 9. Mint a *new* session with a fresh `session_id`, access token,
//!    and refresh token. The new session inherits the preserved
//!    `(amr, acr)`.
//! 10. Emit `Refreshed` audit event and return canonical
//!     `AuthenticateResponse`.

use uuid::Uuid;
use vta_sdk::protocols::auth::{
    AuthenticateResponse, Session as WireSession, TokenBundle, epoch_to_rfc3339,
};

use crate::auth::AuthError;
use crate::auth::backend::{AuthAuditEvent, AuthBackend, RefreshInput, SessionStore};
use crate::auth::session::{Session, SessionState, now_epoch};

/// Process a `/auth/refresh` request.
pub async fn handle_refresh<B: AuthBackend>(
    backend: &B,
    input: RefreshInput,
) -> Result<AuthenticateResponse, B::Error> {
    // ---- 1. Atomic claim of refresh-token index ----

    let session_id = backend
        .sessions()
        .take_session_id_by_refresh(&input.refresh_token)
        .await
        .map_err(|e| AuthError::Internal(format!("take_session_id_by_refresh failed: {e:?}")))?
        .ok_or(AuthError::RefreshTokenInvalid)?;

    // ---- 2. Load session ----

    let old_session = backend
        .sessions()
        .get_session(&session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("get_session failed: {e:?}")))?
        .ok_or(AuthError::SessionNotFound)?;

    // ---- 3. (DIDComm) Signer-DID-matches-session-DID ----

    if let Some(signer) = &input.signer_did
        && *signer != old_session.did
    {
        tracing::warn!(
            session_id = %old_session.session_id,
            session_did = %old_session.did,
            signer = %signer,
            "refresh rejected: signer DID does not match session DID",
        );
        return Err(AuthError::SignerMismatch.into());
    }

    // ---- 4. State check ----

    if old_session.state != SessionState::Authenticated {
        tracing::warn!(
            session_id = %old_session.session_id,
            did = %old_session.did,
            "refresh rejected: session not authenticated",
        );
        return Err(AuthError::SessionStateMismatch.into());
    }

    // ---- 5. Refresh-token expiry ----

    let now = now_epoch();
    if let Some(expires_at) = old_session.refresh_expires_at
        && now > expires_at
    {
        tracing::warn!(
            session_id = %old_session.session_id,
            did = %old_session.did,
            "refresh rejected: refresh token expired",
        );
        return Err(AuthError::RefreshTokenExpired.into());
    }

    // ---- 6. Preserve AAL across rotation ----

    let (amr, acr) = super::refresh_amr_acr(&old_session);

    // ---- 7. Delete old session ----

    backend
        .sessions()
        .delete_session(&old_session.session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("delete_session failed: {e:?}")))?;

    // ---- 8. Re-look-up ACL role ----

    let role_resolution = backend.check_acl(&old_session.did).await?;

    // ---- 9. Mint new session + tokens ----

    let new_session_id = Uuid::new_v4().to_string();
    let new_refresh_token = Uuid::new_v4().to_string();
    let new_refresh_expires_at = now.saturating_add(backend.refresh_token_ttl());
    // M2: stepped-up sessions keep the shorter `aal2` TTL
    // across rotation (was previously dropping back to the
    // base TTL on every refresh).
    let access_ttl = if acr == "aal2" {
        backend.access_token_ttl_for_aal2()
    } else {
        backend.access_token_ttl()
    };
    let access_expires_at = now.saturating_add(access_ttl);

    let access_token = backend
        .mint_access_token(
            &old_session.did,
            &new_session_id,
            &role_resolution.role,
            &role_resolution.contexts,
            &amr,
            &acr,
            old_session.tee_attested,
            access_ttl,
        )
        .await?;

    let new_session = Session {
        session_id: new_session_id.clone(),
        did: old_session.did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now,
        last_seen: now,
        refresh_token: Some(new_refresh_token.clone()),
        refresh_expires_at: Some(new_refresh_expires_at),
        tee_attested: old_session.tee_attested,
        amr: amr.clone(),
        acr: acr.clone(),
        acr_expires_at: old_session.acr_expires_at,
        // Inherit the per-session ephemeral pubkey across rotation;
        // the holder's DI-proof key didn't change.
        token_id: None,
        session_pubkey_b58btc: old_session.session_pubkey_b58btc.clone(),
    };

    backend
        .sessions()
        .store_session(&new_session)
        .await
        .map_err(|e| AuthError::Internal(format!("store_session failed: {e:?}")))?;
    backend
        .sessions()
        .store_refresh_index(&new_refresh_token, &new_session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("store_refresh_index failed: {e:?}")))?;

    backend.audit(AuthAuditEvent::Refreshed {
        did: &old_session.did,
        old_session_id: &old_session.session_id,
        new_session_id: &new_session_id,
        amr: &amr,
        acr: &acr,
    });

    // ---- 10. Canonical response ----

    Ok(AuthenticateResponse {
        session: WireSession {
            id: new_session_id,
            subject: old_session.did,
            issued_at: epoch_to_rfc3339(now),
            expires_at: epoch_to_rfc3339(access_expires_at),
            amr,
            acr,
        },
        tokens: TokenBundle {
            access_token,
            refresh_token: Some(new_refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: access_ttl,
            refresh_expires_in: Some(backend.refresh_token_ttl()),
            scope: role_resolution
                .contexts
                .into_iter()
                .map(|c| format!("ctx:{c}"))
                .collect(),
        },
    })
}
