//! Canonical `POST /auth/challenge` handler.
//!
//! Flow:
//! 1. Validate DID method (backend hook, default no-op).
//! 2. ACL gate — DID must be present + unexpired.
//! 3. Per-DID rate limit — bounds concurrent `ChallengeSent`
//!    sessions per DID at the backend's configured cap.
//! 4. Mint 32-byte challenge (OS RNG, hex-encoded).
//! 5. Optional TEE attestation (backend hook, default
//!    not-attested).
//! 6. Persist `ChallengeSent` session with `tee_attested` set
//!    from the attestation outcome and `amr`/`acr` empty —
//!    populated when the session transitions to `Authenticated`
//!    by [`super::handle_authenticate`].
//! 7. Emit `ChallengeIssued` audit event and return canonical
//!    `ChallengeResponse`.

use uuid::Uuid;
use vta_sdk::protocols::auth::{ChallengeResponse, epoch_to_rfc3339};

use crate::auth::AuthError;
use crate::auth::backend::{AuthAuditEvent, AuthBackend, ChallengeInput, SessionStore};
use crate::auth::session::{Session, SessionState, now_epoch};

/// Process a `/auth/challenge` request.
pub async fn handle_challenge<B: AuthBackend>(
    backend: &B,
    input: ChallengeInput,
) -> Result<ChallengeResponse, B::Error> {
    // ---- Gates: DID method, ACL, rate limit ----

    backend.validate_did(&input.did).await?;
    backend.check_acl(&input.did).await?;

    let limit = backend.max_pending_challenges_per_did();
    if limit > 0 {
        let pending = backend
            .sessions()
            .count_pending_challenges(&input.did)
            .await
            .map_err(|e| AuthError::Internal(format!("count_pending_challenges failed: {e:?}")))?;
        if pending >= limit {
            tracing::warn!(
                did = %input.did,
                pending,
                limit,
                "auth challenge rate limited per-DID"
            );
            return Err(AuthError::PendingChallengeLimitReached.into());
        }
    }

    // ---- Mint challenge + optional TEE attestation ----

    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let challenge = hex::encode(bytes);
    let session_id = Uuid::new_v4().to_string();

    let attestation = backend.attest_challenge(&bytes).await?;

    // ---- Persist session ----

    let created_at = now_epoch();
    let session = Session {
        session_id: session_id.clone(),
        did: input.did,
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at,
        last_seen: created_at,
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: attestation.attested,
        amr: Vec::new(),
        acr: String::new(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: input.session_pubkey_b58btc,
    };

    backend
        .sessions()
        .store_session(&session)
        .await
        .map_err(|e| AuthError::Internal(format!("store_session failed: {e:?}")))?;

    backend.audit(AuthAuditEvent::ChallengeIssued {
        did: &session.did,
        session_id: &session_id,
    });

    Ok(ChallengeResponse {
        challenge,
        session_id,
        expires_at: epoch_to_rfc3339(created_at.saturating_add(backend.challenge_ttl())),
        tee_attestation: attestation.report,
    })
}
