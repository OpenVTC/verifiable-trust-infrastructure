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
use crate::auth::session::{Session, SessionState, now_epoch};

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
    // ---- Audience (SPEC §7.2 item 5, #1638) ----
    //
    // First, before the session is loaded: a document addressed to another
    // service is refused on what it says, and learns nothing about who is
    // enrolled here.
    if let Err(e) = input.audience.check() {
        tracing::warn!(
            session_id = %input.session_id,
            reason = %e,
            "authenticate rejected: not addressed to this service",
        );
        return Err(e.into());
    }

    // ---- Load + state-check session ----

    let session = backend
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

    // ---- Consume the challenge (the claim) ----
    //
    // Every check above read the row; this takes it. It happens *before* the
    // ACL lookup and the mint, and deliberately so: those are awaits, and
    // while the row still existed across them two interleaved presentations
    // of the same signed envelope both passed the `ChallengeSent` check and
    // both minted (#1656). `take_session` is a claim — exactly one concurrent
    // caller observes `Some` — so the loser is refused here, as a replay is.
    //
    // A challenge row is always uuid-keyed (`handle_challenge` mints a v4),
    // so this can never take the DID-keyed row of an established session.
    if backend
        .sessions()
        .take_session(&input.session_id)
        .await
        .map_err(|e| AuthError::Internal(format!("take_session failed: {e:?}")))?
        .is_none()
    {
        tracing::warn!(
            session_id = %input.session_id,
            did = %session.did,
            "authenticate rejected: challenge already consumed (replay or race)",
        );
        return Err(AuthError::SessionStateMismatch.into());
    }

    // ---- Re-look-up ACL role (propagates revocation) ----

    let role_resolution = backend.check_acl(&session.did).await?;

    // ---- Mint tokens (acr-dependent TTL + Authenticated audit) ----
    //
    // The authenticated session is **canonical and transport-agnostic**: keyed
    // on the identity (the DID), not the ephemeral challenge handle. So the JWT
    // `session_id` is the DID, and this session unifies with the intrinsic-
    // sender (DIDComm/TSP) session for the same DID.
    //
    // The shared minter centralises the `aal2` short-TTL hardening (M2 from the
    // May 2026 security review — bound the blast radius of a leaked elevated
    // token) so every mint path applies it identically.
    let did = session.did.clone();
    let minted = super::mint::mint_session_tokens(
        backend,
        &did,
        &did,
        &role_resolution.role,
        &role_resolution.contexts,
        &amr,
        &acr,
        session.tee_attested,
    )
    .await?;

    // ---- Create the authenticated session, replace the challenge row ----
    //
    // Coalesce-per-DID: a fresh login overwrites any prior session for this
    // identity, so one DID has one active refresh token (last-write-wins). The
    // access token is pinned via `token_id` (the jti), so the previous login's
    // access token is superseded immediately. The single-use challenge row (a
    // distinct, ephemeral, uuid-keyed record) was already taken above.
    let auth_session = Session {
        session_id: did.clone(),
        did: did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now,
        last_seen: now,
        refresh_token: Some(minted.refresh_token.clone()),
        refresh_expires_at: Some(minted.refresh_expires_at),
        tee_attested: session.tee_attested,
        amr: amr.clone(),
        acr: acr.clone(),
        acr_expires_at: None,
        token_id: Some(minted.token_id.clone()),
        session_pubkey_b58btc: input
            .session_pubkey_b58btc
            .or(session.session_pubkey_b58btc.clone()),
    };

    backend
        .sessions()
        .store_session(&auth_session)
        .await
        .map_err(|e| AuthError::Internal(format!("store_session failed: {e:?}")))?;
    backend
        .sessions()
        .store_refresh_index(&minted.refresh_token, &did)
        .await
        .map_err(|e| AuthError::Internal(format!("store_refresh_index failed: {e:?}")))?;

    // ---- Build canonical response ----

    Ok(AuthenticateResponse {
        session: WireSession {
            id: did.clone(),
            subject: did,
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

#[cfg(test)]
mod claim_tests {
    use super::*;
    use crate::auth::backend::{AudienceBinding, RoleResolution, SessionStore};
    use crate::auth::session::now_epoch;
    use crate::error::AppError;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const DID: &str = "did:key:zHolder";
    const CHALLENGE: &str = "challenge-0";
    const SESSION_ID: &str = "11111111-1111-4111-8111-111111111111";

    /// In-memory `sessions` keyspace whose `take_session` is a real claim
    /// (remove under the map's lock), as `KeyspaceSessionStore`'s is.
    #[derive(Default)]
    struct MemStore {
        sessions: Mutex<HashMap<String, Session>>,
    }

    #[async_trait]
    impl SessionStore for MemStore {
        type Error = AppError;

        async fn store_session(&self, s: &Session) -> Result<(), AppError> {
            self.sessions
                .lock()
                .unwrap()
                .insert(s.session_id.clone(), s.clone());
            Ok(())
        }

        async fn get_session(&self, session_id: &str) -> Result<Option<Session>, AppError> {
            Ok(self.sessions.lock().unwrap().get(session_id).cloned())
        }

        async fn delete_session(&self, session_id: &str) -> Result<(), AppError> {
            self.sessions.lock().unwrap().remove(session_id);
            Ok(())
        }

        async fn take_session(&self, session_id: &str) -> Result<Option<Session>, AppError> {
            Ok(self.sessions.lock().unwrap().remove(session_id))
        }

        async fn store_refresh_index(&self, _: &str, _: &str) -> Result<(), AppError> {
            Ok(())
        }

        async fn take_session_id_by_refresh(&self, _: &str) -> Result<Option<String>, AppError> {
            Ok(None)
        }

        async fn count_pending_challenges(&self, did: &str) -> Result<usize, AppError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .values()
                .filter(|s| s.did == did && s.state == SessionState::ChallengeSent)
                .count())
        }
    }

    struct MockBackend {
        store: MemStore,
    }

    #[async_trait]
    impl AuthBackend for MockBackend {
        type Store = MemStore;
        type Error = AppError;
        type Role = String;

        fn sessions(&self) -> &MemStore {
            &self.store
        }

        #[allow(clippy::too_many_arguments)]
        async fn mint_access_token(
            &self,
            _subject: &str,
            _session_id: &str,
            _role: &String,
            _contexts: &[String],
            _amr: &[String],
            _acr: &str,
            _tee_attested: bool,
            _ttl_secs: u64,
            jti: &str,
        ) -> Result<String, AppError> {
            // Minting is the expensive, awaiting part of the handler — the
            // window the challenge row used to stay alive across. The yield
            // makes the interleaving deterministic rather than lucky.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok(format!("access:{jti}"))
        }

        async fn check_acl(&self, _did: &str) -> Result<RoleResolution<String>, AppError> {
            Ok(RoleResolution::new("reader".to_string()))
        }

        fn challenge_ttl(&self) -> u64 {
            60
        }
        fn access_token_ttl(&self) -> u64 {
            900
        }
        fn refresh_token_ttl(&self) -> u64 {
            86_400
        }
    }

    fn challenge_row() -> Session {
        let now = now_epoch();
        Session {
            session_id: SESSION_ID.to_string(),
            did: DID.to_string(),
            challenge: CHALLENGE.to_string(),
            state: SessionState::ChallengeSent,
            created_at: now,
            last_seen: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        }
    }

    fn input() -> AuthenticateInput {
        AuthenticateInput {
            session_id: SESSION_ID.to_string(),
            challenge: CHALLENGE.to_string(),
            signer_did: DID.to_string(),
            created_time: None,
            session_pubkey_b58btc: None,
            audience: AudienceBinding::Transport,
        }
    }

    /// #1656: two presentations of the *same* challenge, interleaved, mint
    /// exactly once.
    ///
    /// The challenge row used to be deleted after the ACL lookup and the
    /// mint, so while those awaited, a second caller still saw a row in
    /// `ChallengeSent` and minted too. It is now taken before them, and a
    /// take is a claim, so the loser is refused.
    ///
    /// Revert the ordering and this fails with two successes.
    #[tokio::test(flavor = "current_thread")]
    async fn two_presentations_of_one_challenge_mint_once() {
        let backend = MockBackend {
            store: MemStore::default(),
        };
        backend.store.store_session(&challenge_row()).await.unwrap();

        let (first, second) = tokio::join!(
            handle_authenticate(&backend, input()),
            handle_authenticate(&backend, input()),
        );

        let minted = [&first, &second].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            minted, 1,
            "exactly one presentation may mint; got first={first:?} second={second:?}"
        );
        assert!(
            backend
                .store
                .get_session(SESSION_ID)
                .await
                .unwrap()
                .is_none(),
            "the challenge row is gone either way"
        );
    }

    /// The trait's default `take_session` — what a backend that does not
    /// override it gets — reads the row and removes it.
    #[tokio::test]
    async fn the_default_take_session_reads_and_removes() {
        /// A store with no override, so the default body runs.
        #[derive(Default)]
        struct Unoverridden(MemStore);

        #[async_trait]
        impl SessionStore for Unoverridden {
            type Error = AppError;
            async fn store_session(&self, s: &Session) -> Result<(), AppError> {
                self.0.store_session(s).await
            }
            async fn get_session(&self, id: &str) -> Result<Option<Session>, AppError> {
                self.0.get_session(id).await
            }
            async fn delete_session(&self, id: &str) -> Result<(), AppError> {
                self.0.delete_session(id).await
            }
            async fn store_refresh_index(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            async fn take_session_id_by_refresh(
                &self,
                _: &str,
            ) -> Result<Option<String>, AppError> {
                Ok(None)
            }
            async fn count_pending_challenges(&self, did: &str) -> Result<usize, AppError> {
                self.0.count_pending_challenges(did).await
            }
        }

        let store = Unoverridden::default();
        store.store_session(&challenge_row()).await.unwrap();

        let taken = store.take_session(SESSION_ID).await.unwrap();
        assert_eq!(taken.map(|s| s.did), Some(DID.to_string()));
        assert!(store.get_session(SESSION_ID).await.unwrap().is_none());
        assert!(store.take_session(SESSION_ID).await.unwrap().is_none());
    }
}
