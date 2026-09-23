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
use crate::auth::session::{
    RefreshTombstone, Session, SessionState, TombstoneCause, now_epoch, refresh_token_hash,
};

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
    // identity, so one DID has one active refresh token. The access token is
    // pinned via `token_id` (the jti), so the previous login's access token is
    // superseded immediately. The single-use challenge row (a distinct,
    // ephemeral, uuid-keyed record) is deleted.
    //
    // "One active refresh token" holds only because the previous token is
    // explicitly retired below. Overwriting the session row does not do it:
    // the reverse index is a separate `refresh:{hash}` row per token, and
    // `/auth/refresh` authorises from that index alone without consulting
    // `session.refresh_token`. Leaving the old entry behind therefore left a
    // second, fully live chain on the same account — a token stolen before a
    // re-login kept working, in its own chain, and since the two chains never
    // shared a token no replay ever occurred and reuse detection never fired.
    // Read the outgoing token *before* `store_session` overwrites the row —
    // afterwards there is nothing left to say which token this login is
    // replacing. `None` on a first login, or on a prior session that carried
    // no refresh token (an intrinsic DIDComm/TSP session).
    let superseded_refresh_token = backend
        .sessions()
        .get_session(&did)
        .await
        .map_err(|e| AuthError::Internal(format!("get_session failed: {e:?}")))?
        .and_then(|prior| prior.refresh_token);

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

    // ---- Retire the token this login replaces ----
    //
    // Ordered after the new chain is durable, as on the rotation path: a crash
    // here leaves the old token live, which is merely the previous behaviour,
    // whereas retiring first and crashing would leave the account with no
    // usable refresh token at all.
    //
    // Claim-and-delete rather than a plain delete, so two logins racing on the
    // same DID cannot both believe they retired it and write duplicate
    // tombstones. The claimed session id is discarded — only the removal
    // matters here.
    //
    // Store errors are logged, not returned, matching `handle_refresh`'s
    // handling of the same two writes. The login is already committed: the new
    // session and its index are durable and the caller's tokens are minted, so
    // failing here would report an error for a login that in fact succeeded
    // and withhold the tokens it had already issued. The cost of continuing is
    // bounded — a retired-but-untombstoned token is still refused, just not
    // attributed, and a token whose index outlived this call is no worse off
    // than it was before this retirement existed.
    if let Some(superseded) = superseded_refresh_token {
        if let Err(e) = backend
            .sessions()
            .take_session_id_by_refresh(&superseded)
            .await
        {
            tracing::error!(
                did = %did,
                "failed to retire the refresh token superseded by this login; \
                 it stays live until it expires: {e:?}",
            );
        } else if let Err(e) = backend
            .sessions()
            .store_refresh_tombstone(
                &superseded,
                &RefreshTombstone {
                    session_id: did.clone(),
                    did: did.clone(),
                    rotated_at: now,
                    expires_at: now.saturating_add(backend.refresh_token_ttl()),
                    successor_hash: refresh_token_hash(&minted.refresh_token),
                    cause: TombstoneCause::Superseded,
                },
            )
            .await
        {
            // Tombstoned, not merely deleted, so the retired token is still
            // *recognised* if it comes back. Deleting alone would make a
            // replay indistinguishable from a token this node never issued,
            // and a token presented after a re-login is worth reporting: the
            // legitimate client holds the new one and has no reason to send
            // the old. `TombstoneCause::Superseded` withholds the
            // innocent-retry grace, which exists only for a lost rotation
            // response.
            tracing::error!(
                did = %did,
                "failed to tombstone the refresh token superseded by this \
                 login; a replay of it will be refused but not attributed: {e:?}",
            );
        }
    }

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
