//! Canonical `POST /auth/challenge` handler.
//!
//! Flow:
//! 1. Validate DID method (backend hook, default no-op).
//! 2. Resolve whether the subject has an effective ACL entry —
//!    which decides what this handler *does*, never what it
//!    *says*.
//! 3. Per-DID rate limit for an enrolled subject — bounds
//!    concurrent `ChallengeSent` sessions at the backend's cap.
//! 4. Mint 32-byte challenge (OS RNG, hex-encoded).
//! 5. Optional TEE attestation (backend hook, default
//!    not-attested).
//! 6. For an enrolled subject, persist a `ChallengeSent` session
//!    with `tee_attested` set from the attestation outcome and
//!    `amr`/`acr` empty — populated when the session transitions
//!    to `Authenticated` by [`super::handle_authenticate`]. For
//!    any other subject, persist nothing.
//! 7. Return the canonical `ChallengeResponse` either way.
//!
//! # Why an unenrolled subject is answered, not refused
//!
//! A challenge endpoint that refuses an unknown subject and
//! answers a known one is an enumeration oracle: anyone who can
//! guess or harvest identifiers learns which of them this node
//! holds authority for, which is the first step in targeting the
//! people behind them. The information is disclosed by the
//! *shape* of the answer, so no amount of care in the error
//! message removes it.
//!
//! So both subjects get a challenge, and only an enrolled one
//! gets a session to redeem it against. The challenge issued to
//! an unenrolled subject is unusable — `/auth/authenticate` finds
//! no session and refuses, in the same terms it refuses every
//! other pre-authentication failure ([`crate::error::AppError`]'s
//! `From<AuthError>` impl). Redeeming it requires the DID's
//! private key in any case, which a party probing identifiers it
//! does not control never has.
//!
//! What this deliberately does not spend: an unenrolled subject
//! costs one RNG draw and no write, so the endpoint cannot be
//! used to fill the session store with identifiers nobody
//! enrolled. The residual signal is timing — a persisted session
//! is a store round-trip that a decoy is not — and closing that
//! belongs with the store, not here.
//!
//! Implements VTI-SES-006 and VTI-SES-007 of the VTI
//! specification (<https://trustoverip.github.io/dtgwg-vti-spec/>).

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

    // Decides what happens below, and nothing about the response. An
    // unenrolled subject is answered exactly as an enrolled one is; see the
    // module docs.
    let enrolled = backend.has_effective_entry(&input.did).await;

    // The rate limit counts persisted sessions, so it only bites where there
    // are any. An unenrolled subject writes nothing to be limited.
    let limit = backend.max_pending_challenges_per_did();
    if enrolled && limit > 0 {
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

    if enrolled {
        backend
            .sessions()
            .store_session(&session)
            .await
            .map_err(|e| AuthError::Internal(format!("store_session failed: {e:?}")))?;

        backend.audit(AuthAuditEvent::ChallengeIssued {
            did: &session.did,
            session_id: &session_id,
        });
    } else {
        // Not an audit event: nothing was granted, and an operator paging
        // through `ChallengeIssued` rows should not find entries for
        // subjects that hold no authority. It is a warning because a run of
        // these is what identifier probing looks like.
        tracing::warn!(
            did = %session.did,
            "auth challenge requested for a subject with no effective ACL entry — \
             answered with an unusable challenge, nothing persisted"
        );
    }

    Ok(ChallengeResponse {
        challenge,
        session_id,
        expires_at: epoch_to_rfc3339(created_at.saturating_add(backend.challenge_ttl())),
        tee_attestation: attestation.report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::backend::{RoleResolution, SessionStore};
    use crate::error::AppError;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Records what was written so a test can assert that nothing was.
    #[derive(Default)]
    struct RecordingStore {
        stored: Mutex<Vec<Session>>,
    }

    #[async_trait]
    impl SessionStore for RecordingStore {
        type Error = AppError;
        async fn store_session(&self, s: &Session) -> Result<(), AppError> {
            self.stored.lock().unwrap().push(s.clone());
            Ok(())
        }
        async fn get_session(&self, _: &str) -> Result<Option<Session>, AppError> {
            Ok(None)
        }
        async fn delete_session(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn store_refresh_index(&self, _: &str, _: &str) -> Result<(), AppError> {
            unreachable!()
        }
        async fn take_session_id_by_refresh(&self, _: &str) -> Result<Option<String>, AppError> {
            unreachable!()
        }
        async fn count_pending_challenges(&self, _: &str) -> Result<usize, AppError> {
            Ok(0)
        }
    }

    /// `Acl::Present` enrols the subject; `Absent` has no entry for it;
    /// `Broken` fails the way a store outage does.
    #[derive(Clone, Copy)]
    enum Acl {
        Present,
        Absent,
        Broken,
    }

    struct MockBackend {
        store: RecordingStore,
        acl: Acl,
        audited: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl AuthBackend for MockBackend {
        type Store = RecordingStore;
        type Error = AppError;
        type Role = String;

        fn sessions(&self) -> &RecordingStore {
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
            _jti: &str,
        ) -> Result<String, AppError> {
            unreachable!("challenge never mints a token")
        }

        async fn check_acl(&self, _did: &str) -> Result<RoleResolution<String>, AppError> {
            match self.acl {
                Acl::Present => Ok(RoleResolution {
                    role: "reader".to_string(),
                    contexts: vec![],
                }),
                Acl::Absent => Err(AuthError::Forbidden.into()),
                Acl::Broken => Err(AppError::Internal("acl keyspace unavailable".into())),
            }
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

        fn audit(&self, event: AuthAuditEvent<'_>) {
            if let AuthAuditEvent::ChallengeIssued { did, .. } = event {
                self.audited.lock().unwrap().push(did.to_string());
            }
        }
    }

    fn backend(acl: Acl) -> MockBackend {
        MockBackend {
            store: RecordingStore::default(),
            acl,
            audited: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn input(did: &str) -> ChallengeInput {
        ChallengeInput {
            did: did.to_string(),
            session_pubkey_b58btc: None,
        }
    }

    #[tokio::test]
    async fn an_enrolled_subject_gets_a_persisted_session() {
        let b = backend(Acl::Present);
        let resp = handle_challenge(&b, input("did:key:zEnrolled"))
            .await
            .unwrap();

        assert_eq!(b.store.stored.lock().unwrap().len(), 1);
        assert_eq!(b.audited.lock().unwrap().as_slice(), ["did:key:zEnrolled"]);
        assert_eq!(resp.challenge.len(), 64, "32 bytes, hex-encoded");
    }

    /// VTI-SES-007. The response must not distinguish a subject this node
    /// holds authority for from one it has never heard of.
    #[tokio::test]
    async fn an_unenrolled_subject_gets_a_challenge_and_nothing_is_persisted() {
        let b = backend(Acl::Absent);
        let resp = handle_challenge(&b, input("did:key:zStranger"))
            .await
            .expect("an unenrolled subject is answered, not refused");

        assert!(
            b.store.stored.lock().unwrap().is_empty(),
            "a subject with no entry must not be able to fill the session store"
        );
        assert!(
            b.audited.lock().unwrap().is_empty(),
            "nothing was granted, so nothing belongs in the challenge-issued trail"
        );
        assert_eq!(resp.challenge.len(), 64);
    }

    /// The property is about the *shape* of the answer, so assert on the
    /// shape rather than on either branch's internals.
    #[tokio::test]
    async fn the_two_answers_are_indistinguishable() {
        let enrolled = handle_challenge(&backend(Acl::Present), input("did:key:zEnrolled"))
            .await
            .unwrap();
        let stranger = handle_challenge(&backend(Acl::Absent), input("did:key:zStranger"))
            .await
            .unwrap();

        assert_eq!(enrolled.challenge.len(), stranger.challenge.len());
        assert_eq!(
            enrolled.session_id.len(),
            stranger.session_id.len(),
            "both are UUIDs"
        );
        assert_eq!(
            enrolled.tee_attestation.is_some(),
            stranger.tee_attestation.is_some(),
            "attestation is performed for both, or the answer says which is which"
        );
        assert!(!enrolled.expires_at.is_empty() && !stranger.expires_at.is_empty());
        assert_ne!(
            enrolled.challenge, stranger.challenge,
            "each challenge is freshly minted"
        );
    }

    /// A store outage must not become an oracle either: it reads as absent,
    /// and the real error surfaces at authenticate, where the caller has
    /// already proven control of the DID.
    #[tokio::test]
    async fn a_broken_acl_store_does_not_disclose_itself() {
        let b = backend(Acl::Broken);
        let resp = handle_challenge(&b, input("did:key:zEnrolled"))
            .await
            .unwrap();

        assert_eq!(resp.challenge.len(), 64);
        assert!(b.store.stored.lock().unwrap().is_empty());
    }
}
