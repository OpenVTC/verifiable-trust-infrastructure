//! Canonical `POST /auth/challenge` handler.
//!
//! Flow:
//! 1. Validate DID method (backend hook, default no-op).
//! 2. Resolve whether the subject has an effective ACL entry —
//!    which decides what this handler *does*, never what it
//!    *says*.
//! 3. Mint 32-byte challenge (OS RNG, hex-encoded).
//! 4. Optional TEE attestation (backend hook, default
//!    not-attested).
//! 5. For an enrolled subject, hold the per-DID cap — its outstanding
//!    `ChallengeSent` sessions stay at the backend's cap by evicting
//!    the oldest, never by refusing (see `make_room_for_challenge`) —
//!    and persist a `ChallengeSent` session
//!    with `tee_attested` set from the attestation outcome and
//!    `amr`/`acr` empty — populated when the session transitions
//!    to `Authenticated` by [`super::handle_authenticate`]. For
//!    any other subject, persist nothing.
//! 6. Return the canonical `ChallengeResponse` either way.
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

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, Weak};

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
    // ---- Gates: DID method, ACL ----

    backend.validate_did(&input.did).await?;

    // Decides what happens below, and nothing about the response. An
    // unenrolled subject is answered exactly as an enrolled one is; see the
    // module docs.
    let enrolled = backend.has_effective_entry(&input.did).await;

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
        not_after: None,
    };

    if enrolled {
        // The cap counts persisted sessions, so it only bites where there
        // are any: an unenrolled subject writes nothing to be limited. The
        // lock makes listing, evicting and storing one step per subject, so
        // two concurrent requests cannot both see room for one more
        // (VTI-SES-005).
        let limit = backend.max_pending_challenges_per_did();
        let cap = cap_lock(&session.did);
        let _cap = tokio::time::timeout(CAP_LOCK_WAIT, cap.lock())
            .await
            .map_err(|_| {
                AuthError::Internal(format!(
                    "the per-DID challenge cap stayed busy for {CAP_LOCK_WAIT:?}"
                ))
            })?;
        if limit > 0 {
            make_room_for_challenge(backend, &session.did, limit).await?;
        }
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

/// Locks serialising the per-DID cap, one per subject while it is in use.
///
/// One per DID, not striped, so a slow store call for one subject never holds
/// up another's challenge. The map keeps only weak references: a subject's
/// lock is dropped with its last holder, and the dead entries are cleared
/// whenever a new one is made, so the map stays the size of the challenges in
/// flight.
///
/// In-process, so the cap is exact for a session store one process owns, as
/// VTA and VTC stores are (embedded fjall, or the enclave's vsock store). A
/// store shared by several processes would need the cap held by the store
/// itself.
static CAP_LOCKS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
> = std::sync::LazyLock::new(Default::default);

/// Longest a challenge request waits for the subject's cap lock. The lock is
/// held across store calls (list, evict, store) — local, but in an enclave a
/// vsock round trip each — so a waiter gives up rather than queueing behind a
/// wedged store indefinitely (R1.3).
const CAP_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn cap_lock(did: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = CAP_LOCKS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(lock) = locks.get(did).and_then(Weak::upgrade) {
        return lock;
    }
    locks.retain(|_, lock| lock.strong_count() > 0);
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(did.to_owned(), Arc::downgrade(&lock));
    lock
}

/// Hold the per-DID cap on outstanding challenges (VTI-SES-005) so that one
/// more can be issued: discard the subject's expired challenges, which are no
/// longer outstanding (VTI-SES-003), then evict the oldest live ones.
///
/// Evicting rather than refusing is deliberate. Only an enrolled subject has
/// pending challenges, so refusing at the cap told anyone who asked for
/// `limit + 1` challenges that the subject is enrolled (VTI-SES-007); and
/// anyone — the subject retrying a login it could not finish, or a stranger
/// naming its DID — could lock the DID out of logging in until the rows were
/// swept.
///
/// Eviction has a cost of its own. A challenge request names its subject
/// without proving anything, so a stranger who asks for `limit` challenges
/// for someone else's DID evicts that subject's oldest outstanding one, and a
/// login waiting to redeem it fails and has to start over. That is a cancelled
/// login, not a lockout: the subject's next challenge is issued at once, and
/// the stranger pays for every eviction from their own address's budget.
///
/// A store that cannot list a subject's challenges keeps the old behaviour:
/// count them and refuse at the cap.
async fn make_room_for_challenge<B: AuthBackend>(
    backend: &B,
    did: &str,
    limit: usize,
) -> Result<(), B::Error> {
    let sessions = backend.sessions();
    let Some(pending) = sessions
        .pending_challenges(did)
        .await
        .map_err(|e| AuthError::Internal(format!("pending_challenges failed: {e:?}")))?
    else {
        let pending = sessions
            .count_pending_challenges(did)
            .await
            .map_err(|e| AuthError::Internal(format!("count_pending_challenges failed: {e:?}")))?;
        if pending >= limit {
            tracing::warn!(did, pending, limit, "auth challenge rate limited per-DID");
            return Err(AuthError::PendingChallengeLimitReached.into());
        }
        return Ok(());
    };

    let now = now_epoch();
    let ttl = backend.challenge_ttl();
    let (expired, live): (Vec<_>, Vec<_>) = pending
        .into_iter()
        .partition(|s| now.saturating_sub(s.created_at) > ttl);
    // `pending` is oldest first, so `live` is too: the excess is its head.
    let excess = (live.len() + 1).saturating_sub(limit);
    if excess > 0 {
        tracing::warn!(
            did,
            outstanding = live.len(),
            limit,
            evicted = excess,
            "auth challenge cap reached per-DID — evicting the oldest outstanding challenges"
        );
    }
    for s in expired.iter().chain(live.iter().take(excess)) {
        sessions
            .delete_session(&s.session_id)
            .await
            .map_err(|e| AuthError::Internal(format!("delete_session failed: {e:?}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::backend::{RoleResolution, SessionStore};
    use crate::auth::handlers::store::KeyspaceSessionStore;
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
            Ok(self.stored.lock().unwrap().len())
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

    struct MockBackend<S = RecordingStore> {
        store: S,
        acl: Acl,
        audited: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl<S: SessionStore<Error = AppError> + Send + Sync + 'static> AuthBackend for MockBackend<S> {
        type Store = S;
        type Error = AppError;
        type Role = String;

        fn sessions(&self) -> &S {
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

    // ── Per-DID cap (VTI-SES-003, VTI-SES-005, VTI-SES-007) ─────────

    fn keyspace_backend(acl: Acl) -> (MockBackend<KeyspaceSessionStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::store::Store::open(&crate::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let sessions = KeyspaceSessionStore::new(store.keyspace("sessions").expect("keyspace"));
        let b = MockBackend {
            store: sessions,
            acl,
            audited: Arc::new(Mutex::new(Vec::new())),
        };
        (b, dir)
    }

    fn challenge_row(session_id: &str, did: &str, created_at: u64) -> Session {
        Session {
            session_id: session_id.into(),
            did: did.into(),
            challenge: "00".into(),
            state: SessionState::ChallengeSent,
            created_at,
            last_seen: created_at,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec![],
            acr: String::new(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
            not_after: None,
        }
    }

    async fn outstanding(b: &MockBackend<KeyspaceSessionStore>, did: &str) -> Vec<String> {
        b.store
            .pending_challenges(did)
            .await
            .unwrap()
            .expect("the keyspace store lists challenges")
            .into_iter()
            .map(|s| s.session_id)
            .collect()
    }

    /// The livelock: a client that cannot finish a login and retries must
    /// not lock its own DID out. At the cap the oldest challenge goes and
    /// the new one is issued.
    #[tokio::test]
    async fn at_the_cap_a_challenge_is_evicted_not_refused() {
        let (b, _dir) = keyspace_backend(Acl::Present);
        let did = "did:key:zRetrying";
        let limit = b.max_pending_challenges_per_did();
        let mut issued = Vec::new();
        for _ in 0..=limit {
            let resp = handle_challenge(&b, input(did))
                .await
                .expect("a challenge is never refused at the cap");
            issued.push(resp.session_id);
        }

        // `created_at` has one-second resolution and these share a second,
        // so which of them is "oldest" is a tie: assert what holds anyway.
        let left = outstanding(&b, did).await;
        assert_eq!(left.len(), limit, "the cap still holds (VTI-SES-005)");
        assert!(
            left.contains(&issued[limit]),
            "the new challenge is never the one evicted"
        );
        let evicted: Vec<_> = issued.iter().filter(|id| !left.contains(id)).collect();
        assert_eq!(evicted.len(), 1, "exactly one was evicted");
        assert!(
            b.store.get_session(evicted[0]).await.unwrap().is_none(),
            "an evicted challenge can no longer be redeemed"
        );
    }

    #[tokio::test]
    async fn eviction_takes_the_oldest_outstanding_challenge() {
        let (b, _dir) = keyspace_backend(Acl::Present);
        let did = "did:key:zOrdered";
        let now = now_epoch();
        let limit = b.max_pending_challenges_per_did();
        for i in 0..limit {
            // Inside the TTL, oldest first: `c-0` was issued earliest.
            let at = now - (limit - i) as u64;
            b.store
                .store_session(&challenge_row(&format!("c-{i}"), did, at))
                .await
                .unwrap();
        }

        handle_challenge(&b, input(did)).await.unwrap();

        let left = outstanding(&b, did).await;
        assert!(!left.contains(&"c-0".to_string()), "{left:?}");
        assert!(left.contains(&"c-1".to_string()), "{left:?}");
    }

    /// An expired challenge is not outstanding (VTI-SES-003), so it neither
    /// counts against the cap nor survives the next request.
    #[tokio::test]
    async fn expired_challenges_are_discarded_and_do_not_count() {
        let (b, _dir) = keyspace_backend(Acl::Present);
        let did = "did:key:zStale";
        let stale_at = now_epoch() - b.challenge_ttl() - 1;
        for i in 0..b.max_pending_challenges_per_did() {
            b.store
                .store_session(&challenge_row(&format!("stale-{i}"), did, stale_at))
                .await
                .unwrap();
        }

        let resp = handle_challenge(&b, input(did)).await.unwrap();

        assert_eq!(outstanding(&b, did).await, [resp.session_id]);
    }

    /// VTI-SES-007: past the cap, an enrolled subject is answered exactly as
    /// an unenrolled one is — with a challenge.
    #[tokio::test]
    async fn the_cap_does_not_disclose_enrolment() {
        for acl in [Acl::Present, Acl::Absent] {
            let (b, _dir) = keyspace_backend(acl);
            for _ in 0..=b.max_pending_challenges_per_did() {
                let resp = handle_challenge(&b, input("did:key:zProbed")).await;
                assert!(resp.is_ok(), "never refused, enrolled or not");
            }
        }
    }

    /// VTI-SES-005 under concurrency: requests that arrive together, one
    /// below the cap, must not each see room for one more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_cannot_overshoot_the_cap() {
        let (b, _dir) = keyspace_backend(Acl::Present);
        let b = Arc::new(b);
        let did = "did:key:zConcurrent";
        let limit = b.max_pending_challenges_per_did();
        let now = now_epoch();
        for i in 0..limit - 1 {
            b.store
                .store_session(&challenge_row(&format!("seed-{i}"), did, now))
                .await
                .unwrap();
        }

        let requests: Vec<_> = (0..8)
            .map(|_| {
                let b = Arc::clone(&b);
                tokio::spawn(async move { handle_challenge(&*b, input(did)).await })
            })
            .collect();
        for r in requests {
            r.await.unwrap().expect("never refused at the cap");
        }

        assert_eq!(outstanding(&b, did).await.len(), limit);
    }

    /// A store that cannot list a subject's challenges keeps the old
    /// count-and-refuse behaviour.
    #[tokio::test]
    async fn a_store_that_cannot_list_challenges_still_refuses_at_the_cap() {
        let b = backend(Acl::Present);
        for _ in 0..b.max_pending_challenges_per_did() {
            handle_challenge(&b, input("did:key:zLegacy"))
                .await
                .unwrap();
        }
        let err = handle_challenge(&b, input("did:key:zLegacy"))
            .await
            .expect_err("refused at the cap");
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("too many pending challenges")),
            "{err:?}"
        );
    }
}
