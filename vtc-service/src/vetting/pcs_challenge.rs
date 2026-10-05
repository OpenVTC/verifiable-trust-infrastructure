//! The challenge a hidden submission is bound to — **issued by the VTC**, single-use, and
//! consumed when the proof is counted.
//!
//! A hidden proof is bound to a challenge so that one cannot be replayed: the same bytes
//! submitted twice verify twice, and without a freshness anchor the second one counts. The
//! proof already binds a challenge; what was missing until now is the half that makes it mean
//! anything, which is that the community **issued** that challenge and accepts it exactly once.
//!
//! The shape is [`crate::credentials::present_challenge`]'s, for the same reasons, with one
//! difference: a presentation challenge is keyed by the DIDComm thread it was sent on, and this
//! one is keyed by the **applicant DID**, because a hidden submission's freshness is a fact
//! about an applicant's attempt rather than about a conversation. One open challenge per
//! applicant; asking again replaces it.
//!
//! # A supplement needs a new challenge
//!
//! `consume` spends the row, so an applicant answering `requestMore` asks for another
//! challenge and builds another proof over it. That is the intended cost: the alternative is a
//! challenge that survives its first use, which is not a freshness anchor.
//!
//! Stored in the `join_requests` keyspace under a `vetting-pcs-challenge:` prefix, disjoint
//! from `join_requests:`, `credx-pending:` and `present-challenge:`, and swept by the same
//! retention pass.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::info;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

pub use super::challenge_refusal::ChallengeRefusal;

/// Primary-key prefix. Disjoint from every other prefix in this keyspace.
const PREFIX: &str = "vetting-pcs-challenge:";

/// How long an applicant has to build a proof over a challenge it asked for. Long enough for a
/// person to finish a submission, short enough that a leaked challenge is worth nothing.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PcsChallenge {
    /// Empty once spent: the marker [`consume`] leaves keeps no challenge.
    challenge: String,
    expires_at: DateTime<Utc>,
    /// Set when a submission spent it. Absent on a row written before markers existed, which is
    /// an unspent challenge, as it always was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spent_at: Option<DateTime<Utc>>,
}

fn key(applicant_did: &str) -> Vec<u8> {
    format!("{PREFIX}{applicant_did}").into_bytes()
}

/// Mint a challenge for `applicant_did` and store it. Returns the hex the applicant binds into
/// its proof.
///
/// 16 bytes from the OS: the value only has to be unguessable and unique, and it is compared
/// for equality, never parsed.
///
/// # Errors
///
/// [`AppError`] if the row cannot be written.
pub async fn issue(
    ks: &KeyspaceHandle,
    applicant_did: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let challenge: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    record(ks, applicant_did, &challenge, ttl, now).await?;
    Ok(challenge)
}

/// Store a challenge this community minted elsewhere. Split from [`issue`] so a caller that
/// already has the value — a transport that mints one per exchange, or a test replaying a
/// recorded submission — records it the one way.
///
/// # Errors
///
/// [`AppError`] if the row cannot be written.
pub async fn record(
    ks: &KeyspaceHandle,
    applicant_did: &str,
    challenge: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let rec = PcsChallenge {
        challenge: challenge.to_string(),
        expires_at: now + ttl,
        spent_at: None,
    };
    ks.insert(key(applicant_did), &rec).await
}

/// Why [`consume`] did not accept a challenge: the applicant's side of it, or the store's.
#[derive(Debug)]
pub enum ConsumeError {
    /// Refused — which way is what the applicant is told.
    Refused(ChallengeRefusal),
    /// The keyspace failed. Nothing about the submission.
    Store(AppError),
}

impl From<AppError> for ConsumeError {
    fn from(e: AppError) -> Self {
        Self::Store(e)
    }
}

impl std::fmt::Display for ConsumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => r.fmt(f),
            Self::Store(e) => e.fmt(f),
        }
    }
}

/// Consume `applicant_did`'s challenge and check that `presented` is the one issued.
///
/// **Single-use**: the row is taken atomically before anything is checked, so a replayed
/// submission cannot spend it again. A mismatch spends it too — an applicant who presents a
/// challenge this community did not issue does not get to keep the one it did.
///
/// What is left behind is a **spent marker** in place of the row: the expiry, and no challenge.
/// It is there only so that a second submission can be told "already used" rather than "never
/// issued" — the two are different stories to an applicant — and it goes when the row would
/// have, at the sweep after `expires_at`. An expired challenge is put back as it was rather than
/// marked spent, so that every attempt against it says "expired" until it is swept; it can never
/// be accepted either way. Both writes are `insert_if_absent`, so a challenge the applicant asks
/// for in the meantime is never overwritten by what this attempt leaves.
///
/// Each refusal is logged with its kind and the applicant, never the challenge value.
///
/// # Errors
///
/// [`ConsumeError::Refused`] with the [`ChallengeRefusal`] that says why, or
/// [`ConsumeError::Store`] if the keyspace fails.
pub async fn consume(
    ks: &KeyspaceHandle,
    applicant_did: &str,
    presented: &str,
    now: DateTime<Utc>,
) -> Result<(), ConsumeError> {
    let refused = |r: ChallengeRefusal| {
        info!(
            applicant = %applicant_did,
            refusal = r.kind(),
            "hidden-vetting challenge refused"
        );
        Err(ConsumeError::Refused(r))
    };

    let Some(raw) = ks.take_raw(key(applicant_did)).await? else {
        return refused(ChallengeRefusal::NotIssued);
    };
    let rec: PcsChallenge = serde_json::from_slice(&raw)
        .map_err(|e| AppError::Internal(format!("hidden-vetting challenge row: {e}")))?;

    if rec.spent_at.is_some() {
        ks.insert_if_absent(key(applicant_did), &rec).await?;
        return refused(ChallengeRefusal::AlreadyUsed);
    }
    if now >= rec.expires_at {
        ks.insert_if_absent(key(applicant_did), &rec).await?;
        return refused(ChallengeRefusal::Expired {
            expired_at: rec.expires_at,
        });
    }
    let spent = PcsChallenge {
        challenge: String::new(),
        expires_at: rec.expires_at,
        spent_at: Some(now),
    };
    ks.insert_if_absent(key(applicant_did), &spent).await?;
    // Constant-time is not the property that matters here — the challenge is this community's
    // own public nonce, and an attacker who can guess it still cannot produce a proof over it.
    if rec.challenge != presented {
        return refused(ChallengeRefusal::Mismatch);
    }
    Ok(())
}

/// GC every challenge row whose `expires_at` has passed — an applicant who asks for one and
/// walks away, and the spent markers [`consume`] leaves. Returns the count purged. Called by the daemon's retention sweeper.
///
/// # Errors
///
/// [`AppError`] if the keyspace cannot be walked.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    let mut purged = 0usize;
    for (k, raw) in ks.prefix_iter_raw(PREFIX.as_bytes().to_vec()).await? {
        // A row that will not parse is left alone: this is best-effort GC, not validation.
        if let Ok(rec) = serde_json::from_slice::<PcsChallenge>(&raw)
            && now >= rec.expires_at
        {
            ks.remove(k).await?;
            purged += 1;
        }
    }
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::build_test_vtc;

    const BOB: &str = "did:key:z6MkBob";

    /// The refusal `consume` answered with, or a panic naming what it answered instead.
    async fn refusal(
        ks: &KeyspaceHandle,
        did: &str,
        presented: &str,
        now: DateTime<Utc>,
    ) -> ChallengeRefusal {
        match consume(ks, did, presented, now).await {
            Err(ConsumeError::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_challenge_is_single_use() {
        let state = build_test_vtc().await.state;
        let now = Utc::now();
        let c = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        consume(&state.join_requests_ks, BOB, &c, now)
            .await
            .unwrap();
        // The same proof, submitted again, is told the challenge was used — not that it never
        // existed, which would send the applicant looking for the wrong problem.
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, &c, now).await,
            ChallengeRefusal::AlreadyUsed
        );
        // And again: the spent marker stays until it is swept.
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, &c, now).await,
            ChallengeRefusal::AlreadyUsed
        );
    }

    #[tokio::test]
    async fn no_challenge_asked_for_is_not_issued() {
        let state = build_test_vtc().await.state;
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, "deadbeef", Utc::now()).await,
            ChallengeRefusal::NotIssued
        );
    }

    /// The case the whole module exists for: a challenge the applicant minted itself.
    #[tokio::test]
    async fn a_challenge_this_community_never_issued_is_refused() {
        let state = build_test_vtc().await.state;
        let now = Utc::now();
        let c = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, "deadbeef", now).await,
            ChallengeRefusal::Mismatch
        );
        // And the real one is spent by the attempt, rather than left for a second try.
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, &c, now).await,
            ChallengeRefusal::AlreadyUsed
        );
    }

    /// Asking again replaces the open challenge; a proof built over the first is a mismatch.
    #[tokio::test]
    async fn a_proof_over_a_replaced_challenge_is_a_mismatch() {
        let state = build_test_vtc().await.state;
        let now = Utc::now();
        let first = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        let _second = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, &first, now).await,
            ChallengeRefusal::Mismatch
        );
    }

    /// Asking for a new challenge after one was spent clears the marker: the new one is accepted.
    #[tokio::test]
    async fn a_new_challenge_replaces_the_spent_marker() {
        let state = build_test_vtc().await.state;
        let now = Utc::now();
        let c = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        consume(&state.join_requests_ks, BOB, &c, now)
            .await
            .unwrap();
        let fresh = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        consume(&state.join_requests_ks, BOB, &fresh, now)
            .await
            .expect("a fresh challenge is accepted once");
    }

    #[tokio::test]
    async fn an_expired_challenge_says_so_until_it_is_swept() {
        let state = build_test_vtc().await.state;
        let issued_at = Utc::now() - Duration::hours(1);
        let c = issue(
            &state.join_requests_ks,
            BOB,
            DEFAULT_CHALLENGE_TTL,
            issued_at,
        )
        .await
        .unwrap();
        let expired_at = issued_at + DEFAULT_CHALLENGE_TTL;
        // Expired, and it stays expired: a second attempt is not told it was "used".
        for _ in 0..2 {
            assert_eq!(
                refusal(&state.join_requests_ks, BOB, &c, Utc::now()).await,
                ChallengeRefusal::Expired { expired_at }
            );
        }
        assert_eq!(
            sweep_expired(&state.join_requests_ks, Utc::now())
                .await
                .unwrap(),
            1,
            "an abandoned challenge is swept"
        );
        assert_eq!(
            refusal(&state.join_requests_ks, BOB, &c, Utc::now()).await,
            ChallengeRefusal::NotIssued
        );
    }

    /// The spent marker is retention-bound like the challenge it replaced, and holds no value.
    #[tokio::test]
    async fn the_spent_marker_holds_no_challenge_and_is_swept() {
        let state = build_test_vtc().await.state;
        let now = Utc::now();
        let c = issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        consume(&state.join_requests_ks, BOB, &c, now)
            .await
            .unwrap();
        let raw = state
            .join_requests_ks
            .get_raw(key(BOB))
            .await
            .unwrap()
            .expect("a spent marker");
        assert!(
            !String::from_utf8_lossy(&raw).contains(&c),
            "the marker keeps no challenge"
        );
        assert_eq!(
            sweep_expired(&state.join_requests_ks, now).await.unwrap(),
            0,
            "not before its expiry"
        );
        assert_eq!(
            sweep_expired(&state.join_requests_ks, now + DEFAULT_CHALLENGE_TTL)
                .await
                .unwrap(),
            1
        );
    }
}
