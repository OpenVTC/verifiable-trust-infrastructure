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
//! `consume` removes the row, so an applicant answering `requestMore` asks for another
//! challenge and builds another proof over it. That is the intended cost: the alternative is a
//! challenge that survives its first use, which is not a freshness anchor.
//!
//! Stored in the `join_requests` keyspace under a `vetting-pcs-challenge:` prefix, disjoint
//! from `join_requests:`, `credx-pending:` and `present-challenge:`, and swept by the same
//! retention pass.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Primary-key prefix. Disjoint from every other prefix in this keyspace.
const PREFIX: &str = "vetting-pcs-challenge:";

/// How long an applicant has to build a proof over a challenge it asked for. Long enough for a
/// person to finish a submission, short enough that a leaked challenge is worth nothing.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PcsChallenge {
    challenge: String,
    expires_at: DateTime<Utc>,
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
    };
    ks.insert(key(applicant_did), &rec).await
}

/// Consume `applicant_did`'s challenge and check that `presented` is the one issued.
///
/// **Single-use**: the row is removed before the expiry check, so a replayed submission finds
/// nothing. A mismatch removes it too — an applicant who presents a challenge this community
/// did not issue does not get to keep the one it did.
///
/// # Errors
///
/// [`AppError::Validation`] if there is no open challenge, if it has expired, or if `presented`
/// is not the challenge that was issued.
pub async fn consume(
    ks: &KeyspaceHandle,
    applicant_did: &str,
    presented: &str,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let rec: PcsChallenge = ks.get(key(applicant_did)).await?.ok_or_else(|| {
        AppError::Validation(format!(
            "no open hidden-vetting challenge for `{applicant_did}` \
             (never issued, already used, or expired)"
        ))
    })?;
    ks.remove(key(applicant_did)).await?;
    if now >= rec.expires_at {
        return Err(AppError::Validation(format!(
            "hidden-vetting challenge for `{applicant_did}` expired at {}",
            rec.expires_at
        )));
    }
    // Constant-time is not the property that matters here — the challenge is this community's
    // own public nonce, and an attacker who can guess it still cannot produce a proof over it.
    if rec.challenge != presented {
        return Err(AppError::Validation(format!(
            "the submission's challenge is not the one issued to `{applicant_did}`"
        )));
    }
    Ok(())
}

/// GC every challenge row whose `expires_at` has passed — an applicant who asks for one and
/// walks away. Returns the count purged. Called by the daemon's retention sweeper.
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
        // The same proof, submitted again, finds no challenge.
        let err = consume(&state.join_requests_ks, BOB, &c, now)
            .await
            .expect_err("a consumed challenge is gone");
        assert!(format!("{err}").contains("already used"), "{err}");
    }

    /// The case the whole module exists for: a challenge the applicant minted itself.
    #[tokio::test]
    async fn a_challenge_this_community_never_issued_is_refused() {
        let state = build_test_vtc().await.state;
        let now = Utc::now();
        issue(&state.join_requests_ks, BOB, DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();
        let err = consume(&state.join_requests_ks, BOB, "deadbeef", now)
            .await
            .expect_err("not the challenge that was issued");
        assert!(format!("{err}").contains("not the one issued"), "{err}");
        // And the real one is spent by the attempt, rather than left for a second try.
        let err = consume(&state.join_requests_ks, BOB, "deadbeef", now)
            .await
            .expect_err("the row is gone either way");
        assert!(format!("{err}").contains("already used"), "{err}");
    }

    #[tokio::test]
    async fn an_expired_challenge_is_refused_and_swept() {
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
        assert_eq!(
            sweep_expired(&state.join_requests_ks, Utc::now())
                .await
                .unwrap(),
            1,
            "an abandoned challenge is swept"
        );
        let err = consume(&state.join_requests_ks, BOB, &c, Utc::now())
            .await
            .expect_err("swept");
        assert!(
            format!("{err}").contains("no open hidden-vetting challenge"),
            "{err}"
        );
    }
}
