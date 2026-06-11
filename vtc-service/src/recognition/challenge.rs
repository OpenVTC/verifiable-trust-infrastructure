//! Single-use recognise challenge — the freshness / replay / audience anchor
//! for the two-step cross-community `POST /v1/auth/recognise` flow.
//!
//! Unlike [`crate::credentials::present_challenge`] (keyed by the DIDComm
//! thread id of an in-flight `credential-exchange/query`), the recognise flow
//! has no thread: the caller fetches a nonce from
//! `POST /v1/auth/recognise/challenge`, the foreign-credential holder signs a
//! W3C VP over `{nonce, domain = this VTC's DID, [VEC, VMC]}`, and the
//! `recognise` handler [`consume`]s the challenge by the nonce embedded in that
//! VP. The **nonce itself is the key**.
//!
//! - **single-use** — the record is removed on consume, so a replayed VP (same
//!   nonce) finds no challenge and is refused;
//! - **TTL-bounded** — a stale nonce (aged out) is refused;
//! - **audience-bound** — the stored `aud` is the VTC DID the holder's VP
//!   `domain` must name, so a VP captured by a different VTC can't be replayed
//!   here.
//!
//! Stored in the `join_requests` keyspace under a disjoint
//! `recognise-challenge:` prefix — never collides with `present-challenge:`,
//! `join_requests:`, or `credx-pending:`.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Primary-key prefix. Disjoint from `present-challenge:`, `join_requests:`,
/// and `credx-pending:`.
const PREFIX: &str = "recognise-challenge:";

/// Default lifetime of a recognise challenge. Short — the holder fetches a
/// nonce and presents in one round-trip.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::minutes(5);

fn key(nonce: &str) -> Vec<u8> {
    format!("{PREFIX}{nonce}").into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecogniseChallenge {
    /// The verifier identity (this VTC's DID) the holder's VP `domain` must
    /// name. Recovered on [`consume`] and fed to the VP verifier as the
    /// expected audience.
    aud: String,
    expires_at: DateTime<Utc>,
}

/// The audience binding recovered by [`consume`] — the verifier identity the
/// holder's VP `domain` must name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedChallenge {
    /// The VTC DID the holder bound as the presentation `domain`.
    pub aud: String,
}

/// Issue a single-use recognise challenge bound to `aud` (this VTC's DID).
/// Returns the freshly-generated nonce for the caller to sign into its VP.
pub async fn issue(
    ks: &KeyspaceHandle,
    aud: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    let nonce = Uuid::new_v4().to_string();
    let rec = RecogniseChallenge {
        aud: aud.to_string(),
        expires_at: now + ttl,
    };
    ks.insert(key(&nonce), &rec).await?;
    Ok(nonce)
}

/// Consume the challenge identified by `nonce`. **Single-use**: the record is
/// removed before the expiry check, so a replayed presentation finds no
/// challenge. Errors if absent (unknown / already-consumed) or expired.
pub async fn consume(
    ks: &KeyspaceHandle,
    nonce: &str,
    now: DateTime<Utc>,
) -> Result<ConsumedChallenge, AppError> {
    let rec: RecogniseChallenge = ks.get(key(nonce)).await?.ok_or_else(|| {
        AppError::Validation(
            "no recognise challenge for this nonce (unknown or already consumed)".into(),
        )
    })?;
    // Remove first — single-use, even on the expired path.
    ks.remove(key(nonce)).await?;
    if now >= rec.expires_at {
        return Err(AppError::Validation(
            "recognise challenge expired (fetch a fresh one)".into(),
        ));
    }
    Ok(ConsumedChallenge { aud: rec.aud })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("join_requests").unwrap();
        (dir, ks)
    }

    #[tokio::test]
    async fn issue_then_consume_round_trips() {
        let (_dir, ks) = fresh_ks();
        let now = Utc::now();
        let nonce = issue(&ks, "did:web:vtc.example", DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();

        let consumed = consume(&ks, &nonce, now).await.unwrap();
        assert_eq!(consumed.aud, "did:web:vtc.example");
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let (_dir, ks) = fresh_ks();
        let now = Utc::now();
        let nonce = issue(&ks, "did:web:vtc.example", DEFAULT_CHALLENGE_TTL, now)
            .await
            .unwrap();

        consume(&ks, &nonce, now).await.expect("first consume");
        // A replay with the same nonce finds no challenge.
        let err = consume(&ks, &nonce, now).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("already consumed")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn consume_rejects_an_expired_challenge() {
        let (_dir, ks) = fresh_ks();
        let issued_at = Utc::now() - Duration::minutes(10);
        let nonce = issue(&ks, "did:web:vtc.example", DEFAULT_CHALLENGE_TTL, issued_at)
            .await
            .unwrap();

        let err = consume(&ks, &nonce, Utc::now()).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("expired")),
            "{err:?}"
        );
        // Even expired, it was consumed (single-use cleanup).
        let again = consume(&ks, &nonce, Utc::now()).await.unwrap_err();
        assert!(matches!(&again, AppError::Validation(m) if m.contains("already consumed")));
    }

    #[tokio::test]
    async fn consume_rejects_an_unknown_nonce() {
        let (_dir, ks) = fresh_ks();
        let err = consume(&ks, "never-issued", Utc::now()).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("unknown")),
            "{err:?}"
        );
    }
}
