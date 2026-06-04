//! Single-use presentation challenge — the freshness / replay anchor for the
//! credential-exchange `present` → join loop (close-the-join-loop, part 3).
//!
//! The VTC generates a nonce when it sends a `credential-exchange/query`, keyed
//! by the query's DIDComm thread id, and binds it to the audience the holder
//! must echo (the VTC's own DID). The holder presents on that thread; the
//! `present` handler [`consume`]s the challenge:
//!
//! - **single-use** — the record is removed on consume, so a replayed
//!   `vp_token` on the same thread finds no challenge and is refused;
//! - **TTL-bounded** — a stale challenge (the nonce aged out) is refused.
//!
//! Stored in the `join_requests` keyspace under a disjoint `present-challenge:`
//! prefix (the same keyspace the credx-pending issuance store uses; the prefixes
//! never collide).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Primary-key prefix. Disjoint from `join_requests:` and `credx-pending:`.
const PREFIX: &str = "present-challenge:";

/// Default lifetime of a presentation challenge.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::minutes(5);

fn key(thread_id: &str) -> Vec<u8> {
    format!("{PREFIX}{thread_id}").into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresentChallenge {
    nonce: String,
    aud: String,
    expires_at: DateTime<Utc>,
}

/// The freshness `nonce` + `aud` a holder must have bound into its presentation,
/// recovered by [`consume`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedChallenge {
    /// The single-use nonce the holder's kb-jwt must echo.
    pub nonce: String,
    /// The verifier identity (the VTC DID) the holder's kb-jwt must name.
    pub aud: String,
}

/// Issue a single-use presentation challenge for `thread_id`, bound to `aud`
/// (the verifier identity the holder's kb-jwt must name). Returns the
/// freshly-generated nonce to place in the outgoing `credential-exchange/query`.
pub async fn issue(
    ks: &KeyspaceHandle,
    thread_id: &str,
    aud: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<String, AppError> {
    let nonce = Uuid::new_v4().to_string();
    let rec = PresentChallenge {
        nonce: nonce.clone(),
        aud: aud.to_string(),
        expires_at: now + ttl,
    };
    ks.insert(key(thread_id), &rec).await?;
    Ok(nonce)
}

/// Consume the challenge for `thread_id`. **Single-use**: the record is removed
/// before the expiry check, so a replayed presentation on the same thread finds
/// no challenge. Errors if absent (unknown / already-consumed) or expired.
pub async fn consume(
    ks: &KeyspaceHandle,
    thread_id: &str,
    now: DateTime<Utc>,
) -> Result<ConsumedChallenge, AppError> {
    let rec: PresentChallenge = ks.get(key(thread_id)).await?.ok_or_else(|| {
        AppError::Validation(format!(
            "no presentation challenge for thread `{thread_id}` (unknown or already consumed)"
        ))
    })?;
    // Remove first — single-use, even on the expired path.
    ks.remove(key(thread_id)).await?;
    if now >= rec.expires_at {
        return Err(AppError::Validation(format!(
            "presentation challenge for thread `{thread_id}` expired at {}",
            rec.expires_at
        )));
    }
    Ok(ConsumedChallenge {
        nonce: rec.nonce,
        aud: rec.aud,
    })
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
        let nonce = issue(
            &ks,
            "thread-1",
            "did:web:vtc.example",
            DEFAULT_CHALLENGE_TTL,
            now,
        )
        .await
        .unwrap();

        let consumed = consume(&ks, "thread-1", now).await.unwrap();
        assert_eq!(consumed.nonce, nonce);
        assert_eq!(consumed.aud, "did:web:vtc.example");
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let (_dir, ks) = fresh_ks();
        let now = Utc::now();
        issue(
            &ks,
            "thread-1",
            "did:web:vtc.example",
            DEFAULT_CHALLENGE_TTL,
            now,
        )
        .await
        .unwrap();

        consume(&ks, "thread-1", now).await.expect("first consume");
        // A replay on the same thread finds no challenge.
        let err = consume(&ks, "thread-1", now).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("already consumed")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn consume_rejects_an_expired_challenge() {
        let (_dir, ks) = fresh_ks();
        let issued_at = Utc::now() - Duration::minutes(10);
        issue(
            &ks,
            "thread-1",
            "did:web:vtc.example",
            DEFAULT_CHALLENGE_TTL,
            issued_at,
        )
        .await
        .unwrap();

        let err = consume(&ks, "thread-1", Utc::now()).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("expired")),
            "{err:?}"
        );
        // Even expired, it was consumed (single-use cleanup).
        let again = consume(&ks, "thread-1", Utc::now()).await.unwrap_err();
        assert!(matches!(&again, AppError::Validation(m) if m.contains("already consumed")));
    }

    #[tokio::test]
    async fn consume_rejects_an_unknown_thread() {
        let (_dir, ks) = fresh_ks();
        let err = consume(&ks, "never-issued", Utc::now()).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("unknown")),
            "{err:?}"
        );
    }
}
