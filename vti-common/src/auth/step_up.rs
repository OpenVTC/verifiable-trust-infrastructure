//! Pending step-up store.
//!
//! When an AAL1 session hits a step-up-gated operation, the relying party
//! (the VTA) mints a **pending step-up**: a short-lived, single-use record
//! binding a fresh `challenge` to the `session_id`/`subject` being elevated and
//! the `targetAcr` requested. It is keyed by the challenge so the matching
//! `auth/step-up/approve-response/0.1` can be located by its echoed challenge.
//!
//! Stored under `stepup:{challenge}` in the sessions keyspace, mirroring the
//! `nonce:`/`refresh:` index conventions in [`crate::auth::session`]. Records
//! are consumed exactly once on a successful (or expired) match so an
//! approve-response cannot be replayed.

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

use super::session::now_epoch;

/// A pending AAL step-up awaiting an `approve-response`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingStepUp {
    /// base64url challenge the approver echoes + signs/asserts over. The
    /// store key is `stepup:{challenge}`.
    pub challenge: String,
    /// The session being elevated.
    pub session_id: String,
    /// The VID whose session is being elevated; the approve-response's
    /// `subject` (and proof VM DID / credential subject) MUST equal this.
    pub subject: String,
    /// The acr the relying party requested. The elevated session MUST reach
    /// at least this, else `acr_unsatisfied`.
    pub target_acr: String,
    /// Evidence kinds the relying party will accept (`did-signed`,
    /// `webauthn`). Empty = any supported kind.
    #[serde(default)]
    pub acceptable_evidence: Vec<String>,
    pub created_at: u64,
    /// Unix seconds after which the step-up is no longer valid.
    pub expires_at: u64,
}

fn step_up_key(challenge: &str) -> String {
    format!("stepup:{challenge}")
}

/// Outcome of consuming a pending step-up by challenge.
#[derive(Debug, PartialEq)]
pub enum ConsumeOutcome {
    /// No pending step-up matched the challenge (`challenge_unknown`).
    NotFound,
    /// A match existed but had expired (`challenge_expired`). The stale
    /// record is removed as a side effect.
    Expired,
    /// A live match; the record was removed (single-use).
    Found(Box<PendingStepUp>),
}

/// Store a pending step-up keyed by its challenge.
pub async fn store_pending_step_up(
    sessions: &KeyspaceHandle,
    pending: &PendingStepUp,
) -> Result<(), AppError> {
    sessions
        .insert(step_up_key(&pending.challenge), pending)
        .await
}

/// Read a pending step-up by challenge without consuming it. Returns the raw
/// record (no expiry filtering) — callers that want single-use semantics
/// should use [`consume_pending_step_up`].
pub async fn get_pending_step_up(
    sessions: &KeyspaceHandle,
    challenge: &str,
) -> Result<Option<PendingStepUp>, AppError> {
    sessions.get(step_up_key(challenge)).await
}

/// Locate and **consume** the pending step-up matching `challenge` (single
/// use). On a live match the record is removed and returned; on an expired
/// match the stale record is removed and [`ConsumeOutcome::Expired`] returned;
/// a miss yields [`ConsumeOutcome::NotFound`].
///
/// Typed records are stored encrypted-aware via `insert`, so consumption is a
/// `get` (which decrypts) + `remove`, matching how the rest of the session
/// layer handles typed rows. The remove makes the challenge single-use.
pub async fn consume_pending_step_up(
    sessions: &KeyspaceHandle,
    challenge: &str,
    now: u64,
) -> Result<ConsumeOutcome, AppError> {
    let key = step_up_key(challenge);
    let Some(pending): Option<PendingStepUp> = sessions.get(key.clone()).await? else {
        return Ok(ConsumeOutcome::NotFound);
    };
    // Single-use either way: remove before returning so neither a live nor an
    // expired challenge can be presented twice.
    sessions.remove(key).await?;
    if now >= pending.expires_at {
        return Ok(ConsumeOutcome::Expired);
    }
    Ok(ConsumeOutcome::Found(Box::new(pending)))
}

/// Convenience: build a pending step-up expiring `ttl_secs` from now.
pub fn new_pending_step_up(
    challenge: impl Into<String>,
    session_id: impl Into<String>,
    subject: impl Into<String>,
    target_acr: impl Into<String>,
    acceptable_evidence: Vec<String>,
    ttl_secs: u64,
) -> PendingStepUp {
    let created_at = now_epoch();
    PendingStepUp {
        challenge: challenge.into(),
        session_id: session_id.into(),
        subject: subject.into(),
        target_acr: target_acr.into(),
        acceptable_evidence,
        created_at,
        expires_at: created_at.saturating_add(ttl_secs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    async fn ks() -> KeyspaceHandle {
        let dir = tempfile::tempdir().expect("tempdir");
        // Leak the tempdir for the test's lifetime so the fjall files survive.
        let dir = Box::leak(Box::new(dir));
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        store.keyspace("sessions").expect("keyspace")
    }

    fn sample(challenge: &str, expires_at: u64) -> PendingStepUp {
        PendingStepUp {
            challenge: challenge.to_string(),
            session_id: "sess-1".to_string(),
            subject: "did:key:zHolder".to_string(),
            target_acr: "aal2".to_string(),
            acceptable_evidence: vec!["did-signed".into(), "webauthn".into()],
            created_at: 1000,
            expires_at,
        }
    }

    #[tokio::test]
    async fn round_trips_and_consumes_once() {
        let ks = ks().await;
        let p = sample("VHJhbnNmZXJDb25maXJtTm9uY2VYWQ", now_epoch() + 300);
        store_pending_step_up(&ks, &p).await.unwrap();

        // get does not consume
        assert_eq!(
            get_pending_step_up(&ks, &p.challenge).await.unwrap(),
            Some(p.clone())
        );

        // first consume returns it
        match consume_pending_step_up(&ks, &p.challenge, now_epoch())
            .await
            .unwrap()
        {
            ConsumeOutcome::Found(found) => assert_eq!(*found, p),
            other => panic!("expected Found, got {other:?}"),
        }
        // second consume is a miss (single-use)
        assert_eq!(
            consume_pending_step_up(&ks, &p.challenge, now_epoch())
                .await
                .unwrap(),
            ConsumeOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn unknown_challenge_is_not_found() {
        let ks = ks().await;
        assert_eq!(
            consume_pending_step_up(&ks, "no-such-challenge", now_epoch())
                .await
                .unwrap(),
            ConsumeOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn expired_challenge_is_consumed_and_reported_expired() {
        let ks = ks().await;
        let p = sample("RXhwaXJlZENoYWxsZW5nZVZhbHVlWA", 1000); // expires_at in the past
        store_pending_step_up(&ks, &p).await.unwrap();
        assert_eq!(
            consume_pending_step_up(&ks, &p.challenge, now_epoch())
                .await
                .unwrap(),
            ConsumeOutcome::Expired
        );
        // expired record was removed
        assert_eq!(get_pending_step_up(&ks, &p.challenge).await.unwrap(), None);
    }

    #[test]
    fn new_pending_sets_expiry() {
        let p = new_pending_step_up(
            "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
            "sess-1",
            "did:key:zHolder",
            "aal2",
            vec!["webauthn".into()],
            300,
        );
        assert_eq!(p.expires_at, p.created_at + 300);
        assert_eq!(p.target_acr, "aal2");
    }
}
