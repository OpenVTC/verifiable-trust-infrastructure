//! The duplicate-execution record — SPEC §7.2 item 11, VTI-OPS-025…027.
//!
//! Both witness tasks are consequential: `witness/session` opens session state
//! and `witness/session/submit` mints a credential. A mediator redelivers a
//! frame routinely (on every reconnect it re-pushes the undelivered inbox), and
//! the redelivered copy carries the same valid proof, so without a record a
//! replayed `submit` would mint a second VWC and a replayed `session` would open
//! a second session.
//!
//! This is `trust_tasks_rs::ReplayGuard` over the service's store, keyed by the
//! receiving identity and the document `id`, comparing
//! `trust_tasks_rs::document_digest` (the canonical serialization of the whole
//! document, proof included). The same document again is a duplicate and gets
//! the first answer back; a different document under the same `id` is
//! `idConflict`.
//!
//! # Why the store, not `InMemoryReplayGuard`
//!
//! The sessions it protects are durable, so the record must be: an in-memory
//! record lost on restart would let a replay of a `submit` accepted just before
//! the restart in again, and the record is also not capacity-evicted here. Same
//! reasoning as the VTC's `accepted_ids` (whose type is not reusable from this
//! crate: it lives in `vtc-service`).
//!
//! # Atomicity
//!
//! A claim is read → drop-if-expired → insert, so it runs under one mutex; the
//! insert itself is `insert_if_absent`. The mutex guards only local store calls
//! — no network await is ever made under it (R1.3). The store is embedded
//! fjall, which one process holds exclusively, so process-wide is the whole
//! scope in which two claims can race.

use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{DocumentDigest, ReplayGuard, ReplayGuardError, ReplayVerdict};
use vti_common::store::KeyspaceHandle;

use crate::store::row_key;

/// Retention for a claim the caller could not bound. The dispatcher requires
/// `issuedAt`, so every document it claims has a window; this keeps an
/// unbounded row out of a durable store if that ever changes.
const FALLBACK_RETENTION: TimeDelta = TimeDelta::minutes(11);

/// Serialises claims: see the module docs.
static CLAIMS: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    digest: String,
    retain_until: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    completed: bool,
}

/// One identity's view of the record.
pub struct AcceptedIds {
    ks: KeyspaceHandle,
    identity_did: String,
}

impl AcceptedIds {
    /// The record for documents addressed to `identity_did`.
    pub fn new(ks: KeyspaceHandle, identity_did: impl Into<String>) -> Self {
        Self {
            ks,
            identity_did: identity_did.into(),
        }
    }

    fn key(&self, id: &str) -> Vec<u8> {
        row_key(&self.identity_did, id)
    }
}

fn unavailable(e: impl std::fmt::Display) -> ReplayGuardError {
    tracing::error!(error = %e, "the duplicate-execution record is unavailable");
    ReplayGuardError("store".to_string())
}

#[async_trait::async_trait]
impl ReplayGuard for AcceptedIds {
    async fn claim(
        &self,
        id: &str,
        digest: &DocumentDigest,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<ReplayVerdict, ReplayGuardError> {
        let key = self.key(id);
        let _claims = CLAIMS.lock().await;
        if let Some(existing) = self
            .ks
            .get::<Record>(key.clone())
            .await
            .map_err(unavailable)?
        {
            if existing.retain_until > now {
                return Ok(if existing.digest == digest.as_str() {
                    ReplayVerdict::Duplicate {
                        in_flight: !existing.completed,
                        prior_response: existing.response,
                    }
                } else {
                    ReplayVerdict::Conflict
                });
            }
            // Past its retention: the `id` is released.
            self.ks.remove(key.clone()).await.map_err(unavailable)?;
        }
        let record = Record {
            digest: digest.as_str().to_string(),
            retain_until: retain_until.unwrap_or(now + FALLBACK_RETENTION),
            response: None,
            completed: false,
        };
        if self
            .ks
            .insert_if_absent(key, &record)
            .await
            .map_err(unavailable)?
        {
            Ok(ReplayVerdict::Fresh)
        } else {
            // Unreachable while every claim takes `CLAIMS`; refuse rather than
            // guess, so a document is never executed twice.
            Err(ReplayGuardError("raced".to_string()))
        }
    }

    async fn record_response(
        &self,
        id: &str,
        response: Option<&Value>,
    ) -> Result<(), ReplayGuardError> {
        let key = self.key(id);
        let _claims = CLAIMS.lock().await;
        let Some(mut record) = self
            .ks
            .get::<Record>(key.clone())
            .await
            .map_err(unavailable)?
        else {
            return Ok(());
        };
        record.completed = true;
        record.response = response.cloned();
        self.ks.insert(key, &record).await.map_err(unavailable)
    }

    async fn release(&self, id: &str, digest: &DocumentDigest) -> Result<(), ReplayGuardError> {
        let key = self.key(id);
        let _claims = CLAIMS.lock().await;
        // Only the claim this digest took: never another document's record.
        if let Some(record) = self
            .ks
            .get::<Record>(key.clone())
            .await
            .map_err(unavailable)?
            && record.digest == digest.as_str()
            && !record.completed
        {
            self.ks.remove(key).await.map_err(unavailable)?;
        }
        Ok(())
    }
}

/// Drop every record past its retention. Returns how many went.
pub(crate) async fn sweep(ks: &KeyspaceHandle, now: DateTime<Utc>) -> anyhow::Result<usize> {
    let _claims = CLAIMS.lock().await;
    let rows = ks
        .prefix_iter_raw(Vec::new())
        .await
        .map_err(|e| anyhow::anyhow!("scan the accepted-id record: {e}"))?;
    let mut removed = 0;
    for (key, value) in rows {
        let expired = serde_json::from_slice::<Record>(&value)
            .map(|r| r.retain_until <= now)
            .unwrap_or(true);
        if expired {
            ks.remove(key)
                .await
                .map_err(|e| anyhow::anyhow!("remove an accepted-id record: {e}"))?;
            removed += 1;
        }
    }
    Ok(removed)
}
