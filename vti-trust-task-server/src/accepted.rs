//! The accepted-document-id record — **VTI-OPS-025 … 027**, SPEC §7.2 item 11.
//!
//! Once a node has accepted a document with a given `id` for execution, the
//! same document arriving again **MUST NOT** cause its effect a second time,
//! and a *different* document under that `id` **MUST** be refused with
//! `idConflict`. VTI-OPS-027 requires the record to be shared by every binding
//! the node exposes, so it is a store the service supplies
//! ([`AcceptedIdStore`]); [`InMemoryAcceptedIds`] is the process-local one, for
//! tests and single-binding services.
//!
//! The record is digest-keyed (SPEC §7.2 *Keying and comparison for item
//! 11*), so a retry is told from a conflict, and it is **claimed before
//! execution**, so two simultaneous deliveries cannot both pass a
//! check-then-act test. A claim must be settled: [`Claim::completed`] when the
//! execution succeeded, [`Claim::release`] when it did not, so a corrected
//! resend under the same `id` is not refused as a conflict.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};

/// Retention applied to a claim whose caller could bound nothing: the widest
/// acceptance window a VTI node applies (ten minutes plus a minute of skew).
///
/// The spine never claims such a document — it requires `issuedAt` — so this
/// only keeps a durable record from growing without bound if a caller does.
pub const FALLBACK_RETENTION_SECS: i64 = 11 * 60;

/// What the record says about a document offered for execution.
pub enum Acceptance {
    /// This `id` has not been accepted before. Execute, then settle the claim.
    Fresh(Claim),

    /// This `id` was already accepted under a document with the **same**
    /// digest — a retry, a redelivery, or a replay. Do not execute again;
    /// answer with `prior_response` where one was recorded, or say the
    /// original is still running (`in_flight`). "In no case is a duplicate
    /// reported as `taskFailed`; the task did not fail, it already happened."
    Duplicate {
        /// The response the first execution recorded, if it recorded one.
        prior_response: Option<Value>,
        /// The first execution has not completed yet.
        in_flight: bool,
    },

    /// This `id` was already accepted under a **different** document:
    /// `idConflict`.
    Conflict,
}

/// Why a claim could not be decided. Both are refusals; they differ in what the
/// producer should do about it.
#[derive(Debug)]
#[non_exhaustive]
pub enum AcceptedIdsError {
    /// The document cannot be canonicalised, so it has no content identity to
    /// key a record by. Not retryable — the document is the problem.
    NotDigestible(String),
    /// The record could not be consulted or written. **Fail closed**, as the
    /// retryable `unavailable`. Carries no detail: the store's failure is
    /// logged where it arises, not named on the wire.
    Unavailable,
}

impl AcceptedIdsError {
    /// The wire refusal for this failure.
    pub fn reject_reason(&self) -> RejectReason {
        match self {
            Self::NotDigestible(reason) => RejectReason::InternalError {
                reason: format!(
                    "cannot canonicalise the document to key its replay record: {reason}"
                ),
            },
            Self::Unavailable => RejectReason::Unavailable { retry_after: None },
        }
    }
}

/// The store-specific half of a claim: how to record completion or give the
/// `id` back.
#[async_trait::async_trait]
pub trait ClaimSettle: Send {
    /// The execution succeeded: record `response` (or no response) against the
    /// claim. Failure is the store's to log; the claim stands.
    async fn completed(self: Box<Self>, response: Option<&Value>);
    /// The execution did not happen: give the `id` back.
    async fn release(self: Box<Self>);
}

/// A claim on a document `id`, held across that document's execution.
#[must_use = "a claim that is neither completed nor released burns its document id until the \
              record expires"]
pub struct Claim(Box<dyn ClaimSettle>);

impl Claim {
    /// Wrap a store's claim.
    pub fn new(inner: impl ClaimSettle + 'static) -> Self {
        Self(Box::new(inner))
    }

    /// The execution succeeded; record `response` for a redelivery.
    pub async fn completed(self, response: Option<&Value>) {
        self.0.completed(response).await;
    }

    /// The execution did not happen; give the `id` back.
    pub async fn release(self) {
        self.0.release().await;
    }
}

/// The accepted-id record a node shares across its bindings.
#[async_trait::async_trait]
pub trait AcceptedIdStore: Send + Sync {
    /// Claim `doc`'s `id` for execution, or say why it may not be executed.
    ///
    /// `retain_until` is the end of the caller's acceptance window for this
    /// document; `None` means the caller could bound nothing
    /// ([`FALLBACK_RETENTION_SECS`]).
    async fn claim(
        &self,
        doc: &TrustTask<Value>,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AcceptedIdsError>;
}

#[derive(Debug, Clone)]
struct Record {
    digest: String,
    retain_until: DateTime<Utc>,
    response: Option<Value>,
    completed: bool,
}

type Records = Arc<Mutex<HashMap<String, Record>>>;

/// A process-local [`AcceptedIdStore`]: the record is lost on restart and is
/// visible only to this process, so it satisfies VTI-OPS-027 only for a node
/// whose every binding runs in one process. Expired rows are dropped as they
/// are met.
#[derive(Clone, Default)]
pub struct InMemoryAcceptedIds {
    records: Records,
}

impl InMemoryAcceptedIds {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rows currently held (including expired rows not yet met).
    pub fn len(&self) -> usize {
        self.records.lock().map(|r| r.len()).unwrap_or(0)
    }

    /// Whether no row is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl AcceptedIdStore for InMemoryAcceptedIds {
    async fn claim(
        &self,
        doc: &TrustTask<Value>,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AcceptedIdsError> {
        let digest = trust_tasks_rs::document_digest(doc)
            .map_err(|e| AcceptedIdsError::NotDigestible(e.to_string()))?
            .as_str()
            .to_string();
        let retain_until =
            retain_until.unwrap_or_else(|| now + TimeDelta::seconds(FALLBACK_RETENTION_SECS));
        let mut records = self
            .records
            .lock()
            .map_err(|_| AcceptedIdsError::Unavailable)?;
        if let Some(existing) = records.get(&doc.id)
            && existing.retain_until > now
        {
            return Ok(if existing.digest == digest {
                Acceptance::Duplicate {
                    prior_response: existing.response.clone(),
                    in_flight: !existing.completed,
                }
            } else {
                Acceptance::Conflict
            });
        }
        records.insert(
            doc.id.clone(),
            Record {
                digest: digest.clone(),
                retain_until,
                response: None,
                completed: false,
            },
        );
        Ok(Acceptance::Fresh(Claim::new(InMemoryClaim {
            records: self.records.clone(),
            id: doc.id.clone(),
            digest,
        })))
    }
}

struct InMemoryClaim {
    records: Records,
    id: String,
    digest: String,
}

#[async_trait::async_trait]
impl ClaimSettle for InMemoryClaim {
    async fn completed(self: Box<Self>, response: Option<&Value>) {
        if let Ok(mut records) = self.records.lock()
            && let Some(record) = records.get_mut(&self.id)
            && record.digest == self.digest
        {
            record.response = response.cloned();
            record.completed = true;
        }
    }

    async fn release(self: Box<Self>) {
        if let Ok(mut records) = self.records.lock()
            && records
                .get(&self.id)
                .is_some_and(|r| r.digest == self.digest && !r.completed)
        {
            records.remove(&self.id);
        }
    }
}
