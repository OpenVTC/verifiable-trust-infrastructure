//! The accepted-document-id record — **VTI-OPS-025 … 027**, SPEC §7.2 item 11.
//!
//! # What it is for
//!
//! A signed Trust Task document is durable evidence of intent, and durable
//! evidence is replayable unless something remembers it. Once this service has
//! accepted a document with a given `id` for execution, the same document
//! arriving again **MUST NOT** cause the consequential effect a second time,
//! and a *different* document under that `id` **MUST** be refused with
//! `idConflict`. That is item 11, and VTI-OPS-025/-026 are the same rule in the
//! VTI specification's words: every document carries a unique identifier, and
//! one already accepted within the acceptance window is refused.
//!
//! # Why it is in the store, and not in a map
//!
//! **VTI-OPS-027**: "The record of accepted document identifiers MUST be shared
//! across every binding a node exposes. A document accepted on one binding MUST
//! NOT be acceptable on another." Its rationale is the whole reason this module
//! exists:
//!
//! > A document captured from one binding — a log, a proxy, a stored message —
//! > is a well-formed, correctly signed, correctly addressed document, and the
//! > second binding has no reason to doubt it. Where the two bindings do not
//! > share a record, the node's replay protection is exactly as good as its
//! > least-used transport.
//!
//! Until #1641 phase 2 the record was a process-local `InMemoryReplayGuard`
//! reachable only from [`crate::trust_tasks::dispatch_trust_task_core`]. That
//! is adequate while the dispatcher is the only door. It stops being adequate
//! the moment a task is served *both* on the dispatcher and on its bearer-JWT
//! REST route — which is exactly what phase 2 does, 49 times. The record has to
//! be shared **before** the first task moves, or the migration itself opens the
//! hole it is meant to close: the attacker replays on the door that is not
//! keeping a record.
//!
//! So the record lives in [`crate::store::keyspaces::ACCEPTED_IDS`], where any
//! binding in this process can consult it: the document dispatcher today, a
//! REST route tomorrow. Two properties fall out for free — it survives a
//! restart, which the in-memory map did not, and it is not capacity-evicted,
//! which the in-memory map was (a burst of distinct documents could push a live
//! record out before its deadline and let a replay through).
//!
//! # Using it from a binding
//!
//! ```ignore
//! let retain_until = /* the end of this consumer's acceptance window */;
//! match state.accepted_ids().claim(&doc, retain_until, now).await {
//!     Ok(Acceptance::Fresh(claim)) => {
//!         let outcome = run(&doc).await;
//!         if outcome.is_success() {
//!             claim.completed(response.as_ref()).await;
//!         } else {
//!             claim.release().await;
//!         }
//!         outcome
//!     }
//!     Ok(Acceptance::Duplicate { prior_response, .. }) => answer_with(prior_response),
//!     Ok(Acceptance::Conflict) => refuse(RejectReason::IdConflict),
//!     Err(e) => refuse(e.reject_reason()),
//! }
//! ```
//!
//! Settling the claim is not optional. A claim that is neither completed nor
//! released burns its `id` until the record expires, so a corrected resend
//! under the same `id` comes back `idConflict` for the rest of the window.
//! [`AcceptedClaim`] is `#[must_use]` and warns on drop if it was neither.
//!
//! # Why not `impl trust_tasks_rs::ReplayGuard`
//!
//! The trait is the library's seam for exactly this substitution, and this type
//! could implement it. It deliberately does not, because the trait's
//! `record_response(id, ..)` is keyed by `id` alone while
//! [`AcceptedClaim::completed`] carries the digest of the document that took
//! the claim and refuses to attach a response to anybody else's record. Having
//! both would mean two completion paths with different safety, reachable from
//! the same type. Adding the impl later is a dozen lines if a caller ever needs
//! `&dyn ReplayGuard`.

use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Row prefix inside [`crate::store::keyspaces::ACCEPTED_IDS`]. Rows are
/// `accepted:<document id>`; the prefix leaves the keyspace room for another
/// row kind without a migration.
const KEY_PREFIX: &[u8] = b"accepted:";

/// Retention applied to a claim whose caller could bound nothing — the widest
/// acceptance window this service applies, which is
/// [`crate::trust_tasks::freshness_policy`]'s `max_age` plus its skew.
///
/// SPEC §7.2 (*Bounding the record*) forbids executing a *consequential Trust
/// Task* on a document that can be placed in no window at all, so the spine
/// refuses such a document long before it reaches here and this constant is
/// unreachable from it. It exists because the record is now **durable**: the
/// in-memory guard bounded an unbounded record by capacity eviction, and a
/// keyspace does not. An unbounded row in a durable store is a leak, and the
/// direction to fail in is the one that keeps the record at least as long as
/// the document is acceptable.
///
/// Pinned against the spine's actual window by
/// `fallback_retention_matches_the_acceptance_window`.
const FALLBACK_RETENTION_SECS: i64 = 11 * 60;

/// How many locks the claim path stripes over. Claims for different `id`s
/// proceed in parallel; claims for the same `id` serialise.
const STRIPES: usize = 64;

/// The mutual exclusion that makes claim-and-record atomic.
///
/// # Why a lock at all, given `insert_if_absent`
///
/// [`KeyspaceHandle::insert_if_absent`] is atomic on its own and is what
/// actually writes the record. It is not sufficient by itself, because a claim
/// is not one operation: an **expired** record must be treated as absent (the
/// `id` is released rather than conflicting forever with a document nobody
/// would execute), so the path is read → remove-if-expired → insert. Two
/// callers racing on an expired record can each remove and each insert — the
/// second removing the first's live record — and both come away `Fresh`. That
/// is the TOCTOU #1656 closed on the authenticate path, in another costume.
///
/// # What its scope is, honestly
///
/// **Process-wide, which is the whole scope in which two claims can race
/// today.** The store is embedded fjall, which holds an exclusive lock on its
/// directory: a second process cannot open the same store, so there is no
/// second process to race with. This is the same scope as the store's own
/// per-keyspace write locks, which is what `insert_if_absent`, `take_raw` and
/// `swap` serialise on.
///
/// **It is not cross-replica, and nothing here could make it so.** Two VTC
/// replicas behind a load balancer would need a shared *store*, not a shared
/// lock, and no networked store backend exists for the VTC
/// (`vti_common::store::Store` is fjall or the enclave's vsock proxy, and the
/// VTC never targets TEE). When one does, the correct fix is a native
/// conditional write at the store layer — Redis `SET NX` / `GETDEL`, DynamoDB
/// `ConditionExpression` / `DeleteItem ReturnValues=ALL_OLD` — reached through
/// a new `KeyspaceHandle` primitive, and [`AcceptedIds::claim`] becomes a
/// single call to it. Until then a replicated VTC would double-execute, which
/// is a deployment this service does not support for several other reasons
/// (the in-memory session map, the member-count cache, the rate limiter).
static STRIPE_LOCKS: LazyLock<Vec<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| (0..STRIPES).map(|_| tokio::sync::Mutex::new(())).collect());

fn stripe_for(id: &str) -> &'static tokio::sync::Mutex<()> {
    // FNV-1a over the id. Any stable spread will do; the only requirement is
    // that one `id` always maps to one lock.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    &STRIPE_LOCKS[(h % STRIPES as u64) as usize]
}

fn key(id: &str) -> Vec<u8> {
    let mut k = KEY_PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

/// One accepted document id.
///
/// `digest` is the document's content identity — SPEC §7.2 (*Keying and
/// comparison for item 11*) requires the comparison to be over the canonical
/// serialization, because "an `id` alone cannot distinguish the retry it must
/// absorb from the conflict it must reject".
///
/// `response` is the answer the first execution produced, held so a redelivery
/// can be answered with it rather than with silence. It is the same document
/// the caller already received, kept for the acceptance window and no longer;
/// the keyspace is at rest exactly like `join_requests` and `members`, which
/// hold more.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    digest: String,
    /// The instant past which this record may be dropped, which SPEC §7.2
    /// makes the same instant as the end of this consumer's willingness to
    /// execute the document. Never optional in the row: see
    /// [`FALLBACK_RETENTION_SECS`].
    retain_until: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response: Option<Value>,
    completed: bool,
}

impl Record {
    fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.retain_until <= now
    }
}

/// The store-backed accepted-id record, usable from any binding.
///
/// Cheap to clone and to construct — the state is the keyspace handle, and the
/// locks are shared statically (see [`STRIPE_LOCKS`]). A binding holds one for
/// as long as it needs it and does not have to thread it through anything.
#[derive(Clone)]
pub(crate) struct AcceptedIds {
    ks: KeyspaceHandle,
}

/// What the record says about a document offered for execution.
pub(crate) enum Acceptance {
    /// This `id` has not been accepted before. Execute, then settle the claim
    /// with [`AcceptedClaim::completed`] or [`AcceptedClaim::release`].
    Fresh(AcceptedClaim),

    /// This `id` was already accepted, under a document with the **same**
    /// digest — a SPEC §8.4 retry, a mediator redelivery, or a replay. The
    /// caller **MUST NOT** execute again.
    ///
    /// SPEC §7.2 (*Disposition of a duplicate*): answer with the result the
    /// first execution produced where one was recorded; where the original
    /// execution is still running (`in_flight`), expose that instead of
    /// starting another. "In no case is a duplicate reported as `taskFailed`;
    /// the task did not fail, it already happened."
    Duplicate {
        prior_response: Option<Value>,
        in_flight: bool,
    },

    /// This `id` was already accepted, under a **different** document. SPEC
    /// §7.2 item 11 requires `idConflict`, and requires that it not be treated
    /// as a retry of the original.
    Conflict,
}

/// Why a claim could not be decided. Both are refusals; they differ in what
/// the producer should do about it, which is why they are not one variant.
#[derive(Debug)]
pub(crate) enum AcceptedIdsError {
    /// The document cannot be canonicalised, so it has no content identity to
    /// key a record by. Not retryable — the document is the problem.
    NotDigestible(String),
    /// The record could not be consulted or written. **Fail closed**: a
    /// consumer that cannot establish whether a document is a duplicate has
    /// not satisfied item 11, so it must not execute. `unavailable` is
    /// retryable, which is the truthful signal — the producer's bit-for-bit
    /// resend is absorbed correctly once the store is back.
    ///
    /// Carries no detail on purpose: the store's failure mode is logged at
    /// `error!` where it arises, and naming it on the wire is the SPEC §10.4
    /// leak in another costume.
    Unavailable,
}

impl AcceptedIdsError {
    /// The wire refusal for this failure.
    pub(crate) fn reject_reason(&self) -> RejectReason {
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

impl AcceptedIds {
    /// Wrap the accepted-id keyspace.
    pub(crate) fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Claim `doc`'s `id` for execution, or say why it may not be executed.
    ///
    /// `retain_until` is the end of the caller's acceptance window for this
    /// document — the instant past which the record may be dropped, which SPEC
    /// §7.2 makes the same instant as the end of the caller's willingness to
    /// execute it. `None` means the caller could bound nothing; see
    /// [`FALLBACK_RETENTION_SECS`] for what happens then and why it should not
    /// arise.
    ///
    /// The claim is taken **before** execution, not checked before and written
    /// after: two simultaneous deliveries must not both pass a check-then-act
    /// test.
    pub(crate) async fn claim(
        &self,
        doc: &TrustTask<Value>,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AcceptedIdsError> {
        let digest = trust_tasks_rs::document_digest(doc)
            .map_err(|e| AcceptedIdsError::NotDigestible(e.to_string()))?;
        let id = doc.id.clone();
        let retain_until =
            retain_until.unwrap_or_else(|| now + TimeDelta::seconds(FALLBACK_RETENTION_SECS));

        self.claim_inner(&id, digest.as_str(), retain_until, now)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %id, "accepted-id record unavailable");
                AcceptedIdsError::Unavailable
            })
    }

    async fn claim_inner(
        &self,
        id: &str,
        digest: &str,
        retain_until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AppError> {
        let _guard = stripe_for(id).lock().await;
        let k = key(id);

        if let Some(existing) = self.ks.get::<Record>(k.clone()).await? {
            if !existing.is_expired_at(now) {
                return Ok(if existing.digest == digest {
                    Acceptance::Duplicate {
                        prior_response: existing.response,
                        in_flight: !existing.completed,
                    }
                } else {
                    Acceptance::Conflict
                });
            }
            // Expired, so treated as absent: the document under it can no
            // longer be executed, and holding the key would only manufacture a
            // permanent `idConflict` for an `id` nobody can use. Safe to remove
            // under the stripe lock — no concurrent claim for this `id` can be
            // between its own read and write.
            self.ks.remove(k.clone()).await?;
        }

        let record = Record {
            digest: digest.to_string(),
            retain_until,
            response: None,
            completed: false,
        };
        if !self.ks.insert_if_absent(k, &record).await? {
            // Unreachable: every writer of this row takes the stripe lock
            // first. If it ever happens, something writes the record outside
            // this module, and the honest answer is to refuse rather than to
            // guess which of the two claims is live.
            return Err(AppError::Internal(format!(
                "accepted-id row for {id} appeared while its claim was held"
            )));
        }
        Ok(Acceptance::Fresh(AcceptedClaim {
            ids: self.clone(),
            id: id.to_string(),
            digest: digest.to_string(),
            settled: false,
        }))
    }

    /// Attach `response` to the record `id` holds, but only if that record was
    /// taken by the document whose digest is `digest`.
    async fn complete(
        &self,
        id: &str,
        digest: &str,
        response: Option<&Value>,
    ) -> Result<(), AppError> {
        let _guard = stripe_for(id).lock().await;
        let k = key(id);
        let Some(mut record) = self.ks.get::<Record>(k.clone()).await? else {
            return Ok(());
        };
        if record.digest != digest {
            return Ok(());
        }
        record.response = response.cloned();
        record.completed = true;
        self.ks.insert(k, &record).await
    }

    /// Drop the record `id` holds, if it was taken by `digest` and its
    /// execution never completed.
    ///
    /// Only the claim this digest made: a concurrent arrival that legitimately
    /// holds the key must not have it taken away by a different document's
    /// cleanup.
    async fn release(&self, id: &str, digest: &str) -> Result<(), AppError> {
        let _guard = stripe_for(id).lock().await;
        let k = key(id);
        let Some(record) = self.ks.get::<Record>(k.clone()).await? else {
            return Ok(());
        };
        if record.digest == digest && !record.completed {
            self.ks.remove(k).await?;
        }
        Ok(())
    }
}

/// A claim taken on a document `id`, held across that document's execution.
///
/// Settle it exactly once: [`Self::completed`] when the execution succeeded,
/// [`Self::release`] when it did not. Releasing a failed execution is what
/// keeps a corrected resend under the same `id` from being refused as a
/// conflict for the rest of the retention window.
#[must_use = "a claim that is neither completed nor released burns its document id until the \
              record expires"]
pub(crate) struct AcceptedClaim {
    ids: AcceptedIds,
    id: String,
    digest: String,
    settled: bool,
}

impl AcceptedClaim {
    /// The execution succeeded: record `response` so the redelivery this
    /// record exists to absorb is answered with the result rather than with
    /// silence.
    ///
    /// Failure is logged, not returned. The effect happened and the claim
    /// stands, so item 11 still holds; only the answer-a-retry courtesy of
    /// SPEC §7.2 (*Disposition of a duplicate*) is lost.
    pub(crate) async fn completed(mut self, response: Option<&Value>) {
        self.settled = true;
        if let Err(e) = self.ids.complete(&self.id, &self.digest, response).await {
            tracing::warn!(error = %e, id = %self.id, "accepted-id record: response not recorded");
        }
    }

    /// The execution did not happen — a check after the claim refused the
    /// document, or the handler failed. Give the `id` back.
    pub(crate) async fn release(mut self) {
        self.settled = true;
        if let Err(e) = self.ids.release(&self.id, &self.digest).await {
            tracing::warn!(error = %e, id = %self.id, "accepted-id record: claim not released");
        }
    }
}

impl Drop for AcceptedClaim {
    fn drop(&mut self) {
        if !self.settled {
            // An early return between the claim and its settlement — the shape
            // a `?` in a REST handler makes. Not an error the caller can be
            // told about (drop cannot await), but it burns the `id` until the
            // record expires, and it must not do so silently.
            tracing::warn!(
                id = %self.id,
                "accepted-id claim dropped without being completed or released; the document id \
                 stays spent until its record expires"
            );
        }
    }
}

/// Drop every record whose retention deadline has passed.
///
/// Correctness does not depend on this: [`AcceptedIds::claim`] already treats
/// an expired record as absent, so a row that outlives its deadline refuses
/// nothing and absorbs nothing. What the sweep bounds is **storage**. The
/// in-memory guard this replaced was bounded by capacity eviction; a keyspace
/// is not, so without a sweep the record would grow for the life of the
/// deployment.
///
/// Runs on the existing retention sweeper's tick (hourly by default), which is
/// far longer than the ~11-minute retention deadline. That is deliberate and
/// costs only storage: the steady-state size is bounded by one sweep interval's
/// worth of documents, not by uptime.
///
/// A row that cannot be parsed is **left in place** and logged. Removing it
/// would hand its `id` back, and a record this service cannot read is one it
/// cannot prove was never accepted — [`AcceptedIds::claim`] fails closed on the
/// same row for the same reason.
pub(crate) async fn sweep_expired(
    ks: &KeyspaceHandle,
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let rows = ks.prefix_iter_raw(KEY_PREFIX.to_vec()).await?;
    let mut purged = 0usize;
    let mut unreadable = 0usize;
    for (k, v) in rows {
        match serde_json::from_slice::<Record>(&v) {
            Ok(record) if record.is_expired_at(now) => {
                ks.remove(k).await?;
                purged += 1;
            }
            Ok(_) => {}
            Err(_) => unreadable += 1,
        }
    }
    if unreadable > 0 {
        tracing::warn!(
            unreadable,
            "accepted-id sweep: rows this build cannot parse were left in place"
        );
    }
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TypeUri;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn ids() -> (AcceptedIds, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store
            .keyspace(crate::store::keyspaces::ACCEPTED_IDS)
            .unwrap();
        (AcceptedIds::new(ks.clone()), ks, dir)
    }

    fn doc(id: &str, payload: Value) -> TrustTask<Value> {
        TrustTask::new(
            id,
            TypeUri::canonical("vtc/join-requests/status", 0, 1).unwrap(),
            payload,
        )
    }

    /// The fallback retention this module applies when a caller bounds nothing
    /// must not be shorter than the window the spine will accept a document
    /// in — a record dropped while its document is still executable is a
    /// replay that executes twice.
    #[test]
    fn fallback_retention_matches_the_acceptance_window() {
        let policy = crate::trust_tasks::freshness_policy();
        let window = policy.max_age.expect("the window is set") + policy.skew;
        assert_eq!(
            TimeDelta::seconds(FALLBACK_RETENTION_SECS),
            window,
            "FALLBACK_RETENTION_SECS must track freshness_policy()'s window"
        );
    }

    /// **VTI-OPS-025 / VTI-OPS-026.** The same document twice: the second
    /// claim is a duplicate carrying what the first execution recorded, not a
    /// second `Fresh`.
    #[tokio::test]
    async fn vti_ops_025_a_replayed_id_is_a_duplicate_carrying_the_recorded_outcome() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({ "requestId": "r" }));
        let until = Some(now + TimeDelta::minutes(11));

        let Ok(Acceptance::Fresh(claim)) = ids.claim(&d, until, now).await else {
            panic!("the first claim is fresh");
        };
        claim
            .completed(Some(&serde_json::json!({ "status": "pending" })))
            .await;

        match ids.claim(&d, until, now).await {
            Ok(Acceptance::Duplicate {
                prior_response,
                in_flight,
            }) => {
                assert!(!in_flight, "the first execution finished");
                assert_eq!(
                    prior_response,
                    Some(serde_json::json!({ "status": "pending" })),
                    "a redelivery is answered with the result of the original"
                );
            }
            _ => panic!("a replayed id must not be claimable a second time"),
        }
    }

    /// **VTI-OPS-025.** A duplicate arriving while the original is still
    /// running is a duplicate with nothing to return yet — not a conflict, and
    /// not a second execution.
    #[tokio::test]
    async fn vti_ops_025_a_duplicate_of_an_unfinished_execution_is_in_flight() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));
        let until = Some(now + TimeDelta::minutes(11));

        let Ok(Acceptance::Fresh(claim)) = ids.claim(&d, until, now).await else {
            panic!("fresh");
        };
        match ids.claim(&d, until, now).await {
            Ok(Acceptance::Duplicate {
                prior_response,
                in_flight,
            }) => {
                assert!(in_flight);
                assert!(prior_response.is_none());
            }
            _ => panic!("expected an in-flight duplicate"),
        }
        claim.release().await;
    }

    /// **VTI-OPS-025**, the conflict half: a *different* document under a spent
    /// `id` is `idConflict`, never absorbed as a retry.
    #[tokio::test]
    async fn vti_ops_025_a_different_document_under_a_spent_id_is_a_conflict() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let until = Some(now + TimeDelta::minutes(11));

        let Ok(Acceptance::Fresh(claim)) = ids
            .claim(&doc("req-1", serde_json::json!({ "a": 1 })), until, now)
            .await
        else {
            panic!("fresh");
        };
        claim.completed(None).await;

        let other = doc("req-1", serde_json::json!({ "a": 2 }));
        assert!(
            matches!(
                ids.claim(&other, until, now).await,
                Ok(Acceptance::Conflict)
            ),
            "a different document under a spent id is a conflict"
        );
    }

    /// A claim released because its execution failed gives the `id` back, so a
    /// corrected resend is not refused for the rest of the window.
    #[tokio::test]
    async fn a_released_claim_frees_the_id() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));
        let until = Some(now + TimeDelta::minutes(11));

        let Ok(Acceptance::Fresh(claim)) = ids.claim(&d, until, now).await else {
            panic!("fresh");
        };
        claim.release().await;

        assert!(
            matches!(ids.claim(&d, until, now).await, Ok(Acceptance::Fresh(_))),
            "a released id is claimable again"
        );
    }

    /// **VTI-OPS-026.** The record is bounded by the acceptance window: once
    /// the deadline passes the row is treated as absent, so an `id` is not
    /// pinned forever.
    #[tokio::test]
    async fn vti_ops_026_an_expired_record_is_treated_as_absent() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));

        let Ok(Acceptance::Fresh(claim)) =
            ids.claim(&d, Some(now + TimeDelta::minutes(11)), now).await
        else {
            panic!("fresh");
        };
        claim.completed(None).await;

        let later = now + TimeDelta::minutes(12);
        assert!(
            matches!(
                ids.claim(&d, Some(later + TimeDelta::minutes(11)), later)
                    .await,
                Ok(Acceptance::Fresh(_))
            ),
            "past its retention deadline the record no longer refuses anything"
        );
    }

    /// **VTI-OPS-026.** …and the sweep actually removes the row, so the record
    /// is bounded in storage and not only in effect.
    #[tokio::test]
    async fn vti_ops_026_the_sweep_purges_expired_records_and_keeps_live_ones() {
        let (ids, ks, _dir) = ids().await;
        let now = Utc::now();

        let stale = doc("stale", serde_json::json!({}));
        let live = doc("live", serde_json::json!({}));
        for (d, until) in [
            (&stale, now + TimeDelta::minutes(1)),
            (&live, now + TimeDelta::minutes(11)),
        ] {
            let Ok(Acceptance::Fresh(claim)) = ids.claim(d, Some(until), now).await else {
                panic!("fresh");
            };
            claim.completed(None).await;
        }

        let purged = sweep_expired(&ks, now + TimeDelta::minutes(5))
            .await
            .unwrap();
        assert_eq!(purged, 1, "only the expired record is purged");

        let remaining = ks.prefix_iter_raw(KEY_PREFIX.to_vec()).await.unwrap();
        assert_eq!(remaining.len(), 1, "the live record survives the sweep");
        assert_eq!(remaining[0].0, key("live"));
    }

    /// **VTI-OPS-025 / VTI-OPS-027.** Two simultaneous presentations of the
    /// same document: exactly one is `Fresh`. A check-then-insert that is not
    /// atomic gives two, which is the TOCTOU #1656 closed on the authenticate
    /// path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn vti_ops_025_concurrent_presentations_of_one_id_yield_one_claim() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));
        let until = Some(now + TimeDelta::minutes(11));

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let ids = ids.clone();
            let d = d.clone();
            set.spawn(async move {
                matches!(ids.claim(&d, until, now).await, Ok(Acceptance::Fresh(_)))
            });
        }
        let fresh = set.join_all().await.into_iter().filter(|won| *won).count();
        assert_eq!(fresh, 1, "exactly one concurrent claim may execute");
    }

    /// The same race over an **expired** record, which is the one
    /// `insert_if_absent` alone cannot settle: the path is read →
    /// remove-if-expired → insert, and without the stripe lock two callers can
    /// each remove and each insert.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn vti_ops_025_concurrent_claims_over_an_expired_record_yield_one_claim() {
        let (ids, _ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));

        let Ok(Acceptance::Fresh(claim)) =
            ids.claim(&d, Some(now + TimeDelta::minutes(1)), now).await
        else {
            panic!("fresh");
        };
        claim.completed(None).await;

        let later = now + TimeDelta::minutes(5);
        let until = Some(later + TimeDelta::minutes(11));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let ids = ids.clone();
            let d = d.clone();
            set.spawn(async move {
                matches!(ids.claim(&d, until, later).await, Ok(Acceptance::Fresh(_)))
            });
        }
        let fresh = set.join_all().await.into_iter().filter(|won| *won).count();
        assert_eq!(fresh, 1, "exactly one claim may replace an expired record");
    }

    /// **VTI-OPS-027.** The record is in the store, so a second binding
    /// consults the same rows — this is the whole point of the change. Two
    /// independent [`AcceptedIds`] over the same keyspace stand in for the
    /// dispatcher and a REST route.
    #[tokio::test]
    async fn vti_ops_027_a_second_binding_sees_what_the_first_accepted() {
        let (dispatcher, ks, _dir) = ids().await;
        let rest_route = AcceptedIds::new(ks);
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));
        let until = Some(now + TimeDelta::minutes(11));

        let Ok(Acceptance::Fresh(claim)) = dispatcher.claim(&d, until, now).await else {
            panic!("fresh");
        };
        claim
            .completed(Some(&serde_json::json!({ "ok": true })))
            .await;

        match rest_route.claim(&d, until, now).await {
            Ok(Acceptance::Duplicate { prior_response, .. }) => assert_eq!(
                prior_response,
                Some(serde_json::json!({ "ok": true })),
                "the second binding answers with the first binding's result"
            ),
            _ => panic!("a document accepted on one binding must not be acceptable on another"),
        }
    }

    /// A claim whose caller bounds nothing is still bounded — the record must
    /// not be a row with no deadline in a durable store.
    #[tokio::test]
    async fn an_unbounded_claim_is_bounded_here() {
        let (ids, ks, _dir) = ids().await;
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));

        let Ok(Acceptance::Fresh(claim)) = ids.claim(&d, None, now).await else {
            panic!("fresh");
        };
        claim.completed(None).await;

        let stored: Record = ks.get(key("req-1")).await.unwrap().expect("a row");
        assert_eq!(
            stored.retain_until,
            now + TimeDelta::seconds(FALLBACK_RETENTION_SECS)
        );
    }
}
