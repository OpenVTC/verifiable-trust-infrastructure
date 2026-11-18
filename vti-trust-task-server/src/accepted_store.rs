//! The **durable** accepted-document-id record — the [`AcceptedIdStore`] a
//! node keeps in its own store, so the record survives a restart and is shared
//! by every binding that can reach the store (VTI-OPS-025 … 027, SPEC §7.2
//! item 11).
//!
//! # Why in the store, and not in a map
//!
//! **VTI-OPS-027**: "The record of accepted document identifiers MUST be shared
//! across every binding a node exposes. A document accepted on one binding MUST
//! NOT be acceptable on another." A process-local map meets that only while
//! every door is in one process and the process never restarts. Two further
//! properties come with the store:
//!
//! - **It survives a restart.** A document accepted a minute before a restart
//!   is still inside its acceptance window after it; with an in-memory record
//!   its replay executes a second time.
//! - **It is not capacity-evicted.** A bounded map evicts the oldest rows under
//!   load, so a burst of distinct documents can push a live record out before
//!   its deadline and let a replay through — the defence weakest exactly when
//!   the node is busiest.
//!
//! This is the record the VTC kept in its `accepted_ids` keyspace since #1641
//! phase 2, moved here so the VTA keeps the same one rather than a second
//! implementation of it.
//!
//! # Using it from a binding
//!
//! ```ignore
//! match ids.claim(&doc, retain_until, now).await {
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
//! under the same `id` is answered as a duplicate still in flight for the rest
//! of the window. [`Claim`] is `#[must_use]`, and this store's claim warns on
//! drop if it was neither.
//!
//! # Why not `impl trust_tasks_rs::ReplayGuard`
//!
//! That trait's `record_response(id, ..)` is keyed by `id` alone, while a
//! claim here carries the digest of the document that took it and refuses to
//! attach a response to anybody else's record. Having both would mean two
//! completion paths with different safety, reachable from the same type.

use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_common::store::expiry_index::{ExpiryIndex, RecordState, Unreadable};

use crate::accepted::{
    Acceptance, AcceptedIdStore, AcceptedIdsError, Claim, ClaimSettle, FALLBACK_RETENTION_SECS,
};

/// Row prefix inside the keyspace a node gives this record. Rows are
/// `accepted:<document id>`; the prefix leaves the keyspace room for another
/// row kind without a migration. Unchanged from the VTC's own record, so its
/// existing rows are read as they are.
const KEY_PREFIX: &[u8] = b"accepted:";

/// The records ordered by deadline, so a sweep reads only what expired
/// (#2626). Rows `accepted-exp:{deadline}:accepted:{id}`; records an older
/// build wrote are indexed by the first sweep that runs without the marker.
const EXPIRY: ExpiryIndex = ExpiryIndex {
    record_prefix: KEY_PREFIX,
    index_prefix: b"accepted-exp:",
    marker: b"meta:accepted-exp-index",
};

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
/// directory, or the enclave's vsock proxy to one such store: a second process
/// cannot open the same store, so there is no second process to race with.
///
/// **It is not cross-replica, and nothing here could make it so.** Two replicas
/// behind a load balancer would need a shared *store*, not a shared lock. When
/// one exists, the fix is a native conditional write at the store layer
/// reached through a new `KeyspaceHandle` primitive, and [`StoreAcceptedIds::claim`]
/// becomes a single call to it.
///
/// One set of locks for every [`StoreAcceptedIds`] in the process. Two
/// instances over *different* keyspaces share stripes they do not need to,
/// which costs a little parallelism and nothing else.
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
/// can be answered with it rather than with silence. A node that must not keep
/// a response (one that discloses a secret) records `None`.
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
/// locks are shared statically (see [`STRIPE_LOCKS`]). A binding builds one
/// over the node's keyspace whenever it needs it.
///
/// Give it a keyspace of its own: [`sweep_expired`] walks its expiry index,
/// and once every `accepted:` row in it.
#[derive(Clone)]
pub struct StoreAcceptedIds {
    ks: KeyspaceHandle,
}

impl StoreAcceptedIds {
    /// Wrap the node's accepted-id keyspace.
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Claim `doc`'s `id` for execution, or say why it may not be executed.
    ///
    /// `retain_until` is the end of the caller's acceptance window for this
    /// document. `None` means the caller could bound nothing; the record is
    /// then kept for [`FALLBACK_RETENTION_SECS`], because an unbounded row in a
    /// durable store is a leak.
    ///
    /// The claim is taken **before** execution, not checked before and written
    /// after: two simultaneous deliveries must not both pass a check-then-act
    /// test.
    pub async fn claim(
        &self,
        doc: &TrustTask<Value>,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AcceptedIdsError> {
        let digest = trust_tasks_rs::document_digest(doc)
            .map_err(|e| AcceptedIdsError::NotDigestible(e.to_string()))?;
        let retain_until =
            retain_until.unwrap_or_else(|| now + TimeDelta::seconds(FALLBACK_RETENTION_SECS));

        self.claim_inner(&doc.id, digest.as_str(), retain_until, now)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, id = %doc.id, "accepted-id record unavailable");
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

        // A row this build cannot parse is an error, and so `unavailable`: a
        // record that cannot be read is one that cannot prove the `id` was
        // never accepted.
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
        // Indexed first: an index row without its record is dropped by the
        // sweep, a record without one would never be swept.
        EXPIRY.insert(&self.ks, retain_until, &k).await?;
        if !self.ks.insert_if_absent(k, &record).await? {
            // Unreachable: every writer of this row takes the stripe lock
            // first. If it ever happens, something writes the record outside
            // this module, and the honest answer is to refuse rather than to
            // guess which of the two claims is live.
            return Err(AppError::Internal(format!(
                "accepted-id row for {id} appeared while its claim was held"
            )));
        }
        Ok(Acceptance::Fresh(Claim::new(StoreClaim {
            ids: self.clone(),
            id: id.to_string(),
            digest: digest.to_string(),
            settled: false,
        })))
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

#[async_trait::async_trait]
impl AcceptedIdStore for StoreAcceptedIds {
    async fn claim(
        &self,
        doc: &TrustTask<Value>,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Acceptance, AcceptedIdsError> {
        StoreAcceptedIds::claim(self, doc, retain_until, now).await
    }
}

/// A claim this store took, held across the document's execution.
struct StoreClaim {
    ids: StoreAcceptedIds,
    id: String,
    digest: String,
    settled: bool,
}

#[async_trait::async_trait]
impl ClaimSettle for StoreClaim {
    /// Failure is logged, not returned. The effect happened and the claim
    /// stands, so item 11 still holds; only the answer-a-retry courtesy of SPEC
    /// §7.2 (*Disposition of a duplicate*) is lost.
    async fn completed(mut self: Box<Self>, response: Option<&Value>) {
        self.settled = true;
        if let Err(e) = self.ids.complete(&self.id, &self.digest, response).await {
            tracing::warn!(error = %e, id = %self.id, "accepted-id record: response not recorded");
        }
    }

    async fn release(mut self: Box<Self>) {
        self.settled = true;
        if let Err(e) = self.ids.release(&self.id, &self.digest).await {
            tracing::warn!(error = %e, id = %self.id, "accepted-id record: claim not released");
        }
    }
}

impl Drop for StoreClaim {
    fn drop(&mut self) {
        if !self.settled {
            // An early return between the claim and its settlement. Not an
            // error the caller can be told about (drop cannot await), but it
            // burns the `id` until the record expires, and it must not do so
            // silently.
            tracing::warn!(
                id = %self.id,
                "accepted-id claim dropped without being completed or released; the document id \
                 stays spent until its record expires"
            );
        }
    }
}

/// Drop every record in `ks` whose retention deadline has passed, returning
/// how many went.
///
/// Correctness does not depend on this: [`StoreAcceptedIds::claim`] already
/// treats an expired record as absent, so a row that outlives its deadline
/// refuses nothing and absorbs nothing. What the sweep bounds is **storage**:
/// without it the record grows for the life of the deployment. The
/// steady-state size is one sweep interval's worth of documents, not uptime.
///
/// A row that cannot be parsed is **left in place** and logged. Removing it
/// would hand its `id` back, and a record this node cannot read is one it
/// cannot prove was never accepted — [`StoreAcceptedIds::claim`] fails closed
/// on the same row for the same reason.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: DateTime<Utc>) -> Result<usize, AppError> {
    // Bounded pages over the expiry index, never one read of every record: a
    // record carries its whole response, and over vsock a scan of them all is
    // one frame that stops fitting (#2626).
    let count = EXPIRY
        .sweep(
            ks,
            now,
            Unreadable::Keep,
            |v| match serde_json::from_slice::<Record>(v) {
                Ok(record) if record.is_expired_at(now) => RecordState::Expired,
                Ok(record) => RecordState::Live(record.retain_until),
                Err(_) => RecordState::Unreadable,
            },
        )
        .await?;
    if count.unreadable > 0 {
        tracing::warn!(
            unreadable = count.unreadable,
            "accepted-id sweep: rows this build cannot parse were left in place"
        );
    }
    Ok(count.purged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TypeUri;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn ids() -> (StoreAcceptedIds, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("accepted_ids").unwrap();
        (StoreAcceptedIds::new(ks.clone()), ks, dir)
    }

    fn doc(id: &str, payload: Value) -> TrustTask<Value> {
        TrustTask::new(
            id,
            TypeUri::canonical("vtc/join-requests/status", 0, 1).unwrap(),
            payload,
        )
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

    /// #2626: records an older build wrote carry no expiry-index row; the
    /// first sweep indexes them, and they are swept when due.
    #[tokio::test]
    async fn records_from_before_the_expiry_index_are_still_swept() {
        let (_ids, ks, _dir) = ids().await;
        let now = Utc::now();
        for (id, until) in [
            ("legacy-dead", now - TimeDelta::minutes(1)),
            ("legacy-live", now + TimeDelta::minutes(10)),
        ] {
            let record = Record {
                digest: "d".into(),
                retain_until: until,
                response: Some(serde_json::json!({ "big": "response" })),
                completed: true,
            };
            ks.insert(key(id), &record).await.unwrap();
        }
        assert_eq!(sweep_expired(&ks, now).await.unwrap(), 1);
        assert_eq!(
            sweep_expired(&ks, now + TimeDelta::minutes(11))
                .await
                .unwrap(),
            1,
            "the backfilled record is swept once due"
        );
        assert!(
            ks.prefix_iter_raw(KEY_PREFIX.to_vec())
                .await
                .unwrap()
                .is_empty()
        );
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
    /// independent [`StoreAcceptedIds`] over the same keyspace stand in for the
    /// dispatcher and a REST route.
    #[tokio::test]
    async fn vti_ops_027_a_second_binding_sees_what_the_first_accepted() {
        let (dispatcher, ks, _dir) = ids().await;
        let rest_route = StoreAcceptedIds::new(ks);
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

    /// **VTI-OPS-026**, across a restart: a document accepted before the node
    /// restarts is still inside its acceptance window after it, so the record
    /// must still refuse it. The in-memory guard this replaced on the VTA
    /// forgot it, and the replay executed a second time.
    #[tokio::test]
    async fn vti_ops_026_the_record_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let now = Utc::now();
        let d = doc("req-1", serde_json::json!({}));
        let until = Some(now + TimeDelta::minutes(11));
        {
            let store = Store::open(&config).unwrap();
            let ids = StoreAcceptedIds::new(store.keyspace("accepted_ids").unwrap());
            let Ok(Acceptance::Fresh(claim)) = ids.claim(&d, until, now).await else {
                panic!("fresh");
            };
            claim
                .completed(Some(&serde_json::json!({ "ok": true })))
                .await;
            store.persist().await.unwrap();
        }

        let store = Store::open(&config).unwrap();
        let ids = StoreAcceptedIds::new(store.keyspace("accepted_ids").unwrap());
        match ids.claim(&d, until, now + TimeDelta::minutes(1)).await {
            Ok(Acceptance::Duplicate { prior_response, .. }) => assert_eq!(
                prior_response,
                Some(serde_json::json!({ "ok": true })),
                "the restarted node answers with the result recorded before it"
            ),
            _ => panic!("a document accepted before a restart must not execute again after it"),
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
