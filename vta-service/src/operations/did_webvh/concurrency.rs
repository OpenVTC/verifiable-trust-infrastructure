//! Optimistic-concurrency helpers for `WebvhDidRecord` mutations.
//!
//! Several `did_webvh` operations follow a load-then-modify-then-store
//! pattern that is susceptible to lost-update races when two operators
//! (or one operator + a bot, or the daemon + a rollback) hit the same
//! DID concurrently:
//!
//! - `register_did_with_server` reads `record.server_id` and rejects
//!   if it's not `"serverless"`, then writes the new server_id +
//!   mnemonic. Two concurrent calls both pass the serverless check
//!   then both write — the second clobbers the first, the local view
//!   ends up pointing at one of two different upstream hosts that
//!   each think they own the DID.
//! - `rotate_did_webvh_keys` reads `record.next_fragment_id`, derives
//!   N keys from `[next_fragment_id, next_fragment_id + N)`, then
//!   bumps the counter. Two concurrent rotates derive overlapping
//!   fragment ids; only one record-write survives, so the loser has
//!   minted keys whose `#key-N` references collide with the winner's.
//!
//! `update_did_webvh` already had its own ad-hoc within-operation
//! check on `log_entry_count`. The helpers in this module factor that
//! pattern out so every record-mutating op shares one CAS surface,
//! and so the next op the workspace adds can't quietly miss it.
//!
//! ## Pattern
//!
//! ```ignore
//! let record = webvh_store::get_did(&webvh_ks, did).await?...;
//! let snapshot = RecordSnapshot::capture(&record);
//! // ... perform expensive work that may mutate the record locally ...
//! // ... but BEFORE the final store, re-load and assert nothing
//! // ... else changed the on-disk record:
//! let current = webvh_store::get_did(&webvh_ks, did).await?...;
//! snapshot.assert_unchanged(&current)?;
//! webvh_store::store_did(&webvh_ks, &record).await?;
//! ```
//!
//! The assertion is conservative — `log_entry_count`, `updated_at`,
//! and `server_id` are all part of the snapshot, so any mutation a
//! concurrent op might have made surfaces as `RaceDetected`. False
//! positives (e.g. operator B touched the record but the change is
//! benign for our purposes) are vastly preferable to silent overwrites.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use vta_sdk::webvh::WebvhDidRecord;

/// Per-DID execution locks for mutations that append to a did:webvh log.
///
/// A log update reads its current head, derives and signs the next entry, then
/// persists and possibly publishes it. Those are separate store and network
/// operations, so they must remain under one lock: otherwise two requests can
/// both build a successor of the same head and one can overwrite the other's
/// local log. The lock is process-local, matching VTA's single-process owner
/// model; it intentionally does not promise coordination between replicas.
#[derive(Clone, Default)]
pub struct DidUpdateLocks {
    inner: Arc<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl DidUpdateLocks {
    /// Acquire the lock for `did`, creating it on first use.
    pub async fn acquire(&self, did: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(locks.entry(did.to_string()).or_default())
        };
        lock.lock_owned().await
    }
}

/// Process-wide registry shared by every WebVH update entry point, including
/// REST, DIDComm, Trust Task, and offline CLI callers.
pub static DID_UPDATE_LOCKS: std::sync::LazyLock<DidUpdateLocks> =
    std::sync::LazyLock::new(DidUpdateLocks::default);

/// Snapshot of the record fields we treat as the optimistic-concurrency
/// version vector. Captured at the start of an op; re-checked just
/// before the final write.
///
/// We pin three fields:
/// - `log_entry_count` — incremented by `update_did_webvh` on every
///   appended log entry; the strongest signal that someone else has
///   mutated the DID.
/// - `updated_at` — touched by every record mutation, including the
///   ones that *don't* append a log entry (`register_did_with_server`,
///   `rotate_did_webvh_keys`'s `next_fragment_id` bump). Catches
///   concurrent ops that don't grow the log.
/// - `server_id` — the serverless→server-managed transition is a
///   one-way state change that affects which transport future ops
///   take. Pin it so a concurrent register can't quietly slip a
///   different server_id underneath us.
///
/// `mnemonic`, `next_fragment_id`, and `pre_rotation_count` are NOT
/// part of the snapshot — they're owned-mutated by the op itself and
/// are expected to differ between snapshot and final write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSnapshot {
    did: String,
    log_entry_count: u32,
    updated_at: chrono::DateTime<chrono::Utc>,
    server_id: String,
}

impl RecordSnapshot {
    /// Capture the version-vector fields from `record`. Cheap — just
    /// clones a few small fields.
    pub fn capture(record: &WebvhDidRecord) -> Self {
        Self {
            did: record.did.clone(),
            log_entry_count: record.log_entry_count,
            updated_at: record.updated_at,
            server_id: record.server_id.clone(),
        }
    }

    /// Compare against the latest on-disk record. Returns
    /// `Err(RaceDetected)` if any tracked field differs.
    ///
    /// Caller-formatted error message — the common shape is
    /// `"DID {did} was updated concurrently …"`, but each op has
    /// slightly different recovery guidance, so the error type is
    /// generic and the op wraps it in its own variant.
    pub fn assert_unchanged(&self, current: &WebvhDidRecord) -> Result<(), RaceDetected> {
        debug_assert_eq!(
            self.did, current.did,
            "RecordSnapshot::assert_unchanged comparing different DIDs — caller bug"
        );
        if self.log_entry_count != current.log_entry_count {
            return Err(RaceDetected::LogEntryCountChanged {
                did: self.did.clone(),
                expected: self.log_entry_count,
                current: current.log_entry_count,
            });
        }
        if self.updated_at != current.updated_at {
            return Err(RaceDetected::UpdatedAtChanged {
                did: self.did.clone(),
                expected: self.updated_at,
                current: current.updated_at,
            });
        }
        if self.server_id != current.server_id {
            return Err(RaceDetected::ServerIdChanged {
                did: self.did.clone(),
                expected: self.server_id.clone(),
                current: current.server_id.clone(),
            });
        }
        Ok(())
    }
}

/// Reasons the snapshot's fields no longer match the on-disk record.
/// Each carries enough context for the op-layer wrapper to format an
/// actionable operator-facing message.
///
/// The `Changed` suffix is intentional — every variant says "this
/// specific field's value changed between snapshot and re-load", and
/// hoisting `Changed` to the enum name would lose that contrast with
/// other potential race shapes (e.g. a future `RecordDeleted` arm).
/// Suppress clippy's enum-variant-names lint for that reason.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error)]
pub enum RaceDetected {
    #[error(
        "DID `{did}` log_entry_count changed concurrently \
         (expected {expected}, got {current}) — another caller appended a log entry"
    )]
    LogEntryCountChanged {
        did: String,
        expected: u32,
        current: u32,
    },
    #[error(
        "DID `{did}` was modified concurrently \
         (record updated_at moved from {expected} to {current})"
    )]
    UpdatedAtChanged {
        did: String,
        expected: chrono::DateTime<chrono::Utc>,
        current: chrono::DateTime<chrono::Utc>,
    },
    #[error(
        "DID `{did}` server_id changed concurrently \
         (`{expected}` → `{current}`) — another caller registered or moved this DID"
    )]
    ServerIdChanged {
        did: String,
        expected: String,
        current: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn record(did: &str, count: u32, ts: i64, server: &str) -> WebvhDidRecord {
        WebvhDidRecord {
            did: did.into(),
            server_id: server.into(),
            mnemonic: "irrelevant".into(),
            scid: "scid".into(),
            context_id: "vta".into(),
            portable: true,
            log_entry_count: count,
            pre_rotation_count: 0,
            next_fragment_id: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0).unwrap(),
        }
    }

    #[test]
    fn unchanged_record_passes() {
        let r = record("did:webvh:foo", 1, 1_000_000, "serverless");
        let snap = RecordSnapshot::capture(&r);
        snap.assert_unchanged(&r).expect("identity case must pass");
    }

    #[test]
    fn log_entry_count_change_detected() {
        let before = record("did:webvh:foo", 1, 1_000_000, "serverless");
        let after = record("did:webvh:foo", 2, 1_000_000, "serverless");
        let snap = RecordSnapshot::capture(&before);
        let err = snap.assert_unchanged(&after).unwrap_err();
        assert!(
            matches!(
                err,
                RaceDetected::LogEntryCountChanged {
                    expected: 1,
                    current: 2,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn updated_at_change_detected() {
        let before = record("did:webvh:foo", 1, 1_000_000, "serverless");
        let after = record("did:webvh:foo", 1, 1_000_001, "serverless");
        let snap = RecordSnapshot::capture(&before);
        let err = snap.assert_unchanged(&after).unwrap_err();
        assert!(
            matches!(err, RaceDetected::UpdatedAtChanged { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn server_id_change_detected() {
        let before = record("did:webvh:foo", 1, 1_000_000, "serverless");
        let after = record("did:webvh:foo", 1, 1_000_000, "webvh-prod");
        let snap = RecordSnapshot::capture(&before);
        let err = snap.assert_unchanged(&after).unwrap_err();
        assert!(
            matches!(err, RaceDetected::ServerIdChanged { ref expected, ref current, .. }
                if expected == "serverless" && current == "webvh-prod"),
            "got {err:?}"
        );
    }

    /// Mutations to fields not part of the version vector (e.g.
    /// `mnemonic`, `next_fragment_id`) must NOT cause a false-positive
    /// race detection — the op-under-snapshot is expected to mutate
    /// those itself.
    #[test]
    fn unrelated_field_changes_do_not_trip_assertion() {
        let before = record("did:webvh:foo", 1, 1_000_000, "serverless");
        let mut after = before.clone();
        after.mnemonic = "rotated-by-this-op".into();
        after.next_fragment_id = 42;
        after.pre_rotation_count = 3;
        let snap = RecordSnapshot::capture(&before);
        snap.assert_unchanged(&after)
            .expect("only log_entry_count, updated_at, server_id are version-vector fields");
    }

    #[tokio::test]
    async fn did_update_lock_serializes_same_did() {
        let locks = DidUpdateLocks::default();
        let first = locks.acquire("did:webvh:scid:example.com:agent").await;
        let (started_tx, started_rx) = oneshot::channel();
        let (acquired_tx, mut acquired_rx) = oneshot::channel();
        let waiting_locks = locks.clone();

        let waiting = tokio::spawn(async move {
            let _ = started_tx.send(());
            let _second = waiting_locks
                .acquire("did:webvh:scid:example.com:agent")
                .await;
            let _ = acquired_tx.send(());
        });

        started_rx.await.expect("waiting task started");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut acquired_rx)
                .await
                .is_err(),
            "the second update must wait for the first holder"
        );

        drop(first);
        acquired_rx
            .await
            .expect("second update acquired after release");
        waiting.await.expect("waiting task joined");
    }
}
