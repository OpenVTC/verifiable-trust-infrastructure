//! Process-wide serialised allocation of little-endian `u32` store
//! counters.
//!
//! The store has no atomic increment primitive, so a bare
//! read → +1 → write sequence hands the same value to two concurrent
//! callers. For BIP-32 path and context-index counters that means two
//! records silently sharing a private-key subtree — the exact bug
//! `vta-service`'s path allocator was patched for, later found
//! re-implemented unguarded in the context allocator.
//!
//! Every counter in the workspace allocates through [`allocate_u32`],
//! which serialises behind one process-wide lock. The lock is
//! app-level (not the `LocalStore` per-keyspace write lock) so it
//! also covers the vsock backend, whose get/insert pair crosses two
//! RPCs. Allocation is infrequent and the critical section is two
//! store ops, so a single global lock is acceptable; per-key sharding
//! would be a refinement only if this becomes a hot path.
//!
//! Counters only ever move forward. A caller that allocates a value
//! and then fails simply leaves a gap — gaps are safe, reuse is not.

use std::sync::LazyLock;

use tokio::sync::Mutex;

use super::KeyspaceHandle;
use crate::error::AppError;

static COUNTER_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Allocate the next value of the `u32` counter stored at
/// `counter_key`, returning the pre-increment value (a missing key
/// reads as 0). Serialised process-wide: concurrent callers never
/// observe the same value.
///
/// The increment is fsynced before the value is returned: a counter
/// that survives only in the journal buffer could be re-derived after
/// a crash, handing out an already-used value — for BIP-32 path
/// counters that is silent private-key reuse. Allocation is
/// infrequent; the fsync cost is acceptable.
pub async fn allocate_u32(ks: &KeyspaceHandle, counter_key: &str) -> Result<u32, AppError> {
    allocate_u32_block(ks, counter_key, 1, None).await
}

/// Atomically allocate a **contiguous block** of `count` values, returning the
/// first, and optionally assert the block starts exactly where the caller
/// expects.
///
/// Two problems, one primitive.
///
/// **Contiguity.** A caller needing several adjacent indices cannot get them from
/// a loop of [`allocate_u32`]: the lock is released between calls, so a concurrent
/// allocator can land in the middle and the "block" is no longer a block. Anything
/// that predicted those indices — a dry-run — is then wrong about all of them.
///
/// **Expectation.** `expected` closes the gap between predicting an allocation and
/// performing it. A peek reserves nothing, so between a prediction and its use
/// another allocation can move the counter and the caller silently derives
/// something other than what it predicted. Passing the peeked value here makes
/// that a `Conflict` instead: the check and the allocation happen under one lock
/// acquisition, so nothing can slip between them.
///
/// This matters where the prediction was shown to a **human**. An approver who
/// authorized a rotation to key `n` must not have key `n+1` installed, and
/// "unlikely" is not the bar — the entire point of showing them the key is that
/// it is the key that executes.
///
/// A failed assertion consumes nothing. Gaps are safe; reuse is not.
pub async fn allocate_u32_block(
    ks: &KeyspaceHandle,
    counter_key: &str,
    count: u32,
    expected: Option<u32>,
) -> Result<u32, AppError> {
    let _guard = COUNTER_LOCK.lock().await;
    let current = read_u32(ks, counter_key).await?;

    if let Some(expected) = expected
        && current != expected
    {
        return Err(AppError::Conflict(format!(
            "derivation counter at `{counter_key}` moved from {expected} to {current} while a \
             decision was pending — the keys this would derive are not the keys that were approved"
        )));
    }

    if count == 0 {
        return Ok(current);
    }

    ks.insert_raw(counter_key, (current + count).to_le_bytes().to_vec())
        .await?;
    ks.persist().await?;
    // Re-seal the TEE integrity manifest so the counter bump is reflected in the
    // sealed snapshot — a rolled-back counter forces BIP-32 key reuse (P0.2a).
    // No-op unless running in a TEE.
    crate::integrity::reseal_if_active().await?;
    Ok(current)
}

/// Read the counter at `counter_key` **without** allocating (a missing key reads
/// as 0) — the value [`allocate_u32`] would return next.
///
/// This exists so a caller can compute what it *would* derive without consuming
/// an index: a dry-run that allocated would both burn a path and, worse, cause
/// the real run to derive a *different* key than the one the dry-run reported.
///
/// A peeked value is a prediction, not a reservation. Nothing stops another
/// allocation landing in between, so a caller that must guarantee the prediction
/// held has to pin the counter and re-check it at the point of use.
pub async fn peek_u32(ks: &KeyspaceHandle, counter_key: &str) -> Result<u32, AppError> {
    let _guard = COUNTER_LOCK.lock().await;
    read_u32(ks, counter_key).await
}

/// Decode the stored counter. Callers hold `COUNTER_LOCK`.
async fn read_u32(ks: &KeyspaceHandle, counter_key: &str) -> Result<u32, AppError> {
    match ks.get_raw(counter_key).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| AppError::Internal(format!("corrupt counter at {counter_key}")))?;
            Ok(u32::from_le_bytes(arr))
        }
        None => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn allocate_u32_is_collision_free_under_concurrency() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("test").expect("keyspace");

        let n = 64usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                allocate_u32(&ks, "counter:x").await.expect("alloc")
            }));
        }
        let mut seen = std::collections::HashSet::with_capacity(n);
        for h in handles {
            let v = h.await.expect("join");
            assert!(seen.insert(v), "duplicate counter value {v}");
        }
        assert_eq!(seen.len(), n);
    }

    #[tokio::test]
    async fn allocate_u32_starts_at_zero_and_is_sequential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("test").expect("keyspace");

        for expect in 0..3u32 {
            assert_eq!(allocate_u32(&ks, "counter:y").await.unwrap(), expect);
        }
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    async fn ks() -> (crate::store::KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace("keys").unwrap(), dir)
    }

    #[tokio::test]
    async fn a_block_is_contiguous() {
        let (ks, _d) = ks().await;
        // First block of 3 starts at 0; the counter then stands at 3.
        assert_eq!(allocate_u32_block(&ks, "c", 3, None).await.unwrap(), 0);
        // A single allocation continues from there — no gap, no overlap.
        assert_eq!(allocate_u32(&ks, "c").await.unwrap(), 3);
        assert_eq!(allocate_u32_block(&ks, "c", 2, None).await.unwrap(), 4);
    }

    /// The race, closed. A caller pins the counter it peeked and passes it as
    /// `expected`. If anything advanced the counter in the meantime, the
    /// allocation refuses rather than handing back a block that starts somewhere
    /// the caller did not predict.
    #[tokio::test]
    async fn an_expectation_that_no_longer_holds_is_refused() {
        let (ks, _d) = ks().await;

        // A caller peeks: the next value is 0. It intends to allocate a block
        // starting there.
        assert_eq!(peek_u32(&ks, "c").await.unwrap(), 0);

        // But a concurrent allocator lands first.
        assert_eq!(allocate_u32(&ks, "c").await.unwrap(), 0);

        // The first caller's pinned expectation (0) no longer holds. It must NOT
        // get a block — it would derive keys nobody predicted.
        let err = allocate_u32_block(&ks, "c", 2, Some(0)).await.unwrap_err();
        assert!(
            matches!(err, AppError::Conflict(_)),
            "a moved counter must be a Conflict, got: {err:?}"
        );

        // And the failure consumed nothing: the counter is still where the
        // concurrent allocator left it. Gaps are safe; a burned index would not be.
        assert_eq!(peek_u32(&ks, "c").await.unwrap(), 1);

        // Re-peeking and re-pinning to the current value succeeds.
        assert_eq!(allocate_u32_block(&ks, "c", 2, Some(1)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_matching_expectation_allocates() {
        let (ks, _d) = ks().await;
        assert_eq!(allocate_u32_block(&ks, "c", 2, Some(0)).await.unwrap(), 0);
    }
}
