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
    let _guard = COUNTER_LOCK.lock().await;
    let current = read_u32(ks, counter_key).await?;
    ks.insert_raw(counter_key, (current + 1).to_le_bytes().to_vec())
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
