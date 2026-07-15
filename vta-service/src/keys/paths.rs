use crate::error::AppError;
use crate::store::KeyspaceHandle;
use tracing::debug;
use vti_common::store::counter;

/// Construct a full derivation path from a base and index.
pub fn path_at(base: &str, index: u32) -> String {
    format!("{base}/{index}'")
}

/// Allocate the next sequential derivation path from a group's counter.
///
/// Allocation goes through [`vti_common::store::counter::allocate_u32`],
/// which serialises the read-increment-write process-wide. Two
/// concurrent callers handed the same counter value would receive
/// identical BIP-32 derivation paths — two `KeyRecord`s sharing a
/// private key — so collision-freedom here is load-bearing.
pub async fn allocate_path(keys_ks: &KeyspaceHandle, base: &str) -> Result<String, AppError> {
    let counter_key = format!("path_counter:{base}");
    let current = counter::allocate_u32(keys_ks, &counter_key).await?;
    let path = path_at(base, current);
    debug!(base, path = %path, "derivation path allocated");
    Ok(path)
}

/// Read a group's path counter **without** allocating.
///
/// Pair with [`peek_paths`] to predict what a subsequent allocation would
/// derive, and pin this value so the prediction can be re-checked at the point
/// of use — a peek reserves nothing, so an allocation elsewhere in the same
/// group moves it.
pub async fn peek_path_counter(keys_ks: &KeyspaceHandle, base: &str) -> Result<u32, AppError> {
    counter::peek_u32(keys_ks, &format!("path_counter:{base}")).await
}

/// The next `count` derivation paths [`allocate_path`] *would* hand out, without
/// consuming any of them.
///
/// This is what makes a read-only dry-run of a key-rotating operation possible.
/// Deriving via `allocate_path` in order to *show* someone which key would be
/// used both burns an index and defeats the purpose: the subsequent real run
/// allocates the *next* index and derives a **different** key than the one that
/// was shown.
pub async fn peek_paths(
    keys_ks: &KeyspaceHandle,
    base: &str,
    count: u32,
) -> Result<Vec<String>, AppError> {
    let next = peek_path_counter(keys_ks, base).await?;
    Ok((0..count).map(|i| path_at(base, next + i)).collect())
}

/// Allocate `count` **contiguous** paths in one atomic step, asserting the block
/// starts at `expected_start` if given.
///
/// This is the allocating counterpart to [`peek_paths`], and it is what makes a
/// plan/apply split *sound* rather than merely plausible. Allocating the paths
/// one at a time lets a concurrent allocation split the block, and pinning the
/// counter in a caller that then allocates separately lets one slip in between
/// the check and the use. Both put keys nobody approved into the chain. Doing the
/// whole thing under one lock — the assertion and the block allocation together —
/// is the only way to promise the approver that the keys they saw are the keys
/// that execute.
pub async fn allocate_paths(
    keys_ks: &KeyspaceHandle,
    base: &str,
    count: u32,
    expected_start: Option<u32>,
) -> Result<Vec<String>, AppError> {
    let counter_key = format!("path_counter:{base}");
    let start = counter::allocate_u32_block(keys_ks, &counter_key, count, expected_start).await?;
    Ok((0..count).map(|i| path_at(base, start + i)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tempfile::TempDir;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Regression test for the BIP-32 derivation-path race: launching N
    /// concurrent `allocate_path` calls against the same base must
    /// produce N distinct paths. Without the serialization lock, this
    /// test fails reliably under release-mode contention because the
    /// non-atomic get → +1 → insert sequence hands the same counter to
    /// multiple awaiting tasks before any of them writes it back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn allocate_path_is_collision_free_under_concurrency() {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let keys_ks = Arc::new(store.keyspace(crate::keyspaces::KEYS).expect("keyspace"));

        let base = "m/26'/0'";
        let n = 64usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let ks = keys_ks.clone();
            handles.push(tokio::spawn(async move {
                allocate_path(&ks, base).await.expect("alloc")
            }));
        }

        let mut paths = HashSet::with_capacity(n);
        for h in handles {
            let p = h.await.expect("join");
            assert!(
                paths.insert(p.clone()),
                "duplicate derivation path {p} — allocate_path lost a race",
            );
        }
        assert_eq!(
            paths.len(),
            n,
            "expected {n} unique paths, got {}",
            paths.len()
        );
    }
}
