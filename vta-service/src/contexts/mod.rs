pub use vta_sdk::contexts::ContextRecord;

use chrono::Utc;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn ctx_key(id: &str) -> String {
    format!("ctx:{id}")
}

/// Retrieve a context by ID.
pub async fn get_context(ks: &KeyspaceHandle, id: &str) -> Result<Option<ContextRecord>, AppError> {
    ks.get(ctx_key(id)).await
}

/// Store (create or overwrite) a context record.
pub async fn store_context(ks: &KeyspaceHandle, record: &ContextRecord) -> Result<(), AppError> {
    ks.insert(ctx_key(&record.id), record).await
}

/// Store a NEW context record, claiming the id atomically. Returns
/// `false` (storing nothing) when the id is already taken — creation
/// paths must treat that as a Conflict, never overwrite: last-writer-
/// wins on a context record silently re-points its BIP-32 base path.
pub async fn store_new_context(
    ks: &KeyspaceHandle,
    record: &ContextRecord,
) -> Result<bool, AppError> {
    ks.insert_if_absent(ctx_key(&record.id), record).await
}

/// Delete a context by ID.
pub async fn delete_context(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(ctx_key(id)).await
}

/// List all context records.
pub async fn list_contexts(ks: &KeyspaceHandle) -> Result<Vec<ContextRecord>, AppError> {
    let raw = ks.prefix_iter_raw("ctx:").await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: ContextRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    Ok(records)
}

/// Allocate the next context index and return `(index, base_path)`.
///
/// Allocate the next BIP-32 base path under `base_prefix`, bumping the counter
/// at `counter_key`.
///
/// Top-level contexts use [`CONTEXT_KEY_BASE`] + the legacy `ctx_counter` key
/// (so existing indices are preserved). A sub-context passes its **parent's**
/// `base_path` as the prefix and a **per-parent** counter key, so each parent
/// allocates its children independently and the derivation path nests:
/// `{parent.base_path}/<child>'`.
pub async fn allocate_context_index(
    ks: &KeyspaceHandle,
    base_prefix: &str,
    counter_key: &str,
) -> Result<(u32, String), AppError> {
    // Serialised via the shared counter allocator: two concurrent
    // context creations handed the same index would share an entire
    // BIP-32 subtree — identical private keys across trust boundaries.
    let current = vti_common::store::counter::allocate_u32(ks, counter_key).await?;
    let base_path = format!("{base_prefix}/{current}'");
    Ok((current, base_path))
}

/// Create a new top-level application context and store it.
pub async fn create_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    let (index, base_path) = allocate_context_index(contexts_ks, CONTEXT_KEY_BASE, "ctx_counter")
        .await
        .map_err(|e| format!("{e}"))?;
    let now = Utc::now();
    let record = ContextRecord {
        id: id.to_string(),
        name: name.to_string(),
        did: None,
        description: None,
        parent: None,
        base_path,
        index,
        created_at: now,
        updated_at: now,
    };
    if !store_new_context(contexts_ks, &record)
        .await
        .map_err(|e| format!("{e}"))?
    {
        // The allocated counter slot is intentionally left as a gap —
        // counters skip forward on a lost race, they never reuse.
        return Err(format!("context already exists: {id}").into());
    }
    Ok(record)
}

/// Base path for application context keys.
pub const CONTEXT_KEY_BASE: &str = "m/26'/2'";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        (store.keyspace("contexts").expect("keyspace"), dir)
    }

    /// Regression test for the context-index race: N concurrent
    /// allocations must yield N distinct base paths. Two contexts
    /// handed the same index would share an entire BIP-32 subtree —
    /// identical private keys across trust boundaries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn allocate_context_index_is_collision_free_under_concurrency() {
        let (ks, _dir) = temp_ks();

        let n = 64usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                allocate_context_index(&ks, CONTEXT_KEY_BASE, "ctx_counter")
                    .await
                    .expect("alloc")
            }));
        }
        let mut paths = std::collections::HashSet::with_capacity(n);
        for h in handles {
            let (_, base_path) = h.await.expect("join");
            assert!(
                paths.insert(base_path.clone()),
                "duplicate context base path {base_path}"
            );
        }
        assert_eq!(paths.len(), n);
    }

    /// Concurrent creates with the same id: exactly one may win; the
    /// losers must not overwrite the winner's record (last-writer-wins
    /// would silently re-point the context's BIP-32 base path).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_id_creates_admit_exactly_one() {
        let (ks, _dir) = temp_ks();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                create_context(&ks, "contested", "Contested").await.ok()
            }));
        }
        let mut winners = Vec::new();
        for h in handles {
            if let Some(rec) = h.await.expect("join") {
                winners.push(rec);
            }
        }
        assert_eq!(winners.len(), 1, "exactly one same-id create may win");

        let stored = get_context(&ks, "contested")
            .await
            .expect("get")
            .expect("record exists");
        assert_eq!(
            stored.base_path, winners[0].base_path,
            "stored record must be the winner's — no overwrite by losers"
        );
    }
}
