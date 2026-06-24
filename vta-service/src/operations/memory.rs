//! Agent-memory store (operations layer) — a per-context key/value store for
//! AI-agent memory.
//!
//! Backs the `vta/memory/{put,list,delete}/0.1` Trust Tasks
//! (`crate::trust_tasks::memory`). The transport/auth ceremony (the context-ACL
//! gate, audit) stays in the trust-task handler; this module owns the store
//! operations.
//!
//! ## Layout
//!
//! Entries live in the [`MEMORY`](crate::keyspaces::MEMORY) keyspace, one record
//! per `(contextId, key)` pair, stored under the key
//! `mem:<contextId>:<key>`. The stored value is a small JSON `MemoryRecord`
//! `{ key, value }` carrying the entry key verbatim, so `list` can return the
//! original key without having to parse it back out of the (delimiter-bearing)
//! storage key.
//!
//! - [`put`] upserts (a second `put` of the same `(contextId, key)` overwrites).
//! - [`list`] is a `mem:<contextId>:` prefix scan, returning every entry in the
//!   context. Because the prefix includes the trailing `:`, a `list` of context
//!   `a` never returns context `b`'s entries (per-domain isolation in the store
//!   layer, on top of the context-ACL gate in the handler).
//! - [`delete`] removes one entry, returning [`AppError::NotFound`] when the key
//!   is absent.

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use vta_sdk::protocols::memory::MemoryItem;

/// The stored value for one memory entry. The `key` is held verbatim so `list`
/// can reconstruct the original entry key without parsing the storage key
/// (context ids and entry keys may both contain the `:` delimiter).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryRecord {
    key: String,
    value: String,
}

/// Storage key for one `(context_id, key)` entry: `mem:<context_id>:<key>`.
fn store_key(context_id: &str, key: &str) -> String {
    format!("mem:{context_id}:{key}")
}

/// Storage-key prefix for every entry in `context_id`: `mem:<context_id>:`.
/// The trailing `:` makes the scan context-exact (a prefix of `a:` never
/// matches `ab:`).
fn context_prefix(context_id: &str) -> String {
    format!("mem:{context_id}:")
}

/// Upsert `value` under `(context_id, key)`. A second `put` of the same pair
/// overwrites the stored value.
pub async fn put(
    memory_ks: &KeyspaceHandle,
    context_id: &str,
    key: &str,
    value: &str,
) -> Result<(), AppError> {
    let record = MemoryRecord {
        key: key.to_string(),
        value: value.to_string(),
    };
    memory_ks.insert(store_key(context_id, key), &record).await
}

/// List every entry in `context_id`, in ascending storage-key order. A prefix
/// scan over `mem:<context_id>:` — never returns another context's entries.
pub async fn list(
    memory_ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<Vec<MemoryItem>, AppError> {
    let pairs = memory_ks
        .prefix_iter_raw(context_prefix(context_id))
        .await?;
    let mut items = Vec::with_capacity(pairs.len());
    for (_key_bytes, value_bytes) in pairs {
        let record: MemoryRecord = serde_json::from_slice(&value_bytes)
            .map_err(|e| AppError::Internal(format!("decode memory record: {e}")))?;
        items.push(MemoryItem {
            key: record.key,
            value: record.value,
        });
    }
    Ok(items)
}

/// Delete the entry at `(context_id, key)`. Returns [`AppError::NotFound`] when
/// the key is absent (so the handler can surface `not_found`).
pub async fn delete(
    memory_ks: &KeyspaceHandle,
    context_id: &str,
    key: &str,
) -> Result<(), AppError> {
    let sk = store_key(context_id, key);
    if memory_ks.get_raw(sk.clone()).await?.is_none() {
        return Err(AppError::NotFound(format!(
            "memory entry `{key}` not found in context `{context_id}`"
        )));
    }
    memory_ks.remove(sk).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn open() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::MEMORY).unwrap();
        (dir, ks)
    }

    #[tokio::test]
    async fn put_then_list_returns_the_entry() {
        let (_d, ks) = open().await;
        put(&ks, "ctx-a", "name", "Ada").await.unwrap();
        let items = list(&ks, "ctx-a").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key, "name");
        assert_eq!(items[0].value, "Ada");
    }

    #[tokio::test]
    async fn put_same_key_twice_upserts() {
        let (_d, ks) = open().await;
        put(&ks, "ctx-a", "name", "Ada").await.unwrap();
        put(&ks, "ctx-a", "name", "Grace").await.unwrap();
        let items = list(&ks, "ctx-a").await.unwrap();
        assert_eq!(items.len(), 1, "second put must replace, not append");
        assert_eq!(items[0].value, "Grace");
    }

    #[tokio::test]
    async fn delete_removes_and_unknown_is_not_found() {
        let (_d, ks) = open().await;
        put(&ks, "ctx-a", "k", "v").await.unwrap();
        delete(&ks, "ctx-a", "k").await.unwrap();
        assert!(list(&ks, "ctx-a").await.unwrap().is_empty());
        let err = delete(&ks, "ctx-a", "k").await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn context_a_memory_is_not_returned_listing_context_b() {
        let (_d, ks) = open().await;
        put(&ks, "ctx-a", "secret", "a-only").await.unwrap();
        put(&ks, "ctx-b", "secret", "b-only").await.unwrap();
        let a = list(&ks, "ctx-a").await.unwrap();
        let b = list(&ks, "ctx-b").await.unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].value, "a-only");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].value, "b-only");
    }

    #[tokio::test]
    async fn prefix_scan_is_context_exact() {
        // `ctx` must not match `ctx-extra` — the trailing `:` in the prefix
        // guards against a sibling-prefix bleed.
        let (_d, ks) = open().await;
        put(&ks, "ctx", "k", "short").await.unwrap();
        put(&ks, "ctx-extra", "k", "long").await.unwrap();
        let items = list(&ks, "ctx").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "short");
    }
}
