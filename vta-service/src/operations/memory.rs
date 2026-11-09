//! Agent-memory store (operations layer) — a per-context, versioned store for
//! AI-agent memory.
//!
//! Backs `vta/memory/{put,delete,list}/0.2` and `vta/memory/get/0.1`, and keeps
//! serving `vta/memory/{put,list,delete}/0.1` from the same store
//! (`crate::trust_tasks::memory`). The transport/auth ceremony (capability and
//! context gates, audit) stays in the trust-task handler.
//!
//! ## One store, built on application state's
//!
//! Memory 0.2 has exactly application state's semantics with one namespace: a
//! per-context write counter that is both the `expectedVersion` token and the
//! `sinceVersion` watermark, conflicts that carry the winner's view, tombstones
//! reaped behind a watermark, and an index that makes the change feed
//! paginatable (#2115, `vta/_shared/0.1/memory-record`). Rather than keep a
//! second copy of that machinery, items are application-state records in the
//! [`MEMORY`](crate::keyspaces::MEMORY) keyspace under the fixed namespace
//! [`NAMESPACE`], each value a JSON string, written with
//! [`ValueMeasure::Utf8Text`] because the memory specification measures the
//! text, not its JSON encoding. The keyspace stays memory's own, so memory is
//! backed up, purged and capability-gated as it always was, and an application
//! namespace called `memory` in `APP_STATE` is a different thing entirely.
//!
//! ## 0.1 on the same store
//!
//! A 0.1 `put` is an unconditional 0.2 put, a 0.1 `delete` leaves a tombstone
//! (answering `notFound` when nothing was live, as 0.1 did), and a 0.1 `list`
//! returns every live item. Both versions therefore see one store, and a 0.2
//! reader syncing a context converges whatever version wrote it.
//!
//! ## Rows written before versioning
//!
//! The 0.1 store kept `mem:<contextId>:<key>` → `{key, value}`.
//! [`migrate_legacy`] moves each such row into the versioned layout at boot and
//! removes it. It is idempotent: a row is removed only after its versioned copy
//! is written, so a crash between the two re-migrates the row on the next boot
//! — giving the item a new version, which is harmless, and never losing it.

use serde::Deserialize;
use serde_json::Value;

use crate::error::AppError;
use crate::operations::app_state::{
    self, AppStateError, DeleteOutcome, ListPage, NamespaceLocks, PutOutcome, ValueMeasure,
};
use crate::store::KeyspaceHandle;
use vta_sdk::protocols::app_state::AppStateRecord;
use vta_sdk::protocols::memory::MemoryItem;

/// The application-state namespace every memory item is stored under, inside
/// the memory keyspace.
pub(crate) const NAMESPACE: &str = "memory";

/// Largest page [`list_all_live`] asks for while draining a context for 0.1.
const LIST_ALL_PAGE: usize = 1000;

/// Prefix of the rows `vta/memory/*/0.1` wrote before versioning.
const LEGACY_PREFIX: &str = "mem:";

/// The application-state layout keeps its prefixes unambiguous only because a
/// context id cannot contain `:` — so a memory call naming one that is not a
/// valid context path is refused here, before it reaches the store. Access to a
/// context does not imply the id is well formed: an unrestricted admin may act
/// in any context, including ones that cannot exist.
fn check_context(context_id: &str) -> Result<(), AppStateError> {
    vti_common::context_path::validate_context_path(context_id)
        .map_err(|e| AppStateError::Validation(format!("contextId: {e}")))
}

/// A row as the 0.1 store wrote it.
#[derive(Deserialize)]
struct LegacyRecord {
    key: String,
    value: String,
}

/// Store `value` at `(context_id, key)`, conditional on `expected_version`
/// (`None` an upsert, `Some(0)` create-only).
pub async fn put(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    context_id: &str,
    key: &str,
    value: &str,
    expected_version: Option<u64>,
) -> Result<PutOutcome, AppStateError> {
    check_context(context_id)?;
    app_state::put_measured(
        ks,
        locks,
        context_id,
        NAMESPACE,
        key,
        Some(&Value::String(value.to_string())),
        None,
        expected_version,
        ValueMeasure::Utf8Text,
    )
    .await
}

/// Forget `(context_id, key)`, leaving a tombstone; conditional on a positive
/// `expected_version`.
pub async fn delete(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
    context_id: &str,
    key: &str,
    expected_version: Option<u64>,
) -> Result<DeleteOutcome, AppStateError> {
    check_context(context_id)?;
    app_state::delete(ks, locks, context_id, NAMESPACE, key, expected_version).await
}

/// One page of a context's items: a snapshot, or the change feed from
/// `since_version`.
#[allow(clippy::too_many_arguments)]
pub async fn list(
    ks: &KeyspaceHandle,
    context_id: &str,
    prefix: Option<&str>,
    since_version: Option<u64>,
    include_values: bool,
    include_deleted: Option<bool>,
    page_size: Option<usize>,
    cursor: Option<&str>,
    tombstone_retention_seconds: Option<u64>,
) -> Result<ListPage, AppStateError> {
    check_context(context_id)?;
    app_state::list(
        ks,
        context_id,
        Some(NAMESPACE),
        prefix,
        since_version,
        include_values,
        include_deleted,
        page_size,
        cursor,
        tombstone_retention_seconds,
    )
    .await
}

/// Up to 256 named items: `(found, missing, deferred)`.
pub async fn get_many(
    ks: &KeyspaceHandle,
    context_id: &str,
    keys: &[String],
    include_deleted: bool,
) -> Result<(Vec<AppStateRecord>, Vec<String>, Vec<String>), AppStateError> {
    check_context(context_id)?;
    app_state::get_many(ks, context_id, NAMESPACE, keys, include_deleted).await
}

/// Every live item in `context_id`, in key order — what `vta/memory/list/0.1`
/// returns, which has no paging.
pub async fn list_all_live(
    ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<Vec<MemoryItem>, AppStateError> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = list(
            ks,
            context_id,
            None,
            None,
            true,
            Some(false),
            Some(LIST_ALL_PAGE),
            cursor.as_deref(),
            None,
        )
        .await?;
        for r in page.records {
            if let Some(Value::String(value)) = r.value {
                items.push(MemoryItem { key: r.key, value });
            }
        }
        match page.cursor {
            Some(next) if page.truncated => cursor = Some(next),
            _ => break,
        }
    }
    Ok(items)
}

/// Remove everything the store holds for `context_id`, versioned and legacy.
/// Called by the context-deletion cascade, so a context recreated under the
/// same id starts with no memory and a change feed from zero. Returns how many
/// items (live or tombstoned) went.
pub async fn purge_context(ks: &KeyspaceHandle, context_id: &str) -> Result<usize, AppError> {
    let mut n = app_state::purge_context(ks, context_id).await?;
    // Rows from before versioning, should the boot migration not have run yet.
    let legacy = ks
        .prefix_keys(format!("{LEGACY_PREFIX}{context_id}:"))
        .await?;
    if !legacy.is_empty() {
        n += legacy.len();
        let mut batch = vti_common::store::Batch::new();
        for key in legacy {
            batch.remove(key);
        }
        ks.apply_batch(batch).await?;
    }
    Ok(n)
}

/// Move every row the 0.1 store wrote into the versioned layout. Returns how
/// many moved. Run once at boot, before the request path opens.
///
/// The context id is recovered by stripping the record's own key from the end
/// of the storage key — unambiguous, since the record holds its key verbatim.
/// A row that cannot be read or placed (a key the versioned store refuses: empty,
/// over 512 bytes, or containing NUL; or a context id that is not a valid
/// context path) is **left where it is** and logged, so nothing is lost; it
/// still goes with its context's deletion.
pub async fn migrate_legacy(
    ks: &KeyspaceHandle,
    locks: &NamespaceLocks,
) -> Result<usize, AppError> {
    let mut moved = 0usize;
    for (sk, bytes) in ks.prefix_iter_raw(LEGACY_PREFIX).await? {
        let Ok(sk) = String::from_utf8(sk) else {
            continue;
        };
        let Ok(rec) = serde_json::from_slice::<LegacyRecord>(&bytes) else {
            tracing::warn!(storage_key = %sk, "memory migration: unreadable 0.1 row left in place");
            continue;
        };
        let Some(context_id) = sk
            .strip_prefix(LEGACY_PREFIX)
            .and_then(|rest| rest.strip_suffix(&format!(":{}", rec.key)))
        else {
            tracing::warn!(storage_key = %sk, "memory migration: 0.1 row whose key does not match its storage key left in place");
            continue;
        };
        if check_context(context_id).is_err() {
            tracing::warn!(storage_key = %sk, "memory migration: 0.1 row in a context id that cannot exist left in place");
            continue;
        }
        let written = app_state::put_measured(
            ks,
            locks,
            context_id,
            NAMESPACE,
            &rec.key,
            Some(&Value::String(rec.value)),
            None,
            None,
            ValueMeasure::Utf8TextUncapped,
        )
        .await;
        match written {
            Ok(_) => {
                ks.remove(sk).await?;
                moved += 1;
            }
            Err(e) => {
                tracing::warn!(
                    storage_key = %sk,
                    error = %e,
                    "memory migration: 0.1 row the versioned store refuses left in place"
                );
            }
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn open() -> (tempfile::TempDir, KeyspaceHandle, NamespaceLocks) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::MEMORY).unwrap();
        (dir, ks, NamespaceLocks::default())
    }

    #[tokio::test]
    async fn put_then_list_returns_the_entry() {
        let (_d, ks, l) = open().await;
        put(&ks, &l, "ctx-a", "name", "Ada", None).await.unwrap();
        let items = list_all_live(&ks, "ctx-a").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key, "name");
        assert_eq!(items[0].value, "Ada");
    }

    #[tokio::test]
    async fn put_same_key_twice_upserts_and_advances_the_version() {
        let (_d, ks, l) = open().await;
        let a = put(&ks, &l, "ctx-a", "name", "Ada", None).await.unwrap();
        let b = put(&ks, &l, "ctx-a", "name", "Grace", None).await.unwrap();
        assert!(a.created && !b.created);
        assert!(b.version > a.version);
        let items = list_all_live(&ks, "ctx-a").await.unwrap();
        assert_eq!(items.len(), 1, "second put must replace, not append");
        assert_eq!(items[0].value, "Grace");
    }

    /// The race #2115 is about: a writer that read version N loses to one that
    /// wrote after it, and is handed the winner's value.
    #[tokio::test]
    async fn a_stale_expected_version_conflicts_and_carries_the_winner() {
        let (_d, ks, l) = open().await;
        let first = put(&ks, &l, "c", "k", "one", None).await.unwrap();
        put(&ks, &l, "c", "k", "two", Some(first.version))
            .await
            .unwrap();
        let err = put(&ks, &l, "c", "k", "three", Some(first.version))
            .await
            .unwrap_err();
        match err {
            AppStateError::VersionConflict {
                current_value,
                current_version,
                ..
            } => {
                assert_eq!(current_value, Some(Value::String("two".into())));
                assert!(current_version > Some(first.version));
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_only_refuses_a_live_item() {
        let (_d, ks, l) = open().await;
        put(&ks, &l, "c", "k", "v", Some(0)).await.unwrap();
        assert!(matches!(
            put(&ks, &l, "c", "k", "v2", Some(0)).await,
            Err(AppStateError::VersionConflict { .. })
        ));
    }

    /// The cap is on the text: a value of quotes and newlines at the cap is
    /// accepted, though its JSON encoding is roughly twice the size.
    #[tokio::test]
    async fn the_cap_measures_utf8_text_not_its_json_encoding() {
        let (_d, ks, l) = open().await;
        let at_cap = "\"\n".repeat((app_state::MAX_VALUE_BYTES / 2) as usize);
        let out = put(&ks, &l, "c", "k", &at_cap, None).await.unwrap();
        assert_eq!(out.value_bytes, app_state::MAX_VALUE_BYTES);
        let over = format!("{at_cap}x");
        assert!(matches!(
            put(&ks, &l, "c", "k", &over, None).await,
            Err(AppStateError::ValueTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn delete_leaves_a_tombstone_the_change_feed_carries() {
        let (_d, ks, l) = open().await;
        let w = put(&ks, &l, "c", "k", "v", None).await.unwrap();
        let d = delete(&ks, &l, "c", "k", None).await.unwrap();
        assert!(d.existed);
        assert!(list_all_live(&ks, "c").await.unwrap().is_empty());
        let feed = list(
            &ks,
            "c",
            None,
            Some(w.version),
            true,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(feed.records.len(), 1);
        assert!(feed.records[0].deleted);
        assert_eq!(feed.records[0].value, None);
        let again = delete(&ks, &l, "c", "k", None).await.unwrap();
        assert!(
            !again.existed,
            "deleting a tombstone is a success, not a change"
        );
    }

    #[tokio::test]
    async fn context_a_memory_is_not_returned_listing_context_b() {
        let (_d, ks, l) = open().await;
        put(&ks, &l, "ctx-a", "secret", "a-only", None)
            .await
            .unwrap();
        put(&ks, &l, "ctx-b", "secret", "b-only", None)
            .await
            .unwrap();
        let a = list_all_live(&ks, "ctx-a").await.unwrap();
        let b = list_all_live(&ks, "ctx-b").await.unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].value, "a-only");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].value, "b-only");
        let (found, missing, _) = get_many(&ks, "ctx-b", &["secret".into()], false)
            .await
            .unwrap();
        assert_eq!(found[0].value, Some(Value::String("b-only".into())));
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn a_context_id_that_cannot_exist_is_refused() {
        let (_d, ks, l) = open().await;
        assert!(matches!(
            put(&ks, &l, "a:b", "k", "v", None).await,
            Err(AppStateError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn listing_is_context_exact() {
        // `ctx` must not match `ctx-extra`.
        let (_d, ks, l) = open().await;
        put(&ks, &l, "ctx", "k", "short", None).await.unwrap();
        put(&ks, &l, "ctx-extra", "k", "long", None).await.unwrap();
        let items = list_all_live(&ks, "ctx").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "short");
    }

    #[tokio::test]
    async fn list_all_live_drains_every_page() {
        let (_d, ks, l) = open().await;
        for i in 0..(LIST_ALL_PAGE + 5) {
            put(&ks, &l, "c", &format!("k{i:05}"), "v", None)
                .await
                .unwrap();
        }
        assert_eq!(
            list_all_live(&ks, "c").await.unwrap().len(),
            LIST_ALL_PAGE + 5
        );
    }

    /// A 0.1 row — including one past the cap, which 0.1 never enforced, one in
    /// a nested context, and one whose key contains the `:` delimiter — moves
    /// into the versioned store and its old row goes; a second run moves
    /// nothing. A row in a context id that cannot exist stays put.
    #[tokio::test]
    async fn legacy_rows_migrate_once_and_nothing_is_lost() {
        let (_d, ks, l) = open().await;
        let big = "x".repeat(app_state::MAX_VALUE_BYTES as usize + 10);
        for (ctx, key, value) in [
            ("a", "name", "Ada"),
            ("b/c", "k:1", big.as_str()),
            ("bad:ctx", "k", "kept"),
        ] {
            ks.insert(
                format!("mem:{ctx}:{key}"),
                &serde_json::json!({ "key": key, "value": value }),
            )
            .await
            .unwrap();
        }
        assert_eq!(migrate_legacy(&ks, &l).await.unwrap(), 2);
        assert_eq!(
            ks.prefix_keys("mem:").await.unwrap().len(),
            1,
            "only the row in an impossible context remains"
        );
        assert_eq!(list_all_live(&ks, "a").await.unwrap()[0].value, "Ada");
        let moved = list_all_live(&ks, "b/c").await.unwrap();
        assert_eq!(moved[0].key, "k:1");
        assert_eq!(moved[0].value.len(), big.len());
        assert_eq!(migrate_legacy(&ks, &l).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn purge_takes_versioned_and_legacy_rows() {
        let (_d, ks, l) = open().await;
        put(&ks, &l, "c", "k", "v", None).await.unwrap();
        ks.insert(
            "mem:c:old",
            &serde_json::json!({ "key": "old", "value": "v" }),
        )
        .await
        .unwrap();
        put(&ks, &l, "other", "k", "v", None).await.unwrap();
        assert_eq!(purge_context(&ks, "c").await.unwrap(), 2);
        assert!(list_all_live(&ks, "c").await.unwrap().is_empty());
        assert_eq!(list_all_live(&ks, "other").await.unwrap().len(), 1);
    }
}
