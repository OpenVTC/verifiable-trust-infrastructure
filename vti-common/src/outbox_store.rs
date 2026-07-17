//! Durable [`OutboxStore`] for the D1 delivery layer, backed by the workspace
//! [`Store`](crate::store::Store) (local fjall or vsock-proxied).
//!
//! The delivery layer's `Guaranteed` sends are written to a durable outbox so a
//! process restart does not lose delivery-critical work (the layer's
//! `InMemoryOutboxStore` is dev-only). A service backs the outbox with one
//! keyspace via [`VtiOutboxStore::new`] and drives it with the delivery layer's
//! `drain_loop` / `confirmation_loop`.
//!
//! Schema (matches the workspace keyspace pattern, cf.
//! `vta-service::messaging::drain_store`):
//! - Key:   `outbox:{idempotency_key}`
//! - Value: JSON-serialized delivery [`OutboxEntry`]
//!
//! The scanning reads ([`OutboxStore::due`], [`OutboxStore::awaiting_confirmation`])
//! prefix-scan the keyspace and filter in memory, replicating the semantics of
//! the reference `InMemoryOutboxStore` — including the per-`ordering_key` FIFO
//! head gate in `due`.

use std::collections::HashMap;

use affinidi_messaging_delivery::{OutboxEntry, OutboxError, OutboxState, OutboxStore};
use async_trait::async_trait;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

const PREFIX: &str = "outbox:";

fn outbox_key(idempotency_key: &str) -> String {
    format!("{PREFIX}{idempotency_key}")
}

/// Map a store-backend [`AppError`] to the delivery layer's [`OutboxError`].
fn backend(e: AppError) -> OutboxError {
    OutboxError::Backend(e.to_string())
}

/// A durable [`OutboxStore`] over one [`KeyspaceHandle`].
///
/// Cheap to clone-by-`Arc`: the handle is a shared reference to the keyspace,
/// so a service can hand the same store to the drain, confirmation, and send
/// paths.
pub struct VtiOutboxStore {
    ks: KeyspaceHandle,
}

impl VtiOutboxStore {
    /// Back the outbox with `ks` (one keyspace per service, e.g. `"outbox"`).
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Every persisted entry, decoded — the basis for the scanning reads.
    async fn all(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        let raw = self.ks.prefix_iter_raw(PREFIX).await.map_err(backend)?;
        let mut out = Vec::with_capacity(raw.len());
        for (_key, value) in raw {
            let entry = serde_json::from_slice(&value)
                .map_err(|e| OutboxError::Backend(format!("outbox decode: {e}")))?;
            out.push(entry);
        }
        Ok(out)
    }
}

#[async_trait]
impl OutboxStore for VtiOutboxStore {
    async fn put(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        self.ks
            .insert(outbox_key(&entry.idempotency_key), &entry)
            .await
            .map_err(backend)
    }

    async fn get(&self, idempotency_key: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        self.ks
            .get(outbox_key(idempotency_key))
            .await
            .map_err(backend)
    }

    async fn due(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        let entries = self.all().await?;

        // Per ordering-key FIFO head: the earliest-enqueued NON-TERMINAL entry
        // for each key gates the rest. Entries with no ordering key are
        // independent. (Mirrors `InMemoryOutboxStore::due`.)
        let mut head_created_at: HashMap<&str, u64> = HashMap::new();
        for e in &entries {
            if e.state.is_terminal() {
                continue;
            }
            if let Some(key) = &e.ordering_key {
                let head = head_created_at
                    .entry(key.as_str())
                    .or_insert(e.created_at_ms);
                if e.created_at_ms < *head {
                    *head = e.created_at_ms;
                }
            }
        }

        let mut due: Vec<OutboxEntry> = entries
            .iter()
            .filter(|e| e.state == OutboxState::Queued && e.next_attempt_at_ms <= now_ms)
            .filter(|e| match &e.ordering_key {
                // Only the FIFO head for this key is eligible.
                Some(key) => head_created_at.get(key.as_str()) == Some(&e.created_at_ms),
                None => true,
            })
            .cloned()
            .collect();

        // Oldest-first, tie-broken by key for determinism.
        due.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.idempotency_key.cmp(&b.idempotency_key))
        });
        Ok(due)
    }

    async fn awaiting_confirmation(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(self
            .all()
            .await?
            .into_iter()
            .filter(|e| e.state == OutboxState::Sent)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use tempfile::{TempDir, tempdir};

    fn fresh() -> (TempDir, KeyspaceHandle) {
        let dir = tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace("outbox").unwrap();
        (dir, ks)
    }

    fn entry(key: &str, created: u64) -> OutboxEntry {
        OutboxEntry::new(
            key,
            "did:example:bob",
            vec![1, 2, 3],
            created,
            created + 60_000,
        )
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        store.put(entry("k1", 1_000)).await.unwrap();

        let got = store.get("k1").await.unwrap().unwrap();
        assert_eq!(got.idempotency_key, "k1");
        assert_eq!(got.dest_did, "did:example:bob");
        assert_eq!(got.packed, vec![1, 2, 3]);
        assert_eq!(got.state, OutboxState::Queued);
        assert!(store.get("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn entries_survive_reopening_the_store() {
        // The whole point of a durable outbox: a restart must not lose queued
        // work. Write, drop the store, reopen the same data dir, read it back.
        let dir = tempdir().unwrap();
        let cfg = StoreConfig {
            data_dir: dir.path().into(),
        };
        {
            let store = VtiOutboxStore::new(Store::open(&cfg).unwrap().keyspace("outbox").unwrap());
            store.put(entry("persisted", 1_000)).await.unwrap();
        }
        let reopened = VtiOutboxStore::new(Store::open(&cfg).unwrap().keyspace("outbox").unwrap());
        assert_eq!(
            reopened
                .get("persisted")
                .await
                .unwrap()
                .unwrap()
                .idempotency_key,
            "persisted"
        );
    }

    #[tokio::test]
    async fn due_returns_queued_eligible_entries_oldest_first() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        store.put(entry("b", 2_000)).await.unwrap();
        store.put(entry("a", 1_000)).await.unwrap();
        // A future-scheduled retry is not yet due.
        let mut later = entry("c", 3_000);
        later.next_attempt_at_ms = 10_000;
        store.put(later).await.unwrap();

        let due = store.due(5_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["a", "b"]); // oldest-first, "c" not yet due
    }

    #[tokio::test]
    async fn due_honors_per_ordering_key_fifo_head() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        // Two entries share an ordering key; only the earliest is eligible.
        store
            .put(entry("head", 1_000).with_ordering_key("ord"))
            .await
            .unwrap();
        store
            .put(entry("tail", 2_000).with_ordering_key("ord"))
            .await
            .unwrap();

        let due = store.due(5_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["head"]); // tail gated behind the FIFO head
    }

    #[tokio::test]
    async fn awaiting_confirmation_returns_only_sent() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        store.put(entry("queued", 1_000)).await.unwrap();
        let mut sent = entry("sent", 1_000);
        sent.state = OutboxState::Sent;
        store.put(sent).await.unwrap();
        let mut delivered = entry("delivered", 1_000);
        delivered.state = OutboxState::Delivered;
        store.put(delivered).await.unwrap();

        let awaiting = store.awaiting_confirmation().await.unwrap();
        let keys: Vec<_> = awaiting
            .iter()
            .map(|e| e.idempotency_key.as_str())
            .collect();
        assert_eq!(keys, vec!["sent"]);
    }
}
