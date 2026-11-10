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
//! Two index rows sit beside each entry, written in the same atomic batch as
//! the entry itself (#2550):
//! - `outbox-live:{idempotency_key}` → a small [`LiveMeta`] (state, times,
//!   ordering key), for an entry that is not terminal;
//! - `outbox-done:{created_at_ms:020}:{idempotency_key}` → empty, for one that
//!   is.
//!
//! The scanning reads ([`OutboxStore::due`], [`OutboxStore::awaiting_confirmation`])
//! read only the live rows, and load the full entry — `packed` included — just
//! for those they return, so a tick costs what is in flight rather than every
//! entry ever written. They keep the semantics of the reference
//! `InMemoryOutboxStore`, including the per-`ordering_key` FIFO head gate in
//! `due`. Reaping ([`OutboxStore::terminal_before`],
//! [`OutboxStore::remove_if_terminal`]) is a key-ordered scan of the done rows
//! and a conditional delete; a service drives it with the delivery layer's
//! `reap_loop`.
//!
//! An outbox written before the index existed is indexed once, on the first
//! scanning read, and the marker key `outbox-index:v1` records that it was.

use std::collections::HashMap;

use affinidi_messaging_delivery::{OutboxEntry, OutboxError, OutboxState, OutboxStore};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use crate::error::AppError;
use crate::store::{Batch, KeyspaceHandle};

const PREFIX: &str = "outbox:";
const LIVE_PREFIX: &str = "outbox-live:";
const DONE_PREFIX: &str = "outbox-done:";
/// Set once every entry on disk has its index row.
const INDEX_MARKER: &str = "outbox-index:v1";

fn outbox_key(idempotency_key: &str) -> String {
    format!("{PREFIX}{idempotency_key}")
}

fn live_key(idempotency_key: &str) -> String {
    format!("{LIVE_PREFIX}{idempotency_key}")
}

/// Zero-padded, so the done rows sort by creation time.
fn done_key(created_at_ms: u64, idempotency_key: &str) -> String {
    format!("{DONE_PREFIX}{created_at_ms:020}:{idempotency_key}")
}

/// Map a store-backend [`AppError`] to the delivery layer's [`OutboxError`].
fn backend(e: AppError) -> OutboxError {
    OutboxError::Backend(e.to_string())
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, OutboxError> {
    serde_json::from_slice(bytes).map_err(|e| OutboxError::Backend(format!("outbox decode: {e}")))
}

/// What the scanning reads need of a non-terminal entry: everything but the
/// message bytes, which are most of an entry's size.
#[derive(Serialize, Deserialize)]
struct LiveMeta {
    key: String,
    state: OutboxState,
    next_attempt_at_ms: u64,
    created_at_ms: u64,
    ordering_key: Option<String>,
}

/// Write `entry` and its index row, and remove the row of the other kind, to
/// `batch`. The index rows are a function of the entry alone, so nothing has to
/// be read first.
fn index_writes(batch: &mut Batch, entry: &OutboxEntry) -> Result<(), OutboxError> {
    let key = &entry.idempotency_key;
    if entry.state.is_terminal() {
        batch.remove(live_key(key));
        batch.insert_raw(done_key(entry.created_at_ms, key), Vec::new());
    } else {
        batch.remove(done_key(entry.created_at_ms, key));
        batch
            .insert(
                live_key(key),
                &LiveMeta {
                    key: key.to_string(),
                    state: entry.state,
                    next_attempt_at_ms: entry.next_attempt_at_ms,
                    created_at_ms: entry.created_at_ms,
                    ordering_key: entry.ordering_key.as_ref().map(|k| k.to_string()),
                },
            )
            .map_err(backend)?;
    }
    Ok(())
}

/// A durable [`OutboxStore`] over one [`KeyspaceHandle`].
///
/// Cheap to clone-by-`Arc`: the handle is a shared reference to the keyspace,
/// so a service can hand the same store to the drain, confirmation, and send
/// paths.
pub struct VtiOutboxStore {
    ks: KeyspaceHandle,
    indexed: OnceCell<()>,
}

impl VtiOutboxStore {
    /// Back the outbox with `ks` (one keyspace per service, e.g. `"outbox"`).
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self {
            ks,
            indexed: OnceCell::new(),
        }
    }

    /// Index an outbox written before the index existed, once.
    ///
    /// Each entry is indexed in a batch that requires it unchanged, so an entry
    /// a concurrent `put` rewrote — which wrote its own index row — is left to
    /// that write. Safe to run from two instances over one keyspace.
    async fn ensure_indexed(&self) -> Result<(), OutboxError> {
        self.indexed
            .get_or_try_init(|| async {
                if self.ks.get_raw(INDEX_MARKER).await.map_err(backend)?.is_some() {
                    return Ok(());
                }
                let raw = self.ks.prefix_iter_raw(PREFIX).await.map_err(backend)?;
                let count = raw.len();
                for (key, value) in raw {
                    let entry: OutboxEntry = match decode(&value) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(error = %e, "outbox: an entry does not read; left unindexed");
                            continue;
                        }
                    };
                    let mut batch = Batch::new();
                    batch.require_unchanged(key, value);
                    index_writes(&mut batch, &entry)?;
                    self.ks.apply_batch(batch).await.map_err(backend)?;
                }
                self.ks
                    .insert_raw(INDEX_MARKER, Vec::new())
                    .await
                    .map_err(backend)?;
                if count > 0 {
                    tracing::info!(entries = count, "outbox: indexed an existing outbox");
                }
                Ok(())
            })
            .await
            .map(|_| ())
    }

    /// The non-terminal entries' index rows.
    async fn live(&self) -> Result<Vec<LiveMeta>, OutboxError> {
        self.ensure_indexed().await?;
        let raw = self
            .ks
            .prefix_iter_raw(LIVE_PREFIX)
            .await
            .map_err(backend)?;
        raw.iter().map(|(_, v)| decode(v)).collect()
    }

    /// The full entries for `keys`, in that order, skipping any removed since.
    async fn load(&self, keys: Vec<String>) -> Result<Vec<OutboxEntry>, OutboxError> {
        let mut out = Vec::new();
        for key in keys {
            if let Some(e) = self.get(&key).await? {
                out.push(e);
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl OutboxStore for VtiOutboxStore {
    async fn put(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        // Every state transition the delivery layer makes lands here — this is
        // the one place that sees `Queued → Sent → Delivered | Unconfirmed |
        // Failed` for a durable send. Nothing else logged it, so a Guaranteed
        // send that was accepted for enqueue and then never reached its
        // mediator looked, from the outside, exactly like one that arrived: the
        // caller's `send_guaranteed` returns as soon as the entry is written,
        // and the loops that move it afterwards are silent.
        //
        // Diagnosing "the approver was never notified" without this meant
        // comparing the sender's logs against the mediator's by hand and
        // matching hashed DIDs. `dest_hash` is emitted for exactly that reason:
        // the mediator records recipients as `sha256(did)`, so this is what
        // makes a VTA log line greppable against a mediator one.
        //
        // Terminal states are `warn` when they mean loss, `info` otherwise —
        // an operator scanning for trouble should not have to know the state
        // machine to spot a message that never arrived.
        let dest_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(entry.dest_did.as_bytes());
            hex::encode(h.finalize())
        };
        match entry.state {
            OutboxState::Unconfirmed | OutboxState::Failed => tracing::warn!(
                key = %entry.idempotency_key,
                dest = %entry.dest_did,
                dest_hash = %dest_hash,
                state = ?entry.state,
                attempts = entry.attempts,
                deliver_by_ms = entry.deliver_by_ms,
                "outbox: durable send settled without confirmed delivery"
            ),
            _ => tracing::info!(
                key = %entry.idempotency_key,
                dest = %entry.dest_did,
                dest_hash = %dest_hash,
                state = ?entry.state,
                attempts = entry.attempts,
                next_attempt_at_ms = entry.next_attempt_at_ms,
                deliver_by_ms = entry.deliver_by_ms,
                "outbox: durable send state"
            ),
        }
        // The entry and its index row in one batch, so a scan never sees one
        // without the other.
        let mut batch = Batch::new();
        batch
            .insert(outbox_key(&entry.idempotency_key), &entry)
            .map_err(backend)?;
        index_writes(&mut batch, &entry)?;
        self.ks.apply_batch(batch).await.map_err(backend)?;
        Ok(())
    }

    async fn get(&self, idempotency_key: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        self.ks
            .get(outbox_key(idempotency_key))
            .await
            .map_err(backend)
    }

    async fn due(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        let live = self.live().await?;

        // Per ordering-key FIFO head: the earliest-enqueued NON-TERMINAL entry
        // for each key gates the rest — and every live row is non-terminal.
        // Entries with no ordering key are independent. (Mirrors
        // `InMemoryOutboxStore::due`.)
        let mut head_created_at: HashMap<&str, u64> = HashMap::new();
        for m in &live {
            if let Some(key) = &m.ordering_key {
                let head = head_created_at
                    .entry(key.as_str())
                    .or_insert(m.created_at_ms);
                if m.created_at_ms < *head {
                    *head = m.created_at_ms;
                }
            }
        }

        let mut due: Vec<&LiveMeta> = live
            .iter()
            .filter(|m| m.state == OutboxState::Queued && m.next_attempt_at_ms <= now_ms)
            .filter(|m| match &m.ordering_key {
                // Only the FIFO head for this key is eligible.
                Some(key) => head_created_at.get(key.as_str()) == Some(&m.created_at_ms),
                None => true,
            })
            .collect();

        // Oldest-first, tie-broken by key for determinism.
        due.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.key.cmp(&b.key))
        });
        let keys: Vec<String> = due.into_iter().map(|m| m.key.clone()).collect();
        // An entry that moved on since the index was read is no longer due.
        Ok(self
            .load(keys)
            .await?
            .into_iter()
            .filter(|e| e.state == OutboxState::Queued && e.next_attempt_at_ms <= now_ms)
            .collect())
    }

    async fn awaiting_confirmation(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        let sent = self
            .live()
            .await?
            .into_iter()
            .filter(|m| m.state == OutboxState::Sent)
            .map(|m| m.key)
            .collect();
        Ok(self
            .load(sent)
            .await?
            .into_iter()
            .filter(|e| e.state == OutboxState::Sent)
            .collect())
    }

    /// Terminal entries created **and whose delivery window closed** at or before
    /// `cutoff_ms`, oldest first.
    ///
    /// The window condition is this store's, and narrower than the trait asks.
    /// A push ([`crate::trust_task_push`]) reads its attempt's entry until it
    /// sees the attempt settle, and an attempt's window can run past any fixed
    /// retention (an election notice runs until the election closes). An entry
    /// reaped before the push saw it would read as never queued, and the push
    /// would send it again. Held until its window closed a whole retention ago,
    /// an entry has outlived the push's view of it many times over: the sweep
    /// runs every thirty seconds.
    async fn terminal_before(&self, cutoff_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        self.ensure_indexed().await?;
        // The done rows sort by creation time, so the scan reads keys only and
        // stops at the cutoff.
        let keys = self.ks.prefix_keys(DONE_PREFIX).await.map_err(backend)?;
        let mut due = Vec::new();
        for key in keys {
            let key = String::from_utf8_lossy(&key);
            let Some((created, idem)) = key
                .strip_prefix(DONE_PREFIX)
                .and_then(|rest| rest.split_once(':'))
            else {
                continue;
            };
            let Ok(created) = created.parse::<u64>() else {
                continue;
            };
            if created > cutoff_ms {
                break;
            }
            due.push(idem.to_string());
        }
        Ok(self
            .load(due)
            .await?
            .into_iter()
            .filter(|e| {
                e.state.is_terminal()
                    && e.created_at_ms <= cutoff_ms
                    && e.deliver_by_ms <= cutoff_ms
            })
            .collect())
    }

    async fn remove_if_terminal(&self, idempotency_key: &str) -> Result<bool, OutboxError> {
        let key = outbox_key(idempotency_key);
        let Some(raw) = self.ks.get_raw(key.clone()).await.map_err(backend)? else {
            return Ok(false);
        };
        let entry: OutboxEntry = decode(&raw)?;
        if !entry.state.is_terminal() {
            return Ok(false);
        }
        // The check and the delete in one batch, under the keyspace's write
        // lock that `put` also takes: an entry re-queued since it was read is
        // not removed (the trait's CWE-367 note).
        let mut batch = Batch::new();
        batch.require_unchanged(key.clone(), raw);
        batch.remove(key);
        batch.remove(done_key(entry.created_at_ms, idempotency_key));
        batch.remove(live_key(idempotency_key));
        Ok(self
            .ks
            .apply_batch(batch)
            .await
            .map_err(backend)?
            .is_applied())
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

    fn settled(key: &str, created: u64, state: OutboxState) -> OutboxEntry {
        let mut e = entry(key, created);
        e.state = state;
        e
    }

    /// #2550: settled entries are reaped once older than the cutoff, oldest
    /// first, and a live one never is.
    #[tokio::test]
    async fn terminal_entries_are_reaped_by_age_and_live_ones_are_not() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        store
            .put(settled("old-delivered", 1_000, OutboxState::Delivered))
            .await
            .unwrap();
        store
            .put(settled("old-failed", 2_000, OutboxState::Failed))
            .await
            .unwrap();
        store
            .put(settled("new-unconfirmed", 90_000, OutboxState::Unconfirmed))
            .await
            .unwrap();
        store
            .put(settled("old-sent", 500, OutboxState::Sent))
            .await
            .unwrap();

        let old = store.terminal_before(100_000).await.unwrap();
        let keys: Vec<_> = old.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["old-delivered", "old-failed"]);

        let report = affinidi_messaging_delivery::reap::reap_terminal(
            &store,
            100_000 + 1,
            std::time::Duration::from_millis(1),
        )
        .await
        .unwrap();
        assert_eq!(report.reaped, 2, "{report:?}");
        assert!(store.get("old-delivered").await.unwrap().is_none());
        assert!(store.get("new-unconfirmed").await.unwrap().is_some());
        assert!(
            store.get("old-sent").await.unwrap().is_some(),
            "live work is never reaped"
        );
        assert!(!store.remove_if_terminal("old-sent").await.unwrap());
    }

    /// An entry whose delivery window closed after the cutoff is kept, however
    /// old: a push may still be reading it.
    #[tokio::test]
    async fn an_entry_whose_window_closed_recently_is_kept() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        let mut long = settled("long-window", 1_000, OutboxState::Unconfirmed);
        long.deliver_by_ms = 50_000;
        store.put(long).await.unwrap();
        assert!(store.terminal_before(10_000).await.unwrap().is_empty());
        assert_eq!(store.terminal_before(50_000).await.unwrap().len(), 1);
    }

    /// The delete is conditional: an entry re-queued after the reaper read it
    /// (a retried `Unconfirmed` send) stays.
    #[tokio::test]
    async fn a_requeued_entry_is_not_removed() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks);
        store
            .put(settled("k", 1_000, OutboxState::Unconfirmed))
            .await
            .unwrap();
        let read = store.terminal_before(100_000).await.unwrap();
        assert_eq!(read.len(), 1);
        store.put(entry("k", 1_000)).await.unwrap(); // back to Queued
        assert!(!store.remove_if_terminal("k").await.unwrap());
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Queued
        );
        assert_eq!(
            store.due(5_000).await.unwrap().len(),
            1,
            "and it is due again"
        );
    }

    /// Settled entries leave the scanning reads: only live rows are read.
    #[tokio::test]
    async fn settling_an_entry_takes_it_out_of_the_scans() {
        let (_dir, ks) = fresh();
        let store = VtiOutboxStore::new(ks.clone());
        let mut e = settled("k", 1_000, OutboxState::Sent);
        store.put(e.clone()).await.unwrap();
        assert_eq!(store.awaiting_confirmation().await.unwrap().len(), 1);
        e.state = OutboxState::Delivered;
        store.put(e).await.unwrap();
        assert!(store.awaiting_confirmation().await.unwrap().is_empty());
        assert!(ks.prefix_keys(LIVE_PREFIX).await.unwrap().is_empty());
        assert_eq!(ks.prefix_keys(DONE_PREFIX).await.unwrap().len(), 1);
    }

    /// An outbox written before the index existed is indexed on first use, so
    /// its live entries still drain and its settled backlog is reaped.
    #[tokio::test]
    async fn an_outbox_from_before_the_index_is_indexed_once() {
        let (_dir, ks) = fresh();
        // Rows as the earlier store wrote them: the entry alone.
        let queued = entry("queued", 1_000);
        let done = settled("done", 1_000, OutboxState::Failed);
        ks.insert(outbox_key("queued"), &queued).await.unwrap();
        ks.insert(outbox_key("done"), &done).await.unwrap();

        let store = VtiOutboxStore::new(ks.clone());
        let due = store.due(5_000).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].idempotency_key, "queued");
        assert!(ks.get_raw(INDEX_MARKER).await.unwrap().is_some());
        assert_eq!(store.terminal_before(100_000).await.unwrap().len(), 1);
        assert!(store.remove_if_terminal("done").await.unwrap());

        // A second instance over the same keyspace finds it already indexed.
        let again = VtiOutboxStore::new(ks);
        assert_eq!(again.due(5_000).await.unwrap().len(), 1);
    }
}
