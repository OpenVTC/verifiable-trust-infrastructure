//! Durable TSP relationship store, backed by the VTA's encrypted `relationships`
//! keyspace.
//!
//! Rev 3 §7.2.2 has an endpoint silently drop application traffic from a VID it
//! holds no relationship with. The SDK's default relationship store is in-memory
//! and wiped on restart, so a restarted VTA forgets every peer and their traffic
//! vanishes until each re-handshakes. Persisting the state makes a restart
//! transparent (design note `docs/05-design-notes/tsp-relationship-recovery.md`,
//! D1).
//!
//! [`KeyspaceRelationshipKv`] adapts the keyspace's byte interface to the SDK's
//! [`RelationshipKv`]; the SDK's `PersistentRelationshipStore` layers the record
//! encoding, per-facet keys and defaults on top. Encryption-at-rest is already
//! applied to the handle by `apply_encryption` before it reaches here, so this
//! adapter handles no keys.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::{EvictionPolicy, PersistentRelationshipStore, RelationshipKv};
use tracing::{info, warn};

use crate::store::KeyspaceHandle;

/// A [`RelationshipKv`] over one [`KeyspaceHandle`] (the encrypted
/// `relationships` keyspace). Get / put / delete map straight onto the keyspace's
/// raw byte operations; the SDK owns the key layout and serialisation.
pub struct KeyspaceRelationshipKv {
    keyspace: KeyspaceHandle,
}

impl KeyspaceRelationshipKv {
    /// Wrap the (already encryption-wrapped) `relationships` keyspace handle.
    pub fn new(keyspace: KeyspaceHandle) -> Self {
        Self { keyspace }
    }
}

#[async_trait::async_trait]
impl RelationshipKv for KeyspaceRelationshipKv {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        self.keyspace
            .get_raw(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace get: {e}")))
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
        self.keyspace
            .insert_raw(key.to_vec(), value.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace put: {e}")))
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        self.keyspace
            .remove(key.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace delete: {e}")))
    }

    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ATMError> {
        self.keyspace
            .prefix_iter_raw(prefix.to_vec())
            .await
            .map_err(|e| ATMError::SDKError(format!("relationships keyspace scan: {e}")))
    }
}

/// A concrete durable relationship store over the encrypted `relationships`
/// keyspace — the type the maintenance loop needs (`evict_idle` /
/// `established_relationships` are on `PersistentRelationshipStore`, not the
/// `RelationshipStore` trait the ATM is handed).
pub type VtaRelationshipStore = PersistentRelationshipStore<KeyspaceRelationshipKv>;

/// How often the idle-eviction sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Background maintenance for the durable TSP relationship store (design note
/// `tsp-relationship-recovery.md`, D6/D9).
///
/// On boot it logs how many relationships survived the restart (D9); then it
/// periodically evicts idle ones (D6/D5, 7-day default).
///
/// **Spawn this ONCE, at server startup — never from `build_messaging`.** It
/// holds the store and does not depend on the mediator socket, so tying it to
/// the connect path would leak one sweep task per reconnect (the same lifecycle
/// trap the mediator-connection supervisor is written to avoid).
pub async fn maintenance_loop(store: Arc<VtaRelationshipStore>) {
    match store.established_relationships().await {
        Ok(established) => info!(
            count = established.len(),
            "TSP relationships restored from the durable store"
        ),
        Err(e) => warn!(error = %e, "could not enumerate restored TSP relationships"),
    }

    let policy = EvictionPolicy::default();
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        let Some(now_ms) = unix_millis() else {
            continue;
        };
        match store.evict_idle(now_ms, &policy).await {
            Ok(evicted) if !evicted.is_empty() => {
                info!(count = evicted.len(), "evicted idle TSP relationships")
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "TSP relationship eviction sweep failed"),
        }
    }
}

fn unix_millis() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}
