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

use affinidi_messaging_sdk::RelationshipKv;
use affinidi_messaging_sdk::errors::ATMError;

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
}
