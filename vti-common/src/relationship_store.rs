//! Durable TSP relationship store, shared by the VTA and VTC.
//!
//! Rev 3 §7.2.2 has an endpoint silently drop application traffic from a VID it
//! holds no relationship with. The SDK's default relationship store is in-memory
//! and wiped on restart, so a restarted server forgets every peer and their
//! traffic vanishes until each re-handshakes. Persisting the state makes a
//! restart transparent (design note
//! `docs/05-design-notes/tsp-relationship-recovery.md`, D1).
//!
//! [`KeyspaceRelationshipKv`] adapts a [`KeyspaceHandle`]'s byte interface to the
//! SDK's [`RelationshipKv`]; the SDK's `PersistentRelationshipStore` layers the
//! record encoding, per-facet keys and defaults on top. Encryption-at-rest, when
//! the consumer wants it, is applied to the handle before it reaches here, so
//! this adapter handles no keys. Both `vta-service` and `vtc-service` build the
//! store here and add only their own answering policy on top.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::RelationshipState;
use affinidi_messaging_sdk::{EvictionPolicy, PersistentRelationshipStore, RelationshipKv};
use tracing::{info, warn};

use crate::store::KeyspaceHandle;

/// A [`RelationshipKv`] over one [`KeyspaceHandle`]. Get / put / delete / scan map
/// straight onto the keyspace's raw byte operations; the SDK owns the key layout
/// and serialisation.
pub struct KeyspaceRelationshipKv {
    keyspace: KeyspaceHandle,
}

impl KeyspaceRelationshipKv {
    /// Wrap the (optionally encryption-wrapped) relationships keyspace handle.
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

/// A concrete durable relationship store over a [`KeyspaceHandle`] — the type the
/// maintenance loop needs (`evict_idle` / `established_relationships` are on
/// `PersistentRelationshipStore`, not the `RelationshipStore` trait the ATM is
/// handed).
pub type KeyspaceRelationshipStore = PersistentRelationshipStore<KeyspaceRelationshipKv>;

/// Build a durable relationship store over `keyspace`, ready to hand to the ATM
/// (`ATMConfig::builder().with_relationship_store(store.clone())`) and to
/// [`maintenance_loop`].
pub fn build_relationship_store(keyspace: KeyspaceHandle) -> Arc<KeyspaceRelationshipStore> {
    Arc::new(PersistentRelationshipStore::new(
        KeyspaceRelationshipKv::new(keyspace),
    ))
}

/// How often the idle-eviction sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Background maintenance for the durable TSP relationship store (design note
/// `tsp-relationship-recovery.md`, D6/D9).
///
/// On boot it logs how many relationships survived the restart (D9); then it
/// periodically evicts idle ones (D6/D5, 7-day default).
///
/// **Spawn this ONCE, at server startup — never from the mediator-connect path.**
/// It holds the store and does not depend on the mediator socket, so tying it to
/// the connect path would leak one sweep task per reconnect.
pub async fn maintenance_loop(store: Arc<KeyspaceRelationshipStore>) {
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

/// Whether a refused accept was already answered, read from the relationship
/// state **after** the refusal — the answering half of the SDK's
/// `invite_refusal_is_benign`, and decided the same way: by re-reading the
/// store, never by matching the error's text (R3.7).
///
/// `accept_relationship` runs `SendAccept`, which is legal only out of
/// `InviteReceived`. Two invites from one peer that arrive together — a client
/// re-forming a relationship it lost, retried, or two of its sessions doing it
/// at once — are both recorded first, each leaving the pair `InviteReceived`;
/// the first accept moves it to `Bidirectional`, and the second is refused
/// (`invalid transition: SendAccept in state Bidirectional`). That second invite
/// has been answered: an accept went to the same peer for the same pair a
/// moment earlier, and receiving any accept completes its side. Logging it as
/// "the peer sees no answer" said the opposite of what happened (seen at gt-vta,
/// 2026-10-11, against the browser wallet).
///
/// Anything but `Bidirectional` after the refusal means the accept failed for
/// its own reasons — no route, no key, the mediator refused it — and nothing
/// else completed the relationship, so that failure stands.
#[must_use]
pub fn accept_refusal_is_benign(after: RelationshipState) -> bool {
    after == RelationshipState::Bidirectional
}

#[cfg(test)]
mod accept_refusal_tests {
    use super::*;

    #[test]
    fn an_accept_beaten_by_a_concurrent_one_was_answered() {
        assert!(accept_refusal_is_benign(RelationshipState::Bidirectional));
    }

    #[test]
    fn an_accept_that_left_the_invite_pending_still_failed() {
        // The send itself failed; the invite is still waiting for an answer.
        assert!(!accept_refusal_is_benign(RelationshipState::InviteReceived));
    }

    #[test]
    fn an_accept_for_a_relationship_since_forgotten_still_failed() {
        assert!(!accept_refusal_is_benign(RelationshipState::None));
        assert!(!accept_refusal_is_benign(RelationshipState::Pending));
    }
}
