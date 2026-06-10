//! Persistent backing for the sealed-transfer `NonceStore` trait.
//!
//! Stores one row per sealed `bundle_id` under the `sealed-nonce:<hex>` key
//! prefix in a dedicated keyspace, so repeated seals of the same request
//! (typically: the operator re-running `vta bootstrap seal` after a network
//! glitch, or a replayed Mode A / Mode B request) are rejected with
//! [`SealedTransferError::NonceReplay`].
//!
//! Mode A token consumption and Mode B carve-out sentinels already prevent
//! cross-restart replay at the policy layer — this store is belt-and-
//! suspenders for anyone who calls `seal_payload` directly and a meaningful
//! guard for the Mode C offline CLI where there is no other anti-replay state.

use std::future::Future;
use std::pin::Pin;

use tokio::sync::Mutex;
use vta_sdk::sealed_transfer::{NonceStore, SealedTransferError};

use crate::store::KeyspaceHandle;

const KEY_PREFIX: &str = "sealed-nonce:";

/// Fjall-backed (or vsock-backed) persistent nonce store. Any
/// [`KeyspaceHandle`] will do. The bundle_id lives in the (plaintext)
/// key; encrypted deployments now also encrypt the row value, binding it
/// to its `(keyspace, key)` location via AAD so a hostile store operator
/// cannot relocate or substitute a nonce record (P0.1). Anti-rollback of
/// the whole keyspace is a separate concern (P0.2).
pub struct PersistentNonceStore {
    ks: KeyspaceHandle,
    /// Serialises the check-and-record critical section across threads so
    /// two concurrent `seal_payload` calls with the same bundle_id cannot
    /// both pass the absence check. Callers hit the store very rarely
    /// (at most a few bootstrap flows per minute) so a mutex is fine.
    lock: Mutex<()>,
}

impl PersistentNonceStore {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self {
            ks,
            lock: Mutex::new(()),
        }
    }

    fn key(bundle_id: &[u8; 16]) -> String {
        let mut s = String::with_capacity(KEY_PREFIX.len() + 32);
        s.push_str(KEY_PREFIX);
        const T: &[u8; 16] = b"0123456789abcdef";
        for &b in bundle_id {
            s.push(T[(b >> 4) as usize] as char);
            s.push(T[(b & 0xf) as usize] as char);
        }
        s
    }
}

impl NonceStore for PersistentNonceStore {
    fn check_and_record<'a>(
        &'a self,
        bundle_id: &'a [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<(), SealedTransferError>> + Send + 'a>> {
        let key = Self::key(bundle_id);
        Box::pin(async move {
            let _guard = self.lock.lock().await;
            if self
                .ks
                .get_raw(key.clone())
                .await
                .map_err(|e| SealedTransferError::NonceStore(e.to_string()))?
                .is_some()
            {
                return Err(SealedTransferError::NonceReplay);
            }
            self.ks
                .insert_raw(key, b"1".to_vec())
                .await
                .map_err(|e| SealedTransferError::NonceStore(e.to_string()))?;
            Ok(())
        })
    }
}
