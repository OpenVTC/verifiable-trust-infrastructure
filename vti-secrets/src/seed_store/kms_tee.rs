//! KMS TEE seed store — holds the bootstrapped seed in TEE memory.
//!
//! The seed was bootstrapped from KMS during enclave startup. The ciphertext
//! is stored in the "bootstrap" keyspace of the persistent store (not files).
//! The `get` method returns a clone of the in-memory seed. The `set` method
//! updates the in-memory seed (full re-encryption requires a restart).

use std::sync::Mutex;

use vti_common::error::AppError;

use super::{BoxFuture, SeedStore};

/// Seed store backed by a KMS-bootstrapped seed held in TEE memory.
pub struct KmsTeeSeedStore {
    /// The plaintext seed, held only in enclave memory.
    seed: Mutex<Option<Vec<u8>>>,
    /// KMS key ARN (for reference / future re-encryption).
    _key_arn: String,
    /// AWS region (for reference / future re-encryption).
    _region: String,
}

impl KmsTeeSeedStore {
    pub fn new(seed: Vec<u8>, key_arn: String, region: String) -> Self {
        Self {
            seed: Mutex::new(Some(seed)),
            _key_arn: key_arn,
            _region: region,
        }
    }
}

impl SeedStore for KmsTeeSeedStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async {
            let guard = self
                .seed
                .lock()
                .map_err(|e| AppError::SecretStore(format!("seed lock poisoned: {e}")))?;
            Ok(guard.clone())
        })
    }

    fn set(&self, seed: &[u8]) -> BoxFuture<'_, Result<(), AppError>> {
        let seed = seed.to_vec();
        Box::pin(async move {
            // Updates the in-memory seed ONLY. This is NOT durable: nothing
            // re-encrypts the new seed into the bootstrap keyspace, so on the
            // next enclave boot KMS bootstrap restores the *original* seed and
            // this value is lost. `set_persists_across_restart()` returns
            // `false` so the rotation path refuses before ever reaching here;
            // any other caller must treat the write as ephemeral.
            tracing::warn!(
                "KmsTeeSeedStore::set updates the in-memory seed only — it is \
                 NOT persisted and will be lost on the next enclave boot"
            );
            let mut guard = self
                .seed
                .lock()
                .map_err(|e| AppError::SecretStore(format!("seed lock poisoned: {e}")))?;
            *guard = Some(seed);
            Ok(())
        })
    }

    fn set_persists_across_restart(&self) -> bool {
        // The seed is held only in enclave memory; rotating it would be
        // silently undone on the next boot (KMS restores the original
        // bootstrap seed). Until in-place re-encryption is wired up, the
        // rotation path must refuse — see `operations::seeds::rotate_seed`.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_does_not_persist_across_restart() {
        let store =
            KmsTeeSeedStore::new(vec![0u8; 32], "arn:aws:kms:test".into(), "us-east-1".into());
        assert!(
            !store.set_persists_across_restart(),
            "the TEE KMS seed store must report that set() is not restart-durable \
             so the rotation path refuses"
        );
    }
}
