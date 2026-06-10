//! Shared trait for secret/seed storage backends.
//!
//! Both VTA (`SeedStore` — BIP-32 master seed) and VTC (`SecretStore` — raw key
//! material) use this trait. Service crates provide their own implementations
//! for AWS, GCP, Azure, OS keyring, etc.

use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Backend for storing and retrieving secret key material.
///
/// Implementations should encrypt at rest (AWS KMS, GCP KMS, Azure Key Vault)
/// or use OS-level protection (keyring). The plaintext file backend exists only
/// as a development fallback.
pub trait SeedStore: Send + Sync {
    /// Retrieve the stored secret, if any.
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;

    /// Store (or overwrite) the secret.
    fn set(&self, secret: &[u8]) -> BoxFuture<'_, Result<(), AppError>>;

    /// Remove the secret from the backend.
    ///
    /// Default is a no-op — backends where `set` overwrites in-place don't need
    /// explicit deletion.
    fn delete(&self) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async { Ok(()) })
    }

    /// Whether a successful [`set`](SeedStore::set) durably survives a
    /// process / host restart.
    ///
    /// `true` for backends that write the secret to durable storage
    /// (OS keyring, cloud secret managers, plaintext file). `false`
    /// for backends whose `set` only updates in-memory state and rely
    /// on a separate persistence step that does not happen
    /// automatically — notably the TEE KMS store, where a rotated seed
    /// lives only in enclave memory and the next boot restores the
    /// *original* KMS-bootstrapped seed instead.
    ///
    /// Seed rotation must refuse when this is `false`: rotating would
    /// bump `active_seed_id` to a generation whose bytes vanish on
    /// restart, silently making every key minted after the rotation
    /// unrecoverable.
    fn set_persists_across_restart(&self) -> bool {
        true
    }
}
