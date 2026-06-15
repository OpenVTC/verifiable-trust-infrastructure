//! Seed-store facade.
//!
//! The concrete backends + the `create_seed_store` factory were lifted into
//! the shared `vti-secrets` crate (issue #501) so external integrations can
//! reuse them without depending on `vta-service`. This module re-exports them
//! and keeps the `&AppConfig`-taking [`create_seed_store`] wrapper, so every
//! existing `crate::keys::seed_store::*` call site is unchanged — the
//! extraction is behaviour-preserving.

use crate::config::AppConfig;
use crate::error::AppError;

pub use vti_secrets::SeedStore;
pub use vti_secrets::seed_store::PlaintextSeedStore;

#[cfg(feature = "aws-secrets")]
pub use vti_secrets::seed_store::AwsSeedStore;
#[cfg(feature = "azure-secrets")]
pub use vti_secrets::seed_store::AzureSeedStore;
#[cfg(feature = "config-seed")]
pub use vti_secrets::seed_store::ConfigSeedStore;
#[cfg(feature = "gcp-secrets")]
pub use vti_secrets::seed_store::GcpSeedStore;
#[cfg(feature = "k8s-secrets")]
pub use vti_secrets::seed_store::K8sSeedStore;
#[cfg(feature = "keyring")]
pub use vti_secrets::seed_store::KeyringSeedStore;
#[cfg(feature = "tee")]
pub use vti_secrets::seed_store::KmsTeeSeedStore;
#[cfg(feature = "vault-secrets")]
pub use vti_secrets::seed_store::VaultSeedStore;

/// Create a seed store backend from the VTA's [`AppConfig`].
///
/// Thin wrapper over [`vti_secrets::create_seed_store`] that supplies the
/// `[secrets]` table + the store data dir (consulted only by the plaintext
/// fallback). Kept so the many `create_seed_store(&config)` call sites across
/// the service stay unchanged after the extraction.
pub fn create_seed_store(config: &AppConfig) -> Result<Box<dyn SeedStore>, AppError> {
    vti_secrets::create_seed_store(&config.secrets, &config.store.data_dir)
}
