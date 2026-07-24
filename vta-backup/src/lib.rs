//! Backup/restore subsystem for the VTA, extracted from `vta-service`.
//!
//! - [`backup_bundle_store`] — the sealed backup-bundle store (bundle records +
//!   on-disk blobs for the two-phase export/import trust tasks).
//! - [`backup_bundle_sweeper`] — TTL sweep of expired backup bundles.
//! - [`ops`] — the encrypted full-state export/import operations (Argon2id +
//!   AES-256-GCM), the compatibility check, and the two-phase descriptor flow.
//!
//! The operations take narrow dependencies (keyspace handles, config, a
//! [`vta_keyspaces::Keyspaces`] bundle) rather than a `&AppState`. The two
//! `vta-service`-specific glue points stay in `vta-service`:
//!
//! - `DescriptorDeps` / `apply_import` are borrowed from `AppState` there via
//!   free constructors (`operations::descriptor_deps_from_app_state`).
//! - TEE KMS re-encryption during import is injected through the
//!   [`BootstrapReEncryptor`] trait, whose only implementation wraps
//!   `vta-service`'s `tee::kms_bootstrap::re_encrypt_bootstrap_secrets`.

pub mod backup_bundle_store;
pub mod backup_bundle_sweeper;
pub mod ops;

#[cfg(test)]
mod test_support;

/// Test-only keyspaces: the sweeper tests open isolated keyspaces so a run
/// can't clobber the shared `backup_bundles`.
#[cfg(test)]
pub(crate) const BACKUP_BUNDLES_TEST: &str = "backup_bundles_test";
#[cfg(test)]
pub(crate) const BACKUP_BUNDLES_SWEEPER_TEST: &str = "backup_bundles_sweeper_test";

/// Injection seam for the TEE KMS re-encryption step of an import.
///
/// During a Mode-B (`TeeMode::Required`) import, the restored seed + JWT key
/// must be re-encrypted to the enclave's KMS-derived storage key before the
/// crash-safety sentinel is cleared. That call (`re_encrypt_bootstrap_secrets`)
/// lives in `vta-service`'s `tee` module, which cannot move here — so the
/// import op takes a `&dyn BootstrapReEncryptor` and `vta-service` supplies the
/// one implementation.
#[cfg(feature = "tee")]
#[async_trait::async_trait]
pub trait BootstrapReEncryptor: Sync {
    async fn re_encrypt(
        &self,
        kms: &vta_config::TeeKmsConfig,
        store: &vti_common::store::Store,
        seed: &[u8],
        jwt: &[u8; 32],
    ) -> Result<(), vti_common::error::AppError>;
}
