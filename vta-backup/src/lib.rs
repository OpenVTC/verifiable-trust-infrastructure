//! Backup/restore subsystem for the VTA, extracted from `vta-service`.
//!
//! - [`backup_bundle_store`] — the sealed backup-bundle store (bundle records +
//!   on-disk blobs for the two-phase export/import trust tasks).
//! - [`backup_bundle_sweeper`] — TTL sweep of expired backup bundles.
//! - [`ops`] — the encrypted full-state export and the import that stages a
//!   restore (Argon2id + AES-256-GCM), the compatibility check, and the
//!   two-phase descriptor flow.
//! - [`restore`] — applying a staged restore at boot.
//!
//! # Portability
//!
//! A backup restores into any kind of deployment — plain, hardened, or a Nitro
//! enclave — from any kind. Export writes every backed-up keyspace in
//! plaintext (inside the password envelope); import *stages* the restore and
//! commits the restored seed the target's own way ([`RestoreCommitter`]); the
//! next boot applies it under the storage key that seed yields. See
//! `vta_support::restore_stage` for why it cannot be applied in place, and
//! `docs/05-design-notes/backup-restore-portability.md` for the whole design.

// The bundle store and its sweeper are the node-neutral half of backup
// transfer, shared with the VTC, and live in `vti_common::backup_transfer`.
// Re-exported under their old paths so every caller keeps working.
pub use vti_common::backup_transfer::bundle_store as backup_bundle_store;
pub use vti_common::backup_transfer::sweeper as backup_bundle_sweeper;
pub mod ops;
pub mod restore;

#[cfg(test)]
mod restore_tests;
#[cfg(test)]
mod test_support;

use vta_sdk::protocols::backup_management::types::BackupEnvironment;
use vta_support::restore_stage::AnchorBinding;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};

/// The store a backup is read from, or a restore staged into, and how it is
/// protected at rest.
#[derive(Clone, Copy)]
pub struct BackupTarget<'a> {
    pub store: &'a Store,
    /// The at-rest key every keyspace except `bootstrap` is encrypted under,
    /// or `None` for a plain store.
    pub storage_key: Option<[u8; 32]>,
    pub environment: BackupEnvironment,
}

impl BackupTarget<'_> {
    /// Open `name` the way the running VTA does: encrypted under
    /// [`Self::storage_key`] when there is one.
    ///
    /// Never use this for `bootstrap`, which is unencrypted in every
    /// deployment — open that with `store.keyspace` directly.
    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let ks = self.store.keyspace(name)?;
        Ok(match self.storage_key {
            Some(key) => ks.with_encryption(key),
            None => ks,
        })
    }

    /// The unencrypted `bootstrap` keyspace.
    pub fn bootstrap(&self) -> Result<KeyspaceHandle, AppError> {
        self.store.keyspace(vta_keyspaces::BOOTSTRAP)
    }
}

/// The restored secrets an import asks the target to adopt.
pub struct RestoredSecrets<'a> {
    pub seed: &'a [u8],
    /// The backup's JWT signing key, or `None` if it carried none (the target
    /// then keeps its own).
    pub jwt_key: Option<[u8; 32]>,
    /// The DID the VTA will run as after the restore.
    pub vta_did: Option<&'a str>,
}

/// What a [`RestoreCommitter`] prepared, to be recorded in the staged restore's
/// authenticated metadata before [`RestoreCommitter::commit`] runs.
#[derive(Default)]
pub struct PreparedCommit {
    /// The KMS-sealed secrets row an enclave will commit (opaque here).
    pub tee_secrets_row: Option<Vec<u8>>,
    /// Anti-rollback reservation, when the target runs an external counter.
    pub anchor: Option<AnchorBinding>,
}

/// How a target adopts a restored seed. The seam between this crate and the
/// deployment: [`SeedStoreCommitter`] for plain and hardened VTAs, and an
/// enclave implementation in `vta-service` that seals the seed under KMS.
///
/// The two steps are split so the staged restore can record what `prepare`
/// produced *before* anything changes which seed the next boot sees.
#[async_trait::async_trait]
pub trait RestoreCommitter: Sync {
    /// Validate that the target can adopt `secrets` and compute anything the
    /// stage must bind to. Must not change what the next boot starts from.
    async fn prepare(&self, secrets: &RestoredSecrets<'_>) -> Result<PreparedCommit, AppError>;

    /// Make the restored seed the one the next boot starts from. After this
    /// returns the staged restore opens, and the next boot applies it.
    async fn commit(
        &self,
        secrets: &RestoredSecrets<'_>,
        prepared: PreparedCommit,
    ) -> Result<(), AppError>;

    /// The import failed after [`Self::prepare`] and before a successful
    /// [`Self::commit`]: undo whatever `prepare` did to the running VTA (an
    /// enclave freezes its integrity sealer there). The VTA carries on as it
    /// was.
    async fn abort(&self) {}
}

/// [`RestoreCommitter`] for a plain or hardened VTA: the seed lives in the
/// configured secret store, and the JWT key is written at boot by the restore.
pub struct SeedStoreCommitter<'a> {
    pub seed_store: &'a dyn vta_keys::seed_store::SeedStore,
}

#[async_trait::async_trait]
impl RestoreCommitter for SeedStoreCommitter<'_> {
    async fn prepare(&self, _secrets: &RestoredSecrets<'_>) -> Result<PreparedCommit, AppError> {
        if !self.seed_store.set_persists_across_restart() {
            return Err(AppError::Validation(
                "this VTA's seed store cannot persist a new seed across a restart, so a \
                 restore could never take effect. Configure a persistent secret-store \
                 backend (keyring, aws, gcp, azure, vault, k8s) before restoring."
                    .into(),
            ));
        }
        Ok(PreparedCommit::default())
    }

    async fn commit(
        &self,
        secrets: &RestoredSecrets<'_>,
        _prepared: PreparedCommit,
    ) -> Result<(), AppError> {
        self.seed_store
            .set(secrets.seed)
            .await
            .map_err(|e| AppError::Internal(format!("seed store: {e}")))
    }
}
