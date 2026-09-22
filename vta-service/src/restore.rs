//! The service side of a portable restore: which kind of deployment this VTA
//! is, how it adopts a restored seed, applying a staged restore at boot, and
//! the reboot that gets from one to the other.
//!
//! The mechanism lives in `vta-backup` and `vta_support::restore_stage`; this
//! module is the glue that knows about `AppState`, the enclave's KMS and
//! anti-rollback counter, and the two binaries' boot sequences. Design note:
//! `docs/05-design-notes/backup-restore-portability.md`.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use tracing::info;

use vta_backup::restore::{PendingRestore, RestoreProvenance};
use vta_backup::{
    BackupTarget, PreparedCommit, RestoreCommitter, RestoredSecrets, SeedStoreCommitter,
};
use vta_sdk::protocols::backup_management::types::BackupEnvironment;
use vti_common::error::AppError;
use vti_common::store::Store;

use crate::config::AppConfig;
use crate::server::AppState;

/// The kind of deployment a running VTA is, as a backup names it.
///
/// An enclave is the one with a TEE context; a hardened VTA is the one whose
/// store is encrypted without one. Nothing else encrypts the store.
#[must_use]
pub fn environment_of(storage_key: Option<[u8; 32]>, in_enclave: bool) -> BackupEnvironment {
    match (in_enclave, storage_key) {
        (true, Some(_)) => BackupEnvironment::Tee,
        (_, Some(_)) => BackupEnvironment::Hardened,
        (_, None) => BackupEnvironment::Plain,
    }
}

/// The key the persona correlation index is blinded under. Derived from the
/// at-rest key (all-zero input on a plain store), domain-separated so the
/// compromise of one does not hand over the other.
#[must_use]
pub fn persona_correlation_key(storage_key: Option<[u8; 32]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vta-persona/correlation-index/v1");
    h.update(storage_key.unwrap_or([0u8; 32]));
    h.finalize().into()
}

// ── Boot ────────────────────────────────────────────────────────────────

/// Apply a committed restore, if one is staged. **Every binary calls this as
/// soon as it knows its seed and storage key, before anything else reads the
/// store** — `vta` after deriving the hardened key (and before loading the JWT
/// key from the store), `vta-enclave` after the KMS bootstrap (and before the
/// stored identity is reconciled).
///
/// Returns the provenance of the restore it applied, if any. An error leaves the
/// stage in place, so the next boot tries again; it is never swallowed, because
/// the store is part-way through being replaced.
pub async fn apply_pending_restore(
    store: &Store,
    storage_key: Option<[u8; 32]>,
    environment: BackupEnvironment,
    seed: &[u8],
    config: &mut AppConfig,
) -> Result<Option<RestoreProvenance>, AppError> {
    let target = BackupTarget {
        store,
        storage_key,
        environment,
    };
    let ready = match vta_backup::restore::load_pending(&target, seed).await? {
        PendingRestore::None | PendingRestore::Discarded { .. } => return Ok(None),
        PendingRestore::Ready(ready) => ready,
    };
    let applied = ready.apply(&target, config).await?;
    // Derived indexes, rebuilt before the stage is dropped: a crash here must
    // re-run the restore rather than leave the indexes empty for good.
    vta_persona::PersonaStore::new(
        target.keyspace(crate::keyspaces::PERSONA)?,
        persona_correlation_key(storage_key),
    )
    .rebuild_blinded_indexes()
    .await?;
    ready.finish(&target).await?;
    info!(
        restore_id = %applied.provenance.restore_id,
        source_did = applied.provenance.source_did.as_deref().unwrap_or("unknown"),
        source_environment = ?applied.provenance.source_environment,
        target_environment = %applied.provenance.target_environment,
        "this VTA's state now derives from a restore"
    );
    Ok(Some(applied.provenance))
}

/// Write the restore to the audit trail, once, on the first boot that has an
/// audit sink. VTI-VTA-051: a restore MUST be recorded in the audit trail. It
/// cannot be recorded by the restore itself — the trail is part of the state
/// the restore replaced.
pub async fn audit_restore_once(state: &AppState) -> Result<(), AppError> {
    let access = state.backup_access();
    let target = access.target();
    let Some(p) = vta_backup::restore::read_provenance(&target).await? else {
        return Ok(());
    };
    if p.audited {
        return Ok(());
    }
    let detail = format!(
        "restore={} source={} source_env={} target_env={} staged_at={}{}{}",
        p.restore_id,
        p.source_did.as_deref().unwrap_or("unknown"),
        p.source_environment
            .map_or_else(|| "unknown".to_string(), |e| e.to_string()),
        p.target_environment,
        p.staged_at.to_rfc3339(),
        if p.internal_keys_lost.is_empty() {
            String::new()
        } else {
            format!(" internal_keys_lost={}", p.internal_keys_lost.join(","))
        },
        if p.hosted_dids_detached.is_empty() {
            String::new()
        } else {
            format!(" hosted_dids_detached={}", p.hosted_dids_detached.join(","))
        },
    );
    crate::audit::record_with_detail(
        &state.audit_sink,
        "backup.restore.applied",
        &p.staged_by,
        p.source_did.as_deref(),
        "success",
        None,
        None,
        Some(&detail),
    )
    .await?;
    vta_backup::restore::mark_provenance_audited(&target).await
}

// ── Reboot ──────────────────────────────────────────────────────────────

static REBOOT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Ask the running server to stop so the binary boots again from the top — the
/// only way a committed restore takes effect. A soft restart is not enough: it
/// keeps the storage key the process started with, and a restore may have
/// changed it.
pub fn request_reboot(restart_tx: &watch::Sender<bool>) {
    REBOOT_REQUESTED.store(true, Ordering::SeqCst);
    crate::server::trigger_restart(restart_tx);
}

/// Whether [`request_reboot`] was called. The server's run loop returns instead
/// of soft-restarting, and the binary then calls [`reexec`].
#[must_use]
pub fn reboot_requested() -> bool {
    REBOOT_REQUESTED.load(Ordering::SeqCst)
}

/// Replace this process with a fresh copy of itself, same arguments and
/// environment. A fresh process is the point: every piece of state derived from
/// the old seed — keyspace handles, the integrity sealer, caches — goes with
/// the old image, and the boot applies the staged restore before any of it is
/// rebuilt. The PID is kept, so a supervisor sees no exit; in an enclave, which
/// nothing restarts, it is the only way to boot again at all.
pub fn reexec() -> ! {
    let exe = std::env::current_exe();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    if let Ok(exe) = &exe {
        use std::os::unix::process::CommandExt;
        info!("re-executing to apply the committed restore");
        let err = std::process::Command::new(exe).args(&args).exec();
        tracing::error!("re-exec failed: {err}");
    }
    // Not unix, or exec failed: exit so a supervisor restarts us. The restore
    // is committed and applies on whatever boot comes next.
    tracing::error!(
        "the VTA could not restart itself; start it again to apply the committed restore"
    );
    let _ = exe;
    std::process::exit(75)
}

// ── Committing an import ────────────────────────────────────────────────

/// What a backup or restore needs from a running VTA, whichever transport's
/// state the request arrived on.
pub struct BackupAccess<'a> {
    pub store: &'a Store,
    pub storage_key: Option<[u8; 32]>,
    pub in_enclave: bool,
    pub seed_store: &'a dyn crate::keys::seed_store::SeedStore,
    pub config: &'a tokio::sync::RwLock<AppConfig>,
}

impl<'a> BackupAccess<'a> {
    /// The store as a backup sees it: every keyspace, this deployment's at-rest
    /// key, and which kind of deployment it is.
    pub fn target(&self) -> BackupTarget<'a> {
        BackupTarget {
            store: self.store,
            storage_key: self.storage_key,
            environment: environment_of(self.storage_key, self.in_enclave),
        }
    }

    /// The committer for the deployment this is.
    pub async fn committer(&self) -> ServiceCommitter<'a> {
        #[cfg(feature = "tee")]
        if self.in_enclave {
            let config = self.config.read().await;
            if let Some(kms) = config.tee.kms.clone() {
                let running_jwt = config
                    .auth
                    .jwt_signing_key
                    .as_deref()
                    .and_then(|b64| {
                        use base64::Engine;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(b64)
                            .ok()
                    })
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                return ServiceCommitter::Enclave(Box::new(EnclaveCommitter {
                    kms,
                    store: self.store.clone(),
                    running_did: config.vta_did.clone(),
                    running_jwt,
                }));
            }
        }
        ServiceCommitter::SeedStore(SeedStoreCommitter {
            seed_store: self.seed_store,
        })
    }
}

/// How the running deployment adopts a restored seed.
pub enum ServiceCommitter<'a> {
    SeedStore(SeedStoreCommitter<'a>),
    #[cfg(feature = "tee")]
    Enclave(Box<EnclaveCommitter>),
}

#[async_trait::async_trait]
impl RestoreCommitter for ServiceCommitter<'_> {
    async fn prepare(&self, secrets: &RestoredSecrets<'_>) -> Result<PreparedCommit, AppError> {
        match self {
            Self::SeedStore(c) => c.prepare(secrets).await,
            #[cfg(feature = "tee")]
            Self::Enclave(c) => c.prepare(secrets).await,
        }
    }
    async fn commit(
        &self,
        secrets: &RestoredSecrets<'_>,
        prepared: PreparedCommit,
    ) -> Result<(), AppError> {
        match self {
            Self::SeedStore(c) => c.commit(secrets, prepared).await,
            #[cfg(feature = "tee")]
            Self::Enclave(c) => c.commit(secrets, prepared).await,
        }
    }
    async fn abort(&self) {
        match self {
            Self::SeedStore(c) => c.abort().await,
            #[cfg(feature = "tee")]
            Self::Enclave(c) => c.abort().await,
        }
    }
}

/// How an enclave adopts a restored seed: sealed under attested KMS as one
/// row, with the anti-rollback counter for the restored identity reserved.
#[cfg(feature = "tee")]
pub struct EnclaveCommitter {
    kms: crate::config::TeeKmsConfig,
    store: Store,
    running_did: Option<String>,
    running_jwt: Option<[u8; 32]>,
}

#[cfg(feature = "tee")]
impl EnclaveCommitter {
    /// Reserve the anti-rollback version the restored boot must find. For the
    /// identity this enclave already runs as, that is the live sealer's final
    /// seal; for another identity, its counter is moved on by one (or created)
    /// here. Either way a later replay of this staged restore finds the counter
    /// somewhere else and is refused.
    async fn reserve_anchor(
        &self,
        did: &str,
        live: Option<(u64, bool)>,
    ) -> Result<Option<vta_support::restore_stage::AnchorBinding>, AppError> {
        if self.kms.anchor.is_none() {
            return Ok(None);
        }
        if self.running_did.as_deref() == Some(did)
            && let Some((version, true)) = live
        {
            return Ok(Some(vta_support::restore_stage::AnchorBinding {
                did: did.to_owned(),
                version,
            }));
        }
        let Some(counter) = build_anchor_counter(&self.kms, Some(did)).await? else {
            return Ok(None);
        };
        let version = match counter.read().await? {
            None => {
                counter.init(0, [0u8; 32]).await?;
                0
            }
            Some(n) => {
                counter.set(n, n + 1, [0u8; 32]).await?;
                n + 1
            }
        };
        Ok(Some(vta_support::restore_stage::AnchorBinding {
            did: did.to_owned(),
            version,
        }))
    }
}

#[cfg(feature = "tee")]
#[async_trait::async_trait]
impl RestoreCommitter for EnclaveCommitter {
    async fn prepare(&self, secrets: &RestoredSecrets<'_>) -> Result<PreparedCommit, AppError> {
        let jwt = secrets.jwt_key.or(self.running_jwt).ok_or_else(|| {
            AppError::Internal(
                "neither the backup nor this enclave has a JWT signing key to seal".into(),
            )
        })?;
        let row =
            crate::tee::kms_bootstrap::seal_restored_secrets(&self.kms, secrets.seed, &jwt).await?;
        // From here the running enclave refuses covered mutations: one landing
        // before the reboot would move the counter off the reservation.
        let live = vti_common::integrity::seal_and_freeze_for_restore().await?;
        let anchor = match secrets.vta_did {
            Some(did) => match self.reserve_anchor(did, live).await {
                Ok(anchor) => anchor,
                Err(e) => {
                    vti_common::integrity::thaw_after_aborted_restore();
                    return Err(e);
                }
            },
            None => None,
        };
        Ok(PreparedCommit {
            tee_secrets_row: Some(row),
            anchor,
        })
    }

    async fn commit(
        &self,
        _secrets: &RestoredSecrets<'_>,
        prepared: PreparedCommit,
    ) -> Result<(), AppError> {
        let row = prepared
            .tee_secrets_row
            .ok_or_else(|| AppError::Internal("enclave commit without a sealed row".into()))?;
        let bootstrap = self.store.keyspace(crate::keyspaces::BOOTSTRAP)?;
        bootstrap
            .insert_raw(vta_support::restore_stage::TEE_RESTORED_SECRETS_KEY, row)
            .await?;
        bootstrap.persist().await
    }

    async fn abort(&self) {
        vti_common::integrity::thaw_after_aborted_restore();
    }
}

/// The external anti-rollback counter for `vta_did`, when `[tee.kms.anchor]` is
/// configured (P0.2b), written with the attestation-gated writer credential
/// when one is sealed (P0.2c). `None` when no anchor is configured, or when
/// there is no identity to key it on.
#[cfg(feature = "tee")]
pub async fn build_anchor_counter(
    kms: &crate::config::TeeKmsConfig,
    vta_did: Option<&str>,
) -> Result<Option<std::sync::Arc<dyn vti_common::integrity::AnchorCounter>>, AppError> {
    use base64::Engine;

    let (Some(anchor_cfg), Some(vta_did)) = (kms.anchor.as_ref(), vta_did) else {
        if kms.anchor.is_some() {
            tracing::warn!(
                "tee.kms.anchor is configured but vta_did is unset — booting \
                 manifest-only (P0.2a); the external rollback counter is disabled"
            );
        }
        return Ok(None);
    };
    // P0.2c: if a sealed writer credential is configured, unseal it through the
    // attestation-gated KMS Decrypt so the counter is written with the
    // `vta-anchor-writer` principal (which the instance role is IAM-denied)
    // rather than the instance role a root-on-parent attacker shares. A
    // configured-but-unsealable credential is fatal — falling back to the
    // instance role would silently downgrade to P0.2b.
    let writer = match anchor_cfg.writer_credential_ciphertext.as_ref() {
        Some(b64) => {
            let ct = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| {
                    AppError::Config(format!(
                        "tee.kms.anchor.writer_credential_ciphertext is not valid base64: {e}"
                    ))
                })?;
            let pt = crate::tee::kms_bootstrap::attested_decrypt(kms, &ct).await?;
            let creds: crate::tee::anchor::WriterCredentials = serde_json::from_slice(&pt)
                .map_err(|e| {
                    AppError::Config(format!(
                        "anchor writer credential did not decrypt to \
                         {{access_key_id, secret_access_key}}: {e}"
                    ))
                })?;
            info!("anchor writer credential unsealed (attestation-gated, P0.2c)");
            Some(creds)
        }
        None => None,
    };
    Ok(Some(std::sync::Arc::new(
        crate::tee::anchor::DynamoAnchorCounter::new(
            &kms.region,
            anchor_cfg.table_name.clone(),
            vta_did.to_owned(),
            writer,
        )
        .await,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environment_follows_the_storage_key_and_the_enclave() {
        assert_eq!(environment_of(None, false), BackupEnvironment::Plain);
        assert_eq!(
            environment_of(Some([1; 32]), false),
            BackupEnvironment::Hardened
        );
        assert_eq!(environment_of(Some([1; 32]), true), BackupEnvironment::Tee);
    }

    /// `vta-backup` writes an enclave's identity rows under these names without
    /// depending on `vta-tee`; the enclave reads them under its own constants.
    #[cfg(feature = "tee")]
    #[test]
    fn restore_row_names_match_the_enclave_s() {
        assert_eq!(
            vta_backup::restore::TEE_VTA_DID_KEY,
            crate::tee::did_autogen::VTA_DID_STORE_KEY
        );
        assert_eq!(
            vta_backup::restore::TEE_DID_LOG_KEY,
            crate::tee::did_autogen::DID_LOG_STORE_KEY
        );
        assert_eq!(
            vta_backup::restore::TEE_CARVEOUT_CLOSED_KEY,
            crate::tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY
        );
    }

    /// The boot glue end to end: a plain VTA's backup restored into a hardened
    /// one lands under the restored seed's storage key, the identity is saved,
    /// and the persona correlation index — keyed from the storage key, so never
    /// carried — works again once the restore has run.
    #[tokio::test]
    async fn a_restore_applied_at_boot_rebuilds_what_it_does_not_carry() {
        use vta_persona::model::{Provenance, ValueType};

        let open = || {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(&vti_common::config::StoreConfig {
                data_dir: dir.path().into(),
            })
            .unwrap();
            (dir, store)
        };
        let source_seed = [0x11u8; 32];
        let (_sd, source) = open();

        // The source: a plain VTA whose holder has the same phone number on
        // two attributes — reuse the correlation index exists to see.
        let persona = vta_persona::PersonaStore::new(
            source.keyspace(crate::keyspaces::PERSONA).unwrap(),
            persona_correlation_key(None),
        );
        let phone = |v: &str| {
            vta_persona::store::new_attribute(
                "phone.mobile",
                ValueType::String,
                serde_json::json!(v),
                Provenance::SelfAsserted,
            )
        };
        let a = phone("+61 400");
        persona.put(a.clone(), None).await.unwrap();
        persona.put(phone("+61 400"), None).await.unwrap();

        let mut source_config: AppConfig = toml::from_str("").unwrap();
        source_config.vta_did = Some("did:example:restored".into());
        let seed_store = vta_backup_test_seed(&source_seed);
        let envelope = vta_backup::ops::export_backup(
            &BackupTarget {
                store: &source,
                storage_key: None,
                environment: BackupEnvironment::Plain,
            },
            &seed_store,
            &source_config,
            &crate::test_support::super_admin_claims(),
            "restore-glue-password",
            false,
        )
        .await
        .unwrap();
        let payload = vta_backup::ops::decrypt_backup(&envelope, "restore-glue-password").unwrap();

        // The target: a hardened VTA on a seed of its own.
        let (td, target) = open();
        let target_seed_store = vta_backup_test_seed(&[0x22u8; 32]);
        let key_for = |seed: &[u8]| *crate::hardened_bootstrap::derive_storage_key(seed, "salt");
        let before = BackupTarget {
            store: &target,
            storage_key: Some(key_for(&[0x22u8; 32])),
            environment: BackupEnvironment::Hardened,
        };
        let mut config: AppConfig = toml::from_str("").unwrap();
        config.config_path = td.path().join("config.toml");
        let config_lock = tokio::sync::RwLock::new(config);
        vta_backup::ops::stage_import(
            payload,
            vta_backup::ops::StageRequest {
                target: &before,
                config: &config_lock,
                committer: &SeedStoreCommitter {
                    seed_store: &target_seed_store,
                },
                auth: &crate::test_support::super_admin_claims(),
                replace_identity: false,
            },
        )
        .await
        .unwrap();

        // Boot.
        let seed = crate::keys::seed_store::SeedStore::get(&target_seed_store)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seed, source_seed, "the commit adopted the restored seed");
        let key = key_for(&seed);
        let storage_key = Some(key);
        let mut config = config_lock.into_inner();
        let provenance = apply_pending_restore(
            &target,
            storage_key,
            BackupEnvironment::Hardened,
            &seed,
            &mut config,
        )
        .await
        .unwrap()
        .expect("a committed restore is applied");
        assert_eq!(
            provenance.source_did.as_deref(),
            Some("did:example:restored")
        );

        let restored = vta_persona::PersonaStore::new(
            target
                .keyspace(crate::keyspaces::PERSONA)
                .unwrap()
                .with_encryption(key),
            persona_correlation_key(storage_key),
        );
        assert_eq!(
            restored
                .correlation_count(&serde_json::json!("+61 400"), &a.attribute_id)
                .await
                .unwrap(),
            1,
            "the correlation index is rebuilt under the target's key"
        );
        let saved = std::fs::read_to_string(td.path().join("config.toml")).unwrap();
        assert!(
            saved.contains("did:example:restored"),
            "the restored identity survives a process restart"
        );
        // Applied once: the next boot finds nothing to do.
        assert!(
            apply_pending_restore(
                &target,
                storage_key,
                BackupEnvironment::Hardened,
                &seed,
                &mut config
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    /// A seed store that keeps what it is given, as a real one does.
    fn vta_backup_test_seed(seed: &[u8]) -> MemSeed {
        MemSeed(std::sync::Mutex::new(seed.to_vec()))
    }

    struct MemSeed(std::sync::Mutex<Vec<u8>>);

    impl crate::keys::seed_store::SeedStore for MemSeed {
        fn get(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, AppError>> + Send + '_>,
        > {
            let v = self.0.lock().unwrap().clone();
            Box::pin(async move { Ok(Some(v)) })
        }
        fn set(
            &self,
            seed: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + '_>>
        {
            *self.0.lock().unwrap() = seed.to_vec();
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn restore_row_names_match_the_hardened_bootstrap_s() {
        assert_eq!(
            vta_backup::restore::HARDENED_JWT_KEY,
            crate::hardened_bootstrap::HARDENED_JWT_KEY
        );
    }
}
