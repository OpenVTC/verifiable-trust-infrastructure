//! Applying a staged restore at boot.
//!
//! [`crate::ops::stage_import`] leaves a sealed restore in the `bootstrap`
//! keyspace and has the target adopt the restored seed. Every VTA binary calls
//! [`load_pending`] as soon as it knows its seed and storage key — before
//! anything else reads the store — and, if a committed restore is waiting,
//! applies it:
//!
//! ```text
//! load_pending(store, seed)
//!   └─ Ready(r) → r.apply(target, &mut config)   wipe, write, re-create the
//!                                                 deployment-bound rows
//!               → (caller rebuilds derived indexes)
//!               → r.finish(target)               drop the stage
//! ```
//!
//! Every step is idempotent and the stage is dropped last, so a boot
//! interrupted anywhere simply applies the restore again.
//!
//! # What the target re-creates
//!
//! The backup carries no deployment-bound rows (`vta_keyspaces::
//! ENVIRONMENT_BOUND_ROWS`); [`ReadyRestore::apply`] writes the target's own:
//!
//! | Target | Identity | JWT key | Also |
//! |---|---|---|---|
//! | plain | `config.toml` `vta_did` | `config.toml` | — |
//! | hardened | `config.toml` `vta_did` | `keys` ▸ `hardened:jwt_key` | — |
//! | TEE | `keys` ▸ `tee:vta_did`, `tee:did_log` | KMS row, committed at import | Mode-B carve-out closed; integrity manifest re-baselined |

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use vta_keys::KeyOrigin;
use vta_sdk::protocols::backup_management::types::{BackupEnvironment, BackupPayload};
use vta_support::restore_stage::{self, AnchorBinding, OpenedStage, StageMeta, StageState};
use vti_common::error::AppError;

use crate::BackupTarget;

/// Where a restore records that the node's state derives from it (`keys`
/// keyspace, encrypted). VTI-VTA-051: a node MUST be able to report that its
/// current state derives from a restore, and from when.
pub const PROVENANCE_KEY: &str = "restore:provenance";
/// Tells an enclave's boot to re-baseline the integrity manifest instead of
/// verifying it (`keys` keyspace, encrypted, so the parent cannot forge one).
pub const REBASELINE_KEY: &str = "restore:rebaseline";

/// Mirror of `vta_tee::did_autogen::VTA_DID_STORE_KEY`. `vta-backup` sits
/// beside `vta-tee` rather than above it; a drift test in `vta-service` holds
/// the two equal.
pub const TEE_VTA_DID_KEY: &str = "tee:vta_did";
/// Mirror of `vta_tee::did_autogen::DID_LOG_STORE_KEY`.
pub const TEE_DID_LOG_KEY: &str = "tee:did_log";
/// Mirror of `vta_tee::admin_bootstrap::BOOTSTRAP_CARVEOUT_CLOSED_KEY`.
pub const TEE_CARVEOUT_CLOSED_KEY: &str = "tee:bootstrap-carveout-closed";
/// Mirror of `vta_service::hardened_bootstrap::HARDENED_JWT_KEY`.
pub const HARDENED_JWT_KEY: &str = "hardened:jwt_key";

const INTERNAL_KEY_PREFIX: &str = "internal:";

/// The record VTI-VTA-051 asks for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreProvenance {
    pub restore_id: String,
    pub applied_at: DateTime<Utc>,
    pub staged_at: DateTime<Utc>,
    pub staged_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_environment: Option<BackupEnvironment>,
    pub target_environment: BackupEnvironment,
    /// Internal keys whose records came back without their material.
    #[serde(default)]
    pub internal_keys_lost: Vec<String>,
    /// Hosted-DID registrations were detached because the restore replaced a
    /// different identity; each needs `did-mgmt dids register` again.
    #[serde(default)]
    pub hosted_dids_detached: Vec<String>,
    /// Whether the restore has been written to the audit trail yet. The
    /// trail is part of the state the restore replaced, so the row is written
    /// by the first boot that has an audit sink, not by the restore itself.
    #[serde(default)]
    pub audited: bool,
}

/// Read the node's restore provenance, if its state derives from a restore.
pub async fn read_provenance(
    target: &BackupTarget<'_>,
) -> Result<Option<RestoreProvenance>, AppError> {
    target
        .keyspace(vta_keyspaces::KEYS)?
        .get::<RestoreProvenance>(PROVENANCE_KEY)
        .await
}

/// Record that the restore has been written to the audit trail.
pub async fn mark_provenance_audited(target: &BackupTarget<'_>) -> Result<(), AppError> {
    let keys = target.keyspace(vta_keyspaces::KEYS)?;
    if let Some(mut p) = keys.get::<RestoreProvenance>(PROVENANCE_KEY).await? {
        p.audited = true;
        keys.insert(PROVENANCE_KEY, &p).await?;
    }
    Ok(())
}

/// Instruction to an enclave's boot to re-baseline its integrity manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebaselineMarker {
    pub restore_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AnchorBinding>,
}

/// The pending re-baseline, if a restore left one.
pub async fn read_rebaseline_marker(
    target: &BackupTarget<'_>,
) -> Result<Option<RebaselineMarker>, AppError> {
    target
        .keyspace(vta_keyspaces::KEYS)?
        .get::<RebaselineMarker>(REBASELINE_KEY)
        .await
}

/// Drop the re-baseline marker once the manifest is sealed.
pub async fn clear_rebaseline_marker(target: &BackupTarget<'_>) -> Result<(), AppError> {
    let keys = target.keyspace(vta_keyspaces::KEYS)?;
    keys.remove(REBASELINE_KEY).await?;
    keys.persist().await
}

/// What boot found in the `bootstrap` keyspace.
pub enum PendingRestore {
    None,
    /// A stage that does not open under this seed was dropped: its import never
    /// reached the commit, so the VTA is unchanged.
    Discarded {
        restore_id: String,
    },
    Ready(Box<ReadyRestore>),
}

/// A committed restore waiting to be applied.
pub struct ReadyRestore {
    stage: OpenedStage,
}

/// Look for a staged restore that opens under `seed`. An uncommitted one is
/// discarded here.
pub async fn load_pending(
    target: &BackupTarget<'_>,
    seed: &[u8],
) -> Result<PendingRestore, AppError> {
    let bootstrap = target.bootstrap()?;
    match restore_stage::open_stage(&bootstrap, seed).await? {
        StageState::None => Ok(PendingRestore::None),
        StageState::Uncommitted { restore_id } => {
            warn!(
                restore_id,
                "discarding a staged restore that does not open under this VTA's seed — \
                 its import never committed, so nothing was changed"
            );
            restore_stage::clear_stage(&bootstrap).await?;
            Ok(PendingRestore::Discarded { restore_id })
        }
        StageState::Committed(stage) => Ok(PendingRestore::Ready(Box::new(ReadyRestore {
            stage: *stage,
        }))),
    }
}

/// What applying a restore did, for the caller's follow-up and its log.
pub struct AppliedRestore {
    pub provenance: RestoreProvenance,
    /// Whether `config` was changed (and, outside an enclave, saved).
    pub config_changed: bool,
}

impl ReadyRestore {
    pub fn meta(&self) -> &StageMeta {
        &self.stage.meta
    }

    /// Replace the store's state with the restored one, under `target`'s
    /// storage key, and re-create the rows `target` needs that a backup never
    /// carries. Idempotent: an interrupted apply is simply run again.
    ///
    /// `config` is the running config. Outside an enclave the restored identity
    /// is written to it and saved to `config.toml`; in an enclave config is
    /// delivered by the parent each boot, so the identity is written to the
    /// store instead and only mirrored into `config` for this boot.
    pub async fn apply(
        &self,
        target: &BackupTarget<'_>,
        config: &mut vta_config::AppConfig,
    ) -> Result<AppliedRestore, AppError> {
        let meta = &self.stage.meta;
        let payload = &self.stage.payload;
        if meta.target_environment != target.environment {
            // The stage was committed for one kind of deployment and the VTA
            // booted as another (its config changed in between). Applying it
            // would write the identity and JWT key where this deployment does
            // not look for them. Refuse, and say how to get back.
            return Err(AppError::Config(format!(
                "a restore ({}) was staged for a {} deployment but this VTA booted as {}. \
                 Boot it with the configuration it had when the import was committed to \
                 apply the restore.",
                meta.restore_id, meta.target_environment, target.environment
            )));
        }
        crate::ops::validate_payload(payload)?;
        let seed = zeroize::Zeroizing::new(
            hex::decode(&payload.active_seed_hex)
                .map_err(|e| AppError::Validation(format!("backup seed is not hex: {e}")))?,
        );

        info!(
            restore_id = %meta.restore_id,
            source_did = payload.config.vta_did.as_deref().unwrap_or("unknown"),
            environment = %target.environment,
            "applying staged restore"
        );

        wipe(target).await?;
        write_state(target, payload, &seed).await?;
        let internal_keys_lost = reconcile_internal_keys(target).await?;
        let hosted_dids_detached = if meta.cross_identity {
            detach_hosted_dids(target).await?
        } else {
            Vec::new()
        };
        let config_changed = write_deployment_rows(target, meta, payload, config).await?;

        let provenance = RestoreProvenance {
            restore_id: meta.restore_id.clone(),
            applied_at: Utc::now(),
            staged_at: meta.staged_at,
            staged_by: meta.staged_by.clone(),
            source_did: payload.config.vta_did.clone(),
            source_environment: payload.source_environment,
            target_environment: target.environment,
            internal_keys_lost,
            hosted_dids_detached,
            audited: false,
        };
        target
            .keyspace(vta_keyspaces::KEYS)?
            .insert(PROVENANCE_KEY, &provenance)
            .await?;
        target.store.persist().await?;

        if !provenance.internal_keys_lost.is_empty() {
            warn!(
                keys = ?provenance.internal_keys_lost,
                "restored internal-key records whose material was not in the backup — \
                 these keys cannot sign and cannot be recovered"
            );
        }
        if !provenance.hosted_dids_detached.is_empty() {
            warn!(
                dids = ?provenance.hosted_dids_detached,
                "the restore replaced a different identity, so hosted-DID registrations \
                 were detached; re-attach each with `did-mgmt dids register`"
            );
        }
        Ok(AppliedRestore {
            provenance,
            config_changed,
        })
    }

    /// Drop the stage. Call only after everything that depends on the restored
    /// state (derived indexes) has been rebuilt: until then, a crash must leave
    /// the stage in place so the next boot applies it again.
    pub async fn finish(self, target: &BackupTarget<'_>) -> Result<(), AppError> {
        restore_stage::clear_stage(&target.bootstrap()?).await?;
        info!(restore_id = %self.stage.meta.restore_id, "staged restore applied");
        Ok(())
    }
}

/// Remove every row of every keyspace except `bootstrap` (the deployment's own
/// boot material) and `internal_keys` (reconciled once the restored records
/// are in place).
///
/// Keys are enumerated through bare handles: a row the previous storage key
/// sealed cannot be decrypted under the new one, but it can be deleted.
async fn wipe(target: &BackupTarget<'_>) -> Result<(), AppError> {
    for name in vta_keyspaces::ALL {
        if *name == vta_keyspaces::BOOTSTRAP || *name == vta_keyspaces::INTERNAL_KEYS {
            continue;
        }
        let ks = target.store.keyspace(name)?;
        for key in ks.prefix_keys(Vec::<u8>::new()).await? {
            ks.remove(key).await?;
        }
    }
    Ok(())
}

async fn write_state(
    target: &BackupTarget<'_>,
    payload: &BackupPayload,
    seed: &[u8],
) -> Result<(), AppError> {
    if payload.keyspaces.is_empty() {
        let keys = target.keyspace(vta_keyspaces::KEYS)?;
        let acl = target.keyspace(vta_keyspaces::ACL)?;
        let contexts = target.keyspace(vta_keyspaces::CONTEXTS)?;
        let did_templates = target.keyspace(vta_keyspaces::DID_TEMPLATES)?;
        let audit = target.keyspace(vta_keyspaces::AUDIT)?;
        let imported = target.keyspace(vta_keyspaces::IMPORTED_SECRETS)?;
        #[cfg(feature = "webvh")]
        let webvh = target.keyspace(vta_keyspaces::WEBVH)?;
        let ks = vta_keyspaces::Keyspaces {
            keys: &keys,
            acl: &acl,
            contexts: &contexts,
            did_templates: &did_templates,
            audit: &audit,
            imported: &imported,
            #[cfg(feature = "webvh")]
            webvh: &webvh,
        };
        return crate::ops::write_legacy_payload(payload, &ks, seed).await;
    }
    for dump in &payload.keyspaces {
        let ks = target.keyspace(&dump.name)?;
        for (k, v) in &dump.rows {
            let key = BASE64
                .decode(k)
                .map_err(|e| AppError::Validation(format!("restored row key: {e}")))?;
            // Validated before staging; checked again because this is the write.
            if vta_keyspaces::is_environment_bound(&dump.name, &key) {
                continue;
            }
            let value = zeroize::Zeroizing::new(
                BASE64
                    .decode(v)
                    .map_err(|e| AppError::Validation(format!("restored row value: {e}")))?,
            );
            ks.insert_raw(key, value.to_vec()).await?;
        }
    }
    Ok(())
}

/// Keep an internal key's material only where it belongs to a restored record
/// *and* still opens under this storage key — a restore onto the VTA that took
/// the backup keeps its internal keys; a restore anywhere else cannot, by
/// design. Returns the restored internal-key records left without material.
async fn reconcile_internal_keys(target: &BackupTarget<'_>) -> Result<Vec<String>, AppError> {
    let keys = target.keyspace(vta_keyspaces::KEYS)?;
    let mut restored_internal = std::collections::BTreeSet::new();
    for key in keys.prefix_keys("key:").await? {
        let Some(bytes) = keys.get_raw(key).await? else {
            continue;
        };
        if let Ok(record) = serde_json::from_slice::<vta_sdk::keys::KeyRecord>(&bytes)
            && record.origin == KeyOrigin::Internal
        {
            restored_internal.insert(record.key_id);
        }
    }

    let bare = target.store.keyspace(vta_keyspaces::INTERNAL_KEYS)?;
    let sealed = target.keyspace(vta_keyspaces::INTERNAL_KEYS)?;
    let mut kept = std::collections::BTreeSet::new();
    for key in bare.prefix_keys(Vec::<u8>::new()).await? {
        let id = key
            .strip_prefix(INTERNAL_KEY_PREFIX.as_bytes())
            .and_then(|id| std::str::from_utf8(id).ok())
            .map(str::to_owned);
        let keep = match &id {
            Some(id) if restored_internal.contains(id) => {
                matches!(sealed.get_raw(key.clone()).await, Ok(Some(_)))
            }
            _ => false,
        };
        if keep {
            kept.extend(id);
        } else {
            bare.remove(key).await?;
        }
    }
    Ok(restored_internal.difference(&kept).cloned().collect())
}

/// The restore replaced a different identity: registrations on DID-hosting
/// servers were made by the source, so re-publishing from here would clobber
/// the source's slot (`webvh-rest-auth-audit.md` §H3). Detach them; the
/// operator re-attaches each deliberately.
async fn detach_hosted_dids(target: &BackupTarget<'_>) -> Result<Vec<String>, AppError> {
    let webvh = target.keyspace(vta_keyspaces::WEBVH)?;
    let mut detached = Vec::new();
    for key in webvh.prefix_keys("did:").await? {
        let Some(mut record) = webvh
            .get::<vta_sdk::webvh::WebvhDidRecord>(key.clone())
            .await?
        else {
            continue;
        };
        if record.server_id == "serverless" {
            continue;
        }
        record.server_id = "serverless".into();
        record.mnemonic = String::new();
        webvh.insert(key, &record).await?;
        detached.push(record.did);
    }
    Ok(detached)
}

/// Write what the target keeps outside the backed-up state: identity, JWT key,
/// and — in an enclave — the carve-out and the re-baseline instruction.
async fn write_deployment_rows(
    target: &BackupTarget<'_>,
    meta: &StageMeta,
    payload: &BackupPayload,
    config: &mut vta_config::AppConfig,
) -> Result<bool, AppError> {
    let keys = target.keyspace(vta_keyspaces::KEYS)?;
    let restored = &payload.config;
    match target.environment {
        BackupEnvironment::Tee => {
            if let Some(did) = &restored.vta_did {
                // The enclave's identity lives in the store (config is
                // parent-delivered each boot, and a stored identity wins over
                // it — `did_autogen`), so this is what makes it stick.
                keys.insert_raw(TEE_VTA_DID_KEY, did.as_bytes().to_vec())
                    .await?;
                if let Some(log) = target
                    .keyspace(vta_keyspaces::WEBVH)?
                    .get_raw(format!("log:{did}"))
                    .await?
                {
                    keys.insert_raw(TEE_DID_LOG_KEY, log.clone()).await?;
                    // The parent-side proxy reads the log from here to serve it.
                    target.bootstrap()?.insert_raw(TEE_DID_LOG_KEY, log).await?;
                }
                config.vta_did = Some(did.clone());
            }
            // The restored ACL is the authority now. Leaving the single-use
            // Mode-B carve-out open on a restored enclave would let anyone who
            // reaches it first mint themselves an admin beside it.
            keys.insert_raw(TEE_CARVEOUT_CLOSED_KEY, b"restored".to_vec())
                .await?;
            keys.insert(
                REBASELINE_KEY,
                &RebaselineMarker {
                    restore_id: meta.restore_id.clone(),
                    anchor: meta.anchor.clone(),
                },
            )
            .await?;
            // The JWT key was sealed under KMS at import; nothing to do here.
            Ok(restored.vta_did.is_some())
        }
        BackupEnvironment::Hardened | BackupEnvironment::Plain => {
            if let Some(jwt) = &payload.jwt_signing_key {
                if target.environment == BackupEnvironment::Hardened {
                    let key = BASE64
                        .decode(jwt)
                        .map_err(|e| AppError::Validation(format!("backup JWT key: {e}")))?;
                    keys.insert_raw(HARDENED_JWT_KEY, key).await?;
                } else {
                    config.auth.jwt_signing_key = Some(jwt.clone());
                }
            }
            if let Some(did) = &restored.vta_did {
                config.vta_did = Some(did.clone());
            }
            if let Some(name) = &restored.vta_name {
                config.vta_name = Some(name.clone());
            }
            // The restored DID document advertises these; the node has to be
            // where its own document says it is.
            if let Some(url) = &restored.public_url {
                config.public_url = Some(url.clone());
            }
            if restored.mediator_url.is_some() || restored.mediator_did.is_some() {
                let messaging =
                    config
                        .messaging
                        .get_or_insert_with(|| vti_common::config::MessagingConfig {
                            mediator_url: String::new(),
                            mediator_did: String::new(),
                            mediator_host: None,
                            setup_acl: false,
                            drain_inbox_on_start: false,
                        });
                if let Some(url) = &restored.mediator_url {
                    messaging.mediator_url = url.clone();
                }
                if let Some(did) = &restored.mediator_did {
                    messaging.mediator_did = did.clone();
                }
            }
            // Idempotent, so a boot interrupted after this re-saves the same
            // file. A config with no path (tests, in-memory) is not saved.
            if !config.config_path.as_os_str().is_empty() {
                config.save()?;
            }
            Ok(true)
        }
    }
}
