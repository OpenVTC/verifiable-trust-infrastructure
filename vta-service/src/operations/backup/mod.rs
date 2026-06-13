//! VTA backup export and import operations.
//!
//! Export: reads all keyspaces + seed, assembles a `BackupPayload`, encrypts
//! with Argon2id + AES-256-GCM, and wraps in a `BackupEnvelope`.
//!
//! Import: decrypts the envelope, validates the payload, optionally previews,
//! then replaces all keyspace data and updates the seed store.
//!
//! ## Sub-modules
//!
//! - [`descriptors`] — the 3-phase descriptor-pattern op layer for
//!   the trust-task slice. Wraps the inline `export_backup` /
//!   `preview_import` / `apply_import` functions below, decoupling
//!   bulk byte transport from the JSON envelope. See
//!   `docs/05-design-notes/backup-descriptor-pattern.md`.

pub mod blob;
pub mod descriptors;

use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::keys::KeyOrigin;
use crate::keys::imported;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{SeedRecord, get_active_seed_id, save_seed_record, set_active_seed_id};
use crate::seal::{SealRecord, get_seal};
use crate::store::{KeyspaceHandle, RawKvPair};

use vta_sdk::protocols::backup_management::types::*;

// ── Argon2id parameters (OWASP recommended) ────────────────────────

const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

// ── Argon2id parameter clamps (import-side defence) ────────────────
//
// `decrypt_backup` reads KDF parameters from the envelope itself —
// without bounds, an attacker who can submit a backup can force a
// memory bomb (`m_cost = u32::MAX` ≈ 4 TiB) or a trivially-fast KDF
// for known-plaintext probes. On a Nitro Enclave with fixed memory,
// a memory bomb is fatal. These bounds give honest backups generous
// headroom (the OWASP profile sits well within them) while rejecting
// adversarial values.

/// Maximum memory cost (in KiB) accepted on import. 1 GiB.
const MAX_M_COST: u32 = 1 << 20;
/// Minimum memory cost (in KiB) accepted on import. 8 MiB — well below
/// the OWASP recommendation, here only to reject the m=1 footgun.
const MIN_M_COST: u32 = 8 * 1024;
/// Maximum iteration count.
const MAX_T_COST: u32 = 10;
/// Minimum iteration count.
const MIN_T_COST: u32 = 1;
/// Maximum parallelism factor.
const MAX_P_COST: u32 = 16;
/// Minimum parallelism factor.
const MIN_P_COST: u32 = 1;

// ── Export ──────────────────────────────────────────────────────────

/// Assemble and encrypt a backup of the entire VTA state.
pub async fn export_backup(
    ks: &super::Keyspaces<'_>,
    seed_store: &dyn SeedStore,
    config: &crate::config::AppConfig,
    auth: &AuthClaims,
    password: &str,
    include_audit: bool,
) -> Result<BackupEnvelope, AppError> {
    // The keyspaces captured here are exactly `crate::keyspaces::BACKED_UP`
    // ({keys, acl, contexts, audit, imported_secrets, webvh}). That registry
    // partitions every keyspace into BACKED_UP vs EXCLUDED_FROM_BACKUP and a
    // guard test (`keyspaces::tests::backup_partition_is_total`) keeps the
    // partition total, so a newly-added keyspace can't be silently dropped from
    // the backup decision. If you add a keyspace to BACKED_UP, wire it in here.
    let keys_ks = ks.keys;
    let acl_ks = ks.acl;
    let contexts_ks = ks.contexts;
    let audit_ks = ks.audit;
    let imported_ks = ks.imported;
    #[cfg(feature = "webvh")]
    let webvh_ks = ks.webvh;
    auth.require_super_admin()?;

    if password.len() < 12 {
        return Err(AppError::Validation(
            "backup password must be at least 12 characters".into(),
        ));
    }

    // 1. Collect the active seed
    let seed_bytes = seed_store
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("seed store: {e}")))?
        .ok_or_else(|| AppError::Internal("no active seed available".into()))?;
    let active_seed_hex = hex::encode(&seed_bytes);
    let active_seed_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("get active seed id: {e}")))?;

    // A backup must be COMPLETE: unlike the steady-state list paths (which
    // skip a corrupt row so one bad entry can't break management), export
    // FAILS LOUDLY on any row it cannot deserialize. Silently omitting a
    // key or ACL row from a backup loses key material or an admin grant —
    // far worse than refusing to take the backup.
    fn corrupt_row(kind: &str, key: &[u8], e: impl std::fmt::Display) -> AppError {
        AppError::Internal(format!(
            "backup aborted: {kind} row '{}' is corrupt and would be silently \
             omitted from the backup: {e}",
            String::from_utf8_lossy(key)
        ))
    }

    // 2. Collect seed records (retired seeds)
    let seed_records: Vec<SeedRecordBackup> = {
        let raw = keys_ks.prefix_iter_raw("seed:").await?;
        let mut records = Vec::with_capacity(raw.len());
        for (key, value) in raw {
            let sr: SeedRecord =
                serde_json::from_slice(&value).map_err(|e| corrupt_row("seed", &key, e))?;
            records.push(SeedRecordBackup {
                id: sr.id,
                seed_hex: sr.seed_hex,
                seed_enc: sr.seed_enc,
                created_at: sr.created_at,
                retired_at: sr.retired_at,
            });
        }
        records
    };

    // 3. Collect key records
    let key_records: Vec<vta_sdk::keys::KeyRecord> = {
        let raw = keys_ks.prefix_iter_raw("key:").await?;
        let mut out = Vec::with_capacity(raw.len());
        for (key, value) in raw {
            out.push(serde_json::from_slice(&value).map_err(|e| corrupt_row("key", &key, e))?);
        }
        out
    };

    // 4. Collect context records + counter
    let context_records: Vec<vta_sdk::contexts::ContextRecord> = {
        let raw = contexts_ks.prefix_iter_raw("ctx:").await?;
        let mut out = Vec::with_capacity(raw.len());
        for (key, value) in raw {
            out.push(serde_json::from_slice(&value).map_err(|e| corrupt_row("context", &key, e))?);
        }
        out
    };
    let context_counter: u32 = contexts_ks
        .get_raw("ctx_counter")
        .await?
        .and_then(|b| b.try_into().ok().map(u32::from_le_bytes))
        .unwrap_or(0);

    // 4b. Collect the BIP-32 allocation counters so a restore onto a fresh
    // store cannot re-derive private keys / context subtrees that restored
    // records already occupy (P0.5). `path_counter:{base}` lives in the keys
    // keyspace; `ctx_counter:{parent}` (per-parent sub-context counters) live
    // in the contexts keyspace alongside the top-level `ctx_counter`.
    let read_u32_counters = |pairs: Vec<RawKvPair>| -> Vec<(String, u32)> {
        pairs
            .into_iter()
            .filter_map(|(k, v)| {
                let key = String::from_utf8(k).ok()?;
                let arr: [u8; 4] = v.try_into().ok()?;
                Some((key, u32::from_le_bytes(arr)))
            })
            .collect()
    };
    let path_counters = read_u32_counters(keys_ks.prefix_iter_raw("path_counter:").await?);
    let subcontext_counters = read_u32_counters(contexts_ks.prefix_iter_raw("ctx_counter:").await?);

    // 5. Collect ACL entries. Two forms, both from the same scan:
    //   - `acl_entries_full`: the stored `AclEntry` JSON verbatim (lossless).
    //   - `acl_entries`: the legacy 6-field projection (kept for
    //     forward/backward compatibility; the importer prefers the full form).
    // A row that can't be parsed aborts the backup rather than being silently
    // dropped (an incomplete backup loses an admin grant) — see P0.14.
    let (acl_entries, acl_entries_full): (Vec<AclEntryBackup>, Vec<serde_json::Value>) = {
        let raw = acl_ks.prefix_iter_raw("acl:").await?;
        let mut lossy = Vec::with_capacity(raw.len());
        let mut full = Vec::with_capacity(raw.len());
        for (key, v) in raw {
            let val: serde_json::Value =
                serde_json::from_slice(&v).map_err(|e| corrupt_row("ACL", &key, e))?;
            lossy.push(AclEntryBackup {
                did: val["did"].as_str().unwrap_or_default().to_string(),
                role: val["role"].as_str().unwrap_or("Reader").to_string(),
                label: val["label"].as_str().map(String::from),
                allowed_contexts: val["allowed_contexts"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                created_at: val["created_at"].as_u64().unwrap_or(0),
                created_by: val["created_by"].as_str().unwrap_or_default().to_string(),
            });
            full.push(val);
        }
        (lossy, full)
    };

    // 6. Collect seal record
    let seal = get_seal(acl_ks)
        .await
        .ok()
        .flatten()
        .map(|s| SealRecordBackup {
            sealed_by: s.sealed_by,
            sealed_at: s.sealed_at,
            reason: s.reason,
        });

    // 7. Collect WebVH records
    #[cfg(feature = "webvh")]
    let (webvh_servers, webvh_dids, webvh_logs) = {
        let servers: Vec<vta_sdk::webvh::WebvhServerRecord> = webvh_ks
            .prefix_iter_raw("server:")
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        let dids: Vec<vta_sdk::webvh::WebvhDidRecord> = webvh_ks
            .prefix_iter_raw("did:")
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        let logs: Vec<WebvhLogBackup> = webvh_ks
            .prefix_iter_raw("log:")
            .await?
            .into_iter()
            .filter_map(|(k, v)| {
                let did = String::from_utf8(k).ok()?.strip_prefix("log:")?.to_string();
                let log_json = String::from_utf8(v).ok()?;
                Some(WebvhLogBackup { did, log_json })
            })
            .collect();
        (servers, dids, logs)
    };
    #[cfg(not(feature = "webvh"))]
    let (webvh_servers, webvh_dids, webvh_logs) = (Vec::new(), Vec::new(), Vec::new());

    // 8. Collect audit logs (optional)
    let audit_logs = if include_audit {
        let raw = audit_ks.prefix_iter_raw("log:").await?;
        raw.into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    } else {
        Vec::new()
    };

    // 9. Config snapshot
    let backup_config = BackupConfig {
        vta_did: config.vta_did.clone(),
        vta_name: config.vta_name.clone(),
        public_url: config.public_url.clone(),
        mediator_url: config.messaging.as_ref().map(|m| m.mediator_url.clone()),
        mediator_did: config.messaging.as_ref().map(|m| m.mediator_did.clone()),
    };

    // 10. JWT signing key
    let jwt_signing_key = config.auth.jwt_signing_key.clone();

    // 11. Collect imported secrets
    let imported_kek_salt = imported::get_salt(keys_ks).await?.map(hex::encode);
    let imported_secrets = {
        let mut secrets = Vec::new();
        for kr in &key_records {
            if kr.origin == KeyOrigin::Imported
                && kr.status == vta_sdk::keys::KeyStatus::Active
                && let Ok(mut plaintext) = imported::load_secret(
                    imported_ks,
                    keys_ks,
                    &seed_bytes,
                    &kr.key_id,
                    &kr.key_type.to_string(),
                )
                .await
            {
                secrets.push(ImportedSecretBackup {
                    key_id: kr.key_id.clone(),
                    private_key_hex: hex::encode(&plaintext),
                });
                use zeroize::Zeroize;
                plaintext.zeroize();
            }
        }
        secrets
    };

    // Assemble payload
    let payload = BackupPayload {
        active_seed_hex,
        active_seed_id,
        seed_records,
        jwt_signing_key,
        key_records,
        context_records,
        context_counter,
        path_counters,
        subcontext_counters,
        acl_entries,
        acl_entries_full,
        seal,
        webvh_servers,
        webvh_dids,
        webvh_logs,
        config: backup_config,
        audit_logs,
        imported_secrets,
        imported_kek_salt,
    };

    // Encrypt
    let envelope = encrypt_payload(&payload, password, include_audit, config)?;

    info!(
        keys = payload.key_records.len(),
        acls = payload.acl_entries.len(),
        contexts = payload.context_records.len(),
        audit = payload.audit_logs.len(),
        "backup exported"
    );

    Ok(envelope)
}

// ── Import ─────────────────────────────────────────────────────────

/// Decrypt and validate a backup, returning a preview without modifying state.
pub async fn preview_import(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<(BackupPayload, ImportResult), AppError> {
    let payload = decrypt_backup(envelope, password)?;

    let result = ImportResult {
        status: "preview".into(),
        source_did: payload.config.vta_did.clone(),
        key_count: payload.key_records.len(),
        acl_count: payload.acl_entries.len(),
        context_count: payload.context_records.len(),
        audit_count: payload.audit_logs.len(),
        imported_secret_count: payload.imported_secrets.len(),
        message: Some("Preview only — no changes applied. Set confirm=true to import.".into()),
    };

    Ok((payload, result))
}

/// Reject an import if the backup's `vta_did` would overwrite a
/// different running VTA's identity. A fresh install (no running
/// `vta_did`) accepts any backup — this covers disaster recovery from
/// a completely lost VTA. An identity migration (deliberately
/// replacing one VTA DID with another) requires the operator to clear
/// `vta_did` from the running config first.
fn check_vta_did_compatibility(
    running_did: Option<&str>,
    backup_did: Option<&str>,
) -> Result<(), AppError> {
    let running = match running_did {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(()),
    };
    let backup = backup_did.unwrap_or("");
    if backup == running {
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "backup vta_did mismatch: backup claims '{backup}' but this VTA is running \
         as '{running}'. Refusing to overwrite identity. If this is intentional \
         (identity migration), clear vta_did from the running config first."
    )))
}

/// Key under which `apply_import` records that a destructive import is in
/// flight. Written (and persisted) before the keyspaces are cleared and
/// removed only after every record is back; if a crash interrupts the
/// import, this survives and boot refuses to start on the resulting hybrid
/// state (see `crate::server::run`). Lives in the keys keyspace under a
/// prefix no clear/scan touches.
pub const IMPORT_IN_PROGRESS_KEY: &str = "backup:import_in_progress";

/// Recompute `path_counter:{base}` values from restored key records, so an
/// old (pre-P0.5) backup with no exported counters still can't re-derive an
/// in-use BIP-32 path. For each derived key (`derivation_path` = `{base}/{n}'`)
/// the counter for `base` must be at least `n + 1`.
fn recompute_path_counters(
    key_records: &[vta_sdk::keys::KeyRecord],
) -> std::collections::HashMap<String, u32> {
    let mut counters: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for kr in key_records {
        let path = kr.derivation_path.trim();
        if path.is_empty() {
            continue; // imported (non-derived) key — no allocation counter
        }
        if let Some((base, last)) = path.rsplit_once('/')
            && let Ok(index) = last.trim_end_matches('\'').parse::<u32>()
        {
            let next = index.saturating_add(1);
            let slot = counters.entry(base.to_string()).or_insert(0);
            *slot = (*slot).max(next);
        }
    }
    counters
}

/// Recompute `ctx_counter:{parent}` values from restored context records. A
/// sub-context carries its per-parent `index`; the counter for that parent
/// must be at least `index + 1`.
fn recompute_subcontext_counters(
    context_records: &[vta_sdk::contexts::ContextRecord],
) -> std::collections::HashMap<String, u32> {
    let mut counters: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for cr in context_records {
        if let Some(parent) = cr.parent.as_deref() {
            let next = cr.index.saturating_add(1);
            let slot = counters.entry(parent.to_string()).or_insert(0);
            *slot = (*slot).max(next);
        }
    }
    counters
}

/// Apply an import: clears all keyspaces and writes the backup data.
///
/// When `store` and TEE KMS config are provided, re-encrypts the imported
/// seed and JWT key with KMS for the bootstrap keyspace. The `store`
/// parameter is therefore only consumed under `feature = "tee"`; non-TEE
/// builds receive `None` and silently skip step 12.
///
/// **vta_did guard**: if the running VTA already has a vta_did in config
/// and it differs from the backup's, the import is rejected — a foreign
/// backup replacing a live VTA's state is almost certainly an operator
/// mistake. A fresh install (no vta_did yet) accepts any backup; this
/// covers the legitimate disaster-recovery path. To deliberately migrate
/// an identity, clear the running config first.
///
/// The caller is responsible for triggering a soft restart after this returns.
#[cfg_attr(not(feature = "tee"), allow(unused_variables))]
pub async fn apply_import(
    payload: &BackupPayload,
    ks: &super::Keyspaces<'_>,
    seed_store: &Arc<dyn SeedStore>,
    config: &tokio::sync::RwLock<crate::config::AppConfig>,
    store: Option<&crate::store::Store>,
) -> Result<ImportResult, AppError> {
    // vta_did cross-check: refuse to overwrite a different VTA's
    // identity with this backup. A fresh install (running_did is None)
    // accepts any backup.
    {
        let running_did = config.read().await.vta_did.clone();
        check_vta_did_compatibility(running_did.as_deref(), payload.config.vta_did.as_deref())?;
    }

    let keys_ks = ks.keys;
    let acl_ks = ks.acl;
    let contexts_ks = ks.contexts;
    let audit_ks = ks.audit;
    let imported_ks = ks.imported;
    #[cfg(feature = "webvh")]
    let webvh_ks = ks.webvh;

    // Crash-safety sentinel (P0.5): record that a destructive import has
    // begun, and fsync it, BEFORE clearing anything. If a crash interrupts
    // the rewrite below, the store is left in a hybrid half-imported state;
    // this marker survives and boot refuses to start on it (server::run)
    // rather than running on corrupt state. Removed + fsynced only after the
    // import fully completes.
    keys_ks
        .insert_raw(IMPORT_IN_PROGRESS_KEY, b"1".to_vec())
        .await?;
    keys_ks.persist().await?;

    // 1. Clear all keyspaces. `path_counter:` (keys) and `ctx_counter:`
    // (per-parent sub-context counters, contexts) are cleared too so a
    // re-import over a dirty store can't leave a stale counter that would
    // re-allocate an in-use BIP-32 index (P0.5).
    clear_keyspace(keys_ks, &["key:", "seed:", "path_counter:"]).await?;
    clear_keyspace(acl_ks, &["acl:", "vta:"]).await?;
    clear_keyspace(contexts_ks, &["ctx:", "ctx_counter:"]).await?;
    clear_keyspace(audit_ks, &["log:"]).await?;
    clear_keyspace(imported_ks, &["secret:"]).await?;
    #[cfg(feature = "webvh")]
    clear_keyspace(
        webvh_ks,
        // `server-auth:` is explicitly included so that a restore
        // wipes any cached daemon-REST tokens before installing the
        // backed-up server registry. Tokens never travel in the
        // backup payload itself (the export path scans `server:`
        // only — `server-auth:` is service-local secret material),
        // so a fresh import correctly leaves us un-authenticated to
        // every daemon and forces a re-authenticate on first use.
        &["server:", "server-auth:", "did:", "log:"],
    )
    .await?;

    // Also remove counters
    let _ = keys_ks.remove("active_seed_id").await;
    let _ = contexts_ks.remove("ctx_counter").await;

    // 2. Write seed to external store
    let seed_bytes = hex::decode(&payload.active_seed_hex)
        .map_err(|e| AppError::Internal(format!("invalid seed hex in backup: {e}")))?;
    seed_store
        .set(&seed_bytes)
        .await
        .map_err(|e| AppError::Internal(format!("seed store: {e}")))?;

    // 3. Write active_seed_id
    set_active_seed_id(keys_ks, payload.active_seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("set active seed id: {e}")))?;

    // 4. Write seed records
    for sr in &payload.seed_records {
        let record = SeedRecord {
            id: sr.id,
            seed_hex: sr.seed_hex.clone(),
            seed_enc: sr.seed_enc.clone(),
            created_at: sr.created_at,
            retired_at: sr.retired_at,
        };
        save_seed_record(keys_ks, &record)
            .await
            .map_err(|e| AppError::Internal(format!("save seed record: {e}")))?;
    }

    // 5. Write key records
    for kr in &payload.key_records {
        keys_ks
            .insert(crate::keys::store_key(&kr.key_id), kr)
            .await?;
    }

    // 6. Write context records + counters
    for cr in &payload.context_records {
        contexts_ks.insert(format!("ctx:{}", cr.id), cr).await?;
    }
    contexts_ks
        .insert_raw("ctx_counter", &payload.context_counter.to_le_bytes())
        .await?;

    // 6b. Restore the BIP-32 allocation counters (P0.5). Take the MAX of the
    // exported value (exact — preserves gaps left by deleted keys) and the
    // value recomputed from the restored records (the only source for a
    // pre-P0.5 backup that has no exported counters). Either alone could
    // under-count and re-derive an in-use key/subtree; the max never does.
    {
        let mut path_counters = recompute_path_counters(&payload.key_records);
        for (k, v) in &payload.path_counters {
            // Exported keys are the full `path_counter:{base}`; recompute is
            // keyed by bare `{base}`. Normalise to bare base for the merge.
            let base = k.strip_prefix("path_counter:").unwrap_or(k).to_string();
            let slot = path_counters.entry(base).or_insert(0);
            *slot = (*slot).max(*v);
        }
        for (base, next) in path_counters {
            keys_ks
                .insert_raw(format!("path_counter:{base}"), next.to_le_bytes().to_vec())
                .await?;
        }

        let mut sub_counters = recompute_subcontext_counters(&payload.context_records);
        for (k, v) in &payload.subcontext_counters {
            let parent = k.strip_prefix("ctx_counter:").unwrap_or(k).to_string();
            let slot = sub_counters.entry(parent).or_insert(0);
            *slot = (*slot).max(*v);
        }
        for (parent, next) in sub_counters {
            contexts_ks
                .insert_raw(format!("ctx_counter:{parent}"), next.to_le_bytes().to_vec())
                .await?;
        }
    }

    // 7. Write ACL entries. Prefer the lossless full-JSON form
    // (`acl_entries_full`) so expiry / step-up floors / capabilities / kind /
    // device / version survive; fall back to the lossy 6-field `acl_entries`
    // only for a pre-P0.5 backup that carries no full form.
    if !payload.acl_entries_full.is_empty() {
        for entry in &payload.acl_entries_full {
            let did = entry
                .get("did")
                .and_then(|d| d.as_str())
                .ok_or_else(|| AppError::Internal("backup ACL entry has no `did` field".into()))?;
            let bytes = serde_json::to_vec(entry)?;
            acl_ks.insert_raw(format!("acl:{did}"), bytes).await?;
        }
    } else {
        if !payload.acl_entries.is_empty() {
            tracing::warn!(
                count = payload.acl_entries.len(),
                "restoring ACL from a pre-P0.5 backup's lossy form — expiry, step-up \
                 floors, and capability restrictions are not present and default to \
                 permanent/none. Re-export with this build for a lossless backup."
            );
            for entry in &payload.acl_entries {
                acl_ks.insert(format!("acl:{}", entry.did), entry).await?;
            }
        }
    }

    // 8. Write seal record
    if let Some(ref seal) = payload.seal {
        let record = SealRecord {
            sealed_by: seal.sealed_by.clone(),
            sealed_at: seal.sealed_at,
            reason: seal.reason.clone(),
        };
        acl_ks.insert("vta:sealed", &record).await?;
    }

    // 9. Write WebVH records.
    //
    // Cross-VTA disaster recovery (audit H3): if we're importing
    // someone else's backup (running_did present and != backup_did,
    // *or* backup carries no vta_did), strip `server_id`/`mnemonic`
    // off every imported `WebvhDidRecord` before persisting. The
    // imported daemon registrations still belong to the source VTA;
    // re-publishing from this VTA would clobber the source's slot.
    // Operator must explicitly re-`register_did_with_server` per
    // imported DID. See `docs/05-design-notes/webvh-rest-auth-audit.md`
    // §H3.
    #[cfg(feature = "webvh")]
    {
        let backup_vta_did = payload.config.vta_did.as_deref();
        let running_vta_did = config.read().await.vta_did.clone();
        let cross_vta_restore = match (running_vta_did.as_deref(), backup_vta_did) {
            (None, _) => false,      // fresh install — backup is authoritative
            (Some(_), None) => true, // running but backup missing identity
            (Some(running), Some(backup)) => running != backup, // operator-confirmed swap
        };

        for server in &payload.webvh_servers {
            webvh_ks
                .insert(format!("server:{}", server.id), server)
                .await?;
        }
        for did_rec in &payload.webvh_dids {
            let mut record = did_rec.clone();
            if cross_vta_restore && record.server_id != "serverless" {
                tracing::warn!(
                    did = %record.did,
                    original_server = %record.server_id,
                    "cross-VTA restore: stripping server_id/mnemonic from imported WebvhDidRecord; \
                     operator must `register_did_with_server` to re-attach to this VTA",
                );
                record.server_id = "serverless".to_string();
                record.mnemonic = String::new();
            }
            webvh_ks
                .insert(format!("did:{}", record.did), &record)
                .await?;
        }
        for log in &payload.webvh_logs {
            webvh_ks
                .insert_raw(format!("log:{}", log.did), log.log_json.as_bytes())
                .await?;
        }
    }

    // 10. Write audit logs
    for entry in &payload.audit_logs {
        audit_ks
            .insert(format!("log:{:020}:{}", entry.timestamp, entry.id), entry)
            .await?;
    }

    // 11. Restore imported secrets
    if !payload.imported_secrets.is_empty() {
        // Restore the KEK salt (or create a new one)
        if let Some(ref salt_hex) = payload.imported_kek_salt {
            let salt = hex::decode(salt_hex)
                .map_err(|e| AppError::Internal(format!("invalid imported KEK salt hex: {e}")))?;
            imported::set_salt(keys_ks, &salt).await?;
        }

        for secret_backup in &payload.imported_secrets {
            let private_bytes = hex::decode(&secret_backup.private_key_hex)
                .map_err(|e| AppError::Internal(format!("invalid imported secret hex: {e}")))?;

            // Find the matching key record for AAD
            let key_type_str = payload
                .key_records
                .iter()
                .find(|kr| kr.key_id == secret_backup.key_id)
                .map(|kr| kr.key_type.to_string())
                .unwrap_or_else(|| "ed25519".to_string());

            imported::store_secret(
                imported_ks,
                keys_ks,
                &seed_bytes,
                &secret_backup.key_id,
                &key_type_str,
                &private_bytes,
            )
            .await?;
        }
    }

    // 12. Update config
    {
        let mut cfg = config.write().await;
        if let Some(ref did) = payload.config.vta_did {
            cfg.vta_did = Some(did.clone());
        }
        if let Some(ref name) = payload.config.vta_name {
            cfg.vta_name = Some(name.clone());
        }
        if let Some(ref url) = payload.config.public_url {
            cfg.public_url = Some(url.clone());
        }
        if let Some(ref jwt) = payload.jwt_signing_key {
            cfg.auth.jwt_signing_key = Some(jwt.clone());
        }
        if payload.config.mediator_url.is_some() || payload.config.mediator_did.is_some() {
            let messaging =
                cfg.messaging
                    .get_or_insert_with(|| vti_common::config::MessagingConfig {
                        mediator_url: String::new(),
                        mediator_did: String::new(),
                        mediator_host: None,
                    });
            if let Some(ref url) = payload.config.mediator_url {
                messaging.mediator_url = url.clone();
            }
            if let Some(ref did) = payload.config.mediator_did {
                messaging.mediator_did = did.clone();
            }
        }
    }

    // 12. TEE: re-encrypt seed + JWT key with KMS for bootstrap keyspace
    #[cfg(feature = "tee")]
    if let Some(store) = store {
        let cfg = config.read().await;
        if let crate::config::TeeMode::Required = cfg.tee.mode
            && let Some(ref kms_config) = cfg.tee.kms
        {
            let jwt_key_bytes: Option<[u8; 32]> =
                payload.jwt_signing_key.as_ref().and_then(|b64| {
                    base64::Engine::decode(&BASE64, b64)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                });
            if let Some(jwt_key) = jwt_key_bytes {
                crate::tee::kms_bootstrap::re_encrypt_bootstrap_secrets(
                    kms_config,
                    store,
                    &seed_bytes,
                    &jwt_key,
                )
                .await?;
            } else {
                info!("no JWT key in backup — skipping KMS re-encryption");
            }
        }
    }

    // Import complete and consistent: clear the crash-safety sentinel and
    // fsync, so boot no longer sees a half-imported store (P0.5). Done last,
    // after every record (incl. the TEE KMS re-encryption above) is in place.
    keys_ks.remove(IMPORT_IN_PROGRESS_KEY).await?;
    keys_ks.persist().await?;

    // Restore rewrote the covered singletons (ACL, counters, …) via raw inserts
    // that bypass the integrity chokepoints, so re-seal the TEE manifest to the
    // freshly-restored state — otherwise the next boot would fail closed against
    // the pre-restore manifest. The restore is super-admin-authorized, so the
    // restored state is the new legitimate baseline (P0.2a). No-op outside a TEE.
    vti_common::integrity::reseal_if_active().await?;

    info!(
        keys = payload.key_records.len(),
        acls = payload.acl_entries.len(),
        contexts = payload.context_records.len(),
        audit = payload.audit_logs.len(),
        "backup imported — soft restart required"
    );

    Ok(ImportResult {
        status: "imported".into(),
        source_did: payload.config.vta_did.clone(),
        key_count: payload.key_records.len(),
        acl_count: payload.acl_entries.len(),
        context_count: payload.context_records.len(),
        audit_count: payload.audit_logs.len(),
        imported_secret_count: payload.imported_secrets.len(),
        message: Some("Import complete. VTA will restart with new identity.".into()),
    })
}

// ── Crypto helpers ─────────────────────────────────────────────────

fn encrypt_payload(
    payload: &BackupPayload,
    password: &str,
    include_audit: bool,
    config: &crate::config::AppConfig,
) -> Result<BackupEnvelope, AppError> {
    let plaintext =
        serde_json::to_vec(payload).map_err(|e| AppError::Internal(format!("serialize: {e}")))?;

    use aes_gcm::aead::rand_core::RngCore;
    let mut rng = aes_gcm::aead::OsRng;
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    // Derive key via Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| AppError::Internal(format!("argon2 params: {e}")))?,
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?;

    // Encrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| AppError::Internal(format!("aes encrypt: {e}")))?;

    Ok(BackupEnvelope {
        version: 1,
        format: "vta-backup-v1".into(),
        created_at: Utc::now(),
        source_did: config.vta_did.clone(),
        source_version: env!("CARGO_PKG_VERSION").into(),
        kdf: KdfParams {
            algorithm: "argon2id".into(),
            salt: BASE64.encode(salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        },
        encryption: EncryptionParams {
            algorithm: "aes-256-gcm".into(),
            nonce: BASE64.encode(nonce_bytes),
        },
        includes_audit: include_audit,
        ciphertext: BASE64.encode(&ciphertext),
    })
}

/// Decrypt a backup envelope and return the payload.
///
/// Use this for confirmed imports to avoid the overhead of building an
/// `ImportResult` preview. For preview mode, use `preview_import()`.
pub fn decrypt_backup(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<BackupPayload, AppError> {
    if envelope.version != 1 || envelope.format != "vta-backup-v1" {
        return Err(AppError::Validation(format!(
            "unsupported backup format: {} v{}",
            envelope.format, envelope.version
        )));
    }

    // Reject KDF parameters outside sane bounds. An untrusted envelope
    // can otherwise force a memory bomb or a near-trivial KDF.
    if envelope.kdf.algorithm != "argon2id" {
        return Err(AppError::Validation(format!(
            "unsupported KDF algorithm: '{}' (only 'argon2id' is accepted)",
            envelope.kdf.algorithm
        )));
    }
    if !(MIN_M_COST..=MAX_M_COST).contains(&envelope.kdf.m_cost) {
        return Err(AppError::Validation(format!(
            "argon2 m_cost {} out of bounds [{}, {}]",
            envelope.kdf.m_cost, MIN_M_COST, MAX_M_COST
        )));
    }
    if !(MIN_T_COST..=MAX_T_COST).contains(&envelope.kdf.t_cost) {
        return Err(AppError::Validation(format!(
            "argon2 t_cost {} out of bounds [{}, {}]",
            envelope.kdf.t_cost, MIN_T_COST, MAX_T_COST
        )));
    }
    if !(MIN_P_COST..=MAX_P_COST).contains(&envelope.kdf.p_cost) {
        return Err(AppError::Validation(format!(
            "argon2 p_cost {} out of bounds [{}, {}]",
            envelope.kdf.p_cost, MIN_P_COST, MAX_P_COST
        )));
    }
    if envelope.encryption.algorithm != "aes-256-gcm" {
        return Err(AppError::Validation(format!(
            "unsupported encryption algorithm: '{}' (only 'aes-256-gcm' is accepted)",
            envelope.encryption.algorithm
        )));
    }

    let salt = BASE64
        .decode(&envelope.kdf.salt)
        .map_err(|e| AppError::Validation(format!("invalid salt: {e}")))?;
    if salt.len() != SALT_LEN {
        return Err(AppError::Validation(format!(
            "invalid salt length: {} (expected {SALT_LEN})",
            salt.len()
        )));
    }
    let nonce_bytes = BASE64
        .decode(&envelope.encryption.nonce)
        .map_err(|e| AppError::Validation(format!("invalid nonce: {e}")))?;
    // Hard length check before `Nonce::from_slice` — the
    // `aes-gcm` impl of that constructor panics on the wrong length,
    // which a crafted backup envelope would otherwise weaponise into
    // a process-killing DoS on `/backup/import`.
    if nonce_bytes.len() != NONCE_LEN {
        return Err(AppError::Validation(format!(
            "invalid nonce length: {} (expected {NONCE_LEN})",
            nonce_bytes.len()
        )));
    }
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|e| AppError::Validation(format!("invalid ciphertext: {e}")))?;

    // Derive key via Argon2id (using params from envelope)
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            envelope.kdf.m_cost,
            envelope.kdf.t_cost,
            envelope.kdf.p_cost,
            Some(32),
        )
        .map_err(|e| AppError::Validation(format!("argon2 params: {e}")))?,
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?;

    // Decrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| AppError::Authentication("incorrect backup password".into()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| AppError::Internal(format!("backup payload corrupt: {e}")))
}

/// Remove all entries under the given prefixes from a keyspace.
async fn clear_keyspace(ks: &KeyspaceHandle, prefixes: &[&str]) -> Result<(), AppError> {
    for prefix in prefixes {
        let keys = ks.prefix_keys(prefix.to_string()).await?;
        for key in keys {
            ks.remove(key).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::webvh_store::{WebvhServerAuthRecord, store_server_auth};
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Pre-existing daemon REST auth-cache records must be wiped by
    /// the restore path. Otherwise a backup imported on a different
    /// VTA (or a fresh install before re-onboarding the daemons)
    /// would inherit tokens that, if still un-expired, could be used
    /// against daemons the operator no longer controls. The import
    /// path does not carry tokens *forward* (the export filter only
    /// touches `server:` keys, not `server-auth:`), so what matters
    /// is that the wipe step explicitly includes our prefix.
    #[tokio::test]
    async fn restore_clears_pre_existing_webvh_auth_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();

        // Plant a stale auth record (as if a previous VTA installation
        // had cached daemon REST tokens here).
        let stale = WebvhServerAuthRecord {
            server_id: "prod".into(),
            access_token: "stale-access".into(),
            access_expires_at: 9_999_999_999,
            refresh_token: "stale-refresh".into(),
            refresh_expires_at: 9_999_999_999,
        };
        store_server_auth(&webvh_ks, &stale).await.unwrap();

        // Run the same wipe-prefixes call `apply_import` uses on the
        // webvh keyspace.
        clear_keyspace(&webvh_ks, &["server:", "server-auth:", "did:", "log:"])
            .await
            .unwrap();

        // The stale auth record must be gone.
        let remaining = crate::webvh_store::get_server_auth(&webvh_ks, "prod")
            .await
            .unwrap();
        assert!(
            remaining.is_none(),
            "server-auth: prefix must be cleared on import; otherwise stale tokens leak across installations"
        );
    }

    /// A backup must be complete: a corrupt `key:` row must ABORT the
    /// export rather than be silently omitted (which would drop key
    /// material from the backup). This is the deliberate opposite of the
    /// steady-state list paths, which skip corrupt rows.
    #[tokio::test]
    async fn export_aborts_on_corrupt_key_row() {
        let ts = crate::test_support::open_test_store().await;
        let seed_store = crate::test_support::TestSeedStore(vec![42u8; 32]);
        let config = crate::test_support::test_app_config(ts.data_dir.clone());
        let auth = crate::test_support::super_admin_claims();

        // Plant a garbage row under the `key:` prefix that export scans.
        ts.keys_ks
            .insert_raw("key:corrupt", b"{not a key record".to_vec())
            .await
            .unwrap();

        let ks = super::super::Keyspaces {
            keys: &ts.keys_ks,
            acl: &ts.acl_ks,
            contexts: &ts.contexts_ks,
            did_templates: &ts.did_templates_ks,
            audit: &ts.audit_ks,
            imported: &ts.imported_ks,
            #[cfg(feature = "webvh")]
            webvh: &ts.webvh_ks,
        };

        let err = export_backup(&ks, &seed_store, &config, &auth, "a-strong-password", false)
            .await
            .expect_err("export must abort on a corrupt key row");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("corrupt") && msg.contains("key"),
            "error must name the corrupt-row cause, got: {msg}"
        );
    }

    fn test_payload() -> BackupPayload {
        BackupPayload {
            active_seed_hex: hex::encode([42u8; 32]),
            active_seed_id: 1,
            seed_records: vec![SeedRecordBackup {
                id: 0,
                seed_hex: None,
                // An encrypted retired-seed archive (P0.7b) must round-trip
                // through backup verbatim so it stays decryptable on restore
                // (the active seed + KEK salt are restored alongside it).
                seed_enc: Some(vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]),
                created_at: Utc::now(),
                retired_at: Some(Utc::now()),
            }],
            jwt_signing_key: Some(BASE64.encode([99u8; 32])),
            key_records: vec![],
            context_records: vec![],
            context_counter: 2,
            path_counters: vec![],
            subcontext_counters: vec![],
            acl_entries: vec![AclEntryBackup {
                did: "did:key:z6MkTest".into(),
                role: "Admin".into(),
                label: Some("test admin".into()),
                allowed_contexts: vec!["ctx1".into()],
                created_at: 1000,
                created_by: "did:key:z6MkSetup".into(),
            }],
            acl_entries_full: vec![],
            seal: None,
            webvh_servers: vec![],
            webvh_dids: vec![],
            webvh_logs: vec![],
            config: BackupConfig {
                vta_did: Some("did:key:z6MkVTA".into()),
                vta_name: Some("Test VTA".into()),
                public_url: None,
                mediator_url: None,
                mediator_did: None,
            },
            audit_logs: vec![],
            imported_secrets: vec![],
            imported_kek_salt: None,
        }
    }

    fn test_config() -> crate::config::AppConfig {
        toml::from_str("").unwrap()
    }

    // ── P0.5 import-fidelity tests ──────────────────────────────────

    fn mk_key_record(key_id: &str, derivation_path: &str) -> vta_sdk::keys::KeyRecord {
        use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
        let now = Utc::now();
        KeyRecord {
            key_id: key_id.into(),
            derivation_path: derivation_path.into(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: "zPlaceholder".into(),
            label: None,
            context_id: None,
            seed_id: None,
            origin: KeyOrigin::Derived,
            created_at: now,
            updated_at: now,
        }
    }

    fn import_keyspaces<'a>(ts: &'a crate::test_support::TestStore) -> super::super::Keyspaces<'a> {
        super::super::Keyspaces {
            keys: &ts.keys_ks,
            acl: &ts.acl_ks,
            contexts: &ts.contexts_ks,
            did_templates: &ts.did_templates_ks,
            audit: &ts.audit_ks,
            imported: &ts.imported_ks,
            #[cfg(feature = "webvh")]
            webvh: &ts.webvh_ks,
        }
    }

    /// The headline P0.5 fix: a restore must carry the BIP-32 path counter
    /// forward, or the next key minted after restore re-derives a private
    /// key a restored record already occupies.
    #[tokio::test]
    async fn import_restores_path_counter_preventing_key_reuse() {
        let ts = crate::test_support::open_test_store().await;
        let seed_store: std::sync::Arc<dyn SeedStore> =
            std::sync::Arc::new(crate::test_support::TestSeedStore(vec![42u8; 32]));
        let config =
            tokio::sync::RwLock::new(crate::test_support::test_app_config(ts.data_dir.clone()));

        let base = "m/26'/2'/0'";
        let mut payload = test_payload();
        payload.key_records = vec![mk_key_record("k0", &format!("{base}/0'"))];
        payload.path_counters = vec![(format!("path_counter:{base}"), 1)];
        payload.acl_entries = vec![]; // exercise only the counter path here

        apply_import(&payload, &import_keyspaces(&ts), &seed_store, &config, None)
            .await
            .expect("import");

        // Allocating under the same base must NOT hand back the in-use index 0.
        let next = crate::keys::paths::allocate_path(&ts.keys_ks, base)
            .await
            .expect("alloc");
        assert_eq!(
            next,
            format!("{base}/1'"),
            "restore must carry the path counter forward (no key reuse)"
        );
    }

    /// Without exported counters (a pre-P0.5 backup), the importer recomputes
    /// from the restored key records — so the reuse bug is closed for old
    /// backups too.
    #[tokio::test]
    async fn import_recomputes_path_counter_for_legacy_backup() {
        let ts = crate::test_support::open_test_store().await;
        let seed_store: std::sync::Arc<dyn SeedStore> =
            std::sync::Arc::new(crate::test_support::TestSeedStore(vec![42u8; 32]));
        let config =
            tokio::sync::RwLock::new(crate::test_support::test_app_config(ts.data_dir.clone()));

        let base = "m/26'/2'/0'";
        let mut payload = test_payload();
        // Two restored keys at indices 0 and 1, NO exported counters (legacy).
        payload.key_records = vec![
            mk_key_record("k0", &format!("{base}/0'")),
            mk_key_record("k1", &format!("{base}/1'")),
        ];
        payload.path_counters = vec![];
        payload.acl_entries = vec![];

        apply_import(&payload, &import_keyspaces(&ts), &seed_store, &config, None)
            .await
            .expect("import");

        let next = crate::keys::paths::allocate_path(&ts.keys_ks, base)
            .await
            .expect("alloc");
        assert_eq!(
            next,
            format!("{base}/2'"),
            "recomputed counter must skip both in-use indices"
        );
    }

    /// ACL entries must round-trip ALL fields — expiry, step-up floors,
    /// capabilities, etc. — not collapse to the lossy 6-field projection
    /// (which restored expired grants as permanent and stripped step-up).
    #[tokio::test]
    async fn import_restores_full_acl_entry_fields() {
        use vti_common::acl::{AclEntry, Role};
        use vti_common::auth::step_up::StepUpMode;

        let ts = crate::test_support::open_test_store().await;
        let seed_store: std::sync::Arc<dyn SeedStore> =
            std::sync::Arc::new(crate::test_support::TestSeedStore(vec![42u8; 32]));
        let config =
            tokio::sync::RwLock::new(crate::test_support::test_app_config(ts.data_dir.clone()));

        let mut entry = AclEntry::new("did:key:zAcl", Role::Admin, "did:key:zSetup");
        entry.expires_at = Some(1_900_000_000);
        entry.step_up_require = Some(StepUpMode::SelfApprove);
        let full = serde_json::to_value(&entry).unwrap();

        let mut payload = test_payload();
        payload.acl_entries = vec![]; // ensure the full form is what's used
        payload.acl_entries_full = vec![full];

        apply_import(&payload, &import_keyspaces(&ts), &seed_store, &config, None)
            .await
            .expect("import");

        let restored: AclEntry = ts
            .acl_ks
            .get("acl:did:key:zAcl")
            .await
            .unwrap()
            .expect("acl entry restored");
        assert_eq!(restored.role, Role::Admin);
        assert_eq!(
            restored.expires_at,
            Some(1_900_000_000),
            "expiry must survive (a lossy restore would make it permanent)"
        );
        assert_eq!(
            restored.step_up_require,
            Some(StepUpMode::SelfApprove),
            "step-up floor must survive (a lossy restore would strip it)"
        );
    }

    /// The crash-safety sentinel must be gone after a successful import, and
    /// must live under a key the clear step doesn't wipe (so an interrupted
    /// import leaves it for boot to detect).
    #[tokio::test]
    async fn successful_import_leaves_no_in_progress_sentinel() {
        let ts = crate::test_support::open_test_store().await;
        let seed_store: std::sync::Arc<dyn SeedStore> =
            std::sync::Arc::new(crate::test_support::TestSeedStore(vec![42u8; 32]));
        let config =
            tokio::sync::RwLock::new(crate::test_support::test_app_config(ts.data_dir.clone()));

        let mut payload = test_payload();
        payload.acl_entries = vec![];

        apply_import(&payload, &import_keyspaces(&ts), &seed_store, &config, None)
            .await
            .expect("import");

        assert!(
            ts.keys_ks
                .get_raw(IMPORT_IN_PROGRESS_KEY)
                .await
                .unwrap()
                .is_none(),
            "a completed import must clear its in-progress sentinel"
        );
    }

    #[tokio::test]
    async fn import_sentinel_survives_keyspace_clear() {
        // The sentinel is written before the clear; verify the clear
        // prefixes used by apply_import don't wipe it.
        let ts = crate::test_support::open_test_store().await;
        ts.keys_ks
            .insert_raw(IMPORT_IN_PROGRESS_KEY, b"1".to_vec())
            .await
            .unwrap();
        clear_keyspace(&ts.keys_ks, &["key:", "seed:", "path_counter:"])
            .await
            .unwrap();
        assert!(
            ts.keys_ks
                .get_raw(IMPORT_IN_PROGRESS_KEY)
                .await
                .unwrap()
                .is_some(),
            "the sentinel must survive the import clear so an interrupted import is detectable at boot"
        );
    }

    #[test]
    fn recompute_path_counters_skips_imported_keys_and_takes_max() {
        let recs = vec![
            mk_key_record("a", "m/26'/2'/0'/0'"),
            mk_key_record("b", "m/26'/2'/0'/3'"),
            mk_key_record("imported", ""), // no derivation path → ignored
        ];
        let counters = recompute_path_counters(&recs);
        assert_eq!(counters.get("m/26'/2'/0'"), Some(&4)); // max index 3 + 1
        assert_eq!(counters.len(), 1);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let payload = test_payload();
        let password = "test-password-12chars!";
        let config = test_config();

        let envelope = encrypt_payload(&payload, password, false, &config).unwrap();

        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.format, "vta-backup-v1");
        assert_eq!(envelope.kdf.algorithm, "argon2id");
        assert_eq!(envelope.encryption.algorithm, "aes-256-gcm");
        assert!(!envelope.ciphertext.is_empty());

        let decrypted = decrypt_backup(&envelope, password).unwrap();

        assert_eq!(decrypted.active_seed_hex, payload.active_seed_hex);
        assert_eq!(decrypted.active_seed_id, payload.active_seed_id);
        assert_eq!(decrypted.seed_records.len(), 1);
        assert_eq!(decrypted.seed_records[0].id, 0);
        // The encrypted retired-seed archive survives the backup round-trip
        // byte-for-byte (P0.7b); no plaintext seed_hex is introduced.
        assert_eq!(decrypted.seed_records[0].seed_hex, None);
        assert_eq!(
            decrypted.seed_records[0].seed_enc,
            payload.seed_records[0].seed_enc
        );
        assert_eq!(decrypted.jwt_signing_key, payload.jwt_signing_key);
        assert_eq!(decrypted.context_counter, 2);
        assert_eq!(decrypted.acl_entries.len(), 1);
        assert_eq!(decrypted.acl_entries[0].did, "did:key:z6MkTest");
        assert_eq!(decrypted.acl_entries[0].role, "Admin");
        assert_eq!(decrypted.config.vta_did, Some("did:key:z6MkVTA".into()));
        assert_eq!(decrypted.config.vta_name, Some("Test VTA".into()));
    }

    #[test]
    fn wrong_password_fails() {
        let payload = test_payload();
        let config = test_config();

        let envelope = encrypt_payload(&payload, "correct-password!!", false, &config).unwrap();
        let result = decrypt_backup(&envelope, "wrong-password!!!");

        assert!(result.is_err());
        let err = result.unwrap_err();
        // AES-GCM auth tag mismatch → authentication error
        assert!(
            format!("{err}").contains("incorrect backup password"),
            "expected auth error, got: {err}"
        );
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let payload = test_payload();
        let config = test_config();
        let password = "test-password-12chars!";

        let mut envelope = encrypt_payload(&payload, password, false, &config).unwrap();

        // Tamper with the ciphertext (flip a byte)
        let mut ct_bytes = BASE64.decode(&envelope.ciphertext).unwrap();
        if let Some(byte) = ct_bytes.last_mut() {
            *byte ^= 0xFF;
        }
        envelope.ciphertext = BASE64.encode(&ct_bytes);

        let result = decrypt_backup(&envelope, password);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("incorrect backup password"),
            "tampered ciphertext should fail AES-GCM auth"
        );
    }

    #[test]
    fn unsupported_version_rejected() {
        let payload = test_payload();
        let config = test_config();
        let password = "test-password-12chars!";

        let mut envelope = encrypt_payload(&payload, password, false, &config).unwrap();
        envelope.version = 99;

        let result = decrypt_backup(&envelope, password);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("unsupported backup format"),
            "should reject unknown version"
        );
    }

    #[test]
    fn unsupported_format_rejected() {
        let payload = test_payload();
        let config = test_config();
        let password = "test-password-12chars!";

        let mut envelope = encrypt_payload(&payload, password, false, &config).unwrap();
        envelope.format = "unknown-format".into();

        let result = decrypt_backup(&envelope, password);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("unsupported backup format"),
            "should reject unknown format"
        );
    }

    #[test]
    fn envelope_serialization_roundtrip() {
        let payload = test_payload();
        let config = test_config();
        let password = "test-password-12chars!";

        let envelope = encrypt_payload(&payload, password, true, &config).unwrap();

        // Serialize to JSON and back
        let json = serde_json::to_string_pretty(&envelope).unwrap();
        let deserialized: BackupEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, envelope.version);
        assert_eq!(deserialized.format, envelope.format);
        assert!(deserialized.includes_audit);
        assert_eq!(deserialized.ciphertext, envelope.ciphertext);

        // Should still decrypt correctly
        let decrypted = decrypt_backup(&deserialized, password).unwrap();
        assert_eq!(decrypted.active_seed_hex, payload.active_seed_hex);
    }

    #[test]
    fn different_passwords_produce_different_ciphertexts() {
        let payload = test_payload();
        let config = test_config();

        let env1 = encrypt_payload(&payload, "password-one-12!!", false, &config).unwrap();
        let env2 = encrypt_payload(&payload, "password-two-12!!", false, &config).unwrap();

        // Different salts → different ciphertexts
        assert_ne!(env1.kdf.salt, env2.kdf.salt);
        assert_ne!(env1.ciphertext, env2.ciphertext);
    }

    // ── vta_did cross-check guard ───────────────────────────────────

    #[test]
    fn vta_did_guard_fresh_install_accepts_any_backup() {
        // A VTA that has not yet configured a vta_did accepts any
        // backup — this is the disaster-recovery case.
        check_vta_did_compatibility(None, Some("did:key:z6MkAnything"))
            .expect("fresh install must accept any backup");
        check_vta_did_compatibility(None, None).expect("fresh install accepts no-did backup");
        check_vta_did_compatibility(Some(""), Some("did:key:z6MkAnything"))
            .expect("empty-string vta_did counts as fresh install");
    }

    #[test]
    fn vta_did_guard_matching_dids_accepted() {
        // Legitimate disaster recovery: restore the same VTA's backup
        // onto a fresh host that has the expected vta_did configured.
        check_vta_did_compatibility(Some("did:key:z6MkSame"), Some("did:key:z6MkSame"))
            .expect("matching vta_did must pass");
    }

    #[test]
    fn vta_did_guard_mismatch_rejected() {
        let err = check_vta_did_compatibility(
            Some("did:key:z6MkRunning"),
            Some("did:key:z6MkForeignBackup"),
        )
        .expect_err("mismatched vta_did must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("vta_did mismatch"), "got: {msg}");
        assert!(
            msg.contains("z6MkForeignBackup"),
            "must name backup did: {msg}"
        );
        assert!(msg.contains("z6MkRunning"), "must name running did: {msg}");
    }

    #[test]
    fn vta_did_guard_backup_missing_did_rejected_when_running_has_did() {
        // A backup with no vta_did can't legitimately replace a
        // running VTA's identity — treat empty as mismatch.
        let err = check_vta_did_compatibility(Some("did:key:z6MkRunning"), None)
            .expect_err("missing backup vta_did must be rejected when running has one");
        assert!(format!("{err}").contains("vta_did mismatch"), "got {err:?}");
    }

    // ── KDF parameter clamps on import ──────────────────────────────

    fn make_envelope_with_kdf(m_cost: u32, t_cost: u32, p_cost: u32, alg: &str) -> BackupEnvelope {
        // Build a real encrypted envelope, then mutate the KDF params.
        // The ciphertext won't decrypt with the wrong params, but the
        // bounds check fires before decrypt is attempted — that's the
        // behaviour we're testing.
        let payload = test_payload();
        let config = test_config();
        let mut env = encrypt_payload(&payload, "password-12!ok!a", false, &config).unwrap();
        env.kdf.algorithm = alg.into();
        env.kdf.m_cost = m_cost;
        env.kdf.t_cost = t_cost;
        env.kdf.p_cost = p_cost;
        env
    }

    #[test]
    fn kdf_m_cost_above_max_rejected() {
        let env = make_envelope_with_kdf(MAX_M_COST + 1, ARGON2_T_COST, ARGON2_P_COST, "argon2id");
        let err = decrypt_backup(&env, "anything").expect_err("must reject huge m_cost");
        assert!(format!("{err}").contains("m_cost"), "got {err:?}");
    }

    #[test]
    fn kdf_m_cost_below_min_rejected() {
        let env = make_envelope_with_kdf(1, ARGON2_T_COST, ARGON2_P_COST, "argon2id");
        let err = decrypt_backup(&env, "anything").expect_err("must reject m_cost = 1");
        assert!(format!("{err}").contains("m_cost"), "got {err:?}");
    }

    #[test]
    fn kdf_t_cost_zero_rejected() {
        let env = make_envelope_with_kdf(ARGON2_M_COST, 0, ARGON2_P_COST, "argon2id");
        let err = decrypt_backup(&env, "anything").expect_err("must reject t_cost = 0");
        assert!(format!("{err}").contains("t_cost"), "got {err:?}");
    }

    #[test]
    fn kdf_p_cost_above_max_rejected() {
        let env = make_envelope_with_kdf(ARGON2_M_COST, ARGON2_T_COST, MAX_P_COST + 1, "argon2id");
        let err = decrypt_backup(&env, "anything").expect_err("must reject huge p_cost");
        assert!(format!("{err}").contains("p_cost"), "got {err:?}");
    }

    #[test]
    fn kdf_unknown_algorithm_rejected() {
        let env =
            make_envelope_with_kdf(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, "scrypt-custom");
        let err = decrypt_backup(&env, "anything").expect_err("must reject non-argon2id KDF");
        assert!(format!("{err}").contains("KDF algorithm"), "got {err:?}");
    }

    // ── Salt / nonce length validation on import ───────────────────
    //
    // Regression tests for the DoS where a crafted envelope's
    // wrong-length nonce would panic `Nonce::from_slice`, taking the
    // import handler (super-admin only, but reachable over REST) down
    // with it. The length checks fire before `from_slice` is reached.

    #[test]
    fn nonce_wrong_length_rejected_without_panic() {
        let payload = test_payload();
        let config = test_config();
        let mut env = encrypt_payload(&payload, "password-12!ok!a", false, &config).unwrap();
        // Replace the 12-byte nonce with a 16-byte one (the smallest
        // wrong size large enough that decode succeeds easily).
        env.encryption.nonce = BASE64.encode([0u8; 16]);
        let err = decrypt_backup(&env, "password-12!ok!a")
            .expect_err("wrong-length nonce must be rejected pre-decrypt");
        let msg = format!("{err}");
        assert!(
            msg.contains("nonce length"),
            "expected nonce-length error, got: {msg}"
        );
    }

    #[test]
    fn salt_wrong_length_rejected_without_panic() {
        let payload = test_payload();
        let config = test_config();
        let mut env = encrypt_payload(&payload, "password-12!ok!a", false, &config).unwrap();
        // 16 bytes instead of the expected 32.
        env.kdf.salt = BASE64.encode([0u8; 16]);
        let err = decrypt_backup(&env, "password-12!ok!a")
            .expect_err("wrong-length salt must be rejected pre-decrypt");
        let msg = format!("{err}");
        assert!(
            msg.contains("salt length"),
            "expected salt-length error, got: {msg}"
        );
    }
}
