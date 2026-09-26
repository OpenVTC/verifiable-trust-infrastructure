//! VTA backup export and import operations.
//!
//! **Export** ([`export_backup`]) writes every keyspace in
//! [`vta_keyspaces::BACKED_UP`], row for row, plus the master seed and the JWT
//! signing key, into a `vta-backup-v2` payload, encrypted with Argon2id +
//! AES-256-GCM. Nothing is collected per keyspace: the export walks the list,
//! so a keyspace added to it is backed up with no further code.
//!
//! **Import** decrypts and validates a backup, optionally previews it, and on
//! commit *stages* the restore ([`stage_import`]): the payload is sealed into
//! the `bootstrap` keyspace under a key derived from the restored seed, the
//! target adopts that seed, and the VTA reboots. The restore is applied at boot
//! by [`crate::restore`], under the storage key the restored seed yields. That
//! is what lets a backup move between a plain VTA, a hardened one and an
//! enclave in any direction — see `vta_support::restore_stage`.
//!
//! A `vta-backup-v1` backup (typed collections for six keyspaces) still
//! restores; [`write_legacy_payload`] writes it at boot.
//!
//! ## Sub-modules
//!
//! - [`descriptors`] — the 3-phase descriptor-pattern op layer for
//!   the trust-task slice. Wraps [`export_backup`] / [`preview_import`] /
//!   [`stage_import`], decoupling bulk byte transport from the JSON envelope.
//!   See `docs/05-design-notes/backup-descriptor-pattern.md`.

pub mod blob;
pub mod chunked;
pub mod descriptors;

/// The `chunkedTrustTask` algorithm name, as the bundle record stores it.
pub(crate) fn chunked_algorithm() -> &'static str {
    vta_sdk::protocols::backup_management::chunked::ALGORITHM_CHUNKED
}

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use tracing::{info, warn};

use vta_keys::KeyOrigin;
use vta_keys::imported;
use vta_keys::seed_store::SeedStore;
use vta_keys::seeds::{SeedRecord, get_active_seed_id, save_seed_record, set_active_seed_id};
use vta_support::restore_stage::{self, StageMeta};
use vta_support::seal::SealRecord;
use vti_common::auth::AuthClaims;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use vta_sdk::protocols::backup_management::types::*;

use crate::{BackupTarget, RestoreCommitter, RestoredSecrets};

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

/// Key under which the pre-staging import recorded that a destructive import
/// was in flight. Imports no longer write it — a staged restore is its own
/// crash marker — but boot still refuses a store an older build left
/// half-imported (see `vta-service`'s `server::run`).
pub const IMPORT_IN_PROGRESS_KEY: &str = "backup:import_in_progress";

// ── Export ──────────────────────────────────────────────────────────

/// Every row of `ks`, decrypted.
///
/// Keys first, then one read per row, rather than a single scan: in an enclave
/// the store is a vsock proxy whose frames are capped at 16 MiB, and a whole
/// keyspace in one response is exactly what a long audit trail outgrows.
async fn dump_rows(ks: &KeyspaceHandle) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AppError> {
    let mut rows = Vec::new();
    for key in ks.prefix_keys(Vec::<u8>::new()).await? {
        // A row deleted between the two reads is simply not in the backup; a
        // row that exists but cannot be read (a failed decrypt) aborts it.
        if let Some(value) = ks.get_raw(key.clone()).await? {
            rows.push((key, value));
        }
    }
    Ok(rows)
}

/// A backup carries the seed — every key the VTA can derive — so it is the
/// largest export this VTA makes, and it needs the capability every other
/// export needs (VTI-VTA-003), not only the super-admin role. Checked here,
/// in the one function every backup path calls (REST, DIDComm, the `stream`
/// and `chunkedTrustTask` Trust Tasks), so no transport can skip it.
///
/// Reads the caller's ACL entry, so a super-admin narrowed without
/// `key-export` is refused; with no entry the role decides; a store error
/// refuses.
async fn require_key_export(target: &BackupTarget<'_>, auth: &AuthClaims) -> Result<(), AppError> {
    use vti_common::acl::{Capability, entry_has_capability, get_acl_entry, role_has_capability};
    let acl_ks = target.keyspace(vta_keyspaces::ACL)?;
    let may = match get_acl_entry(&acl_ks, &auth.did).await {
        Ok(Some(entry)) => entry_has_capability(&entry, Capability::KeyExport),
        Ok(None) => role_has_capability(&auth.role, Capability::KeyExport),
        Err(e) => {
            tracing::error!(error = %e, did = %auth.did, "could not read the ACL entry for the backup key-export check; refusing");
            false
        }
    };
    if may {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "backup export denied: {} does not carry the key-export capability. A backup carries \
         the seed, so it is an export of every key this VTA holds (VTI-VTA-003)",
        auth.did
    )))
}

/// Assemble and encrypt a backup of the entire VTA state.
pub async fn export_backup(
    target: &BackupTarget<'_>,
    seed_store: &dyn SeedStore,
    config: &vta_config::AppConfig,
    auth: &AuthClaims,
    password: &str,
    include_audit: bool,
) -> Result<BackupEnvelope, AppError> {
    auth.require_super_admin()?;
    require_key_export(target, auth).await?;
    vta_sdk::protocols::backup_management::validate_backup_password(password)
        .map_err(AppError::Validation)?;

    let seed_bytes = seed_store
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("seed store: {e}")))?
        .ok_or_else(|| AppError::Internal("no active seed available".into()))?;
    let active_seed_hex = hex::encode(&seed_bytes);
    let active_seed_id = get_active_seed_id(&target.keyspace(vta_keyspaces::KEYS)?)
        .await
        .map_err(|e| AppError::Internal(format!("get active seed id: {e}")))?;

    let mut keyspaces = Vec::with_capacity(vta_keyspaces::BACKED_UP.len());
    let mut internal_keys_not_carried = Vec::new();
    for name in vta_keyspaces::BACKED_UP {
        // A backup without its trail is a legitimate thing to ask for; the
        // audit *keys* still travel, so a trail restored later from another
        // backup of the same agent remains checkable.
        if *name == vta_keyspaces::AUDIT && !include_audit {
            continue;
        }
        let mut rows = Vec::new();
        for (key, value) in dump_rows(&target.keyspace(name)?).await? {
            if vta_keyspaces::is_environment_bound(name, &key) {
                continue;
            }
            if *name == vta_keyspaces::KEYS && key.starts_with(b"key:") {
                // A backup must be COMPLETE: unlike the steady-state list
                // paths, which skip a corrupt row so one bad entry cannot break
                // management, export refuses to write a backup that would
                // restore a key record nothing can read.
                let record: vta_sdk::keys::KeyRecord =
                    serde_json::from_slice(&value).map_err(|e| {
                        AppError::Internal(format!(
                            "backup aborted: key row '{}' is corrupt and would be restored \
                             unreadable: {e}",
                            String::from_utf8_lossy(&key)
                        ))
                    })?;
                if record.origin == KeyOrigin::Internal {
                    internal_keys_not_carried.push(record.key_id);
                }
            }
            rows.push((BASE64.encode(&key), BASE64.encode(&value)));
        }
        keyspaces.push(KeyspaceDump {
            name: (*name).to_string(),
            rows,
        });
    }

    let payload = BackupPayload {
        active_seed_hex,
        active_seed_id,
        jwt_signing_key: config.auth.jwt_signing_key.clone(),
        config: BackupConfig {
            vta_did: config.vta_did.clone(),
            vta_name: config.vta_name.clone(),
            public_url: config.public_url.clone(),
            mediator_url: config.messaging.as_ref().map(|m| m.mediator_url.clone()),
            mediator_did: config.messaging.as_ref().map(|m| m.mediator_did.clone()),
        },
        keyspaces,
        source_environment: Some(target.environment),
        internal_keys_not_carried,
        // v1's typed collections; the raw dump above supersedes them.
        seed_records: Vec::new(),
        key_records: Vec::new(),
        context_records: Vec::new(),
        context_counter: 0,
        path_counters: Vec::new(),
        subcontext_counters: Vec::new(),
        acl_entries: Vec::new(),
        acl_entries_full: Vec::new(),
        seal: None,
        webvh_servers: Vec::new(),
        webvh_dids: Vec::new(),
        webvh_logs: Vec::new(),
        audit_logs: Vec::new(),
        imported_secrets: Vec::new(),
        imported_kek_salt: None,
    };
    let counts = payload_counts(&payload);
    let envelope = encrypt_payload(&payload, password, include_audit, config)?;

    info!(
        keyspaces = payload.keyspaces.len(),
        keys = counts.keys,
        acls = counts.acls,
        contexts = counts.contexts,
        audit = counts.audit,
        internal_keys_not_carried = payload.internal_keys_not_carried.len(),
        environment = %target.environment,
        "backup exported"
    );
    Ok(envelope)
}

// ── Import ─────────────────────────────────────────────────────────

/// Row counts a preview or an import reports. Counts, not an inventory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PayloadCounts {
    pub keys: usize,
    pub acls: usize,
    pub contexts: usize,
    pub audit: usize,
    pub imported_secrets: usize,
}

/// Count what a payload restores, whichever format it is.
pub fn payload_counts(payload: &BackupPayload) -> PayloadCounts {
    if payload.keyspaces.is_empty() {
        return PayloadCounts {
            keys: payload.key_records.len(),
            acls: payload
                .acl_entries_full
                .len()
                .max(payload.acl_entries.len()),
            contexts: payload.context_records.len(),
            audit: payload.audit_logs.len(),
            imported_secrets: payload.imported_secrets.len(),
        };
    }
    let count = |keyspace: &str, prefix: &str| {
        payload
            .keyspaces
            .iter()
            .filter(|d| d.name == keyspace)
            .flat_map(|d| d.rows.iter())
            .filter(|(k, _)| {
                BASE64
                    .decode(k)
                    .is_ok_and(|k| k.starts_with(prefix.as_bytes()))
            })
            .count()
    };
    PayloadCounts {
        keys: count(vta_keyspaces::KEYS, "key:"),
        acls: count(vta_keyspaces::ACL, "acl:"),
        contexts: count(vta_keyspaces::CONTEXTS, "ctx:"),
        audit: count(vta_keyspaces::AUDIT, "log:"),
        imported_secrets: count(vta_keyspaces::IMPORTED_SECRETS, "secret:"),
    }
}

fn import_result(payload: &BackupPayload, status: &str, message: String) -> ImportResult {
    let counts = payload_counts(payload);
    ImportResult {
        status: status.into(),
        source_did: payload.config.vta_did.clone(),
        key_count: counts.keys,
        acl_count: counts.acls,
        context_count: counts.contexts,
        audit_count: counts.audit,
        imported_secret_count: counts.imported_secrets,
        message: Some(message),
    }
}

/// Refuse a payload this build cannot restore faithfully, before anything is
/// staged. Everything here is checked again at boot; checking it first means
/// a bad backup is refused to the operator rather than discovered by a boot.
pub fn validate_payload(payload: &BackupPayload) -> Result<(), AppError> {
    let seed = hex::decode(&payload.active_seed_hex)
        .map_err(|e| AppError::Validation(format!("backup seed is not hex: {e}")))?;
    if seed.is_empty() {
        return Err(AppError::Validation("backup carries an empty seed".into()));
    }
    if let Some(jwt) = &payload.jwt_signing_key {
        decode_jwt_key(jwt)?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for dump in &payload.keyspaces {
        // The dump names the keyspace it writes. A backup is attacker-supplied
        // input to a super-admin, and a name outside `BACKED_UP` would let it
        // write into `bootstrap` (the enclave's boot material) or plant an
        // internal key — neither of which any export produces.
        if !vta_keyspaces::BACKED_UP.contains(&dump.name.as_str()) {
            return Err(AppError::Validation(format!(
                "backup carries keyspace '{}', which is not one a backup may restore",
                dump.name
            )));
        }
        if !seen.insert(dump.name.as_str()) {
            return Err(AppError::Validation(format!(
                "backup carries keyspace '{}' twice",
                dump.name
            )));
        }
        for (k, v) in &dump.rows {
            let key = BASE64.decode(k).map_err(|e| {
                AppError::Validation(format!(
                    "backup row key in '{}' is not base64: {e}",
                    dump.name
                ))
            })?;
            BASE64.decode(v).map_err(|e| {
                AppError::Validation(format!(
                    "backup row value in '{}' is not base64: {e}",
                    dump.name
                ))
            })?;
            if vta_keyspaces::is_environment_bound(&dump.name, &key) {
                return Err(AppError::Validation(format!(
                    "backup carries deployment-bound row '{}' in '{}'; a backup of this \
                     agent never does",
                    String::from_utf8_lossy(&key),
                    dump.name
                )));
            }
        }
    }
    Ok(())
}

/// Decrypt and validate a backup, returning a preview without modifying state.
pub async fn preview_import(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<(BackupPayload, ImportResult), AppError> {
    let payload = decrypt_backup(envelope, password)?;
    validate_payload(&payload)?;
    let mut message =
        String::from("Preview only — no changes applied. Set confirm=true to import.");
    if !payload.internal_keys_not_carried.is_empty() {
        message.push_str(&format!(
            " {} internal key(s) are not in the backup and cannot be restored: {}.",
            payload.internal_keys_not_carried.len(),
            payload.internal_keys_not_carried.join(", ")
        ));
    }
    let result = import_result(&payload, "preview", message);
    Ok((payload, result))
}

/// [`preview_import`], plus the identity check a commit would make — so an
/// operator who previews a backup of another agent is told then, with the
/// flag that allows it, rather than after confirming.
pub async fn preview_import_for(
    envelope: &BackupEnvelope,
    password: &str,
    running_did: Option<&str>,
    replace_identity: bool,
) -> Result<(BackupPayload, ImportResult), AppError> {
    let (payload, result) = preview_import(envelope, password).await?;
    check_vta_did_compatibility(
        running_did,
        payload.config.vta_did.as_deref(),
        replace_identity,
    )?;
    Ok((payload, result))
}

/// Reject an import if the backup's `vta_did` would overwrite a
/// different running VTA's identity, unless the operator said to.
///
/// A fresh install (no running `vta_did`) accepts any backup. A VTA that
/// already runs as some DID accepts a backup of *that* DID; a backup of a
/// different one needs `replace_identity` — the disaster-recovery case, where
/// the target was set up fresh and minted a DID of its own (every `vta setup`
/// does, and an enclave with a DID template does on first boot).
fn check_vta_did_compatibility(
    running_did: Option<&str>,
    backup_did: Option<&str>,
    replace_identity: bool,
) -> Result<(), AppError> {
    let running = match running_did {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(()),
    };
    let backup = backup_did.unwrap_or("");
    if backup == running || replace_identity {
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "backup vta_did mismatch: backup claims '{backup}' but this VTA is running \
         as '{running}'. Refusing to overwrite identity. If this is intentional — \
         restoring onto a freshly set-up VTA, or migrating an identity — re-run the \
         import with --replace-identity."
    )))
}

fn decode_jwt_key(b64: &str) -> Result<[u8; 32], AppError> {
    BASE64
        .decode(b64)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            AppError::Validation("backup JWT signing key is not 32 bytes of base64url".into())
        })
}

/// What a caller needs to stage a restore.
pub struct StageRequest<'a> {
    pub target: &'a BackupTarget<'a>,
    pub config: &'a tokio::sync::RwLock<vta_config::AppConfig>,
    pub committer: &'a dyn RestoreCommitter,
    pub auth: &'a AuthClaims,
    /// See [`ImportRequest::replace_identity`].
    pub replace_identity: bool,
}

/// Commit an import: stage the restore, have the target adopt the restored
/// seed, and return. **The caller must then reboot the VTA** — the restore is
/// applied by the next boot, not by this call (see `vta_support::restore_stage`
/// for why it cannot be applied in place).
///
/// Nothing in the running store is changed. If this returns an error before the
/// commit, the VTA carries on exactly as it was; the stage it may have written
/// cannot be opened and the next boot discards it.
pub async fn stage_import(
    payload: BackupPayload,
    req: StageRequest<'_>,
) -> Result<ImportResult, AppError> {
    req.auth.require_super_admin()?;
    validate_payload(&payload)?;

    let running_did = req.config.read().await.vta_did.clone();
    check_vta_did_compatibility(
        running_did.as_deref(),
        payload.config.vta_did.as_deref(),
        req.replace_identity,
    )?;
    let cross_identity = matches!(
        (running_did.as_deref(), payload.config.vta_did.as_deref()),
        (Some(running), backup) if !running.is_empty() && Some(running) != backup
    );

    let seed = zeroize::Zeroizing::new(
        hex::decode(&payload.active_seed_hex)
            .map_err(|e| AppError::Validation(format!("backup seed is not hex: {e}")))?,
    );
    let jwt_key = payload
        .jwt_signing_key
        .as_deref()
        .map(decode_jwt_key)
        .transpose()?;
    let restored_did = payload.config.vta_did.clone();
    let secrets = RestoredSecrets {
        seed: &seed,
        jwt_key,
        vta_did: restored_did.as_deref(),
    };

    let prepared = req.committer.prepare(&secrets).await?;
    let restore_id = uuid::Uuid::new_v4().to_string();
    let meta = StageMeta {
        restore_id: restore_id.clone(),
        staged_at: Utc::now(),
        staged_by: req.auth.did.clone(),
        target_environment: req.target.environment,
        cross_identity,
        tee_secrets_sha256: prepared
            .tee_secrets_row
            .as_deref()
            .map(restore_stage::sha256_hex),
        anchor: prepared.anchor.clone(),
    };
    let result = import_result(
        &payload,
        "imported",
        restore_message(&payload, req.target.environment),
    );

    let staged = async {
        restore_stage::write_stage(&req.target.bootstrap()?, &seed, meta, payload).await?;
        // The point of no return: from here the next boot opens the stage.
        req.committer.commit(&secrets, prepared).await
    }
    .await;
    if let Err(e) = staged {
        req.committer.abort().await;
        return Err(e);
    }

    info!(
        restore_id,
        staged_by = %req.auth.did,
        source_did = result.source_did.as_deref().unwrap_or("unknown"),
        target_environment = %req.target.environment,
        cross_identity,
        "backup import committed — the VTA reboots to apply it"
    );
    Ok(result)
}

fn restore_message(payload: &BackupPayload, target: BackupEnvironment) -> String {
    let mut message = format!(
        "Restore committed. The VTA is rebooting to apply it{}.",
        match payload.source_environment {
            Some(source) if source != target => format!(" ({source} → {target})"),
            _ => String::new(),
        }
    );
    if !payload.internal_keys_not_carried.is_empty() {
        message.push_str(&format!(
            " {} internal key(s) were not in the backup and are lost: {}.",
            payload.internal_keys_not_carried.len(),
            payload.internal_keys_not_carried.join(", ")
        ));
    }
    message
}

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

/// Write a `vta-backup-v1` payload's typed collections into an empty store.
/// Called by the boot-time restore for a v1 backup, after the wipe; a v2
/// backup is written row for row instead.
pub(crate) async fn write_legacy_payload(
    payload: &BackupPayload,
    ks: &vta_keyspaces::Keyspaces<'_>,
    seed_bytes: &[u8],
) -> Result<(), AppError> {
    let keys_ks = ks.keys;
    let acl_ks = ks.acl;
    let contexts_ks = ks.contexts;
    let audit_ks = ks.audit;
    let imported_ks = ks.imported;

    set_active_seed_id(keys_ks, payload.active_seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("set active seed id: {e}")))?;

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

    for kr in &payload.key_records {
        keys_ks.insert(vta_keys::store_key(&kr.key_id), kr).await?;
    }

    for cr in &payload.context_records {
        contexts_ks.insert(format!("ctx:{}", cr.id), cr).await?;
    }
    contexts_ks
        .insert_raw("ctx_counter", &payload.context_counter.to_le_bytes())
        .await?;

    // Restore the BIP-32 allocation counters (P0.5). Take the MAX of the
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

    // Prefer the lossless full-JSON ACL form (`acl_entries_full`) so expiry /
    // step-up floors / capabilities / kind / device / version survive; fall
    // back to the lossy 6-field `acl_entries` only for a pre-P0.5 backup.
    if !payload.acl_entries_full.is_empty() {
        for entry in &payload.acl_entries_full {
            let did = entry
                .get("did")
                .and_then(|d| d.as_str())
                .ok_or_else(|| AppError::Internal("backup ACL entry has no `did` field".into()))?;
            let bytes = serde_json::to_vec(entry)?;
            acl_ks.insert_raw(format!("acl:{did}"), bytes).await?;
        }
    } else if !payload.acl_entries.is_empty() {
        warn!(
            count = payload.acl_entries.len(),
            "restoring ACL from a pre-P0.5 backup's lossy form — expiry, step-up \
             floors, and capability restrictions are not present and default to \
             permanent/none. Re-export with this build for a lossless backup."
        );
        for entry in &payload.acl_entries {
            acl_ks.insert(format!("acl:{}", entry.did), entry).await?;
        }
    }

    if let Some(ref seal) = payload.seal {
        let record = SealRecord {
            sealed_by: seal.sealed_by.clone(),
            sealed_at: seal.sealed_at,
            reason: seal.reason.clone(),
        };
        acl_ks.insert("vta:sealed", &record).await?;
    }

    #[cfg(feature = "webvh")]
    {
        let webvh_ks = ks.webvh;
        for server in &payload.webvh_servers {
            webvh_ks
                .insert(format!("server:{}", server.id), server)
                .await?;
        }
        for did_rec in &payload.webvh_dids {
            webvh_ks
                .insert(format!("did:{}", did_rec.did), did_rec)
                .await?;
        }
        for log in &payload.webvh_logs {
            webvh_ks
                .insert_raw(format!("log:{}", log.did), log.log_json.as_bytes())
                .await?;
        }
    }

    for entry in &payload.audit_logs {
        audit_ks
            .insert(format!("log:{:020}:{}", entry.timestamp, entry.id), entry)
            .await?;
    }

    if !payload.imported_secrets.is_empty() {
        if let Some(ref salt_hex) = payload.imported_kek_salt {
            let salt = hex::decode(salt_hex)
                .map_err(|e| AppError::Internal(format!("invalid imported KEK salt hex: {e}")))?;
            imported::set_salt(keys_ks, &salt).await?;
        }
        for secret_backup in &payload.imported_secrets {
            let mut private_bytes = hex::decode(&secret_backup.private_key_hex)
                .map_err(|e| AppError::Internal(format!("invalid imported secret hex: {e}")))?;
            let key_type_str = payload
                .key_records
                .iter()
                .find(|kr| kr.key_id == secret_backup.key_id)
                .map(|kr| kr.key_type.to_string())
                .unwrap_or_else(|| "ed25519".to_string());
            let stored = imported::store_secret(
                imported_ks,
                keys_ks,
                seed_bytes,
                &secret_backup.key_id,
                &key_type_str,
                &private_bytes,
            )
            .await;
            use zeroize::Zeroize;
            private_bytes.zeroize();
            stored?;
        }
    }
    Ok(())
}

// ── Crypto helpers ─────────────────────────────────────────────────

/// Associated data binding a v2 envelope's metadata to its ciphertext, so the
/// unencrypted fields an operator reads before typing a password (source DID,
/// whether the trail is included) cannot be swapped onto another backup.
fn envelope_aad(envelope: &BackupEnvelope) -> Vec<u8> {
    let mut aad = Vec::new();
    for field in [
        envelope.format.as_bytes(),
        &envelope.version.to_be_bytes(),
        envelope.source_did.as_deref().unwrap_or("").as_bytes(),
        &[u8::from(envelope.includes_audit)],
        envelope.kdf.salt.as_bytes(),
        envelope.encryption.nonce.as_bytes(),
    ] {
        aad.extend_from_slice(&(field.len() as u32).to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad
}

fn derive_backup_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<zeroize::Zeroizing<[u8; 32]>, AppError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| AppError::Validation(format!("argon2 params: {e}")))?,
    );
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?;
    Ok(key)
}

fn encrypt_payload(
    payload: &BackupPayload,
    password: &str,
    include_audit: bool,
    config: &vta_config::AppConfig,
) -> Result<BackupEnvelope, AppError> {
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(payload).map_err(|e| AppError::Internal(format!("serialize: {e}")))?,
    );

    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);

    let key = derive_backup_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;

    let mut envelope = BackupEnvelope {
        version: 2,
        format: BACKUP_FORMAT_V2.into(),
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
        ciphertext: String::new(),
    };

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let nonce = (&nonce_bytes).into();
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: &envelope_aad(&envelope),
            },
        )
        .map_err(|e| AppError::Internal(format!("aes encrypt: {e}")))?;
    envelope.ciphertext = BASE64.encode(&ciphertext);
    Ok(envelope)
}

/// Decrypt a backup envelope and return the payload.
///
/// Accepts `vta-backup-v2` (every export this build writes) and `vta-backup-v1`
/// (typed collections, no associated data). Use this for confirmed imports to
/// avoid the overhead of building an `ImportResult` preview. For preview mode,
/// use `preview_import()`.
pub fn decrypt_backup(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<BackupPayload, AppError> {
    let v2 = match (envelope.version, envelope.format.as_str()) {
        (2, BACKUP_FORMAT_V2) => true,
        (1, BACKUP_FORMAT_V1) => false,
        _ => {
            return Err(AppError::Validation(format!(
                "unsupported backup format: {} v{}",
                envelope.format, envelope.version
            )));
        }
    };

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
    // Length check before the nonce is built. This used to be the *only*
    // thing standing between a crafted backup envelope and a process-killing
    // DoS on `/backup/import`, because `Nonce::from_slice` panicked on the
    // wrong length. The conversion below is now `TryFrom`, so the panic is
    // gone by construction and this check is no longer load-bearing for
    // safety — it stays because it produces the better error: "invalid nonce
    // length: 11 (expected 12)" rather than a bare conversion failure.
    if nonce_bytes.len() != NONCE_LEN {
        return Err(AppError::Validation(format!(
            "invalid nonce length: {} (expected {NONCE_LEN})",
            nonce_bytes.len()
        )));
    }
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|e| AppError::Validation(format!("invalid ciphertext: {e}")))?;

    let key = derive_backup_key(
        password,
        &salt,
        envelope.kdf.m_cost,
        envelope.kdf.t_cost,
        envelope.kdf.p_cost,
    )?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| AppError::Validation(format!("nonce must be {NONCE_LEN} bytes")))?;
    let aad = if v2 {
        envelope_aad(envelope)
    } else {
        Vec::new()
    };
    let plaintext = zeroize::Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| AppError::Authentication("incorrect backup password".into()))?,
    );

    serde_json::from_slice(&plaintext)
        .map_err(|e| AppError::Internal(format!("backup payload corrupt: {e}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support::{
        TestSeedStore, open_test_store, super_admin_claims, test_app_config,
    };

    /// The Argon2id key derivation, pinned to a frozen vector.
    ///
    /// A backup envelope stores the salt and the KDF parameters, not the key.
    /// Decryption re-derives it, so this function's output *is* the format:
    /// change a byte of it and every backup ever written becomes
    /// undecryptable, with nothing to say so but an AES-GCM tag failure.
    ///
    /// The encrypt/decrypt round-trip tests cannot catch that — they derive
    /// the key twice with the same linked version, so both sides move
    /// together. This vector was produced by argon2 0.5 and re-checked
    /// against 0.6 during that upgrade; it does not move.
    ///
    /// If this fails, do not regenerate it. It means the linked crate changed
    /// its derivation, and the change needs a versioned KDF marker in the
    /// envelope plus a path that reads the old one.
    #[test]
    fn argon2id_derivation_matches_the_frozen_vector() {
        let key = derive_backup_key(
            "backup-password",
            b"0123456789abcdef",
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        )
        .unwrap();
        assert_eq!(
            key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "3558837960e818d4ae946a900d505053894bf02a6ac9e046f0781fe09a616bf9",
            "the backup KDF changed — every existing envelope is now \
             undecryptable"
        );
    }

    fn plain_target(ts: &crate::test_support::TestStore) -> BackupTarget<'_> {
        BackupTarget {
            store: &ts.store,
            storage_key: None,
            environment: BackupEnvironment::Plain,
        }
    }

    /// A backup must be complete: a corrupt `key:` row must ABORT the
    /// export rather than be silently carried (which would restore a key
    /// record nothing can read). This is the deliberate opposite of the
    /// steady-state list paths, which skip corrupt rows.
    #[tokio::test]
    async fn export_aborts_on_corrupt_key_row() {
        let ts = open_test_store().await;
        let config = test_app_config(ts.data_dir.clone());
        ts.keys_ks
            .insert_raw("key:corrupt", b"{not a key record".to_vec())
            .await
            .unwrap();

        let err = export_backup(
            &plain_target(&ts),
            &TestSeedStore(vec![42u8; 32]),
            &config,
            &super_admin_claims(),
            "a-strong-password",
            false,
        )
        .await
        .expect_err("export must abort on a corrupt key row");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("corrupt") && msg.contains("key"),
            "error must name the corrupt-row cause, got: {msg}"
        );
    }

    /// `export_backup` rejects passwords shorter than 15 characters with a
    /// `Validation` error. The check fires before any keyspace I/O.
    /// A password of exactly 15 characters must be accepted (boundary).
    #[tokio::test]
    async fn export_rejects_short_password() {
        let ts = open_test_store().await;
        let config = test_app_config(ts.data_dir.clone());
        let seed_store = TestSeedStore(vec![42u8; 32]);
        let target = plain_target(&ts);
        let auth = super_admin_claims();

        let err = export_backup(
            &target,
            &seed_store,
            &config,
            &auth,
            "14-char-passwo",
            false,
        )
        .await
        .expect_err("export must reject a 14-character password");
        assert!(
            format!("{err}").contains("15 characters"),
            "error must mention the 15-character minimum, got: {err}"
        );
        export_backup(
            &target,
            &seed_store,
            &config,
            &auth,
            "15-char-passwor",
            false,
        )
        .await
        .expect("export must accept a 15-character password");
    }

    /// Environment-bound rows are the deployment's, not the agent's. An export
    /// that carried the source enclave's identity mirror or a hardened VTA's
    /// JWT row would plant it on a target that means something else by it.
    #[tokio::test]
    async fn export_leaves_deployment_bound_rows_behind() {
        let ts = open_test_store().await;
        let config = test_app_config(ts.data_dir.clone());
        ts.keys_ks
            .insert_raw("tee:vta_did", b"did:example:enclave".to_vec())
            .await
            .unwrap();
        ts.keys_ks
            .insert_raw("hardened:jwt_key", vec![1u8; 32])
            .await
            .unwrap();
        ts.webvh_ks
            .insert_raw("server-auth:srv", b"token".to_vec())
            .await
            .unwrap();
        ts.keys_ks
            .insert_raw("path_counter:m/1'", 3u32.to_le_bytes().to_vec())
            .await
            .unwrap();

        let env = export_backup(
            &plain_target(&ts),
            &TestSeedStore(vec![42u8; 32]),
            &config,
            &super_admin_claims(),
            "a-strong-password",
            false,
        )
        .await
        .unwrap();
        let payload = decrypt_backup(&env, "a-strong-password").unwrap();
        let keys: Vec<Vec<u8>> = payload
            .keyspaces
            .iter()
            .flat_map(|d| d.rows.iter().map(|(k, _)| BASE64.decode(k).unwrap()))
            .collect();
        assert!(keys.iter().any(|k| k == b"path_counter:m/1'"));
        for bound in [&b"tee:vta_did"[..], b"hardened:jwt_key", b"server-auth:srv"] {
            assert!(
                !keys.iter().any(|k| k == bound),
                "{} must not be exported",
                String::from_utf8_lossy(bound)
            );
        }
        assert_eq!(payload.source_environment, Some(BackupEnvironment::Plain));
    }

    fn v2_payload() -> BackupPayload {
        BackupPayload {
            active_seed_hex: hex::encode([42u8; 32]),
            active_seed_id: 1,
            seed_records: vec![],
            jwt_signing_key: Some(BASE64.encode([99u8; 32])),
            key_records: vec![],
            context_records: vec![],
            context_counter: 0,
            path_counters: vec![],
            subcontext_counters: vec![],
            acl_entries: vec![],
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
            keyspaces: vec![KeyspaceDump {
                name: vta_keyspaces::ACL.into(),
                rows: vec![(BASE64.encode("acl:did:key:zA"), BASE64.encode("{}"))],
            }],
            source_environment: Some(BackupEnvironment::Tee),
            internal_keys_not_carried: vec![],
        }
    }

    fn test_config() -> vta_config::AppConfig {
        toml::from_str("").unwrap()
    }

    /// The pre-v2 envelope, exactly as the previous build wrote it (no
    /// associated data), so the v1 read path stays tested against real bytes
    /// rather than against its own writer.
    fn encrypt_v1(payload: &BackupPayload, password: &str) -> BackupEnvelope {
        let plaintext = serde_json::to_vec(payload).unwrap();
        let salt = [5u8; SALT_LEN];
        let nonce_bytes = [6u8; NONCE_LEN];
        let key = derive_backup_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let ciphertext = cipher
            .encrypt((&nonce_bytes).into(), plaintext.as_ref())
            .unwrap();
        BackupEnvelope {
            version: 1,
            format: BACKUP_FORMAT_V1.into(),
            created_at: Utc::now(),
            source_did: payload.config.vta_did.clone(),
            source_version: "0.0.0".into(),
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
            includes_audit: false,
            ciphertext: BASE64.encode(ciphertext),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let payload = v2_payload();
        let password = "test-password-12chars!";
        let envelope = encrypt_payload(&payload, password, false, &test_config()).unwrap();

        assert_eq!(envelope.version, 2);
        assert_eq!(envelope.format, BACKUP_FORMAT_V2);
        assert_eq!(envelope.kdf.algorithm, "argon2id");
        assert_eq!(envelope.encryption.algorithm, "aes-256-gcm");

        let decrypted = decrypt_backup(&envelope, password).unwrap();
        assert_eq!(decrypted.active_seed_hex, payload.active_seed_hex);
        assert_eq!(decrypted.jwt_signing_key, payload.jwt_signing_key);
        assert_eq!(decrypted.keyspaces.len(), 1);
        assert_eq!(decrypted.keyspaces[0].rows, payload.keyspaces[0].rows);
        assert_eq!(decrypted.source_environment, Some(BackupEnvironment::Tee));
        assert_eq!(decrypted.config.vta_did, Some("did:key:z6MkVTA".into()));
    }

    /// Every backup written before v2 must keep restoring.
    #[test]
    fn a_v1_envelope_still_decrypts() {
        let mut payload = v2_payload();
        payload.keyspaces.clear();
        payload.acl_entries = vec![AclEntryBackup {
            did: "did:key:z6MkTest".into(),
            role: "Admin".into(),
            label: None,
            allowed_contexts: vec![],
            created_at: 1000,
            created_by: "did:key:z6MkSetup".into(),
        }];
        let env = encrypt_v1(&payload, "v1-password-12chars");
        let back = decrypt_backup(&env, "v1-password-12chars").unwrap();
        assert!(back.keyspaces.is_empty());
        assert_eq!(back.acl_entries.len(), 1);
    }

    /// The fields an operator reads before typing a password are bound to the
    /// ciphertext in v2: relabelling a backup as another agent's fails.
    #[test]
    fn v2_envelope_metadata_is_authenticated() {
        let password = "test-password-12chars!";
        let mut env = encrypt_payload(&v2_payload(), password, false, &test_config()).unwrap();
        env.source_did = Some("did:key:z6MkSomeoneElse".into());
        assert!(decrypt_backup(&env, password).is_err());

        let mut env = encrypt_payload(&v2_payload(), password, false, &test_config()).unwrap();
        env.includes_audit = true;
        assert!(decrypt_backup(&env, password).is_err());
    }

    #[test]
    fn wrong_password_fails() {
        let envelope =
            encrypt_payload(&v2_payload(), "correct-password!!", false, &test_config()).unwrap();
        let err = decrypt_backup(&envelope, "wrong-password!!!").unwrap_err();
        assert!(
            format!("{err}").contains("incorrect backup password"),
            "expected auth error, got: {err}"
        );
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let password = "test-password-12chars!";
        let mut envelope = encrypt_payload(&v2_payload(), password, false, &test_config()).unwrap();
        let mut ct_bytes = BASE64.decode(&envelope.ciphertext).unwrap();
        if let Some(byte) = ct_bytes.last_mut() {
            *byte ^= 0xFF;
        }
        envelope.ciphertext = BASE64.encode(&ct_bytes);
        assert!(
            format!("{}", decrypt_backup(&envelope, password).unwrap_err())
                .contains("incorrect backup password"),
            "tampered ciphertext should fail AES-GCM auth"
        );
    }

    #[test]
    fn unsupported_version_and_format_rejected() {
        let password = "test-password-12chars!";
        for (version, format) in [
            (99, BACKUP_FORMAT_V2),
            (2, "unknown-format"),
            // A version that does not match its format is not guessed at.
            (1, BACKUP_FORMAT_V2),
            (2, BACKUP_FORMAT_V1),
        ] {
            let mut envelope =
                encrypt_payload(&v2_payload(), password, false, &test_config()).unwrap();
            envelope.version = version;
            envelope.format = format.into();
            assert!(
                format!("{}", decrypt_backup(&envelope, password).unwrap_err())
                    .contains("unsupported backup format"),
                "v{version} {format} must be refused"
            );
        }
    }

    #[test]
    fn envelope_serialization_roundtrip() {
        let password = "test-password-12chars!";
        let envelope = encrypt_payload(&v2_payload(), password, true, &test_config()).unwrap();
        let json = serde_json::to_string_pretty(&envelope).unwrap();
        let deserialized: BackupEnvelope = serde_json::from_str(&json).unwrap();
        assert!(deserialized.includes_audit);
        assert_eq!(deserialized.ciphertext, envelope.ciphertext);
        let decrypted = decrypt_backup(&deserialized, password).unwrap();
        assert_eq!(decrypted.active_seed_hex, v2_payload().active_seed_hex);
    }

    #[test]
    fn different_passwords_produce_different_ciphertexts() {
        let env1 =
            encrypt_payload(&v2_payload(), "password-one-12!!", false, &test_config()).unwrap();
        let env2 =
            encrypt_payload(&v2_payload(), "password-two-12!!", false, &test_config()).unwrap();
        assert_ne!(env1.kdf.salt, env2.kdf.salt);
        assert_ne!(env1.ciphertext, env2.ciphertext);
    }

    // ── payload validation ──────────────────────────────────────────

    /// A backup is attacker-supplied input to a super-admin. A dump naming a
    /// keyspace outside `BACKED_UP` would write straight into an enclave's
    /// boot material, or plant an "internal" key nobody generated.
    #[test]
    fn a_payload_cannot_write_outside_the_backed_up_keyspaces() {
        for name in [
            vta_keyspaces::BOOTSTRAP,
            vta_keyspaces::INTERNAL_KEYS,
            "no_such",
        ] {
            let mut payload = v2_payload();
            payload.keyspaces.push(KeyspaceDump {
                name: name.into(),
                rows: vec![],
            });
            let err = validate_payload(&payload).unwrap_err();
            assert!(format!("{err}").contains(name), "{name}: {err}");
        }
    }

    #[test]
    fn a_payload_cannot_carry_a_deployment_bound_row() {
        let mut payload = v2_payload();
        payload.keyspaces.push(KeyspaceDump {
            name: vta_keyspaces::KEYS.into(),
            rows: vec![(BASE64.encode("tee:vta_did"), BASE64.encode("did:x"))],
        });
        assert!(
            format!("{}", validate_payload(&payload).unwrap_err()).contains("deployment-bound")
        );
    }

    #[test]
    fn a_payload_cannot_name_a_keyspace_twice() {
        let mut payload = v2_payload();
        payload.keyspaces.push(payload.keyspaces[0].clone());
        assert!(format!("{}", validate_payload(&payload).unwrap_err()).contains("twice"));
    }

    #[test]
    fn payload_counts_read_raw_rows() {
        let mut payload = v2_payload();
        payload.keyspaces.push(KeyspaceDump {
            name: vta_keyspaces::KEYS.into(),
            rows: vec![
                (BASE64.encode("key:a"), BASE64.encode("{}")),
                (BASE64.encode("key:b"), BASE64.encode("{}")),
                (BASE64.encode("path_counter:x"), BASE64.encode("1")),
            ],
        });
        let counts = payload_counts(&payload);
        assert_eq!(counts.keys, 2);
        assert_eq!(counts.acls, 1);
    }

    // ── vta_did cross-check guard ───────────────────────────────────

    #[test]
    fn vta_did_guard_fresh_install_accepts_any_backup() {
        check_vta_did_compatibility(None, Some("did:key:z6MkAnything"), false)
            .expect("fresh install must accept any backup");
        check_vta_did_compatibility(None, None, false)
            .expect("fresh install accepts no-did backup");
        check_vta_did_compatibility(Some(""), Some("did:key:z6MkAnything"), false)
            .expect("empty-string vta_did counts as fresh install");
    }

    #[test]
    fn vta_did_guard_matching_dids_accepted() {
        check_vta_did_compatibility(Some("did:key:z6MkSame"), Some("did:key:z6MkSame"), false)
            .expect("matching vta_did must pass");
    }

    #[test]
    fn vta_did_guard_mismatch_rejected_with_the_fix() {
        let err = check_vta_did_compatibility(
            Some("did:key:z6MkRunning"),
            Some("did:key:z6MkForeignBackup"),
            false,
        )
        .expect_err("mismatched vta_did must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("vta_did mismatch"), "got: {msg}");
        assert!(
            msg.contains("z6MkForeignBackup"),
            "must name backup did: {msg}"
        );
        assert!(msg.contains("z6MkRunning"), "must name running did: {msg}");
        assert!(
            msg.contains("--replace-identity"),
            "must name the fix: {msg}"
        );
    }

    /// Disaster recovery onto a freshly set-up VTA: it minted a DID of its
    /// own, and the operator says to replace it.
    #[test]
    fn vta_did_guard_yields_to_replace_identity() {
        check_vta_did_compatibility(
            Some("did:key:z6MkFreshlySetUp"),
            Some("did:key:z6MkTheOneWeLost"),
            true,
        )
        .expect("replace_identity must allow the swap");
    }

    #[test]
    fn vta_did_guard_backup_missing_did_rejected_when_running_has_did() {
        let err = check_vta_did_compatibility(Some("did:key:z6MkRunning"), None, false)
            .expect_err("missing backup vta_did must be rejected when running has one");
        assert!(format!("{err}").contains("vta_did mismatch"), "got {err:?}");
    }

    #[test]
    fn recompute_path_counters_skips_imported_keys_and_takes_max() {
        let recs = vec![
            mk_key_record("a", "m/26'/2'/0'/0'"),
            mk_key_record("b", "m/26'/2'/0'/3'"),
            mk_key_record("imported", ""),
        ];
        let counters = recompute_path_counters(&recs);
        assert_eq!(counters.get("m/26'/2'/0'"), Some(&4));
        assert_eq!(counters.len(), 1);
    }

    pub(crate) fn mk_key_record(key_id: &str, derivation_path: &str) -> vta_sdk::keys::KeyRecord {
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
            exportable: None,
            origin: KeyOrigin::Derived,
            created_at: now,
            updated_at: now,
        }
    }

    // ── KDF parameter clamps on import ──────────────────────────────

    fn make_envelope_with_kdf(m_cost: u32, t_cost: u32, p_cost: u32, alg: &str) -> BackupEnvelope {
        // Build a real encrypted envelope, then mutate the KDF params. The
        // bounds check fires before decrypt is attempted — that's the
        // behaviour under test.
        let mut env =
            encrypt_payload(&v2_payload(), "password-12!ok!a", false, &test_config()).unwrap();
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
    // Regression tests for the DoS where a crafted envelope's wrong-length
    // nonce would panic `Nonce::from_slice`. The panic is now impossible by
    // construction — the conversion is `TryFrom` — but these stay: they
    // assert the *rejection*, which is still what callers depend on.

    #[test]
    fn nonce_wrong_length_rejected_without_panic() {
        let mut env =
            encrypt_payload(&v2_payload(), "password-12!ok!a", false, &test_config()).unwrap();
        env.encryption.nonce = BASE64.encode([0u8; 16]);
        let msg = format!(
            "{}",
            decrypt_backup(&env, "password-12!ok!a")
                .expect_err("wrong-length nonce must be rejected pre-decrypt")
        );
        assert!(
            msg.contains("nonce length"),
            "expected nonce-length error, got: {msg}"
        );
    }

    #[test]
    fn salt_wrong_length_rejected_without_panic() {
        let mut env =
            encrypt_payload(&v2_payload(), "password-12!ok!a", false, &test_config()).unwrap();
        env.kdf.salt = BASE64.encode([0u8; 16]);
        let msg = format!(
            "{}",
            decrypt_backup(&env, "password-12!ok!a")
                .expect_err("wrong-length salt must be rejected pre-decrypt")
        );
        assert!(
            msg.contains("salt length"),
            "expected salt-length error, got: {msg}"
        );
    }
}
