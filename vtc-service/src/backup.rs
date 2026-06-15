//! Encrypted full-state backup / restore (P3.9).
//!
//! The VTC holds a community's irreplaceable social state — members,
//! ACL, endorsements, relationships, policies, audit, and the bitstring
//! status lists whose loss bricks every issued VMC's `credentialStatus`.
//! This module exports that state (plus the signing key bundle) into a
//! single password-encrypted artifact and restores it.
//!
//! Design note: `docs/05-design-notes/vtc-backup-restore.md`. Crypto is
//! the VTA's verbatim — Argon2id + AES-256-GCM. The keyspace census
//! (`keyspaces::BACKED_UP` ∪ `EXCLUDED_FROM_BACKUP` == `ALL`) guarantees
//! no keyspace is silently omitted.

use std::collections::BTreeMap;

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::config::MessagingConfig;
use crate::keys::seed_store::SecretStore;
use crate::server::AppState;
use crate::store::keyspaces;

// ── Crypto parameters (VTA-identical) ───────────────────────────────────
const VERSION: u32 = 1;
const FORMAT: &str = "vtc-backup-v1";
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MIN_PASSWORD_LEN: usize = 12;

// Import-side Argon2 bounds — clamp untrusted envelopes so a malicious
// `m_cost` can't drive a memory bomb on decrypt.
const MIN_M_COST: u32 = 8 * 1024; // 8 MiB
const MAX_M_COST: u32 = 1 << 20; // 1 GiB
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 10;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 16;

/// Sentinel key, written into the `config` keyspace (excluded from
/// backup, so it survives the import-time clear) before the destructive
/// replay and removed only on success. Boot refuses to start while it's
/// present — see [`import_in_progress`].
const IMPORT_IN_PROGRESS_KEY: &[u8] = b"backup:import_in_progress";

// ── Wire types ──────────────────────────────────────────────────────────

/// Outer envelope: unencrypted metadata + the encrypted payload. Crypto
/// fields mirror the VTA's `vta-backup-v1`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BackupEnvelope {
    pub version: u32,
    pub format: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    pub source_version: String,
    pub kdf: KdfParams,
    pub encryption: EncryptionParams,
    pub includes_audit: bool,
    /// base64url(AES-256-GCM(JSON([`BackupPayload`]))).
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct KdfParams {
    pub algorithm: String, // "argon2id"
    pub salt: String,      // base64url, 32 bytes
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EncryptionParams {
    pub algorithm: String, // "aes-256-gcm"
    pub nonce: String,     // base64url, 12 bytes
}

/// Inner (encrypted) payload. A config snapshot, the signing key bundle,
/// and a faithful raw dump of every backed-up keyspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    pub config: BackupConfig,
    /// Hex of the raw secret-store bytes (the encoded `VtcKeyBundle`).
    /// `None` only if the source had no bundle stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_bundle_hex: Option<String>,
    pub keyspaces: Vec<KeyspaceDump>,
}

/// One backed-up keyspace's full contents. Both key and value are
/// base64url-encoded so binary keys/values round-trip losslessly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyspaceDump {
    pub name: String,
    pub rows: Vec<(String, String)>,
}

/// The slice of config that travels with a backup so a restore onto a
/// fresh install reconstitutes the VTC's identity. The secrets *backend*
/// is deliberately not carried — the target's own backend is used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtc_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtc_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messaging: Option<MessagingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_signing_key: Option<String>,
}

/// Result of an import (or, with `confirm = false`, a preview).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportResult {
    pub status: String, // "imported" | "preview"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    /// Per-keyspace row counts the import wrote (or would write).
    pub counts: BTreeMap<String, usize>,
    pub message: String,
}

// ── Export ──────────────────────────────────────────────────────────────

/// Export every backed-up keyspace + the signing key bundle into an
/// encrypted [`BackupEnvelope`]. The `secret_store` (the configured
/// backend, constructed by the route from config) supplies the signing
/// key bundle. Caller must be super-admin (gated at the route).
pub async fn export_backup(
    state: &AppState,
    secret_store: &dyn SecretStore,
    password: &str,
    include_audit: bool,
) -> Result<BackupEnvelope, AppError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(AppError::Validation(format!(
            "backup password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }

    // Signing key bundle (hex of the raw stored bytes — backend-agnostic
    // round-trip).
    let key_bundle_hex = secret_store.get().await?.map(hex::encode);

    // Config snapshot.
    let config = {
        let cfg = state.config.read().await;
        BackupConfig {
            vtc_did: cfg.vtc_did.clone(),
            vtc_name: cfg.vtc_name.clone(),
            vta_did: cfg.vta_did.clone(),
            public_url: cfg.public_url.clone(),
            messaging: cfg.messaging.clone(),
            jwt_signing_key: cfg.auth.jwt_signing_key.clone(),
        }
    };

    // Keyspace census. `audit` rows are skipped unless requested; the
    // keyspace still appears (empty) so the dump shape is stable.
    let mut keyspace_dumps = Vec::with_capacity(keyspaces::BACKED_UP.len());
    for name in keyspaces::BACKED_UP {
        if *name == keyspaces::AUDIT && !include_audit {
            keyspace_dumps.push(KeyspaceDump {
                name: (*name).to_string(),
                rows: Vec::new(),
            });
            continue;
        }
        let ks = backed_up_handle(state, name).ok_or_else(|| {
            AppError::Internal(format!("backup: no AppState handle for keyspace '{name}'"))
        })?;
        let raw = ks.prefix_iter_raw(Vec::<u8>::new()).await?;
        let rows = raw
            .into_iter()
            .map(|(k, v)| (BASE64.encode(k), BASE64.encode(v)))
            .collect();
        keyspace_dumps.push(KeyspaceDump {
            name: (*name).to_string(),
            rows,
        });
    }

    let payload = BackupPayload {
        config,
        key_bundle_hex,
        keyspaces: keyspace_dumps,
    };
    encrypt_payload(&payload, password, include_audit, state).await
}

// ── Import ──────────────────────────────────────────────────────────────

/// Decrypt + apply a backup. With `confirm = false` this is a no-op
/// **preview** returning the row counts; with `confirm = true` it clears
/// the backed-up keyspaces and replays the backup. Identity-guarded on
/// `vtc_did`. Caller must be super-admin (gated at the route).
pub async fn import_backup(
    state: &AppState,
    secret_store: &dyn SecretStore,
    envelope: &BackupEnvelope,
    password: &str,
    confirm: bool,
) -> Result<ImportResult, AppError> {
    let payload = decrypt_backup(envelope, password)?;

    // Identity guard before any mutation.
    {
        let running = state.config.read().await.vtc_did.clone();
        check_vtc_did_compatibility(running.as_deref(), payload.config.vtc_did.as_deref())?;
    }

    let counts: BTreeMap<String, usize> = payload
        .keyspaces
        .iter()
        .map(|d| (d.name.clone(), d.rows.len()))
        .collect();

    if !confirm {
        return Ok(ImportResult {
            status: "preview".into(),
            source_did: payload.config.vtc_did.clone(),
            counts,
            message: "Preview only — pass confirm=true to apply. This will overwrite \
                      all community state."
                .into(),
        });
    }

    // Crash-safety: stamp the sentinel (in the excluded `config`
    // keyspace, so it survives the clear) + flush before mutating.
    state
        .config_ks
        .insert_raw(IMPORT_IN_PROGRESS_KEY.to_vec(), b"1".to_vec())
        .await?;
    state.config_ks.persist().await?;

    // Clear every backed-up keyspace, then replay.
    for name in keyspaces::BACKED_UP {
        let ks = backed_up_handle(state, name).ok_or_else(|| {
            AppError::Internal(format!("backup: no AppState handle for keyspace '{name}'"))
        })?;
        clear_keyspace(ks).await?;
    }
    for dump in &payload.keyspaces {
        // Ignore a keyspace the dump names but we don't back up (forward
        // compat with a future BACKED_UP addition).
        let Some(ks) = backed_up_handle(state, &dump.name) else {
            continue;
        };
        for (k_b64, v_b64) in &dump.rows {
            let key = BASE64
                .decode(k_b64)
                .map_err(|e| AppError::Validation(format!("backup: bad row key b64: {e}")))?;
            let val = BASE64
                .decode(v_b64)
                .map_err(|e| AppError::Validation(format!("backup: bad row value b64: {e}")))?;
            ks.insert_raw(key, val).await?;
        }
        ks.persist().await?;
    }

    // Restore identity config + the signing key bundle.
    apply_config(
        state,
        secret_store,
        &payload.config,
        payload.key_bundle_hex.as_deref(),
    )
    .await?;

    // Done — clear the sentinel + flush.
    state
        .config_ks
        .remove(IMPORT_IN_PROGRESS_KEY.to_vec())
        .await?;
    state.config_ks.persist().await?;

    Ok(ImportResult {
        status: "imported".into(),
        source_did: payload.config.vtc_did.clone(),
        counts,
        message: "Import complete. Restart the daemon to serve the restored identity.".into(),
    })
}

/// True if a previous import was interrupted before it finished. Boot
/// consults this and refuses to start while it's set (the half-applied
/// state is unsafe to serve). Cleared by a successful re-import.
pub async fn import_in_progress(config_ks: &KeyspaceHandle) -> Result<bool, AppError> {
    Ok(config_ks
        .prefix_iter_raw(IMPORT_IN_PROGRESS_KEY.to_vec())
        .await?
        .iter()
        .any(|(k, _)| k.as_slice() == IMPORT_IN_PROGRESS_KEY))
}

/// `vtc_did` guard — a configured VTC refuses a backup from a different
/// identity; a fresh install accepts anything. Mirrors the VTA's
/// `check_vta_did_compatibility`.
fn check_vtc_did_compatibility(
    running_did: Option<&str>,
    backup_did: Option<&str>,
) -> Result<(), AppError> {
    let running = match running_did {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(()), // fresh install accepts any backup
    };
    let backup = backup_did.unwrap_or("");
    if backup == running {
        return Ok(());
    }
    Err(AppError::Conflict(format!(
        "backup vtc_did mismatch: backup claims '{backup}' but this VTC is running as \
         '{running}'. Refusing to overwrite identity. If this is intentional (identity \
         migration), clear vtc_did from the running config first."
    )))
}

// ── Internals ───────────────────────────────────────────────────────────

/// Map a backed-up keyspace name to its `AppState` handle. Returns
/// `None` for names not in `BACKED_UP`.
fn backed_up_handle<'a>(state: &'a AppState, name: &str) -> Option<&'a KeyspaceHandle> {
    use keyspaces::*;
    Some(match name {
        x if x == ACL => &state.acl_ks,
        x if x == COMMUNITY => &state.community_ks,
        x if x == MEMBERS => &state.members_ks,
        x if x == JOIN_REQUESTS => &state.join_requests_ks,
        x if x == POLICIES => &state.policies_ks,
        x if x == ACTIVE_POLICIES => &state.active_policies_ks,
        x if x == STATUS_LISTS => &state.status_lists_ks,
        x if x == RELATIONSHIPS => &state.relationships_ks,
        x if x == RELATIONSHIPS_BY_DID => &state.relationships_by_did_ks,
        x if x == ENDORSEMENT_TYPES => &state.endorsement_types_ks,
        x if x == SCHEMAS => &state.schemas_ks,
        x if x == ENDORSEMENTS => &state.endorsements_ks,
        x if x == AUDIT => &state.audit_ks,
        x if x == AUDIT_KEY => &state.audit_key_ks,
        _ => return None,
    })
}

/// Remove every row from a keyspace (whole-keyspace clear — VTC
/// keyspaces are single-purpose, unlike the VTA's prefix-shared ones).
async fn clear_keyspace(ks: &KeyspaceHandle) -> Result<(), AppError> {
    let keys: Vec<Vec<u8>> = ks
        .prefix_iter_raw(Vec::<u8>::new())
        .await?
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    for k in keys {
        ks.remove(k).await?;
    }
    Ok(())
}

/// Apply the config snapshot + restore the signing key bundle, then
/// persist `config.toml`.
async fn apply_config(
    state: &AppState,
    secret_store: &dyn SecretStore,
    bc: &BackupConfig,
    key_bundle_hex: Option<&str>,
) -> Result<(), AppError> {
    // Restore the bundle first. The config-secret backend is read-only
    // at runtime (its bytes live inline in config.toml), so for it we
    // write the hex into the config; every other backend takes a `set`.
    if let Some(hex_s) = key_bundle_hex {
        let bundle_bytes = hex::decode(hex_s)
            .map_err(|e| AppError::Validation(format!("backup: bad key_bundle hex: {e}")))?;
        let is_inline = state.config.read().await.secrets.secret.is_some();
        if is_inline {
            state.config.write().await.secrets.secret = Some(hex::encode(&bundle_bytes));
        } else {
            secret_store
                .set(&bundle_bytes)
                .await
                .map_err(|e| AppError::SecretStore(format!("backup: restore key bundle: {e}")))?;
        }
    }

    let mut cfg = state.config.write().await;
    if let Some(v) = &bc.vtc_did {
        cfg.vtc_did = Some(v.clone());
    }
    if let Some(v) = &bc.vtc_name {
        cfg.vtc_name = Some(v.clone());
    }
    if let Some(v) = &bc.vta_did {
        cfg.vta_did = Some(v.clone());
    }
    if let Some(v) = &bc.public_url {
        cfg.public_url = Some(v.clone());
    }
    if bc.messaging.is_some() {
        cfg.messaging = bc.messaging.clone();
    }
    if let Some(v) = &bc.jwt_signing_key {
        cfg.auth.jwt_signing_key = Some(v.clone());
    }
    cfg.save()?;
    Ok(())
}

fn encrypt_payload_inner(
    payload: &BackupPayload,
    password: &str,
    include_audit: bool,
    source_did: Option<String>,
) -> Result<BackupEnvelope, AppError> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|e| AppError::Internal(format!("backup serialize: {e}")))?;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::Internal(format!("backup aes key: {e}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|e| AppError::Internal(format!("backup encrypt: {e}")))?;

    Ok(BackupEnvelope {
        version: VERSION,
        format: FORMAT.into(),
        created_at: Utc::now(),
        source_did,
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

async fn encrypt_payload(
    payload: &BackupPayload,
    password: &str,
    include_audit: bool,
    state: &AppState,
) -> Result<BackupEnvelope, AppError> {
    let source_did = state.config.read().await.vtc_did.clone();
    encrypt_payload_inner(payload, password, include_audit, source_did)
}

/// Decrypt + validate a backup envelope. Wrong password / tamper →
/// `Authentication` (the GCM tag failed).
pub fn decrypt_backup(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<BackupPayload, AppError> {
    if envelope.version != VERSION || envelope.format != FORMAT {
        return Err(AppError::Validation(format!(
            "unsupported backup format: {} v{}",
            envelope.format, envelope.version
        )));
    }
    if envelope.kdf.algorithm != "argon2id" {
        return Err(AppError::Validation(format!(
            "unsupported KDF '{}' (only argon2id)",
            envelope.kdf.algorithm
        )));
    }
    if !(MIN_M_COST..=MAX_M_COST).contains(&envelope.kdf.m_cost) {
        return Err(AppError::Validation(format!(
            "argon2 m_cost {} out of bounds [{MIN_M_COST}, {MAX_M_COST}]",
            envelope.kdf.m_cost
        )));
    }
    if !(MIN_T_COST..=MAX_T_COST).contains(&envelope.kdf.t_cost) {
        return Err(AppError::Validation("argon2 t_cost out of bounds".into()));
    }
    if !(MIN_P_COST..=MAX_P_COST).contains(&envelope.kdf.p_cost) {
        return Err(AppError::Validation("argon2 p_cost out of bounds".into()));
    }
    if envelope.encryption.algorithm != "aes-256-gcm" {
        return Err(AppError::Validation(format!(
            "unsupported cipher '{}' (only aes-256-gcm)",
            envelope.encryption.algorithm
        )));
    }

    let salt = BASE64
        .decode(&envelope.kdf.salt)
        .map_err(|e| AppError::Validation(format!("invalid salt: {e}")))?;
    if salt.len() != SALT_LEN {
        return Err(AppError::Validation(format!(
            "invalid salt length {} (expected {SALT_LEN})",
            salt.len()
        )));
    }
    let nonce_bytes = BASE64
        .decode(&envelope.encryption.nonce)
        .map_err(|e| AppError::Validation(format!("invalid nonce: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(AppError::Validation(format!(
            "invalid nonce length {} (expected {NONCE_LEN})",
            nonce_bytes.len()
        )));
    }
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|e| AppError::Validation(format!("invalid ciphertext: {e}")))?;

    let key = derive_key(
        password,
        &salt,
        envelope.kdf.m_cost,
        envelope.kdf.t_cost,
        envelope.kdf.p_cost,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::Internal(format!("backup aes key: {e}")))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| AppError::Authentication("incorrect backup password".into()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| AppError::Internal(format!("backup payload corrupt: {e}")))
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], AppError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| AppError::Validation(format!("argon2 params: {e}")))?,
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> BackupPayload {
        BackupPayload {
            config: BackupConfig {
                vtc_did: Some("did:webvh:vtc.example.com:abc".into()),
                vtc_name: Some("Acme".into()),
                vta_did: Some("did:webvh:vta.example.com:xyz".into()),
                public_url: Some("https://vtc.example.com".into()),
                messaging: None,
                jwt_signing_key: Some("sign-key".into()),
            },
            key_bundle_hex: Some(hex::encode(b"bundle-bytes")),
            keyspaces: vec![
                KeyspaceDump {
                    name: keyspaces::ACL.into(),
                    rows: vec![(
                        BASE64.encode("acl:did:key:z6Mk"),
                        BASE64.encode(r#"{"r":1}"#),
                    )],
                },
                KeyspaceDump {
                    name: keyspaces::STATUS_LISTS.into(),
                    // a binary-ish value to prove base64 round-trips it
                    rows: vec![(BASE64.encode("sl:0"), BASE64.encode([0u8, 159, 146, 150]))],
                },
            ],
        }
    }

    fn enc(p: &BackupPayload, pw: &str) -> BackupEnvelope {
        encrypt_payload_inner(p, pw, false, p.config.vtc_did.clone()).unwrap()
    }

    #[test]
    fn roundtrip() {
        let p = sample_payload();
        let env = enc(&p, "correct-horse-battery");
        assert_eq!(env.version, 1);
        assert_eq!(env.format, "vtc-backup-v1");
        assert_eq!(env.kdf.algorithm, "argon2id");
        assert_eq!(env.encryption.algorithm, "aes-256-gcm");

        let back = decrypt_backup(&env, "correct-horse-battery").unwrap();
        assert_eq!(back.config.vtc_did, p.config.vtc_did);
        assert_eq!(back.key_bundle_hex, p.key_bundle_hex);
        assert_eq!(back.keyspaces.len(), 2);
        assert_eq!(
            back.keyspaces[1].rows[0].1,
            BASE64.encode([0u8, 159, 146, 150])
        );
    }

    #[test]
    fn wrong_password_fails() {
        let env = enc(&sample_payload(), "the-right-password");
        let err = decrypt_backup(&env, "the-wrong-password").unwrap_err();
        assert!(format!("{err}").contains("incorrect backup password"));
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let mut env = enc(&sample_payload(), "twelve-char-pw!!");
        let mut ct = BASE64.decode(&env.ciphertext).unwrap();
        *ct.last_mut().unwrap() ^= 0xFF;
        env.ciphertext = BASE64.encode(&ct);
        assert!(decrypt_backup(&env, "twelve-char-pw!!").is_err());
    }

    #[test]
    fn rejects_bad_format_and_param_bounds() {
        let good = enc(&sample_payload(), "twelve-char-pw!!");

        let mut bad = good.clone();
        bad.format = "vta-backup-v1".into();
        assert!(decrypt_backup(&bad, "twelve-char-pw!!").is_err());

        let mut bad = good.clone();
        bad.kdf.m_cost = MAX_M_COST + 1;
        assert!(decrypt_backup(&bad, "twelve-char-pw!!").is_err());

        let mut bad = good.clone();
        bad.kdf.algorithm = "scrypt".into();
        assert!(decrypt_backup(&bad, "twelve-char-pw!!").is_err());

        let mut bad = good;
        bad.kdf.salt = BASE64.encode([0u8; 8]); // wrong length
        assert!(decrypt_backup(&bad, "twelve-char-pw!!").is_err());
    }

    #[test]
    fn did_guard_fresh_install_accepts_any() {
        check_vtc_did_compatibility(None, Some("did:key:z6MkAny")).unwrap();
        check_vtc_did_compatibility(Some(""), Some("did:key:z6MkAny")).unwrap();
        check_vtc_did_compatibility(None, None).unwrap();
    }

    #[test]
    fn did_guard_matching_accepted() {
        check_vtc_did_compatibility(Some("did:key:z6MkSame"), Some("did:key:z6MkSame")).unwrap();
    }

    #[test]
    fn did_guard_mismatch_rejected() {
        let err =
            check_vtc_did_compatibility(Some("did:key:z6MkRunning"), Some("did:key:z6MkForeign"))
                .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("vtc_did mismatch"), "{msg}");
        assert!(
            msg.contains("z6MkForeign") && msg.contains("z6MkRunning"),
            "{msg}"
        );
    }
}
