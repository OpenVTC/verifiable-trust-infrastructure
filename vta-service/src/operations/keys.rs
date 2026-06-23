use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use multibase::Base;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tracing::info;
use zeroize::Zeroize;

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody,
    list::ListKeysResultBody,
    rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody,
    secret::GetKeySecretResultBody,
    sign::{SignAlgorithm, SignResultBody},
};

use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::contexts::get_context;
use crate::error::{AppError, key_derivation_error};
use crate::keys::derivation::Bip32Extension;
use crate::keys::imported;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{
    self, KeyOrigin, KeyRecord, KeyStatus, KeyType, encode_private_multibase,
    encode_public_multibase,
};
use crate::store::KeyspaceHandle;

pub struct CreateKeyParams {
    pub key_type: KeyType,
    pub derivation_path: Option<String>,
    pub key_id: Option<String>,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

pub struct ListKeysParams {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<KeyStatus>,
    pub context_id: Option<String>,
}

pub async fn create_key(
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: CreateKeyParams,
    channel: &str,
) -> Result<CreateKeyResultBody, AppError> {
    // Caller-supplied key_ids must stay in the plain-identifier class.
    // VM-shaped ids (`did:...#key-0`) are minted by internal paths only
    // — an API caller who could take one would shadow another DID's
    // verification method in exports and key lookups. The internal
    // default (key_id = derivation path) is exempt: it is not caller
    // input and legitimately contains `/` and `'`.
    if let Some(ref id) = params.key_id {
        vti_common::identifier::validate_identifier("key_id", id)?;
    }

    // Resolve context: explicit > super-admin (None) > single-context default
    let context_id = if let Some(ref ctx) = params.context_id {
        auth.require_context(ctx)?;
        Some(ctx.clone())
    } else if auth.is_super_admin() {
        None
    } else if let Some(ctx) = auth.default_context() {
        Some(ctx.to_string())
    } else {
        return Err(AppError::Forbidden(
            "context_id required: admin has access to multiple contexts".into(),
        ));
    };

    // Resolve derivation path: use explicit value, or auto-derive from context
    let derivation_path = match params.derivation_path {
        Some(path) if !path.is_empty() => path,
        _ => {
            let ctx_id = context_id.as_ref().ok_or_else(|| {
                AppError::Validation(
                    "derivation_path is required when context_id is not provided".into(),
                )
            })?;
            let ctx = get_context(contexts_ks, ctx_id)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("context not found: {ctx_id}")))?;
            allocate_path(keys_ks, &ctx.base_path).await?
        }
    };

    if params.mnemonic.is_some() {
        return Err(AppError::Validation(
            "mnemonic is not accepted via the API — use seed rotation instead".into(),
        ));
    }

    let active_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(keys_ks, &**seed_store, Some(active_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;

    let public_key = match params.key_type {
        KeyType::Ed25519 => {
            let s = bip32.derive_ed25519(&derivation_path)?;
            s.get_public_keymultibase()?
        }
        KeyType::X25519 => {
            let s = bip32.derive_x25519(&derivation_path)?;
            s.get_public_keymultibase()?
        }
        KeyType::P256 => {
            let p256_secret = bip32.derive_p256(&derivation_path)?;
            let verifying_key = p256_secret.secret_key.public_key();
            let encoded = verifying_key.to_encoded_point(true);
            multibase::encode(Base::Base58Btc, encoded.as_bytes())
        }
    };

    let now = Utc::now();
    let key_id = params.key_id.unwrap_or_else(|| derivation_path.clone());

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.clone(),
        key_type: params.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: params.label.clone(),
        context_id: context_id.clone(),
        seed_id: Some(active_id),
        origin: keys::KeyOrigin::Derived,
        created_at: now,
        updated_at: now,
    };

    if !keys_ks
        .insert_if_absent(keys::store_key(&key_id), &record)
        .await?
    {
        return Err(AppError::Conflict(format!(
            "key {key_id} already exists — choose a different key_id, \
             or rename the existing key first"
        )));
    }

    info!(channel, key_id = %key_id, key_type = ?params.key_type, path = %derivation_path, "key created");
    audit!(
        "key.create",
        actor = &auth.did,
        resource = &key_id,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "key.create",
        &auth.did,
        Some(&key_id),
        "success",
        Some(channel),
        context_id.as_deref(),
    )
    .await;

    Ok(CreateKeyResultBody {
        key_id,
        key_type: params.key_type,
        derivation_path,
        public_key,
        status: KeyStatus::Active,
        label: params.label,
        origin: keys::KeyOrigin::Derived,
        created_at: now,
    })
}

// ── Import key ─────────────────────────────────────────────────────

pub struct ImportKeyParams {
    pub key_type: KeyType,
    pub private_key_bytes: Vec<u8>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

pub async fn import_key(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: ImportKeyParams,
    channel: &str,
) -> Result<CreateKeyResultBody, AppError> {
    // Require admin role (stricter than create_key which allows initiator)
    auth.require_admin()?;

    // Resolve context
    let context_id = if let Some(ref ctx) = params.context_id {
        auth.require_context(ctx)?;
        Some(ctx.clone())
    } else if auth.is_super_admin() {
        None
    } else if let Some(ctx) = auth.default_context() {
        Some(ctx.to_string())
    } else {
        return Err(AppError::Forbidden(
            "context_id required: admin has access to multiple contexts".into(),
        ));
    };

    // Validate key bytes and derive public key
    let mut private_bytes = params.private_key_bytes;
    let (public_key, key_type_str) = match params.key_type {
        KeyType::Ed25519 => {
            if private_bytes.len() != 32 {
                return Err(AppError::Validation(format!(
                    "Ed25519 private key must be 32 bytes, got {}",
                    private_bytes.len()
                )));
            }
            let signing_key =
                ed25519_dalek::SigningKey::from_bytes(private_bytes.as_slice().try_into().unwrap());
            let pub_bytes = signing_key.verifying_key().to_bytes();
            let pub_multibase = keys::ed25519_multibase_pubkey(&pub_bytes);
            (pub_multibase, "ed25519")
        }
        KeyType::X25519 => {
            if private_bytes.len() != 32 {
                return Err(AppError::Validation(format!(
                    "X25519 private key must be 32 bytes, got {}",
                    private_bytes.len()
                )));
            }
            let secret_bytes: [u8; 32] = private_bytes.as_slice().try_into().unwrap();
            let secret = x25519_dalek::StaticSecret::from(secret_bytes);
            let public = x25519_dalek::PublicKey::from(&secret);
            let pub_multibase = multibase::encode(Base::Base58Btc, public.as_bytes());
            (pub_multibase, "x25519")
        }
        KeyType::P256 => {
            let secret_key = p256::SecretKey::from_slice(&private_bytes)
                .map_err(|e| AppError::Validation(format!("invalid P-256 private key: {e}")))?;
            let public = secret_key.public_key();
            let encoded = public.to_encoded_point(true);
            let pub_multibase = multibase::encode(Base::Base58Btc, encoded.as_bytes());
            (pub_multibase, "p256")
        }
    };

    let now = Utc::now();
    let key_id = params
        .label
        .clone()
        .unwrap_or_else(|| format!("imported-{}-{}", key_type_str, now.format("%Y%m%d%H%M%S")));

    // A caller-supplied label becomes the key_id, so it must pass the
    // same identifier validation as create_key's key_id (the generated
    // fallback id is already in the allowed class).
    if params.label.is_some() {
        vti_common::identifier::validate_identifier("label (used as key_id)", &key_id)
            .inspect_err(|_| private_bytes.zeroize())?;
    }

    // Claim the key record FIRST: insert_if_absent makes the record the
    // lock on the key_id, so a duplicate import fails here — before it
    // could overwrite the winner's secret ciphertext in store_secret.
    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: String::new(),
        key_type: params.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: params.label.clone(),
        context_id: context_id.clone(),
        seed_id: None,
        origin: KeyOrigin::Imported,
        created_at: now,
        updated_at: now,
    };
    if !keys_ks
        .insert_if_absent(keys::store_key(&key_id), &record)
        .await?
    {
        private_bytes.zeroize();
        return Err(AppError::Conflict(format!(
            "key {key_id} already exists — choose a different label, \
             or rename the existing key first"
        )));
    }

    // Encrypt and store the secret; if any step fails, compensate by
    // removing the record we just claimed so no secret-less record is
    // left behind.
    let stored: Result<(), AppError> = async {
        let active_id = get_active_seed_id(keys_ks)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let seed = load_seed_bytes(keys_ks, &**seed_store, Some(active_id))
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        imported::store_secret(
            imported_ks,
            keys_ks,
            &seed,
            &key_id,
            key_type_str,
            &private_bytes,
        )
        .await
    }
    .await;

    // Zeroize private key material
    private_bytes.zeroize();

    if let Err(e) = stored {
        let _ = keys_ks.remove(keys::store_key(&key_id)).await;
        return Err(e);
    }

    info!(channel, key_id = %key_id, key_type = ?params.key_type, "key imported");
    audit!(
        "key.import",
        actor = &auth.did,
        resource = &key_id,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "key.import",
        &auth.did,
        Some(&key_id),
        "success",
        Some(channel),
        context_id.as_deref(),
    )
    .await;

    Ok(CreateKeyResultBody {
        key_id,
        key_type: params.key_type,
        derivation_path: String::new(),
        public_key,
        status: KeyStatus::Active,
        label: params.label,
        origin: KeyOrigin::Imported,
        created_at: now,
    })
}

pub async fn get_key(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<KeyRecord, AppError> {
    // Role floor: Monitor-role principals (intended for metrics / health
    // only) must not be able to read key records, even when the context
    // checks below would pass. Belongs at the top of the function so
    // both REST and DIDComm callers hit it.
    auth.require_read()?;

    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can access keys without a context".into(),
        ));
    }

    info!(channel, key_id = %key_id, "key retrieved");
    Ok(record)
}

pub async fn list_keys(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: ListKeysParams,
    channel: &str,
) -> Result<ListKeysResultBody, AppError> {
    // Role floor: Monitor-role principals must not enumerate key
    // records. Per-record context filtering below is a *visibility*
    // filter, not an authorization gate; the gate is here.
    auth.require_read()?;

    let raw = keys_ks.prefix_iter_raw("key:").await?;

    let mut records: Vec<KeyRecord> = Vec::with_capacity(raw.len());
    let mut skipped = 0usize;
    for (key, value) in raw {
        // Skip (don't abort on) a corrupt row: one undeserializable key
        // record must not break key listing for every other key.
        let record: KeyRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(e) => {
                skipped += 1;
                tracing::warn!(
                    key = %String::from_utf8_lossy(&key),
                    error = %e,
                    "skipping undeserializable key row in list_keys"
                );
                continue;
            }
        };
        if let Some(ref status) = params.status
            && record.status != *status
        {
            continue;
        }
        if let Some(ref ctx) = params.context_id
            && record.context_id.as_deref() != Some(ctx.as_str())
        {
            continue;
        }
        if !auth.is_super_admin() {
            match record.context_id {
                Some(ref ctx) if auth.has_context_access(ctx) => {}
                _ => continue,
            }
        }
        records.push(record);
    }
    if skipped > 0 {
        tracing::warn!(channel, skipped, "list_keys skipped corrupt rows");
    }

    let total = records.len() as u64;
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50);

    let page: Vec<KeyRecord> = records
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    info!(channel, caller = %auth.did, count = page.len(), total, "keys listed");

    Ok(ListKeysResultBody {
        keys: page,
        total,
        offset,
        limit,
    })
}

pub async fn rename_key(
    keys_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    new_key_id: &str,
    channel: &str,
) -> Result<RenameKeyResultBody, AppError> {
    // Same identifier class as create_key's key_id: rename must not be
    // a back door into VM-shaped or namespace-colliding names.
    vti_common::identifier::validate_identifier("new_key_id", new_key_id)?;

    let old_store_key = keys::store_key(key_id);

    let mut record: KeyRecord = keys_ks
        .get(old_store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can rename keys without a context".into(),
        ));
    }

    let new_store_key = keys::store_key(new_key_id);
    record.key_id = new_key_id.to_string();
    record.updated_at = Utc::now();

    if !keys_ks.swap(old_store_key, new_store_key, &record).await? {
        return Err(AppError::Conflict(format!(
            "key {new_key_id} already exists"
        )));
    }

    info!(channel, old_id = %key_id, new_id = %new_key_id, "key renamed");
    audit!(
        "key.rename",
        actor = &auth.did,
        resource = new_key_id,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "key.rename",
        &auth.did,
        Some(new_key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(RenameKeyResultBody {
        key_id: new_key_id.to_string(),
        updated_at: record.updated_at,
    })
}

pub async fn revoke_key(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<RevokeKeyResultBody, AppError> {
    let store_key = keys::store_key(key_id);

    let mut record: KeyRecord = keys_ks
        .get(store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can revoke keys without a context".into(),
        ));
    }

    if record.status == KeyStatus::Revoked {
        return Err(AppError::Conflict(format!(
            "key {key_id} is already revoked"
        )));
    }

    // Secure deletion for imported keys: destroy the encrypted secret
    if record.origin == KeyOrigin::Imported {
        imported::delete_secret(imported_ks, key_id).await?;
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    keys_ks.insert(store_key, &record).await?;

    info!(channel, key_id = %key_id, "key revoked");
    audit!(
        "key.revoke",
        actor = &auth.did,
        resource = key_id,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "key.revoke",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(RevokeKeyResultBody {
        key_id: key_id.to_string(),
        status: record.status,
        updated_at: record.updated_at,
    })
}

pub async fn get_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<GetKeySecretResultBody, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can access keys without a context".into(),
        ));
    }

    let (public_key_multibase, private_key_multibase) = match record.origin {
        KeyOrigin::Imported => {
            // Decrypt from imported_secrets keyspace
            let seed = load_seed_bytes(keys_ks, &**seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;
            let priv_mb = encode_private_multibase(&record.key_type, &secret_bytes);
            secret_bytes.zeroize();
            (record.public_key.clone(), priv_mb)
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, &**seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
                key_derivation_error(format!("failed to create BIP-32 root key: {e}"))
            })?;

            match record.key_type {
                KeyType::Ed25519 => {
                    let secret = bip32.derive_ed25519(&record.derivation_path)?;
                    (
                        secret.get_public_keymultibase()?,
                        secret.get_private_keymultibase()?,
                    )
                }
                KeyType::X25519 => {
                    let secret = bip32.derive_x25519(&record.derivation_path)?;
                    (
                        secret.get_public_keymultibase()?,
                        secret.get_private_keymultibase()?,
                    )
                }
                KeyType::P256 => {
                    let p256_secret = bip32.derive_p256(&record.derivation_path)?;
                    let public_key = p256_secret.secret_key.public_key();
                    let encoded = public_key.to_encoded_point(true);
                    let pub_mb = encode_public_multibase(&KeyType::P256, encoded.as_bytes());
                    let priv_mb = encode_private_multibase(
                        &KeyType::P256,
                        &p256_secret.secret_key.to_bytes(),
                    );
                    (pub_mb, priv_mb)
                }
            }
        }
    };

    info!(channel, key_id = %key_id, "key secret retrieved");
    audit!(
        "key.secret_export",
        actor = &auth.did,
        resource = key_id,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "key.secret_export",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase,
        private_key_multibase,
    })
}

/// Internal-authority variant of [`get_key_secret`] that bypasses the
/// `auth.require_context` / `auth.is_super_admin` gates.
///
/// Required because the provision-integration flow needs to load the
/// VTA's own signing material (`{vta_did}#key-0`,
/// `{vta_did}#sealed-transfer-0`) to issue VCs and sign producer
/// assertions; those keys are server-internal, not user-attributable.
/// The user-facing caller has already been authorised upstream as a
/// context admin at precondition time.
///
/// Construction of [`InternalAuthority`](super::internal_authority::InternalAuthority)
/// is `pub(super)` to the `operations` module — route handlers cannot
/// reach it. Each elevation
/// thus has to come from the operations layer with an explicit purpose
/// tag, which is logged as the audit actor.
pub async fn get_key_secret_internal(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit_ks: &KeyspaceHandle,
    authority: super::internal_authority::InternalAuthority,
    key_id: &str,
    channel: &str,
) -> Result<GetKeySecretResultBody, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    // Deliberately no `auth.require_context` / `is_super_admin` gate —
    // possessing an `InternalAuthority` IS the gate.

    let (public_key_multibase, private_key_multibase) = match record.origin {
        KeyOrigin::Imported => {
            let seed = load_seed_bytes(keys_ks, seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;
            let priv_mb = encode_private_multibase(&record.key_type, &secret_bytes);
            secret_bytes.zeroize();
            (record.public_key.clone(), priv_mb)
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
                key_derivation_error(format!("failed to create BIP-32 root key: {e}"))
            })?;

            match record.key_type {
                KeyType::Ed25519 => {
                    let secret = bip32.derive_ed25519(&record.derivation_path)?;
                    (
                        secret.get_public_keymultibase()?,
                        secret.get_private_keymultibase()?,
                    )
                }
                KeyType::X25519 => {
                    let secret = bip32.derive_x25519(&record.derivation_path)?;
                    (
                        secret.get_public_keymultibase()?,
                        secret.get_private_keymultibase()?,
                    )
                }
                KeyType::P256 => {
                    let p256_secret = bip32.derive_p256(&record.derivation_path)?;
                    let public_key = p256_secret.secret_key.public_key();
                    let encoded = public_key.to_encoded_point(true);
                    let pub_mb = encode_public_multibase(&KeyType::P256, encoded.as_bytes());
                    let priv_mb = encode_private_multibase(
                        &KeyType::P256,
                        &p256_secret.secret_key.to_bytes(),
                    );
                    (pub_mb, priv_mb)
                }
            }
        }
    };

    let actor = authority.audit_actor();
    info!(channel, key_id = %key_id, actor = %actor, "key secret retrieved (internal)");
    audit!(
        "key.secret_export",
        actor = &actor,
        resource = key_id,
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "key.secret_export",
        &actor,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase,
        private_key_multibase,
    })
}

/// Sign a payload using a VTA-managed key.
///
/// For derived keys, re-derives from BIP-32 seed. For imported keys,
/// decrypts from the imported_secrets keyspace. Key material is zeroized
/// after signing.
#[allow(clippy::too_many_arguments)]
pub async fn sign_payload(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    key_id: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    channel: &str,
) -> Result<SignResultBody, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(
            "cannot sign with a revoked key".into(),
        ));
    }

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
        // Context policy is a resource-bound guardrail: it constrains the key's
        // context regardless of the actor — even the super-admin. This is what
        // lets a higher authority (e.g. a VTC/fleet-pushed policy) or the
        // owner's own policy bind every signer; the owner relaxes it via policy
        // CRUD, never by bypassing it here. Resolved across the whole ancestor
        // chain, so a child context can only narrow the set, never widen it. An
        // unscoped key (no context) has no policy and is naturally unrestricted
        // (and super-admin-only, gated below).
        let policy = crate::contexts::effective_context_policy(contexts_ks, ctx).await?;
        if !policy.allows_signing_key(key_id) {
            return Err(AppError::Forbidden(format!(
                "signing key {key_id} is not permitted by the policy of context {ctx}"
            )));
        }
        if let Some(limit) = policy.quota_for("sign") {
            crate::contexts::enforce_daily_quota(contexts_ks, ctx, "sign", limit).await?;
        }
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can use unscoped keys".into(),
        ));
    }

    let signature_bytes = match record.origin {
        KeyOrigin::Imported => {
            // Decrypt imported secret and sign
            let seed = load_seed_bytes(keys_ks, &**seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;

            let sig = match (algorithm, &record.key_type) {
                (SignAlgorithm::EdDSA, KeyType::Ed25519) => {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(
                        secret_bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| AppError::Internal("invalid Ed25519 key length".into()))?,
                    );
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
                (SignAlgorithm::ES256, KeyType::P256) => {
                    let secret_key = p256::SecretKey::from_slice(&secret_bytes)
                        .map_err(|e| AppError::Internal(format!("invalid P-256 key: {e}")))?;
                    let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    secret_bytes.zeroize();
                    return Err(AppError::Validation(format!(
                        "algorithm {} incompatible with key type {}",
                        algorithm, record.key_type
                    )));
                }
            };
            secret_bytes.zeroize();
            sig
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, &**seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
                key_derivation_error(format!("failed to create BIP-32 root key: {e}"))
            })?;

            match (algorithm, &record.key_type) {
                (SignAlgorithm::EdDSA, KeyType::Ed25519) => {
                    let derivation_path: ed25519_dalek_bip32::DerivationPath =
                        record.derivation_path.parse().map_err(|e| {
                            key_derivation_error(format!("invalid derivation path: {e}"))
                        })?;
                    let derived = bip32
                        .derive(&derivation_path)
                        .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;
                    let signing_key =
                        ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
                (SignAlgorithm::ES256, KeyType::P256) => {
                    let p256_secret = bip32.derive_p256(&record.derivation_path)?;
                    let signing_key = p256::ecdsa::SigningKey::from(&p256_secret.secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    return Err(AppError::Validation(format!(
                        "algorithm {} incompatible with key type {}",
                        algorithm, record.key_type
                    )));
                }
            }
        }
    };

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    info!(channel, key_id = %key_id, "payload signed");

    Ok(SignResultBody {
        key_id: key_id.to_string(),
        signature,
        algorithm: algorithm.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use vti_common::acl::Role;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    use crate::auth::AuthClaims;
    use crate::contexts::create_context;
    use crate::keys::seed_store::SeedStore;

    /// A mock seed store backed by a Mutex so `set` actually persists.
    struct MockSeedStore(Mutex<Option<Vec<u8>>>);

    impl SeedStore for MockSeedStore {
        fn get(
            &self,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<Vec<u8>>, crate::error::AppError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(self.0.lock().await.clone()) })
        }
        fn set(
            &self,
            seed: &[u8],
        ) -> Pin<
            Box<dyn std::future::Future<Output = Result<(), crate::error::AppError>> + Send + '_>,
        > {
            let seed = seed.to_vec();
            Box::pin(async move {
                *self.0.lock().await = Some(seed);
                Ok(())
            })
        }
    }

    /// Helper: open a temp store and return the keyspace handles needed by key operations.
    struct TestHarness {
        keys_ks: KeyspaceHandle,
        contexts_ks: KeyspaceHandle,
        audit_ks: KeyspaceHandle,
        imported_ks: KeyspaceHandle,
        seed_store: Arc<dyn SeedStore>,
        _dir: tempfile::TempDir,
    }

    impl TestHarness {
        async fn new() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let store_config = StoreConfig {
                data_dir: dir.path().to_path_buf(),
            };
            let store = Store::open(&store_config).expect("open store");

            let keys_ks = store.keyspace(crate::keyspaces::KEYS).unwrap();
            let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
            let audit_ks = store.keyspace(crate::keyspaces::AUDIT).unwrap();
            let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS).unwrap();

            // 32-byte seed; will be expanded to 64 bytes by BIP-32 internally
            let seed_store: Arc<dyn SeedStore> =
                Arc::new(MockSeedStore(Mutex::new(Some(vec![0xABu8; 32]))));

            // Create a test context so create_key can resolve it
            create_context(&contexts_ks, "test-ctx", "Test Context")
                .await
                .expect("create context");

            Self {
                keys_ks,
                contexts_ks,
                audit_ks,
                imported_ks,
                seed_store,
                _dir: dir,
            }
        }

        fn super_admin_auth(&self) -> AuthClaims {
            AuthClaims {
                did: "did:key:z6MkTestAdmin".to_string(),
                role: Role::Admin,
                allowed_contexts: vec![], // empty = super admin
                session_id: "test-session".into(),
                access_expires_at: 0,
                amr: Vec::new(),
                acr: String::new(),
            }
        }
    }

    #[tokio::test]
    async fn create_key_refuses_to_overwrite_existing_record() {
        // Reproduces the silent-overwrite hole: a second create with the
        // same key_id (e.g. naming a key after the VTA's own signing key)
        // must Conflict and leave the original record untouched.
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        let victim = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("victim-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("first create succeeds");

        let err = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/2'/0'/7'".into()),
                key_id: Some("victim-key".into()),
                mnemonic: None,
                label: Some("attacker remap".into()),
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect_err("duplicate key_id must be refused");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");

        let record: KeyRecord = h
            .keys_ks
            .get(keys::store_key("victim-key"))
            .await
            .unwrap()
            .expect("victim record still present");
        assert_eq!(record.public_key, victim.public_key);
        assert_eq!(record.derivation_path, victim.derivation_path);
        assert_eq!(record.label, None, "attacker's label must not land");
    }

    #[tokio::test]
    async fn create_key_rejects_separator_shaped_key_id() {
        // Caller-supplied key_ids must not be able to take VM-shaped or
        // namespace-colliding names; those are minted by internal paths
        // only. Kid shapes (`did:...#key-0`) are the concrete attack.
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        for bad in ["did:web:example.com#key-0", "key:sneaky", "a/b", "x y"] {
            let err = create_key(
                &h.keys_ks,
                &h.contexts_ks,
                &h.seed_store,
                &h.audit_ks,
                &auth,
                CreateKeyParams {
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: Some(bad.into()),
                    mnemonic: None,
                    label: None,
                    context_id: Some("test-ctx".into()),
                },
                "test",
            )
            .await
            .expect_err("separator-shaped key_id must be rejected");
            assert!(matches!(err, AppError::Validation(_)), "{bad}: {err:?}");
        }
    }

    #[tokio::test]
    async fn import_key_refuses_duplicate_key_id() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        let first = import_key(
            &h.keys_ks,
            &h.imported_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            ImportKeyParams {
                key_type: KeyType::Ed25519,
                private_key_bytes: vec![0x11u8; 32],
                label: Some("shared-name".into()),
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("first import succeeds");

        let err = import_key(
            &h.keys_ks,
            &h.imported_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            ImportKeyParams {
                key_type: KeyType::Ed25519,
                private_key_bytes: vec![0x22u8; 32],
                label: Some("shared-name".into()),
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect_err("duplicate import key_id must be refused");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");

        // The winner's record AND secret must be intact: the loser must
        // not have overwritten the stored ciphertext before failing.
        let record: KeyRecord = h
            .keys_ks
            .get(keys::store_key("shared-name"))
            .await
            .unwrap()
            .expect("first import's record still present");
        assert_eq!(record.public_key, first.public_key);
        let active_id = get_active_seed_id(&h.keys_ks).await.unwrap();
        let seed = load_seed_bytes(&h.keys_ks, &*h.seed_store, Some(active_id))
            .await
            .unwrap();
        let secret =
            imported::load_secret(&h.imported_ks, &h.keys_ks, &seed, "shared-name", "ed25519")
                .await
                .expect("first import's secret still decryptable");
        assert_eq!(secret.as_slice(), &[0x11u8; 32]);
    }

    #[tokio::test]
    async fn rename_key_rejects_separator_shaped_new_key_id() {
        // rename is the other wire path that takes a caller-supplied id;
        // it must not be a bypass around create_key's validation.
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("plain-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create succeeds");

        let err = rename_key(
            &h.keys_ks,
            &h.audit_ks,
            &auth,
            "plain-key",
            "did:web:example.com#key-0",
            "test",
        )
        .await
        .expect_err("VM-shaped rename target must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");

        let still_there: Option<KeyRecord> =
            h.keys_ks.get(keys::store_key("plain-key")).await.unwrap();
        assert!(still_there.is_some(), "record must remain at the old id");
    }

    #[tokio::test]
    async fn import_key_rejects_separator_shaped_label_as_key_id() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        let err = import_key(
            &h.keys_ks,
            &h.imported_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            ImportKeyParams {
                key_type: KeyType::Ed25519,
                private_key_bytes: vec![0x11u8; 32],
                label: Some("evil:label".into()),
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect_err("label used as key_id must pass identifier validation");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn test_create_key_ed25519() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        let result = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("test-ed25519".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create_key should succeed");

        assert_eq!(result.key_type, KeyType::Ed25519);
        assert_eq!(result.status, KeyStatus::Active);
        assert!(
            !result.public_key.is_empty(),
            "public_key must be non-empty"
        );
        assert_eq!(result.key_id, "test-ed25519");
    }

    #[tokio::test]
    async fn test_create_key_p256() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        let result = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::P256,
                derivation_path: None,
                key_id: Some("test-p256".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create_key should succeed");

        assert_eq!(result.key_type, KeyType::P256);
        assert_eq!(result.status, KeyStatus::Active);
        assert!(
            !result.public_key.is_empty(),
            "public_key must be non-empty"
        );
        assert_eq!(result.key_id, "test-p256");
    }

    #[tokio::test]
    async fn test_sign_and_verify_ed25519() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();

        // First create a key
        let key = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("sign-test-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create_key should succeed");

        // Sign a payload
        let payload = b"hello world";
        let result = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.seed_store,
            &auth,
            &key.key_id,
            payload,
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("sign_payload should succeed");

        assert_eq!(result.key_id, "sign-test-key");
        assert_eq!(result.algorithm, SignAlgorithm::EdDSA);
        // Verify the signature is valid base64url
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&result.signature)
            .expect("signature should be valid base64url");
        assert!(!decoded.is_empty(), "decoded signature must be non-empty");
        // Ed25519 signatures are 64 bytes
        assert_eq!(decoded.len(), 64, "Ed25519 signature should be 64 bytes");
    }

    /// Context policy gates the signing oracle as a *resource-bound* guardrail:
    /// the key's context policy binds every signer — a context-scoped actor and
    /// the super-admin alike — while a key the policy permits still signs.
    #[tokio::test]
    async fn sign_payload_honours_context_policy_signable_keys() {
        use crate::contexts::{ContextRecord, store_context};
        use vta_sdk::context_policy::ContextPolicy;

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // A context whose policy only permits a *different* key id.
        let now = chrono::Utc::now();
        store_context(
            &h.contexts_ks,
            &ContextRecord {
                id: "locked-ctx".into(),
                name: "locked".into(),
                did: None,
                description: None,
                parent: None,
                base_path: "m/26'/2'/9'".into(),
                index: 9,
                created_at: now,
                updated_at: now,
                context_policy: Some(ContextPolicy {
                    signable_keys: Some(["allowed-key".to_string()].into_iter().collect()),
                    ..ContextPolicy::unrestricted()
                }),
            },
        )
        .await
        .expect("store locked-ctx");

        let key = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("blocked-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("locked-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create_key");

        // A context-scoped actor is denied: blocked-key is not in the allow-list.
        let scoped = AuthClaims {
            did: "did:key:z6MkScopedStaff".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["locked-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.seed_store,
            &scoped,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "context-scoped sign of a non-allowed key must be Forbidden, got {denied:?}"
        );

        // Resource-bound: even the super-admin is gated by the key's context
        // policy. (The owner relaxes it via policy CRUD, not by bypassing here.)
        let denied_admin = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.seed_store,
            &admin,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await;
        assert!(
            matches!(denied_admin, Err(crate::error::AppError::Forbidden(_))),
            "super-admin is also bound by the key's context policy, got {denied_admin:?}"
        );

        // A key the policy *does* permit signs fine for the scoped actor.
        let allowed = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("allowed-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("locked-ctx".into()),
            },
            "test",
        )
        .await
        .expect("create allowed-key");
        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.seed_store,
            &scoped,
            &allowed.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("policy permits allowed-key");
    }

    /// Regression test for the missing role floor on `get_key` /
    /// `list_keys`. A Monitor-role caller (intended for metrics +
    /// health endpoints only) must not be able to read key records,
    /// even when context filtering would otherwise let them through.
    #[tokio::test]
    async fn get_key_and_list_keys_reject_monitor_role() {
        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // Plant a key under test-ctx so there's something to read.
        let key = create_key(
            &h.keys_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("monitor-floor-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("seed key");

        // Monitor role with the same context scope still must be refused
        // by the role floor — the floor sits above the per-record context
        // check intentionally so DIDComm callers hit it too.
        let monitor = AuthClaims {
            did: "did:key:zMonitor".into(),
            role: Role::Monitor,
            allowed_contexts: vec!["test-ctx".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };

        let get_err = get_key(&h.keys_ks, &monitor, &key.key_id, "test")
            .await
            .expect_err("monitor must not get_key");
        assert!(
            matches!(get_err, AppError::Forbidden(_)),
            "expected Forbidden, got {get_err:?}"
        );

        let list_err = list_keys(
            &h.keys_ks,
            &monitor,
            ListKeysParams {
                status: None,
                context_id: None,
                offset: None,
                limit: None,
            },
            "test",
        )
        .await
        .expect_err("monitor must not list_keys");
        assert!(
            matches!(list_err, AppError::Forbidden(_)),
            "expected Forbidden, got {list_err:?}"
        );

        // Sanity check: a Reader-role caller in the same context CAN
        // read — the floor is "at least Reader", not "Admin only".
        let reader = AuthClaims {
            did: "did:key:zReader".into(),
            role: Role::Reader,
            allowed_contexts: vec!["test-ctx".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        get_key(&h.keys_ks, &reader, &key.key_id, "test")
            .await
            .expect("reader-role caller can get_key");
    }
}
