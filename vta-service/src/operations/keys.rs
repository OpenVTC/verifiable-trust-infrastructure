use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use base64::Engine;
use chrono::Utc;
use multibase::Base;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tracing::info;
use zeroize::Zeroize;

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody,
    derive_and_sign::DeriveAndSignResultBody,
    derive_and_sign_document::DeriveAndSignDocumentResultBody,
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
    /// Mint a **non-extractable internal key** instead of a BIP-32 derived one.
    ///
    /// The key is generated from the system CSPRNG, has no derivation path,
    /// and **cannot be recovered by any means** — not from the mnemonic, not
    /// from a backup. Losing it loses every signature it was the sole authority
    /// for, permanently. Callers must surface that to an operator before
    /// setting this; the CLI requires an explicit confirmation.
    pub internal: bool,
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

/// Mint a non-extractable internal key.
///
/// Split out of [`create_key`] rather than branched inline because the two
/// share almost nothing: this path loads no seed, builds no BIP-32 root, and
/// records no derivation path. Every one of those absences is deliberate — a
/// derivation path would be a reconstruction route, and the origin's whole
/// value is that none exists.
#[allow(clippy::too_many_arguments)]
async fn create_internal_key(
    keys_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: CreateKeyParams,
    context_id: Option<String>,
    channel: &str,
) -> Result<CreateKeyResultBody, AppError> {
    let key_id = params.key_id.clone().ok_or_else(|| {
        AppError::Validation(
            "an internal key needs an explicit key_id: it has no derivation path to \
             name it after"
                .into(),
        )
    })?;

    if keys_ks
        .get::<KeyRecord>(keys::store_key(&key_id))
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!("key `{key_id}` already exists")));
    }

    let key_type = params.key_type.clone();
    let label = params.label.clone();
    let public = vta_keys::internal::generate(internal_ks, &key_id, key_type.clone()).await?;
    let public_key = encode_public_multibase(&key_type, &public);

    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.clone(),
        // Deliberately not a BIP-32 path. It names the origin instead, so a
        // reader of the record cannot mistake it for something re-derivable.
        derivation_path: "internal".to_string(),
        key_type: key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: label.clone(),
        context_id: context_id.clone(),
        // No seed is involved, so there is no seed generation to pin to.
        seed_id: None,
        origin: keys::KeyOrigin::Internal,
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(keys::store_key(&key_id), &record).await?;

    let _ = audit::record(
        audit_ks,
        "key.create.internal",
        &auth.did,
        Some(&key_id),
        "success",
        Some(channel),
        context_id.as_deref(),
    )
    .await;

    Ok(CreateKeyResultBody {
        key_id,
        key_type,
        derivation_path: "internal".to_string(),
        public_key,
        status: KeyStatus::Active,
        label,
        origin: keys::KeyOrigin::Internal,
        created_at: now,
    })
}

pub async fn create_key(
    keys_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
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

    // Internal keys short-circuit here, before any derivation-path resolution:
    // they load no seed, build no BIP-32 root, and record no path, because each
    // of those would be the reconstruction route the origin exists to deny.
    if params.internal {
        return create_internal_key(
            keys_ks,
            internal_ks,
            audit_ks,
            auth,
            params,
            context_id,
            channel,
        )
        .await;
    }

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
    let bip32 = vti_common::slip10::ExtendedSigningKey::from_seed(&seed)
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

    // The guarantee, enforced before any authorization check so it cannot be
    // reasoned around: an internal key is never exported, to anybody, at any
    // role. Admin is not a bypass — the whole point of the origin is that no
    // caller has this power, so treating it as a permission question would be
    // the wrong shape.
    if record.origin == KeyOrigin::Internal {
        return Err(AppError::Forbidden(format!(
            "key `{key_id}` is an internal key: its material is generated from the \
             system CSPRNG, is not derived from the master seed, and is never \
             exported by any surface. Use the signing oracle instead — and note \
             that an internal key cannot be recovered if lost"
        )));
    }

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

    // Internal keys are refused here too. `InternalAuthority` bypasses the ACL,
    // not the non-extractability guarantee — an internal key has no export
    // surface at all, and an internal caller wanting a signature must go
    // through the signing oracle like everyone else.
    if record.origin == KeyOrigin::Internal {
        return Err(AppError::Forbidden(format!(
            "key `{key_id}` is an internal key and is never exported, including \
             under internal authority"
        )));
    }

    let (public_key_multibase, private_key_multibase) = match record.origin {
        // Unreachable: the early return above refuses internal keys. Kept as a
        // second, local refusal so deleting that guard cannot quietly turn this
        // match into an export path for them.
        KeyOrigin::Internal => {
            return Err(AppError::Forbidden(format!(
                "key `{key_id}` is an internal key and is never exported"
            )));
        }
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
            let bip32 = vti_common::slip10::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
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
        // Unreachable: the early return above refuses internal keys. Kept as a
        // second, local refusal so deleting that guard cannot quietly turn this
        // match into an export path for them.
        KeyOrigin::Internal => {
            return Err(AppError::Forbidden(format!(
                "key `{key_id}` is an internal key and is never exported"
            )));
        }
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
            let bip32 = vti_common::slip10::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
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

/// Gate 4 of [`sign_payload`] (#818): the **actor-scoped** key filter.
///
/// Loads the caller's stored ACL row and asks its [`KeyScope`] whether
/// `key_id` is within the entry's `allowed_keys`. Complements the
/// resource-bound `ContextPolicy.signable_keys` (which binds every actor,
/// super-admin included); this one binds *this caller*, and only ever
/// narrows what the context gates already allowed.
///
/// Reads the store rather than the JWT deliberately: an operator narrowing
/// an entry's `allowed_keys` is a privilege reduction, and reading the row
/// live means the reduction binds the subject's **next** sign request — no
/// session revocation, no waiting out an access-token TTL (the trap the
/// VTC's `is_privilege_reduction` path exists to close for claims-borne
/// authority).
///
/// A caller with **no ACL row** passes: the only callers that reach here
/// without one are process-local synthesized identities (the offline CLI's
/// `cli:<channel>` sentinel), whose trust boundary is the OS, and a row
/// deleted mid-session — for whom this preserves today's behaviour exactly
/// (`None` on every existing row is byte-identical, and absence of a row
/// carries no `allowed_keys` to enforce). The decode goes through
/// [`AclEntry::key_scope`], never a bare emptiness test: `Some(∅)` means
/// authorized on **no** keys, the opposite of `None`.
///
/// [`KeyScope`]: vti_common::acl::KeyScope
/// [`AclEntry::key_scope`]: vti_common::acl::AclEntry::key_scope
async fn require_key_in_caller_scope(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
) -> Result<(), AppError> {
    let Some(entry) = vti_common::acl::get_acl_entry(acl_ks, &auth.did).await? else {
        return Ok(());
    };
    if entry.key_scope().allows(key_id) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "signing key {key_id} is not in the caller's allowed keys"
    )))
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
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
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
        // Gate 4 (#818) — the caller's own ACL row may narrow which key ids
        // it can invoke the oracle on. Runs strictly AFTER `require_context`,
        // so a caller can never reach (or learn about) a key outside its
        // contexts by naming it here — the filter intersects with the context
        // scope, never widens it. Placed BEFORE the policy quota so a refused
        // call burns none of the context's daily sign budget.
        require_key_in_caller_scope(acl_ks, auth, key_id).await?;
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
    } else {
        if !auth.is_super_admin() {
            return Err(AppError::Forbidden(
                "only super admin can use unscoped keys".into(),
            ));
        }
        // Gate 4 applies to unscoped keys too: the filter can only ever
        // *narrow* whatever the context dimension allowed, and a super-admin
        // whose entry names specific keys asked to be bound to them.
        require_key_in_caller_scope(acl_ks, auth, key_id).await?;
    }

    let signature_bytes = match record.origin {
        // The one place internal key material is used. It never leaves this
        // call: `vta_keys::internal::sign` loads, signs, and zeroizes without
        // returning the secret to any caller.
        KeyOrigin::Internal => {
            let expected = matches!(
                (algorithm, &record.key_type),
                (SignAlgorithm::EdDSA, KeyType::Ed25519) | (SignAlgorithm::ES256, KeyType::P256)
            );
            if !expected {
                return Err(AppError::Validation(format!(
                    "algorithm {} incompatible with key type {}",
                    algorithm, record.key_type
                )));
            }
            vta_keys::internal::sign(internal_ks, key_id, payload).await?
        }
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
            let bip32 = vti_common::slip10::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
                key_derivation_error(format!("failed to create BIP-32 root key: {e}"))
            })?;

            match (algorithm, &record.key_type) {
                (SignAlgorithm::EdDSA, KeyType::Ed25519) => {
                    let derivation_path: vti_common::slip10::DerivationPath =
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

/// Ephemeral derive-and-sign: derive an Ed25519 key at `derivation_path` from
/// the VTA's seed, sign `payload`, and return `{ public_key, signature }`
/// **without persisting a `KeyRecord`**.
///
/// This is the signing oracle that lets a fleet manager (whose fleet seed *is*
/// this VTA's seed, ideally TEE-sealed) act as any derived child identity — e.g.
/// a per-VTA super-admin at `m/26'/9'/<idx>'` — so the seed never leaves the
/// VTA. **Admin-gated** (the strictest gate, like `create_key`): the caller can
/// derive + sign as *any* path, so it must be a fully-trusted admin.
pub async fn derive_and_sign(
    keys_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    key_type: &KeyType,
    derivation_path: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    channel: &str,
) -> Result<DeriveAndSignResultBody, AppError> {
    auth.require_admin()?;

    if !matches!(
        (algorithm, key_type),
        (SignAlgorithm::EdDSA, KeyType::Ed25519)
    ) {
        return Err(AppError::Validation(format!(
            "derive-and-sign currently supports only EdDSA/Ed25519 (got {algorithm}/{key_type:?})"
        )));
    }

    let seed = load_seed_bytes(keys_ks, &**seed_store, None)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = vti_common::slip10::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;
    let path: vti_common::slip10::DerivationPath = derivation_path
        .parse()
        .map_err(|e| key_derivation_error(format!("invalid derivation path: {e}")))?;
    let derived = bip32
        .derive(&path)
        .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());
    let public_key =
        encode_public_multibase(&KeyType::Ed25519, signing_key.verifying_key().as_bytes());

    use ed25519_dalek::Signer;
    let signature_bytes = signing_key.sign(payload).to_bytes().to_vec();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    info!(
        channel,
        derivation_path = %derivation_path,
        "ephemeral derive-and-sign (no key record persisted)"
    );

    Ok(DeriveAndSignResultBody {
        public_key,
        signature,
        algorithm: algorithm.clone(),
    })
}

/// Derive an Ed25519 key at `derivation_path` and attach an `eddsa-jcs-2022`
/// Data-Integrity proof to `document`, signed **as the derived key**, persisting
/// no key record. The DI-signing counterpart of [`derive_and_sign`].
///
/// Uses the same `DataIntegrityProof::sign` the VTA uses to issue VCs, so the
/// proof is correct-by-construction for any `affinidi-data-integrity` verifier.
/// This is how a fleet manager has its fleet VTA sign an `auth/authenticate/0.1`
/// document as a per-VTA super-admin (`m/26'/9'/<idx>'`) — the seed never leaves
/// the VTA. **Admin-gated.**
pub async fn derive_and_sign_document(
    keys_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    key_type: &KeyType,
    derivation_path: &str,
    mut document: serde_json::Value,
    proof_purpose: Option<&str>,
    channel: &str,
) -> Result<DeriveAndSignDocumentResultBody, AppError> {
    auth.require_admin()?;

    if !matches!(key_type, KeyType::Ed25519) {
        return Err(AppError::Validation(format!(
            "derive-and-sign-document currently supports only Ed25519 (got {key_type:?})"
        )));
    }
    if !document.is_object() {
        return Err(AppError::Validation(
            "document must be a JSON object".into(),
        ));
    }

    let seed = load_seed_bytes(keys_ks, &**seed_store, None)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = vti_common::slip10::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;
    let path: vti_common::slip10::DerivationPath = derivation_path
        .parse()
        .map_err(|e| key_derivation_error(format!("invalid derivation path: {e}")))?;
    let derived = bip32
        .derive(&path)
        .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());

    // The derived identity's did:key + its verification method (did:key:zX#zX),
    // and a Secret built from the derived private key — identical to how the VTA
    // builds its issuer Secret.
    let pub_mb = encode_public_multibase(&KeyType::Ed25519, signing_key.verifying_key().as_bytes());
    let signer_did = format!("did:key:{pub_mb}");
    let priv_mb = encode_private_multibase(&KeyType::Ed25519, &signing_key.to_bytes());
    let mut secret = Secret::from_multibase(&priv_mb, None)
        .map_err(|e| AppError::Internal(format!("construct derived Secret: {e}")))?;
    secret.id = format!("{signer_did}#{pub_mb}");

    // JCS is presence-sensitive — sign the proof-less shape (verifiers strip
    // `proof` too).
    if let Some(obj) = document.as_object_mut() {
        obj.remove("proof");
    }
    let proof = DataIntegrityProof::sign(
        &document,
        &secret,
        SignOptions::new()
            .with_proof_purpose(proof_purpose.unwrap_or("assertionMethod"))
            .with_cryptosuite(CryptoSuite::EddsaJcs2022)
            .with_created(Utc::now()),
    )
    .await
    .map_err(|e| AppError::Internal(format!("DI-sign document: {e}")))?;
    document
        .as_object_mut()
        .expect("checked is_object above")
        .insert(
            "proof".to_string(),
            serde_json::to_value(&proof)
                .map_err(|e| AppError::Internal(format!("serialize proof: {e}")))?,
        );

    info!(
        channel,
        derivation_path = %derivation_path,
        "derive-and-sign-document (DI proof, no key record persisted)"
    );
    Ok(DeriveAndSignDocumentResultBody {
        signer_did,
        document,
    })
}

/// Find a VTA key by its multibase public key.
///
/// Used by the mdoc receive path to answer "do we hold the private half of this
/// credential's MSO `deviceKey`?". A linear scan of the key records: the
/// keyspace is indexed by key id, not by public key, and adding a reverse index
/// for one caller on the receive path is not worth the write amplification on
/// every mint.
///
/// Deliberately takes no `AuthClaims` — it answers a factual question about the
/// keyspace, not an authorization one. The **caller** must gate on the returned
/// record's `context_id`, because binding a credential to a key in a context the
/// caller cannot act in would be a cross-tenant escape.
pub async fn find_key_by_public_multibase(
    keys_ks: &KeyspaceHandle,
    public_key: &str,
) -> Result<Option<KeyRecord>, AppError> {
    for (raw_key, value) in keys_ks.prefix_iter_raw("key:").await? {
        // Skip (don't abort on) a corrupt row, matching `list_keys`: one bad
        // record must not make every lookup fail.
        let record: KeyRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    key = %String::from_utf8_lossy(&raw_key),
                    error = %e,
                    "skipping undeserializable key record during public-key lookup"
                );
                continue;
            }
        };
        if record.public_key == public_key {
            return Ok(Some(record));
        }
    }
    Ok(None)
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
        internal_ks: KeyspaceHandle,
        acl_ks: KeyspaceHandle,
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
            let internal_ks = store.keyspace(crate::keyspaces::INTERNAL_KEYS).unwrap();
            let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();

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
                internal_ks,
                acl_ks,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                internal: false,
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
                &h.internal_ks,
                &h.contexts_ks,
                &h.seed_store,
                &h.audit_ks,
                &auth,
                CreateKeyParams {
                    internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &auth,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
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

    #[tokio::test]
    async fn derive_and_sign_is_ephemeral_admin_only_and_verifies() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();
        let payload = b"fleet super-admin auth challenge";

        let result = derive_and_sign(
            &h.keys_ks,
            &h.seed_store,
            &auth,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            payload,
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("derive_and_sign should succeed for an admin");

        // The signature verifies against the returned (derived) public key.
        let (_, pk_bytes) = multibase::decode(&result.public_key).expect("multibase pubkey");
        assert_eq!(&pk_bytes[0..2], &[0xed, 0x01], "ed25519-pub multicodec");
        let vk = VerifyingKey::from_bytes(pk_bytes[2..].try_into().unwrap()).unwrap();
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&result.signature)
            .unwrap();
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        vk.verify(payload, &sig).expect("signature must verify");

        // Ephemeral: no key record was persisted.
        let listed = list_keys(
            &h.keys_ks,
            &auth,
            ListKeysParams {
                offset: None,
                limit: None,
                status: None,
                context_id: None,
            },
            "test",
        )
        .await
        .expect("list keys");
        assert!(
            listed.keys.is_empty(),
            "derive_and_sign must not persist a key"
        );

        // A non-admin caller is rejected.
        let non_admin = AuthClaims {
            role: Role::Application,
            ..h.super_admin_auth()
        };
        assert!(
            derive_and_sign(
                &h.keys_ks,
                &h.seed_store,
                &non_admin,
                &KeyType::Ed25519,
                "m/26'/9'/0'",
                payload,
                &SignAlgorithm::EdDSA,
                "test",
            )
            .await
            .is_err(),
            "non-admin must be rejected"
        );
    }

    #[tokio::test]
    async fn derive_and_sign_document_grafts_di_proof_as_derived_key() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();
        let doc = serde_json::json!({
            "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
            "payload": { "challenge": "abc", "sessionId": "s1" },
        });

        let res = derive_and_sign_document(
            &h.keys_ks,
            &h.seed_store,
            &auth,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            doc.clone(),
            None,
            "test",
        )
        .await
        .expect("derive_and_sign_document should succeed for an admin");

        // Signer is the derived super-admin did:key.
        assert!(
            res.signer_did.starts_with("did:key:z6Mk"),
            "{}",
            res.signer_did
        );
        // A proof was grafted, by the derived key, with a proofValue.
        let proof = res.document.get("proof").expect("proof grafted");
        assert!(
            proof.get("proofValue").and_then(|v| v.as_str()).is_some(),
            "proof has a proofValue"
        );
        let vm = proof
            .get("verificationMethod")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(
            vm.starts_with(&res.signer_did),
            "vm {vm} bound to signer {}",
            res.signer_did
        );

        // Deterministic: same path → same signer.
        let res2 = derive_and_sign_document(
            &h.keys_ks,
            &h.seed_store,
            &auth,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            doc,
            None,
            "test",
        )
        .await
        .unwrap();
        assert_eq!(res.signer_did, res2.signer_did);

        // Non-admin rejected.
        let non_admin = AuthClaims {
            role: Role::Application,
            ..h.super_admin_auth()
        };
        assert!(
            derive_and_sign_document(
                &h.keys_ks,
                &h.seed_store,
                &non_admin,
                &KeyType::Ed25519,
                "m/26'/9'/0'",
                serde_json::json!({"x": 1}),
                None,
                "test",
            )
            .await
            .is_err(),
            "non-admin must be rejected"
        );
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
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

    /// Gate 4 (#818): the caller's own ACL row may narrow which key ids it
    /// can invoke the oracle on — the actor-scoped complement of the
    /// resource-bound `signable_keys` policy pinned above.
    #[tokio::test]
    async fn sign_payload_honours_acl_allowed_keys() {
        use vti_common::acl::{AclEntry, store_acl_entry};

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // Two keys in the same context — the split gate 4 exists to express.
        for id in ["tenant-key-a", "tenant-key-b"] {
            create_key(
                &h.keys_ks,
                &h.internal_ks,
                &h.contexts_ks,
                &h.seed_store,
                &h.audit_ks,
                &admin,
                CreateKeyParams {
                    internal: false,
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: Some(id.into()),
                    mnemonic: None,
                    label: None,
                    context_id: Some("test-ctx".into()),
                },
                "test",
            )
            .await
            .expect("create key");
        }

        let caller_did = "did:key:z6MkFilteredSigner";
        let claims = AuthClaims {
            did: caller_did.to_string(),
            role: Role::Application,
            allowed_contexts: vec!["test-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let sign = |key_id: &'static str| {
            let claims = claims.clone();
            let h = &h;
            async move {
                sign_payload(
                    &h.keys_ks,
                    &h.imported_ks,
                    &h.internal_ks,
                    &h.contexts_ks,
                    &h.acl_ks,
                    &h.seed_store,
                    &claims,
                    key_id,
                    b"payload",
                    &SignAlgorithm::EdDSA,
                    "test",
                )
                .await
            }
        };

        // No ACL filter (`allowed_keys: None`): every key in scope — the
        // pre-#818 behaviour, byte-identical.
        let entry = AclEntry::new(caller_did, Role::Application, "did:key:zSetup")
            .with_contexts(vec!["test-ctx".into()]);
        store_acl_entry(&h.acl_ks, &entry).await.unwrap();
        sign("tenant-key-a").await.expect("no filter: key-a signs");
        sign("tenant-key-b").await.expect("no filter: key-b signs");

        // A filter naming exactly key-a: key-b is refused, key-a still signs.
        // The narrowing bound the very next request — same claims, same live
        // "session", no revocation step in between (the gate reads the row).
        store_acl_entry(
            &h.acl_ks,
            &entry
                .clone()
                .with_allowed_keys(Some(["tenant-key-a".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();
        sign("tenant-key-a").await.expect("filter names key-a");
        let denied = sign("tenant-key-b").await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "a key outside the caller's allowed_keys must be Forbidden, got {denied:?}"
        );

        // Trap 1: PRESENT-BUT-EMPTY is authorized on NO keys — the narrowest
        // grant, never a wildcard. If a bare `is_empty()` ever sneaks into
        // the gate, this is the assertion that catches it.
        store_acl_entry(
            &h.acl_ks,
            &entry.clone().with_allowed_keys(Some(Default::default())),
        )
        .await
        .unwrap();
        for key in ["tenant-key-a", "tenant-key-b"] {
            let denied = sign(key).await;
            assert!(
                matches!(denied, Err(crate::error::AppError::Forbidden(_))),
                "an EMPTY allowed_keys must refuse every key (got {denied:?} for {key})"
            );
        }
    }

    /// Gate 4 intersects — it never widens. A filter naming a key outside the
    /// caller's contexts does not grant it: the context gate still runs
    /// first, so the caller is refused before its key filter is even asked.
    /// And the filter binds the unscoped-key path too: a super-admin whose
    /// entry names specific keys asked to be bound to them.
    #[tokio::test]
    async fn sign_payload_allowed_keys_only_narrows_never_widens() {
        use crate::contexts::{ContextRecord, store_context};
        use vta_sdk::context_policy::ContextPolicy;
        use vti_common::acl::{AclEntry, store_acl_entry};

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // A key in a context the caller does NOT hold.
        let now = chrono::Utc::now();
        store_context(
            &h.contexts_ks,
            &ContextRecord {
                id: "other-ctx".into(),
                name: "other".into(),
                did: None,
                description: None,
                parent: None,
                base_path: "m/26'/2'/31'".into(),
                index: 31,
                created_at: now,
                updated_at: now,
                context_policy: Some(ContextPolicy::unrestricted()),
            },
        )
        .await
        .unwrap();
        let foreign = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("foreign-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("other-ctx".into()),
            },
            "test",
        )
        .await
        .unwrap();

        // The caller's entry NAMES the foreign key — and must still be
        // refused, because the filter intersects with the context scope.
        let caller_did = "did:key:z6MkOverreach";
        store_acl_entry(
            &h.acl_ks,
            &AclEntry::new(caller_did, Role::Application, "did:key:zSetup")
                .with_contexts(vec!["test-ctx".into()])
                .with_allowed_keys(Some(["foreign-key".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();
        let claims = AuthClaims {
            did: caller_did.to_string(),
            role: Role::Application,
            allowed_contexts: vec!["test-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &claims,
            &foreign.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "naming a key in allowed_keys must not reach past the context scope, got {denied:?}"
        );

        // Unscoped keys are gated too: a super-admin whose own row carries a
        // filter is bound by it even where no context policy exists.
        let unscoped = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/2'/77'/0'".into()),
                key_id: Some("unscoped-key".into()),
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .unwrap();
        store_acl_entry(
            &h.acl_ks,
            &AclEntry::new(&admin.did, Role::Admin, "did:key:zSetup")
                .with_allowed_keys(Some(["some-other-key".to_string()].into_iter().collect())),
        )
        .await
        .unwrap();
        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &admin,
            &unscoped.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "a filtered super-admin is bound on unscoped keys too, got {denied:?}"
        );
    }

    /// A caller authorized in one context cannot sign with another context's
    /// key (#805).
    ///
    /// This is the property a declined proposal rests on. The VTA does not
    /// inspect what it signs, so "a multi-domain signer cannot sign as a domain
    /// it does not hold" is true *only* because the caller's context scope is
    /// checked against the key's. If this regressed, a compromised gateway
    /// holding one domain's session could sign as any domain whose key id it
    /// could name — and nothing about the request would look wrong.
    ///
    /// Note the granularity being pinned: **per context, not per key id**. A
    /// caller scoped to a context may sign with *every* key in it by default.
    /// Per-key narrowing exists in two opt-in forms — the resource-bound
    /// `signable_keys` policy and the actor-scoped `allowed_keys` ACL filter
    /// (#818), each covered above; separation between domains still comes
    /// from giving each its own context.
    #[tokio::test]
    async fn sign_payload_refuses_a_key_outside_the_callers_contexts() {
        use crate::contexts::{ContextRecord, store_context};
        use vta_sdk::context_policy::ContextPolicy;

        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        // Two tenant contexts, both with an unrestricted policy — so the only
        // thing that can refuse below is the caller's context scope, not the
        // `signable_keys` guardrail (which has its own test above).
        let now = chrono::Utc::now();
        for (idx, id) in [(21u32, "domain-a"), (22, "domain-b")] {
            store_context(
                &h.contexts_ks,
                &ContextRecord {
                    id: id.into(),
                    name: id.into(),
                    did: None,
                    description: None,
                    parent: None,
                    base_path: format!("m/26'/2'/{idx}'"),
                    index: idx,
                    created_at: now,
                    updated_at: now,
                    context_policy: Some(ContextPolicy::unrestricted()),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("store {id}: {e:?}"));
        }

        let key = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("domain-a-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("domain-a".into()),
            },
            "test",
        )
        .await
        .expect("create domain-a-key");

        // Authorized in `domain-b` only — a different tenant of the same VTA.
        let other_tenant = AuthClaims {
            did: "did:key:z6MkDomainB".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["domain-b".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };

        let denied = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &other_tenant,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await;
        assert!(
            matches!(denied, Err(crate::error::AppError::Forbidden(_))),
            "signing another context's key must be Forbidden, got {denied:?}"
        );

        // ...and the same caller signs fine once the key is in *their* context,
        // so the refusal above is the scope check and not an unrelated failure.
        let own = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("domain-b-key".into()),
                mnemonic: None,
                label: None,
                context_id: Some("domain-b".into()),
            },
            "test",
        )
        .await
        .expect("create domain-b-key");
        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &other_tenant,
            &own.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("a caller signs with a key in their own context");
    }

    /// An **unscoped** key (no `context_id`) is super-admin-only (#805).
    ///
    /// Such a key has no context, so it has no context policy to constrain it —
    /// the resource-bound guardrail that binds even a super-admin simply does
    /// not apply. That makes the role floor the only thing standing between a
    /// scoped caller and an unconstrained signer, which is why it is asserted
    /// rather than assumed.
    #[tokio::test]
    async fn sign_payload_restricts_unscoped_keys_to_super_admin() {
        let h = TestHarness::new().await;
        let admin = h.super_admin_auth();

        let key = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/2'/99'/0'".into()),
                key_id: Some("unscoped-key".into()),
                mnemonic: None,
                label: None,
                // No context — hence the explicit path (a context would
                // otherwise supply its own base path).
                context_id: None,
            },
            "test",
        )
        .await
        .expect("create unscoped-key");

        // A context-scoped admin is *not* a super-admin (its list is non-empty),
        // so it is refused — the `ActScope` distinction, not a role comparison.
        let scoped = AuthClaims {
            did: "did:key:z6MkScopedStaff".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["some-ctx".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        assert!(!scoped.is_super_admin());

        let denied = sign_payload(
            &h.keys_ks,
            &h.internal_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
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
            "a scoped caller must not sign with an unscoped key, got {denied:?}"
        );

        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &admin,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("super-admin may use an unscoped key");
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
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &admin,
            CreateKeyParams {
                internal: false,
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
    // ── internal (non-extractable) keys ──────────────────────────────

    async fn mint_internal(h: &TestHarness, key_id: &str) -> CreateKeyResultBody {
        create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: true,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some(key_id.to_string()),
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .expect("mint internal key")
    }

    /// The guarantee, stated as a test: no export surface returns an internal
    /// key, and admin is not a bypass — a super-admin is refused like anyone.
    #[tokio::test]
    async fn an_internal_key_is_never_exported_even_to_a_super_admin() {
        let h = TestHarness::new().await;
        mint_internal(&h, "k-internal").await;

        let err = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.seed_store,
            &h.audit_ks,
            &h.super_admin_auth(),
            "k-internal",
            "test",
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
            "a super-admin must still be refused; got {err:?}"
        );
    }

    /// `InternalAuthority` bypasses the ACL, not the non-extractability
    /// guarantee. If this ever passes, the export surface has reopened through
    /// the back door rather than the front.
    #[tokio::test]
    async fn internal_authority_does_not_bypass_non_extractability() {
        let h = TestHarness::new().await;
        mint_internal(&h, "k-internal").await;

        let err = get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &*h.seed_store,
            &h.audit_ks,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-internal",
            "test",
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
            "{err:?}"
        );
    }

    /// The other half: an internal key must actually be usable. A key nobody
    /// can export *and* nobody can sign with is just a liability.
    #[tokio::test]
    async fn an_internal_key_signs_through_the_oracle() {
        let h = TestHarness::new().await;
        let created = mint_internal(&h, "k-sign").await;
        assert_eq!(created.origin, keys::KeyOrigin::Internal);
        assert_eq!(
            created.derivation_path, "internal",
            "an internal key records no BIP-32 path — there is nothing to derive"
        );

        let sig = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.super_admin_auth(),
            "k-sign",
            b"payload",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect("an internal key must be usable for signing");
        assert!(!sig.signature.is_empty());
    }

    /// An internal key has no derivation path, so it cannot be named after one.
    /// Refusing here beats minting an unrecoverable key under a generated id
    /// the operator never chose and may not record.
    #[tokio::test]
    async fn an_internal_key_requires_an_explicit_key_id() {
        let h = TestHarness::new().await;
        let err = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit_ks,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: true,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: None,
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("explicit key_id")),
            "{err:?}"
        );
    }
}
