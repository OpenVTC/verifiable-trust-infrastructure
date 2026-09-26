use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use base64::Engine;
use chrono::Utc;
use p256::elliptic_curve::sec1::ToSec1Point;
use tracing::info;
use zeroize::Zeroize;

use vti_common::acl::Capability;

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody,
    derive_and_sign::DeriveAndSignResultBody,
    derive_and_sign_document::DeriveAndSignDocumentResultBody,
    list::ListKeysResultBody,
    rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody,
    secret::GetKeySecretResultBody,
    sign::{SignAlgorithm, SignResultBody, SigningDomain},
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
    audit: &vta_audit::SharedAuditSink,
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
        exportable: None,
        // No seed is involved, so there is no seed generation to pin to.
        seed_id: None,
        origin: keys::KeyOrigin::Internal,
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(keys::store_key(&key_id), &record).await?;

    audit::record_best_effort(
        audit,
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
    audit: &vta_audit::SharedAuditSink,
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
            audit,
            auth,
            params,
            context_id,
            channel,
        )
        .await;
    }

    // Resolve derivation path: use explicit value, or auto-derive from context.
    //
    // An explicit path is key custody's rule 4: super-admin only, and it must
    // belong to the context the record will carry. Without this check a
    // context-scoped admin could derive any key the VTA holds (another tenant's,
    // the VTA's own) and record it under its own context, where
    // `get_key_secret`'s scope check reads the record's context and releases
    // it. See `vta_keys::custody`.
    let derivation_path = match params.derivation_path {
        Some(path) if !path.is_empty() => {
            super::key_custody::authorize_explicit_key_path(
                contexts_ks,
                auth,
                &path,
                context_id.as_deref(),
                audit,
                channel,
            )
            .await?;
            path
        }
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
            let encoded = verifying_key.to_sec1_point(true);
            // Multicodec-prefixed (`p256-pub`), exactly as key custody encodes
            // the same key when it is exported — so the record, the export and
            // any DID document built from the record all publish one form, and
            // a verifier can read the algorithm off the key (VTI-KEY-012). The
            // bare SEC1 point stored here before named no algorithm at all.
            encode_public_multibase(&KeyType::P256, encoded.as_bytes())
        }
        KeyType::MlDsa44 => {
            let s = bip32.derive_ml_dsa_44(&derivation_path)?;
            s.get_public_keymultibase()?
        }
        KeyType::MlDsa65 => {
            let s = bip32.derive_ml_dsa_65(&derivation_path)?;
            s.get_public_keymultibase()?
        }
        // `KeyType` is `#[non_exhaustive]`, so this arm is required. It refuses
        // rather than falling back, because every branch above derives through a
        // scheme-specific SLIP-0010 path and there is no generic one — a
        // wildcard could only mint a key of some *other* algorithm wearing this
        // label.
        other => {
            return Err(AppError::Validation(format!(
                "key derivation does not support {other} yet"
            )));
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
        exportable: None,
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
    audit::record_best_effort(
        audit,
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
    audit: &vta_audit::SharedAuditSink,
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
            // Multicodec-prefixed (`x25519-pub`), as every other published key
            // is (VTI-KEY-012: a key names its own algorithm).
            let pub_multibase = encode_public_multibase(&KeyType::X25519, public.as_bytes());
            (pub_multibase, "x25519")
        }
        KeyType::P256 => {
            let secret_key = p256::SecretKey::from_slice(&private_bytes)
                .map_err(|e| AppError::Validation(format!("invalid P-256 private key: {e}")))?;
            let public = secret_key.public_key();
            let encoded = public.to_sec1_point(true);
            let pub_multibase = encode_public_multibase(&KeyType::P256, encoded.as_bytes());
            (pub_multibase, "p256")
        }
        // `KeyType` is `#[non_exhaustive]`, so this arm is required. Import
        // validates the supplied bytes against the scheme before storing them,
        // and there is no generic validation to fall through to — accepting a
        // key type this function cannot check would store unvalidated material
        // under a label claiming it was checked.
        other => {
            return Err(AppError::Validation(format!(
                "key import does not support {other} yet"
            )));
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
        exportable: None,
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
    audit::record_best_effort(
        audit,
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
    audit: &vta_audit::SharedAuditSink,
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
    audit::record_best_effort(
        audit,
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
    audit: &vta_audit::SharedAuditSink,
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
    audit::record_best_effort(
        audit,
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

/// The caller's stored ACL entry, for a capability gate.
///
/// `Ok(None)` means the caller has no entry and its role decides — the
/// process-local synthesized identities (the offline CLI's `cli:<channel>`
/// sentinel) and nothing else reach here without one. A store error **refuses**:
/// an unreadable entry must not become a grant, and the caller is told only that
/// the capability could not be confirmed while the operator gets the reason.
async fn entry_for_capability_gate(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
    capability: &str,
) -> Result<Option<vti_common::acl::AclEntry>, AppError> {
    vti_common::acl::get_acl_entry(acl_ks, &auth.did)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, did = %auth.did, capability,
                "could not read the ACL entry for a capability check; refusing"
            );
            AppError::Forbidden(format!(
                "{what} denied: could not confirm that {} carries the {capability} capability",
                auth.did
            ))
        })
}

/// Whether `entry` (or, with none, the caller's role) carries `cap` — the role's
/// set narrowed by the entry's own list, as every capability gate reads it.
fn entry_or_role_has(
    entry: Option<&vti_common::acl::AclEntry>,
    auth: &AuthClaims,
    cap: Capability,
) -> bool {
    match entry {
        Some(entry) => vti_common::acl::entry_has_capability(entry, cap),
        None => vti_common::acl::role_has_capability(&auth.role, cap),
    }
}

/// The export gate: the caller must hold [`Capability::KeyExport`] (VTI-VTA-003).
///
/// This is the one implementation of it, and it lives here — in the operation,
/// not in a handler — because the export surface is reachable over REST, DIDComm
/// and the Trust-Task spine (itself carried over HTTPS, DIDComm and TSP). It used
/// to be applied by the `keys/export-secret` handler alone, so the same export
/// over `GET /keys/{id}/secret` or DIDComm `get-key-secret` checked only the
/// admin *role*: an admin narrowed without `key-export` could still take a key by
/// choosing a different transport. Checked in the operation, a transport added
/// later cannot be wired without it.
///
/// Reads the caller's **entry**, so a narrowing that removes `key-export` binds
/// the very next export. Runs before the key or context is looked up, so a
/// refused caller learns nothing about which ids exist.
///
/// The refusal names the exact command that fixes it — the caller is often a
/// service logging at boot, and the person reading that log is the one who has
/// to run it.
pub(crate) async fn ensure_may_export(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
) -> Result<(), AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, what, "key-export").await?;
    if entry_or_role_has(entry.as_ref(), auth, Capability::KeyExport) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "{what} denied: {} does not carry the key-export capability. Releasing a \
         private key is an export, and VTI-VTA-003 gates export on a capability \
         distinct from using the key; only an admin derives it, so a service that \
         holds a context's keys must be an admin scoped to that context. {}",
        auth.did,
        key_export_fix(entry.as_ref(), &auth.did)
    )))
}

/// The generic signing-oracle gate: the caller must hold [`Capability::Sign`].
///
/// `Sign` is "the capability to use the key" VTI-VTA-003 distinguishes export
/// from, and the capability VTI-VTA-007 distinguishes from the constrained
/// signing grants (`sign-trust-task`, `room-present`, …). Every role that can
/// reach the oracle derives it, so an un-narrowed entry loses nothing; what this
/// adds is that an operator who narrowed `sign` away from an entry gets the
/// refusal they asked for — before, the role floor was the only check, and the
/// narrowing was silently ignored on every transport.
pub(crate) async fn ensure_may_sign(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
) -> Result<(), AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, what, "sign").await?;
    if entry_or_role_has(entry.as_ref(), auth, Capability::Sign) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "{what} denied: {} does not carry the sign capability",
        auth.did
    )))
}

/// The command an operator runs so `did` may export.
///
/// Built from the caller's stored entry, because the right command depends on it:
///
/// - **no entry** — create one, as an admin of the context;
/// - **a non-admin with a context scope** — `change-role` to admin, which keeps the scope
///   (and, like any admin grant, confers the rest of what an admin of that context holds);
/// - **a non-admin with no context** — scope it first: promoting an entry with no contexts
///   would make it a *super*-admin, so that is never suggested;
/// - **an admin narrowed without `key-export`** — re-state the narrowing with `key-export`
///   added, rather than suggesting `--capabilities-all`, which would also undo whatever
///   else the narrowing deliberately removed.
fn key_export_fix(entry: Option<&vti_common::acl::AclEntry>, did: &str) -> String {
    use vta_sdk::acl::ActScope;

    let Some(entry) = entry else {
        return format!(
            "Grant it with: pnm acl create --did {did} --role admin --contexts <CONTEXT>"
        );
    };
    if entry.role != crate::acl::Role::Admin {
        let promote = format!(
            "pnm acl change-role --did {did} --from {} --to admin",
            entry.role
        );
        let narrowed = restated_narrowing(entry);
        return match (entry.act_scope(), narrowed) {
            (ActScope::Contexts(_), None) => format!("Grant it with: {promote}"),
            (ActScope::Contexts(_), Some(caps)) => {
                format!("Grant it with: {promote} && pnm acl update {did} --capabilities {caps}")
            }
            // Authorized nowhere (or, defensively, anything else): scope first.
            _ => format!(
                "Scope it to the context first, then promote it: \
                 pnm acl update {did} --contexts <CONTEXT> && {promote}"
            ),
        };
    }
    match restated_narrowing(entry) {
        Some(caps) => format!("Grant it with: pnm acl update {did} --capabilities {caps}"),
        // An un-narrowed admin derives `KeyExport`, so reaching here means something other
        // than the narrowing withheld it — say what to look at rather than guess a command.
        None => format!("Inspect the entry with: pnm acl get {did}"),
    }
}

/// The entry's stored capability list with `key-export` added, as the comma-separated
/// value `pnm acl update --capabilities` takes — or `None` when the entry is not narrowed.
///
/// `--capabilities` *replaces* the list, so the command has to carry every name already
/// there; a bare `--capabilities key-export` would narrow an admin to that one power.
fn restated_narrowing(entry: &vti_common::acl::AclEntry) -> Option<String> {
    if entry.capabilities.is_empty() {
        return None;
    }
    let name = |c: &Capability| {
        serde_json::to_value(c)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
    };
    let mut names: Vec<String> = entry.capabilities.iter().filter_map(name).collect();
    if let Some(key_export) = name(&Capability::KeyExport)
        && !names.contains(&key_export)
    {
        names.push(key_export);
    }
    Some(names.join(","))
}

/// Load the record `key_id` names **for a caller**, answering "absent" and
/// "not yours" identically.
///
/// A caller whose scope is restricted learns nothing about ids outside it: a
/// key that does not exist and a key in a context it cannot act in get the same
/// refusal, with a message that names neither the key's context nor whether it
/// exists. Only a super-admin — who can reach every key — is told a key is
/// absent. Without this, `keys/export-secret` and `keys/sign` were an existence
/// oracle for every key id in the VTA, and their "no access to context: X"
/// refusal also named the context the key lived in.
pub(crate) async fn load_record_in_caller_scope(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
) -> Result<KeyRecord, AppError> {
    let out_of_reach =
        || AppError::Forbidden(format!("key `{key_id}` is not within the caller's scope"));
    let record: Option<KeyRecord> = keys_ks.get(keys::store_key(key_id)).await?;
    let Some(record) = record else {
        return Err(if auth.is_super_admin() {
            AppError::NotFound(format!("key {key_id} not found"))
        } else {
            out_of_reach()
        });
    };
    let reachable = match record.context_id.as_deref() {
        Some(ctx) => auth.has_context_access(ctx),
        None => auth.is_super_admin(),
    };
    if !reachable {
        return Err(out_of_reach());
    }
    Ok(record)
}

/// How the channel a released private key travels over protects it — stated
/// by the caller of [`get_key_secret`], because only the transport knows.
///
/// A type rather than a flag so that a new call site has to say which case it
/// is in. The `&str` is the audit `channel` the export is recorded under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportChannel<'a> {
    /// Encrypted by the transport to the requester alone: DIDComm authcrypt,
    /// or TSP. No intermediary — mediator included — holds the plaintext.
    EndToEnd(&'a str),
    /// Sealed to the recipient before it leaves the VTA
    /// (`vta_sdk::sealed_transfer`, HPKE), whatever carries the envelope.
    Sealed(&'a str),
    /// Never leaves this host: an on-host CLI running as the VTA's own OS user.
    Local(&'a str),
    /// Confidential in transit at best — REST, and Trust Tasks over HTTPS. TLS
    /// terminates wherever the operator terminates it, so the plaintext key
    /// would exist there. **Refused**: see [`get_key_secret`].
    HopByHop(&'a str),
}

impl<'a> ExportChannel<'a> {
    /// The audit `channel` this export is recorded under.
    pub fn audit_channel(self) -> &'a str {
        match self {
            Self::EndToEnd(c) | Self::Sealed(c) | Self::Local(c) | Self::HopByHop(c) => c,
        }
    }
}

/// Release a key's private material to the caller — `keys/export-secret`, over
/// every transport.
///
/// Every check a release needs, in the order the specification sets
/// (`keys/export-secret/0.1` § Authorization: entitlement first, then the two
/// refusals no authority satisfies, then the response):
///
/// 1. **`KeyExport`** ([`ensure_may_export`]), before the key is looked up;
/// 2. **a confidential channel** — an [`ExportChannel::HopByHop`] export is
///    refused. `keys/export-secret/0.1` requires the exchange to be "carried
///    over a channel confidential to the two parties", and the response is a
///    private key in the clear; over REST or HTTPS it would exist in plaintext
///    wherever TLS terminates. `keys/import` refuses the cleartext carrier over
///    the same transports for the same reason. Checked before the key is
///    looked up, so the refusal says nothing about which ids exist;
/// 3. **scope** — the key's context, or super-admin for an unscoped key;
/// 4. **never an internal key**, to anybody;
/// 5. **never a key marked non-exportable**;
/// 6. a **durable audit row**, written before the material is returned — see
///    [`release_key_secret`].
///
/// The transports are thin: `GET /keys/{id}/secret`, DIDComm `get-key-secret`
/// and the `keys/export-secret/0.1` handler all call this and nothing else, so
/// none of them carries a check the others lack.
#[allow(clippy::too_many_arguments)]
pub async fn get_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: ExportChannel<'_>,
) -> Result<GetKeySecretResultBody, AppError> {
    export_key_secret(
        keys_ks,
        imported_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        channel,
    )
    .await
    .map_err(AppError::from)
}

/// Why a key's private half is refused **about the key rather than the
/// caller** — the two refusals `keys/export-secret/0.1` gives codes of their
/// own, because retrying with more authority changes neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExportRefusal {
    /// An internal key: generated inside this VTA, reproducible nowhere, never
    /// released to anybody — `keys/export-secret:neverExportable`.
    NeverExportable,
    /// Marked non-exportable by `keys/set-exportability` — a decision that can
    /// be reversed, by more authority than imposed it —
    /// `keys/export-secret:notExportable`.
    NotExportable,
}

impl KeyExportRefusal {
    /// The local part of the task's extended error code.
    pub fn code(self) -> &'static str {
        match self {
            Self::NeverExportable => "neverExportable",
            Self::NotExportable => "notExportable",
        }
    }
}

/// The error [`export_key_secret`] returns: a refusal about the key, typed so a
/// transport that can name it (the Trust-Task spine) does, or any other error.
#[derive(Debug)]
pub enum KeyExportError {
    Refused(KeyExportRefusal, String),
    Other(AppError),
}

impl From<AppError> for KeyExportError {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<KeyExportError> for AppError {
    /// For transports with no code to carry: a refusal about the key is a 403
    /// with the same message.
    fn from(e: KeyExportError) -> Self {
        match e {
            KeyExportError::Refused(_, message) => AppError::Forbidden(message),
            KeyExportError::Other(e) => e,
        }
    }
}

/// [`get_key_secret`] with the refusals about the key kept typed — what the
/// `keys/export-secret/0.1` handler calls so it can answer `notExportable` /
/// `neverExportable`. Same checks in the same order: the capability, the
/// channel and the caller's scope are all established first, so those codes
/// are only ever said to a caller already entitled to the key (the spec's
/// "after establishing entitlement and before assembling a response").
#[allow(clippy::too_many_arguments)]
pub async fn export_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: ExportChannel<'_>,
) -> Result<GetKeySecretResultBody, KeyExportError> {
    ensure_may_export(acl_ks, auth, "keys/export-secret").await?;
    if let ExportChannel::HopByHop(_) = channel {
        return Err(AppError::Forbidden(
            "keys/export-secret refused: a private key is released only over a channel \
             confidential end to end — DIDComm or TSP — or sealed to its recipient, and \
             this request arrived over REST/HTTPS, where TLS terminates wherever the \
             operator terminates it and the key would exist in plaintext there. Retry over \
             DIDComm or TSP, or run the export on the VTA host."
                .into(),
        )
        .into());
    }
    release_key_secret(
        keys_ks,
        imported_ks,
        contexts_ks,
        seed_store,
        audit,
        auth,
        key_id,
        channel.audit_channel(),
    )
    .await
}

/// Checks 3–6 of [`get_key_secret`]: scope, the internal-key and
/// non-exportable refusals, and the durable audit row. The one place a private
/// key leaves the VTA. Private: every caller goes through [`get_key_secret`]
/// and so through the capability and channel gates.
///
/// `get_key_secret_internal` is deliberately NOT gated by exportability: it is
/// the *use* surface, loading a key so the VTA can sign or decrypt with it, and
/// a key that may not leave may still be used.
///
/// # The audit row is a precondition of the release
///
/// VTI-VTA-003 requires an export to be audited, and elsewhere in this module
/// the row is best-effort, because a failed write must not fail an operation
/// that has already happened — refusing to revoke a key because the log is full
/// protects nobody. An export is the opposite case: nothing has happened until
/// the material is returned, and once it has, it cannot be taken back. So the
/// row is written first and a failed write **refuses the export**. The row
/// carries who (`actor`), which key (`resource`), its context, and the
/// transport (`channel`) — never the material.
#[allow(clippy::too_many_arguments)]
async fn release_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<GetKeySecretResultBody, KeyExportError> {
    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;

    // A revoked key is refused like a missing one would be to its owner: its
    // record is kept for history (and a rotation's retired and staging records
    // are revoked by construction), not so its private half can still leave.
    if record.status != KeyStatus::Active {
        return Err(KeyExportError::Other(AppError::Forbidden(format!(
            "key `{key_id}` is not active and its private half is not released"
        ))));
    }

    // Internal keys are refused here too. `InternalAuthority` bypasses the ACL,
    // not the non-extractability guarantee — an internal key has no export
    // surface at all, and an internal caller wanting a signature must go
    // through the signing oracle like everyone else.
    if record.origin == KeyOrigin::Internal {
        return Err(KeyExportError::Refused(
            KeyExportRefusal::NeverExportable,
            format!(
                "key `{key_id}` is an internal key and is never exported, including \
                 under internal authority"
            ),
        ));
    }

    // The exportability restriction, enforced at the one place a private key
    // leaves the VTA — every export path (`keys/export-secret` on each
    // transport, `vta/contexts/secrets`, the offline CLI exports, and
    // provisioning's read-back) arrives here. `get_key_secret_internal` is
    // deliberately NOT gated: it is the *use* surface, and gating it would break
    // the VTA's own signing rather than protect anything, because nothing it
    // returns reaches a caller.
    //
    // `None` means exportable — see `KeyRecord::exportable`. Only an explicit
    // `Some(false)` refuses, so records written before the member existed are
    // unaffected.
    if record.exportable == Some(false) {
        return Err(KeyExportError::Refused(
            KeyExportRefusal::NotExportable,
            format!(
                "key `{key_id}` is marked non-exportable and its private half is never \
                 released; it can still be used for signing and key agreement. Changing \
                 that needs `keys/set-exportability` with authority beyond the one that \
                 set it"
            ),
        ));
    }

    let (public_key_multibase, private_key_multibase) = match record.origin {
        // Unreachable: the early return above refuses internal keys. Kept as a
        // second, local refusal so deleting that guard cannot quietly turn this
        // match into an export path for them.
        KeyOrigin::Internal => {
            return Err(KeyExportError::Refused(
                KeyExportRefusal::NeverExportable,
                format!("key `{key_id}` is an internal key and is never exported"),
            ));
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
        // Through key custody: the record's path must lie in its context's base,
        // so a record carrying a foreign path is refused here rather than
        // exported (VTI-KEY-032, `vta_keys::custody` rule 6).
        KeyOrigin::Derived => {
            let key = super::key_custody::derive_record_key(
                contexts_ks,
                keys_ks,
                &**seed_store,
                audit,
                &auth.did,
                &record,
                channel,
            )
            .await?;
            let (public, private) = key.multibase_pair()?;
            (public, (*private).clone())
        }
    };

    // Durable before the material is returned, and refusing on failure — see
    // "The audit row is a precondition of the release" above.
    if let Err(e) = audit::record(
        audit,
        "key.secret_export",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await
    {
        let mut private_key_multibase = private_key_multibase;
        private_key_multibase.zeroize();
        tracing::error!(
            target: vta_audit::AUDIT_WRITE_FAILURE_TARGET,
            error = %e, channel, key_id = %key_id, actor = %auth.did,
            "key export refused: its audit row could not be written"
        );
        return Err(KeyExportError::Other(AppError::Internal(format!(
            "key `{key_id}` was not released: the export could not be recorded in the \
             audit trail, and an unrecorded export is not permitted (VTI-VTA-003)"
        ))));
    }
    info!(channel, key_id = %key_id, "key secret retrieved");
    audit!(
        "key.secret_export",
        actor = &auth.did,
        resource = key_id,
        outcome = "success"
    );

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase,
        private_key_multibase,
    })
}

/// Set whether a key's private half may be released, and refuse to make that
/// decision cheaply reversible.
///
/// # The asymmetry is the feature
///
/// A restriction that whoever imposed it can lift again protects against
/// accident but not against a compromised caller holding that party's
/// credentials — which is the case the restriction exists for. So the two
/// directions do not carry the same entitlement:
///
/// - **Imposing it** (`exportable: false`) needs admin of the key's context.
///   Foreclosing something is the safe direction.
/// - **Lifting it** (`false` → `true`) needs that *and* one of two things
///   beyond it: super-admin, or a live step-up on this session. Either is
///   strictly more than the entitlement that imposed it, which is what
///   `keys/set-exportability/0.1` requires of a conforming consumer. The spec
///   deliberately does not name the mechanism — SPEC §7.3 item 13 forbids a
///   specification from mandating a step-up — so choosing these two is this
///   VTA's policy, and either satisfies the rule.
///
/// Offering both rather than only super-admin matters operationally: a
/// deployment with no super-admin session to hand can still recover a key it
/// locked down, by stepping up. One with no step-up policy configured can still
/// do it as super-admin. Requiring only one of them would strand somebody.
///
/// # Idempotent, and only the transition is gated
///
/// `exportable` is an absolute state, not a toggle, so a producer that retries
/// a request whose reply was lost lands where it asked. Setting `true` on a key
/// that is already exportable takes nothing away and so takes the ordinary
/// path — only a real `false` → `true` transition meets the stronger gate.
pub async fn set_key_exportability(
    keys_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    exportable: bool,
    channel: &str,
) -> Result<KeyRecord, AppError> {
    let mut record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    // Standing over the key's scope, exactly as the export path requires it.
    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can act on keys without a context".into(),
        ));
    }
    auth.require_admin()?;

    // An internal key has no export surface at all, so `exportable: true` is
    // asking for something no authority can grant. Refused as a precondition
    // rather than a permission failure — retrying as super-admin changes
    // nothing, and saying "forbidden" would send the operator to look for more
    // authority that does not exist.
    if record.origin == KeyOrigin::Internal && exportable {
        return Err(AppError::Validation(format!(
            "key `{key_id}` is an internal key: its private half is never released              regardless of this setting, so it cannot be made exportable"
        )));
    }

    let currently = record.exportable != Some(false);
    if !currently && exportable {
        // The one gated transition. Super-admin OR a live step-up; the error
        // names both, because a caller told only "forbidden" cannot tell which
        // of the two routes is open to it.
        if auth.require_super_admin().is_err() {
            auth.require_fresh_step_up(sessions_ks).await.map_err(|_| {
                AppError::Forbidden(format!(
                    "making `{key_id}` exportable again needs more authority than the                      admin that restricted it: either super-admin, or a fresh step-up                      on this session"
                ))
            })?;
        }
    }

    record.exportable = Some(exportable);
    record.updated_at = chrono::Utc::now();
    keys_ks.insert(keys::store_key(key_id), &record).await?;

    audit!(
        "key.set_exportability",
        actor = &auth.did,
        resource = key_id,
        outcome = "success"
    );
    audit::record_best_effort(
        audit,
        "key.set_exportability",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(record)
}

/// Internal-authority variant of [`get_key_secret`] — the **use** surface,
/// audited as `key.internal_use` — that bypasses the
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
    contexts_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit: &vta_audit::SharedAuditSink,
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

    // Internal authority skips the ACL, not the key's lifecycle: a revoked key
    // (retired by a rotation, or revoked outright) must not keep signing or
    // decrypting for the VTA.
    if record.status != KeyStatus::Active {
        return Err(AppError::Forbidden(format!(
            "key `{key_id}` is not active and is not loaded for use"
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
        // Through key custody even under internal authority: `InternalAuthority`
        // bypasses the ACL, not the rule that a record's path belongs to its
        // context.
        KeyOrigin::Derived => {
            let key = super::key_custody::derive_record_key(
                contexts_ks,
                keys_ks,
                seed_store,
                audit,
                &authority.audit_actor(),
                &record,
                channel,
            )
            .await?;
            let (public, private) = key.multibase_pair()?;
            (public, (*private).clone())
        }
    };

    // `key.internal_use`, not `key.secret_export`: nothing here leaves the VTA
    // — the key is loaded so the VTA can sign or decrypt with it itself. Filed
    // under the export action, every VC the VTA issued and every webvh publish
    // it authenticated read as a key export, which buried the real exports an
    // incident review is looking for under the VTA's own routine use.
    let actor = authority.audit_actor();
    info!(channel, key_id = %key_id, actor = %actor, "key loaded for internal use");
    audit!(
        "key.internal_use",
        actor = &actor,
        resource = key_id,
        outcome = "success"
    );
    audit::record_best_effort(
        audit,
        "key.internal_use",
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
///
/// `audit` is required rather than optional: this is the one chokepoint every
/// transport reaches the signing oracle through, so a caller who could opt out
/// of the trail could sign unrecorded. See the audit call at the tail.
#[allow(clippy::too_many_arguments)]
pub async fn sign_payload(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    internal_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    domain: SigningDomain,
    channel: &str,
) -> Result<SignResultBody, AppError> {
    // Gate 0 — the generic oracle needs `Sign` (VTI-VTA-003, VTI-VTA-007).
    // Only for `Opaque`: those bytes came from a caller, which is the generic
    // signing request `Sign` names. `ProtocolDefined` input is built inside the
    // VTA by an operation that has already applied the constrained capability
    // its own task requires (`credential-write` for a room's credentials, for
    // instance) — and VTI-VTA-007 is precisely that such a grant must not have
    // to carry the general one. Before any lookup, so a refused caller learns
    // nothing about which key ids exist.
    if domain == SigningDomain::Opaque {
        ensure_may_sign(acl_ks, auth, "keys/sign").await?;
    }

    // Scope before existence: an out-of-scope caller gets the same refusal for
    // a key that exists and one that does not.
    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;

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

    // What gets signed, which is not always what was handed in: an opaque

    // payload is framed under its domain tag first. See `SigningDomain`.

    let to_sign = domain.signing_input(payload);

    let payload = to_sign.as_ref();

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
        // Through key custody: a record whose path lies outside its context's
        // base is refused before anything is signed (`vta_keys::custody` rule 6).
        KeyOrigin::Derived => {
            if !matches!(
                (algorithm, &record.key_type),
                (SignAlgorithm::EdDSA, KeyType::Ed25519) | (SignAlgorithm::ES256, KeyType::P256)
            ) {
                return Err(AppError::Validation(format!(
                    "algorithm {} incompatible with key type {}",
                    algorithm, record.key_type
                )));
            }
            let key = super::key_custody::derive_record_key(
                contexts_ks,
                keys_ks,
                &**seed_store,
                audit,
                &auth.did,
                &record,
                channel,
            )
            .await?;
            match record.key_type {
                KeyType::P256 => {
                    let p256_secret = key.p256_secret()?;
                    let signing_key = p256::ecdsa::SigningKey::from(&p256_secret.secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    let bytes = key.ed25519_signing_key_bytes()?;
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
            }
        }
    };

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    info!(channel, key_id = %key_id, "payload signed");

    // A signature is the most consequential thing this agent does with a key,
    // and it was the one key operation absent from the queryable trail.
    // `keys/create`, `keys/revoke`, `keys/secret` and `keys/derive-and-sign`
    // all record; the oracle that actually signs did not. An incident review
    // could establish that a key existed and that nobody exported it, and not
    // that it had signed four thousand times — which is the question asked
    // first when a key is suspected.
    //
    // Recorded here rather than in each transport's handler because this is the
    // chokepoint all four callers reach the oracle through (the Trust Task,
    // REST, DIDComm, and the rooms signer). A handler-level row would have to
    // be remembered four times and again for the fifth caller; here a new
    // caller is audited by construction.
    //
    // Success only, deliberately: a refusal returns from one of the gates
    // above, and for Trust Tasks the dispatch spine already records those as
    // `task.refused` with the URI. The REST and DIDComm refusal rows are a
    // separate gap, and belong wherever those two transports grow a spine of
    // their own rather than in eight early returns here.
    //
    // The payload is deliberately not recorded: it is the caller's bytes, may
    // carry anything, and the trail answers "which key signed, for whom, over
    // what transport", not "what did it say". The action name matches
    // `keys.derive-and-sign`, the sibling oracle, rather than this module's
    // older `key.*` rows.
    audit::record_best_effort(
        audit,
        "keys.sign",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

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
/// VTA.
///
/// **Super-admin only, and only inside `m/26'/9'`**
/// ([`vta_keys::custody::DELEGATED_IDENTITY_ROOT`]). The caller picks the
/// identity it signs as, so a role-only gate let a context-scoped admin sign as
/// any key the VTA holds, including its own `did:webvh` update key. The subtree
/// confinement holds even for a super-admin: this oracle never signs as a key
/// a record exists for. Every signature is audited with the path and a digest
/// of what was signed (VTI-VTA-006).
#[allow(clippy::too_many_arguments)]
pub async fn derive_and_sign(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    audit: &vta_audit::SharedAuditSink,
    key_type: &KeyType,
    derivation_path: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    channel: &str,
) -> Result<DeriveAndSignResultBody, AppError> {
    // The same `Sign` gate as the stored-key oracle: this signs caller-supplied
    // bytes too, and a super-admin narrowed without `sign` asked not to.
    ensure_may_sign(acl_ks, auth, "keys/derive-and-sign").await?;
    let signing_bytes = super::key_custody::derive_delegated_identity(
        keys_ks,
        &**seed_store,
        auth,
        derivation_path,
        "keys.derive-and-sign",
        audit,
        channel,
    )
    .await?;

    if !matches!(
        (algorithm, key_type),
        (SignAlgorithm::EdDSA, KeyType::Ed25519)
    ) {
        return Err(AppError::Validation(format!(
            "derive-and-sign currently supports only EdDSA/Ed25519 (got {algorithm}/{key_type:?})"
        )));
    }

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);
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
    record_delegated_signature(
        audit,
        auth,
        "keys.derive-and-sign",
        derivation_path,
        &format!("keyType={key_type} alg={algorithm}"),
        payload,
        channel,
    )
    .await;

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
/// the VTA. **Super-admin only, inside `m/26'/9'`**, for the reasons given on
/// [`derive_and_sign`]. Audited with a digest of the signed document.
#[allow(clippy::too_many_arguments)]
pub async fn derive_and_sign_document(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    audit: &vta_audit::SharedAuditSink,
    key_type: &KeyType,
    derivation_path: &str,
    mut document: serde_json::Value,
    proof_purpose: Option<&str>,
    channel: &str,
) -> Result<DeriveAndSignDocumentResultBody, AppError> {
    // `Sign`, as for `derive_and_sign`: the document is the caller's, and any
    // JSON object is accepted, so this is a general signing request.
    ensure_may_sign(acl_ks, auth, "keys/derive-and-sign-document").await?;
    let signing_bytes = super::key_custody::derive_delegated_identity(
        keys_ks,
        &**seed_store,
        auth,
        derivation_path,
        "keys.derive-and-sign-document",
        audit,
        channel,
    )
    .await?;

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

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);

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
    let signed_bytes = serde_json::to_vec(&document)
        .map_err(|e| AppError::Internal(format!("serialize signed document: {e}")))?;
    record_delegated_signature(
        audit,
        auth,
        "keys.derive-and-sign-document",
        derivation_path,
        &format!(
            "keyType={key_type} proofPurpose={}",
            proof_purpose.unwrap_or("assertionMethod")
        ),
        &signed_bytes,
        channel,
    )
    .await;
    Ok(DeriveAndSignDocumentResultBody {
        signer_did,
        document,
    })
}

/// Audit a delegated-identity signature: who, as which path, and a SHA-256 of
/// what was signed (VTI-VTA-006: record what was signed, for which caller). A
/// digest, not the payload, because the payload may carry personal data an
/// audit row must not embed (VTI-AUD-005).
async fn record_delegated_signature(
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    action: &str,
    derivation_path: &str,
    detail: &str,
    signed: &[u8],
    channel: &str,
) {
    use sha2::Digest;
    let digest = hex::encode(sha2::Sha256::digest(signed));
    audit::record_with_detail_best_effort(
        audit,
        action,
        &auth.did,
        Some(derivation_path),
        "success",
        Some(channel),
        None,
        Some(&format!("{detail} sha256:{digest}")),
    )
    .await;
}

/// Find an **active** key of context `context_id` by its multibase public key.
///
/// For a caller that acts on the record it finds (realign-keys rewrites and
/// deletes it). A record of another context, an unscoped record, or a revoked
/// one is never returned, so a public key someone copied into their own
/// document cannot reach a record they do not own.
pub async fn find_key_by_public_multibase_in_context(
    keys_ks: &KeyspaceHandle,
    public_key: &str,
    context_id: &str,
) -> Result<Option<KeyRecord>, AppError> {
    for (_, value) in keys_ks.prefix_iter_raw("key:").await? {
        let Ok(record) = serde_json::from_slice::<KeyRecord>(&value) else {
            continue;
        };
        if record.public_key == public_key
            && record.status == KeyStatus::Active
            && record.context_id.as_deref() == Some(context_id)
        {
            return Ok(Some(record));
        }
    }
    Ok(None)
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
        audit: vta_audit::SharedAuditSink,
        imported_ks: KeyspaceHandle,
        internal_ks: KeyspaceHandle,
        acl_ks: KeyspaceHandle,
        sessions_ks: KeyspaceHandle,
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
            let audit: vta_audit::SharedAuditSink =
                vta_audit::shared_keyspace_sink(store.keyspace(crate::keyspaces::AUDIT).unwrap());
            let imported_ks = store.keyspace(crate::keyspaces::IMPORTED_SECRETS).unwrap();
            let internal_ks = store.keyspace(crate::keyspaces::INTERNAL_KEYS).unwrap();
            let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
            let sessions_ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();

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
                audit,
                imported_ks,
                internal_ks,
                acl_ks,
                sessions_ks,
                seed_store,
                _dir: dir,
            }
        }

        /// Admin of `test-ctx` and nothing else — the entitlement that may
        /// impose the export restriction but must not be able to lift it.
        fn context_admin_auth(&self) -> AuthClaims {
            AuthClaims {
                did: "did:key:z6MkCtxAdmin".to_string(),
                role: Role::Admin,
                allowed_contexts: vec!["test-ctx".to_string()],
                session_id: "ctx-admin-session".into(),
                access_expires_at: 0,
                issued_at: 0,
                amr: Vec::new(),
                acr: String::new(),
            }
        }

        fn super_admin_auth(&self) -> AuthClaims {
            AuthClaims {
                did: "did:key:z6MkTestAdmin".to_string(),
                role: Role::Admin,
                allowed_contexts: vec![], // empty = super admin
                session_id: "test-session".into(),
                access_expires_at: 0,
                issued_at: 0,
                amr: Vec::new(),
                acr: String::new(),
            }
        }
    }

    /// VTI-KEY-032 (found alongside FTL-29904): a context-scoped admin must not
    /// make the VTA derive a key outside its own context's subtree. The target
    /// here is the VTA's own `did:webvh` update-key path. Before the fix
    /// `create_key` accepted it, recorded the key under the caller's context,
    /// and `get_key_secret`'s scope check, which reads that context, then
    /// released the VTA's private key.
    #[tokio::test]
    async fn vti_key_032_context_admin_cannot_derive_outside_its_context() {
        let h = TestHarness::new().await;
        let super_admin = h.super_admin_auth();
        let tenant = h.context_admin_auth();

        let victim = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &super_admin,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/0'/0'/0'".into()),
                key_id: Some("vta-update-key".into()),
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .expect("super-admin creates the VTA's own key");

        let attempt = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &tenant,
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: Some("m/26'/0'/0'/0'".into()),
                key_id: Some("innocuous".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await;
        assert!(
            matches!(attempt, Err(AppError::Forbidden(_))),
            "a context admin must not choose a derivation path, got {:?}",
            attempt.map(|c| c.public_key == victim.public_key)
        );

        // Defence in depth (custody rule 6): a record already planted this way,
        // by a build before the fix or through a restore, is inert. It can be
        // neither exported nor used to sign, even by its own context's admin.
        let now = chrono::Utc::now();
        let planted = KeyRecord {
            key_id: "planted".into(),
            derivation_path: "m/26'/0'/0'/0'".into(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: victim.public_key.clone(),
            label: None,
            context_id: Some("test-ctx".into()),
            exportable: None,
            seed_id: None,
            origin: KeyOrigin::Derived,
            created_at: now,
            updated_at: now,
        };
        h.keys_ks
            .insert(keys::store_key("planted"), &planted)
            .await
            .unwrap();
        let export = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &tenant,
            "planted",
            ExportChannel::Local("test"),
        )
        .await;
        assert!(
            matches!(export, Err(AppError::Forbidden(_))),
            "export: {export:?}"
        );
        let sign = sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &tenant,
            "planted",
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
            "test",
        )
        .await;
        assert!(
            matches!(sign, Err(AppError::Forbidden(_))),
            "sign: {sign:?}"
        );
    }

    /// `keys/derive-and-sign` lets the caller pick the identity it signs as, so
    /// it is super-admin only and confined to the delegated subtree: a tenant
    /// admin cannot sign as the VTA (or anyone else) through it.
    #[tokio::test]
    async fn derive_and_sign_refuses_a_context_admin_and_foreign_paths() {
        let h = TestHarness::new().await;
        let sign = async |auth: &AuthClaims, path: &str| {
            derive_and_sign(
                &h.keys_ks,
                &h.acl_ks,
                &h.seed_store,
                auth,
                &h.audit,
                &KeyType::Ed25519,
                path,
                b"x",
                &SignAlgorithm::EdDSA,
                "test",
            )
            .await
        };
        let tenant = h.context_admin_auth();
        let admin = h.super_admin_auth();
        assert!(matches!(
            sign(&tenant, "m/26'/9'/0'").await,
            Err(AppError::Forbidden(_))
        ));
        // The VTA's did:webvh update-key path: refused even for a super-admin.
        assert!(matches!(
            sign(&admin, "m/26'/0'/0'/0'").await,
            Err(AppError::Forbidden(_))
        ));
        assert!(sign(&admin, "m/26'/9'/0'").await.is_ok());
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
            &h.audit,
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
            &h.audit,
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
                &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
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
            &h.audit,
            &auth,
            &key.key_id,
            payload,
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
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
                &h.acl_ks,
                &h.seed_store,
                &non_admin,
                &h.audit,
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
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
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
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
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
                &h.acl_ks,
                &h.seed_store,
                &non_admin,
                &h.audit,
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
            &h.audit,
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
            issued_at: 0,
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
            &h.audit,
            &scoped,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
            &admin,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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
            &h.audit,
            &scoped,
            &allowed.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
                &h.audit,
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
            issued_at: 0,
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
                    &h.audit,
                    &claims,
                    key_id,
                    b"payload",
                    &SignAlgorithm::EdDSA,
                    SigningDomain::Opaque,
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
            &h.audit,
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
            issued_at: 0,
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
            &h.audit,
            &claims,
            &foreign.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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
            &h.audit,
            &admin,
            &unscoped.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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
            issued_at: 0,
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
            &h.audit,
            &other_tenant,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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
            &h.audit,
            &other_tenant,
            &own.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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
            issued_at: 0,
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
            &h.audit,
            &scoped,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
            &admin,
            &key.key_id,
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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
            issued_at: 0,
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
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        get_key(&h.keys_ks, &reader, &key.key_id, "test")
            .await
            .expect("reader-role caller can get_key");
    }
    // ── internal (non-extractable) keys ──────────────────────────────

    /// An ordinary derived key in `test-ctx` — the scope `context_admin_auth`
    /// administers, so the exportability tests exercise a real context admin
    /// rather than borrowing super-admin authority.
    async fn mint_derived(h: &TestHarness, key_id: &str) -> KeyRecord {
        create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some(key_id.to_string()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".to_string()),
            },
            "test",
        )
        .await
        .expect("mint derived key");
        h.keys_ks
            .get(keys::store_key(key_id))
            .await
            .expect("read back")
            .expect("the record exists")
    }

    async fn mint_internal(h: &TestHarness, key_id: &str) -> CreateKeyResultBody {
        create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
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
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-internal",
            ExportChannel::Local("test"),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
            "a super-admin must still be refused; got {err:?}"
        );
    }

    // ── exportability ────────────────────────────────────────────────
    //
    // The member's whole value is that the two directions are not equally easy
    // to travel. These assert the relation, not just each end of it.

    /// A key created the ordinary way carries no opinion, and absence reads as
    /// exportable — the compatibility guarantee for every record written before
    /// the member existed.
    #[tokio::test]
    async fn a_key_is_exportable_until_someone_says_otherwise() {
        let h = TestHarness::new().await;
        let created = mint_derived(&h, "k-open").await;
        assert_eq!(
            created.exportable, None,
            "a new key records no decision; `Some(true)` would be a claim nobody made"
        );

        get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-open",
            ExportChannel::Local("test"),
        )
        .await
        .expect("absence must read as exportable");
    }

    /// The restriction bites at the one place a private key leaves the VTA.
    #[tokio::test]
    async fn a_restricted_key_is_never_exported() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-shut").await;

        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-shut",
            false,
            "test",
        )
        .await
        .expect("a context admin may impose the restriction");

        let err = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-shut",
            ExportChannel::Local("test"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("non-exportable")),
            "even a super-admin is refused the material; got {err:?}"
        );
    }

    /// The asymmetry itself. The same claim that imposed the restriction must
    /// not be able to lift it — otherwise the restriction protects against
    /// accident but not against a compromised caller holding that claim, which
    /// is the case it exists for.
    #[tokio::test]
    async fn the_admin_that_restricted_a_key_cannot_release_it_again() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-asym").await;
        let admin = h.context_admin_auth();

        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &admin,
            "k-asym",
            false,
            "test",
        )
        .await
        .expect("imposing is the cheap direction");

        let err = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &admin,
            "k-asym",
            true,
            "test",
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m)
                if m.contains("super-admin") && m.contains("step-up")),
            "the refusal must name both routes, or a caller cannot tell which is \
             open to it; got {err:?}"
        );
    }

    /// Super-admin is one of the two ways past that gate.
    #[tokio::test]
    async fn a_super_admin_can_release_a_restricted_key() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-reopen").await;

        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-reopen",
            false,
            "test",
        )
        .await
        .expect("restrict");

        let record = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.super_admin_auth(),
            "k-reopen",
            true,
            "test",
        )
        .await
        .expect("a super-admin holds strictly more than the context admin that restricted it");
        assert_eq!(record.exportable, Some(true));

        get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-reopen",
            ExportChannel::Local("test"),
        )
        .await
        .expect("and the key exports again");
    }

    /// Only a real `false` -> `true` transition meets the stronger gate.
    /// Setting `true` on an already-exportable key takes nothing away, so
    /// gating it would demand super-admin for a no-op — and would make a
    /// retried request harder to complete than the original.
    #[tokio::test]
    async fn re_asserting_exportable_on_an_open_key_is_not_gated() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-noop").await;

        let record = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-noop",
            true,
            "test",
        )
        .await
        .expect("a context admin may confirm what is already true");
        assert_eq!(record.exportable, Some(true));
    }

    /// Idempotent in the other direction too: `exportable` is an absolute
    /// state, so a producer retrying a lost `false` lands on `false` rather
    /// than toggling back.
    #[tokio::test]
    async fn restricting_twice_stays_restricted() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-twice").await;
        let admin = h.context_admin_auth();

        for _ in 0..2 {
            let record = set_key_exportability(
                &h.keys_ks,
                &h.sessions_ks,
                &h.audit,
                &admin,
                "k-twice",
                false,
                "test",
            )
            .await
            .expect("a repeat is a no-op, not a toggle");
            assert_eq!(record.exportable, Some(false));
        }
    }

    /// Scope still applies: an admin of another context reaches nothing here,
    /// the same rule the export path enforces.
    #[tokio::test]
    async fn an_admin_of_another_context_cannot_set_exportability() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-scope").await;
        let mut elsewhere = h.context_admin_auth();
        elsewhere.allowed_contexts = vec!["some-other-ctx".to_string()];

        let err = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &elsewhere,
            "k-scope",
            false,
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got: {err:?}");
    }

    /// An internal key can never be released, so asking for that is a
    /// precondition failure rather than a permission one — retrying with more
    /// authority changes nothing, and `Forbidden` would send the operator
    /// looking for authority that does not exist.
    #[tokio::test]
    async fn an_internal_key_cannot_be_made_exportable() {
        let h = TestHarness::new().await;
        mint_internal(&h, "k-internal").await;

        let err = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.super_admin_auth(),
            "k-internal",
            true,
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("internal key")),
            "got: {err:?}"
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
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
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

    /// A revoked record — a key a rotation retired, or a rotation's inert
    /// staging record — is kept for history only: the VTA's own loads do not
    /// release its private half. (The export surface refuses it too; that half
    /// is tested with the export gate.)
    #[tokio::test]
    async fn a_revoked_key_is_not_loaded() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-retired").await;
        let mut record: KeyRecord = h
            .keys_ks
            .get(keys::store_key("k-retired"))
            .await
            .unwrap()
            .unwrap();
        record.status = KeyStatus::Revoked;
        h.keys_ks
            .insert(keys::store_key("k-retired"), &record)
            .await
            .unwrap();

        let err = get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-retired",
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not active")),
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
            &h.audit,
            &h.super_admin_auth(),
            "k-sign",
            b"payload",
            &SignAlgorithm::EdDSA,
            SigningDomain::Opaque,
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
            &h.audit,
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

    // ── the export and signing gates, on every channel ───────────────
    //
    // Phase 0 of the key-roles work: the `key-export` gate used to live in the
    // `keys/export-secret` Trust-Task handler alone, so `GET /keys/{id}/secret`
    // and DIDComm `get-key-secret` released keys to an admin narrowed without
    // it; and `sign` was never checked anywhere. Both now live in the
    // operation, and these tests hold them there for every channel a transport
    // can state.

    /// A sink that keeps what it is given — or refuses everything.
    struct RecordingSink {
        rows: Mutex<Vec<vta_sdk::protocols::audit_management::list::AuditLogEntry>>,
        refuse: bool,
    }

    #[async_trait::async_trait]
    impl vta_audit::AuditSink for RecordingSink {
        async fn record(
            &self,
            entry: &vta_sdk::protocols::audit_management::list::AuditLogEntry,
        ) -> Result<(), AppError> {
            if self.refuse {
                return Err(AppError::Internal("audit sink unavailable".into()));
            }
            self.rows.lock().await.push(entry.clone());
            Ok(())
        }
    }

    fn recording_sink(refuse: bool) -> Arc<RecordingSink> {
        Arc::new(RecordingSink {
            rows: Mutex::new(Vec::new()),
            refuse,
        })
    }

    /// Every channel a caller can state, with the audit name each records.
    fn every_channel() -> [ExportChannel<'static>; 4] {
        [
            ExportChannel::EndToEnd("didcomm"),
            ExportChannel::Sealed("provision-integration"),
            ExportChannel::Local("cli"),
            ExportChannel::HopByHop("rest"),
        ]
    }

    /// Store an ACL entry for `auth` — an admin of `test-ctx` narrowed to
    /// `capabilities` — so the gates read it, as they do for every live caller.
    async fn store_narrowed(h: &TestHarness, auth: &AuthClaims, capabilities: Vec<Capability>) {
        vti_common::acl::store_acl_entry(
            &h.acl_ks,
            &vti_common::acl::AclEntry::new(&auth.did, auth.role.clone(), "did:key:zRoot")
                .with_contexts(auth.allowed_contexts.clone())
                .with_capabilities(capabilities),
        )
        .await
        .expect("store the caller's entry");
    }

    async fn export(
        h: &TestHarness,
        audit: &vta_audit::SharedAuditSink,
        auth: &AuthClaims,
        key_id: &str,
        channel: ExportChannel<'_>,
    ) -> Result<GetKeySecretResultBody, AppError> {
        get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            audit,
            auth,
            key_id,
            channel,
        )
        .await
    }

    /// VTI-VTA-003: an admin narrowed without `key-export` is refused on every
    /// channel — REST and DIDComm included, which is where it used to pass —
    /// and the refusal names the capability and the fix. Nothing is recorded
    /// as exported.
    #[tokio::test]
    async fn vti_vta_003_export_without_key_export_is_refused_on_every_channel() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-gated").await;
        let auth = h.context_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::Sign, Capability::KeyMint]).await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();

        for channel in every_channel() {
            let err = export(&h, &audit, &auth, "k-gated", channel)
                .await
                .expect_err("narrowed away, key-export is gone on every transport");
            assert!(
                matches!(&err, AppError::Forbidden(m)
                    if m.contains("key-export")
                        && m.contains("--capabilities sign,key-mint,key-export")),
                "{channel:?}: {err:?}"
            );
        }
        assert!(
            sink.rows.lock().await.is_empty(),
            "a refused export must not be recorded as one"
        );
    }

    /// The gate runs before the lookup: a caller without `key-export` gets the
    /// same refusal for a key that exists and one that does not.
    #[tokio::test]
    async fn the_export_gate_does_not_reveal_which_keys_exist() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-real").await;
        let auth = h.context_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::Sign]).await;
        let real = export(&h, &h.audit, &auth, "k-real", ExportChannel::Local("t"))
            .await
            .unwrap_err()
            .to_string();
        let imaginary = export(&h, &h.audit, &auth, "k-none", ExportChannel::Local("t"))
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(real, imaginary);
    }

    /// `keys/export-secret/0.1`: the exchange must be confidential to the two
    /// parties. An entitled caller asking over a hop-by-hop channel is refused,
    /// told how to succeed, and nothing is released or recorded.
    #[tokio::test]
    async fn an_export_over_a_hop_by_hop_channel_is_refused_even_when_entitled() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-tls").await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();

        let err = export(
            &h,
            &audit,
            &h.super_admin_auth(),
            "k-tls",
            ExportChannel::HopByHop("rest"),
        )
        .await
        .expect_err("REST never carries a private key");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("DIDComm or TSP")),
            "the refusal must say which transports work: {err:?}"
        );
        assert!(sink.rows.lock().await.is_empty());

        export(
            &h,
            &audit,
            &h.super_admin_auth(),
            "k-tls",
            ExportChannel::EndToEnd("didcomm"),
        )
        .await
        .expect("the same caller succeeds end to end");
    }

    /// A key marked non-exportable, and an internal key, are refused on every
    /// channel that could otherwise release them — to a super-admin, with
    /// `key-export`.
    #[tokio::test]
    async fn non_exportable_and_internal_keys_are_refused_on_every_channel() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-locked").await;
        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-locked",
            false,
            "test",
        )
        .await
        .expect("restrict");
        mint_internal(&h, "k-inside").await;

        for channel in every_channel() {
            if matches!(channel, ExportChannel::HopByHop(_)) {
                // Refused before the key is read at all — asserted above.
                continue;
            }
            let err = export(&h, &h.audit, &h.super_admin_auth(), "k-locked", channel)
                .await
                .expect_err("non-exportable");
            assert!(
                matches!(&err, AppError::Forbidden(m) if m.contains("non-exportable")),
                "{channel:?}: {err:?}"
            );
            let err = export(&h, &h.audit, &h.super_admin_auth(), "k-inside", channel)
                .await
                .expect_err("internal");
            assert!(
                matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
                "{channel:?}: {err:?}"
            );
        }
    }

    /// VTI-VTA-003 "and MUST be audited": a successful export leaves one
    /// durable `key.secret_export` row naming who, which key, its context and
    /// the transport — and never the material.
    #[tokio::test]
    async fn vti_vta_003_a_successful_export_writes_a_durable_audit_row() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-audited").await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();
        let auth = h.context_admin_auth();

        let released = export(
            &h,
            &audit,
            &auth,
            "k-audited",
            ExportChannel::EndToEnd("trust-task/tsp"),
        )
        .await
        .expect("an admin of the key's context exports it end to end");

        let rows = sink.rows.lock().await;
        let exports: Vec<_> = rows
            .iter()
            .filter(|r| r.action == "key.secret_export")
            .collect();
        assert_eq!(exports.len(), 1, "exactly one export row: {rows:?}");
        let row = exports[0];
        assert_eq!(row.actor, auth.did);
        assert_eq!(row.resource.as_deref(), Some("k-audited"));
        assert_eq!(row.context_id.as_deref(), Some("test-ctx"));
        assert_eq!(row.channel.as_deref(), Some("trust-task/tsp"));
        assert_eq!(row.outcome, "success");
        let serialized = serde_json::to_string(row).unwrap();
        assert!(
            !serialized.contains(&released.private_key_multibase),
            "the audit row must never carry the key material"
        );
    }

    /// The row is a precondition of the release: a sink that cannot record
    /// means no key leaves.
    #[tokio::test]
    async fn an_export_that_cannot_be_audited_is_refused() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-unrecorded").await;
        let audit: vta_audit::SharedAuditSink = recording_sink(true);

        let err = export(
            &h,
            &audit,
            &h.super_admin_auth(),
            "k-unrecorded",
            ExportChannel::Local("cli"),
        )
        .await
        .expect_err("an unrecorded export is not permitted");
        assert!(
            matches!(&err, AppError::Internal(m) if m.contains("VTI-VTA-003")),
            "{err:?}"
        );
    }

    async fn sign_as(
        h: &TestHarness,
        auth: &AuthClaims,
        key_id: &str,
        domain: SigningDomain,
    ) -> Result<SignResultBody, AppError> {
        sign_payload(
            &h.keys_ks,
            &h.imported_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            auth,
            key_id,
            b"hello",
            &SignAlgorithm::EdDSA,
            domain,
            "test",
        )
        .await
    }

    /// VTI-VTA-003 / VTI-VTA-007: `sign` is the capability to use a key through
    /// the generic oracle. An entry narrowed without it is refused opaque
    /// signing — which, before, the role floor let straight through.
    #[tokio::test]
    async fn vti_vta_007_opaque_signing_without_sign_is_refused() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-sign").await;
        let auth = h.context_admin_auth();

        sign_as(&h, &auth, "k-sign", SigningDomain::Opaque)
            .await
            .expect("an un-narrowed admin derives sign");

        store_narrowed(&h, &auth, vec![Capability::KeyExport]).await;
        let err = sign_as(&h, &auth, "k-sign", SigningDomain::Opaque)
            .await
            .expect_err("narrowed away, sign is gone");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("sign capability")),
            "{err:?}"
        );
        // Before the lookup: an id that does not exist is refused the same way.
        let absent = sign_as(&h, &auth, "k-none", SigningDomain::Opaque)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), absent.to_string());
    }

    /// VTI-VTA-007 the other way round: a constrained grant must not need the
    /// general one. Protocol-defined input is built inside the VTA by an
    /// operation that applied its own capability, so `sign` is not demanded.
    #[tokio::test]
    async fn vti_vta_007_protocol_defined_signing_does_not_need_sign() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-room").await;
        let auth = h.context_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::CredentialWrite]).await;

        sign_as(&h, &auth, "k-room", SigningDomain::ProtocolDefined)
            .await
            .expect("a credential-write grant signs its own documents without sign");
    }

    /// The ephemeral oracles take caller bytes too, so they need `sign` — even
    /// from a super-admin, when its entry was narrowed without it.
    #[tokio::test]
    async fn derive_and_sign_without_sign_is_refused() {
        let h = TestHarness::new().await;
        let auth = h.super_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::KeyExport]).await;

        let err = derive_and_sign(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            b"hello",
            &SignAlgorithm::EdDSA,
            "test",
        )
        .await
        .expect_err("no sign");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("sign capability")),
            "{err:?}"
        );

        let err = derive_and_sign_document(
            &h.keys_ks,
            &h.acl_ks,
            &h.seed_store,
            &auth,
            &h.audit,
            &KeyType::Ed25519,
            "m/26'/9'/0'",
            serde_json::json!({ "a": 1 }),
            None,
            "test",
        )
        .await
        .expect_err("no sign");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("sign capability")),
            "{err:?}"
        );
    }

    /// The VTA's own use of a key is recorded as `key.internal_use`, never as
    /// an export — so `key.secret_export` rows are exactly the keys that left.
    #[tokio::test]
    async fn internal_use_is_not_recorded_as_an_export() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-used").await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();
        get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-used",
            "test",
        )
        .await
        .expect("internal load");
        let rows = sink.rows.lock().await;
        assert!(
            rows.iter().any(|r| r.action == "key.internal_use"),
            "{rows:?}"
        );
        assert!(
            !rows.iter().any(|r| r.action == "key.secret_export"),
            "internal use must not read as an export: {rows:?}"
        );
    }

    /// A P-256 key's stored public key is the multicodec form (`p256-pub`),
    /// identical to what custody publishes when the key is exported — one
    /// encoding across record, export and document.
    #[tokio::test]
    async fn p256_record_and_export_agree_on_the_multicodec_public_key() {
        let h = TestHarness::new().await;
        let created = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: false,
                key_type: KeyType::P256,
                derivation_path: None,
                key_id: Some("k-p256".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("mint P-256");
        let (_, bytes) = multibase::decode(&created.public_key).unwrap();
        assert!(bytes.starts_with(KeyType::P256.multicodec_public()));
        assert_eq!(bytes.len(), 2 + 33);

        let exported = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-p256",
            ExportChannel::Local("test"),
        )
        .await
        .expect("export");
        assert_eq!(exported.public_key_multibase, created.public_key);
    }

    /// Scope before existence: a caller restricted to `test-ctx` gets one
    /// refusal for a key in another context and for a key that does not
    /// exist — naming neither — on both the export and the signing oracle.
    #[tokio::test]
    async fn out_of_scope_and_absent_keys_are_indistinguishable() {
        let h = TestHarness::new().await;
        create_context(&h.contexts_ks, "other-ctx", "Other")
            .await
            .unwrap();
        create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("k-elsewhere".into()),
                mnemonic: None,
                label: None,
                context_id: Some("other-ctx".into()),
            },
            "test",
        )
        .await
        .unwrap();
        let auth = h.context_admin_auth();
        let refuse = |id: &'static str| {
            let h = &h;
            let auth = auth.clone();
            async move {
                let e = export(h, &h.audit, &auth, id, ExportChannel::Local("t"))
                    .await
                    .unwrap_err()
                    .to_string();
                let s = sign_as(h, &auth, id, SigningDomain::Opaque)
                    .await
                    .unwrap_err()
                    .to_string();
                (e.replace(id, "<id>"), s.replace(id, "<id>"))
            }
        };
        let real = refuse("k-elsewhere").await;
        let absent = refuse("k-nowhere").await;
        assert_eq!(real, absent);
        assert!(
            !real.0.contains("other-ctx"),
            "must not name the key's context: {real:?}"
        );
    }

    /// A revoked key's private half is not released, and internal authority
    /// does not load it for use either.
    #[tokio::test]
    async fn revoked_keys_are_neither_exported_nor_loaded() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-gone").await;
        revoke_key(
            &h.keys_ks,
            &h.imported_ks,
            &h.audit,
            &h.super_admin_auth(),
            "k-gone",
            "test",
        )
        .await
        .expect("revoke");
        let err = export(
            &h,
            &h.audit,
            &h.super_admin_auth(),
            "k-gone",
            ExportChannel::Local("t"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not active")),
            "{err:?}"
        );
        let err = get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-gone",
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not active")),
            "{err:?}"
        );
    }
}
