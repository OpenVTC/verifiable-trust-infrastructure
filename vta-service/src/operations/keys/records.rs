//! Key records: create, import, read, list, rename, revoke, and the lookups by
//! public key.

use super::*;

/// Key records one page of a `keys/list` scan reads from the store (#2627).
pub(super) const LIST_SCAN_PAGE: usize = 256;

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
    /// The previous page's `nextCursor`.
    pub cursor: Option<String>,
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
pub(super) async fn create_internal_key(
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
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: CreateKeyParams,
    channel: &str,
) -> Result<CreateKeyResultBody, AppError> {
    // `KeyMint` decides *whether* (Keyring VTI-23); the context resolution
    // below decides *where*. First, so a refused caller learns nothing about
    // which contexts or key ids exist.
    ensure_may_mint_key(acl_ks, auth, "keys/create").await?;

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
            crate::operations::key_custody::authorize_explicit_key_path(
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

    // Keyset pagination (`keys/list/0.2`): records in `key_id` order, a page
    // resuming strictly after the last id the previous one returned, under the
    // filters its cursor was minted for. A cursor this VTA did not issue for
    // these filters is refused rather than guessed at.
    let filters = list_cursor_filters(&params);
    let after = match params.cursor.as_deref() {
        Some(cursor) => Some(open_list_cursor(cursor, &filters).ok_or_else(|| {
            AppError::Validation(
                "keys/list: the cursor was not issued by this VTA for these filters; list \
                 again from the first page"
                    .into(),
            )
        })?),
        None => None,
    };
    let limit = usize::try_from(params.limit.unwrap_or(50)).unwrap_or(usize::MAX);

    // Rows are `key:{key_id}`, so storage order is `key_id` order: a page is a
    // range read from the cursor that stops once one more record than the page
    // passes the filters (#2627) — not every key record decoded and sorted per
    // page, which made walking the list quadratic and, over vsock, one frame
    // that stops fitting.
    let mut opts = ScanOpts::new("key:", LIST_SCAN_PAGE);
    if let Some(after) = &after {
        opts = opts.after(format!("key:{after}"));
    }
    let mut pages = keys_ks.scan_pager(opts);
    let mut records: Vec<KeyRecord> = Vec::new();
    let mut skipped = 0usize;
    'scan: loop {
        let page = pages.next_page().await?;
        if page.is_empty() {
            break;
        }
        for (key, value) in page {
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
            // The row's key names the id the cursor resumes after; a record whose
            // `key_id` disagreed with its row would otherwise be served out of order.
            if let Some(after) = &after
                && record.key_id <= *after
            {
                continue;
            }
            records.push(record);
            if records.len() > limit {
                break 'scan;
            }
        }
    }
    if skipped > 0 {
        tracing::warn!(channel, skipped, "list_keys skipped corrupt rows");
    }

    records.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = more
        .then(|| records.last().map(|r| list_cursor(&filters, &r.key_id)))
        .flatten();

    info!(channel, caller = %auth.did, count = records.len(), more, "keys listed");

    Ok(ListKeysResultBody {
        keys: records,
        next_cursor,
    })
}

/// The filters of a `keys/list` request, as its cursor binds them.
pub(super) fn list_cursor_filters(params: &ListKeysParams) -> String {
    let status = params
        .status
        .as_ref()
        .and_then(|s| serde_json::to_value(s).ok())
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({ "status": status, "contextId": params.context_id }).to_string()
}

pub(super) fn list_filter_digest(filters: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(filters.as_bytes())[..8])
}

/// `k1.<filter digest>.<base64url of the last key id returned>`.
pub(super) fn list_cursor(filters: &str, last_key_id: &str) -> String {
    use base64::Engine as _;
    format!(
        "k1.{}.{}",
        list_filter_digest(filters),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(last_key_id)
    )
}

/// The key id a cursor resumes after, or `None` for one these filters were
/// not given.
pub(super) fn open_list_cursor(cursor: &str, filters: &str) -> Option<String> {
    use base64::Engine as _;
    let rest = cursor.strip_prefix("k1.")?;
    let (digest, id) = rest.split_once('.')?;
    if digest != list_filter_digest(filters) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id)
        .ok()?;
    String::from_utf8(raw).ok().filter(|s| !s.is_empty())
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
    reason: Option<&str>,
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
    // The operator's `reason` (keys/revoke/0.1) goes into the audit row's
    // detail, as an ACL revocation's does (#2583).
    audit::record_with_detail_best_effort(
        audit,
        "key.revoke",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
        reason,
    )
    .await;

    Ok(RevokeKeyResultBody {
        key_id: key_id.to_string(),
        status: record.status,
        updated_at: record.updated_at,
    })
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
    use crate::auth::AuthClaims;
    use crate::operations::keys::test_support::*;
    use vti_common::acl::Role;

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
            &h.acl_ks,
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
            &h.acl_ks,
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
                &h.acl_ks,
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
            &h.acl_ks,
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
            &h.acl_ks,
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
            &h.acl_ks,
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
            &h.acl_ks,
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
                cursor: None,
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
}
