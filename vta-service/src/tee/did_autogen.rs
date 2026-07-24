//! Auto-generate VTA did:webvh identity on first boot in TEE mode.
//!
//! When `tee.kms.vta_did_template` is configured, the VTA generates its own
//! did:webvh identity on first boot using the KMS-bootstrapped seed. The DID
//! is persisted in the encrypted store and the did.jsonl log entry is written
//! to disk for the operator to upload to their WebVH server.
//!
//! On subsequent boots, the DID is restored from the store.

use std::sync::Arc;

use didwebvh_rs::create::{CreateDIDConfig, create_did};
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use serde_json::json;
use tracing::info;

use crate::config::AppConfig;
use crate::contexts;
use crate::error::AppError;
use crate::keys;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::store::{KeyspaceHandle, Store};

/// Well-known store key for the auto-generated VTA DID.
const VTA_DID_STORE_KEY: &str = "tee:vta_did";

/// Build the `WebvhDidRecord` for the auto-generated serverless VTA DID.
///
/// `webvh_store` keys the record (`did:{did}`) and the log (`log:{did}`)
/// separately. `list_services` (and did update/rotate ops) require the record
/// via `webvh_store::get_did`; without it `GET /services` 500s with
/// `VtaDidRecordMissing` even though the log resolves and
/// `/.well-known/did.jsonl` serves fine. Mirrors the production
/// `create_did_webvh` (final mode) builder: defensive defaults for the
/// key-count fields — the next rotate/update re-scans the log and persists the
/// corrected values. The SCID is the third colon-segment of a
/// `did:webvh:{SCID}:{host}` identifier.
#[cfg(feature = "webvh")]
fn build_vta_webvh_record(did: &str) -> vta_sdk::webvh::WebvhDidRecord {
    let scid = did.split(':').nth(2).unwrap_or_default().to_string();
    let now = chrono::Utc::now();
    vta_sdk::webvh::WebvhDidRecord {
        did: did.to_string(),
        server_id: "serverless".to_string(),
        mnemonic: String::new(),
        scid,
        context_id: "vta".to_string(),
        portable: true,
        log_entry_count: 1,
        pre_rotation_count: 0,
        next_fragment_id: 1,
        created_at: now,
        updated_at: now,
    }
}

/// Check for an existing DID in the store, or auto-generate one from the template.
///
/// Sets `config.vta_did` on success (either from store or newly generated).
/// Returns `Ok(())` on success or if no template is configured (no-op).
pub async fn maybe_generate_vta_did(
    config: &mut AppConfig,
    seed_store: &dyn SeedStore,
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
) -> Result<(), AppError> {
    // Guard: already configured in config.toml
    if config.vta_did.is_some() {
        return Ok(());
    }

    // Guard: no KMS config or no template
    let kms_config = match &config.tee.kms {
        Some(kms) if kms.vta_did_template.is_some() => kms.clone(),
        _ => return Ok(()),
    };
    let template = kms_config.vta_did_template.as_ref().unwrap();

    // Open encrypted keyspaces
    let apply_enc = |ks: KeyspaceHandle| -> KeyspaceHandle {
        if let Some(key) = storage_encryption_key {
            ks.with_encryption(key)
        } else {
            ks
        }
    };
    let keys_ks = apply_enc(store.keyspace(crate::keyspaces::KEYS)?);
    let contexts_ks = apply_enc(store.keyspace(crate::keyspaces::CONTEXTS)?);

    // Check if DID already exists in the store (subsequent boot)
    if let Some(did_bytes) = keys_ks.get_raw(VTA_DID_STORE_KEY).await? {
        let did = String::from_utf8(did_bytes)
            .map_err(|e| AppError::Internal(format!("corrupt stored VTA DID: {e}")))?;
        info!(did = %did, "restored VTA identity from encrypted store");

        // Backfill the webvh DID *record* if an earlier build persisted only
        // the log (`log:{did}`) but not the record (`did:{did}`). Idempotent:
        // only writes when the record is absent, so a rebuild+reboot repairs
        // `list_services` for an already-generated DID without wiping state
        // (which would rotate the DID). See `build_vta_webvh_record`.
        #[cfg(feature = "webvh")]
        {
            let webvh_ks = apply_enc(store.keyspace(crate::keyspaces::WEBVH)?);
            if crate::webvh_store::get_did(&webvh_ks, &did).await?.is_none() {
                let record = build_vta_webvh_record(&did);
                crate::webvh_store::store_did(&webvh_ks, &record).await?;
                store.persist().await?;
                info!(did = %did, "backfilled missing webvh DID record on restore");
            }
        }

        config.vta_did = Some(did);
        return Ok(());
    }

    // First boot: generate the DID
    info!(template = %template, "auto-generating VTA did:webvh identity from template");

    // Load seed
    let active_seed_id = get_active_seed_id(&keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(&keys_ks, seed_store, Some(active_seed_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Create or get the "vta" context
    let ctx = match contexts::get_context(&contexts_ks, "vta").await? {
        Some(ctx) => ctx,
        None => contexts::create_context(&contexts_ks, "vta", "VTA Identity")
            .await
            .map_err(|e| AppError::Internal(format!("failed to create VTA context: {e}")))?,
    };

    // Derive entity keys
    let mut derived = keys::derive_entity_keys(
        &seed,
        &ctx.base_path,
        "VTA signing key",
        "VTA key-agreement key",
        &keys_ks,
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Derive the VTA's third key — `{vta_did}#sealed-transfer-0` — used
    // only for sealed-transfer producer assertions. Kept separate from
    // `#key-0` (VC issuance) so a compromise of one doesn't void the
    // other and each can rotate independently. See
    // `operations::provision_integration::build_did_signed_assertion`.
    let sealed_transfer = keys::derive_sealed_transfer_key(
        &seed,
        &ctx.base_path,
        "VTA sealed-transfer producer-assertion key",
        &keys_ks,
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Convert signing key ID to did:key format (required by didwebvh-rs)
    let signing_pub_mb = derived
        .signing_secret
        .get_public_keymultibase()
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    derived.signing_secret.id = format!("did:key:{signing_pub_mb}#{signing_pub_mb}");

    // Parse the template to get the URL for didwebvh-rs.
    // Template: "did:webvh:{SCID}:example.com:vta"
    // URL:      "https://example.com/vta"
    let url_str = template_to_url(template)?;

    // Build DID document (inline — avoids dependency on webvh feature-gated modules)
    let did_document = build_vta_did_document(&derived, &sealed_transfer, config);

    // Generate pre-rotation keys (default: 1)
    let (next_key_hashes, pre_rotation_keys) =
        crate::operations::did_webvh::derive_pre_rotation_keys(
            &seed,
            &ctx.base_path,
            "VTA",
            &keys_ks,
            1,
        )
        .await?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone().into()])),
        portable: Some(true),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(
                next_key_hashes.into_iter().map(Into::into).collect(),
            ))
        },
        ..Default::default()
    };

    // Create the DID
    let create_config = CreateDIDConfig::builder()
        .address(&url_str)
        .authorization_key(derived.signing_secret.clone())
        .did_document(did_document)
        .parameters(parameters)
        .build()
        .map_err(|e| AppError::Internal(format!("failed to build DID config: {e}")))?;

    let result = create_did(create_config)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create DID: {e}")))?;

    let final_did = result.did().to_string();
    let scid = result
        .log_entry()
        .get_scid()
        .unwrap_or_default()
        .to_string();
    let log_content = serde_json::to_string(result.log_entry())
        .map_err(|e| AppError::Internal(format!("failed to serialize DID log: {e}")))?;

    // Save key records
    keys::save_entity_key_records(
        &final_did,
        &derived,
        &keys_ks,
        Some("vta"),
        Some(active_seed_id),
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Save the sealed-transfer key at `{vta_did}#sealed-transfer-0`.
    keys::save_sealed_transfer_key_record(
        &final_did,
        &sealed_transfer,
        &keys_ks,
        Some("vta"),
        Some(active_seed_id),
    )
    .await
    .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Save pre-rotation key records
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            &keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            keys::KeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some("vta"),
            Some(active_seed_id),
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    // Update context with the new DID
    let mut ctx = ctx;
    ctx.did = Some(final_did.clone());
    ctx.updated_at = chrono::Utc::now();
    contexts::store_context(&contexts_ks, &ctx)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Persist the DID in a well-known key for subsequent boots
    keys_ks
        .insert_raw(VTA_DID_STORE_KEY, final_did.as_bytes().to_vec())
        .await?;

    // Store did.jsonl in encrypted keyspace for REST API access
    keys_ks
        .insert_raw("tee:did_log", log_content.as_bytes().to_vec())
        .await?;

    // Also store the did.jsonl in the WEBVH keyspace keyed by the DID. Both
    // the public `/.well-known/did.jsonl` route (`serve_canonical`) and the
    // internal self-DID resolver preload read via `webvh_store::get_did_log`,
    // keyed by the DID — without this write the VTA's own did:webvh is
    // unresolvable (well-known 404s, preload WARN fires) so no client can
    // authcrypt to it. Feature-gated to match `webvh_store`.
    #[cfg(feature = "webvh")]
    {
        let webvh_ks = apply_enc(store.keyspace(crate::keyspaces::WEBVH)?);
        crate::webvh_store::store_did_log(&webvh_ks, &final_did, &log_content).await?;

        // Store the DID *record* alongside the log so `list_services` and did
        // update/rotate ops can find it via `webvh_store::get_did`. See
        // `build_vta_webvh_record`.
        let did_record = build_vta_webvh_record(&final_did);
        crate::webvh_store::store_did(&webvh_ks, &did_record).await?;
    }

    // Also store in bootstrap keyspace (no encryption) so the parent proxy
    // can read it and write did.jsonl to disk for the operator.
    let bootstrap_ks = store.keyspace(crate::keyspaces::BOOTSTRAP)?;
    bootstrap_ks
        .insert_raw("tee:did_log", log_content.as_bytes().to_vec())
        .await?;

    // Flush the store to ensure durability
    store.persist().await?;

    info!(
        did = %final_did,
        scid = %scid,
        "VTA did:webvh identity auto-generated — retrieve did.jsonl via: \
         GET /attestation/did-log or from the bootstrap keyspace key 'tee:did_log'"
    );

    config.vta_did = Some(final_did);
    Ok(())
}

/// Build a minimal DID document for the VTA identity.
///
/// Self-contained to avoid depending on webvh feature-gated modules.
fn build_vta_did_document(
    derived: &keys::DerivedEntityKeys,
    sealed_transfer: &keys::DerivedSealedTransferKey,
    config: &AppConfig,
) -> serde_json::Value {
    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "verificationMethod": [
            {
                "id": "{DID}#key-0",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": &derived.signing_pub
            },
            {
                "id": "{DID}#key-1",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": &derived.ka_pub
            },
            {
                "id": "{DID}#sealed-transfer-0",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": &sealed_transfer.public_key
            }
        ],
        "authentication": ["{DID}#key-0"],
        // `#key-0` issues VC Data-Integrity proofs; `#sealed-transfer-0`
        // signs the sealed-transfer producer assertion. Both are
        // assertion-flavoured but keyed separately — see
        // `operations::provision_integration::build_did_signed_assertion`.
        "assertionMethod": ["{DID}#key-0", "{DID}#sealed-transfer-0"],
        "keyAgreement": ["{DID}#key-1"]
    });

    // Add DIDComm mediator service if configured
    if let Some(ref msg) = config.messaging {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#vta-didcomm",
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": msg.mediator_did
            }]
        }));
    }

    // Add TeeAttestation service if configured
    if config.tee.embed_in_did
        && let Some(ref public_url) = config.public_url
    {
        let services = did_document
            .as_object_mut()
            .unwrap()
            .entry("service")
            .or_insert_with(|| json!([]));
        services.as_array_mut().unwrap().push(json!({
            "id": "{DID}#tee-attestation",
            "type": "TeeAttestation",
            "serviceEndpoint": format!("{}/attestation/report", public_url.trim_end_matches('/'))
        }));
    }

    did_document
}

/// Convert a did:webvh template to an HTTPS URL for didwebvh-rs.
///
/// `did:webvh:{SCID}:example.com:vta` → `https://example.com/vta`
/// `did:webvh:{SCID}:example.com%3A8080:vta` → `https://example.com:8080/vta`
fn template_to_url(template: &str) -> Result<String, AppError> {
    // Strip "did:webvh:{SCID}:" prefix
    let rest = template.strip_prefix("did:webvh:{SCID}:").ok_or_else(|| {
        AppError::Config(format!(
            "vta_did_template must start with 'did:webvh:{{SCID}}:' — got: {template}"
        ))
    })?;

    if rest.is_empty() {
        return Err(AppError::Config(
            "vta_did_template must include a domain after 'did:webvh:{SCID}:'".into(),
        ));
    }

    // did:webvh encoding: ":" separates path segments, "%3A" is a literal colon (port)
    // Decode %3A back to ":" for port numbers, then replace ":" with "/" for path
    let url_path = rest
        .replace("%3A", "\x00")
        .replace(':', "/")
        .replace('\x00', ":");

    Ok(format!("https://{url_path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_to_url_simple() {
        assert_eq!(
            template_to_url("did:webvh:{SCID}:example.com:vta").unwrap(),
            "https://example.com/vta"
        );
    }

    #[test]
    fn test_template_to_url_nested_path() {
        assert_eq!(
            template_to_url("did:webvh:{SCID}:example.com:org:agents:vta-1").unwrap(),
            "https://example.com/org/agents/vta-1"
        );
    }

    #[test]
    fn test_template_to_url_with_port() {
        assert_eq!(
            template_to_url("did:webvh:{SCID}:example.com%3A8080:vta").unwrap(),
            "https://example.com:8080/vta"
        );
    }

    #[test]
    fn test_template_to_url_domain_only() {
        assert_eq!(
            template_to_url("did:webvh:{SCID}:example.com").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_template_to_url_invalid_prefix() {
        assert!(template_to_url("did:key:z6Mk...").is_err());
    }

    #[test]
    fn test_template_to_url_empty_domain() {
        assert!(template_to_url("did:webvh:{SCID}:").is_err());
    }
}
