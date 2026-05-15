//! Internal layout:
//! - `mod.rs` — `create_did_webvh`, `delete_did_webvh`, `WebvhTransport`,
//!   `CreateDidWebvhParams`, helpers still used only by the main flow
//! - `document` — pure DID-document construction (shared with the TEE
//!   enclave bootstrap path)
//! - `lifecycle` — read ops on stored DID records (`get`, `list`, log)
//! - `servers` — webvh hosting-server CRUD + DID validation

mod concurrency;
mod document;
mod lifecycle;
mod register_server;
mod servers;
mod update;
mod webvh_keys;

pub(crate) use concurrency::{RaceDetected, RecordSnapshot};

pub(crate) use document::build_did_document_with_options;
pub use document::{build_did_document, build_vta_did_document_with_sealed_transfer};
pub use lifecycle::{GetDidWebvhLogResult, get_did_webvh, get_did_webvh_log, list_dids_webvh};
pub use register_server::{
    RegisterDidWithServerError, RegisterDidWithServerParams, RegisterDidWithServerResult,
    register_did_with_server,
};
pub use servers::{add_webvh_server, list_webvh_servers, remove_webvh_server, update_webvh_server};
pub use update::{
    RotateDidWebvhKeysOptions, UpdateDidWebvhError, UpdateDidWebvhOptions, UpdateDidWebvhResult,
    rotate_did_webvh_keys, update_did_webvh,
};

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use didwebvh_rs::create::{CreateDIDConfig, create_did};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use tracing::info;
use url::Url;

use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::didcomm_bridge::DIDCommBridge;

use vta_sdk::protocols::did_management::{
    create::{CreateDidWebvhBody, CreateDidWebvhResultBody},
    delete::DeleteDidWebvhResultBody,
};
use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::keys::imported;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyType as SdkKeyType, PreRotationKeyData, encode_private_multibase};
use crate::store::KeyspaceHandle;
use crate::webvh_client::{RequestUriResponse, WebvhAuthState, WebvhClient};
use crate::webvh_didcomm::WebvhDIDCommClient;
use crate::webvh_store::{self, WebvhServerAuthRecord};
use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
use zeroize::Zeroize;

use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

/// Resolve a DID template by name for use in a create-DID flow.
///
/// Resolution order:
/// 1. Context scope (if `template_context` is provided)
/// 2. Global scope
/// 3. Built-in templates shipped with the SDK
///
/// Context-scoped templates therefore naturally shadow global ones with the
/// same name; global templates shadow built-ins.
async fn resolve_template_for_render(
    did_templates_ks: &KeyspaceHandle,
    name: &str,
    template_context: Option<&str>,
) -> Result<vta_sdk::did_templates::DidTemplateRecord, AppError> {
    use vta_sdk::did_templates::{DidTemplateRecord, Scope, load_embedded};

    if let Some(ctx) = template_context
        && let Some(record) =
            crate::did_templates::get_context_template(did_templates_ks, ctx, name).await?
    {
        return Ok(record);
    }

    if let Some(record) = crate::did_templates::get_global_template(did_templates_ks, name).await? {
        return Ok(record);
    }

    if let Ok(tpl) = load_embedded(name) {
        // Built-ins have no stored provenance — synthesize a record so
        // downstream code treats it uniformly. `created_at`/`updated_at` are
        // 0 because there's no meaningful moment of authorship beyond the
        // crate's compile time; `created_by` is the well-known sentinel
        // `"builtin"`.
        return Ok(DidTemplateRecord {
            template: tpl,
            scope: Scope::Builtin,
            created_at: 0,
            updated_at: 0,
            created_by: "builtin".into(),
        });
    }

    Err(AppError::NotFound(format!(
        "DID template '{name}' not found (searched{} global, builtin)",
        template_context
            .map(|c| format!(" context '{c}',"))
            .unwrap_or_default()
    )))
}

pub struct CreateDidWebvhParams {
    pub context_id: String,
    pub server_id: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub label: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    pub additional_services: Option<Vec<serde_json::Value>>,
    pub pre_rotation_count: u32,
    /// Client-provided DID Document template. Mutually exclusive with `did_log`
    /// and `template`.
    pub did_document: Option<serde_json::Value>,
    /// Complete, pre-signed did.jsonl log entry. Mutually exclusive with
    /// `did_document` and `template`.
    pub did_log: Option<String>,
    /// Whether to set this DID as the primary DID for the context.
    pub set_primary: bool,
    /// Use an existing key as the signing verification method.
    pub signing_key_id: Option<String>,
    /// Use an existing key as the key-agreement verification method.
    pub ka_key_id: Option<String>,
    /// Stored DID template to render into `did_document`. Resolution order:
    /// `template_context` scope (if set) → global → no fallback.
    pub template: Option<String>,
    /// Scope to look `template` up in. `None` = global only.
    pub template_context: Option<String>,
    /// Caller-supplied template variables. Server injects `DID`,
    /// `SIGNING_KEY_MB`, `KA_KEY_MB`, `VTA_DID`, `VTA_URL`, `CONTEXT_ID`,
    /// `CONTEXT_DID`, `NOW` automatically.
    pub template_vars: std::collections::HashMap<String, serde_json::Value>,
    /// When `true`, this DID *is* the VTA's own identity — mint a third
    /// key (`{did}#sealed-transfer-0`) and add it to the DID document.
    /// The operator uses this key only to sign sealed-transfer producer
    /// assertions, keeping it disjoint from `#key-0` (VC issuance) so
    /// the two can rotate / leak independently. Ignored when
    /// `did_document` is caller-supplied or `did_log` is pre-signed —
    /// templates that need the key must declare it themselves.
    pub is_vta_identity: bool,
}

impl From<CreateDidWebvhBody> for CreateDidWebvhParams {
    fn from(body: CreateDidWebvhBody) -> Self {
        Self {
            context_id: body.context_id,
            server_id: body.server_id,
            url: body.url,
            path: body.path,
            label: body.label,
            portable: body.portable.unwrap_or(true),
            add_mediator_service: body.add_mediator_service.unwrap_or(false),
            additional_services: body.additional_services,
            pre_rotation_count: body.pre_rotation_count.unwrap_or(0),
            did_document: body.did_document,
            did_log: body.did_log,
            set_primary: body.set_primary.unwrap_or(true),
            signing_key_id: body.signing_key_id,
            ka_key_id: body.ka_key_id,
            template: body.template,
            template_context: body.template_context,
            template_vars: body.template_vars.unwrap_or_default(),
            // Wire callers never mint the VTA's own identity — that happens
            // only during first-boot setup (setup wizard / TEE autogen /
            // non-interactive --from). An admin hitting create-did-webvh at
            // runtime is always creating an integration DID.
            is_vta_identity: false,
        }
    }
}

/// Load an existing key record and return it as a `Secret` for use in DID creation.
///
/// Validates key type, status, and context access. Returns the Secret,
/// public key multibase, and the original KeyRecord.
async fn load_key_as_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    key_id: &str,
    expected_type: KeyType,
    auth: &AuthClaims,
) -> Result<(Secret, String, KeyRecord), AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    // Validate key type
    if record.key_type != expected_type {
        return Err(AppError::Validation(format!(
            "key {key_id} is {} but expected {}",
            record.key_type, expected_type
        )));
    }

    // Validate status
    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(format!(
            "key {key_id} is not active (status: {:?})",
            record.status
        )));
    }

    // Validate context access
    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can use keys without a context".into(),
        ));
    }

    // Load private key material
    let private_key_multibase = match record.origin {
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
            priv_mb
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ExtendedSigningKey::from_seed(&seed).map_err(|e| {
                AppError::Internal(format!("failed to create BIP-32 root key: {e}"))
            })?;
            let derivation_path: DerivationPath = record
                .derivation_path
                .parse()
                .map_err(|e| AppError::Internal(format!("invalid derivation path: {e}")))?;
            let derived_key = bip32
                .derive(&derivation_path)
                .map_err(|e| AppError::Internal(format!("key derivation failed: {e}")))?;
            encode_private_multibase(&KeyType::Ed25519, derived_key.signing_key.as_bytes())
        }
    };

    let secret = Secret::from_multibase(&private_key_multibase, None).map_err(|e| {
        AppError::Internal(format!("failed to construct Secret from key {key_id}: {e}"))
    })?;

    Ok((secret, record.public_key.clone(), record))
}

/// Check whether a DID document (JSON) contains any DIDCommMessaging service.
fn document_has_didcomm_service(doc: &serde_json::Value) -> bool {
    doc.get("service")
        .and_then(|s| s.as_array())
        .is_some_and(|services| {
            services.iter().any(|svc| {
                svc.get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == "DIDCommMessaging")
                    || svc
                        .get("type")
                        .and_then(|t| t.as_array())
                        .is_some_and(|types| {
                            types
                                .iter()
                                .any(|t| t.as_str().is_some_and(|s| s == "DIDCommMessaging"))
                        })
            })
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn create_did_webvh(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
    auth: &AuthClaims,
    mut params: CreateDidWebvhParams,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    channel: &str,
) -> Result<CreateDidWebvhResultBody, AppError> {
    auth.require_admin()?;
    auth.require_context(&params.context_id)?;

    let rest_auth = WebvhRestAuthContext {
        webvh_ks,
        keys_ks,
        seed_store,
        config,
        channel,
    };

    // Template is mutually exclusive with raw did_document / did_log — it
    // renders into did_document, so specifying both would ambiguously
    // override.
    if params.template.is_some() && (params.did_document.is_some() || params.did_log.is_some()) {
        return Err(AppError::Validation(
            "template is mutually exclusive with did_document and did_log".into(),
        ));
    }

    // Validate did_document and did_log are mutually exclusive
    if params.did_document.is_some() && params.did_log.is_some() {
        return Err(AppError::Validation(
            "did_document and did_log are mutually exclusive".into(),
        ));
    }

    // Validate ka_key_id requires signing_key_id
    if params.ka_key_id.is_some() && params.signing_key_id.is_none() {
        return Err(AppError::Validation(
            "ka_key_id requires signing_key_id".into(),
        ));
    }

    // Validate exactly one of server_id / url is provided
    let serverless = match (&params.server_id, &params.url) {
        (Some(_), Some(_)) => {
            return Err(AppError::Validation(
                "server_id and url are mutually exclusive".into(),
            ));
        }
        (None, None) => {
            return Err(AppError::Validation(
                "either server_id or url is required".into(),
            ));
        }
        (None, Some(_)) => true,
        (Some(_), None) => false,
    };

    // Resolve context
    let mut ctx = crate::contexts::get_context(contexts_ks, &params.context_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("context not found: {}", params.context_id)))?;

    let now = Utc::now();

    // ── Final mode: client-provided pre-signed log entry ────────────
    if let Some(ref did_log) = params.did_log {
        let log_entry = LogEntry::deserialize_string(did_log, None)
            .map_err(|e| AppError::Validation(format!("invalid did_log: {e}")))?;

        let final_did_document = log_entry.get_did_document().map_err(|e| {
            AppError::Validation(format!("failed to extract DID document from log: {e}"))
        })?;
        let final_did = final_did_document["id"]
            .as_str()
            .ok_or_else(|| AppError::Validation("DID document missing 'id' field".into()))?
            .to_string();
        let scid = log_entry.get_scid().unwrap_or_default().to_string();

        // Publish to server if not serverless
        if !serverless {
            let server_id = params.server_id.as_ref().ok_or_else(|| {
                AppError::Validation(
                    "server_id is required when serverless=false (final-mode publish path)".into(),
                )
            })?;
            let server = webvh_store::get_server(webvh_ks, server_id)
                .await?
                .ok_or_else(|| {
                    AppError::NotFound(format!("webvh server not found: {server_id}"))
                })?;
            let transport =
                WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, &rest_auth)
                    .await?;
            // Final mode has no mnemonic from a server request — use the SCID as identifier
            transport.publish_did(&scid, did_log).await?;
        }

        // Optionally set as primary DID
        if params.set_primary {
            ctx.did = Some(final_did.clone());
            ctx.updated_at = now;
            crate::contexts::store_context(contexts_ks, &ctx)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
        }

        // Store DID record and log
        let server_id_str = params
            .server_id
            .as_deref()
            .unwrap_or("serverless")
            .to_string();
        // Pre-signed-log mode: we don't know the pre-rotation count or
        // current fragment id without parsing the log. Use defensive
        // defaults; the next `update_did_webvh` call performs a one-shot
        // re-scan and persists the corrected values.
        let did_record = WebvhDidRecord {
            did: final_did.clone(),
            server_id: server_id_str.clone(),
            mnemonic: String::new(),
            scid: scid.clone(),
            context_id: params.context_id.clone(),
            portable: params.portable,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 1,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(webvh_ks, &did_record).await?;
        webvh_store::store_did_log(webvh_ks, &final_did, did_log).await?;

        info!(
            channel,
            did = %final_did,
            context = %params.context_id,
            "did:webvh created (final mode)"
        );

        return Ok(CreateDidWebvhResultBody {
            did: final_did.clone(),
            context_id: params.context_id,
            server_id: if serverless { None } else { params.server_id },
            mnemonic: None,
            scid,
            portable: params.portable,
            signing_key_id: String::new(),
            ka_key_id: String::new(),
            pre_rotation_key_count: 0,
            created_at: now,
            did_document: Some(final_did_document),
            log_entry: Some(did_log.clone()),
        });
    }

    // ── VTA-built or template mode ──────────────────────────────────

    let label = params.label.as_deref().unwrap_or(&params.context_id);

    // Track whether keys were user-specified (affects key record saving)
    let user_specified_keys = params.signing_key_id.is_some();

    // Load or derive entity keys
    let (derived, active_seed_id) = if let Some(ref signing_key_id) = params.signing_key_id {
        // ── User-specified keys ─────────────────────────────────────
        let (mut signing_secret, signing_pub, signing_record) = load_key_as_secret(
            keys_ks,
            imported_ks,
            seed_store,
            signing_key_id,
            KeyType::Ed25519,
            auth,
        )
        .await?;

        // Convert signing key ID to did:key format (required by didwebvh-rs)
        let pub_mb = signing_secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        signing_secret.id = format!("did:key:{pub_mb}#{pub_mb}");

        let (ka_secret, ka_pub, ka_path, ka_label) = if let Some(ref ka_key_id) = params.ka_key_id {
            let (ka_secret, ka_pub, ka_record) = load_key_as_secret(
                keys_ks,
                imported_ks,
                seed_store,
                ka_key_id,
                KeyType::X25519,
                auth,
            )
            .await?;
            (
                ka_secret,
                ka_pub,
                ka_record.derivation_path,
                ka_record
                    .label
                    .unwrap_or_else(|| format!("{label} key-agreement key")),
            )
        } else {
            // No KA key — use dummy values (won't be in the document)
            (
                Secret::generate_ed25519(None, None),
                String::new(),
                String::new(),
                String::new(),
            )
        };

        let derived = keys::DerivedEntityKeys {
            signing_secret,
            signing_path: signing_record.derivation_path.clone(),
            signing_pub,
            signing_priv: String::new(), // Not needed for DID creation
            signing_label: signing_record
                .label
                .unwrap_or_else(|| format!("{label} signing key")),
            ka_secret,
            ka_path,
            ka_pub,
            ka_priv: String::new(),
            ka_label,
        };

        // seed_id from the signing key record (may be None for imported)
        (derived, signing_record.seed_id)
    } else {
        // ── VTA-derived keys ────────────────────────────────────────
        let active_seed_id = get_active_seed_id(keys_ks)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let seed = load_seed_bytes(keys_ks, seed_store, Some(active_seed_id))
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;

        let mut derived = keys::derive_entity_keys(
            &seed,
            &ctx.base_path,
            &format!("{label} signing key"),
            &format!("{label} key-agreement key"),
            keys_ks,
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

        // Convert signing key ID to did:key format (required by didwebvh-rs)
        let pub_mb = derived
            .signing_secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        derived.signing_secret.id = format!("did:key:{pub_mb}#{pub_mb}");

        (derived, Some(active_seed_id))
    };

    // ── VTA identity: derive the `#sealed-transfer-0` key ──────────
    //
    // Minting this key here (before the DID doc is built) means it can
    // be embedded as a verificationMethod from the start — no DID doc
    // rev needed later. Only applies to the VTA's own identity; every
    // other webvh DID (integrations, mediators) doesn't need it.
    let sealed_transfer = if params.is_vta_identity && !user_specified_keys {
        let seed_for_st = if let Some(sid) = active_seed_id {
            load_seed_bytes(keys_ks, seed_store, Some(sid))
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?
        } else {
            return Err(AppError::Internal(
                "is_vta_identity set but no active seed — VTA identity requires seed-derived keys"
                    .into(),
            ));
        };
        Some(
            keys::derive_sealed_transfer_key(
                &seed_for_st,
                &ctx.base_path,
                &format!("{label} sealed-transfer producer-assertion key"),
                keys_ks,
            )
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?,
        )
    } else {
        None
    };

    // Resolve URL: serverless uses user-provided URL, server-managed requests from server
    let (url_str, mnemonic) = if serverless {
        let url_str = params
            .url
            .as_ref()
            .ok_or_else(|| AppError::Validation("url is required when serverless=true".into()))?
            .clone();
        // Validate the URL
        let parsed_url =
            Url::parse(&url_str).map_err(|e| AppError::Validation(format!("invalid url: {e}")))?;
        WebVHURL::parse_url(&parsed_url)
            .map_err(|e| AppError::Validation(format!("failed to parse WebVH URL: {e}")))?;
        (url_str, None)
    } else {
        let server_id = params.server_id.as_ref().ok_or_else(|| {
            AppError::Validation("server_id is required when serverless=false".into())
        })?;
        let server = webvh_store::get_server(webvh_ks, server_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

        let transport =
            WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, &rest_auth).await?;
        let uri_response = transport.request_uri(params.path.as_deref()).await?;

        // Validate the URL
        let parsed_url = Url::parse(&uri_response.did_url)
            .map_err(|e| AppError::Internal(format!("invalid did_url from server: {e}")))?;
        WebVHURL::parse_url(&parsed_url)
            .map_err(|e| AppError::Internal(format!("failed to parse WebVH URL: {e}")))?;
        (uri_response.did_url, Some(uri_response.mnemonic))
    };

    let has_ka = params.ka_key_id.is_some() || !user_specified_keys;

    // ── Template resolution + render ────────────────────────────────
    //
    // If the caller named a stored (or built-in) DID template, resolve it,
    // inject ambient variables from the keys minted above plus config +
    // context state, and render the result into `params.did_document`. The
    // rest of the flow then treats it as a caller-supplied document.
    //
    // `{DID}` is passed through as a sentinel — `didwebvh-rs` substitutes
    // it with the computed DID after SCID generation.
    if let Some(ref template_name) = params.template {
        let record = resolve_template_for_render(
            did_templates_ks,
            template_name,
            params.template_context.as_deref(),
        )
        .await?;

        let mut vars = vta_sdk::did_templates::TemplateVars::new();
        vars.insert_string("DID", "{DID}");
        vars.insert_string("SIGNING_KEY_MB", derived.signing_pub.clone());
        if has_ka {
            vars.insert_string("KA_KEY_MB", derived.ka_pub.clone());
        }
        if let Some(ref vta_did) = config.vta_did {
            vars.insert_string("VTA_DID", vta_did.clone());
        }
        if let Some(ref vta_url) = config.public_url {
            vars.insert_string("VTA_URL", vta_url.clone());
        }
        vars.insert_string("CONTEXT_ID", params.context_id.clone());
        if let Some(ref did) = ctx.did {
            vars.insert_string("CONTEXT_DID", did.clone());
        }
        vars.insert_string("NOW", Utc::now().to_rfc3339());
        for (k, v) in &params.template_vars {
            vars.insert(k.clone(), v.clone());
        }

        let rendered = record.template.render(&vars).map_err(|e| {
            AppError::Validation(format!("template '{template_name}' render failed: {e}"))
        })?;
        params.did_document = Some(rendered);
    }

    // Build DID document: use client-provided template or build internally
    let did_document = match params.did_document {
        Some(doc) => doc,
        None if user_specified_keys => {
            // Build document from user-specified keys (signing only, or signing + KA)
            build_did_document_with_options(
                &derived,
                config,
                has_ka,
                params.add_mediator_service,
                &params.additional_services,
            )
        }
        None if sealed_transfer.is_some() => build_vta_did_document_with_sealed_transfer(
            &derived,
            sealed_transfer.as_ref().unwrap(),
            config,
            params.add_mediator_service,
            &params.additional_services,
        ),
        None => build_did_document(
            &derived,
            config,
            params.add_mediator_service,
            &params.additional_services,
        ),
    };

    // Validate DIDComm services require a KA key
    if !has_ka && (params.add_mediator_service || document_has_didcomm_service(&did_document)) {
        return Err(AppError::Validation(
            "DIDCommMessaging services require a key-agreement key (ka_key_id)".into(),
        ));
    }

    // Derive pre-rotation keys (requires seed)
    let seed_for_pre_rotation = if params.pre_rotation_count > 0 {
        let sid = match active_seed_id {
            Some(id) => id,
            None => get_active_seed_id(keys_ks)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?,
        };
        Some(
            load_seed_bytes(keys_ks, seed_store, Some(sid))
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?,
        )
    } else {
        None
    };
    let (next_key_hashes, pre_rotation_keys) = if let Some(ref seed) = seed_for_pre_rotation {
        derive_pre_rotation_keys(
            seed,
            &ctx.base_path,
            label,
            keys_ks,
            params.pre_rotation_count,
        )
        .await?
    } else {
        (vec![], vec![])
    };

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone().into()])),
        portable: Some(params.portable),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(
                next_key_hashes.iter().cloned().map(Into::into).collect(),
            ))
        },
        ..Default::default()
    };

    // Create the DID
    let create_config = CreateDIDConfig::builder()
        .address(&url_str)
        .authorization_key(derived.signing_secret.clone())
        .did_document(did_document.clone())
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
    if !user_specified_keys {
        // VTA-derived: save both signing and KA key records
        keys::save_entity_key_records(
            &final_did,
            &derived,
            keys_ks,
            Some(&params.context_id),
            active_seed_id,
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

        // Persist `#sealed-transfer-0` alongside `#key-0`/`#key-1`. Only
        // populated when this DID is the VTA's own identity (see the
        // derivation block above).
        if let Some(ref st) = sealed_transfer {
            keys::save_sealed_transfer_key_record(
                &final_did,
                st,
                keys_ks,
                Some(&params.context_id),
                active_seed_id,
            )
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        }
    } else {
        // User-specified: save key records referencing the user's keys
        keys::save_key_record(
            keys_ks,
            &format!("{final_did}#key-0"),
            &derived.signing_path,
            SdkKeyType::Ed25519,
            &derived.signing_pub,
            &derived.signing_label,
            Some(&params.context_id),
            active_seed_id,
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

        if has_ka {
            keys::save_key_record(
                keys_ks,
                &format!("{final_did}#key-1"),
                &derived.ka_path,
                SdkKeyType::X25519,
                &derived.ka_pub,
                &derived.ka_label,
                Some(&params.context_id),
                active_seed_id,
            )
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        }
    }

    // Save pre-rotation key records
    let pre_rotation_seed_id = active_seed_id.unwrap_or(0);
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            SdkKeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some(&params.context_id),
            Some(pre_rotation_seed_id),
        )
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    // Index every minted key into the per-version `webvh_keys` keyspace so
    // `update_did_webvh` can resolve handles by hash without legacy-scan
    // fallbacks. Pre-rotation handles MUST be installed here — the webvh
    // signing-key check on the first update consults `previous.next_key_hashes`,
    // and the secret behind those hashes lives only at the BIP-32 paths
    // captured by these handles. Without this, an update-with-pre-rotation
    // path can't find the right secret.
    let genesis_version_id = result
        .log_entry()
        .get_version_id_fields()
        .map(|(n, h)| format!("{n}-{h}"))
        .map_err(|e| AppError::Internal(format!("read genesis version id: {e}")))?;

    let signing_hash = Secret::base58_hash_string(&derived.signing_pub)
        .map_err(|e| AppError::Internal(format!("hash genesis signing pubkey: {e}")))?;
    let now_ts = Utc::now();
    let signing_handle = webvh_keys::WebvhKeyHandle {
        scid: scid.clone(),
        version_id: genesis_version_id.clone(),
        hash: signing_hash,
        public_key: derived.signing_pub.clone(),
        derivation_path: derived.signing_path.clone(),
        seed_id: active_seed_id,
        role: webvh_keys::WebvhKeyRole::UpdateKey,
        label: derived.signing_label.clone(),
        created_at: now_ts,
    };
    webvh_keys::install(keys_ks, &signing_handle)
        .await
        .map_err(|e| AppError::Internal(format!("install genesis update-key handle: {e}")))?;

    for (i, (hash, pk)) in next_key_hashes
        .iter()
        .zip(pre_rotation_keys.iter())
        .enumerate()
    {
        let handle = webvh_keys::WebvhKeyHandle {
            scid: scid.clone(),
            version_id: genesis_version_id.clone(),
            hash: hash.clone(),
            public_key: pk.public_key.clone(),
            derivation_path: pk.path.clone(),
            seed_id: Some(pre_rotation_seed_id),
            role: webvh_keys::WebvhKeyRole::PreRotation,
            label: format!("genesis pre-rotation #{i}"),
            created_at: now_ts,
        };
        webvh_keys::install(keys_ks, &handle).await.map_err(|e| {
            AppError::Internal(format!("install genesis pre-rotation handle #{i}: {e}"))
        })?;
    }

    // Optionally set as primary DID
    if params.set_primary {
        ctx.did = Some(final_did.clone());
        ctx.updated_at = now;
        crate::contexts::store_context(contexts_ks, &ctx)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
    }

    // Extract the rendered DID document from the just-built log entry.
    // Shared by both branches so the returned `did_document` / `log_entry`
    // shape is identical regardless of publish target — downstream flows
    // (notably `provision_integration`) rely on these being populated.
    let final_did_document = result
        .log_entry()
        .get_did_document()
        .ok()
        .unwrap_or(did_document);

    if serverless {
        // Serverless: skip publish but DO store the DID record and log locally.
        // Create mints exactly two verificationMethods (#key-0 = signing,
        // #key-1 = key-agreement). Next rotation allocates from `#key-2`.
        let did_record = WebvhDidRecord {
            did: final_did.clone(),
            server_id: "serverless".to_string(),
            mnemonic: String::new(),
            scid: scid.clone(),
            context_id: params.context_id.clone(),
            portable: params.portable,
            log_entry_count: 1,
            pre_rotation_count: pre_rotation_keys.len() as u32,
            next_fragment_id: 2,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(webvh_ks, &did_record).await?;
        webvh_store::store_did_log(webvh_ks, &final_did, &log_content).await?;

        info!(
            channel,
            did = %final_did,
            context = %params.context_id,
            "did:webvh created (serverless)"
        );

        Ok(CreateDidWebvhResultBody {
            did: final_did.clone(),
            context_id: params.context_id,
            server_id: None,
            mnemonic: None,
            scid,
            portable: params.portable,
            signing_key_id: format!("{final_did}#key-0"),
            ka_key_id: format!("{final_did}#key-1"),
            pre_rotation_key_count: pre_rotation_keys.len() as u32,
            created_at: now,
            did_document: Some(final_did_document),
            log_entry: Some(log_content),
        })
    } else {
        // Server-managed: publish, update context, store records
        let server_id = params.server_id.as_ref().unwrap();
        let mnemonic = mnemonic.as_ref().unwrap();

        let server = webvh_store::get_server(webvh_ks, server_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

        let transport =
            WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, &rest_auth).await?;
        transport.publish_did(mnemonic, &log_content).await?;

        // Store DID record and log
        let did_record = WebvhDidRecord {
            did: final_did.clone(),
            server_id: server_id.clone(),
            mnemonic: mnemonic.clone(),
            scid: scid.clone(),
            context_id: params.context_id.clone(),
            portable: params.portable,
            log_entry_count: 1,
            pre_rotation_count: pre_rotation_keys.len() as u32,
            next_fragment_id: 2,
            created_at: now,
            updated_at: now,
        };
        webvh_store::store_did(webvh_ks, &did_record).await?;
        webvh_store::store_did_log(webvh_ks, &final_did, &log_content).await?;

        info!(
            channel,
            did = %final_did,
            context = %params.context_id,
            server = %server_id,
            "did:webvh created and published"
        );

        Ok(CreateDidWebvhResultBody {
            did: final_did.clone(),
            context_id: params.context_id,
            server_id: Some(server_id.clone()),
            mnemonic: Some(mnemonic.clone()),
            scid,
            portable: params.portable,
            signing_key_id: format!("{final_did}#key-0"),
            ka_key_id: format!("{final_did}#key-1"),
            pre_rotation_key_count: pre_rotation_keys.len() as u32,
            created_at: now,
            did_document: Some(final_did_document),
            log_entry: Some(log_content),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn delete_did_webvh(
    webvh_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
    auth: &AuthClaims,
    did: &str,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    channel: &str,
) -> Result<DeleteDidWebvhResultBody, AppError> {
    auth.require_admin()?;

    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;

    // Resolve server for remote deletion
    let server = webvh_store::get_server(webvh_ks, &record.server_id).await?;

    if let Some(server) = server {
        let rest_auth = WebvhRestAuthContext {
            webvh_ks,
            keys_ks,
            seed_store,
            config,
            channel,
        };
        match WebvhTransport::from_server(&server, did_resolver, didcomm_bridge, &rest_auth).await {
            Ok(transport) => {
                if let Err(e) = transport.delete_did(&record.mnemonic).await {
                    tracing::warn!(did = %did, error = %e, "failed to delete DID from webvh-server (continuing local cleanup)");
                }
            }
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "failed to resolve server endpoint (continuing local cleanup)");
            }
        }
    }

    // Remove local DID record and log
    webvh_store::delete_did(webvh_ks, did).await?;

    // Clean up associated key records (best-effort)
    for key_id in &[format!("{did}#key-0"), format!("{did}#key-1")] {
        let _ = keys_ks.remove(keys::store_key(key_id)).await;
    }
    // Clean up pre-rotation key records
    for i in 0..100u32 {
        let key_id = format!("{did}#pre-rotation-{i}");
        let store_key = keys::store_key(&key_id);
        if keys_ks.get_raw(store_key.clone()).await?.is_none() {
            break;
        }
        let _ = keys_ks.remove(store_key).await;
    }

    info!(channel, did = %did, "webvh DID deleted");
    Ok(DeleteDidWebvhResultBody {
        did: did.to_string(),
        deleted: true,
    })
}

// ---------------------------------------------------------------------------
// WebVH transport abstraction
// ---------------------------------------------------------------------------

/// Transport choice inferred from a resolved WebVH server DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedServerTransport {
    Didcomm,
    Rest(String),
}

fn normalize_service_uri(url: String) -> String {
    url.trim_matches('"').trim_end_matches('/').to_string()
}

fn resolve_server_transport<T>(
    services: &[T],
    service_types: impl Fn(&T) -> &[String],
    service_uri: impl Fn(&T) -> Option<String>,
) -> Option<ResolvedServerTransport> {
    if services
        .iter()
        .any(|svc| servers::is_didcomm_service_type(service_types(svc)))
    {
        return Some(ResolvedServerTransport::Didcomm);
    }

    services.iter().find_map(|svc| {
        if !servers::is_webvh_rest_service_type(service_types(svc)) {
            return None;
        }
        service_uri(svc)
            .map(normalize_service_uri)
            .map(ResolvedServerTransport::Rest)
    })
}

const WEBVH_REST_TOKEN_REFRESH_SKEW_SECS: u64 = 30;

pub(super) struct WebvhRestAuthContext<'a> {
    webvh_ks: &'a KeyspaceHandle,
    keys_ks: &'a KeyspaceHandle,
    seed_store: &'a dyn SeedStore,
    config: &'a AppConfig,
    channel: &'a str,
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn access_token_is_fresh(auth_state: &WebvhServerAuthRecord, now: u64) -> bool {
    auth_state
        .access_token
        .as_ref()
        .is_some_and(|token| !token.is_empty())
        && auth_state
            .access_expires_at
            .is_some_and(|exp| exp > now.saturating_add(WEBVH_REST_TOKEN_REFRESH_SKEW_SECS))
}

async fn load_vta_signing_secret(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
) -> Result<(String, Secret), AppError> {
    let vta_did = config
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("vta_did is not configured".into()))?
        .clone();
    let key_id = format!("{vta_did}#key-0");

    let record: KeyRecord = keys_ks
        .get(keys::store_key(&key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("VTA signing key not found: {key_id}")))?;

    if record.key_type != KeyType::Ed25519 {
        return Err(AppError::Internal(format!(
            "VTA signing key {key_id} must be Ed25519, found {}",
            record.key_type
        )));
    }
    if record.status != KeyStatus::Active {
        return Err(AppError::Internal(format!(
            "VTA signing key {key_id} is not active"
        )));
    }
    if record.origin != KeyOrigin::Derived {
        return Err(AppError::Internal(format!(
            "webvh REST auth currently requires a derived VTA signing key; {key_id} is {:?}",
            record.origin
        )));
    }

    let seed = load_seed_bytes(keys_ks, seed_store, record.seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::Internal(format!("failed to create BIP-32 root key: {e}")))?;
    let derivation_path: DerivationPath = record
        .derivation_path
        .parse()
        .map_err(|e| AppError::Internal(format!("invalid derivation path: {e}")))?;
    let derived_key = bip32
        .derive(&derivation_path)
        .map_err(|e| AppError::Internal(format!("key derivation failed: {e}")))?;
    let private_key_multibase =
        encode_private_multibase(&KeyType::Ed25519, derived_key.signing_key.as_bytes());

    let signing_secret = if vta_did.starts_with("did:key:") {
        let seed: [u8; 32] = vta_sdk::did_key::decode_private_key_multibase(&private_key_multibase)
            .map_err(|e| {
                AppError::Internal(format!("decode VTA did:key signing seed for {key_id}: {e}"))
            })?;
        vta_sdk::did_key::secrets_from_did_key(&vta_did, &seed)
            .map_err(|e| AppError::Internal(format!("construct did:key secrets: {e}")))?
            .signing
    } else {
        let mut secret = Secret::from_multibase(&private_key_multibase, None).map_err(|e| {
            AppError::Internal(format!(
                "construct Secret for VTA signing key {key_id}: {e}"
            ))
        })?;
        secret.id = key_id;
        secret
    };

    Ok((vta_did, signing_secret))
}

fn apply_webvh_auth_state(stored: &mut WebvhServerAuthRecord, auth_state: &WebvhAuthState) {
    stored.access_token = Some(auth_state.access_token.clone());
    stored.access_expires_at = Some(auth_state.access_expires_at);
    if let Some(ref refresh_token) = auth_state.refresh_token {
        stored.refresh_token = Some(refresh_token.clone());
    }
}

async fn build_authenticated_rest_client(
    server: &WebvhServerRecord,
    url: &str,
    auth: &WebvhRestAuthContext<'_>,
) -> Result<WebvhClient, AppError> {
    let mut client = WebvhClient::new(url);
    let now = unix_now_secs();
    let stored = webvh_store::get_server_auth(auth.webvh_ks, &server.id).await?;

    if let Some(ref auth_state) = stored
        && access_token_is_fresh(auth_state, now)
    {
        if let Some(ref token) = auth_state.access_token {
            client.set_access_token(token.clone());
        }
        return Ok(client);
    }

    let mut updated = stored.unwrap_or_default();

    if let Some(refresh_token) = updated.refresh_token.clone() {
        match client.refresh_access_token(&refresh_token).await {
            Ok(auth_state) => {
                apply_webvh_auth_state(&mut updated, &auth_state);
                webvh_store::store_server_auth(auth.webvh_ks, &server.id, &updated).await?;
                client.set_access_token(auth_state.access_token);
                info!(
                    channel = auth.channel,
                    server_id = %server.id,
                    server_did = %server.did,
                    transport = "rest",
                    "refreshed stored WebVH REST access token"
                );
                return Ok(client);
            }
            Err(e) => {
                tracing::warn!(
                    channel = auth.channel,
                    server_id = %server.id,
                    server_did = %server.did,
                    error = %e,
                    "failed to refresh WebVH REST access token; falling back to full authentication"
                );
            }
        }
    }

    if auth.config.vta_did.as_deref().is_none_or(str::is_empty) {
        info!(
            channel = auth.channel,
            server_id = %server.id,
            server_did = %server.did,
            transport = "rest",
            "no configured vta_did yet; using unauthenticated WebVH REST client"
        );
        return Ok(client);
    }

    let (vta_did, signing_secret) =
        load_vta_signing_secret(auth.keys_ks, auth.seed_store, auth.config).await?;
    let auth_state = client
        .authenticate(&vta_did, &signing_secret, &server.did)
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "authenticate VTA DID {vta_did} to webvh server {} via REST: {e}",
                server.did
            ))
        })?;

    apply_webvh_auth_state(&mut updated, &auth_state);
    webvh_store::store_server_auth(auth.webvh_ks, &server.id, &updated).await?;
    client.set_access_token(auth_state.access_token);

    info!(
        channel = auth.channel,
        server_id = %server.id,
        server_did = %server.did,
        vta_did = %vta_did,
        transport = "rest",
        "authenticated VTA to WebVH REST endpoint"
    );

    Ok(client)
}

/// Unified transport for communicating with a WebVH server via REST or DIDComm.
///
/// Owns all necessary state so callers don't need to branch on transport type.
pub(super) enum WebvhTransport<'a> {
    Rest(WebvhClient),
    DIDComm {
        bridge: &'a DIDCommBridge,
        server_did: String,
    },
}

impl<'a> WebvhTransport<'a> {
    /// Resolve the server DID and construct the appropriate transport.
    ///
    /// Prefers `DIDCommMessaging` and falls back to REST when the DID exposes
    /// either `WebVHHosting` or `WebVHHostingService`.
    pub(super) async fn from_server(
        server: &WebvhServerRecord,
        did_resolver: &DIDCacheClient,
        didcomm_bridge: &'a Arc<DIDCommBridge>,
        rest_auth: &WebvhRestAuthContext<'_>,
    ) -> Result<Self, AppError> {
        let resolved = did_resolver.resolve(&server.did).await.map_err(|e| {
            AppError::Internal(format!("failed to resolve server DID {}: {e}", server.did))
        })?;

        match resolve_server_transport(
            &resolved.doc.service,
            |svc| &svc.type_,
            |svc| svc.service_endpoint.get_uri(),
        ) {
            Some(ResolvedServerTransport::Didcomm) => {
                info!(server_did = %server.did, transport = "didcomm", "resolved webvh server endpoint");
                Ok(Self::DIDComm {
                    bridge: didcomm_bridge,
                    server_did: server.did.clone(),
                })
            }
            Some(ResolvedServerTransport::Rest(url)) => {
                info!(server_did = %server.did, transport = "rest", %url, "resolved webvh server endpoint");
                let client = build_authenticated_rest_client(server, &url, rest_auth).await?;
                Ok(Self::Rest(client))
            }
            None => Err(AppError::Internal(format!(
                "server DID {} has no DIDCommMessaging, WebVHHosting, or WebVHHostingService endpoint",
                server.did,
            ))),
        }
    }

    async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        match self {
            Self::Rest(c) => c.request_uri(path).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .request_uri(path)
                    .await
            }
        }
    }

    pub(super) async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
    ) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.publish_did(mnemonic, log_content).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .publish_did(mnemonic, log_content)
                    .await
            }
        }
    }

    /// Atomic claim-and-publish — single round-trip alternative to
    /// `request_uri` + `publish_did`. The server commits slot
    /// allocation, log content, and owner index in one batch, so
    /// resolvers never see the slot empty.
    pub(super) async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
    ) -> Result<RequestUriResponse, AppError> {
        match self {
            Self::Rest(c) => c.register_did_atomic(path, did_log, force).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .register_did_atomic(path, did_log, force)
                    .await
            }
        }
    }

    async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.delete_did(mnemonic).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .delete_did(mnemonic)
                    .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) async fn derive_pre_rotation_keys(
    seed: &[u8],
    base: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
    count: u32,
) -> Result<(Vec<String>, Vec<PreRotationKeyData>), AppError> {
    if count == 0 {
        return Ok((vec![], vec![]));
    }

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| AppError::Internal(format!("failed to create BIP-32 root key: {e}")))?;

    let mut hashes = Vec::with_capacity(count as usize);
    let mut key_data = Vec::with_capacity(count as usize);

    for i in 0..count {
        let path = allocate_path(keys_ks, base)
            .await
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| AppError::Internal(format!("invalid derivation path: {e}")))?;
        let derived_key = root
            .derive(&derivation_path)
            .map_err(|e| AppError::Internal(format!("key derivation failed: {e}")))?;

        let secret = Secret::generate_ed25519(None, Some(derived_key.signing_key.as_bytes()));
        let pub_mb = secret
            .get_public_keymultibase()
            .map_err(|e| AppError::Internal(format!("{e}")))?;
        let hash = secret
            .get_public_keymultibase_hash()
            .map_err(|e| AppError::Internal(format!("{e}")))?;

        key_data.push(PreRotationKeyData {
            path,
            public_key: pub_mb,
            label: format!("{label} pre-rotation key {i}"),
        });

        hashes.push(hash);
    }

    Ok((hashes, key_data))
}

#[cfg(test)]
mod tests {
    use super::{
        ResolvedServerTransport, WEBVH_REST_TOKEN_REFRESH_SKEW_SECS, WebvhAuthState,
        access_token_is_fresh, apply_webvh_auth_state, resolve_server_transport,
    };
    use crate::webvh_store::WebvhServerAuthRecord;

    #[derive(Debug, Clone)]
    struct TestService {
        types: Vec<String>,
        uri: Option<String>,
    }

    fn service(types: &[&str], uri: Option<&str>) -> TestService {
        TestService {
            types: types.iter().map(|t| (*t).to_string()).collect(),
            uri: uri.map(str::to_string),
        }
    }

    #[test]
    fn resolve_server_transport_prefers_didcomm_when_both_didcomm_and_hosting_exist() {
        let services = [
            service(&["WebVHHosting"], Some("https://host.example.com/webvh/")),
            service(&["DIDCommMessaging"], Some("https://mediator.example.com")),
        ];

        assert_eq!(
            resolve_server_transport(&services, |svc| &svc.types, |svc| svc.uri.clone()),
            Some(ResolvedServerTransport::Didcomm)
        );
    }

    #[test]
    fn resolve_server_transport_uses_rest_for_webvh_hosting() {
        let services = [service(
            &["WebVHHosting"],
            Some("\"https://host.example.com/webvh/\""),
        )];

        assert_eq!(
            resolve_server_transport(&services, |svc| &svc.types, |svc| svc.uri.clone()),
            Some(ResolvedServerTransport::Rest(
                "https://host.example.com/webvh".to_string()
            ))
        );
    }

    #[test]
    fn resolve_server_transport_uses_rest_for_webvh_hosting_service() {
        let services = [service(
            &["WebVHHostingService"],
            Some("https://host.example.com/webvh/"),
        )];

        assert_eq!(
            resolve_server_transport(&services, |svc| &svc.types, |svc| svc.uri.clone()),
            Some(ResolvedServerTransport::Rest(
                "https://host.example.com/webvh".to_string()
            ))
        );
    }

    #[test]
    fn resolve_server_transport_returns_none_without_supported_service_types() {
        let services = [service(&["LinkedDomains"], Some("https://example.com"))];

        assert_eq!(
            resolve_server_transport(&services, |svc| &svc.types, |svc| svc.uri.clone()),
            None
        );
    }

    #[test]
    fn access_token_is_fresh_requires_nonempty_token_and_future_expiry() {
        let now = 1_000u64;
        let record = WebvhServerAuthRecord {
            access_token: Some("tok".into()),
            access_expires_at: Some(now + WEBVH_REST_TOKEN_REFRESH_SKEW_SECS + 1),
            refresh_token: None,
        };
        assert!(access_token_is_fresh(&record, now));

        let mut no_token = record.clone();
        no_token.access_token = None;
        assert!(!access_token_is_fresh(&no_token, now));

        let mut empty_token = record.clone();
        empty_token.access_token = Some(String::new());
        assert!(!access_token_is_fresh(&empty_token, now));

        let mut missing_expiry = record.clone();
        missing_expiry.access_expires_at = None;
        assert!(!access_token_is_fresh(&missing_expiry, now));
    }

    #[test]
    fn access_token_is_fresh_respects_refresh_skew_window() {
        let now = 5_000u64;
        let record = WebvhServerAuthRecord {
            access_token: Some("tok".into()),
            access_expires_at: Some(now + WEBVH_REST_TOKEN_REFRESH_SKEW_SECS),
            refresh_token: None,
        };

        assert!(
            !access_token_is_fresh(&record, now),
            "expiry at or inside the skew window must trigger refresh/auth"
        );
    }

    #[test]
    fn apply_webvh_auth_state_keeps_existing_refresh_token_when_not_reissued() {
        let mut record = WebvhServerAuthRecord {
            access_token: None,
            access_expires_at: None,
            refresh_token: Some("existing-refresh".into()),
        };

        apply_webvh_auth_state(
            &mut record,
            &WebvhAuthState {
                access_token: "new-access".into(),
                access_expires_at: 42,
                refresh_token: None,
            },
        );

        assert_eq!(record.access_token.as_deref(), Some("new-access"));
        assert_eq!(record.access_expires_at, Some(42));
        assert_eq!(record.refresh_token.as_deref(), Some("existing-refresh"));
    }
}
