//! Internal layout:
//! - `mod.rs` — `create_did_webvh`, `delete_did_webvh`, `WebvhTransport`,
//!   `CreateDidWebvhParams`, helpers still used only by the main flow
//! - `document` — pure DID-document construction (shared with the TEE
//!   enclave bootstrap path)
//! - `lifecycle` — read ops on stored DID records (`get`, `list`, log)
//! - `servers` — webvh hosting-server CRUD + DID validation

pub(crate) mod auth_cache;
mod concurrency;
mod document;
mod lifecycle;
mod register_server;
mod servers;
mod transport;
mod update;
mod webvh_keys;

pub use auth_cache::WebvhAuthLocks;
pub(crate) use auth_cache::{
    delete_log_on_server, publish_log_to_server, register_did_atomic_on_server,
};

pub(crate) use concurrency::{RaceDetected, RecordSnapshot};

pub(crate) use document::build_did_document_with_options;
pub use document::{build_did_document, build_vta_did_document_with_sealed_transfer};
pub use lifecycle::{GetDidWebvhLogResult, get_did_webvh, get_did_webvh_log, list_dids_webvh};
pub use register_server::{
    RegisterDidWithServerError, RegisterDidWithServerParams, RegisterDidWithServerResult,
    register_did_with_server,
};
pub use servers::{
    add_webvh_server, list_webvh_server_domains, list_webvh_servers, remove_webvh_server,
    update_webvh_server,
};
pub use update::{
    RotateDidWebvhKeysOptions, UpdateDidWebvhError, UpdateDidWebvhOptions, UpdateDidWebvhResult,
    UpdatePlan, plan_did_webvh_update, rotate_did_webvh_keys, state_from_jsonl_pub,
    update_did_webvh,
};

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use didwebvh_rs::create::{CreateDIDConfig, create_did};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use tracing::{info, warn};
use url::Url;

use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::didcomm_bridge::DIDCommBridge;

use vta_sdk::protocols::did_management::{
    create::{CreateDidWebvhBody, CreateDidWebvhResultBody, WebvhPathMode},
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
use crate::webvh_client::{RequestUriResponse, WebvhClient};
use crate::webvh_didcomm::WebvhDIDCommClient;
use crate::webvh_store;
use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
use zeroize::Zeroize;

use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

/// Shared dependency bundle for the WebVH DID-management operations
/// (`delete_did_webvh`, `rotate_did_webvh_keys`, `register_did_with_server`,
/// `list_webvh_server_domains`) — P2.5.
///
/// These ops each took the same 11–14 positional arguments: the five keyspaces
/// the WebVH publish path touches (keys / imported / contexts / webvh / audit)
/// plus `seed_store`, `did_resolver`, `didcomm_bridge`, and the per-server
/// `auth_locks`. Bundling them into one borrowed struct — built once at the
/// transport boundary via [`WebvhDeps::from_app_state`] /
/// [`WebvhDeps::from_vta_state`] (or directly by the offline CLI / tests) and
/// threaded through unchanged — drops every op to ≤6 args.
///
/// All fields are borrows. The per-op identity (`vta_did`, `scid`, the DID
/// being operated on, the WebVH server target) stays a separate argument — it
/// varies per call and isn't ambient state. `contexts_ks` is read only by
/// `rotate_did_webvh_keys`; the other ops ignore it.
pub struct WebvhDeps<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub imported_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub webvh_ks: &'a KeyspaceHandle,
    pub audit_ks: &'a KeyspaceHandle,
    pub seed_store: &'a dyn SeedStore,
    pub did_resolver: &'a DIDCacheClient,
    pub didcomm_bridge: &'a Arc<DIDCommBridge>,
    pub auth_locks: &'a WebvhAuthLocks,
}

impl<'a> WebvhDeps<'a> {
    /// Borrow the WebVH op dependencies from an [`AppState`](crate::server::AppState)
    /// (REST + trust-task transports). `did_resolver` is threaded separately
    /// because `AppState` holds it as an `Option` — the caller unwraps it
    /// (surfacing the typed "DID resolver not available" reject) first.
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    pub fn from_app_state(
        s: &'a crate::server::AppState,
        did_resolver: &'a DIDCacheClient,
    ) -> Self {
        Self {
            keys_ks: &s.keys_ks,
            imported_ks: &s.imported_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            audit_ks: &s.audit_ks,
            seed_store: &*s.seed_store,
            did_resolver,
            didcomm_bridge: &s.didcomm_bridge,
            auth_locks: &s.webvh_auth_locks,
        }
    }

    /// Borrow the WebVH op dependencies from a
    /// [`VtaState`](crate::messaging::router::VtaState) (DIDComm transport).
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    pub fn from_vta_state(
        s: &'a crate::messaging::router::VtaState,
        did_resolver: &'a DIDCacheClient,
    ) -> Self {
        Self {
            keys_ks: &s.keys_ks,
            imported_ks: &s.imported_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            audit_ks: &s.audit_ks,
            seed_store: &*s.seed_store,
            did_resolver,
            didcomm_bridge: &s.didcomm_bridge,
            auth_locks: &s.webvh_auth_locks,
        }
    }
}

/// Dependency bundle for [`create_did_webvh`] — P2.5.
///
/// Create has a *different* shape from [`WebvhDeps`]: it mints + stores a new
/// DID locally (no remote publish at create time, so no `auth_locks` / `audit_ks`
/// / `vta_did`), but it renders a DID template (`did_templates_ks`) and reads
/// operator config (`config`). Distinct struct rather than a strained reuse.
///
/// `config` is a borrowed `&AppConfig` snapshot — REST/DIDComm callers pass the
/// guard from `state.config.read().await`, so the constructors take it as an
/// explicit argument (it can't be produced synchronously from `&state`).
pub struct CreateDidWebvhDeps<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub imported_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub webvh_ks: &'a KeyspaceHandle,
    pub did_templates_ks: &'a KeyspaceHandle,
    /// Audit keyspace — needed to load the VTA's own signing identity
    /// (`load_vta_webvh_signing_identity`) when authenticating a
    /// server publish. Only touched on the non-serverless path.
    pub audit_ks: &'a KeyspaceHandle,
    pub seed_store: &'a dyn SeedStore,
    pub config: &'a AppConfig,
    pub did_resolver: &'a DIDCacheClient,
    pub didcomm_bridge: &'a Arc<DIDCommBridge>,
    /// Per-server auth-cache mutex registry — serialises token
    /// refresh/reauth against a hosting daemon. Only used when
    /// publishing to a registered server (not serverless / did:key).
    pub auth_locks: &'a WebvhAuthLocks,
}

impl<'a> CreateDidWebvhDeps<'a> {
    /// Borrow create-deps from an [`AppState`](crate::server::AppState) (REST +
    /// trust-task). `config` (the read-guard snapshot) and the unwrapped
    /// `did_resolver` are threaded separately.
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    pub fn from_app_state(
        s: &'a crate::server::AppState,
        config: &'a AppConfig,
        did_resolver: &'a DIDCacheClient,
    ) -> Self {
        Self {
            keys_ks: &s.keys_ks,
            imported_ks: &s.imported_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            did_templates_ks: &s.did_templates_ks,
            audit_ks: &s.audit_ks,
            seed_store: &*s.seed_store,
            config,
            did_resolver,
            didcomm_bridge: &s.didcomm_bridge,
            auth_locks: &s.webvh_auth_locks,
        }
    }

    /// Borrow create-deps from a
    /// [`VtaState`](crate::messaging::router::VtaState) (DIDComm transport).
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    pub fn from_vta_state(
        s: &'a crate::messaging::router::VtaState,
        config: &'a AppConfig,
        did_resolver: &'a DIDCacheClient,
    ) -> Self {
        Self {
            keys_ks: &s.keys_ks,
            imported_ks: &s.imported_ks,
            contexts_ks: &s.contexts_ks,
            webvh_ks: &s.webvh_ks,
            did_templates_ks: &s.did_templates_ks,
            audit_ks: &s.audit_ks,
            seed_store: &*s.seed_store,
            config,
            did_resolver,
            didcomm_bridge: &s.didcomm_bridge,
            auth_locks: &s.webvh_auth_locks,
        }
    }
}

/// Refresh the resolver cache for `did` from the provided did.jsonl content.
///
/// This runs after local did-log mutations so subsequent in-process resolves
/// observe the newest DID document without waiting for process restart.
///
/// Fail-safe on error: if the new log can't be parsed/deserialized we **keep**
/// the existing cache entry rather than evicting it. For the VTA's own DID the
/// runtime-service-management invariant keeps `verificationMethod` byte-identical
/// across mutations, so a stale-but-present self-document still carries the exact
/// keys DIDComm pack/unpack needs — strictly safer than dropping the entry, which
/// for a serverless / network-unreachable `did:webvh` would leave self-resolution
/// with no source at all. Failures are non-fatal regardless: the mutation already
/// committed, and normal resolver network fallback remains available.
pub(crate) async fn refresh_resolver_doc_from_log(
    did_resolver: &DIDCacheClient,
    did: &str,
    did_log: &str,
    channel: &str,
) {
    let doc_value = match crate::operations::protocol::document::current_document_from_log(did_log)
    {
        Ok(doc) => doc,
        Err(e) => {
            warn!(
                channel,
                did = %did,
                error = %e,
                "resolver refresh skipped: parse current DID document from did.jsonl failed; keeping last-known-good cache entry"
            );
            return;
        }
    };

    let doc = match serde_json::from_value(doc_value) {
        Ok(doc) => doc,
        Err(e) => {
            warn!(
                channel,
                did = %did,
                error = %e,
                "resolver refresh skipped: deserialize DID document failed; keeping last-known-good cache entry"
            );
            return;
        }
    };

    let mut cache = did_resolver.clone();
    cache.add_did_document(did, doc).await;
}

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
    /// How to choose the server-managed DID's `<path>` segment. Drives
    /// the host's `check-name`/`create_did` call (`WellKnown` →
    /// `.well-known`, `Explicit` → label, `AutoAssign` → host allocates).
    /// Ignored in serverless mode (`server_id` is `None`).
    pub path_mode: WebvhPathMode,
    /// Optional explicit hosting domain on the target server.
    /// Honored only for server-managed DIDs (when `server_id` is set);
    /// ignored in serverless mode. Resolution chain on the remote:
    /// explicit → caller's ACL default on the server → server's
    /// system default → reject with `did-management:unknown_domain`.
    /// Enables a VTA managing slots across multiple tenant domains
    /// on one shared `did-hosting-control` backplane to direct
    /// provisioning at the right tenant.
    pub domain: Option<String>,
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
            // Explicit `path_mode` wins; otherwise interpret the legacy
            // `path` field so pre-enum wire callers keep working.
            path_mode: WebvhPathMode::resolve(body.path_mode, body.path),
            domain: body.domain,
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

/// A synthetic, strictly-increasing, backdated `versionTime` for the VTA's next
/// did:webvh log entry. did:webvh serialises `versionTime` at second granularity
/// and requires each entry to be strictly later than the previous and not in the
/// future; the real wall-clock value is irrelevant for resolution. We backdate a
/// day and space entries a minute apart by their index, so the VTA can create
/// then update its DID back-to-back (e.g. `setup` then `services didcomm enable`)
/// without producing same-second timestamps that serialise identically and make
/// the DID unresolvable. `existing_entry_count` is the number of log entries
/// already in the chain (0 for the genesis entry).
fn backdated_version_time(existing_entry_count: usize) -> chrono::DateTime<chrono::FixedOffset> {
    use chrono::Duration;
    Utc::now().fixed_offset() - Duration::days(1) + Duration::minutes(existing_entry_count as i64)
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

/// Build an *authenticated* hosting-server transport for a create-DID
/// publish/request-uri call.
///
/// This is the create-path analogue of the `auth_cache::*_on_server`
/// helpers (which take a [`WebvhDeps`], not a [`CreateDidWebvhDeps`]).
/// It loads the VTA's own signing identity via `config.vta_did`,
/// constructs an [`auth_cache::AuthContext`], and hands it to
/// [`WebvhTransport::from_server_authenticated`], which applies a fresh
/// Bearer token for REST transports and no-ops for DIDComm (authcrypt
/// authenticates at the envelope layer).
///
/// The returned transport does not borrow the (locally-owned) signing
/// identity — `from_server_authenticated` consumes the `AuthContext`
/// synchronously while minting/refreshing the token, so the identity can
/// be dropped as soon as this helper returns.
///
/// Returns a clear [`AppError`] when `config.vta_did` is `None`: a server
/// publish requires the VTA to authenticate to the hosting daemon with
/// its own DID, and there is no identity to sign the auth challenge with.
#[allow(clippy::too_many_arguments)]
async fn authenticated_server_transport<'a>(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &'a Arc<DIDCommBridge>,
    auth_locks: &WebvhAuthLocks,
    vta_did: Option<&str>,
    server: &WebvhServerRecord,
) -> Result<WebvhTransport<'a>, AppError> {
    let vta_did = vta_did.ok_or_else(|| {
        AppError::Validation(
            "vta_did is not configured; the VTA needs its own DID to authenticate to a webvh \
             hosting server (set `vta_did` in config / VTA_DID)"
                .into(),
        )
    })?;
    let identity = auth_cache::load_vta_webvh_signing_identity(
        keys_ks,
        imported_ks,
        seed_store,
        audit_ks,
        vta_did,
    )
    .await?;
    let auth_ctx = auth_cache::AuthContext {
        webvh_ks,
        identity: &identity,
        locks: auth_locks,
    };
    WebvhTransport::from_server_authenticated(server, did_resolver, didcomm_bridge, &auth_ctx).await
}

pub async fn create_did_webvh(
    deps: &CreateDidWebvhDeps<'_>,
    auth: &AuthClaims,
    mut params: CreateDidWebvhParams,
    channel: &str,
) -> Result<CreateDidWebvhResultBody, AppError> {
    // Re-bind the bundled deps to the historical local names so the (large)
    // body below is unchanged. All fields are `Copy` references, so this
    // copies the borrows out of `*deps` rather than moving the struct.
    let CreateDidWebvhDeps {
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        did_templates_ks,
        audit_ks,
        seed_store,
        config,
        did_resolver,
        didcomm_bridge,
        auth_locks,
    } = *deps;

    auth.require_admin()?;
    auth.require_context(&params.context_id)?;

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
        // Final mode (a client-provided, pre-signed did.jsonl) is serverless-only.
        // Publishing a pre-signed log to a hosting server would use the SCID as the
        // mnemonic path segment with no prior slot reservation — which the host
        // rejects (a base58 SCID is mixed-case, and the slot was never registered)
        // — so a server-managed final-mode create can never succeed. No first-party
        // flow uses it (setup's advanced `did_log` path is always serverless). Fail
        // fast, before parsing the log, with an actionable error instead of a
        // confusing downstream mnemonic-validation failure at the host. (D4-F2)
        if !serverless {
            return Err(AppError::Validation(
                "final-mode create (a pre-signed `did_log`) is only supported \
                 serverless — `server_id` must be unset. To create a server-hosted \
                 DID, use template or did_document mode instead."
                    .into(),
            ));
        }

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
        refresh_resolver_doc_from_log(did_resolver, &final_did, did_log, channel).await;

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

        let transport = authenticated_server_transport(
            keys_ks,
            imported_ks,
            seed_store,
            audit_ks,
            webvh_ks,
            did_resolver,
            didcomm_bridge,
            auth_locks,
            config.vta_did.as_deref(),
            &server,
        )
        .await?;
        // Domain selection: `params.domain` is the explicit caller-
        // supplied override (pnm CLI `--domain`). When omitted, the
        // remote resolves via caller's ACL default → system default.
        let uri_response = transport
            .request_uri(params.path_mode.to_request_path(), params.domain.as_deref())
            .await?;

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
        // Backdated genesis timestamp (entry index 0) so a follow-on update in
        // the same second doesn't collide — see `backdated_version_time`.
        .version_time(backdated_version_time(0))
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
        refresh_resolver_doc_from_log(did_resolver, &final_did, &log_content, channel).await;

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

        let transport = authenticated_server_transport(
            keys_ks,
            imported_ks,
            seed_store,
            audit_ks,
            webvh_ks,
            did_resolver,
            didcomm_bridge,
            auth_locks,
            config.vta_did.as_deref(),
            &server,
        )
        .await?;
        // Reuse the same `params.domain` selection the request_uri
        // call above used. The remote already knows the slot's domain
        // from the reservation, so this is a redundant override —
        // sending it explicitly catches a misconfigured caller before
        // the log lands on the wrong domain.
        transport
            .publish_did(mnemonic, &log_content, params.domain.as_deref())
            .await?;

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
        refresh_resolver_doc_from_log(did_resolver, &final_did, &log_content, channel).await;

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

pub async fn delete_did_webvh(
    deps: &WebvhDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    vta_did: Option<&str>,
    channel: &str,
) -> Result<DeleteDidWebvhResultBody, AppError> {
    auth.require_admin()?;

    let record = webvh_store::get_did(deps.webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;
    // Mirror the context-scoping that create/get/get_log/list already
    // enforce on this record. Without this check, any context-scoped
    // admin could trigger remote deletion (via record.mnemonic) and
    // local key cleanup of DIDs owned by other contexts on the same
    // VTA.
    auth.require_context(&record.context_id)?;

    // Resolve server for remote deletion. Track the outcome so the
    // operator can act on a daemon-side orphan rather than seeing
    // local cleanup succeed silently. (Spec / audit H4: surface the
    // failure on the result body.)
    let mut daemon_cleanup_error: Option<String> = None;
    let server = webvh_store::get_server(deps.webvh_ks, &record.server_id).await?;
    if let Some(server) = server {
        match vta_did {
            Some(vta_did_value) => {
                if let Err(e) =
                    delete_log_on_server(deps, vta_did_value, &server, &record.mnemonic, None).await
                {
                    tracing::warn!(
                        did = %did,
                        server_id = %server.id,
                        error = %e,
                        "did-hosting-daemon delete_did failed; continuing local cleanup but DID is now orphaned on the daemon"
                    );
                    daemon_cleanup_error = Some(format!(
                        "daemon `{}` rejected delete: {e} — DID is orphaned on the daemon and \
                         must be cleaned up out-of-band",
                        server.id
                    ));
                }
            }
            None => {
                let msg = format!(
                    "VTA DID is not configured — skipping daemon-side delete on server `{}`. \
                     Local record removed, but the daemon entry is now orphaned.",
                    server.id
                );
                tracing::warn!(did = %did, "{msg}");
                daemon_cleanup_error = Some(msg);
            }
        }
    }

    // Remove local DID record and log
    webvh_store::delete_did(deps.webvh_ks, did).await?;

    // Clean up associated key records (best-effort)
    for key_id in &[format!("{did}#key-0"), format!("{did}#key-1")] {
        let _ = deps.keys_ks.remove(keys::store_key(key_id)).await;
    }
    // Clean up pre-rotation key records (M4: bound to the record's
    // declared count so a DID created with a high pre_rotation_count
    // doesn't leak entries).
    let pre_rotation_bound = std::cmp::max(record.pre_rotation_count, 32);
    for i in 0..pre_rotation_bound {
        let key_id = format!("{did}#pre-rotation-{i}");
        let store_key = keys::store_key(&key_id);
        if deps.keys_ks.get_raw(store_key.clone()).await?.is_none() {
            break;
        }
        let _ = deps.keys_ks.remove(store_key).await;
    }

    info!(channel, did = %did, "webvh DID deleted");
    Ok(DeleteDidWebvhResultBody {
        did: did.to_string(),
        deleted: true,
        daemon_cleanup_error,
    })
}

// ---------------------------------------------------------------------------
// WebVH transport abstraction
// ---------------------------------------------------------------------------

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
    /// Transport selection is delegated to the pure
    /// [`transport::resolve_server_transport`] helper — DIDComm wins
    /// over REST regardless of service[] ordering, and both
    /// `WebVHHosting` (current) and `WebVHHostingService` (legacy
    /// alias) are accepted on read. See [`transport`] for the
    /// canonical set of types we emit vs. accept.
    pub(super) async fn from_server(
        server: &WebvhServerRecord,
        did_resolver: &DIDCacheClient,
        didcomm_bridge: &'a Arc<DIDCommBridge>,
    ) -> Result<Self, AppError> {
        let resolved = did_resolver.resolve(&server.did).await.map_err(|e| {
            AppError::Internal(format!("failed to resolve server DID {}: {e}", server.did))
        })?;

        match transport::resolve_server_transport(&resolved.doc.service) {
            Some(transport::ResolvedTransport::DIDComm) => {
                info!(server_did = %server.did, transport = "didcomm", "resolved webvh server endpoint");
                Ok(Self::DIDComm {
                    bridge: didcomm_bridge,
                    server_did: server.did.clone(),
                })
            }
            Some(transport::ResolvedTransport::Rest { url }) => {
                info!(server_did = %server.did, transport = "rest", %url, "resolved webvh server endpoint");
                // The access token (if any) is now loaded from
                // `server-auth:{id}` by the auth-cache layer rather
                // than embedded on the public `WebvhServerRecord`.
                // Construction here is unauthenticated; callers that
                // need an authenticated request set the token via
                // `set_access_token` after consulting the auth cache.
                let client = WebvhClient::new(&url, &server.did)?;
                Ok(Self::Rest(client))
            }
            None => Err(AppError::Validation(format!(
                "server DID {} has no supported webvh endpoint (expected: {})",
                server.did,
                transport::SUPPORTED_TYPES_HUMAN,
            ))),
        }
    }

    async fn request_uri(
        &self,
        path: Option<&str>,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        match self {
            Self::Rest(c) => c.request_uri(path, domain).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .request_uri(path, domain)
                    .await
            }
        }
    }

    pub(super) async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => c.publish_did(mnemonic, log_content, domain).await,
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .publish_did(mnemonic, log_content, domain)
                    .await
            }
        }
    }

    // The unauthenticated `register_did_atomic` and `delete_did`
    // methods that used to live here have been removed — every call
    // site now goes through the auth-cache helpers
    // (`auth_cache::publish_log_to_server`, `delete_log_on_server`,
    // `register_did_atomic_on_server`) which use the
    // `_authenticated` variants below.

    // ── Authenticated transport + 401-retry wrappers ──────────────
    //
    // The methods above keep the original "dumb transport" API for
    // call sites that don't authenticate (e.g. read-only resolution
    // tests). Mutating operations against an ACL-protected daemon
    // go through the wrappers below, which:
    //
    // 1. Ensure the REST client carries a fresh bearer token (loaded
    //    via `auth_cache::ensure_fresh_access_token` under the
    //    per-server async mutex), and
    // 2. On `Unauthorized` from the daemon mid-window — meaning the
    //    daemon revoked the token between the cache check and the
    //    call — invalidate the cache, re-authenticate, retry once.
    //
    // DIDComm transports are pass-through: there's no auth-cache
    // state, and authcrypt handles the equivalent at the envelope
    // layer.

    /// Build a transport with a freshly-validated access token
    /// already applied (REST only). For DIDComm transports this
    /// behaves identically to [`Self::from_server`] since DIDComm
    /// authentication lives at the envelope layer.
    pub(super) async fn from_server_authenticated(
        server: &WebvhServerRecord,
        did_resolver: &DIDCacheClient,
        didcomm_bridge: &'a Arc<DIDCommBridge>,
        auth_ctx: &auth_cache::AuthContext<'_>,
    ) -> Result<Self, AppError> {
        let mut transport = Self::from_server(server, did_resolver, didcomm_bridge).await?;
        if let Self::Rest(ref mut client) = transport {
            auth_cache::ensure_fresh_access_token(auth_ctx, server, client).await?;
        }
        Ok(transport)
    }

    /// `publish_did` with one-shot 401 retry. If the daemon returns
    /// 401 mid-window (token revoked), invalidate the cache,
    /// re-authenticate, and retry exactly once.
    pub(super) async fn publish_did_authenticated(
        &mut self,
        mnemonic: &str,
        log_content: &str,
        domain: Option<&str>,
        auth_ctx: &auth_cache::AuthContext<'_>,
        server: &WebvhServerRecord,
    ) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => match c.publish_did(mnemonic, log_content, domain).await {
                Ok(()) => Ok(()),
                Err(AppError::Unauthorized(_)) => {
                    info!(
                        server_id = %server.id,
                        "webvh publish_did got 401; invalidating cache and retrying"
                    );
                    auth_cache::invalidate_cached_token(auth_ctx.webvh_ks, &server.id).await?;
                    auth_cache::ensure_fresh_access_token(auth_ctx, server, c).await?;
                    c.publish_did(mnemonic, log_content, domain).await
                }
                Err(e) => Err(e),
            },
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .publish_did(mnemonic, log_content, domain)
                    .await
            }
        }
    }

    /// `delete_did` with one-shot 401 retry.
    pub(super) async fn delete_did_authenticated(
        &mut self,
        mnemonic: &str,
        domain: Option<&str>,
        auth_ctx: &auth_cache::AuthContext<'_>,
        server: &WebvhServerRecord,
    ) -> Result<(), AppError> {
        match self {
            Self::Rest(c) => match c.delete_did(mnemonic, domain).await {
                Ok(()) => Ok(()),
                Err(AppError::Unauthorized(_)) => {
                    info!(
                        server_id = %server.id,
                        "webvh delete_did got 401; invalidating cache and retrying"
                    );
                    auth_cache::invalidate_cached_token(auth_ctx.webvh_ks, &server.id).await?;
                    auth_cache::ensure_fresh_access_token(auth_ctx, server, c).await?;
                    c.delete_did(mnemonic, domain).await
                }
                Err(e) => Err(e),
            },
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .delete_did(mnemonic, domain)
                    .await
            }
        }
    }

    /// `register_did_atomic` with one-shot 401 retry.
    pub(super) async fn register_did_atomic_authenticated(
        &mut self,
        path: &str,
        did_log: &str,
        force: bool,
        domain: Option<&str>,
        auth_ctx: &auth_cache::AuthContext<'_>,
        server: &WebvhServerRecord,
    ) -> Result<RequestUriResponse, AppError> {
        match self {
            Self::Rest(c) => match c.register_did_atomic(path, did_log, force, domain).await {
                Ok(r) => Ok(r),
                Err(AppError::Unauthorized(_)) => {
                    info!(
                        server_id = %server.id,
                        "webvh register_did_atomic got 401; invalidating cache and retrying"
                    );
                    auth_cache::invalidate_cached_token(auth_ctx.webvh_ks, &server.id).await?;
                    auth_cache::ensure_fresh_access_token(auth_ctx, server, c).await?;
                    c.register_did_atomic(path, did_log, force, domain).await
                }
                Err(e) => Err(e),
            },
            Self::DIDComm { bridge, server_did } => {
                WebvhDIDCommClient::new(bridge, server_did)
                    .register_did_atomic(path, did_log, force, domain)
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
    use std::sync::Arc;

    use super::*;
    use crate::store::Store;
    use crate::webvh_store;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use didwebvh_rs::create::{CreateDIDConfig, create_did};
    use serde_json::json;
    use tempfile::TempDir;
    use vti_common::acl::Role;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// `backdated_version_time` must yield timestamps that are (a) in
    /// the past (did:webvh rejects future `versionTime`) and (b)
    /// strictly increasing by entry index at *second* granularity, so
    /// a genesis-create and a follow-on update minted in the same
    /// wall-clock second don't collide. This is the helper behind the
    /// `services didcomm enable`-right-after-`setup` fix (PR #600).
    #[test]
    fn backdated_version_time_is_past_and_strictly_increasing() {
        let now = chrono::Utc::now();

        let t0 = backdated_version_time(0);
        let t1 = backdated_version_time(1);
        let t2 = backdated_version_time(2);

        // Backdated — comfortably in the past (roughly a day).
        assert!(
            t0 < now.fixed_offset(),
            "genesis timestamp must be in the past"
        );
        assert!(
            t2 < now.fixed_offset(),
            "later timestamps must still be in the past"
        );

        // Strictly increasing by index …
        assert!(t0 < t1, "entry 1 must be strictly after entry 0");
        assert!(t1 < t2, "entry 2 must be strictly after entry 1");

        // … and distinct even after did:webvh's second-granularity
        // truncation — index spacing (a minute apart) guarantees a
        // whole-second gap, which is what the same-second collision
        // needed. Compare truncated-to-second Unix timestamps.
        assert_ne!(
            t0.timestamp(),
            t1.timestamp(),
            "entries must differ at second precision"
        );
        assert_ne!(t1.timestamp(), t2.timestamp());
    }

    /// Pin the post-fetch context-scoping invariant that `delete_did_webvh`
    /// enforces. A context-A admin must not be able to delete a DID record
    /// owned by context B, even when the record exists and the caller has
    /// `Role::Admin`. The full function is heavyweight (DIDComm bridge,
    /// resolver, seed store) so this exercises the invariant against a
    /// realistic planted record using the same `webvh_store::get_did` +
    /// `auth.require_context(&record.context_id)` sequence the operation
    /// runs first.
    #[tokio::test]
    async fn delete_did_webvh_blocks_cross_context_admin() {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let webvh_ks = store.keyspace(crate::keyspaces::WEBVH).expect("keyspace");

        let now = Utc::now();
        let did = "did:webvh:QmTest:example.com:abc";
        webvh_store::store_did(
            &webvh_ks,
            &WebvhDidRecord {
                did: did.to_string(),
                server_id: "prod".to_string(),
                mnemonic: "fixture-mnemonic".to_string(),
                scid: "QmTest".to_string(),
                context_id: "ctx-b".to_string(),
                portable: false,
                log_entry_count: 1,
                pre_rotation_count: 0,
                next_fragment_id: 1,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("plant did record");

        let auth_a = AuthClaims {
            did: "did:key:z6MkCtxAAdmin".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["ctx-a".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };

        // Mirror the prelude `delete_did_webvh` runs before any I/O.
        auth_a.require_admin().expect("admin floor passes");
        let record = webvh_store::get_did(&webvh_ks, did)
            .await
            .expect("get_did ok")
            .expect("record present");
        let err = auth_a
            .require_context(&record.context_id)
            .expect_err("context-A admin must not pass require_context for ctx-b");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden, got: {err:?}"
        );

        // Sanity check: same call from a ctx-B admin passes.
        let auth_b = AuthClaims {
            did: "did:key:z6MkCtxBAdmin".to_string(),
            role: Role::Admin,
            allowed_contexts: vec!["ctx-b".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        auth_b
            .require_context(&record.context_id)
            .expect("ctx-B admin passes require_context for ctx-b");
    }

    async fn sample_did_log_for_refresh() -> (String, String, serde_json::Value) {
        use didwebvh_rs::parameters::Parameters as WebVHParameters;

        let mut signing =
            affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pub_mb = signing
            .get_public_keymultibase()
            .expect("public key multibase");
        signing.id = format!("did:key:{pub_mb}#{pub_mb}");

        let did_document = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "{DID}",
            "verificationMethod": [{
                "id": "{DID}#key-0",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": pub_mb,
            }],
            "authentication": ["{DID}#key-0"],
            "assertionMethod": ["{DID}#key-0"],
        });

        let parameters = WebVHParameters {
            update_keys: Some(Arc::new(vec![pub_mb.clone().into()])),
            ..Default::default()
        };

        let cfg = CreateDIDConfig::builder()
            .address("https://example.invalid/.well-known/did/did.jsonl")
            .authorization_key(signing)
            .did_document(did_document)
            .parameters(parameters)
            .build()
            .expect("create did config");

        let result = create_did(cfg).await.expect("create did");
        let did = result.did().to_string();
        let did_log = serde_json::to_string(result.log_entry()).expect("serialize did log entry");
        let expected_doc_value =
            crate::operations::protocol::document::current_document_from_log(&did_log)
                .expect("current document from log");
        (did, did_log, expected_doc_value)
    }

    #[tokio::test]
    async fn refresh_resolver_doc_from_log_seeds_cache_from_log() {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver");
        let (did, did_log, expected_doc_value) = sample_did_log_for_refresh().await;

        refresh_resolver_doc_from_log(&resolver, &did, &did_log, "test").await;

        let resolved = resolver
            .resolve(&did)
            .await
            .expect("resolve from refreshed cache");
        assert!(resolved.cache_hit, "expected cache hit after refresh");

        let expected_doc =
            serde_json::from_value(expected_doc_value).expect("deserialize expected did document");
        assert_eq!(resolved.doc, expected_doc);
    }

    #[tokio::test]
    async fn refresh_resolver_doc_from_log_preserves_cache_on_parse_failure() {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("resolver");
        let mut signing =
            affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pub_mb = signing
            .get_public_keymultibase()
            .expect("public key multibase");
        signing.id = format!("did:key:{pub_mb}#{pub_mb}");
        let did = format!("did:key:{pub_mb}");

        // A minimal did.jsonl line with a did:key state is enough to seed the
        // cache with a known-good entry we can then assert survives a failed
        // refresh.
        let did_log = serde_json::to_string(&json!({
            "versionId": "1-test",
            "versionTime": "2026-01-01T00:00:00Z",
            "parameters": {},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
            }
        }))
        .expect("serialize did log");

        refresh_resolver_doc_from_log(&resolver, &did, &did_log, "test").await;
        let seeded = resolver
            .resolve(&did)
            .await
            .expect("resolve seeded DID from cache");
        assert!(
            seeded.cache_hit,
            "sanity: DID should be served from cache after the good refresh"
        );

        // A failed refresh must be fail-safe: keep the last-known-good entry
        // rather than evicting it (evicting would strand a non-network-resolvable
        // self-DID). The entry stays cached.
        refresh_resolver_doc_from_log(&resolver, &did, "not-a-valid-did-log", "test").await;

        let after = resolver
            .resolve(&did)
            .await
            .expect("resolve after failed refresh");
        assert!(
            after.cache_hit,
            "after a failed refresh the prior cache entry must be preserved (still a cache hit)"
        );
    }
}
