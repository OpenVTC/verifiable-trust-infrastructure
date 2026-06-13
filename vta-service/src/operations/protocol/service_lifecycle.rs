//! Generic enable/update engine for the transport-service families
//! (`rest`, `webauthn`) — P2.3 part (a).
//!
//! `enable_rest` / `enable_webauthn` and `update_rest` / `update_webauthn`
//! were ~95% identical: they differ only in the config flag they read/flip,
//! the document patcher + service reader, the snapshot variant, the telemetry
//! kind, and (enable only) how "enabled" is persisted. This module captures
//! the shared skeleton once:
//!
//! ```text
//! super-admin → PROTOCOL_LOCK → validate URL → preconditions →
//! snapshot (pre-state) → patch document → publish (update_did_webvh) →
//! [persist enabled, enable only] → telemetry → result
//! ```
//!
//! The transport differences live behind [`ServiceLifecycle`] (all-sync hooks,
//! so the engine futures stay `Send`); the enable-vs-update *shape* is the two
//! `run_*` engines. The per-op modules keep their public `*Params` / `*Result`
//! / `*Error` types and become thin wrappers, so every caller (routes, DIDComm
//! dispatch, rollback) is untouched. Disable/rollback (brick-prevention) and
//! the DIDComm family are intentionally out of scope here.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use tracing::info;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use vta_sdk::protocol::services::validate_service_url;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::preconditions::ProtocolPreconditionError;
use crate::operations::protocol::snapshot::{self, ServiceConfigSnapshot};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK};
use crate::store::KeyspaceHandle;
use tokio::sync::RwLock;

/// Transport-specific hooks for the shared enable/update engine. One impl per
/// advertised transport service (`RestService`, `WebauthnService`). All methods
/// are synchronous so a generic engine over `S: ServiceLifecycle` produces a
/// `Send` future (the only async step — persisting "enabled" — is passed to
/// [`run_enable`] as a closure instead).
pub(crate) trait ServiceLifecycle {
    /// Human label for log lines (`"REST"`, `"WebAuthn"`).
    const LABEL: &'static str;
    /// Telemetry kind emitted on a successful enable.
    const ENABLE_TELEMETRY: TelemetryKind;
    /// Telemetry kind emitted on a successful update.
    const UPDATE_TELEMETRY: TelemetryKind;

    /// Is this service currently flagged on in the live config?
    fn config_enabled(cfg: &AppConfig) -> bool;
    /// The URL this service currently advertises in the DID document, if any.
    fn current_service_url(doc: &JsonValue) -> Option<String>;
    /// Patch the document to advertise `url` on this service entry (insert on
    /// enable, replace on update — the patcher is idempotent on shape).
    fn with_service(doc: JsonValue, url: &str) -> Result<JsonValue, DocumentPatchError>;
    /// Pre-state snapshot for an enable (rollback target = "off").
    fn snapshot_disabled() -> ServiceConfigSnapshot;
    /// Pre-state snapshot for an update (rollback target = the prior URL).
    fn snapshot_enabled(prior_url: String) -> ServiceConfigSnapshot;
}

/// Error-construction surface the engine needs. Implemented by each per-op
/// error enum so the engine builds the *caller's* error type directly — the
/// public `*Error` enums (matched by routes + DIDComm `ToProblemReport`) are
/// preserved unchanged. The `From` supertraits reuse the enums' existing
/// `#[from]` / `From<…>` impls for the `?`-propagated cases.
pub(crate) trait ServiceMutationError:
    Sized + From<ProtocolPreconditionError> + From<DocumentPatchError> + From<UpdateDidWebvhError>
{
    fn validation(msg: String) -> Self;
    fn auth(msg: String) -> Self;
    fn storage(msg: String) -> Self;
}

/// Enable-specific error constructors.
pub(crate) trait EnableMutationError: ServiceMutationError {
    fn already_enabled() -> Self;
    fn config_persistence(msg: String) -> Self;
}

/// Update-specific error constructors.
pub(crate) trait UpdateMutationError: ServiceMutationError {
    fn not_present() -> Self;
}

/// Successful enable/update outcome. The per-op wrapper maps this into its
/// public `*Result` (`prior_url` is `Some` only for updates).
pub(crate) struct ServiceMutationOk {
    pub new_version_id: String,
    pub canonical_url: String,
    pub vta_did: String,
    pub serverless: bool,
    pub prior_url: Option<String>,
}

/// Keyspaces + shared infra threaded into both engines. Bundling them keeps the
/// engine signatures (and the wrapper call sites) from sprawling past the
/// `too_many_arguments` line; the fields mirror the historical positional args.
pub(crate) struct ServiceLifecycleDeps<'a> {
    pub config: &'a Arc<RwLock<AppConfig>>,
    pub keys_ks: &'a KeyspaceHandle,
    pub imported_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub webvh_ks: &'a KeyspaceHandle,
    pub audit_ks: &'a KeyspaceHandle,
    pub snapshot_ks: &'a KeyspaceHandle,
    pub seed_store: &'a dyn SeedStore,
    pub did_resolver: &'a DIDCacheClient,
    pub didcomm_bridge: &'a Arc<DIDCommBridge>,
    pub telemetry: &'a SharedTelemetrySink,
    pub webvh_auth_locks: &'a crate::operations::did_webvh::WebvhAuthLocks,
}

/// Publish a patched document via `update_did_webvh` — the common publish step
/// shared by enable + update.
async fn publish_patch<E: ServiceMutationError>(
    deps: &ServiceLifecycleDeps<'_>,
    auth: &AuthClaims,
    scid: &str,
    vta_did: &str,
    patched: JsonValue,
    channel: &str,
) -> Result<crate::operations::did_webvh::UpdateDidWebvhResult, E> {
    update_did_webvh(
        deps.keys_ks,
        deps.imported_ks,
        deps.contexts_ks,
        deps.webvh_ks,
        deps.audit_ks,
        deps.seed_store,
        auth,
        scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        deps.did_resolver,
        deps.didcomm_bridge,
        Some(vta_did),
        deps.webvh_auth_locks,
        channel,
    )
    .await
    .map_err(E::from)
}

/// Enable preconditions: the service must be OFF in both the live config and
/// the on-chain DID document. A divergence surfaces as already-enabled (the
/// operator reconciles via `services list`). Returns the loaded doc state.
///
/// Extracted from [`run_enable`] so it stays unit-testable with just a config +
/// store fixture (no resolver / seed-store / bridge), preserving the coverage
/// the per-op `read_preconditions` helpers used to carry.
pub(crate) async fn check_enable_preconditions<S, E>(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<crate::operations::protocol::preconditions::VtaDocState, E>
where
    S: ServiceLifecycle,
    E: EnableMutationError,
{
    {
        let cfg = config.read().await;
        if S::config_enabled(&cfg) {
            return Err(E::already_enabled());
        }
    }
    let state =
        crate::operations::protocol::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    if S::current_service_url(&state.current_doc).is_some() {
        return Err(E::already_enabled());
    }
    Ok(state)
}

/// Update preconditions: the service must be ON in both the live config and the
/// on-chain document. Returns the loaded doc state plus the prior URL (the
/// rollback target captured for the snapshot).
pub(crate) async fn check_update_preconditions<S, E>(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<
    (
        crate::operations::protocol::preconditions::VtaDocState,
        String,
    ),
    E,
>
where
    S: ServiceLifecycle,
    E: UpdateMutationError,
{
    {
        let cfg = config.read().await;
        if !S::config_enabled(&cfg) {
            return Err(E::not_present());
        }
    }
    let state =
        crate::operations::protocol::preconditions::load_vta_doc_state(config, webvh_ks).await?;
    let prior_url = S::current_service_url(&state.current_doc).ok_or_else(E::not_present)?;
    Ok((state, prior_url))
}

/// Generic `enable_<service>` engine.
///
/// `persist_enabled` performs the (async, transport-specific) "flip to enabled"
/// step after a successful publish — REST writes runtime-state + the in-memory
/// flag, WebAuthn writes the config file. Passing it as a closure keeps
/// [`ServiceLifecycle`] all-sync (and the engine future `Send`).
pub(crate) async fn run_enable<S, E>(
    deps: &ServiceLifecycleDeps<'_>,
    auth: &AuthClaims,
    url: &str,
    ctx: OpContext,
    channel: &str,
    persist_enabled: impl AsyncFnOnce() -> Result<(), String>,
) -> Result<ServiceMutationOk, E>
where
    S: ServiceLifecycle,
    E: EnableMutationError,
{
    auth.require_super_admin()
        .map_err(|e| E::auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    let canonical_url = validate_service_url(url)
        .map_err(|e| E::validation(e.to_string()))?
        .to_string();

    let state = check_enable_preconditions::<S, E>(deps.config, deps.webvh_ks).await?;

    // Snapshot BEFORE the runtime mutation (spec §3.5a): pre-state is "off".
    snapshot::write(deps.snapshot_ks, S::snapshot_disabled())
        .await
        .map_err(|e| E::storage(format!("snapshot write: {e}")))?;

    let patched = S::with_service(state.current_doc, &canonical_url)?;
    let update_result =
        publish_patch::<E>(deps, auth, &state.scid, &state.vta_did, patched, channel).await?;

    persist_enabled().await.map_err(E::config_persistence)?;

    emit_telemetry(
        deps.telemetry,
        S::ENABLE_TELEMETRY,
        channel,
        &update_result.new_version_id,
        &canonical_url,
        None,
        ctx,
    )
    .await;
    info!(
        channel,
        url = %canonical_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %state.vta_did,
        "{} enabled",
        S::LABEL,
    );

    Ok(ServiceMutationOk {
        new_version_id: update_result.new_version_id,
        canonical_url,
        vta_did: state.vta_did,
        serverless: update_result.serverless,
        prior_url: None,
    })
}

/// Generic `update_<service>` engine. No config flip — the service stays
/// enabled; only the advertised URL changes. The prior URL is captured for the
/// rollback snapshot and surfaced in `prior_url`.
pub(crate) async fn run_update<S, E>(
    deps: &ServiceLifecycleDeps<'_>,
    auth: &AuthClaims,
    url: &str,
    ctx: OpContext,
    channel: &str,
) -> Result<ServiceMutationOk, E>
where
    S: ServiceLifecycle,
    E: UpdateMutationError,
{
    auth.require_super_admin()
        .map_err(|e| E::auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    let canonical_url = validate_service_url(url)
        .map_err(|e| E::validation(e.to_string()))?
        .to_string();

    let (state, prior_url) = check_update_preconditions::<S, E>(deps.config, deps.webvh_ks).await?;

    // Snapshot BEFORE the mutation (spec §3.5a): pre-state is the prior URL.
    snapshot::write(deps.snapshot_ks, S::snapshot_enabled(prior_url.clone()))
        .await
        .map_err(|e| E::storage(format!("snapshot write: {e}")))?;

    let patched = S::with_service(state.current_doc, &canonical_url)?;
    let update_result =
        publish_patch::<E>(deps, auth, &state.scid, &state.vta_did, patched, channel).await?;

    emit_telemetry(
        deps.telemetry,
        S::UPDATE_TELEMETRY,
        channel,
        &update_result.new_version_id,
        &canonical_url,
        Some(&prior_url),
        ctx,
    )
    .await;
    info!(
        channel,
        prior_url = %prior_url,
        url = %canonical_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %state.vta_did,
        "{} URL updated",
        S::LABEL,
    );

    Ok(ServiceMutationOk {
        new_version_id: update_result.new_version_id,
        canonical_url,
        vta_did: state.vta_did,
        serverless: update_result.serverless,
        prior_url: Some(prior_url),
    })
}

/// Shared telemetry emission (channel + version + URL, optional prior URL, plus
/// the `triggered_by` tag for rollback-dispatched ops).
async fn emit_telemetry(
    telemetry: &SharedTelemetrySink,
    kind: TelemetryKind,
    channel: &str,
    new_version_id: &str,
    url: &str,
    prior_url: Option<&str>,
    ctx: OpContext,
) {
    let mut event = TelemetryEvent::new(kind)
        .with_field("channel", JsonValue::from(channel))
        .with_field("new_version_id", JsonValue::from(new_version_id))
        .with_field("url", JsonValue::from(url));
    if let Some(prior) = prior_url {
        event = event.with_field("prior_url", JsonValue::from(prior));
    }
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;
}

/// REST transport (`#vta-rest`).
pub(crate) struct RestService;

impl ServiceLifecycle for RestService {
    const LABEL: &'static str = "REST";
    const ENABLE_TELEMETRY: TelemetryKind = TelemetryKind::ServicesRestEnable;
    const UPDATE_TELEMETRY: TelemetryKind = TelemetryKind::ServicesRestUpdate;

    fn config_enabled(cfg: &AppConfig) -> bool {
        cfg.services.rest
    }
    fn current_service_url(doc: &JsonValue) -> Option<String> {
        crate::operations::protocol::document::current_rest_service(doc).map(|s| s.url)
    }
    fn with_service(doc: JsonValue, url: &str) -> Result<JsonValue, DocumentPatchError> {
        crate::operations::protocol::document::with_rest_service(doc, url)
    }
    fn snapshot_disabled() -> ServiceConfigSnapshot {
        ServiceConfigSnapshot::Rest(crate::operations::protocol::snapshot::RestSnapshot::Disabled)
    }
    fn snapshot_enabled(prior_url: String) -> ServiceConfigSnapshot {
        ServiceConfigSnapshot::Rest(
            crate::operations::protocol::snapshot::RestSnapshot::Enabled { url: prior_url },
        )
    }
}

/// WebAuthn transport (`#vta-webauthn`).
pub(crate) struct WebauthnService;

impl ServiceLifecycle for WebauthnService {
    const LABEL: &'static str = "WebAuthn";
    const ENABLE_TELEMETRY: TelemetryKind = TelemetryKind::ServicesWebauthnEnable;
    const UPDATE_TELEMETRY: TelemetryKind = TelemetryKind::ServicesWebauthnUpdate;

    fn config_enabled(cfg: &AppConfig) -> bool {
        cfg.services.webauthn
    }
    fn current_service_url(doc: &JsonValue) -> Option<String> {
        crate::operations::protocol::document::current_webauthn_service(doc).map(|s| s.url)
    }
    fn with_service(doc: JsonValue, url: &str) -> Result<JsonValue, DocumentPatchError> {
        crate::operations::protocol::document::with_webauthn_service(doc, url)
    }
    fn snapshot_disabled() -> ServiceConfigSnapshot {
        ServiceConfigSnapshot::Webauthn(
            crate::operations::protocol::snapshot::WebauthnSnapshot::Disabled,
        )
    }
    fn snapshot_enabled(prior_url: String) -> ServiceConfigSnapshot {
        ServiceConfigSnapshot::Webauthn(
            crate::operations::protocol::snapshot::WebauthnSnapshot::Enabled { url: prior_url },
        )
    }
}
