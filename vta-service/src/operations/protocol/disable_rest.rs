//! `disable_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.2,
//! §3.4.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Confirm `services.rest` is currently `true` AND a `#vta-rest`
//!    entry exists in the DID document — refuse with
//!    [`DisableRestError::ServiceNotPresent`] otherwise.
//! 3. Brick-prevention via
//!    [`would_violate_last_service`] — refuse with
//!    [`DisableRestError::LastServiceRefused`] when DIDComm is
//!    also disabled (VTA would have no advertised transport).
//! 4. Read the prior URL from the on-chain DID document for the
//!    snapshot.
//! 5. Persist a [`RestSnapshot::Enabled { url: prior_url }`]
//!    snapshot before the runtime mutation, per spec §3.5a — a
//!    future rollback re-enables REST at the same URL.
//! 6. Patch the document — remove the `#vta-rest` entry via
//!    [`without_rest_service`] — and publish via
//!    [`update_did_webvh`].
//! 7. Persist `services.rest = false` to the config file.
//! 8. Emit [`TelemetryKind::ServicesRestDisable`].
//!
//! REST has no drain semantics — there's nothing to keep listening
//! for after the URL is unadvertised. The Axum process stays running
//! (it's a process-level binding), so the local CLI can still reach
//! the VTA; only the *advertisement* is removed.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::error::VtaError;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::{
    DocumentPatchError, current_rest_service, without_rest_service,
};
use crate::operations::protocol::invariant::{
    CurrentServices, ProposedOp, would_violate_last_service,
};
use crate::operations::protocol::snapshot::{
    self, RestSnapshot, ServiceConfigSnapshot, ServiceKind,
};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default)]
pub struct DisableRestParams;

#[derive(Debug, Clone)]
pub struct DisableRestResult {
    pub new_version_id: String,
    /// Pre-disable URL — recorded so callers / telemetry / audit
    /// can graph what was just unadvertised.
    pub prior_url: String,
    /// The VTA's own DID. See [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum DisableRestError {
    #[error("REST is not currently enabled — nothing to disable.")]
    ServiceNotPresent,
    #[error(
        "refusing operation: would leave the VTA with no advertised services. \
         Enable DIDComm first via `services didcomm enable --mediator-did <did>`, \
         then retry."
    )]
    LastServiceRefused,
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("config persistence failed: {0}")]
    ConfigPersistence(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for DisableRestError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for DisableRestError
{
    fn from(value: crate::operations::protocol::preconditions::ProtocolPreconditionError) -> Self {
        use crate::operations::protocol::preconditions::ProtocolPreconditionError as E;
        match value {
            E::VtaDidNotConfigured => Self::VtaDidNotConfigured,
            E::VtaDidRecordMissing(s) => Self::VtaDidRecordMissing(s),
            E::VtaDidLogMissing(s) => Self::VtaDidLogMissing(s),
            E::EmptyLog => Self::EmptyLog,
            E::Storage(s) | E::DocumentParse(s) => Self::Storage(s),
        }
    }
}

/// Map [`VtaError::LastServiceRefused`] (from the invariant
/// helper) onto our typed variant. Other [`VtaError`] shapes
/// shouldn't surface here — the helper is total over its inputs —
/// but if one ever does we route it through `Storage` so it isn't
/// silently swallowed.
impl From<VtaError> for DisableRestError {
    fn from(value: VtaError) -> Self {
        match value {
            VtaError::LastServiceRefused => Self::LastServiceRefused,
            other => Self::Storage(other.to_string()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn disable_rest(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    service_state_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    _params: DisableRestParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<DisableRestResult, DisableRestError> {
    auth.require_super_admin()
        .map_err(|e| DisableRestError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // 1. Brick-prevention runs FIRST — fail-fast on the cheap
    //    config-only check before any I/O. Mirrors disable_didcomm's
    //    order, where the §3.2 invariant is checked before reading
    //    the webvh log. The prior_url for the snapshot is captured
    //    later, after the brick check has already passed.
    let (didcomm_enabled, webauthn_enabled) = {
        let cfg = config.read().await;
        if !cfg.services.rest {
            return Err(DisableRestError::ServiceNotPresent);
        }
        (cfg.services.didcomm, cfg.services.webauthn)
    };
    would_violate_last_service(
        &CurrentServices::new(true, didcomm_enabled, webauthn_enabled),
        ProposedOp::disable(ServiceKind::Rest),
    )?;

    // 2. Read on-chain state: VTA DID record + DID log. Validates
    //    services.rest == true (already done above) AND captures
    //    the prior URL for the snapshot.
    let (vta_did, scid, current_doc, prior_url, _) = read_preconditions(config, webvh_ks).await?;

    // 3. Persist snapshot BEFORE the runtime mutation per spec
    //    §3.5a. Pre-state is RestSnapshot::Enabled with the prior
    //    URL — rollback re-enables REST at that URL.
    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: prior_url.clone(),
        }),
    )
    .await
    .map_err(|e| DisableRestError::Storage(format!("snapshot write: {e}")))?;

    // 4. Patch the document — remove the #vta-rest entry.
    let patched = without_rest_service(current_doc);

    // 5. Publish via update_did_webvh.
    let update_result = update_did_webvh(
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        auth,
        &scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        did_resolver,
        didcomm_bridge,
        Some(vta_did.as_str()),
        webvh_auth_locks,
        channel,
    )
    .await?;

    // 6. Persist services.rest = false to fjall (authoritative runtime state)
    //    + mirror into the in-memory config so existing readers see it. Same
    //    risk window as the other ops if this fails after publish — operator
    //    retries.
    crate::operations::protocol::runtime_state::set_rest_enabled(service_state_ks, false)
        .await
        .map_err(|e| DisableRestError::Storage(format!("runtime state: {e}")))?;
    {
        let mut cfg = config.write().await;
        cfg.services.rest = false;
    }

    // 7. Telemetry. Prior URL is included so an external verifier
    //    knows what URL just stopped being advertised.
    let mut event = TelemetryEvent::new(TelemetryKind::ServicesRestDisable)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("prior_url", JsonValue::from(prior_url.clone()));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        prior_url = %prior_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %vta_did,
        "REST disabled"
    );

    Ok(DisableRestResult {
        new_version_id: update_result.new_version_id,
        prior_url,
        vta_did,
        serverless: update_result.serverless,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue, String, bool), DisableRestError> {
    // Op-specific config check first — this is what `services.rest`
    // gates. Capture `didcomm_enabled` while we hold the read-lock
    // so the caller knows whether disabling REST would brick the
    // VTA (no protocol surface).
    let didcomm_enabled = {
        let cfg = config.read().await;
        if !cfg.services.rest {
            return Err(DisableRestError::ServiceNotPresent);
        }
        cfg.services.didcomm
    };

    // Common load: `vta_did`, `scid`, `did_log`, `current_doc` —
    // shared with every other protocol op via
    // `super::preconditions::load_vta_doc_state`.
    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;

    let prior_url = current_rest_service(&state.current_doc)
        .map(|s| s.url)
        .ok_or(DisableRestError::ServiceNotPresent)?;

    Ok((
        state.vta_did,
        state.scid,
        state.current_doc,
        prior_url,
        didcomm_enabled,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Mirrors the test fixture in enable_rest / update_rest —
    /// owns the fjall store so a single test can derive multiple
    /// keyspaces from the same handle.
    struct TestFixture {
        _dir: tempfile::TempDir,
        config: Arc<RwLock<AppConfig>>,
        store: Store,
    }

    impl TestFixture {
        fn webvh_ks(&self) -> KeyspaceHandle {
            self.store.keyspace(crate::keyspaces::WEBVH).unwrap()
        }
    }

    fn build_fixture(rest_initially: bool, didcomm_initially: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = rest_initially;
        cfg.services.didcomm = didcomm_initially;
        cfg.vta_did = Some("did:webvh:scid123:host:vta".into());
        cfg.config_path = dir.path().join("vta.toml");
        let initial = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&cfg.config_path, initial).unwrap();

        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        TestFixture {
            _dir: dir,
            config: Arc::new(RwLock::new(cfg)),
            store,
        }
    }

    #[tokio::test]
    async fn read_preconditions_rejects_when_rest_disabled() {
        let fx = build_fixture(false, true);
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, DisableRestError::ServiceNotPresent));
    }

    #[tokio::test]
    async fn read_preconditions_rejects_without_vta_did() {
        let fx = build_fixture(true, true);
        fx.config.write().await.vta_did = None;
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, DisableRestError::VtaDidNotConfigured));
    }

    /// The brick-prevention helper is wired correctly: invoking it
    /// from a "REST on, DIDComm off" state with a disable-rest op
    /// must surface as `LastServiceRefused`.
    #[test]
    fn brick_prevention_rejects_disable_rest_when_didcomm_off() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, false, false),
            ProposedOp::disable(ServiceKind::Rest),
        );
        let err = DisableRestError::from(result.unwrap_err());
        assert!(matches!(err, DisableRestError::LastServiceRefused));
    }

    /// Conversely, brick-prevention accepts disabling REST when
    /// DIDComm is on (S3 → S2).
    #[test]
    fn brick_prevention_allows_disable_rest_when_didcomm_on() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, true, false),
            ProposedOp::disable(ServiceKind::Rest),
        );
        assert!(result.is_ok());
    }

    /// Disabling REST is also allowed when WebAuthn alone is on
    /// — WebAuthn counts as a transport for invariant purposes.
    #[test]
    fn brick_prevention_allows_disable_rest_when_webauthn_on() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, false, true),
            ProposedOp::disable(ServiceKind::Rest),
        );
        assert!(result.is_ok());
    }

    // (Removed: `persist_rest_disabled_flips_config_to_false`. The op now
    // writes runtime state to fjall via `runtime_state::set_rest_enabled`,
    // not to the config file on disk. The integration tests for the full
    // `disable_rest` op cover that path end-to-end.)

    /// Confirms the typed `From<VtaError>` path: the helper's
    /// `LastServiceRefused` round-trips into our error variant
    /// correctly, and any other VtaError shape lands in `Storage`
    /// (defensive — the helper is total today, but the impl
    /// shouldn't drop unknown variants).
    #[test]
    fn vta_error_to_disable_rest_error_mapping_is_typed() {
        let mapped = DisableRestError::from(VtaError::LastServiceRefused);
        assert!(matches!(mapped, DisableRestError::LastServiceRefused));

        let mapped = DisableRestError::from(VtaError::ServiceNotPresent);
        assert!(matches!(mapped, DisableRestError::Storage(_)));
    }
}
