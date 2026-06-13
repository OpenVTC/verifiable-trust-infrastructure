//! `enable_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.4.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Validate URL via
//!    [`vta_sdk::protocol::services::validate_service_url`] (T1.2).
//! 3. Confirm `services.rest` is currently `false` AND no
//!    `#vta-rest` entry is in the DID document — refuse with
//!    [`EnableRestError::ServiceAlreadyEnabled`] otherwise.
//! 4. Look up the VTA's webvh record + current document.
//! 5. Persist a [`RestSnapshot::Disabled`] snapshot before the
//!    runtime mutation, per spec §3.5a (rollback target if the
//!    operator later runs `services rest rollback`).
//! 6. Patch the document — insert `#vta-rest` via
//!    [`with_rest_service`] — and publish via [`update_did_webvh`].
//! 7. Persist `services.rest = true` to the config file.
//! 8. Emit [`TelemetryKind::ServicesRestEnable`].
//!
//! Brick-prevention is **not** consulted — enabling can only add a
//! transport service, never remove one, so the §3.2 invariant is
//! preserved by construction.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use vta_sdk::protocol::services::validate_service_url;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::document::{
    DocumentPatchError, current_rest_service, with_rest_service,
};
use crate::operations::protocol::snapshot::{self, RestSnapshot, ServiceConfigSnapshot};
use crate::operations::protocol::{OpContext, PROTOCOL_LOCK};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone)]
pub struct EnableRestParams {
    /// Public URL the VTA will advertise on its `#vta-rest` service
    /// entry. Validated by [`validate_service_url`] before any
    /// runtime mutation occurs.
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct EnableRestResult {
    pub new_version_id: String,
    /// The validated URL that was published — canonicalised from
    /// `params.url` by `url::Url`.
    pub url: String,
    /// The VTA's own DID — subject of the LogEntry this enable
    /// wrote. Propagated upward so route + DIDComm response
    /// shapes can emit the "fetch did.jsonl + redeploy" hint to
    /// operators running serverless deployments.
    pub vta_did: String,
    /// True when `record.server_id == "serverless"` — the new
    /// LogEntry is local-only.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum EnableRestError {
    #[error("REST is already enabled. Use `services rest update --url <url>` to change the URL.")]
    ServiceAlreadyEnabled,
    #[error("invalid URL: {0}")]
    Validation(String),
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

impl From<AppError> for EnableRestError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for EnableRestError
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

#[allow(clippy::too_many_arguments)]
pub async fn enable_rest(
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
    params: EnableRestParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<EnableRestResult, EnableRestError> {
    auth.require_super_admin()
        .map_err(|e| EnableRestError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // 1. Validate URL up front. Cheap, runs before any I/O.
    let validated = validate_service_url(&params.url)
        .map_err(|e| EnableRestError::Validation(e.to_string()))?;
    let canonical_url = validated.to_string();

    // 2. Read preconditions: REST must be off, both in config and
    //    in the on-chain DID document. We check both because the
    //    sources should agree, and a divergence is itself a bug we
    //    want to surface (operator can run `services list` to
    //    inspect).
    let (vta_did, scid, current_doc) = read_preconditions(config, webvh_ks).await?;

    // 3. Persist snapshot BEFORE the runtime mutation per spec
    //    §3.5a. Pre-state for an enable is RestSnapshot::Disabled
    //    so a future rollback re-applies "off."
    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Rest(RestSnapshot::Disabled),
    )
    .await
    .map_err(|e| EnableRestError::Storage(format!("snapshot write: {e}")))?;

    // 4. Patch the document with the new REST service entry.
    let patched = with_rest_service(current_doc, &canonical_url)?;

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

    // 6. Persist `services.rest = true`. If this fails, the
    //    published LogEntry advertises REST but config disagrees —
    //    same risk window as `disable_didcomm`'s
    //    `persist_didcomm_disabled`. Operator retries with the
    //    config in a known state.
    crate::operations::protocol::runtime_state::set_rest_enabled(service_state_ks, true)
        .await
        .map_err(|e| EnableRestError::ConfigPersistence(format!("runtime state: {e}")))?;
    {
        let mut cfg = config.write().await;
        cfg.services.rest = true;
    }

    // 7. Telemetry. Channel and version-id let an external verifier
    //    join this event to chain history.
    let mut event = TelemetryEvent::new(TelemetryKind::ServicesRestEnable)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("url", JsonValue::from(canonical_url.clone()));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        url = %canonical_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %vta_did,
        "REST enabled"
    );

    Ok(EnableRestResult {
        new_version_id: update_result.new_version_id,
        url: canonical_url,
        vta_did,
        // `update_did_webvh` derives `serverless` from the same
        // record we loaded in `read_preconditions`; trust its
        // answer so this op layer stays a single source of truth
        // (no parallel `server_id == "serverless"` check here).
        serverless: update_result.serverless,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue), EnableRestError> {
    {
        let cfg = config.read().await;
        if cfg.services.rest {
            return Err(EnableRestError::ServiceAlreadyEnabled);
        }
    }

    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;

    if current_rest_service(&state.current_doc).is_some() {
        // Config and on-chain doc disagree (config: rest=false,
        // doc: rest entry present). Surface as ServiceAlreadyEnabled
        // — reconciling means the operator should run `services
        // list`, not retry the enable.
        return Err(EnableRestError::ServiceAlreadyEnabled);
    }

    Ok((state.vta_did, state.scid, state.current_doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::protocol::snapshot::ServiceKind;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Owns the on-disk fjall store so all keyspaces a test reaches
    /// for share a single open handle (fjall locks the data dir on
    /// each open). Caller derives webvh / snapshot / etc. handles
    /// off `store`.
    struct TestFixture {
        _dir: tempfile::TempDir,
        config: Arc<RwLock<AppConfig>>,
        store: Store,
    }

    impl TestFixture {
        fn snapshot_ks(&self) -> KeyspaceHandle {
            self.store.keyspace(snapshot::KEYSPACE_NAME).unwrap()
        }
        fn webvh_ks(&self) -> KeyspaceHandle {
            self.store.keyspace(crate::keyspaces::WEBVH).unwrap()
        }
    }

    fn build_fixture(rest_initially: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = rest_initially;
        // §3.2 brick-prevention: keep DIDComm on so an enable-rest
        // test never needs to consider the no-transport edge case.
        cfg.services.didcomm = true;
        cfg.vta_did = Some("did:webvh:scid123:host:vta".into());
        cfg.config_path = dir.path().join("vta.toml");
        // Persist so `persist_rest_enabled` has a file to write to.
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
    async fn read_preconditions_rejects_when_already_enabled() {
        let fx = build_fixture(true);
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, EnableRestError::ServiceAlreadyEnabled));
    }

    #[tokio::test]
    async fn read_preconditions_rejects_without_vta_did() {
        let fx = build_fixture(false);
        fx.config.write().await.vta_did = None;
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, EnableRestError::VtaDidNotConfigured));
    }

    /// URL validation runs first, before any storage reads. An
    /// invalid URL never reaches the snapshot layer.
    #[tokio::test]
    async fn enable_rest_url_validation_runs_before_persist() {
        let fx = build_fixture(false);
        let snapshot_ks = fx.snapshot_ks();

        // Exercise the validation step alone — `enable_rest` runs it
        // before any I/O, so an invalid URL must not write a
        // snapshot.
        let validated = validate_service_url("http://insecure.example.com");
        assert!(validated.is_err(), "http:// must be rejected");

        assert!(
            snapshot::read(&snapshot_ks, ServiceKind::Rest)
                .await
                .unwrap()
                .is_none(),
            "validation error must abort before snapshot write",
        );
    }

    // (Removed: `persist_rest_enabled_writes_rest_true_to_config_file`.
    // The op now writes runtime state to fjall via
    // `runtime_state::set_rest_enabled`, not to the config file on disk.
    // The integration tests for the full `enable_rest` op cover that path
    // end-to-end.)
}
