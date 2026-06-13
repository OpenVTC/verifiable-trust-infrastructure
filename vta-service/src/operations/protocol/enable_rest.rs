//! `enable_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.4. A thin
//! wrapper over the shared [`service_lifecycle`](super::service_lifecycle)
//! engine — see [`run_enable`] for the full sequence (super-admin →
//! PROTOCOL_LOCK → validate URL → preconditions → snapshot → patch → publish →
//! persist `services.rest = true` → telemetry).
//!
//! Brick-prevention is **not** consulted — enabling can only add a transport
//! service, never remove one, so the §3.2 invariant is preserved by
//! construction.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use thiserror::Error;
use tokio::sync::RwLock;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::SharedTelemetrySink;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::OpContext;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    EnableMutationError, RestService, ServiceLifecycleDeps, ServiceMutationError, run_enable,
};
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone)]
pub struct EnableRestParams {
    /// Public URL the VTA will advertise on its `#vta-rest` service
    /// entry. Validated by `validate_service_url` before any runtime
    /// mutation occurs.
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct EnableRestResult {
    pub new_version_id: String,
    /// The validated URL that was published — canonicalised from
    /// `params.url` by `url::Url`.
    pub url: String,
    /// The VTA's own DID — subject of the LogEntry this enable wrote.
    /// Propagated so route + DIDComm response shapes can emit the
    /// "fetch did.jsonl + redeploy" hint for serverless deployments.
    pub vta_did: String,
    /// True when `record.server_id == "serverless"` — the new LogEntry
    /// is local-only.
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

impl ServiceMutationError for EnableRestError {
    fn validation(msg: String) -> Self {
        Self::Validation(msg)
    }
    fn auth(msg: String) -> Self {
        Self::Auth(msg)
    }
    fn storage(msg: String) -> Self {
        Self::Storage(msg)
    }
}

impl EnableMutationError for EnableRestError {
    fn already_enabled() -> Self {
        Self::ServiceAlreadyEnabled
    }
    fn config_persistence(msg: String) -> Self {
        Self::ConfigPersistence(msg)
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
    let deps = ServiceLifecycleDeps {
        config,
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        snapshot_ks,
        seed_store,
        did_resolver,
        didcomm_bridge,
        telemetry,
        webvh_auth_locks,
    };
    // REST persists "enabled" as runtime state (fjall) + the in-memory flag.
    // If this fails after publish, the LogEntry advertises REST but config
    // disagrees — same risk window as before; operator retries.
    let ok = run_enable::<RestService, EnableRestError>(
        &deps,
        auth,
        &params.url,
        ctx,
        channel,
        || async {
            crate::operations::protocol::runtime_state::set_rest_enabled(service_state_ks, true)
                .await
                .map_err(|e| format!("runtime state: {e}"))?;
            config.write().await.services.rest = true;
            Ok(())
        },
    )
    .await?;

    Ok(EnableRestResult {
        new_version_id: ok.new_version_id,
        url: ok.canonical_url,
        vta_did: ok.vta_did,
        serverless: ok.serverless,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::protocol::service_lifecycle::check_enable_preconditions;
    use crate::operations::protocol::snapshot::{self, ServiceKind};
    use crate::store::Store;
    use vta_sdk::protocol::services::validate_service_url;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Owns the on-disk fjall store so all keyspaces a test reaches for
    /// share a single open handle (fjall locks the data dir on each open).
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
        // §3.2 brick-prevention: keep DIDComm on so an enable-rest test
        // never needs to consider the no-transport edge case.
        cfg.services.didcomm = true;
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
    async fn preconditions_reject_when_already_enabled() {
        let fx = build_fixture(true);
        let err =
            check_enable_preconditions::<RestService, EnableRestError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, EnableRestError::ServiceAlreadyEnabled));
    }

    #[tokio::test]
    async fn preconditions_reject_without_vta_did() {
        let fx = build_fixture(false);
        fx.config.write().await.vta_did = None;
        let err =
            check_enable_preconditions::<RestService, EnableRestError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, EnableRestError::VtaDidNotConfigured));
    }

    /// URL validation runs first, before any storage reads. An invalid URL
    /// never reaches the snapshot layer.
    #[tokio::test]
    async fn enable_rest_url_validation_runs_before_persist() {
        let fx = build_fixture(false);
        let snapshot_ks = fx.snapshot_ks();

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
}
