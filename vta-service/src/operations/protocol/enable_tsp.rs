//! `enable_tsp` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.4 +
//! `docs/05-design-notes/tsp-enablement.md`. A thin wrapper over the shared
//! [`service_lifecycle`](super::service_lifecycle) engine — see [`run_enable`]
//! for the full sequence (super-admin → PROTOCOL_LOCK → validate mediator DID →
//! preconditions → snapshot → patch → publish → persist `services.tsp = true` →
//! telemetry).
//!
//! TSP advertises a **mediator DID** (the VTA's TSP VID), not a URL — so the
//! validate hook checks for a `did:...` string rather than an HTTPS URL. Like
//! REST, TSP has no drain and no handshake.
//!
//! Brick-prevention is **not** consulted — enabling can only add a transport
//! service, never remove one, so the §3.2 invariant is preserved by
//! construction.

use thiserror::Error;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    EnableMutationError, ServiceMutationError, TspService, run_enable,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};

#[derive(Debug, Clone)]
pub struct EnableTspParams {
    /// Mediator DID the VTA will advertise on its `#tsp` service entry
    /// (the VTA's TSP VID). Validated as a `did:...` string before any
    /// runtime mutation occurs.
    pub mediator_did: String,
}

#[derive(Debug, Clone)]
pub struct EnableTspResult {
    pub new_version_id: String,
    /// The validated mediator DID that was published.
    pub mediator_did: String,
    /// The VTA's own DID — subject of the LogEntry this enable wrote.
    /// Propagated so route + DIDComm response shapes can emit the
    /// "fetch did.jsonl + redeploy" hint for serverless deployments.
    pub vta_did: String,
    /// True when `record.server_id == "serverless"` — the new LogEntry
    /// is local-only.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum EnableTspError {
    #[error(
        "TSP is already enabled. Use `services tsp update --mediator-did <did>` to change the mediator."
    )]
    ServiceAlreadyEnabled,
    #[error("invalid mediator DID: {0}")]
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

impl From<AppError> for EnableTspError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for EnableTspError
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

impl ServiceMutationError for EnableTspError {
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

impl EnableMutationError for EnableTspError {
    fn already_enabled() -> Self {
        Self::ServiceAlreadyEnabled
    }
    fn config_persistence(msg: String) -> Self {
        Self::ConfigPersistence(msg)
    }
}

pub async fn enable_tsp(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    params: EnableTspParams,
    ctx: OpContext,
    channel: &str,
) -> Result<EnableTspResult, EnableTspError> {
    // TSP persists "enabled" as runtime state (fjall) + the in-memory flag.
    // If this fails after publish, the LogEntry advertises TSP but config
    // disagrees — same risk window as REST; operator retries.
    let ok = run_enable::<TspService, EnableTspError>(
        deps,
        auth,
        &params.mediator_did,
        ctx,
        channel,
        || async {
            crate::operations::protocol::runtime_state::set_tsp_enabled(
                deps.service_state_ks,
                true,
            )
            .await
            .map_err(|e| format!("runtime state: {e}"))?;
            deps.config.write().await.services.tsp = true;
            Ok(())
        },
    )
    .await?;

    Ok(EnableTspResult {
        new_version_id: ok.new_version_id,
        mediator_did: ok.canonical_url,
        vta_did: ok.vta_did,
        serverless: ok.serverless,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::config::AppConfig;
    use crate::operations::protocol::service_lifecycle::{TspService, check_enable_preconditions};
    use crate::operations::protocol::snapshot::{self, ServiceKind};
    use crate::store::{KeyspaceHandle, Store};
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

    fn build_fixture(tsp_initially: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.tsp = tsp_initially;
        // §3.2 brick-prevention: keep DIDComm on so an enable-tsp test
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
            check_enable_preconditions::<TspService, EnableTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, EnableTspError::ServiceAlreadyEnabled));
    }

    #[tokio::test]
    async fn preconditions_reject_without_vta_did() {
        let fx = build_fixture(false);
        fx.config.write().await.vta_did = None;
        let err =
            check_enable_preconditions::<TspService, EnableTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, EnableTspError::VtaDidNotConfigured));
    }

    /// Mediator-DID validation runs first, before any storage reads. A
    /// non-DID value never reaches the snapshot layer.
    #[tokio::test]
    async fn enable_tsp_did_validation_runs_before_persist() {
        use crate::operations::protocol::service_lifecycle::ServiceLifecycle;
        let fx = build_fixture(false);
        let snapshot_ks = fx.snapshot_ks();

        let validated = TspService::validate("https://not-a-did.example.com");
        assert!(validated.is_err(), "non-did:... must be rejected");

        assert!(
            snapshot::read(&snapshot_ks, ServiceKind::Tsp)
                .await
                .unwrap()
                .is_none(),
            "validation error must abort before snapshot write",
        );
    }
}
