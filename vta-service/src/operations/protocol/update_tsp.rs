//! `update_tsp` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.4 +
//! `docs/05-design-notes/tsp-enablement.md`. A thin wrapper over the shared
//! [`service_lifecycle`](super::service_lifecycle) engine — see [`run_update`]
//! for the sequence (super-admin → PROTOCOL_LOCK → validate mediator DID →
//! preconditions → snapshot prior mediator → patch → publish → telemetry). No
//! `services.tsp` config flip — TSP stays enabled across an update; only the
//! advertised mediator DID changes. Brick-prevention is not consulted (update
//! can't change the on/off state).

use thiserror::Error;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    ServiceMutationError, TspService, UpdateMutationError, run_update,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};

#[derive(Debug, Clone)]
pub struct UpdateTspParams {
    /// New mediator DID for the `#tsp` service entry. Validated as a
    /// `did:...` string before any runtime mutation.
    pub mediator_did: String,
}

#[derive(Debug, Clone)]
pub struct UpdateTspResult {
    pub new_version_id: String,
    /// Pre-update mediator DID — captured from the on-chain DID document
    /// and surfaced so callers / telemetry can join the before-and-after.
    pub prior_mediator_did: String,
    /// The validated new mediator DID that was published.
    pub mediator_did: String,
    /// The VTA's own DID. See [`super::enable_tsp::EnableTspResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum UpdateTspError {
    #[error(
        "TSP is not currently enabled. Use `services tsp enable --mediator-did <did>` to bring it online first."
    )]
    ServiceNotPresent,
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
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for UpdateTspError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for UpdateTspError
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

impl ServiceMutationError for UpdateTspError {
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

impl UpdateMutationError for UpdateTspError {
    fn not_present() -> Self {
        Self::ServiceNotPresent
    }
}

pub async fn update_tsp(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    params: UpdateTspParams,
    ctx: OpContext,
    channel: &str,
) -> Result<UpdateTspResult, UpdateTspError> {
    let ok =
        run_update::<TspService, UpdateTspError>(deps, auth, &params.mediator_did, ctx, channel)
            .await?;

    Ok(UpdateTspResult {
        new_version_id: ok.new_version_id,
        // `run_update` always sets `prior_url` to `Some` on success.
        prior_mediator_did: ok.prior_url.unwrap_or_default(),
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
    use crate::operations::protocol::service_lifecycle::{TspService, check_update_preconditions};
    use crate::operations::protocol::snapshot::{
        self, ServiceConfigSnapshot, ServiceKind, TspSnapshot,
    };
    use crate::store::{KeyspaceHandle, Store};
    use vti_common::config::StoreConfig as VtiStoreConfig;

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
    async fn preconditions_reject_when_tsp_disabled() {
        let fx = build_fixture(false);
        let err =
            check_update_preconditions::<TspService, UpdateTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, UpdateTspError::ServiceNotPresent));
    }

    #[tokio::test]
    async fn preconditions_reject_without_vta_did() {
        let fx = build_fixture(true);
        fx.config.write().await.vta_did = None;
        let err =
            check_update_preconditions::<TspService, UpdateTspError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, UpdateTspError::VtaDidNotConfigured));
    }

    /// Mediator-DID validation runs first, before any storage reads or
    /// snapshot writes — a non-DID value means the snapshot keyspace stays
    /// untouched.
    #[tokio::test]
    async fn invalid_mediator_did_aborts_before_snapshot_write() {
        use crate::operations::protocol::service_lifecycle::ServiceLifecycle;
        let fx = build_fixture(true);
        let snapshot_ks = fx.snapshot_ks();

        let validated = TspService::validate("not-a-did");
        assert!(validated.is_err(), "non-did:... must be rejected");

        assert!(
            snapshot::read(&snapshot_ks, ServiceKind::Tsp)
                .await
                .unwrap()
                .is_none(),
            "validation error must abort before snapshot write",
        );
    }

    /// After a successful update, the snapshot records the *prior* mediator
    /// DID (the rollback target), not the new one.
    #[tokio::test]
    async fn snapshot_records_prior_mediator_for_rollback() {
        let fx = build_fixture(true);
        let snapshot_ks = fx.snapshot_ks();
        let prior = "did:webvh:scid:host:old-mediator".to_string();

        snapshot::write(
            &snapshot_ks,
            ServiceConfigSnapshot::Tsp(TspSnapshot::Enabled {
                mediator_did: prior.clone(),
            }),
        )
        .await
        .unwrap();

        let read_back = snapshot::read(&snapshot_ks, ServiceKind::Tsp)
            .await
            .unwrap()
            .unwrap();
        match read_back {
            ServiceConfigSnapshot::Tsp(TspSnapshot::Enabled { mediator_did }) => {
                assert_eq!(
                    mediator_did, prior,
                    "rollback target must be prior mediator"
                );
            }
            other => panic!("unexpected snapshot variant: {other:?}"),
        }
    }
}
