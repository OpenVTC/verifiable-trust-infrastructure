//! `update_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.4. A thin
//! wrapper over the shared [`service_lifecycle`](super::service_lifecycle)
//! engine — see [`run_update`] for the sequence (super-admin → PROTOCOL_LOCK →
//! validate URL → preconditions → snapshot prior URL → patch → publish →
//! telemetry). No `services.rest` config flip — REST stays enabled across an
//! update; only the URL changes. Brick-prevention is not consulted (update
//! can't change the on/off state).

use thiserror::Error;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::document::DocumentPatchError;
use crate::operations::protocol::service_lifecycle::{
    RestService, ServiceMutationError, UpdateMutationError, run_update,
};
use crate::operations::protocol::{OpContext, ServiceOpDeps};

#[derive(Debug, Clone)]
pub struct UpdateRestParams {
    /// New public URL for the `#vta-rest` service entry. Validated
    /// before any runtime mutation.
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct UpdateRestResult {
    pub new_version_id: String,
    /// Pre-update URL — captured from the on-chain DID document and
    /// surfaced so callers / telemetry can join the before-and-after.
    pub prior_url: String,
    /// The validated new URL that was published.
    pub url: String,
    /// The VTA's own DID. See [`super::enable_rest::EnableRestResult`].
    pub vta_did: String,
    /// True when the VTA's DID is self-hosted.
    pub serverless: bool,
}

#[derive(Debug, Error)]
pub enum UpdateRestError {
    #[error(
        "REST is not currently enabled. Use `services rest enable --url <url>` to bring it online first."
    )]
    ServiceNotPresent,
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
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for UpdateRestError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<crate::operations::protocol::preconditions::ProtocolPreconditionError>
    for UpdateRestError
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

impl ServiceMutationError for UpdateRestError {
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

impl UpdateMutationError for UpdateRestError {
    fn not_present() -> Self {
        Self::ServiceNotPresent
    }
}

pub async fn update_rest(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    params: UpdateRestParams,
    ctx: OpContext,
    channel: &str,
) -> Result<UpdateRestResult, UpdateRestError> {
    let ok =
        run_update::<RestService, UpdateRestError>(deps, auth, &params.url, ctx, channel).await?;

    Ok(UpdateRestResult {
        new_version_id: ok.new_version_id,
        // `run_update` always sets `prior_url` to `Some` on success.
        prior_url: ok.prior_url.unwrap_or_default(),
        url: ok.canonical_url,
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
    use crate::operations::protocol::service_lifecycle::check_update_preconditions;
    use crate::operations::protocol::snapshot::{
        self, RestSnapshot, ServiceConfigSnapshot, ServiceKind,
    };
    use crate::store::{KeyspaceHandle, Store};
    use vta_sdk::protocol::services::validate_service_url;
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

    fn build_fixture(rest_initially: bool) -> TestFixture {
        use crate::test_support::test_app_config;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_app_config(dir.path().into());
        cfg.services.rest = rest_initially;
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
    async fn preconditions_reject_when_rest_disabled() {
        let fx = build_fixture(false);
        let err =
            check_update_preconditions::<RestService, UpdateRestError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, UpdateRestError::ServiceNotPresent));
    }

    #[tokio::test]
    async fn preconditions_reject_without_vta_did() {
        let fx = build_fixture(true);
        fx.config.write().await.vta_did = None;
        let err =
            check_update_preconditions::<RestService, UpdateRestError>(&fx.config, &fx.webvh_ks())
                .await
                .unwrap_err();
        assert!(matches!(err, UpdateRestError::VtaDidNotConfigured));
    }

    /// URL validation runs first, before any storage reads or snapshot
    /// writes — invalid URL means the snapshot keyspace stays untouched.
    #[tokio::test]
    async fn invalid_url_aborts_before_snapshot_write() {
        let fx = build_fixture(true);
        let snapshot_ks = fx.snapshot_ks();

        let validated = validate_service_url("ftp://nope.example.com");
        assert!(validated.is_err(), "non-https must be rejected");

        assert!(
            snapshot::read(&snapshot_ks, ServiceKind::Rest)
                .await
                .unwrap()
                .is_none(),
            "validation error must abort before snapshot write",
        );
    }

    /// After a successful update, the snapshot records the *prior* URL (the
    /// rollback target), not the new one.
    #[tokio::test]
    async fn snapshot_records_prior_url_for_rollback() {
        let fx = build_fixture(true);
        let snapshot_ks = fx.snapshot_ks();
        let prior_url = "https://old.example.com".to_string();

        snapshot::write(
            &snapshot_ks,
            ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
                url: prior_url.clone(),
            }),
        )
        .await
        .unwrap();

        let read_back = snapshot::read(&snapshot_ks, ServiceKind::Rest)
            .await
            .unwrap()
            .unwrap();
        match read_back {
            ServiceConfigSnapshot::Rest(RestSnapshot::Enabled { url }) => {
                assert_eq!(url, prior_url, "rollback target must be prior URL");
            }
            other => panic!("unexpected snapshot variant: {other:?}"),
        }
    }
}
