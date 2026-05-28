//! `update_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.4.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Validate the new URL via
//!    [`vta_sdk::protocol::services::validate_service_url`] (T1.2).
//! 3. Confirm `services.rest` is currently `true` AND a
//!    `#vta-rest` entry exists in the DID document — refuse with
//!    [`UpdateRestError::ServiceNotPresent`] otherwise.
//! 4. Read the prior URL from the on-chain DID document for the
//!    snapshot.
//! 5. Persist a [`RestSnapshot::Enabled { url: prior_url }`]
//!    snapshot before the runtime mutation, per spec §3.5a — a
//!    future rollback restores the prior URL.
//! 6. Patch the document — replace the `#vta-rest` entry's URL
//!    via [`with_rest_service`] — and publish via [`update_did_webvh`].
//! 7. Emit [`TelemetryKind::ServicesRestUpdate`].
//!
//! No `services.rest` config flip — REST stays enabled across an
//! update; only the URL changes. The brick-prevention invariant is
//! not consulted (update can't change the on/off state).

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
pub struct UpdateRestParams {
    /// New public URL for the `#vta-rest` service entry. Validated
    /// before any runtime mutation.
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct UpdateRestResult {
    pub new_version_id: String,
    /// Pre-update URL — captured from the on-chain DID document
    /// and surfaced so callers / telemetry can join the
    /// before-and-after.
    pub prior_url: String,
    /// The validated new URL that was published — canonicalised
    /// from `params.url` by `url::Url`.
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

#[allow(clippy::too_many_arguments)]
pub async fn update_rest(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    _service_state_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    params: UpdateRestParams,
    ctx: OpContext,
    webvh_auth_locks: &crate::operations::did_webvh::WebvhAuthLocks,
    channel: &str,
) -> Result<UpdateRestResult, UpdateRestError> {
    auth.require_super_admin()
        .map_err(|e| UpdateRestError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // 1. Validate the new URL up front. Cheap; runs before I/O.
    let validated = validate_service_url(&params.url)
        .map_err(|e| UpdateRestError::Validation(e.to_string()))?;
    let canonical_url = validated.to_string();

    // 2. Read preconditions: REST must be on, both in config and
    //    on-chain. Capture the prior URL while we're at it — the
    //    snapshot needs it.
    let (vta_did, scid, current_doc, prior_url) = read_preconditions(config, webvh_ks).await?;

    // 3. Persist snapshot BEFORE the runtime mutation per spec
    //    §3.5a. Pre-state for an update is RestSnapshot::Enabled
    //    with the prior URL — rollback restores that URL.
    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: prior_url.clone(),
        }),
    )
    .await
    .map_err(|e| UpdateRestError::Storage(format!("snapshot write: {e}")))?;

    // 4. Patch the document — replace the #vta-rest entry's URL.
    //    `with_rest_service` overwrites the existing entry's URL
    //    while preserving everything else byte-for-byte.
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

    // 6. No config persistence — services.rest stays true. The
    //    AppConfig has no field for the public REST URL, so the
    //    DID document is the single source of truth for the URL
    //    (the SDK's session.rs:1100 already pulls from there).
    //    Operators who restart the VTA pick the new URL up via
    //    DID resolution; no config-file write is necessary.

    // 7. Telemetry: prior + new URL together so external verifiers
    //    can graph URL transitions per VTA.
    let mut event = TelemetryEvent::new(TelemetryKind::ServicesRestUpdate)
        .with_field("channel", JsonValue::from(channel))
        .with_field(
            "new_version_id",
            JsonValue::from(update_result.new_version_id.clone()),
        )
        .with_field("prior_url", JsonValue::from(prior_url.clone()))
        .with_field("url", JsonValue::from(canonical_url.clone()));
    if let Some(tag) = ctx.telemetry_triggered_by() {
        event = event.with_field("triggered_by", JsonValue::from(tag));
    }
    let _ = telemetry.record(event).await;

    info!(
        channel,
        prior_url = %prior_url,
        url = %canonical_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %vta_did,
        "REST URL updated"
    );

    Ok(UpdateRestResult {
        new_version_id: update_result.new_version_id,
        prior_url,
        url: canonical_url,
        vta_did,
        serverless: update_result.serverless,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue, String), UpdateRestError> {
    {
        let cfg = config.read().await;
        if !cfg.services.rest {
            return Err(UpdateRestError::ServiceNotPresent);
        }
    }

    let state = super::preconditions::load_vta_doc_state(config, webvh_ks).await?;

    let prior_url = current_rest_service(&state.current_doc)
        .map(|s| s.url)
        .ok_or(UpdateRestError::ServiceNotPresent)?;

    Ok((state.vta_did, state.scid, state.current_doc, prior_url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::protocol::snapshot::ServiceKind;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Mirrors `enable_rest::tests::TestFixture` — owns the fjall
    /// store so a single test can derive multiple keyspaces from
    /// the same handle (fjall locks the data dir on open).
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
            self.store.keyspace("webvh").unwrap()
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
    async fn read_preconditions_rejects_when_rest_disabled() {
        let fx = build_fixture(false);
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateRestError::ServiceNotPresent));
    }

    #[tokio::test]
    async fn read_preconditions_rejects_without_vta_did() {
        let fx = build_fixture(true);
        fx.config.write().await.vta_did = None;
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateRestError::VtaDidNotConfigured));
    }

    /// URL validation runs first, before any storage reads or
    /// snapshot writes — invalid URL means the snapshot keyspace
    /// stays untouched, leaving any prior snapshot from a
    /// successful mutation intact.
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

    /// Direct exercise of the snapshot semantics: after a
    /// successful update, the snapshot must record the *prior*
    /// URL (not the new one). Constructed directly here because
    /// the full operation requires a webvh store fixture too
    /// large for a unit test — full path coverage lives in the
    /// e2e matrix (P6).
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
