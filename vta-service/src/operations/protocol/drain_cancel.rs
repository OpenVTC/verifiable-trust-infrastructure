//! `mediator drain cancel` operation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! success criterion #7.
//!
//! Cancels a drain entry early, dropping the listener for that
//! mediator immediately. Refuses if the named DID is the active
//! mediator (operator should use `services disable didcomm`
//! instead) or if the DID isn't registered at all.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::telemetry::SharedTelemetrySink;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::messaging::registry::{MediatorListenerRegistry, RegistryError};
use crate::operations::protocol::PROTOCOL_LOCK;
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone)]
pub struct DrainCancelParams {
    pub mediator_did: String,
}

#[derive(Debug, Clone)]
pub struct DrainCancelResult {
    pub mediator_did: String,
}

#[derive(Debug, Error)]
pub enum DrainCancelError {
    #[error("auth: {0}")]
    Auth(String),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

#[allow(clippy::too_many_arguments)]
pub async fn drain_cancel(
    _config: &Arc<RwLock<AppConfig>>,
    drains_ks: &KeyspaceHandle,
    registry: &MediatorListenerRegistry,
    _telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    params: DrainCancelParams,
    channel: &str,
) -> Result<DrainCancelResult, DrainCancelError> {
    auth.require_super_admin()
        .map_err(|e| DrainCancelError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    let entry = registry
        .record_cancel_persisted(drains_ks, &params.mediator_did)
        .await?;

    info!(
        channel,
        mediator = %entry.mediator_did,
        "drain cancelled"
    );

    Ok(DrainCancelResult {
        mediator_did: entry.mediator_did,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::messaging::registry::MediatorBinding;
    use crate::store::Store;
    use crate::test_support::test_app_config;
    use chrono::{Duration, Utc};
    use vti_common::telemetry::RingBufferTelemetry;

    fn config(tmpdir: &std::path::Path) -> Arc<RwLock<AppConfig>> {
        let mut cfg = test_app_config(tmpdir.into());
        cfg.services.rest = true;
        cfg.services.didcomm = true;
        cfg.vta_did = Some("did:webvh:scid:host:vta".into());
        cfg.config_path = tmpdir.join("config.toml");
        Arc::new(RwLock::new(cfg))
    }

    async fn registry_with_drain() -> (
        Arc<MediatorListenerRegistry>,
        SharedTelemetrySink,
        tempfile::TempDir,
        KeyspaceHandle,
    ) {
        use vti_common::config::StoreConfig as VtiStoreConfig;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let drains_ks = store.keyspace(crate::keyspaces::DRAINS).unwrap();
        let sink: SharedTelemetrySink = Arc::new(RingBufferTelemetry::with_capacity(64));
        let reg = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));

        // Set up: A active, B active (replaces A), then A goes
        // into drain. Now A is drainable; B is active.
        reg.record_activate(MediatorBinding {
            mediator_did: "did:m:A".into(),
            endpoint: "wss://A".into(),
        })
        .await;
        reg.record_activate(MediatorBinding {
            mediator_did: "did:m:B".into(),
            endpoint: "wss://B".into(),
        })
        .await;
        reg.record_drain_persisted(
            &drains_ks,
            "did:m:A",
            "wss://A".into(),
            Utc::now() + Duration::seconds(3600),
        )
        .await
        .unwrap();
        (reg, sink, dir, drains_ks)
    }

    fn super_admin() -> AuthClaims {
        AuthClaims::unsafe_local_cli_super_admin("test")
    }

    #[tokio::test]
    async fn cancels_existing_drain() {
        let (reg, sink, dir, drains_ks) = registry_with_drain().await;
        let cfg = config(dir.path());
        assert_eq!(reg.drain_count().await, 1);
        let result = drain_cancel(
            &cfg,
            &drains_ks,
            &reg,
            &sink,
            &super_admin(),
            DrainCancelParams {
                mediator_did: "did:m:A".into(),
            },
            "test",
        )
        .await
        .unwrap();
        assert_eq!(result.mediator_did, "did:m:A");
        assert_eq!(reg.drain_count().await, 0);
    }

    #[tokio::test]
    async fn refuses_unknown_mediator() {
        let (reg, sink, dir, drains_ks) = registry_with_drain().await;
        let cfg = config(dir.path());
        let err = drain_cancel(
            &cfg,
            &drains_ks,
            &reg,
            &sink,
            &super_admin(),
            DrainCancelParams {
                mediator_did: "did:m:never-registered".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            DrainCancelError::Registry(RegistryError::NotRegistered(_))
        ));
    }

    #[tokio::test]
    async fn refuses_active_mediator() {
        // Active mediator B can't be drain-cancelled — operator
        // must use `services disable didcomm` instead.
        let (reg, sink, dir, drains_ks) = registry_with_drain().await;
        let cfg = config(dir.path());
        let err = drain_cancel(
            &cfg,
            &drains_ks,
            &reg,
            &sink,
            &super_admin(),
            DrainCancelParams {
                mediator_did: "did:m:B".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            DrainCancelError::Registry(RegistryError::CannotCancelActive(_))
        ));
    }
}
