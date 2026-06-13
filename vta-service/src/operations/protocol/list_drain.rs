//! `list_drain` operation — read-only.
//!
//! Spec: §5.1 (`pnm services didcomm drain list`). Reads the
//! persisted drain set via [`drain_store::list_drains`] and
//! returns it shaped for the CLI / SDK consumer.
//!
//! Auth: super-admin (matches the rest of the service-management
//! surface).

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;

use vta_sdk::protocol::services::DrainListResponse;

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::messaging::drain_store;
use crate::store::KeyspaceHandle;

#[derive(Debug, Error)]
pub enum ListDrainError {
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for ListDrainError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

/// List currently-draining mediators.
///
/// Returns one entry per drain set member with its DID, endpoint
/// (best-effort), and drain deadline. Empty list is normal — the
/// VTA may have no in-flight drains.
pub async fn list_drain(
    _config: &Arc<RwLock<AppConfig>>,
    drains_ks: &KeyspaceHandle,
    auth: &AuthClaims,
) -> Result<DrainListResponse, ListDrainError> {
    auth.require_super_admin()
        .map_err(|e| ListDrainError::Auth(e.to_string()))?;

    let entries = drain_store::list_drains(drains_ks).await?;
    let entries = entries
        .into_iter()
        .map(|e| vta_sdk::protocol::services::DrainEntry {
            mediator_did: e.mediator_did,
            endpoint: e.endpoint,
            drains_until: e.drains_until.to_rfc3339(),
        })
        .collect();
    Ok(DrainListResponse { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use chrono::{Duration, Utc};
    use vti_common::config::StoreConfig;

    async fn empty_drains_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::DRAINS).unwrap();
        (dir, ks)
    }

    /// Empty drain set returns an empty list, not an error.
    #[tokio::test]
    async fn empty_drain_set_returns_empty_list() {
        let (_dir, ks) = empty_drains_ks().await;
        let cfg = {
            let mut c = crate::test_support::test_app_config(_dir.path().into());
            c.services.rest = true;
            c.services.didcomm = true;
            c.vta_did = Some("did:webvh:scid:host:vta".into());
            c.config_path = _dir.path().join("vta.toml");
            Arc::new(RwLock::new(c))
        };
        let super_admin = AuthClaims::unsafe_local_cli_super_admin("test");
        let response = list_drain(&cfg, &ks, &super_admin).await.unwrap();
        assert!(response.entries.is_empty());
    }

    /// A populated drain set is faithfully returned.
    #[tokio::test]
    async fn populated_drain_set_round_trips() {
        let (_dir, ks) = empty_drains_ks().await;
        let deadline = Utc::now() + Duration::hours(24);
        drain_store::store_drain(
            &ks,
            &drain_store::PersistedDrainEntry {
                mediator_did: "did:peer:2.M".into(),
                endpoint: "https://m.example".into(),
                drains_until: deadline,
            },
        )
        .await
        .unwrap();

        let cfg = {
            let mut c = crate::test_support::test_app_config(_dir.path().into());
            c.services.rest = true;
            c.services.didcomm = true;
            c.vta_did = Some("did:webvh:scid:host:vta".into());
            c.config_path = _dir.path().join("vta.toml");
            Arc::new(RwLock::new(c))
        };
        let super_admin = AuthClaims::unsafe_local_cli_super_admin("test");
        let response = list_drain(&cfg, &ks, &super_admin).await.unwrap();
        assert_eq!(response.entries.len(), 1);
        assert_eq!(response.entries[0].mediator_did, "did:peer:2.M");
        assert_eq!(response.entries[0].endpoint, "https://m.example");
    }
}
