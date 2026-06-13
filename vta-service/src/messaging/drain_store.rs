//! Persistence for the mediator drain set.
//!
//! Schema (matches the workspace's existing keyspace pattern):
//! - Key:   `drain:{mediator_did}`
//! - Value: JSON-serialized [`PersistedDrainEntry`]
//!
//! The `generation` counter on the in-memory [`super::registry::DrainEntry`]
//! is intentionally NOT persisted — it is a process-local optimization
//! for race detection between reconnect tasks and registry mutations,
//! and starts fresh at each boot.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

const PREFIX: &str = "drain:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedDrainEntry {
    pub mediator_did: String,
    pub endpoint: String,
    pub drains_until: DateTime<Utc>,
}

fn drain_key(mediator_did: &str) -> String {
    format!("{PREFIX}{mediator_did}")
}

pub async fn store_drain(ks: &KeyspaceHandle, entry: &PersistedDrainEntry) -> Result<(), AppError> {
    ks.insert(drain_key(&entry.mediator_did), entry).await
}

pub async fn delete_drain(ks: &KeyspaceHandle, mediator_did: &str) -> Result<(), AppError> {
    ks.remove(drain_key(mediator_did)).await
}

pub async fn list_drains(ks: &KeyspaceHandle) -> Result<Vec<PersistedDrainEntry>, AppError> {
    let raw = ks.prefix_iter_raw(PREFIX).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let entry: PersistedDrainEntry = serde_json::from_slice(&value)?;
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use chrono::Duration;
    use tempfile::tempdir;
    use vti_common::config::StoreConfig;

    async fn fresh_keyspace() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::DRAINS).unwrap();
        (dir, ks)
    }

    fn entry(did: &str, secs: i64) -> PersistedDrainEntry {
        PersistedDrainEntry {
            mediator_did: did.into(),
            endpoint: format!("wss://{did}/ws"),
            drains_until: Utc::now() + Duration::seconds(secs),
        }
    }

    #[tokio::test]
    async fn store_and_list_round_trip() {
        let (_d, ks) = fresh_keyspace().await;
        store_drain(&ks, &entry("did:m:A", 3600)).await.unwrap();
        store_drain(&ks, &entry("did:m:B", 7200)).await.unwrap();
        let mut out = list_drains(&ks).await.unwrap();
        out.sort_by(|a, b| a.mediator_did.cmp(&b.mediator_did));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].mediator_did, "did:m:A");
        assert_eq!(out[1].mediator_did, "did:m:B");
    }

    #[tokio::test]
    async fn store_replaces_existing() {
        let (_d, ks) = fresh_keyspace().await;
        store_drain(&ks, &entry("did:m:A", 60)).await.unwrap();
        // Re-store with new TTL — should replace, not duplicate.
        store_drain(&ks, &entry("did:m:A", 120)).await.unwrap();
        let out = list_drains(&ks).await.unwrap();
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn delete_drain_removes_entry() {
        let (_d, ks) = fresh_keyspace().await;
        store_drain(&ks, &entry("did:m:A", 60)).await.unwrap();
        delete_drain(&ks, "did:m:A").await.unwrap();
        assert!(list_drains(&ks).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_empty_when_no_drains() {
        let (_d, ks) = fresh_keyspace().await;
        assert!(list_drains(&ks).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_ignores_unrelated_keys() {
        let (_d, ks) = fresh_keyspace().await;
        ks.insert("other:foo", &"unrelated").await.unwrap();
        store_drain(&ks, &entry("did:m:A", 60)).await.unwrap();
        let out = list_drains(&ks).await.unwrap();
        assert_eq!(out.len(), 1);
    }
}
