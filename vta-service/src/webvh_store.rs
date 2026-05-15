use serde::{Deserialize, Serialize};
use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct WebvhServerAuthRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

fn server_key(id: &str) -> String {
    format!("server:{id}")
}

fn server_auth_key(id: &str) -> String {
    format!("server-auth:{id}")
}

fn did_key(did: &str) -> String {
    format!("did:{did}")
}

fn log_key(did: &str) -> String {
    format!("log:{did}")
}

pub async fn get_server(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<WebvhServerRecord>, AppError> {
    ks.get(server_key(id)).await
}

pub async fn store_server(ks: &KeyspaceHandle, record: &WebvhServerRecord) -> Result<(), AppError> {
    ks.insert(server_key(&record.id), record).await
}

pub async fn delete_server(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(server_key(id)).await
}

pub(crate) async fn get_server_auth(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<WebvhServerAuthRecord>, AppError> {
    ks.get(server_auth_key(id)).await
}

pub(crate) async fn store_server_auth(
    ks: &KeyspaceHandle,
    id: &str,
    record: &WebvhServerAuthRecord,
) -> Result<(), AppError> {
    ks.insert(server_auth_key(id), record).await
}

pub(crate) async fn delete_server_auth(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(server_auth_key(id)).await
}

pub async fn list_servers(ks: &KeyspaceHandle) -> Result<Vec<WebvhServerRecord>, AppError> {
    let raw = ks.prefix_iter_raw("server:").await?;
    let mut servers = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: WebvhServerRecord = serde_json::from_slice(&value)?;
        servers.push(record);
    }
    Ok(servers)
}

pub async fn get_did(ks: &KeyspaceHandle, did: &str) -> Result<Option<WebvhDidRecord>, AppError> {
    ks.get(did_key(did)).await
}

pub async fn store_did(ks: &KeyspaceHandle, record: &WebvhDidRecord) -> Result<(), AppError> {
    ks.insert(did_key(&record.did), record).await
}

pub async fn delete_did(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.remove(did_key(did)).await
}

pub async fn list_dids(ks: &KeyspaceHandle) -> Result<Vec<WebvhDidRecord>, AppError> {
    let raw = ks.prefix_iter_raw("did:").await?;
    let mut dids = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: WebvhDidRecord = serde_json::from_slice(&value)?;
        dids.push(record);
    }
    Ok(dids)
}

pub async fn get_did_log(ks: &KeyspaceHandle, did: &str) -> Result<Option<String>, AppError> {
    let bytes = ks.get_raw(log_key(did)).await?;
    Ok(bytes.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

pub async fn store_did_log(
    ks: &KeyspaceHandle,
    did: &str,
    log_content: &str,
) -> Result<(), AppError> {
    ks.insert_raw(log_key(did), log_content.as_bytes().to_vec())
        .await
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    fn sample_server(id: &str) -> WebvhServerRecord {
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:webvh:{id}"),
            label: Some("edge".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn fresh_webvh_keyspace() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("webvh").expect("open webvh ks");
        (dir, store, ks)
    }

    #[tokio::test]
    async fn server_auth_round_trips_and_deletes() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let auth = WebvhServerAuthRecord {
            access_token: Some("tok".into()),
            access_expires_at: Some(42),
            refresh_token: Some("refresh".into()),
        };

        store_server_auth(&ks, "srv", &auth).await.unwrap();
        assert_eq!(get_server_auth(&ks, "srv").await.unwrap(), Some(auth));

        delete_server_auth(&ks, "srv").await.unwrap();
        assert!(get_server_auth(&ks, "srv").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_servers_reads_only_metadata_records() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        store_server(&ks, &sample_server("srv")).await.unwrap();
        store_server_auth(
            &ks,
            "srv",
            &WebvhServerAuthRecord {
                access_token: Some("tok".into()),
                access_expires_at: Some(42),
                refresh_token: Some("refresh".into()),
            },
        )
        .await
        .unwrap();

        let servers = list_servers(&ks).await.unwrap();
        assert_eq!(servers.len(), 1);

        let json = serde_json::to_value(&servers[0]).unwrap();
        assert!(json.get("access_token").is_none());
        assert!(json.get("access_expires_at").is_none());
        assert!(json.get("refresh_token").is_none());
    }
}
