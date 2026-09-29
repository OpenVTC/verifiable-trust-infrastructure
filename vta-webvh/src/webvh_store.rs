use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

fn server_key(id: &str) -> String {
    format!("server:{id}")
}

fn did_key(did: &str) -> String {
    format!("did:{did}")
}

fn log_key(did: &str) -> String {
    format!("log:{did}")
}

/// The version id last **confirmed published** to the hosting server for this
/// DID. Kept in a service-private key rather than on the record so it never
/// leaks to `list` responses or backups, and so adding it needs no change to
/// the published `WebvhDidRecord` type.
///
/// Its job is recovery: a webvh update commits local state (counter, keys, log)
/// before it can confirm the host received it, so a failed publish leaves the
/// local head ahead of the host. Comparing the local head against this marker
/// tells the next update to *re-publish* the pending log rather than build a
/// new version on top of a divergence — which is what lets a failed attempt
/// self-heal instead of wedging the DID.
fn published_key(did: &str) -> String {
    format!("published:{did}")
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

/// Delete a webvh server record.
pub async fn delete_server(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(server_key(id)).await
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

/// Read the version id last confirmed published to the host (see
/// [`published_key`]). `None` means never confirmed — treat the local head as
/// unpublished and re-publish before building on it.
pub async fn get_published_version(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<String>, AppError> {
    let bytes = ks.get_raw(published_key(did)).await?;
    Ok(bytes.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

/// Record that `version_id` is now confirmed present on the host. Called only
/// after a publish returns success.
pub async fn set_published_version(
    ks: &KeyspaceHandle,
    did: &str,
    version_id: &str,
) -> Result<(), AppError> {
    ks.insert_raw(published_key(did), version_id.as_bytes().to_vec())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vti_common::config::StoreConfig as VtiStoreConfig;
    use vti_common::store::Store;

    async fn setup_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::WEBVH).unwrap();
        (dir, ks)
    }

    /// The reconcile marker: absent until a publish is confirmed, then it
    /// round-trips and overwrites. The update path compares it against the
    /// local head to decide whether to re-publish before building anew.
    #[tokio::test]
    async fn published_version_marker_round_trips() {
        let (_dir, ks) = setup_ks().await;
        let did = "did:webvh:abc:host.example:alice";

        // Absent by default — the update path reads this as "unconfirmed" and
        // re-publishes, which is the safe assumption for a DID that has never
        // confirmed a publish (including one whose create-time publish failed).
        assert_eq!(get_published_version(&ks, did).await.unwrap(), None);

        set_published_version(&ks, did, "3-QmHead").await.unwrap();
        assert_eq!(
            get_published_version(&ks, did).await.unwrap().as_deref(),
            Some("3-QmHead")
        );

        // Overwrites, so a later confirmed version replaces the earlier one.
        set_published_version(&ks, did, "4-QmNext").await.unwrap();
        assert_eq!(
            get_published_version(&ks, did).await.unwrap().as_deref(),
            Some("4-QmNext")
        );

        // Its own key prefix — it must not collide with the log or record.
        assert_eq!(get_did_log(&ks, did).await.unwrap(), None);
    }

    fn sample_server(id: &str) -> WebvhServerRecord {
        let now = Utc::now();
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:web:{id}.example"),
            label: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn delete_server_removes_the_record() {
        let (_dir, ks) = setup_ks().await;
        store_server(&ks, &sample_server("prod")).await.unwrap();
        assert_eq!(list_servers(&ks).await.unwrap().len(), 1);
        delete_server(&ks, "prod").await.unwrap();
        assert!(get_server(&ks, "prod").await.unwrap().is_none());
        assert!(list_servers(&ks).await.unwrap().is_empty());
    }
}
