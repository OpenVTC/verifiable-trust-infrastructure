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

/// The `did:scid:vh:1` identity of a log, keyed by the bare did:scid DID.
///
/// Kept beside the record rather than on it: the published `WebvhDidRecord`
/// is the wire record of `list`/`get`, whose schema refuses unknown members, and
/// its `did` stays the log's did:webvh DID, the handle every webvh/dids task
/// takes. The prefix is not `did:`, which [`list_dids`] scans.
fn scid_key(scid_did: &str) -> String {
    format!("scid:{scid_did}")
}

/// What the VTA knows about the did:scid identity of one of its logs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ScidIdentity {
    /// The bare `did:scid:vh:1:<scid>` DID.
    pub scid_did: String,
    /// The did:webvh DID of the log that verifies it.
    pub webvh_did: String,
    /// Whether the DID is presented as the did:scid (VTI-KEY-165) rather than
    /// only listing it as an alias (VTI-KEY-166).
    pub presented: bool,
    /// Whether the log lists the did:scid DID URL in `alsoKnownAs`, linking the
    /// two forms as one subject (VTI-KEY-164).
    pub alias_listed: bool,
}

impl ScidIdentity {
    /// The identity of `webvh_did`'s log in did:scid form, or `None` for a DID
    /// that is not a did:webvh.
    pub fn of(webvh_did: &str, presented: bool, alias_listed: bool) -> Option<Self> {
        let (scid_did, _) = vta_sdk::did_scid::scid_forms(webvh_did)?;
        Some(Self {
            scid_did,
            webvh_did: webvh_did.to_string(),
            presented,
            alias_listed,
        })
    }

    /// The `did:scid:vh:1:<scid>?src=…` DID URL of the log's location.
    pub fn did_url(&self) -> String {
        vta_sdk::did_scid::scid_forms(&self.webvh_did)
            .map(|(_, url)| url)
            .unwrap_or_else(|| self.scid_did.clone())
    }

    /// The identity the DID is given out as: the did:scid DID when presented
    /// as one, and otherwise the did:webvh DID.
    pub fn identity(&self) -> &str {
        if self.presented {
            &self.scid_did
        } else {
            &self.webvh_did
        }
    }
}

pub async fn store_scid_identity(
    ks: &KeyspaceHandle,
    identity: &ScidIdentity,
) -> Result<(), AppError> {
    ks.insert(scid_key(&identity.scid_did), identity).await
}

/// The did:scid identity of a log, by its did:scid DID (with or without
/// `src`) or its did:webvh DID.
pub async fn get_scid_identity(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<ScidIdentity>, AppError> {
    let scid_did = if vta_sdk::did_scid::is_scid(did) {
        vta_sdk::did_scid::identity(did)
    } else if let Some((bare, _)) = vta_sdk::did_scid::scid_forms(did) {
        bare
    } else {
        return Ok(None);
    };
    let found: Option<ScidIdentity> = ks.get(scid_key(&scid_did)).await?;
    // A did:webvh only finds the identity of its own log: the same SCID under
    // another host is another log.
    Ok(found.filter(|f| vta_sdk::did_scid::is_scid(did) || f.webvh_did == did))
}

pub async fn delete_scid_identity(ks: &KeyspaceHandle, scid_did: &str) -> Result<(), AppError> {
    ks.remove(scid_key(&vta_sdk::did_scid::identity(scid_did)))
        .await
}

/// Every did:scid identity this VTA holds, for seeding the resolver's did:scid
/// sources at boot so a bare did:scid DID resolves after a restart.
pub async fn list_scid_identities(ks: &KeyspaceHandle) -> Result<Vec<ScidIdentity>, AppError> {
    let raw = ks.prefix_iter_raw("scid:").await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        out.push(serde_json::from_slice(&value)?);
    }
    Ok(out)
}

/// The did:webvh DID of the log a `webvh/dids` request names: a did:webvh DID
/// is its own, and a did:scid DID (with or without `src`) is the log of the
/// identity recorded for it. `None` for a did:scid this VTA holds no log for.
pub async fn log_did_for(ks: &KeyspaceHandle, did: &str) -> Result<Option<String>, AppError> {
    if !vta_sdk::did_scid::is_scid(did) {
        return Ok(Some(did.to_string()));
    }
    Ok(get_scid_identity(ks, did).await?.map(|i| i.webvh_did))
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

    /// A did:scid identity is found by its bare DID, by a DID URL with `src`,
    /// and by its own log's did:webvh DID — never by another log's.
    #[tokio::test]
    async fn scid_identity_round_trips_by_either_form() {
        let (_dir, ks) = setup_ks().await;
        let webvh = "did:webvh:QmScid:host.example:alice";
        let identity = ScidIdentity::of(webvh, true, true).unwrap();
        assert_eq!(identity.scid_did, "did:scid:vh:1:QmScid");
        assert_eq!(
            identity.did_url(),
            "did:scid:vh:1:QmScid?src=host.example/alice"
        );
        assert_eq!(identity.identity(), "did:scid:vh:1:QmScid");
        store_scid_identity(&ks, &identity).await.unwrap();

        for did in [
            "did:scid:vh:1:QmScid",
            "did:scid:vh:1:QmScid?src=elsewhere.example",
            webvh,
        ] {
            assert_eq!(
                get_scid_identity(&ks, did).await.unwrap(),
                Some(identity.clone()),
                "{did}"
            );
        }
        assert_eq!(
            get_scid_identity(&ks, "did:webvh:QmScid:other.example")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            log_did_for(&ks, "did:scid:vh:1:QmScid")
                .await
                .unwrap()
                .as_deref(),
            Some(webvh)
        );
        assert_eq!(
            log_did_for(&ks, webvh).await.unwrap().as_deref(),
            Some(webvh)
        );
        assert_eq!(
            log_did_for(&ks, "did:scid:vh:1:QmNone").await.unwrap(),
            None
        );
        // Not a did: key, so a DID listing never sees it.
        assert!(list_dids(&ks).await.unwrap().is_empty());
        assert_eq!(
            list_scid_identities(&ks).await.unwrap(),
            vec![identity.clone()]
        );

        delete_scid_identity(&ks, "did:scid:vh:1:QmScid?src=x")
            .await
            .unwrap();
        assert_eq!(get_scid_identity(&ks, webvh).await.unwrap(), None);
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
