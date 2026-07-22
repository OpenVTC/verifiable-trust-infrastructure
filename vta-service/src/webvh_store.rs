use serde::{Deserialize, Serialize};
use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};
use zeroize::ZeroizeOnDrop;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

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

/// Cached daemon REST auth state for a single webvh server. Kept in
/// a service-private keyspace prefix (`server-auth:`) — never on the
/// public [`WebvhServerRecord`] type — so bearer tokens cannot leak
/// to REST `list` endpoints, DIDComm `list` responses, SDK consumers,
/// or backup exports.
///
/// Three hygiene measures on this type, in increasing strength:
///
/// 1. **Storage isolation** — service-private keyspace prefix, never
///    serialised on a public wire surface (see module-level doc).
/// 2. **Redacted `Debug`** — manual impl below so accidental
///    `tracing::info!(?record, …)` doesn't dump tokens to logs.
/// 3. **`ZeroizeOnDrop`** — when an instance falls out of scope the
///    token bytes are overwritten with zeros before the allocation
///    is freed. Helps against post-drop forensics and accidental
///    memory reuse; doesn't help against an attacker with concurrent
///    read access (in which case tokens leak regardless of disposal
///    semantics).
///
/// `Clone` is intentionally kept — operations occasionally need to
/// fan out a working copy. Each clone is independently zeroised on
/// drop, so the lifetime semantics stay correct.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct WebvhServerAuthRecord {
    /// Server id this auth state is for. Redundant with the
    /// keyspace key but kept on the record for self-description in
    /// diagnostics dumps.
    pub server_id: String,
    pub access_token: String,
    /// Unix-seconds expiry of `access_token`. The auth layer treats
    /// "fresh" as `now + skew < access_expires_at` so a 401 from the
    /// daemon mid-window is still expected to be rare; on a 401 the
    /// caller should clear the cache and re-authenticate.
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

impl std::fmt::Debug for WebvhServerAuthRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact secret material. Operators occasionally `?record` in
        // tracing — without this, the token would land in logs. The
        // expiry timestamps are not secret and are useful for
        // diagnosing freshness questions, so they remain visible.
        f.debug_struct("WebvhServerAuthRecord")
            .field("server_id", &self.server_id)
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
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

/// Delete a webvh server record and, atomically from the caller's
/// perspective, its associated daemon auth cache. The two are stored
/// under different prefixes so deletion is two writes — keeping
/// them paired here means callers can't accidentally remove the
/// server but leave a stale auth record that would be reused if
/// the same `id` were ever re-added.
pub async fn delete_server(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(server_key(id)).await?;
    ks.remove(server_auth_key(id)).await?;
    Ok(())
}

pub async fn get_server_auth(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<WebvhServerAuthRecord>, AppError> {
    ks.get(server_auth_key(id)).await
}

pub async fn store_server_auth(
    ks: &KeyspaceHandle,
    record: &WebvhServerAuthRecord,
) -> Result<(), AppError> {
    ks.insert(server_auth_key(&record.server_id), record).await
}

pub async fn delete_server_auth(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
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
    use crate::store::Store;
    use chrono::Utc;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn setup_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::WEBVH).unwrap();
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

    fn sample_auth(id: &str) -> WebvhServerAuthRecord {
        WebvhServerAuthRecord {
            server_id: id.into(),
            access_token: "test-access-token".into(),
            access_expires_at: 9_999_999_999,
            refresh_token: "test-refresh-token".into(),
            refresh_expires_at: 9_999_999_999,
        }
    }

    #[tokio::test]
    async fn auth_record_round_trips_through_keyspace() {
        let (_dir, ks) = setup_ks().await;
        let auth = sample_auth("prod");
        store_server_auth(&ks, &auth).await.unwrap();
        let loaded = get_server_auth(&ks, "prod").await.unwrap().unwrap();
        assert_eq!(loaded.access_token, "test-access-token");
        assert_eq!(loaded.refresh_token, "test-refresh-token");
    }

    #[tokio::test]
    async fn auth_record_uses_distinct_keyspace_prefix_from_server() {
        // Server metadata and auth state must not share a key —
        // `list_servers` does a `prefix_iter_raw("server:")` and would
        // try to deserialise auth records as `WebvhServerRecord` if
        // they collided. The `-auth` suffix on the prefix prevents
        // that: prefix scanning `server:` does not match `server-auth:`.
        let (_dir, ks) = setup_ks().await;
        store_server(&ks, &sample_server("prod")).await.unwrap();
        store_server_auth(&ks, &sample_auth("prod")).await.unwrap();
        let servers = list_servers(&ks).await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "prod");
    }

    #[tokio::test]
    async fn delete_server_cascades_to_auth_record() {
        // The lifecycle invariant: removing a server must also remove
        // its cached auth state, so re-adding a server with the same
        // id doesn't silently inherit stale tokens.
        let (_dir, ks) = setup_ks().await;
        store_server(&ks, &sample_server("prod")).await.unwrap();
        store_server_auth(&ks, &sample_auth("prod")).await.unwrap();
        assert!(get_server_auth(&ks, "prod").await.unwrap().is_some());

        delete_server(&ks, "prod").await.unwrap();
        assert!(get_server(&ks, "prod").await.unwrap().is_none());
        assert!(
            get_server_auth(&ks, "prod").await.unwrap().is_none(),
            "delete_server must cascade to the auth record"
        );
    }

    #[tokio::test]
    async fn explicit_delete_server_auth_works_independently() {
        // Some flows (refresh failure, token rotation reset) want to
        // wipe just the auth state without touching the server record.
        let (_dir, ks) = setup_ks().await;
        store_server(&ks, &sample_server("prod")).await.unwrap();
        store_server_auth(&ks, &sample_auth("prod")).await.unwrap();

        delete_server_auth(&ks, "prod").await.unwrap();
        assert!(get_server(&ks, "prod").await.unwrap().is_some());
        assert!(get_server_auth(&ks, "prod").await.unwrap().is_none());
    }

    #[test]
    fn auth_record_debug_redacts_secret_fields() {
        // tracing::info!(?record, "...") is a likely future site
        // that would log tokens without this redaction. Pin the
        // invariant.
        let auth = WebvhServerAuthRecord {
            server_id: "prod".into(),
            access_token: "should-not-appear-in-logs-XXXX".into(),
            access_expires_at: 1234,
            refresh_token: "also-not-here-YYYY".into(),
            refresh_expires_at: 5678,
        };
        let dbg = format!("{auth:?}");
        assert!(
            !dbg.contains("XXXX"),
            "access_token must not appear in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("YYYY"),
            "refresh_token must not appear in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug should mark redactions explicitly: {dbg}"
        );
        // Non-secret fields should still be visible — operators
        // diagnosing freshness questions need to see expiry.
        assert!(dbg.contains("1234"), "non-secret expiry must remain: {dbg}");
        assert!(
            dbg.contains("prod"),
            "non-secret server_id must remain: {dbg}"
        );
    }
}
