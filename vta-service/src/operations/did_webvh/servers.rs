//! CRUD + DID validation for webvh hosting servers.
//!
//! The VTA maintains a registry of webvh servers that it can publish
//! `did.jsonl` logs to. Each entry is a `WebvhServerRecord` keyed by a
//! short operator-chosen id (`"prod"`, `"staging"`) pointing at the
//! server's DID. Resolution of the DID → transport endpoint is done
//! lazily at publish/fetch time by the `WebvhTransport` in the parent
//! module.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;
use vta_sdk::protocols::did_management::servers::{
    AddWebvhServerResultBody, ListWebvhServersResultBody, RemoveWebvhServerResultBody,
    UpdateWebvhServerResultBody,
};
use vta_sdk::webvh::WebvhServerRecord;

const DIDCOMM_MESSAGING_SERVICE_TYPE: &str = "DIDCommMessaging";
const WEBVH_HOSTING_SERVICE_TYPE: &str = "WebVHHosting";
const WEBVH_HOSTING_SERVICE_TYPE_LEGACY: &str = "WebVHHostingService";
const SUPPORTED_SERVER_SERVICE_TYPES_TEXT: &str =
    "DIDCommMessaging, WebVHHosting, or WebVHHostingService";

pub async fn add_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    server_did: &str,
    label: Option<String>,
    did_resolver: &DIDCacheClient,
    channel: &str,
) -> Result<AddWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    if webvh_store::get_server(webvh_ks, id).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "webvh server already exists: {id}"
        )));
    }

    // Validate the DID resolves and has a supported WebVH service
    validate_server_did(did_resolver, server_did).await?;

    let now = Utc::now();
    let record = WebvhServerRecord {
        id: id.to_string(),
        did: server_did.to_string(),
        label,
        created_at: now,
        updated_at: now,
    };
    webvh_store::store_server(webvh_ks, &record).await?;

    info!(channel, id = %id, did = %server_did, "webvh server added");
    Ok(record)
}

pub async fn list_webvh_servers(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    channel: &str,
) -> Result<ListWebvhServersResultBody, AppError> {
    // Any authenticated user can list servers
    let servers = webvh_store::list_servers(webvh_ks).await?;
    info!(channel, caller = %auth.did, count = servers.len(), "webvh servers listed");
    Ok(ListWebvhServersResultBody { servers })
}

pub async fn update_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    label: Option<String>,
    channel: &str,
) -> Result<UpdateWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    let mut record = webvh_store::get_server(webvh_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {id}")))?;

    if let Some(lbl) = label {
        record.label = if lbl.is_empty() { None } else { Some(lbl) };
    }
    record.updated_at = Utc::now();

    webvh_store::store_server(webvh_ks, &record).await?;

    info!(channel, id = %id, "webvh server updated");
    Ok(record)
}

pub async fn remove_webvh_server(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    id: &str,
    channel: &str,
) -> Result<RemoveWebvhServerResultBody, AppError> {
    auth.require_super_admin()?;

    webvh_store::get_server(webvh_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {id}")))?;

    webvh_store::delete_server(webvh_ks, id).await?;
    webvh_store::delete_server_auth(webvh_ks, id).await?;

    info!(channel, id = %id, "webvh server removed");
    Ok(RemoveWebvhServerResultBody {
        id: id.to_string(),
        removed: true,
    })
}

/// Returns true when a service type list advertises a DIDComm endpoint.
pub(super) fn is_didcomm_service_type(service_types: &[String]) -> bool {
    service_types
        .iter()
        .any(|t| t == DIDCOMM_MESSAGING_SERVICE_TYPE)
}

/// Returns true when a service type list advertises a REST-capable WebVH
/// hosting endpoint.
pub(super) fn is_webvh_rest_service_type(service_types: &[String]) -> bool {
    service_types
        .iter()
        .any(|t| t == WEBVH_HOSTING_SERVICE_TYPE || t == WEBVH_HOSTING_SERVICE_TYPE_LEGACY)
}

/// Returns true when at least one service entry advertises a supported WebVH
/// server endpoint type.
pub(super) fn has_supported_server_service<T>(
    services: &[T],
    service_types: impl Fn(&T) -> &[String],
) -> bool {
    services.iter().any(|svc| {
        let types = service_types(svc);
        is_didcomm_service_type(types) || is_webvh_rest_service_type(types)
    })
}

/// Validate that a DID resolves and has at least one supported WebVH server
/// service.
///
/// Accepted service types are `DIDCommMessaging`, `WebVHHosting`, and
/// `WebVHHostingService`.
pub(super) async fn validate_server_did(
    did_resolver: &DIDCacheClient,
    server_did: &str,
) -> Result<(), AppError> {
    let resolved = did_resolver.resolve(server_did).await.map_err(|e| {
        AppError::Validation(format!("failed to resolve server DID {server_did}: {e}"))
    })?;

    if !has_supported_server_service(&resolved.doc.service, |svc| &svc.type_) {
        return Err(AppError::Validation(format!(
            "server DID {server_did} has no supported service endpoint (expected {SUPPORTED_SERVER_SERVICE_TYPES_TEXT})"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::has_supported_server_service;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use crate::test_support::super_admin_claims;
    use crate::webvh_store::{self, WebvhServerAuthRecord};
    use vta_sdk::webvh::WebvhServerRecord;

    #[derive(Debug, Clone)]
    struct TestService {
        types: Vec<String>,
    }

    fn service(types: &[&str]) -> TestService {
        TestService {
            types: types.iter().map(|t| (*t).to_string()).collect(),
        }
    }

    fn sample_server(id: &str) -> WebvhServerRecord {
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:webvh:{id}"),
            label: Some("edge".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn fresh_webvh_keyspace() -> (tempfile::TempDir, Store, crate::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace("webvh").expect("open webvh ks");
        (dir, store, ks)
    }

    #[test]
    fn supported_server_service_accepts_didcomm_messaging() {
        let services = [service(&["DIDCommMessaging"])];
        assert!(has_supported_server_service(&services, |svc| &svc.types));
    }

    #[test]
    fn supported_server_service_accepts_webvh_hosting() {
        let services = [service(&["WebVHHosting"])];
        assert!(has_supported_server_service(&services, |svc| &svc.types));
    }

    #[test]
    fn supported_server_service_accepts_webvh_hosting_service() {
        let services = [service(&["WebVHHostingService"])];
        assert!(has_supported_server_service(&services, |svc| &svc.types));
    }

    #[test]
    fn supported_server_service_rejects_unrelated_service_types() {
        let services = [service(&["LinkedDomains"]), service(&["ExampleService"])];
        assert!(!has_supported_server_service(&services, |svc| &svc.types));
    }

    #[tokio::test]
    async fn list_webvh_servers_serializes_metadata_only_when_auth_cache_exists() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let auth = super_admin_claims();
        let server = sample_server("srv");
        webvh_store::store_server(&ks, &server).await.unwrap();
        webvh_store::store_server_auth(
            &ks,
            &server.id,
            &WebvhServerAuthRecord {
                access_token: Some("tok".into()),
                access_expires_at: Some(42),
                refresh_token: Some("refresh".into()),
            },
        )
        .await
        .unwrap();

        let body = super::list_webvh_servers(&ks, &auth, "test").await.unwrap();
        let json = serde_json::to_value(&body).unwrap();

        assert_eq!(json["servers"].as_array().unwrap().len(), 1);
        assert!(json["servers"][0].get("access_token").is_none());
        assert!(json["servers"][0].get("access_expires_at").is_none());
        assert!(json["servers"][0].get("refresh_token").is_none());
    }

    #[tokio::test]
    async fn remove_webvh_server_deletes_stored_auth_cache() {
        let (_dir, _store, ks) = fresh_webvh_keyspace().await;
        let auth = super_admin_claims();
        let server = sample_server("srv");
        webvh_store::store_server(&ks, &server).await.unwrap();
        webvh_store::store_server_auth(
            &ks,
            &server.id,
            &WebvhServerAuthRecord {
                access_token: Some("tok".into()),
                access_expires_at: Some(42),
                refresh_token: Some("refresh".into()),
            },
        )
        .await
        .unwrap();

        super::remove_webvh_server(&ks, &auth, &server.id, "test")
            .await
            .unwrap();

        assert!(
            webvh_store::get_server(&ks, &server.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            webvh_store::get_server_auth(&ks, &server.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
