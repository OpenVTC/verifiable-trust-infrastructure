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

/// Authenticate to the registered hosting server and relay its
/// `/api/me/domains` view to the caller. Used by
/// `pnm did-mgmt list-domains` and the interactive `--domain`
/// prompt in `create-did` / `register-did`.
///
/// Only the REST transport is supported today — the v0.8
/// `did-management/me/domains/...` task is REST-only on the
/// hosting server side. For DIDComm-only servers we return an
/// empty list and a `None` default so the CLI falls back to the
/// server-side resolution chain rather than blocking the user.
pub async fn list_webvh_server_domains(
    deps: &crate::operations::did_webvh::WebvhDeps<'_>,
    auth: &AuthClaims,
    vta_did: Option<&str>,
    server_id: &str,
) -> Result<vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsResultBody, AppError>
{
    use vta_sdk::protocols::did_management::servers::{
        ListWebvhServerDomainsResultBody, WebvhServerDomainEntry,
    };

    // Any authenticated caller may discover hosting domains —
    // identical scope rule as `list_webvh_servers`.
    let server = webvh_store::get_server(deps.webvh_ks, server_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh server not found: {server_id}")))?;

    let vta_did_value = vta_did.ok_or_else(|| {
        AppError::Validation(
            "VTA DID is not configured — complete `vta setup` before listing hosting domains."
                .to_string(),
        )
    })?;

    let identity = crate::operations::did_webvh::auth_cache::load_vta_webvh_signing_identity(
        deps.keys_ks,
        deps.imported_ks,
        deps.seed_store,
        deps.audit_ks,
        vta_did_value,
    )
    .await?;
    let auth_ctx = crate::operations::did_webvh::auth_cache::AuthContext {
        webvh_ks: deps.webvh_ks,
        identity: &identity,
        locks: deps.auth_locks,
    };

    let transport = crate::operations::did_webvh::WebvhTransport::from_server_authenticated(
        &server,
        deps.did_resolver,
        deps.didcomm_bridge,
        &auth_ctx,
    )
    .await?;
    let entries = match transport {
        crate::operations::did_webvh::WebvhTransport::Rest(c) => {
            let resp = c.list_my_domains().await?;
            ListWebvhServerDomainsResultBody {
                domains: resp
                    .domains
                    .into_iter()
                    .map(|d| WebvhServerDomainEntry {
                        name: d.name,
                        default_domain: d.default_domain,
                        status: d.status,
                        label: d.label,
                    })
                    .collect(),
                default: resp.default,
            }
        }
        crate::operations::did_webvh::WebvhTransport::DIDComm { .. } => {
            // DIDComm-only servers don't have a `me/domains` op
            // in the v0.8 surface; the CLI falls back to the
            // server's resolution chain.
            ListWebvhServerDomainsResultBody {
                domains: vec![],
                default: None,
            }
        }
    };
    info!(
        channel = "rest",
        caller = %auth.did,
        server_id = %server_id,
        count = entries.domains.len(),
        "webvh server hosting domains listed"
    );
    Ok(entries)
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

    info!(channel, id = %id, "webvh server removed");
    Ok(RemoveWebvhServerResultBody {
        id: id.to_string(),
        removed: true,
    })
}

/// Validate that a DID resolves and has at least one supported WebVH service.
///
/// Accepts any of the types listed in
/// [`super::transport::SUPPORTED_TYPES_HUMAN`]. Delegates to
/// [`super::transport::resolve_server_transport`] so the accepted-types
/// set is defined in exactly one place — adding or removing a type
/// changes both validation and runtime selection together.
pub(super) async fn validate_server_did(
    did_resolver: &DIDCacheClient,
    server_did: &str,
) -> Result<(), AppError> {
    let resolved = did_resolver.resolve(server_did).await.map_err(|e| {
        AppError::Validation(format!("failed to resolve server DID {server_did}: {e}"))
    })?;

    if super::transport::resolve_server_transport(&resolved.doc.service).is_none() {
        return Err(AppError::Validation(format!(
            "server DID {server_did} has no supported webvh endpoint (expected: {})",
            super::transport::SUPPORTED_TYPES_HUMAN,
        )));
    }

    Ok(())
}
