//! The operation layer's calls to a DID hosting service.
//!
//! Each helper builds a [`WebvhHostClient`] for the server record and makes one
//! Trust-Task call. There is no token, session or per-server lock to manage:
//! every document carries this VTA's proof and the host authorises it from
//! that, on whichever transport carried it.

use vta_sdk::webvh::WebvhServerRecord;

use crate::error::AppError;
use crate::webvh_host::{
    AgentNameAvailability, AgentNameEntry, HostDomains, HostedDidEntry, RequestUriResponse,
    WebvhHostClient,
};

/// A client for `server`, issuing as `vta_did`.
pub(crate) async fn host_client<'a>(
    deps: &super::WebvhDeps<'a>,
    vta_did: &str,
    server: &WebvhServerRecord,
) -> Result<WebvhHostClient<'a>, AppError> {
    WebvhHostClient::for_server(
        &server.did,
        vta_did,
        deps.did_resolver,
        deps.didcomm_bridge,
        #[cfg(feature = "tsp")]
        deps.tsp.clone(),
    )
    .await
}

/// Publish a DID log to a slot this VTA owns.
pub async fn publish_log_to_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    mnemonic: &str,
    log_content: &str,
    domain: Option<&str>,
) -> Result<(), AppError> {
    host_client(deps, vta_did, server)
        .await?
        .publish_did(mnemonic, log_content, domain)
        .await
}

/// Delete a slot on the hosting server.
pub async fn delete_log_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    mnemonic: &str,
    domain: Option<&str>,
) -> Result<(), AppError> {
    host_client(deps, vta_did, server)
        .await?
        .delete_did(mnemonic, domain)
        .await
}

/// Claim a slot and publish its log in one call.
pub async fn register_did_atomic_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    path: &str,
    did_log: &str,
    force: bool,
    domain: Option<&str>,
) -> Result<RequestUriResponse, AppError> {
    host_client(deps, vta_did, server)
        .await?
        .register_did_atomic(path, did_log, force, domain)
        .await
}

/// Bind, release, park or resume an agent name, submitting the signed new
/// `did.jsonl`. `verb.host_state()` is `Some` for the three verbs the host
/// serves through `agent-name/update` and `None` for `remove`.
#[allow(clippy::too_many_arguments)]
pub async fn agent_name_op_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    verb: super::update::AgentNameVerb,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    domain: Option<&str>,
) -> Result<(), AppError> {
    let client = host_client(deps, vta_did, server).await?;
    match verb.host_state() {
        Some(state) => {
            client
                .update_agent_name(mnemonic, name, state, did_log, domain)
                .await
        }
        None => {
            client
                .remove_agent_name(mnemonic, name, did_log, domain)
                .await
        }
    }
}

/// Read a DID's agent-name registry from the hosting server.
pub async fn list_agent_names_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    mnemonic: &str,
    domain: Option<&str>,
) -> Result<Vec<AgentNameEntry>, AppError> {
    host_client(deps, vta_did, server)
        .await?
        .list_agent_names(mnemonic, domain)
        .await
}

/// Probe agent-name availability on the hosting server.
pub async fn check_agent_name_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
    name: &str,
    domain: Option<&str>,
) -> Result<AgentNameAvailability, AppError> {
    host_client(deps, vta_did, server)
        .await?
        .check_agent_name(name, domain)
        .await
}

/// The domains the hosting server lets this VTA mint into.
pub async fn my_domains_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
) -> Result<HostDomains, AppError> {
    host_client(deps, vta_did, server).await?.my_domains().await
}

/// Every slot the hosting server holds for this VTA.
pub async fn list_dids_on_server(
    deps: &super::WebvhDeps<'_>,
    vta_did: &str,
    server: &WebvhServerRecord,
) -> Result<Vec<HostedDidEntry>, AppError> {
    host_client(deps, vta_did, server)
        .await?
        .list_dids(vta_did)
        .await
}
