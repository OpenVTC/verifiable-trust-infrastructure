//! A `did:webs` integration DID (design note did-webs-in-the-vta §4, S7).
//!
//! Selected by `DID_METHOD=webs` ([`super::webvh::take_webs_method`]). The DID
//! is minted by [`create_did_webs`] — level 1, class `service` (an
//! integration's DID is a service DID, VTI-KEY-192), shaped by the template —
//! so every §9.2 check and refusal of `vta/webs/dids/create/0.2` applies, and
//! `[dids] webs_service_dids` gates it as it gates that task's service class.
//! It is published at a registered did-hosting server (`WEBVH_SERVER`, on
//! `WEBVH_DOMAIN`, under `WEBVH_PATH`): a `did:webs` has no serverless mode.

//!
//! A build without the `webs` feature still reads the selection, and refuses
//! it by name rather than minting a `did:webvh` the operator did not ask for.

use std::collections::BTreeMap;

use serde_json::Value;

use super::ProvisionIntegrationDeps;
use crate::auth::AuthClaims;
use crate::error::AppError;
#[cfg(feature = "webs")]
use crate::operations::did_webs::{
    CreateDidWebsParams, WebsDeps, WebsHost, WebsTemplateRequest, create_did_webs,
};
#[cfg(feature = "webs")]
use crate::webs_store::WebsDidClass;

/// Where a `did:webs` integration DID is published: the registered
/// did-hosting servers, or, in tests, a recording fake. Empty without the
/// `webs` feature.
pub(crate) trait WebsHostSource: Sync {
    #[cfg(feature = "webs")]
    type Host<'a>: WebsHost + Sync
    where
        Self: 'a;

    /// The host for registered server `server_id`, reached as this VTA.
    #[cfg(feature = "webs")]
    fn host<'a>(
        &'a self,
        state: &'a ProvisionIntegrationDeps,
        server_id: &str,
    ) -> impl std::future::Future<Output = Result<Self::Host<'a>, AppError>> + Send;
}

/// The did-hosting servers this VTA has registered (`vta did-mgmt servers add`).
pub(crate) struct RegisteredWebsHosts;

impl WebsHostSource for RegisteredWebsHosts {
    #[cfg(feature = "webs")]
    type Host<'a> = crate::webvh_host::WebvhHostClient<'a>;

    #[cfg(feature = "webs")]
    async fn host<'a>(
        &'a self,
        state: &'a ProvisionIntegrationDeps,
        server_id: &str,
    ) -> Result<Self::Host<'a>, AppError> {
        let server = crate::webvh_store::get_server(&state.webvh_ks, server_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("hosting server not found: {server_id}")))?;
        let vta_did = state.config.read().await.vta_did.clone().ok_or_else(|| {
            AppError::Validation(
                "vta_did is not configured; the VTA needs its own DID to sign what it sends a \
                 hosting server (set `vta_did` in config / VTA_DID)"
                    .into(),
            )
        })?;
        let resolver = state
            .did_resolver
            .as_ref()
            .ok_or_else(|| AppError::Internal("DID resolver not initialized".into()))?;
        crate::webvh_host::WebvhHostClient::for_server(
            &server.did,
            &vta_did,
            resolver,
            &state.didcomm_bridge,
            // As the webvh path: provisioning holds no mediator socket of its
            // own, so the seam falls to DIDComm.
            #[cfg(feature = "tsp")]
            None,
        )
        .await
    }
}

/// Where the integration's `did:webs` goes, from the transport-metadata vars.
pub(super) struct WebsTarget {
    pub server_id: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
}

/// What the mint made: the DID, its keys' ids as its document gives them,
/// that document, and the key event stream it derives from.
pub(super) struct WebsMint {
    pub did: String,
    pub signing_key_id: String,
    pub ka_key_id: String,
    pub did_document: Value,
    pub keri_cesr: String,
}

/// Without the `webs` feature: the refusal, before anything is minted.
#[cfg(not(feature = "webs"))]
#[allow(clippy::too_many_arguments)]
pub(super) async fn mint<W: WebsHostSource>(
    _state: &ProvisionIntegrationDeps,
    _auth: &AuthClaims,
    _hosts: &W,
    _context: &str,
    _client_did: &str,
    template_name: &str,
    _template_vars: &BTreeMap<String, Value>,
    _target: WebsTarget,
    _set_primary: bool,
) -> Result<WebsMint, AppError> {
    Err(AppError::Validation(format!(
        "DID_METHOD=webs asks for a did:webs integration DID, and this VTA was built without \
         did:webs (the `webs` feature). Provision template '{template_name}' as a did:webvh \
         (omit DID_METHOD), or from a VTA built with did:webs."
    )))
}

/// Mint, publish and record the integration's `did:webs` from `template_name`.
#[cfg(feature = "webs")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn mint<W: WebsHostSource>(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    hosts: &W,
    context: &str,
    client_did: &str,
    template_name: &str,
    template_vars: &BTreeMap<String, Value>,
    target: WebsTarget,
    set_primary: bool,
) -> Result<WebsMint, AppError> {
    let server_id = target.server_id.ok_or_else(|| {
        AppError::Validation(format!(
            "a did:webs integration is published by a did-hosting server, and template \
             '{template_name}' resolved without one: pass `--var WEBVH_SERVER=<id>` (a server \
             registered with `vta did-mgmt servers add`). A did:webs has no serverless mode, so \
             `URL` alone cannot place it."
        ))
    })?;
    if target.path.as_deref() == Some(".well-known") {
        return Err(AppError::Validation(
            "WEBVH_PATH '.well-known' names a did:webvh root DID; a did:webs is always \
             `did:webs:<domain>[:<path>]:<AID>`. Omit WEBVH_PATH to publish at the domain's top \
             level, or give a `/`-separated slot path."
                .into(),
        ));
    }

    // `WEBVH_SERVER` is where the stream goes, not document content: the
    // template's variable check must not see it.
    let mut vars = template_vars.clone();
    vars.remove("WEBVH_SERVER");

    // A clone, so no lock is held across the publish (R1.3).
    let config = state.config.read().await.clone();
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not initialized".into()))?;
    let deps = WebsDeps {
        keys_ks: &state.keys_ks,
        contexts_ks: &state.contexts_ks,
        webvh_ks: &state.webvh_ks,
        webs_ks: &state.webs_ks,
        did_templates_ks: Some(&state.did_templates_ks),
        acl_ks: Some(&state.acl_ks),
        audit: &state.audit,
        seed_store: &*state.seed_store,
        config: &config,
        did_resolver,
    };

    let mut params = CreateDidWebsParams::new(context, server_id.clone());
    params.path = target.path;
    params.domain = target.domain;
    params.label = Some(client_did.to_string());
    params.set_primary = set_primary;
    params.did_class = Some(WebsDidClass::Service);
    let mut template = WebsTemplateRequest::new(template_name);
    template.context = Some(context.to_string());
    template.vars = vars;
    params.template = Some(template);

    let host = hosts.host(state, &server_id).await?;
    let created = create_did_webs(&deps, auth, params, &host, "provision-integration")
        .await
        .map_err(AppError::from)?;

    let record = crate::webs_store::get(&state.webs_ks, &created.did)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!("{} was created but is not recorded", created.did))
        })?;
    let keri_cesr = String::from_utf8(record.keri_cesr).map_err(|_| {
        AppError::Internal(format!(
            "the key event stream of {} is not text",
            created.did
        ))
    })?;
    // The document as its host serves it: derived from the stream just
    // published, the same derivation every resolver makes.
    let did_document = crate::self_keys::own_document(&created.did, None, Some(&state.webs_ks))
        .await
        .ok_or_else(|| {
            AppError::Internal(format!(
                "the key event stream of {} does not derive a document",
                created.did
            ))
        })?;

    Ok(WebsMint {
        did: created.did,
        signing_key_id: created.signing_key_id,
        ka_key_id: created.key_agreement_key_id,
        did_document,
        keri_cesr,
    })
}
