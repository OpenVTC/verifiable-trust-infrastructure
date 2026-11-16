//! This VTA's own `did:webs` identity, minted before any principal exists:
//! by `vta setup` (`vta_did` kind `create_webs`) and by a TEE VTA's first boot
//! (`[tee.kms] vta_did_webs`, `crate::tee_webs`). One create for both, so the
//! two cannot drift (design note did-webs-in-the-vta §4, S6 and S8).
//!
//! The identity is a key-role identity (decision 2) minted without its host
//! (`defer_publish`): neither caller has standing at the host yet. The first
//! boot registers it on its own authority ([`super::publish_own_identity`],
//! decision 3).
//!
//! # Authority
//!
//! No caller's claims are checked, because none exist: the node is minting
//! the identity every later principal is granted under. That is why
//! [`create_own_identity`] refuses whenever this VTA already has an identity
//! (`vta_did` configured, or the `vta` context holding a primary DID). It is
//! reached from no transport — no route, Trust Task or DIDComm handler — only
//! from setup and the enclave's boot, before the server runs.

use crate::error::AppError;
use crate::webs_store::{self, WebsDidClass};

use super::{
    CreateDidWebsParams, CreateDidWebsResult, Minter, NoHost, WebsDeps, WebsError,
    designated_service_from_json, mint,
};

/// The context a VTA's own identity and its keys belong to.
pub const OWN_IDENTITY_CONTEXT: &str = "vta";

/// The id the hosting server is registered under when none is named.
pub const DEFAULT_OWN_IDENTITY_SERVER_ID: &str = "vta-host";

/// What a VTA's own `did:webs` is minted from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OwnWebsIdentity {
    /// The did-hosting server's DID (`did:webvh:…`).
    pub server_did: String,
    /// The id the server is registered under ([`DEFAULT_OWN_IDENTITY_SERVER_ID`]).
    pub server_id: String,
    /// The domain the host serves the DID on.
    pub domain: String,
    /// Slot path before the AID, `/`-separated; `None` for the domain's top.
    pub path: Option<String>,
    /// Services designated beside `#didcomm`, as JSON entries
    /// ([`crate::operations::protocol::document::vta_additional_services`]):
    /// `#tsp` and the REST entry.
    pub additional_services: Vec<serde_json::Value>,
    /// Designate `#didcomm` through this VTA's mediator.
    pub add_mediator_service: bool,
    /// Who the audit row names as minting it (`cli:setup`, `tee:first-boot`).
    pub actor: String,
}

impl OwnWebsIdentity {
    pub fn new(
        server_did: impl Into<String>,
        domain: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            server_did: server_did.into(),
            server_id: DEFAULT_OWN_IDENTITY_SERVER_ID.to_string(),
            domain: domain.into(),
            path: None,
            additional_services: Vec::new(),
            add_mediator_service: false,
            actor: actor.into(),
        }
    }
}

/// Mint this VTA's own `did:webs`: register its hosting server, create the
/// `vta` context if it is missing, and create the key-role identity there,
/// unpublished, as the context's primary DID (VTI-KEY-192, `did_class`
/// `service`).
///
/// # Errors
/// `Conflict` when this VTA already has an identity; otherwise what
/// [`super::create_did_webs`] refuses (`methodDisabled` without `[dids]
/// webs_enabled`, a bad path, …).
pub async fn create_own_identity(
    deps: &WebsDeps<'_>,
    spec: OwnWebsIdentity,
    channel: &str,
) -> Result<CreateDidWebsResult, WebsError> {
    if let Some(did) = deps.config.vta_did.as_deref() {
        return Err(AppError::Conflict(format!(
            "this VTA already has an identity ({did}); its own did:webs is minted only before it has one"
        ))
        .into());
    }
    let ctx = match crate::contexts::get_context(deps.contexts_ks, OWN_IDENTITY_CONTEXT).await? {
        Some(ctx) => ctx,
        None => crate::contexts::create_context(
            deps.contexts_ks,
            OWN_IDENTITY_CONTEXT,
            "Verifiable Trust Agent",
        )
        .await
        .map_err(|e| AppError::Internal(format!("create the vta context: {e}")))?,
    };
    if let Some(did) = ctx.did.as_deref() {
        return Err(AppError::Conflict(format!(
            "the vta context already holds this VTA's identity ({did})"
        ))
        .into());
    }

    let now = chrono::Utc::now();
    crate::webvh_store::store_server(
        deps.webvh_ks,
        &vta_sdk::webvh::WebvhServerRecord {
            id: spec.server_id.clone(),
            did: spec.server_did.clone(),
            label: Some("this VTA's did:webs host".into()),
            created_at: now,
            updated_at: now,
        },
    )
    .await?;

    let mut params = CreateDidWebsParams::new(OWN_IDENTITY_CONTEXT, &spec.server_id);
    params.path = spec.path.clone();
    params.domain = Some(spec.domain.clone());
    params.label = Some("VTA".into());
    params.add_mediator_service = spec.add_mediator_service;
    // `additional_services` carries `#tsp` and the REST entry.
    params.add_tsp_service = Some(false);
    params.additional_services = spec
        .additional_services
        .iter()
        .map(designated_service_from_json)
        .collect::<Result<_, _>>()?;
    params.set_primary = true;
    params.key_roles = true;
    params.defer_publish = true;
    params.did_class = Some(WebsDidClass::Service);
    mint(
        deps,
        Minter::FirstBoot { actor: &spec.actor },
        params,
        &NoHost,
        channel,
    )
    .await
}

/// The own identity a create left behind without finishing: the key-role
/// `service` record of the `vta` context, minted (`defer_publish`) but never
/// adopted as this VTA's DID — a boot that died between the create and
/// persisting the DID. Adopting it, rather than minting another, keeps one
/// identity per VTA (R2.1).
///
/// # Errors
/// A store failure.
pub async fn own_identity_in_progress(
    webs_ks: &crate::store::KeyspaceHandle,
) -> Result<Option<String>, AppError> {
    let mut candidates = webs_store::list_by_context(webs_ks, OWN_IDENTITY_CONTEXT)
        .await?
        .into_iter()
        .filter(|r| {
            r.did_class == Some(WebsDidClass::Service)
                && r.operational_key_id.is_some()
                && !r.deactivated
        });
    match (candidates.next(), candidates.next()) {
        (Some(record), None) => Ok(Some(record.did)),
        (None, _) => Ok(None),
        (Some(first), Some(second)) => Err(AppError::Conflict(format!(
            "the vta context holds more than one did:webs identity ({}, {}): which is this \
             VTA's cannot be told; restore from a backup or wipe the store",
            first.did, second.did
        ))),
    }
}
