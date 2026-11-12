//! Runtime service management for a `did:webs` VTA (alpha, VTI-KEY-001;
//! `docs/05-design-notes/did-webs-in-the-vta.md` §4, S6).
//!
//! The service ops patch a JSON document and publish it, whatever the method.
//! For a `did:webs` the document is not written: it is derived from the key
//! event stream the VTA stores, and its services are the AID's *designated
//! services*. So here:
//!
//! - **Load** derives the current document from the stored stream, exactly as
//!   a resolver does (and as `self_keys::own_document` does).
//! - **Publish** reads the patched document's whole `service` array as the
//!   designated service set, and replaces the designation with it
//!   (`update_did_webs`, which signs interaction events, publishes the stream
//!   to the host first and commits after — R2.1). Services KERI's own endpoint
//!   data supplies are not designations, and are left to it.
//!
//! **Order.** The resolver renders KERI's endpoint services first, then the
//! designated services in the order the designation lists them. The patchers
//! sort `service[]` canonically (TSP > DIDComm > REST > WebAuthn, then the
//! rest in their order) and the designation keeps that order, so the
//! published document is in canonical order unless the AID also has KERI
//! endpoint replies, which this VTA never writes for itself.
//!
//! **The DIDComm id.** A `did:webs` designates DIDComm as `#didcomm` (the
//! emitted convention); the protocol layer names the VTA's DIDComm service
//! `#vta-didcomm`. Peers match on `type`, so the name is cosmetic, but two
//! managers of one document must agree on it: load presents a designated
//! `#didcomm` to the patchers as `#vta-didcomm`, and publish designates it as
//! `#didcomm` again. A DIDComm service enabled here is so designated too.

use affinidi_did_webs::{DidWebs, Kels, designated_services, resolve_from_artifacts};
use serde_json::Value;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webs::{
    DIDCOMM_FRAGMENT, UpdateDidWebsParams, WebsDeps, WebsError, WebsHost, WebsRefusal,
    WebsServices, designated_service_from_json, update_did_webs, version_id,
};
use crate::operations::did_webvh::UpdateDidWebvhError;
use crate::operations::protocol::document::DIDCOMM_SERVICE_FRAGMENT;
use crate::store::KeyspaceHandle;
use crate::webs_store::{self, WebsDidRecord};
use crate::webvh_host::RequestUriResponse;

use super::OwnWebsHost;
use super::ServiceOpDeps;
use super::preconditions::{ProtocolPreconditionError, VtaDocBacking, VtaDocState};
use super::service_lifecycle::PublishedPatch;

/// The current document of `vta_did`, from its record in `webs_ks`.
pub(crate) async fn load(
    webs_ks: &KeyspaceHandle,
    vta_did: String,
) -> Result<VtaDocState, ProtocolPreconditionError> {
    let record = webs_store::get(webs_ks, &vta_did)
        .await?
        .ok_or_else(|| ProtocolPreconditionError::VtaDidRecordMissing(vta_did.clone()))?;
    // Nothing is published over an identity its host does not serve yet: the
    // first publication is the self-certifying registration first boot makes
    // (`server::publish_own_webs_identity`), and an ordinary publish in its
    // place would leave the record saying it is still to come.
    if !record.published {
        return Err(ProtocolPreconditionError::VtaDidNotPublished(vta_did));
    }
    let current_doc = protocol_view(
        render(&record).map_err(ProtocolPreconditionError::DocumentParse)?,
        &vta_did,
    );
    Ok(VtaDocState {
        vta_did,
        current_doc,
        backing: VtaDocBacking::Webs {
            record: Box::new(record),
        },
    })
}

/// The current document of the `did:webs` `did` held in `webs_ks`, as the
/// service ops read it, published or not. `None` when no record is held.
pub(crate) async fn current_document(
    webs_ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<Value>, String> {
    let Some(record) = webs_store::get(webs_ks, did)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    Ok(Some(protocol_view(render(&record)?, did)))
}

/// The document a resolver derives from `record`'s stream.
fn render(record: &WebsDidRecord) -> Result<Value, String> {
    let did = DidWebs::parse(&record.did).map_err(|e| format!("{}: {e}", record.did))?;
    let document = resolve_from_artifacts(&did, &record.keri_cesr, None)
        .map_err(|e| format!("derive the document of {}: {e}", record.did))?;
    serde_json::to_value(&document).map_err(|e| e.to_string())
}

fn fragment_of<'a>(id: &'a str, did: &str) -> Option<&'a str> {
    if id.starts_with('#') {
        return Some(id);
    }
    id.strip_prefix(did).filter(|f| f.starts_with('#'))
}

fn has_fragment(services: &[Value], did: &str, fragment: &str) -> bool {
    services.iter().any(|s| {
        s.get("id")
            .and_then(Value::as_str)
            .and_then(|id| fragment_of(id, did))
            == Some(fragment)
    })
}

/// `document` with its designated `#didcomm` named `#vta-didcomm`, the id the
/// protocol patchers find the VTA's DIDComm service by (module docs).
fn protocol_view(mut document: Value, did: &str) -> Value {
    let Some(services) = document.get_mut("service").and_then(Value::as_array_mut) else {
        return document;
    };
    if has_fragment(services, did, DIDCOMM_SERVICE_FRAGMENT) {
        return document;
    }
    for service in services.iter_mut() {
        let is_didcomm = service
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| fragment_of(id, did))
            == Some(DIDCOMM_FRAGMENT);
        if is_didcomm {
            service["id"] = Value::String(format!("{did}{DIDCOMM_SERVICE_FRAGMENT}"));
        }
    }
    document
}

/// The designated service set `patched` asks for, in its order: every
/// `service` entry but those KERI's endpoint data supplies (`derived`), each
/// under its relative id, the protocol layer's `#vta-didcomm` designated as
/// `#didcomm` again.
fn designation_of(
    patched: &Value,
    did: &str,
    derived: &[String],
) -> Result<Vec<affinidi_did_webs::DesignatedService>, UpdateDidWebvhError> {
    let services: &[Value] = patched
        .get("service")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let rename_didcomm = !has_fragment(services, did, DIDCOMM_FRAGMENT);
    let mut out = Vec::with_capacity(services.len());
    for service in services {
        let id = service.get("id").and_then(Value::as_str).ok_or_else(|| {
            UpdateDidWebvhError::InvalidDocument(format!("a service has no id: {service}"))
        })?;
        let fragment = fragment_of(id, did).ok_or_else(|| {
            UpdateDidWebvhError::InvalidDocument(format!(
                "service {id} is not a service of {did}; a did:webs designates only its own"
            ))
        })?;
        if derived.iter().any(|d| d == fragment) {
            continue;
        }
        let fragment = if rename_didcomm && fragment == DIDCOMM_SERVICE_FRAGMENT {
            DIDCOMM_FRAGMENT
        } else {
            fragment
        };
        let mut entry = service.clone();
        entry["id"] = Value::String(fragment.to_string());
        out.push(
            designated_service_from_json(&entry)
                .map_err(|e| UpdateDidWebvhError::InvalidDocument(e.to_string()))?,
        );
    }
    Ok(out)
}

/// Ids of services the rendered document of `record` carries that its AID has
/// not designated: KERI's role and witness endpoints, a delegator's service.
fn derived_service_fragments(record: &WebsDidRecord) -> Result<Vec<String>, UpdateDidWebvhError> {
    let library = |e: String| UpdateDidWebvhError::Library(e);
    let kels = Kels::parse(&record.keri_cesr).map_err(|e| library(e.to_string()))?;
    let designated = designated_services(&kels, &record.aid)
        .map_err(|e| library(e.to_string()))?
        .services;
    let rendered = render(record).map_err(library)?;
    let mut out = Vec::new();
    for s in rendered
        .get("service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(fragment) = s
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| fragment_of(id, &record.did))
        else {
            continue;
        };
        if !designated
            .iter()
            .any(|d| d.get("id").and_then(Value::as_str) == Some(fragment))
        {
            out.push(fragment.to_string());
        }
    }
    Ok(out)
}

/// A `did:webs` operation's error as the service ops carry it: in the same
/// `UpdateDidWebvhError` variants a `did:webvh` publish fails with, so every
/// op's error type, route mapping and operator guidance stay as they are.
fn as_publish_error(e: WebsError) -> UpdateDidWebvhError {
    match e {
        WebsError::Refused(kind, message) | WebsError::RefusedWith(kind, message, _) => {
            match kind {
                WebsRefusal::NotFound => UpdateDidWebvhError::NotFound(message),
                WebsRefusal::VersionConflict => UpdateDidWebvhError::Conflict(message),
                WebsRefusal::ServiceIdConflict => UpdateDidWebvhError::InvalidDocument(message),
                WebsRefusal::PublishRefused
                | WebsRefusal::HostDoesNotHostWebs
                | WebsRefusal::DomainNotServed
                | WebsRefusal::PathRefused
                | WebsRefusal::ServerNotFound => {
                    UpdateDidWebvhError::Publish(format!("publish_did: {message}"))
                }
                _ => UpdateDidWebvhError::Rejected(message),
            }
        }
        WebsError::App(AppError::Forbidden(m)) => UpdateDidWebvhError::Forbidden(m),
        WebsError::App(e) => UpdateDidWebvhError::publish_failed("publish_did", e),
    }
}

/// An [`OwnWebsHost`] as a [`WebsHost`].
struct Lent<'a>(&'a dyn OwnWebsHost);

impl WebsHost for Lent<'_> {
    async fn resolve_domain(&self, requested: Option<&str>) -> Result<String, AppError> {
        self.0.resolve_domain_boxed(requested).await
    }

    async fn publish(
        &self,
        mnemonic: &str,
        keri_cesr: &str,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        self.0.publish_stream(mnemonic, keri_cesr, domain).await
    }

    async fn delete(&self, mnemonic: &str, domain: Option<&str>) -> Result<(), AppError> {
        self.0.delete_slot(mnemonic, domain).await
    }
}

impl<T: WebsHost + Send + Sync> OwnWebsHost for T {
    fn publish_stream<'a>(
        &'a self,
        mnemonic: &'a str,
        keri_cesr: &'a str,
        domain: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<RequestUriResponse, AppError>> + Send + 'a>>
    {
        Box::pin(self.publish(mnemonic, keri_cesr, domain))
    }

    fn resolve_domain_boxed<'a>(
        &'a self,
        requested: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<String, AppError>> + Send + 'a>> {
        Box::pin(self.resolve_domain(requested))
    }

    fn delete_slot<'a>(
        &'a self,
        mnemonic: &'a str,
        domain: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(self.delete(mnemonic, domain))
    }
}

/// Designate `patched`'s service set as `vta_did`'s, publish the stream to its
/// host, and reseed this VTA's resolver with the document it now derives.
pub(crate) async fn publish(
    deps: &ServiceOpDeps<'_>,
    auth: &AuthClaims,
    record: &WebsDidRecord,
    vta_did: &str,
    patched: &Value,
    channel: &str,
) -> Result<PublishedPatch, UpdateDidWebvhError> {
    let derived = derived_service_fragments(record)?;
    let additional = designation_of(patched, vta_did, &derived)?;

    let mut params = UpdateDidWebsParams::new(vta_did);
    // The whole set, in the patched order: nothing is added for the mediator
    // here, since the patched document already says what it routes through.
    params.services = Some(WebsServices::new(false, false, additional));

    let config = deps.config.read().await.clone();
    let webs_deps = WebsDeps {
        keys_ks: deps.keys_ks,
        contexts_ks: deps.contexts_ks,
        webvh_ks: deps.webvh_ks,
        webs_ks: deps.webs_ks,
        // No key is minted: only the designation changes.
        acl_ks: None,
        audit: deps.audit,
        seed_store: deps.seed_store,
        config: &config,
        did_resolver: deps.did_resolver,
        // An update renders no template.
        did_templates_ks: None,
    };

    let updated = match deps.webs_host {
        Some(host) => update_did_webs(&webs_deps, auth, params, &Lent(host), channel).await,
        None => {
            let server = crate::webvh_store::get_server(deps.webvh_ks, &record.server_id)
                .await
                .map_err(|e| UpdateDidWebvhError::Persistence(e.to_string()))?
                .ok_or_else(|| {
                    UpdateDidWebvhError::Publish(format!(
                        "publish_did: this VTA's did:webs names hosting server `{}`, which is \
                         not registered (`pnm webvh add-server`)",
                        record.server_id
                    ))
                })?;
            let webvh = deps.webvh();
            let host = crate::operations::did_webvh::host::host_client(&webvh, vta_did, &server)
                .await
                .map_err(|e| UpdateDidWebvhError::publish_failed("publish_did", e))?;
            update_did_webs(&webs_deps, auth, params, &host, channel).await
        }
    };

    let new_version_id = match updated {
        Ok(result) => result.version_id,
        // The designation already is the patched set (an enable over a
        // service the document already advertises, say): nothing to publish,
        // and the version is the one in force.
        Err(WebsError::Refused(WebsRefusal::NoChange, _)) => {
            let current = webs_store::get(deps.webs_ks, vta_did)
                .await
                .map_err(|e| UpdateDidWebvhError::Persistence(e.to_string()))?
                .ok_or_else(|| UpdateDidWebvhError::NotFound(vta_did.to_string()))?;
            version_id(&current.state)
        }
        Err(e) => return Err(as_publish_error(e)),
    };

    // `update_did_webs` does not touch the resolver; this VTA resolves itself
    // from its own stream, so reseed its cache entry now, as the webvh path
    // does from its log.
    let mut resolver = deps.did_resolver.clone();
    crate::server::preload_self_did_document(
        &mut resolver,
        vta_did,
        Some(deps.webvh_ks),
        Some(deps.webs_ks),
    )
    .await;

    Ok(PublishedPatch {
        new_version_id,
        serverless: false,
    })
}
