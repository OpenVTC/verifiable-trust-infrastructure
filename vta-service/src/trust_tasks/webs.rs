//! The `did:webs` lifecycle: `vta/webs/dids/{create,get,list,update,rotate-keys,delete}/0.1`
//! (trustoverip/dtgwg-trust-tasks-tf#1082; design note
//! `docs/05-design-notes/did-webs-in-the-vta.md`).
//!
//! **Feature-gated** — requires `webs`, which requires `webvh`: a `did:webs` is
//! published through the same did-hosting servers, by `did/register/0.1` with
//! `method: "webs"`.
//!
//! The engine is [`crate::operations::did_webs`]; this slice parses each payload
//! against its generated type, calls it, and renders the answer through the
//! task's generated response type, so a response that drifts from its schema
//! fails here rather than at a consumer. Every refusal the engine declares
//! ([`WebsRefusal`]) is answered with the code the task declares for it.
//!
//! | URI | Gate |
//! |---|---|
//! | `create` | `key-mint`, in the context (as `webvh/dids/create`) |
//! | `get`, `list` | access to the DID's context |
//! | `update`, `rotate-keys`, `delete` | admin, in the DID's context (as webvh's) |
//!
//! `did:webs` is for persona, relationship and integration DIDs: never a node's
//! service identity (VTI-KEY-001), which `create` refuses as
//! `serviceDidNotPermitted`.

#![cfg(feature = "webs")]

use affinidi_did_webs::{DesignatedService, Kels, designated_aliases, designated_services};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::{DeclaredErrorCode, RejectReason, TrustTask};
use vti_specs::vta::webs::dids as spec;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations::did_webs::{
    self as engine, CreateDidWebsParams, UpdateDidWebsParams, WebsDeps, WebsError, WebsRefusal,
    WebsServices,
};
use crate::server::AppState;
use crate::webs_store::{self, WebsDidRecord};
use crate::webvh_host::WebvhHostClient;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, success_response,
};

// ─── Refusals ──────────────────────────────────────────────────────────

/// The code each task declares for each refusal it can meet. `None` is a
/// refusal the task cannot reach.
#[derive(Default)]
struct Codes {
    method_disabled: Option<DeclaredErrorCode>,
    server_not_found: Option<DeclaredErrorCode>,
    host_does_not_host_webs: Option<DeclaredErrorCode>,
    domain_not_served: Option<DeclaredErrorCode>,
    path_refused: Option<DeclaredErrorCode>,
    service_did_not_permitted: Option<DeclaredErrorCode>,
    not_found: Option<DeclaredErrorCode>,
    version_conflict: Option<DeclaredErrorCode>,
    no_change: Option<DeclaredErrorCode>,
    service_id_conflict: Option<DeclaredErrorCode>,
    deactivated: Option<DeclaredErrorCode>,
    publish_refused: Option<DeclaredErrorCode>,
}

impl Codes {
    fn of(&self, kind: WebsRefusal) -> Option<DeclaredErrorCode> {
        match kind {
            WebsRefusal::MethodDisabled => self.method_disabled,
            WebsRefusal::ServerNotFound => self.server_not_found,
            WebsRefusal::HostDoesNotHostWebs => self.host_does_not_host_webs,
            WebsRefusal::DomainNotServed => self.domain_not_served,
            WebsRefusal::PathRefused => self.path_refused,
            WebsRefusal::ServiceDidNotPermitted => self.service_did_not_permitted,
            WebsRefusal::NotFound => self.not_found,
            WebsRefusal::VersionConflict => self.version_conflict,
            WebsRefusal::NoChange => self.no_change,
            WebsRefusal::ServiceIdConflict => self.service_id_conflict,
            WebsRefusal::Deactivated => self.deactivated,
            WebsRefusal::PublishRefused => self.publish_refused,
        }
    }
}

/// Answer a refusal with the code the task declares, or, for anything that is
/// not a declared refusal, the framework's code for the underlying error.
fn refuse(doc: &TrustTask<Value>, e: WebsError, codes: &Codes) -> TrustTaskOutcome {
    match e {
        WebsError::App(e) => app_error_to_reject(doc, e),
        WebsError::Refused(kind, message) => match codes.of(kind) {
            Some(code) => reject_declared(doc, code, message),
            // A refusal the task declares no code for is a defect in this
            // slice: say so rather than invent a code no consumer can look up.
            None => reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!(
                        "{} has no code for this refusal ({kind:?}): {message}",
                        doc.type_uri
                    ),
                },
            ),
        },
    }
}

/// Answer with `value` rendered through the task's generated response type.
fn respond<R: DeserializeOwned + Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn bool_of(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

fn strings_of(v: &Value, key: &str) -> Option<Vec<String>> {
    v.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

// ─── The host ──────────────────────────────────────────────────────────

/// The did-hosting client for server `server_id`, issuing as this VTA.
async fn host_for<'a>(
    state: &'a AppState,
    did_resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    server_id: &str,
) -> Result<WebvhHostClient<'a>, WebsError> {
    let server = crate::webvh_store::get_server(&state.webvh_ks, server_id)
        .await?
        .ok_or_else(|| {
            WebsError::refused(
                WebsRefusal::ServerNotFound,
                format!("hosting server not found: {server_id}"),
            )
        })?;
    let vta_did = state.config.read().await.vta_did.clone().ok_or_else(|| {
        AppError::Validation(
            "vta_did is not configured; the VTA needs its own DID to sign what it sends a \
             hosting server (set `vta_did` in config / VTA_DID)"
                .into(),
        )
    })?;
    let deps = crate::operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    Ok(crate::operations::did_webvh::host::host_client(&deps, &vta_did, &server).await?)
}

fn resolver(
    state: &AppState,
) -> Result<&affinidi_did_resolver_cache_sdk::DIDCacheClient, WebsError> {
    state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()).into())
}

type Resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient;

/// Where a write's host comes from: the registered did-hosting server, or, in
/// tests, a recording fake.
trait HostSource: Sync {
    type Host: engine::WebsHost + Send + Sync;

    fn host(
        &self,
        server_id: &str,
    ) -> impl std::future::Future<Output = Result<Self::Host, WebsError>> + Send;
}

/// The did-hosting servers this VTA has registered.
struct RegisteredHosts<'a> {
    state: &'a AppState,
    resolver: &'a Resolver,
}

impl<'a> HostSource for RegisteredHosts<'a> {
    type Host = WebvhHostClient<'a>;

    fn host(
        &self,
        server_id: &str,
    ) -> impl std::future::Future<Output = Result<WebvhHostClient<'a>, WebsError>> + Send {
        host_for(self.state, self.resolver, server_id)
    }
}

/// The registered hosts, or the refusal when there is no resolver to reach
/// them with.
#[allow(clippy::result_large_err)]
fn registered_hosts<'a>(
    state: &'a AppState,
    doc: &TrustTask<Value>,
) -> Result<RegisteredHosts<'a>, TrustTaskOutcome> {
    resolver(state)
        .map(|resolver| RegisteredHosts { state, resolver })
        .map_err(|e| refuse(doc, e, &Codes::default()))
}

// ─── Rendering ─────────────────────────────────────────────────────────

/// The fragment of a key id `<did>#<cesr>`: the key itself, in CESR.
fn fragment(key_id: &str) -> &str {
    key_id.rsplit_once('#').map_or("", |(_, f)| f)
}

/// What the stream designates: the aliases (the DID first) and the services.
fn designations(record: &WebsDidRecord) -> Result<(Vec<String>, Vec<Value>), WebsError> {
    let kels = Kels::parse(&record.keri_cesr)
        .map_err(|e| AppError::Internal(format!("read the stream of {}: {e}", record.did)))?;
    let aliases = designated_aliases(&kels, &record.aid)
        .map_err(|e| AppError::Internal(format!("read the aliases of {}: {e}", record.did)))?
        .aliases;
    let services = designated_services(&kels, &record.aid)
        .map_err(|e| AppError::Internal(format!("read the services of {}: {e}", record.did)))?
        .services;
    Ok((aliases, services))
}

fn service_ids(services: &[Value]) -> Vec<String> {
    services
        .iter()
        .filter_map(|s| str_of(s, "id"))
        .map(str::to_string)
        .collect()
}

/// A record as `WebsDidRecord` (`vta/webs/_shared/0.1/webs-records.schema.json`).
async fn record_json(state: &AppState, record: &WebsDidRecord) -> Result<Value, WebsError> {
    let (aliases, services) = designations(record)?;
    let domain = record.domain.clone().unwrap_or_default();
    let primary = crate::contexts::get_context(&state.contexts_ks, &record.context_id)
        .await?
        .is_some_and(|c| c.did.as_deref() == Some(record.did.as_str()));
    let mut v = json!({
        "did": record.did,
        "aid": record.aid,
        "contextId": record.context_id,
        "serverId": record.server_id,
        "domain": domain,
        "slot": record.mnemonic,
        "keriCesrUrl": format!("https://{domain}/{}/keri.cesr", record.mnemonic),
        "didJsonUrl": format!("https://{domain}/{}/did.json", record.mnemonic),
        "sequenceNumber": record.state.sn,
        "versionId": engine::version_id(&record.state),
        "signingKeyId": record.signing_key_id,
        "signingKey": record.state.keys.first().cloned().unwrap_or_default(),
        "keyAgreementKeyId": record.key_agreement_key_id,
        "keyAgreementKey": fragment(&record.key_agreement_key_id),
        "alsoKnownAs": aliases,
        "services": services,
        "deactivated": record.deactivated,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
        "primary": primary,
    });
    if !record.deactivated {
        v["nextKeyId"] = json!(record.next_key_id);
    } else {
        // The record keeps no separate timestamp for the deactivation: it is
        // the last write, so `updatedAt` is when it was committed.
        v["deactivatedAt"] = json!(record.updated_at);
    }
    if let Some(label) = &record.label {
        v["label"] = json!(label);
    }
    Ok(v)
}

async fn stored(state: &AppState, did: &str) -> Result<WebsDidRecord, WebsError> {
    Ok(webs_store::get(&state.webs_ks, did)
        .await?
        .ok_or_else(|| AppError::Internal(format!("{did} was written but is not in the store")))?)
}

/// Services as the payload states them (`DesignatedService`).
fn designated(v: &Value) -> Option<DesignatedService> {
    let id = str_of(v, "id")?;
    let mut service = DesignatedService::new(id, "", v.get("serviceEndpoint")?.clone());
    service.type_ = v.get("type")?.clone();
    if let Some(map) = v.as_object() {
        for (k, val) in map {
            if !matches!(k.as_str(), "id" | "type" | "serviceEndpoint") {
                service.properties.insert(k.clone(), val.clone());
            }
        }
    }
    Some(service)
}

fn designated_list(v: Option<&Value>) -> Vec<DesignatedService> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(designated).collect())
        .unwrap_or_default()
}

/// `#didcomm` and `#tsp` are the VTA's own, set by the flags; an additional
/// service may not take either id.
fn reserved_ids(additional: &[DesignatedService]) -> Result<(), WebsError> {
    match additional
        .iter()
        .find(|s| s.id == engine::DIDCOMM_FRAGMENT || s.id == "#tsp")
    {
        Some(s) => Err(WebsError::refused(
            WebsRefusal::ServiceIdConflict,
            format!(
                "serviceIdConflict: {} is the VTA's own service id; set it with \
                 `addMediatorService` / `addTspService` (or `mediator` / `tsp`)",
                s.id
            ),
        )),
        None => Ok(()),
    }
}

// ─── Handlers ──────────────────────────────────────────────────────────

/// `vta/webs/dids/create/0.1`.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::create::v0_1 as t;
    let codes = Codes {
        method_disabled: Some(t::error_codes::METHOD_DISABLED),
        server_not_found: Some(t::error_codes::SERVER_NOT_FOUND),
        host_does_not_host_webs: Some(t::error_codes::HOST_DOES_NOT_HOST_WEBS),
        domain_not_served: Some(t::error_codes::DOMAIN_NOT_SERVED),
        path_refused: Some(t::error_codes::PATH_REFUSED),
        service_did_not_permitted: Some(t::error_codes::SERVICE_DID_NOT_PERMITTED),
        service_id_conflict: Some(t::error_codes::SERVICE_ID_CONFLICT),
        publish_refused: Some(t::error_codes::PUBLISH_REFUSED),
        ..Codes::default()
    };
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let hosts = match registered_hosts(state, &doc) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match create(state, auth, &doc.payload, hosts.resolver, &hosts).await {
        Ok(v) => respond::<t::Response>(&doc, v),
        Err(e) => refuse(&doc, e, &codes),
    }
}

async fn create(
    state: &AppState,
    auth: &AuthClaims,
    p: &Value,
    did_resolver: &Resolver,
    hosts: &impl HostSource,
) -> Result<Value, WebsError> {
    let server_id = str_of(p, "serverId").unwrap_or_default();
    let additional = designated_list(p.get("additionalServices"));
    reserved_ids(&additional)?;
    let mut params =
        CreateDidWebsParams::new(str_of(p, "contextId").unwrap_or_default(), server_id);
    params.path = str_of(p, "path").map(str::to_string);
    params.domain = str_of(p, "domain").map(str::to_string);
    params.label = str_of(p, "label").map(str::to_string);
    params.add_mediator_service = bool_of(p, "addMediatorService").unwrap_or(false);
    params.add_tsp_service = bool_of(p, "addTspService");
    params.also_known_as = strings_of(p, "alsoKnownAs").unwrap_or_default();
    params.set_primary = bool_of(p, "setPrimary").unwrap_or(false);
    params.additional_services = additional;
    let set_primary = params.set_primary;

    let host = hosts.host(server_id).await?;
    let config = state.config.read().await;
    let deps = WebsDeps::from_app_state(state, &config, did_resolver);
    let created = engine::create_did_webs(&deps, auth, params, &host, TRANSPORT_TRUST_TASK).await?;
    drop(config);

    let record = stored(state, &created.did).await?;
    let mut v = record_json(state, &record).await?;
    let ids = service_ids(v["services"].as_array().map_or(&[][..], |a| a));
    if let Some(m) = v.as_object_mut() {
        for k in [
            "services",
            "deactivated",
            "updatedAt",
            "label",
            "deactivatedAt",
        ] {
            m.remove(k);
        }
        m.insert("nextKeyId".into(), json!(created.next_key_id));
        if ids.is_empty() {
            m.remove("serviceIds");
        } else {
            m.insert("serviceIds".into(), json!(ids));
        }
        if set_primary {
            m.insert("primary".into(), json!(true));
        } else {
            m.remove("primary");
        }
    }
    Ok(v)
}

/// `vta/webs/dids/get/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::get::v0_1 as t;
    let codes = Codes {
        not_found: Some(t::error_codes::NOT_FOUND),
        ..Codes::default()
    };
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let did = str_of(p, "did").unwrap_or_default();
    let result = async {
        let record = engine::get_did_webs(&state.webs_ks, auth, did)
            .await
            .map_err(|e| match e {
                AppError::NotFound(m) => WebsError::refused(WebsRefusal::NotFound, m),
                e => e.into(),
            })?;
        let mut v = json!({ "record": record_json(state, &record).await? });
        if bool_of(p, "includeKeriCesr") == Some(true) {
            v["keriCesr"] = json!(String::from_utf8_lossy(&record.keri_cesr));
        }
        if record.staged.is_some() {
            v["rotationStaged"] = json!(true);
        }
        Ok::<_, WebsError>(v)
    }
    .await;
    match result {
        Ok(v) => respond::<t::Response>(&doc, v),
        Err(e) => refuse(&doc, e, &codes),
    }
}

/// The page size `list` uses when the caller names none.
const DEFAULT_LIST_LIMIT: usize = 100;

/// `vta/webs/dids/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let result = async {
        let mut records = match str_of(p, "contextId") {
            Some(ctx) => engine::list_did_webs(&state.webs_ks, auth, ctx).await?,
            None => webs_store::list(&state.webs_ks)
                .await?
                .into_iter()
                .filter(|r| auth.has_context_access(&r.context_id))
                .collect(),
        };
        if let Some(server) = str_of(p, "serverId") {
            records.retain(|r| r.server_id == server);
        }
        if bool_of(p, "includeDeactivated") != Some(true) {
            records.retain(|r| !r.deactivated);
        }
        records.sort_by(|a, b| a.did.cmp(&b.did));
        // The cursor is the last DID of the page before, as this VTA wrote it.
        if let Some(cursor) = str_of(p, "cursor") {
            let after = cursor_did(cursor).ok_or_else(|| {
                AppError::Validation("the cursor is not one this VTA issued".into())
            })?;
            records.retain(|r| r.did.as_str() > after.as_str());
        }
        let limit = p
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(DEFAULT_LIST_LIMIT, |l| l as usize);
        let more = records.len() > limit;
        records.truncate(limit);
        let mut dids = Vec::with_capacity(records.len());
        for r in &records {
            dids.push(record_json(state, r).await?);
        }
        let mut v = json!({ "dids": dids });
        if more && let Some(last) = records.last() {
            v["nextCursor"] = json!(issue_cursor(&last.did));
        }
        Ok::<_, WebsError>(v)
    }
    .await;
    match result {
        Ok(v) => respond::<t::Response>(&doc, v),
        Err(e) => refuse(&doc, e, &Codes::default()),
    }
}

const CURSOR_PREFIX: &str = "webs-after:";

fn issue_cursor(did: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{CURSOR_PREFIX}{did}"))
}

fn cursor_did(cursor: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    String::from_utf8(bytes)
        .ok()?
        .strip_prefix(CURSOR_PREFIX)
        .filter(|d| d.starts_with("did:webs:"))
        .map(str::to_string)
}

/// The record of `did`, for the host it lives on, refusing as `notFound` what
/// the caller cannot reach.
async fn reachable(
    state: &AppState,
    auth: &AuthClaims,
    did: &str,
) -> Result<WebsDidRecord, WebsError> {
    engine::get_did_webs(&state.webs_ks, auth, did)
        .await
        .map_err(|e| match e {
            AppError::NotFound(m) => WebsError::refused(WebsRefusal::NotFound, m),
            e => e.into(),
        })
}

/// `vta/webs/dids/update/0.1`.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::update::v0_1 as t;
    let codes = Codes {
        not_found: Some(t::error_codes::NOT_FOUND),
        version_conflict: Some(t::error_codes::VERSION_CONFLICT),
        no_change: Some(t::error_codes::NO_CHANGE),
        service_id_conflict: Some(t::error_codes::SERVICE_ID_CONFLICT),
        deactivated: Some(t::error_codes::DEACTIVATED),
        publish_refused: Some(t::error_codes::PUBLISH_REFUSED),
        ..Codes::default()
    };
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let hosts = match registered_hosts(state, &doc) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match update(state, auth, &doc.payload, hosts.resolver, &hosts).await {
        Ok(v) => respond::<t::Response>(&doc, v),
        Err(e) => refuse(&doc, e, &codes),
    }
}

async fn update(
    state: &AppState,
    auth: &AuthClaims,
    p: &Value,
    did_resolver: &Resolver,
    hosts: &impl HostSource,
) -> Result<Value, WebsError> {
    let did = str_of(p, "did").unwrap_or_default();
    let record = reachable(state, auth, did).await?;

    let mut params = UpdateDidWebsParams::new(did);
    if let Some(s) = p.get("services") {
        let additional = designated_list(s.get("additional"));
        reserved_ids(&additional)?;
        params.services = Some(WebsServices::new(
            bool_of(s, "mediator").unwrap_or(false),
            bool_of(s, "tsp").unwrap_or(false),
            additional,
        ));
    }
    params.rotate_key_agreement_key = bool_of(p, "rotateKeyAgreementKey").unwrap_or(false);
    params.also_known_as = strings_of(p, "alsoKnownAs");
    params.expected_version_id = str_of(p, "expectedVersionId").map(str::to_string);
    params.label = str_of(p, "label").map(str::to_string);

    let host = hosts.host(&record.server_id).await?;
    let config = state.config.read().await;
    let deps = WebsDeps::from_app_state(state, &config, did_resolver);
    let updated = engine::update_did_webs(&deps, auth, params, &host, TRANSPORT_TRUST_TASK).await?;
    drop(config);

    let record = stored(state, did).await?;
    let (aliases, services) = designations(&record)?;
    Ok(json!({
        "did": updated.did,
        "replaced": updated.replaced,
        "sequenceNumber": updated.sequence_number,
        "versionId": updated.version_id,
        "keyAgreementKeyId": record.key_agreement_key_id,
        "keyAgreementKey": fragment(&record.key_agreement_key_id),
        "alsoKnownAs": aliases,
        "serviceIds": service_ids(&services),
    }))
}

/// `vta/webs/dids/rotate-keys/0.1`.
pub(super) async fn handle_rotate_keys(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::rotate_keys::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    match registered_hosts(state, &doc) {
        Ok(hosts) => rotate_keys(state, auth, &doc, hosts.resolver, &hosts).await,
        Err(r) => r,
    }
}

async fn rotate_keys(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    did_resolver: &Resolver,
    hosts: &impl HostSource,
) -> TrustTaskOutcome {
    use spec::rotate_keys::v0_1 as t;
    let codes = Codes {
        not_found: Some(t::error_codes::NOT_FOUND),
        version_conflict: Some(t::error_codes::VERSION_CONFLICT),
        deactivated: Some(t::error_codes::DEACTIVATED),
        publish_refused: Some(t::error_codes::PUBLISH_REFUSED),
        ..Codes::default()
    };
    let p = &doc.payload;
    let result = async {
        let did = str_of(p, "did").unwrap_or_default();
        let record = reachable(state, auth, did).await?;
        let host = hosts.host(&record.server_id).await?;
        let config = state.config.read().await;
        let deps = WebsDeps::from_app_state(state, &config, did_resolver);
        let r = engine::rotate_did_webs_keys(
            &deps,
            auth,
            did,
            str_of(p, "expectedVersionId"),
            &host,
            TRANSPORT_TRUST_TASK,
        )
        .await?;
        Ok::<_, WebsError>(json!({
            "did": r.did,
            "sequenceNumber": r.sequence_number,
            "versionId": r.version_id,
            "signingKeyId": r.signing_key_id,
            "signingKey": r.signing_public_key,
            "nextKeyId": r.next_key_id,
            "retiredKeyId": r.retired_key_id,
            "resumed": r.resumed,
        }))
    }
    .await;
    match result {
        Ok(v) => respond::<t::Response>(doc, v),
        Err(e) => refuse(doc, e, &codes),
    }
}

/// `vta/webs/dids/delete/0.1`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::delete::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    match registered_hosts(state, &doc) {
        Ok(hosts) => delete(state, auth, &doc, hosts.resolver, &hosts).await,
        Err(r) => r,
    }
}

async fn delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    did_resolver: &Resolver,
    hosts: &impl HostSource,
) -> TrustTaskOutcome {
    use spec::delete::v0_1 as t;
    let codes = Codes {
        not_found: Some(t::error_codes::NOT_FOUND),
        version_conflict: Some(t::error_codes::VERSION_CONFLICT),
        publish_refused: Some(t::error_codes::PUBLISH_REFUSED),
        ..Codes::default()
    };
    let p = &doc.payload;
    let result = async {
        let did = str_of(p, "did").unwrap_or_default();
        let record = reachable(state, auth, did).await?;
        let host = hosts.host(&record.server_id).await?;
        let config = state.config.read().await;
        let deps = WebsDeps::from_app_state(state, &config, did_resolver);
        let r = engine::delete_did_webs(
            &deps,
            auth,
            did,
            str_of(p, "expectedVersionId"),
            &host,
            TRANSPORT_TRUST_TASK,
        )
        .await?;
        let mut v = json!({
            "did": r.did,
            "deactivated": true,
            "newlyDeactivated": r.newly_deactivated,
            "versionId": r.version_id,
            "slotRemoved": r.slot_removed,
        });
        if let Some(e) = r.host_cleanup_error {
            v["hostCleanupError"] = json!(e);
        }
        Ok::<_, WebsError>(v)
    }
    .await;
    match result {
        Ok(v) => respond::<t::Response>(doc, v),
        Err(e) => refuse(doc, e, &codes),
    }
}

#[cfg(test)]
#[path = "webs_tests.rs"]
mod wire_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_and_a_foreign_one_is_refused() {
        let did = "did:webs:hosting.example:EAbc";
        assert_eq!(cursor_did(&issue_cursor(did)).as_deref(), Some(did));
        assert_eq!(cursor_did("not-a-cursor"), None);
        use base64::Engine as _;
        let forged =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("webs-after:did:key:z");
        assert_eq!(cursor_did(&forged), None);
    }

    #[test]
    fn a_key_id_fragment_is_the_key() {
        assert_eq!(fragment("did:webs:h:E1#DAbc"), "DAbc");
        assert_eq!(fragment("no-fragment"), "");
    }
}
