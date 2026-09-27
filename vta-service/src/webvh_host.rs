//! The VTA's client to a DID hosting service (`did-hosting-control`).
//!
//! Every call is a Trust Task, typed with the request and response bindings
//! `trust-tasks-rs` generates from the published `did-management/*`
//! specifications. The document goes to `operations::outbound`, which picks the
//! transport from the host's advertisement in the workspace order
//! TSP > DIDComm > HTTPS (`POST {base}/trust-tasks`). There is no other client:
//! the hosting service's REST API is not used.
//!
//! What this module owns is the did-management half:
//!
//! - **The request.** Built from the generated `Payload`, so a member the
//!   schema does not declare cannot be sent, and a value the schema refuses is
//!   refused here, before it is signed. Every document carries this VTA's proof
//!   (operational key, `proofPurpose: authentication`) with the VTA as
//!   `issuer` and the host as `recipient`.
//! - **The reply.** It must carry the host's own proof
//!   (`ReplyTrust::SignedByRecipient`), whichever transport carried it; it
//!   must answer this request (`threadId`) and be addressed to this VTA; and
//!   its payload must parse as the generated `Response`, which refuses unknown
//!   members. A `trust-task-error` document is read for its code, which maps
//!   to the status an operator can act on ([`host_refusal`]).

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::RequestPayload;
use trust_tasks_rs::specs::did_management as dm;

use crate::didcomm_bridge::DIDCommBridge;
use crate::error::{AppError, bad_gateway_error};

/// The framework's refusal document, at any version.
const TRUST_TASK_ERROR_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// The largest page `did/list/0.1` allows.
const DID_LIST_PAGE: u64 = 1000;

/// Pages [`WebvhHostClient::list_dids`] reads before it stops trusting the
/// host's `total`: 100 000 slots. A host that keeps growing its `total`, or
/// answers a full page forever, is refused rather than followed.
const DID_LIST_MAX_PAGES: u64 = 100;

/// A reserved or registered slot: where the log goes, and its identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUriResponse {
    pub did_url: String,
    pub mnemonic: String,
}

/// One slot the host holds for this VTA, as the reconcile reads it.
///
/// Only the members the reconcile needs. `did_id` is `None` for a slot that was
/// reserved and never published to, which is why the reconcile keys on
/// `mnemonic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedDidEntry {
    pub mnemonic: String,
    pub did_id: Option<String>,
    pub domain: Option<String>,
    pub disabled: bool,
}

/// The agent-name registry entry the host keeps for a DID.
pub type AgentNameEntry = dm::agent_name::list::v0_1::AgentNameEntry;

/// The host's answer to "is this agent name free on this domain?".
pub type AgentNameAvailability = dm::agent_name::check::v0_1::Response;

/// The domains the host lets this VTA mint into, and its default.
pub type HostDomains = dm::me::domains::v0_1::Response;

/// Map a `trust-task-error` code to the status an operator can act on.
///
/// Matched on the code's local part, so a spec-declared code
/// (`did-management/did/register:pathTaken`) and a framework code
/// (`permissionDenied`) are read the same way. A code this does not know is a
/// 502: the host refused for a reason this VTA cannot interpret, which is not
/// a reason the caller can fix by changing its request.
pub(crate) fn host_refusal(code: &str, message: &str) -> AppError {
    let detail = format!("the DID hosting service refused the request: {message} [{code}]");
    match code.rsplit(':').next().unwrap_or_default() {
        "notFound" => AppError::NotFound(detail),
        "notOwner" | "forbidden" | "permissionDenied" | "stepUpRequired" | "unauthorized" => {
            AppError::Forbidden(detail)
        }
        "pathTaken" | "nameTaken" | "nameReserved" | "alreadyDeleted" | "conflict" => {
            AppError::Conflict(detail)
        }
        "invalidPath"
        | "invalidLog"
        | "invalidName"
        | "invalidDidData"
        | "hostMismatch"
        | "alsoKnownAsMismatch"
        | "unknownDomain"
        | "validationError" => AppError::Validation(detail),
        _ => bad_gateway_error(detail),
    }
}

/// Build a generated request payload from JSON, refusing what its schema
/// refuses. The refusal is the caller's input, so it is a 400.
fn payload<P: DeserializeOwned>(task: &str, value: Value) -> Result<P, AppError> {
    serde_json::from_value(value)
        .map_err(|e| AppError::Validation(format!("cannot build a {task} request: {e}")))
}

/// The unsigned request document.
fn build_request_document(type_uri: &str, issuer: &str, recipient: &str, payload: Value) -> Value {
    serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": issuer,
        "recipient": recipient,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    })
}

/// Read a reply to the request `request_id` sent by `issuer`, expecting the
/// response type `expected`, into its typed payload.
///
/// The proof has already been checked by the seam. This checks the rest: a
/// reply must thread to this request; a refusal is mapped by its code; an
/// answer must be addressed to this VTA (a signed answer to someone else's
/// question is not an answer to this one), be of the type asked for, and parse
/// as the generated response.
fn read_reply<R: DeserializeOwned>(
    reply: &Value,
    request_id: &str,
    issuer: &str,
    expected: &str,
) -> Result<R, AppError> {
    let doc_type = reply
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let payload = reply.get("payload").cloned().unwrap_or(Value::Null);

    let thread = reply.get("threadId").and_then(Value::as_str);
    if thread != Some(request_id) {
        return Err(bad_gateway_error(format!(
            "the DID hosting service answered a different request (threadId {thread:?}, \
             expected {request_id})"
        )));
    }

    if doc_type.starts_with(TRUST_TASK_ERROR_PREFIX) {
        let code = payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let message = payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(host_refusal(code, message));
    }

    let recipient = reply.get("recipient").and_then(Value::as_str);
    if recipient != Some(issuer) {
        return Err(bad_gateway_error(format!(
            "the DID hosting service addressed its answer to {recipient:?}, not to this VTA"
        )));
    }

    if doc_type != expected {
        return Err(bad_gateway_error(format!(
            "unexpected response document type: expected {expected}, got {doc_type}"
        )));
    }

    serde_json::from_value(payload).map_err(|e| {
        bad_gateway_error(format!(
            "the DID hosting service's {expected} does not match its schema: {e}"
        ))
    })
}

/// A Trust-Task client to one DID hosting service.
pub struct WebvhHostClient<'a> {
    bridge: &'a DIDCommBridge,
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    server_did: String,
    /// This VTA's DID: every document's `issuer`, and the `recipient` every
    /// reply must carry.
    issuer: String,
    /// The HTTPS base derived from the host's `WebVHHosting` service, for when
    /// it advertises no `TrustTaskHTTPS` endpoint of its own.
    https_base: Option<String>,
    #[cfg(feature = "tsp")]
    tsp: Option<crate::operations::outbound::TspSender>,
}

impl<'a> WebvhHostClient<'a> {
    /// A client for `server_did`, reached as its DID document advertises.
    ///
    /// Refuses a server that advertises nothing the seam can carry a Trust
    /// Task over, naming the accepted service types.
    pub async fn for_server(
        server_did: &str,
        issuer: &str,
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
        bridge: &'a DIDCommBridge,
        #[cfg(feature = "tsp")] tsp: Option<crate::operations::outbound::TspSender>,
    ) -> Result<Self, AppError> {
        use crate::operations::did_webvh::transport;

        let resolved = resolver.resolve(server_did).await.map_err(|e| {
            AppError::Validation(format!("failed to resolve server DID {server_did}: {e}"))
        })?;
        let reach = transport::resolve_host_reach(&resolved.doc.service).ok_or_else(|| {
            AppError::Validation(format!(
                "server DID {server_did} advertises no transport this VTA can reach it on \
                 (expected: {})",
                transport::SUPPORTED_TYPES_HUMAN,
            ))
        })?;
        Ok(Self {
            bridge,
            resolver,
            server_did: server_did.to_string(),
            issuer: issuer.to_string(),
            https_base: reach.https_base,
            #[cfg(feature = "tsp")]
            tsp,
        })
    }

    /// Send one task and return its typed response.
    async fn call<P>(&self, request: &P) -> Result<P::Response, AppError>
    where
        P: RequestPayload + Serialize,
    {
        let payload = serde_json::to_value(request)
            .map_err(|e| AppError::Internal(format!("serialise {}: {e}", P::TYPE_URI)))?;
        let mut doc = build_request_document(P::TYPE_URI, &self.issuer, &self.server_did, payload);
        let request_id = doc["id"].as_str().unwrap_or_default().to_string();
        if !self.bridge.sign_outbound_request(&mut doc).await {
            return Err(AppError::Internal(
                "could not sign the DID-management task with this VTA's operational key".into(),
            ));
        }

        let reply = crate::operations::outbound::Outbound::from_parts(
            self.resolver,
            self.bridge,
            #[cfg(feature = "tsp")]
            self.tsp.clone(),
        )
        .with_https_base(self.https_base.clone())
        .send(
            &self.server_did,
            doc,
            crate::operations::outbound::ReplyTrust::SignedByRecipient,
        )
        .await?;

        read_reply(
            &reply,
            &request_id,
            &self.issuer,
            <P::Response as trust_tasks_rs::Payload>::TYPE_URI,
        )
    }

    /// Reserve a path (`did/check-name/0.1` with `reserve: true`).
    ///
    /// `path == None` asks the host to assign one: the member is omitted, never
    /// sent empty. A path that is already taken is a 409.
    pub async fn request_uri(
        &self,
        path: Option<&str>,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let mut body = serde_json::json!({ "reserve": true });
        if let Some(p) = path {
            body["path"] = p.into();
        }
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::did::check_name::v0_1::Payload = payload("did/check-name", body)?;
        project_check_name(self.call(&request).await?)
    }

    /// Claim `path` and publish `did_log` in one call (`did/register/0.1`).
    pub async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, AppError> {
        let mut body = serde_json::json!({
            "path": path,
            "method": "webvh",
            "didData": did_log,
            "force": force,
        });
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::did::register::v0_1::Payload = payload("did/register", body)?;
        let record = self.call(&request).await?.record;
        let did_url = record.did_url.ok_or_else(|| {
            bad_gateway_error("the host registered the slot but named no didUrl for it")
        })?;
        Ok(RequestUriResponse {
            did_url,
            mnemonic: record.mnemonic,
        })
    }

    /// Publish a log to a slot this VTA owns: an owner re-register, never
    /// forced, so a genuine ownership conflict surfaces as one.
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        log_content: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        self.register_did_atomic(mnemonic, log_content, false, domain)
            .await
            .map(|_| ())
    }

    /// Delete a slot (`did/delete/0.1`).
    pub async fn delete_did(&self, mnemonic: &str, domain: Option<&str>) -> Result<(), AppError> {
        let mut body = serde_json::json!({ "mnemonic": mnemonic });
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::did::delete::v0_1::Payload = payload("did/delete", body)?;
        self.call(&request).await.map(|_| ())
    }

    /// Set `name`'s state on `mnemonic` (`agent-name/update/0.1`): `active`
    /// to bind or resume it, `parked` to stop it resolving while keeping it
    /// reserved. `did_log` is the newly signed document, which must agree.
    pub async fn update_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        state: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let mut body = serde_json::json!({
            "mnemonic": mnemonic,
            "name": name,
            "state": state,
            "didData": did_log,
        });
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::agent_name::update::v0_1::Payload = payload("agent-name/update", body)?;
        self.call(&request).await.map(|_| ())
    }

    /// Release `name` (`agent-name/remove/0.1`): it stops resolving and anyone
    /// may claim it.
    pub async fn remove_agent_name(
        &self,
        mnemonic: &str,
        name: &str,
        did_log: &str,
        domain: Option<&str>,
    ) -> Result<(), AppError> {
        let mut body = serde_json::json!({
            "mnemonic": mnemonic,
            "name": name,
            "didData": did_log,
        });
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::agent_name::remove::v0_1::Payload = payload("agent-name/remove", body)?;
        self.call(&request).await.map(|_| ())
    }

    /// The DID's agent-name registry, parked names included
    /// (`agent-name/list/0.1`).
    pub async fn list_agent_names(
        &self,
        mnemonic: &str,
        domain: Option<&str>,
    ) -> Result<Vec<AgentNameEntry>, AppError> {
        let mut body = serde_json::json!({ "mnemonic": mnemonic });
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::agent_name::list::v0_1::Payload = payload("agent-name/list", body)?;
        Ok(self.call(&request).await?.agent_names)
    }

    /// Is `name` free on this domain (`agent-name/check/0.1`)? A reserved
    /// name answers `available: false, reserved: true` rather than an error.
    pub async fn check_agent_name(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Result<AgentNameAvailability, AppError> {
        let mut body = serde_json::json!({ "name": name });
        if let Some(d) = domain {
            body["domain"] = d.into();
        }
        let request: dm::agent_name::check::v0_1::Payload = payload("agent-name/check", body)?;
        self.call(&request).await
    }

    /// The domains the host lets this VTA mint into (`me/domains/0.1`).
    pub async fn my_domains(&self) -> Result<HostDomains, AppError> {
        let request: dm::me::domains::v0_1::Payload = payload("me/domains", serde_json::json!({}))?;
        self.call(&request).await
    }

    /// Every slot the host holds for `owner` (`did/list/0.1`), read page by
    /// page until the host's `total` is reached.
    ///
    /// Complete or an error, never a partial list: the reconcile reports what
    /// is missing from one side, so a short read would name live DIDs as
    /// orphans. A host whose pages stop short of its `total`, overrun it, or
    /// never end, is refused.
    pub async fn list_dids(&self, owner: &str) -> Result<Vec<HostedDidEntry>, AppError> {
        let mut out = Vec::new();
        for _ in 0..DID_LIST_MAX_PAGES {
            // The next page starts after what was read, not at `page * limit`:
            // a host may return fewer than `limit` records a page, and a fixed
            // stride would skip the rest.
            let request: dm::did::list::v0_1::Payload = payload(
                "did/list",
                serde_json::json!({
                    "owner": owner,
                    "limit": DID_LIST_PAGE,
                    "offset": out.len() as u64,
                }),
            )?;
            let response = self.call(&request).await?;
            if accumulate_did_page(&mut out, response)? {
                return Ok(out);
            }
        }
        Err(bad_gateway_error(format!(
            "the DID hosting service's listing did not end within {DID_LIST_MAX_PAGES} pages"
        )))
    }
}

/// Add one `did/list` page to `out`. `Ok(true)` when the listing is complete,
/// `Ok(false)` when there is more to read, and an error when the host's pages
/// and its `total` disagree, or a slot is listed twice (overlapping pages that
/// add up to `total` would otherwise hide the slots they displaced).
fn accumulate_did_page(
    out: &mut Vec<HostedDidEntry>,
    response: dm::did::list::v0_1::Response,
) -> Result<bool, AppError> {
    let got = response.records.len();
    let mut seen: std::collections::HashSet<(String, Option<String>)> = out
        .iter()
        .map(|e| (e.mnemonic.clone(), e.domain.clone()))
        .collect();
    for r in response.records {
        if !seen.insert((r.mnemonic.clone(), r.domain.clone())) {
            return Err(bad_gateway_error(format!(
                "the DID hosting service listed the slot {} twice",
                r.mnemonic
            )));
        }
        out.push(HostedDidEntry {
            mnemonic: r.mnemonic,
            did_id: r.did_id,
            domain: r.domain,
            disabled: r.disabled.unwrap_or(false),
        });
    }
    let read = out.len() as u64;
    if read > response.total {
        return Err(bad_gateway_error(format!(
            "the DID hosting service listed {read} slots but reported a total of {}",
            response.total
        )));
    }
    if read == response.total {
        return Ok(true);
    }
    if got == 0 {
        return Err(bad_gateway_error(format!(
            "the DID hosting service stopped listing at {read} of the {} slots it reported",
            response.total
        )));
    }
    Ok(false)
}

/// Project a `did/check-name/0.1#response` into the reserved slot.
///
/// `available == false` is a path already taken: a clean 409 the caller can
/// act on by choosing another. Available but not reserved, when this VTA asked
/// to reserve, is the host failing its own contract: a 502.
fn project_check_name(
    response: dm::did::check_name::v0_1::Response,
) -> Result<RequestUriResponse, AppError> {
    if !response.reserved {
        if !response.available {
            return Err(AppError::Conflict(
                "webvh path already taken on the hosting server — choose a different \
                 WEBVH_PATH, or omit it for a server-assigned path"
                    .to_string(),
            ));
        }
        return Err(bad_gateway_error(
            "the hosting server did not reserve an available path it was asked to reserve",
        ));
    }
    let record = response.record.ok_or_else(|| {
        bad_gateway_error("the hosting server reserved a path but sent no record")
    })?;
    let did_url = record.did_url.ok_or_else(|| {
        bad_gateway_error("the hosting server reserved a path but named no didUrl")
    })?;
    Ok(RequestUriResponse {
        did_url,
        mnemonic: record.mnemonic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use trust_tasks_rs::Payload as _;

    const SERVER: &str = "did:webvh:scid:host.example";
    const VTA: &str = "did:webvh:scid:vta.example";
    const REQ: &str = "urn:uuid:11111111-1111-4111-8111-111111111111";

    fn record(mnemonic: &str) -> Value {
        json!({
            "mnemonic": mnemonic,
            "owner": VTA,
            "didUrl": "https://host.example/bob/did.jsonl",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "versionCount": 0,
        })
    }

    fn reply(type_uri: &str, payload: Value) -> Value {
        json!({
            "id": "urn:uuid:22222222-2222-4222-8222-222222222222",
            "threadId": REQ,
            "type": type_uri,
            "issuer": SERVER,
            "recipient": VTA,
            "issuedAt": "2026-01-01T00:00:00Z",
            "payload": payload,
        })
    }

    type CheckName = dm::did::check_name::v0_1::Response;
    const CHECK_NAME_RESPONSE: &str =
        "https://trusttasks.org/spec/did-management/did/check-name/0.1#response";

    #[test]
    fn a_request_is_built_from_the_generated_payload() {
        let request: dm::did::check_name::v0_1::Payload =
            payload("did/check-name", json!({ "reserve": true })).unwrap();
        let body = serde_json::to_value(&request).unwrap();
        // Auto-assign omits `path`: an empty one is refused by the host.
        assert!(body.get("path").is_none(), "{body}");
        let doc = build_request_document(
            dm::did::check_name::v0_1::Payload::TYPE_URI,
            VTA,
            SERVER,
            body,
        );
        assert_eq!(
            doc["type"],
            "https://trusttasks.org/spec/did-management/did/check-name/0.1"
        );
        assert_eq!(doc["issuer"], VTA);
        assert_eq!(doc["recipient"], SERVER);
        assert!(doc["id"].as_str().unwrap().starts_with("urn:uuid:"));
    }

    /// A member the schema does not declare cannot be sent — the old client
    /// sent `didLog` where `agent-name/update` names `didData`.
    #[test]
    fn a_member_the_schema_does_not_declare_is_refused_before_signing() {
        let err = payload::<dm::agent_name::update::v0_1::Payload>(
            "agent-name/update",
            json!({ "mnemonic": "bob", "name": "alice", "state": "active", "didLog": "{}" }),
        )
        .expect_err("didLog is not a member of agent-name/update");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[test]
    fn a_register_body_names_the_webvh_method() {
        let request: dm::did::register::v0_1::Payload = payload(
            "did/register",
            json!({ "path": "bob", "method": "webvh", "didData": "{}", "force": false, "domain": "host.example" }),
        )
        .unwrap();
        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(body["method"], "webvh");
        assert_eq!(body["didData"], "{}");
        assert_eq!(body["force"], false);
        assert_eq!(body["domain"], "host.example");
    }

    #[test]
    fn a_reserved_slot_projects_its_record() {
        let r: CheckName = read_reply(
            &reply(
                CHECK_NAME_RESPONSE,
                json!({ "available": true, "reserved": true, "record": record("bob") }),
            ),
            REQ,
            VTA,
            CHECK_NAME_RESPONSE,
        )
        .unwrap();
        let slot = project_check_name(r).unwrap();
        assert_eq!(slot.mnemonic, "bob");
        assert_eq!(slot.did_url, "https://host.example/bob/did.jsonl");
    }

    #[test]
    fn a_taken_path_is_a_conflict_and_an_unreserved_free_one_a_bad_gateway() {
        let taken: CheckName =
            serde_json::from_value(json!({ "available": false, "reserved": false })).unwrap();
        assert!(matches!(
            project_check_name(taken),
            Err(AppError::Conflict(_))
        ));
        let anomaly: CheckName =
            serde_json::from_value(json!({ "available": true, "reserved": false })).unwrap();
        let err = project_check_name(anomaly).unwrap_err();
        assert!(!matches!(err, AppError::Conflict(_)), "{err:?}");
    }

    #[test]
    fn a_refusal_maps_by_its_code() {
        let cases = [
            ("did-management/did/register:pathTaken", "409"),
            ("did-management/agent-name/update:nameReserved", "409"),
            ("did-management/did/delete:notOwner", "403"),
            ("permissionDenied", "403"),
            ("did-management/agent-name/list:notFound", "404"),
            ("did-management:unknownDomain", "400"),
            ("did-management/did/register:invalidLog", "400"),
            ("malformedRequest", "502"),
            ("proofInvalid", "502"),
        ];
        for (code, status) in cases {
            let err = read_reply::<CheckName>(
                &reply(
                    "https://trusttasks.org/spec/trust-task-error/0.5",
                    json!({ "code": code, "message": "no" }),
                ),
                REQ,
                VTA,
                CHECK_NAME_RESPONSE,
            )
            .expect_err("a refusal is an error");
            let got = match err {
                AppError::Conflict(_) => "409",
                AppError::Forbidden(_) => "403",
                AppError::NotFound(_) => "404",
                AppError::Validation(_) => "400",
                _ => "502",
            };
            assert_eq!(got, status, "{code}");
        }
    }

    /// The old `did/problem-report/0.1` reply is not read any more: it is not
    /// the response type asked for, so it is refused as a contract break.
    #[test]
    fn a_problem_report_is_not_an_answer() {
        let err = read_reply::<CheckName>(
            &reply(
                "https://trusttasks.org/spec/did-management/did/problem-report/0.1",
                json!({ "code": "e.p.did.path-unavailable", "comment": "taken" }),
            ),
            REQ,
            VTA,
            CHECK_NAME_RESPONSE,
        )
        .unwrap_err();
        assert!(
            format!("{err:?}").contains("unexpected response document type"),
            "{err:?}"
        );
    }

    #[test]
    fn a_reply_to_another_request_is_refused() {
        let mut r = reply(
            CHECK_NAME_RESPONSE,
            json!({ "available": true, "reserved": true, "record": record("bob") }),
        );
        r["threadId"] = json!("urn:uuid:someone-elses");
        let err = read_reply::<CheckName>(&r, REQ, VTA, CHECK_NAME_RESPONSE).unwrap_err();
        assert!(format!("{err:?}").contains("different request"), "{err:?}");
        // A refusal must thread too: an unrelated error cannot fail this call.
        let mut e = reply(
            "https://trusttasks.org/spec/trust-task-error/0.5",
            json!({ "code": "notFound", "message": "no" }),
        );
        e.as_object_mut().unwrap().remove("threadId");
        let err = read_reply::<CheckName>(&e, REQ, VTA, CHECK_NAME_RESPONSE).unwrap_err();
        assert!(!matches!(err, AppError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn a_reply_addressed_to_someone_else_is_refused() {
        let mut r = reply(
            CHECK_NAME_RESPONSE,
            json!({ "available": true, "reserved": true, "record": record("bob") }),
        );
        r["recipient"] = json!("did:key:z6MkOther");
        let err = read_reply::<CheckName>(&r, REQ, VTA, CHECK_NAME_RESPONSE).unwrap_err();
        assert!(format!("{err:?}").contains("addressed"), "{err:?}");
    }

    #[test]
    fn a_response_of_another_type_or_shape_is_refused() {
        let other = reply(
            "https://trusttasks.org/spec/did-management/did/delete/0.1#response",
            json!({ "record": record("bob") }),
        );
        assert!(read_reply::<CheckName>(&other, REQ, VTA, CHECK_NAME_RESPONSE).is_err());
        // An undeclared member is refused: the response schema is closed.
        let extra = reply(
            CHECK_NAME_RESPONSE,
            json!({ "available": true, "reserved": false, "dids": [] }),
        );
        let err = read_reply::<CheckName>(&extra, REQ, VTA, CHECK_NAME_RESPONSE).unwrap_err();
        assert!(format!("{err:?}").contains("schema"), "{err:?}");
    }

    const LIST: &str = "https://trusttasks.org/spec/did-management/did/list/0.1#response";

    fn list_page(mnemonics: &[&str], total: u64) -> dm::did::list::v0_1::Response {
        let records: Vec<Value> = mnemonics.iter().map(|m| record(m)).collect();
        read_reply(
            &reply(LIST, json!({ "records": records, "total": total })),
            REQ,
            VTA,
            LIST,
        )
        .expect("a did/list page")
    }

    /// The `did/list` response is `{records, total}`; the old `{dids}` shape is
    /// refused.
    #[test]
    fn a_did_list_reads_records_and_total_not_dids() {
        let ok = list_page(&["bob"], 1);
        assert_eq!(ok.total, 1);
        assert_eq!(ok.records[0].mnemonic, "bob");
        assert!(
            read_reply::<dm::did::list::v0_1::Response>(
                &reply(LIST, json!({ "dids": [record("bob")] })),
                REQ,
                VTA,
                LIST,
            )
            .is_err()
        );
    }

    #[test]
    fn a_did_listing_is_read_to_its_total() {
        let mut out = Vec::new();
        assert!(!accumulate_did_page(&mut out, list_page(&["a", "b"], 3)).unwrap());
        assert!(accumulate_did_page(&mut out, list_page(&["c"], 3)).unwrap());
        let slots: Vec<_> = out.iter().map(|e| e.mnemonic.as_str()).collect();
        assert_eq!(slots, ["a", "b", "c"]);
        // An empty host is complete at once.
        assert!(accumulate_did_page(&mut Vec::new(), list_page(&[], 0)).unwrap());
    }

    /// A short or overlong listing is refused, never passed off as complete:
    /// the reconcile would name the missing DIDs as orphans.
    #[test]
    fn a_listing_that_disagrees_with_its_total_is_refused() {
        let mut out = Vec::new();
        assert!(!accumulate_did_page(&mut out, list_page(&["a"], 2)).unwrap());
        assert!(accumulate_did_page(&mut out, list_page(&[], 2)).is_err());
        assert!(accumulate_did_page(&mut Vec::new(), list_page(&["a", "b"], 1)).is_err());
        // Overlapping pages that add up to the total still hide a slot.
        let mut out = Vec::new();
        assert!(!accumulate_did_page(&mut out, list_page(&["a", "b"], 3)).unwrap());
        assert!(accumulate_did_page(&mut out, list_page(&["b"], 3)).is_err());
    }

    /// What goes on the wire is signed by the VTA's operational key.
    #[tokio::test]
    async fn the_document_is_signed_with_the_operational_key() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let vta_did = state.config.read().await.vta_did.clone().unwrap();
        let mut doc = build_request_document(
            dm::did::check_name::v0_1::Payload::TYPE_URI,
            &vta_did,
            SERVER,
            json!({ "reserve": true }),
        );
        assert!(state.didcomm_bridge.sign_outbound_request(&mut doc).await);
        assert_eq!(doc["proof"]["proofPurpose"], "authentication", "{doc}");
        let typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(doc).unwrap();
        let signer =
            vti_common::auth::verify_trust_task_proof_with(&typed, &state.trust_task_vm_resolver())
                .await
                .expect("the proof verifies");
        assert_eq!(signer.split('#').next(), Some(vta_did.as_str()));
    }

    #[tokio::test]
    async fn a_bridge_without_a_signer_signs_nothing() {
        let bridge = DIDCommBridge::placeholder();
        let mut doc = build_request_document(
            dm::did::check_name::v0_1::Payload::TYPE_URI,
            VTA,
            SERVER,
            json!({}),
        );
        assert!(!bridge.sign_outbound_request(&mut doc).await);
        assert!(doc.get("proof").is_none());
    }
}
