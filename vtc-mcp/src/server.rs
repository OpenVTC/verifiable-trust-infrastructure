//! The MCP server handler: a bridge from MCP tool calls to a community.
//!
//! Every tool call is one signed Trust Task the [`VtcClient`] sends — over
//! the mediated session it opened (TSP leg when the community advertises
//! TSP, DIDComm otherwise), or signed and posted over HTTPS when the
//! community advertises neither. The community is the authority: the entry
//! this bridge runs as — a member persona, or a dedicated agent entry with a
//! role ceiling or listed capabilities — decides what actually happens.
//!
//! Two generic tools cover the whole surface: `vtc_list_operations` (the
//! catalog, read from the pinned specification bundles) and `vtc_call`
//! (send any pinned task by Type URI). `vtc_supported_tasks` asks the
//! community what it serves, `vtc_whoami` what it knows of this identity, and
//! `vtc_status` what this bridge is.
//!
//! ## Three things every call goes through
//!
//! 1. **[`vti_mcp_common::guard`]** — the local per-operation gate, because an
//!    MCP host approves a *tool* and this bridge's most useful tool is "send
//!    any operation".
//! 2. **[`vti_mcp_common::observability`]** — a start line, a finish line
//!    with duration and outcome, and a redacted record in the ring (and the
//!    audit file when one is configured).
//! 3. **The community** — which is, and remains, the authority. Everything
//!    above is a second gate in front of it, never a substitute for it.
//!
//! ## A parked operation is an outcome
//!
//! A write that needs other administrators' agreement is parked on the
//! community's action list (VTI-APV-017). The client reports that as
//! [`VtcError::Parked`]; this bridge returns it as a *successful* call whose
//! result says `"status": "parked"` and names the action, because nothing
//! failed and nothing is to be sent again.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, GetPromptRequestParams, GetPromptResponse, GetPromptResult,
    Implementation, ListPromptsResult, ListResourcesResult, PaginatedRequestParams, Prompt,
    PromptArgument, PromptMessage, ProtocolVersion, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, Role, ServerCapabilities,
    ServerConfig,
};
use rmcp::service::{Peer, RequestContext};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, elicit_safe, tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use vtc_client::{VtcClient, VtcError};
use vti_mcp_common::guard::{Decision, Guard, Risk, classify, glob_match, slug_of};

use crate::guides;
use vti_mcp_common::observability::{CallRecord, Recorder, redact_call};
use vti_mcp_common::tool_error::{CallFailure, ToolError};

/// The Trust Task URI each convenience tool **actually sends**.
mod wire {
    use trust_tasks_rs::Payload as _;

    /// `trust-task-discovery/0.4` — what `vtc_supported_tasks` asks.
    pub const DISCOVERY: &str =
        trust_tasks_rs::specs::trust_task_discovery::v0_4::Payload::TYPE_URI;
    /// `auth/whoami/0.1` — what `vtc_whoami` asks.
    pub const WHOAMI: &str = "https://trusttasks.org/spec/auth/whoami/0.1";
}

/// Resource URI for the bridge's own state.
const RESOURCE_STATUS: &str = "vtc://status";
/// Resource URI for the operation catalog.
const RESOURCE_OPERATIONS: &str = "vtc://operations";
/// Resource URI for the in-memory record of recent calls.
const RESOURCE_RECENT: &str = "vtc://calls/recent";

/// Wrap a serializable result as an MCP tool result with pretty-printed JSON
/// text content.
fn ok_json(value: impl serde::Serialize) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(&value)
        .map_err(|e| McpError::internal_error(format!("serialising result: {e}"), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// What a community answered, as a tool result.
///
/// A refusal becomes a tool-execution error (#2594) carrying the community's
/// own `trust-task-error` document (its `code` and `message` are what the
/// caller reads, whichever transport carried the task) — a result the model
/// reads, never a JSON-RPC protocol error, which hosts show as a bridge fault. A parked operation is **not** an error: it
/// completes itself when enough administrators approve, so the result says
/// so and names the action to follow.
///
/// A step-up the community offered to hand to the person's wallet is not an
/// error either: the result says `"status": "stepUpRequired"` and carries the
/// `step-up` link (VTI-LNK-127) for the person to open, and nothing else —
/// never the inline request as something to approve. The bridge holds no
/// factor and never answers it; once the person has, the identical call goes
/// through.
pub(crate) fn outcome(result: Result<Value, VtcError>) -> Result<Value, ToolError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    outcome_at(result, now)
}

/// [`outcome`] at `now` (epoch seconds), for tests.
pub(crate) fn outcome_at(result: Result<Value, VtcError>, now: i64) -> Result<Value, ToolError> {
    match result {
        Ok(value) => Ok(value),
        Err(VtcError::Parked { action_id, message }) => Ok(json!({
            "status": "parked",
            "actionId": action_id,
            "message": message,
            "next": "the community parked this for other administrators' approval; it runs \
                     itself when enough of them approve. Follow it with \
                     vtc/admin/actions/show, and do not send it again.",
        })),
        Err(VtcError::Refused { document }) if step_up_link(&parsed(&document), now).is_some() => {
            let document = parsed(&document);
            let link = step_up_link(&document, now).expect("checked above");
            let inline = vtc_client::step_up::inline_request(&document);
            Ok(json!({
                "status": "stepUpRequired",
                "subject": inline.and_then(|r| r.get("subject")),
                "reason": inline.and_then(|r| r.get("reason")),
                "link": link.link,
                "linkExpiresAt": link.expires_at,
                "next": "the community needs the person's own step-up for this one call. Show \
                         them the link (or a QR code of it) and ask them to open it in their \
                         wallet, which shows exactly what will be done; it expires at \
                         linkExpiresAt. Once they have approved, send the identical call \
                         again. Never approve it yourself or describe it as approved.",
            }))
        }
        Err(VtcError::Refused { document }) => Err(refused(&document)),
        Err(e) => Err(to_tool(e)),
    }
}

/// What a transport or unclassified failure tells the model to do.
const NEXT_STATUS: &str = "call vtc_status to see which identity this bridge runs as and how it \
                           is connected";

/// A community's refusal: kind `refused`, its own `code` and `message`, and
/// the whole `trust-task-error` document as received for anything else it
/// carries.
fn refused(document: &str) -> ToolError {
    let parsed = parsed(document);
    let code = parsed["payload"]["code"]
        .as_str()
        .or_else(|| parsed["code"].as_str())
        .map(str::to_string);
    let message = parsed["payload"]["message"]
        .as_str()
        .or_else(|| parsed["message"].as_str())
        .map_or_else(
            || format!("the community refused the request: {document}"),
            |m| format!("the community refused the request: {m}"),
        );
    let next = match code.as_deref() {
        Some(c) if c.ends_with("permissionDenied") || c.ends_with("forbidden") => {
            "this identity's standing at the community does not permit the operation. Call \
             vtc_whoami to see what the community knows of it; only an administrator can widen \
             it. Do not retry."
        }
        Some(c) if c.ends_with("malformedRequest") => {
            "the payload does not match the operation's schema. Read it with \
             vtc_list_operations (detail 'full') and correct the call."
        }
        Some(c) if c.ends_with("unsupportedType") || c.ends_with("unsupportedVersion") => {
            "the community does not serve this operation at this version. Call \
             vtc_supported_tasks and use one it serves."
        }
        _ => "read the code; send a corrected call only if the refusal says what to change.",
    };
    let mut error = ToolError::new("refused", message).with_next(next);
    if !parsed.is_null() {
        error = error.with_details(json!({ "code": code, "document": parsed }));
    }
    error
}

/// A client-side failure as a tool-execution error, its kind the [`VtcError`]
/// variant.
fn to_tool(e: VtcError) -> ToolError {
    let message = e.to_string();
    match e {
        VtcError::NotFound { code, .. } => ToolError::new("notFound", message)
            .with_next("check the identifier: list the collection first.")
            .with_details(json!({ "code": code })),
        VtcError::InvalidPayload(_) => ToolError::new("invalidRequest", message).with_next(
            "nothing was sent: the payload does not satisfy the operation's schema. Read it \
             with vtc_list_operations (detail 'full'); an unset optional member is absent, \
             never null.",
        ),
        VtcError::UnpinnedTask { type_uri, .. } => ToolError::new("notPinned", message)
            .with_next(
                "nothing was sent: this bridge sends only the Trust Task versions it pins. Call \
                 vtc_list_operations for the URIs it can send.",
            )
            .with_details(json!({ "operation": type_uri })),
        VtcError::NotAuthenticated | VtcError::Auth(_) => {
            ToolError::new("unauthenticated", message).with_next(NEXT_STATUS)
        }
        VtcError::Transport(_)
        | VtcError::Session(_)
        | VtcError::NoTransport { .. }
        | VtcError::NoRestTransport(_) => {
            ToolError::new("transport", message).with_next(NEXT_STATUS)
        }
        VtcError::Http { status, .. } => ToolError::new("httpError", message)
            .with_next(NEXT_STATUS)
            .with_details(json!({ "status": status })),
        _ => ToolError::new("failed", message).with_next(NEXT_STATUS),
    }
}

/// Check `operation` against what the community said it serves (#2594).
/// `None` when served, or when nothing is known; otherwise the refusal to
/// return instead of sending — the discovery answer is the community's own
/// dispatch table, so absence from it is a fact.
fn check_served(operation: &str, served: &[String]) -> Option<ToolError> {
    if served.iter().any(|u| u == operation) {
        return None;
    }
    let family = operation.rsplit_once('/').map(|(f, _)| f);
    let versions: Vec<String> = served
        .iter()
        .filter_map(|u| {
            let (f, v) = u.rsplit_once('/')?;
            (Some(f) == family).then(|| v.to_string())
        })
        .collect();
    let message = if versions.is_empty() {
        format!("this community does not serve {operation}")
    } else {
        format!(
            "this community does not serve {operation} — it serves {}",
            versions.join(", ")
        )
    };
    Some(
        ToolError::new("notServed", message)
            .with_next(
                "nothing was sent. Call vtc_supported_tasks (or vtc_list_operations, whose \
                 'served' says the same) and use an operation the community serves.",
            )
            .with_details(json!({ "operation": operation, "servedVersions": versions })),
    )
}

/// A refusal document as JSON; `Null` when it does not parse.
fn parsed(document: &str) -> Value {
    serde_json::from_str(document).unwrap_or(Value::Null)
}

/// The `step-up` link a refusal's hand-off makes, its contact the community
/// that issued the refusal.
fn step_up_link(document: &Value, now: i64) -> Option<vtc_client::step_up::StepUpLink> {
    let handoff = vtc_client::step_up::handoff_of(document)?;
    let community = document["issuer"].as_str()?;
    vtc_client::step_up::link(community, handoff, now)
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListOperationsParams {
    /// Slug-glob patterns, ORed: `*` for everything, `vtc/groups/*` for a
    /// family, or an exact slug (`vtc/groups/create`). Omit for everything.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// `summary` (default): slug, version, description, risk, policy and
    /// whether the community serves it. `full`: also the payload schema and
    /// the declared error codes, for building a call.
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupportedTasksParams {
    /// Slug-glob patterns, ORed; omit for everything the community serves.
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VtcCallParams {
    /// The Trust Task operation URI to send (from `vtc_list_operations`),
    /// e.g. `https://trusttasks.org/spec/vtc/groups/create/0.1`.
    pub operation: String,
    /// The operation's request payload as a JSON object, in the shape its
    /// schema gives (`vtc_list_operations` with `detail: "full"`). Omit (or
    /// `{}`) for operations that take no parameters. An unset optional member
    /// is absent, never `null`.
    #[serde(default)]
    pub payload: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StatusParams {
    /// How many recent calls to include (default 10, max 100). Pass 0 for none.
    #[serde(default)]
    pub recent_calls: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WhoamiParams {}

/// Approve this community operation?
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Approval {
    /// Approve this operation? Answering no refuses the call.
    pub approve: bool,
}
elicit_safe!(Approval);

/// Who this bridge is, resolved before connecting so it can be reported even
/// when the connection failed.
#[derive(Debug, Clone, Default)]
pub struct BridgeIdentity {
    /// The ladder rung: `did:webvh-bundle`, `did:key`, or `unconfigured`.
    pub mode: String,
    /// The DID this bridge speaks as.
    pub agent_did: Option<String>,
    /// The community.
    pub vtc_did: Option<String>,
    /// The transport pinned by the operator, or `auto`.
    pub transport_choice: String,
    /// Set when the agent key was used with another community before
    /// (`key_reuse`): what the operator should be told about it.
    pub reuse_warning: Option<String>,
    /// How MCP is served: `stdio`, or the `--listen` URL.
    pub serving: String,
}

impl BridgeIdentity {
    fn to_json(&self) -> Value {
        let mut v = json!({
            "mode": self.mode,
            "agentDid": self.agent_did,
            "vtcDid": self.vtc_did,
            "transportChoice": self.transport_choice,
            // Always: this bridge has no rung that replays an operator login.
            "dedicatedAgent": true,
        });
        if let Some(w) = &self.reuse_warning {
            v["keyReuseWarning"] = json!(w);
        }
        v
    }
}

/// One catalog entry, read once from the pinned specification bundle.
struct CatalogEntry {
    uri: &'static str,
    slug: &'static str,
    version: &'static str,
    description: String,
    schema: Value,
    error_codes: Vec<&'static str>,
}

/// The catalog: every pinned request Type URI, from the specification index
/// — never a hand-written description. Built once; it is static data.
fn catalog() -> &'static [CatalogEntry] {
    static CATALOG: OnceLock<Vec<CatalogEntry>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut uris: Vec<&'static str> = vti_specs::schema_index::type_uris()
            .filter(|uri| !uri.contains('#'))
            .collect();
        uris.sort_unstable();
        uris.into_iter()
            .filter_map(|uri| {
                let entry = vti_specs::schema_index::entry(uri)?;
                let slug = slug_of(uri)?;
                let version = uri.rsplit('/').next().unwrap_or("");
                let schema: Value = entry
                    .schema
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(Value::Null);
                let description = schema
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let error_codes = entry
                    .error_codes
                    .map(|codes| codes.iter().map(|c| c.code).collect())
                    .unwrap_or_default();
                Some(CatalogEntry {
                    uri,
                    slug,
                    version,
                    description,
                    schema,
                    error_codes,
                })
            })
            .collect()
    })
}

/// MCP server bridging to one community, as one identity.
#[derive(Clone)]
pub struct VtcMcp {
    /// `None` when the initial connect failed — see [`VtcMcp::degraded`].
    client: Option<Arc<VtcClient>>,
    /// Why the connect failed, in degraded mode.
    connect_error: Option<Arc<str>>,
    pub(crate) identity: Arc<BridgeIdentity>,
    guard: Arc<Guard>,
    recorder: Arc<Recorder>,
    started: Arc<str>,
    /// What the community said it serves, once asked (`vtc_supported_tasks`
    /// with no narrowing, or at connect). `None` until then.
    served: Arc<RwLock<Option<Vec<String>>>>,
    /// The wallet sign-in this bridge has open, and who it is signed in as.
    pub(crate) sign_in: Arc<RwLock<crate::signin::SignInState>>,
    /// Whether the community has answered since the last transport failure
    /// (`health`): what `connected` reports, instead of a flag latched at
    /// connect.
    pub(crate) health: Arc<crate::health::TransportHealth>,
}

/// One in-flight guarded call. Created by [`VtcMcp::begin`], consumed by
/// [`CallGuard::finish`] — which writes the finish line and the audit record,
/// so a tool cannot return without being recorded.
pub(crate) struct CallGuard {
    seq: u64,
    tool: &'static str,
    operation: Option<String>,
    risk: Risk,
    decision: &'static str,
    args: Value,
    started: Instant,
    recorder: Arc<Recorder>,
}

impl CallGuard {
    /// Record the outcome and hand back the result. An operation failure
    /// ([`ToolError`]) is a tool result with `isError: true`, which the model
    /// reads; only a [`CallFailure::Protocol`] stays a JSON-RPC error.
    pub(crate) fn finish<E: Into<CallFailure>>(
        self,
        result: Result<Value, E>,
    ) -> Result<CallToolResult, McpError> {
        let duration_ms = self.started.elapsed().as_millis();
        match result {
            Ok(value) => {
                self.emit("ok", None, duration_ms);
                ok_json(value)
            }
            Err(e) => {
                let failure = e.into();
                self.emit("error", Some(failure.message()), duration_ms);
                failure.into_result()
            }
        }
    }

    /// Record a call that never reached the community, and answer it as a
    /// tool result the model reads.
    pub(crate) fn refuse(
        self,
        outcome: &'static str,
        error: ToolError,
    ) -> Result<CallToolResult, McpError> {
        let duration_ms = self.started.elapsed().as_millis();
        self.emit(outcome, Some(error.message.clone()), duration_ms);
        Ok(error.into_call_result())
    }

    fn emit(&self, outcome: &'static str, error: Option<String>, duration_ms: u128) {
        let error =
            if vti_mcp_common::observability::carries_personal_text(self.operation.as_deref()) {
                error.map(|_| "<elided: personal text>".to_string())
            } else {
                error
            };
        let record = CallRecord {
            seq: self.seq,
            tool: self.tool,
            operation: self.operation.clone(),
            risk: self.risk.label(),
            decision: self.decision,
            outcome,
            duration_ms,
            args: self.args.clone(),
            error: error.clone(),
        };
        match outcome {
            "ok" => tracing::info!(
                seq = self.seq,
                tool = self.tool,
                operation = self.operation.as_deref().unwrap_or("-"),
                risk = self.risk.label(),
                duration_ms = duration_ms as u64,
                "call ok"
            ),
            _ => tracing::warn!(
                seq = self.seq,
                tool = self.tool,
                operation = self.operation.as_deref().unwrap_or("-"),
                risk = self.risk.label(),
                duration_ms = duration_ms as u64,
                outcome,
                error = error.as_deref().unwrap_or("-"),
                "call failed"
            ),
        }
        self.recorder.record(&record);
    }
}

#[tool_router]
impl VtcMcp {
    /// A connected bridge.
    pub fn new(
        client: Arc<VtcClient>,
        identity: BridgeIdentity,
        guard: Guard,
        recorder: Arc<Recorder>,
    ) -> Self {
        Self {
            client: Some(client),
            connect_error: None,
            identity: Arc::new(identity),
            guard: Arc::new(guard),
            recorder,
            started: vti_mcp_common::observability::now_rfc3339().into(),
            served: Arc::new(RwLock::new(None)),
            sign_in: Arc::new(RwLock::new(crate::signin::SignInState::default())),
            health: Arc::default(),
        }
    }

    /// A bridge that failed to connect but serves MCP anyway, so the failure
    /// is legible from inside the session that hit it: `vtc_status` answers,
    /// every other tool returns the connect error verbatim.
    pub fn degraded(
        error: String,
        identity: BridgeIdentity,
        guard: Guard,
        recorder: Arc<Recorder>,
    ) -> Self {
        Self {
            client: None,
            connect_error: Some(error.into()),
            identity: Arc::new(identity),
            guard: Arc::new(guard),
            recorder,
            started: vti_mcp_common::observability::now_rfc3339().into(),
            served: Arc::new(RwLock::new(None)),
            sign_in: Arc::new(RwLock::new(crate::signin::SignInState::default())),
            health: Arc::default(),
        }
    }

    /// Ask the community what it serves and remember the answer, so the
    /// catalog can say which of its entries this community answers. Best
    /// effort: a community that refuses (an identity it does not know) leaves
    /// the catalog saying "unknown", never "no".
    pub async fn learn_served(&self) {
        let Some(client) = &self.client else { return };
        match self.health.observe(client.discover(&[]).await) {
            Ok(answer) => {
                let uris: Vec<String> = vtc_client::supported_type_uris(&answer)
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                tracing::info!(count = uris.len(), "the community listed what it serves");
                *self.served.write().await = Some(uris);
            }
            Err(e) => tracing::warn!(error = %e, "could not ask the community what it serves"),
        }
    }

    pub(crate) fn client(&self) -> Result<&VtcClient, ToolError> {
        match &self.client {
            Some(client) => Ok(client),
            None => Err(ToolError::new(
                "notConnected",
                format!(
                    "this vtc-mcp bridge is not connected to its community: {}. Fix the \
                     connection and restart the MCP server; `vtc_status` reports the \
                     configuration it tried.",
                    self.connect_error.as_deref().unwrap_or("unknown error")
                ),
            )
            .with_next(
                "call vtc_status to see the configuration it tried; the operator has to fix the \
                 connection and restart vtc-mcp.",
            )),
        }
    }

    /// Gate, log and (where the policy asks) confirm one call. `operation` is
    /// the Trust Task URI the tool resolves to — `None` for the local tools.
    ///
    /// `peer` is the host, for a confirmation; without one (a workflow step
    /// exercised directly) a step that needs confirming is refused rather than
    /// run unconfirmed.
    pub(crate) async fn begin(
        &self,
        tool: &'static str,
        operation: Option<&str>,
        args: Value,
        peer: Option<&Peer<RoleServer>>,
    ) -> Result<CallGuard, Box<Result<CallToolResult, McpError>>> {
        let seq = self.recorder.next_seq();
        let risk = operation.map_or(Risk::ReadOnly, classify);
        let decision = operation.map_or(Decision::Allow, |uri| self.guard.decide(uri));
        let guard = CallGuard {
            seq,
            tool,
            operation: operation.map(str::to_string),
            risk,
            decision: decision.label(),
            args: redact_call(operation, &args),
            started: Instant::now(),
            recorder: self.recorder.clone(),
        };
        tracing::info!(
            seq,
            tool,
            operation = operation.unwrap_or("-"),
            risk = risk.label(),
            decision = decision.label(),
            args = %guard.args,
            "call start"
        );
        match decision {
            Decision::Allow => Ok(guard),
            Decision::Deny(reason) => {
                tracing::warn!(seq, tool, reason = %reason, "call denied by local policy");
                Err(Box::new(guard.refuse(
                    "denied",
                    ToolError::refused_locally("denied", reason, "vtc_status"),
                )))
            }
            Decision::Confirm(prompt) => {
                let answer = match peer {
                    Some(peer) => self.confirm(peer, &prompt).await,
                    None => Err(format!(
                        "{prompt} — no MCP host to ask, so the bridge refused rather than \
                         proceeding unconfirmed"
                    )),
                };
                match answer {
                    Ok(true) => Ok(guard),
                    Ok(false) => Err(Box::new(guard.refuse(
                        "declined",
                        ToolError::refused_locally(
                            "declined",
                            format!("{prompt} — declined by the operator."),
                            "vtc_status",
                        ),
                    ))),
                    Err(reason) => Err(Box::new(guard.refuse(
                        "denied",
                        ToolError::refused_locally("denied", reason, "vtc_status"),
                    ))),
                }
            }
        }
    }

    /// Ask the human. `Err` means no answer could be obtained at all, which is
    /// refused rather than waved through.
    pub(crate) async fn confirm(
        &self,
        peer: &Peer<RoleServer>,
        prompt: &str,
    ) -> Result<bool, String> {
        match peer.elicit::<Approval>(prompt.to_string()).await {
            Ok(Some(approval)) => Ok(approval.approve),
            Ok(None) => Ok(false),
            Err(rmcp::service::ElicitationError::UserDeclined)
            | Err(rmcp::service::ElicitationError::UserCancelled)
            | Err(rmcp::service::ElicitationError::NoContent) => Ok(false),
            Err(rmcp::service::ElicitationError::CapabilityNotSupported) => Err(format!(
                "{prompt} — this MCP host cannot ask you (it does not support elicitation), so \
                 the bridge refused rather than proceeding unconfirmed. Restart vtc-mcp with \
                 `--confirm never` to drop the prompt, or `--allow <slug>` to permit just this \
                 operation."
            )),
            Err(e) => Err(format!("{prompt} — could not obtain confirmation: {e}")),
        }
    }

    /// Send one operation and read the answer — the body of `vtc_call`,
    /// without the MCP plumbing, so it can be exercised directly.
    ///
    /// An operation the community has said it does not serve is refused here,
    /// with the versions of it that it does serve, rather than sent.
    pub async fn call_operation(
        &self,
        operation: &str,
        payload: Value,
    ) -> Result<Value, ToolError> {
        let client = self.client()?;
        let served = self.served.read().await.clone();
        if let Some(served) = served
            && let Some(refusal) = check_served(operation, &served)
        {
            return Err(refusal);
        }
        outcome(
            self.health
                .observe(client.send_task(operation, payload).await),
        )
    }

    #[tool(
        description = "List the community operations `vtc_call` can send — every pinned Trust \
                       Task (groups, boards, elections, rooms, directory, members, join \
                       requests, roles, acl, policy, notifications, backup, …), each with its \
                       description from the specification, its risk class, this bridge's local \
                       policy decision (allow / confirm / deny) and, once known, whether the \
                       connected community serves it. Narrow with slug globs such as \
                       'vtc/groups/*'; ask for detail 'full' to get an operation's payload \
                       schema and declared error codes before calling it.",
        annotations(
            title = "List community operations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_list_operations(
        &self,
        Parameters(p): Parameters<ListOperationsParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_list_operations",
                None,
                json!({ "patterns": p.patterns, "detail": p.detail }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let full = match p.detail.as_deref() {
            None | Some("summary") => false,
            Some("full") => true,
            Some(other) => {
                return call.finish(Err(McpError::invalid_params(
                    format!("detail must be 'summary' or 'full', not '{other}'"),
                    None,
                )));
            }
        };
        let patterns: Vec<&str> = p.patterns.iter().map(String::as_str).collect();
        let result = self.operations_catalog(&patterns, full).await;
        call.finish(Ok::<_, ToolError>(result))
    }

    /// The catalog, annotated with this bridge's view of each entry. Shared
    /// with the `vtc://operations` resource.
    async fn operations_catalog(&self, patterns: &[&str], full: bool) -> Value {
        let served = self.served.read().await.clone();
        let operations: Vec<Value> = catalog()
            .iter()
            .filter(|e| patterns.is_empty() || patterns.iter().any(|p| glob_match(p, e.slug)))
            .map(|e| {
                let mut entry = json!({
                    "operation": e.uri,
                    "slug": e.slug,
                    "version": e.version,
                    "description": e.description,
                    "risk": classify(e.uri).label(),
                    "policy": self.guard.decide(e.uri).label(),
                    "served": served.as_ref().map(|s| s.iter().any(|u| u == e.uri)),
                });
                if full {
                    entry["payloadSchema"] = e.schema.clone();
                    entry["errorCodes"] = json!(e.error_codes);
                }
                entry
            })
            .collect();
        json!({
            "policy": self.guard.summary(),
            "servedKnown": served.is_some(),
            "count": operations.len(),
            "operations": operations,
        })
    }

    #[tool(
        description = "Send ANY community Trust Task by URI with a JSON payload — the generic \
                       gateway to the whole surface. Use `vtc_list_operations` to find the URI \
                       and (with detail 'full') the payload shape, and to see which operations \
                       this bridge will allow. A result with status 'parked' means the \
                       community needs other administrators' approval: nothing failed, do not \
                       resend, follow the named action. Subject to this identity's standing at \
                       the community, and to the bridge's own local policy.",
        annotations(
            title = "Send any community operation",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn vtc_call(
        &self,
        Parameters(p): Parameters<VtcCallParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let payload = p.payload.unwrap_or_else(|| json!({}));
        let call = match self
            .begin(
                "vtc_call",
                Some(&p.operation),
                json!({ "operation": p.operation, "payload": payload }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.call_operation(&p.operation, payload).await;
        call.finish(result)
    }

    #[tool(
        description = "Ask the connected community which Trust Tasks it serves \
                       (trust-task-discovery/0.4). Optionally narrow with slug-glob patterns \
                       such as 'vtc/boards/*'; omit for everything. The answer is what the \
                       community routes; what this bridge can send is `vtc_list_operations`, \
                       and the two are intersected there once this has been asked.",
        annotations(
            title = "Supported community tasks",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_supported_tasks(
        &self,
        Parameters(p): Parameters<SupportedTasksParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vtc_supported_tasks",
                Some(wire::DISCOVERY),
                json!({ "patterns": p.patterns }),
                Some(&peer),
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let patterns: Vec<&str> = p.patterns.iter().map(String::as_str).collect();
        let result = match self.client() {
            Ok(client) => match self.health.observe(client.discover(&patterns).await) {
                Ok(answer) => {
                    let uris: Vec<String> = vtc_client::supported_type_uris(&answer)
                        .into_iter()
                        .map(str::to_string)
                        .collect();
                    if patterns.is_empty() || patterns == ["*"] {
                        *self.served.write().await = Some(uris.clone());
                    }
                    Ok(json!({
                        "supportedTypes": uris,
                        "frameworkVersion": answer.framework_version.as_ref().map(|v| v.to_string()),
                    }))
                }
                Err(e) => outcome(Err(e)),
            },
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "What the community knows of this bridge's identity: `auth/whoami` as the \
                       community answers it, beside the identity the bridge was configured with. \
                       A community answers whoami only for a key it holds a sign-in session for, \
                       so a dedicated agent entry or a member persona may get the configured \
                       identity alone, with the community's reason.",
        annotations(
            title = "Who am I",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_whoami(
        &self,
        Parameters(_p): Parameters<WhoamiParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin("vtc_whoami", Some(wire::WHOAMI), json!({}), Some(&peer))
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => Ok(
                match self
                    .health
                    .observe(client.send_task(wire::WHOAMI, json!({})).await)
                {
                    Ok(answer) => json!({
                        "identity": self.identity.to_json(),
                        "whoami": answer,
                    }),
                    Err(e) => json!({
                        "identity": self.identity.to_json(),
                        "whoami": Value::Null,
                        "reason": e.to_string(),
                    }),
                },
            ),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Report what this bridge is: the identity it speaks as, the community, \
                       the transport in use (TSP, DIDComm or HTTPS), its local operation \
                       policy, how many calls it has served, and the most recent ones. Ask this \
                       first when a community tool fails or behaves unexpectedly.",
        annotations(
            title = "Bridge status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vtc_status(
        &self,
        Parameters(p): Parameters<StatusParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self.begin("vtc_status", None, json!({}), Some(&peer)).await {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let limit = p.recent_calls.unwrap_or(10).min(100);
        let status = self.status(limit).await;
        call.finish(Ok::<_, ToolError>(status))
    }

    /// The status document, shared by the tool and the `vtc://status` resource.
    pub(crate) async fn status(&self, recent: usize) -> Value {
        let transport = self
            .client
            .as_ref()
            .and_then(|c| c.transport())
            .map(|t| t.to_string());
        json!({
            // A session, and no transport failure since the community last
            // answered (R6.2: never a flag latched at connect).
            "connected": self.client.is_some() && self.health.reachable(),
            "transportHealth": self.health.to_json(),
            "serving": self.identity.serving,
            "connectError": self.connect_error.as_deref(),
            "startedAt": &*self.started,
            "version": env!("CARGO_PKG_VERSION"),
            "identity": self.identity.to_json(),
            "signedInAs": self.sign_in.read().await.signed_in.as_ref().map(|s| s.to_json()),
            "delegationOf": self.sign_in.read().await.delegation_of,
            "transport": transport,
            "servedKnown": self.served.read().await.is_some(),
            "policy": {
                "summary": self.guard.summary(),
                "readOnly": self.guard.read_only,
                "confirm": self.guard.confirm.label(),
                "allow": self.guard.allow,
                "deny": self.guard.deny,
            },
            "calls": self.recorder.counters().snapshot(),
            "auditLog": self.recorder.audit_path().map(|p| p.display().to_string()),
            "recentCalls": self.recorder.recent(recent),
        })
    }
}

#[tool_handler(router = (Self::tool_router() + Self::workflow_router() + Self::signin_router()))]
impl ServerHandler for VtcMcp {
    /// Up to `2025-11-25`, never `2026-07-28`. Confirmation (`--confirm`) and
    /// `vtc_actions_decide` ask the human with a server-to-client elicitation
    /// request, which `2026-07-28` forbids: a host that negotiates it is served
    /// statelessly, with no client capabilities, so every confirmation would be
    /// refused as "this host cannot ask you". Capping the version makes such a
    /// host fall back to `initialize`, where elicitation works. Lift the cap
    /// only once confirmation is answered with an `InputRequiredResult`.
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        vti_mcp_common::listen::supported_protocol_versions()
    }

    fn get_info(&self) -> ServerConfig {
        let mut server_info = Implementation::from_build_env();
        server_info.name = "vtc-mcp".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(server_info)
        .with_instructions(
            "Bridges a Verifiable Trust Community (VTC) to MCP, as one identity: a member's own \
             persona, or a dedicated agent entry an administrator enrolled. Use \
             vtc_list_operations to find operations (groups, boards, elections, data rooms, the \
             member directory, members and join requests, roles and access control, policy, \
             notifications, backup, …), with detail 'full' for an operation's payload schema, \
             then vtc_call to send one. vtc_supported_tasks asks the community what it serves; \
             vtc_whoami what it knows of this identity; vtc_status what this bridge is — ask it \
             first when anything fails. A vtc_call result with status 'parked' is not a failure: \
             the community is waiting for other administrators to approve; follow the named \
             action and do not resend. For a multi-step job — set up a group, create a board, \
             run an election or poll, open a data room, admit a member, grant administration — \
             use the prompt of that name: it gives the steps in order, which of them park, and \
             what the member sees. The community's own operator guides are the vtc://guide/* \
             resources. All access is bounded by this identity's standing at the community, \
             and by this bridge's local policy: some operations are refused outright and some \
             ask the operator to approve them first.",
        )
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        let prompts = guides::WORKFLOWS
            .iter()
            .map(|w| {
                let arguments: Vec<PromptArgument> = w
                    .arguments
                    .iter()
                    .map(|a| {
                        let mut arg = PromptArgument::new(a.name);
                        arg.description = Some(a.description.to_string());
                        arg.required = Some(false);
                        arg
                    })
                    .collect();
                let mut prompt = Prompt::new(w.name, Some(w.description), Some(arguments));
                prompt.title = Some(w.title.to_string());
                prompt
            })
            .collect();
        Ok(ListPromptsResult::with_all_items(prompts))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        let Some(workflow) = guides::workflow(&request.name) else {
            return Err(McpError::invalid_params(
                format!(
                    "unknown prompt '{}'; the prompts are {}",
                    request.name,
                    guides::WORKFLOWS
                        .iter()
                        .map(|w| w.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None,
            ));
        };
        let text = guides::render(workflow, request.arguments.as_ref());
        let mut result = GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)]);
        result.description = Some(workflow.description.to_string());
        Ok(result.into())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let mut resources = vec![
            Resource::new(RESOURCE_STATUS, "Community bridge status")
                .with_description(
                    "Identity, transport, local policy, call counters and recent calls.",
                )
                .with_mime_type("application/json"),
            Resource::new(RESOURCE_OPERATIONS, "Community operation catalog")
                .with_description(
                    "Every Trust Task URI vtc_call can send, with its description, risk class \
                     and this bridge's policy decision.",
                )
                .with_mime_type("application/json"),
            Resource::new(RESOURCE_RECENT, "Recent community calls")
                .with_description(
                    "The last 100 calls this bridge served, redacted — what it has been doing.",
                )
                .with_mime_type("application/json"),
        ];
        resources.extend(guides::GUIDES.iter().map(|g| {
            Resource::new(guides::guide_uri(g.topic), g.title)
                .with_description(format!(
                    "The community's operator guide ({}), as this bridge's version of it was \
                     written.",
                    g.source
                ))
                .with_mime_type("text/markdown")
        }));
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if let Some(guide) = guides::guide_at(&request.uri) {
            return Ok(
                ReadResourceResult::new(vec![ResourceContents::TextResourceContents {
                    uri: request.uri,
                    mime_type: Some("text/markdown".into()),
                    text: guide.text.to_string(),
                    meta: None,
                }])
                .into(),
            );
        }
        let body = match request.uri.as_str() {
            RESOURCE_STATUS => self.status(10).await,
            RESOURCE_OPERATIONS => self.operations_catalog(&[], false).await,
            RESOURCE_RECENT => json!({ "calls": self.recorder.recent(100) }),
            other => {
                return Err(McpError::resource_not_found(
                    format!("unknown resource '{other}'"),
                    None,
                ));
            }
        };
        let text = serde_json::to_string_pretty(&body)
            .map_err(|e| McpError::internal_error(format!("serialising resource: {e}"), None))?;
        Ok(ReadResourceResult::new(vec![ResourceContents::text(text, request.uri)]).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vtc_client::HolderKey;
    use vti_mcp_common::guard::ConfirmLevel;

    const VTC_DID: &str = "did:web:vtc.example.com";
    const GROUPS_CREATE: &str = "https://trusttasks.org/spec/vtc/groups/create/0.1";

    fn identity() -> BridgeIdentity {
        BridgeIdentity {
            mode: "did:key".into(),
            agent_did: Some("did:key:zAgent".into()),
            vtc_did: Some(VTC_DID.into()),
            transport_choice: "auto".into(),
            reuse_warning: None,
            serving: "stdio".into(),
        }
    }

    fn bridge() -> VtcMcp {
        VtcMcp::degraded(
            "not connected in tests".into(),
            identity(),
            Guard {
                read_only: true,
                confirm: ConfirmLevel::Destructive,
                node: "VTC",
                ..Guard::default()
            },
            Arc::new(Recorder::default()),
        )
    }

    fn holder() -> HolderKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
        );
        let private = multibase::encode(multibase::Base::Base58Btc, signing.to_bytes());
        HolderKey::from_did_key(&did, private).unwrap()
    }

    /// A one-request community over loopback HTTP that answers `status` with
    /// `body` and hands back the document it received.
    async fn one_shot_vtc(
        status: &'static str,
        body: String,
    ) -> (String, tokio::task::JoinHandle<Value>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let head_end = loop {
                let mut chunk = [0u8; 4096];
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let length: usize = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::to_owned)
                })
                .map(|v| v.trim().parse().unwrap())
                .unwrap_or(0);
            let mut request = buf[head_end..].to_vec();
            while request.len() < length {
                let mut chunk = [0u8; 4096];
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
            }
            request.truncate(length);
            sock.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            sock.shutdown().await.ok();
            serde_json::from_slice(&request).unwrap()
        });
        (format!("http://127.0.0.1:{port}/v1"), served)
    }

    fn reply_doc(type_uri: &str, payload: Value) -> String {
        json!({
            "id": "urn:uuid:4d2c3f4e-1b2a-4c3d-8e9f-0a1b2c3d4e5f",
            "type": type_uri,
            "issuer": VTC_DID,
            "issuedAt": "2026-11-06T00:00:00Z",
            "payload": payload,
        })
        .to_string()
    }

    #[test]
    fn tool_router_exposes_the_expected_tools() {
        let router = VtcMcp::tool_router() + VtcMcp::workflow_router() + VtcMcp::signin_router();
        let expected = [
            "vtc_sign_in",
            "vtc_sign_in_finish",
            "vtc_sign_in_cancel",
            "vtc_enrol_signing_key",
            "vtc_list_operations",
            "vtc_call",
            "vtc_supported_tasks",
            "vtc_whoami",
            "vtc_status",
            "group_setup",
            "board_create",
            "election_create",
            "room_open",
            "member_admit",
            "admin_grant",
            "badge_create",
            "vtc_actions_list",
            "vtc_actions_show",
            "vtc_actions_decide",
            "vtc_actions_cancel",
        ];
        let have: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        for name in expected {
            assert!(router.has_route(name), "missing tool {name}; have {have:?}");
        }
        assert_eq!(have.len(), expected.len(), "unexpected tool set: {have:?}");
    }

    /// The Trust Task URI each tool routes through, or `None` for the local
    /// ones — a second copy of what the tool bodies pass to `begin`, so that
    /// changing one without the other is caught here.
    const TOOL_OPERATIONS: &[(&str, Option<&str>)] = &[
        ("vtc_list_operations", None),
        ("vtc_call", None), // classified per call, from the URI the caller names
        ("vtc_supported_tasks", Some(wire::DISCOVERY)),
        ("vtc_whoami", Some(wire::WHOAMI)),
        ("vtc_status", None),
        // The workflow tools: each step is classified under its own URI as it
        // is sent, so the tool itself claims what its riskiest step is.
        ("group_setup", None),
        ("board_create", None),
        ("election_create", None),
        ("room_open", None),
        ("member_admit", None),
        ("admin_grant", None),
        ("badge_create", None),
        (
            "vtc_actions_list",
            Some(crate::workflows::wire::ACTIONS_LIST),
        ),
        (
            "vtc_actions_show",
            Some(crate::workflows::wire::ACTIONS_SHOW),
        ),
        (
            "vtc_actions_decide",
            Some(crate::workflows::wire::CONSENT_DECISION),
        ),
        (
            "vtc_actions_cancel",
            Some(crate::workflows::wire::ACTIONS_CANCEL),
        ),
        ("vtc_sign_in", Some(vtc_client::signin::task::REQUEST)),
        ("vtc_sign_in_finish", Some(vtc_client::signin::task::REDEEM)),
        ("vtc_sign_in_cancel", Some(vtc_client::signin::task::CANCEL)),
        ("vtc_enrol_signing_key", Some(crate::signin::ENROLL)),
    ];

    /// The tools that never leave the process and only read.
    const LOCAL_READS: &[&str] = &["vtc_list_operations", "vtc_status"];

    /// Hosts render `readOnlyHint` and some gate on it, so each annotation is
    /// checked against the shared classifier's verdict on the URI the tool
    /// actually sends.
    #[test]
    fn tool_annotations_agree_with_the_risk_classifier() {
        for tool in
            (VtcMcp::tool_router() + VtcMcp::workflow_router() + VtcMcp::signin_router()).list_all()
        {
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("tool {} has no annotations", tool.name));
            assert!(
                annotations.title.is_some(),
                "tool {} has no title",
                tool.name
            );
            let (_, operation) = TOOL_OPERATIONS
                .iter()
                .find(|(name, _)| *name == &*tool.name)
                .unwrap_or_else(|| panic!("tool {} missing from TOOL_OPERATIONS", tool.name));
            let claims_read_only = annotations.read_only_hint.unwrap_or(false);
            match operation {
                Some(uri) => {
                    let risk = classify(uri);
                    let (read_only, destructive) = risk.hints();
                    assert_eq!(
                        claims_read_only, read_only,
                        "tool {} claims readOnlyHint={claims_read_only} but {uri} is {risk}",
                        tool.name
                    );
                    assert_eq!(
                        annotations.destructive_hint.unwrap_or(true),
                        destructive,
                        "tool {} destructiveHint disagrees with {uri} being {risk}",
                        tool.name
                    );
                }
                None => assert_eq!(
                    claims_read_only,
                    LOCAL_READS.contains(&&*tool.name),
                    "tool {} readOnlyHint is wrong for a tool classified per step",
                    tool.name
                ),
            }
        }
    }

    #[tokio::test]
    async fn the_catalog_is_the_pinned_index_with_risk_and_policy() {
        let bridge = bridge();
        let all = bridge.operations_catalog(&[], false).await;
        let count = all["count"].as_u64().unwrap();
        assert!(count > 250, "the catalog has {count} entries");
        assert_eq!(all["servedKnown"], json!(false));
        for op in all["operations"].as_array().unwrap() {
            let uri = op["operation"].as_str().unwrap();
            assert!(
                vti_specs::schema_index::is_pinned(uri),
                "{uri} is not pinned"
            );
            assert!(!uri.contains('#'));
            assert!(op["risk"].is_string() && op["policy"].is_string());
            assert_eq!(op["served"], Value::Null);
        }

        // A family glob narrows it, and `full` carries the schema and the
        // declared codes.
        let groups = bridge.operations_catalog(&["vtc/groups/*"], true).await;
        let ops = groups["operations"].as_array().unwrap();
        assert!(
            ops.iter()
                .all(|o| o["slug"].as_str().unwrap().starts_with("vtc/groups/"))
        );
        let create = ops
            .iter()
            .find(|o| o["operation"] == GROUPS_CREATE)
            .expect("groups/create is pinned");
        assert!(create["description"].as_str().unwrap().contains("group"));
        assert_eq!(create["payloadSchema"]["required"][0], "name");
        assert!(
            create["errorCodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == "vtc/groups/create:ruleInvalid")
        );
        // A read-only bridge refuses the create and allows the list.
        assert_eq!(create["policy"], "deny");
        let list = ops.iter().find(|o| o["slug"] == "vtc/groups/list").unwrap();
        assert_eq!(list["policy"], "allow");
    }

    #[tokio::test]
    async fn status_reports_the_degraded_state_rather_than_hiding_it() {
        let bridge = bridge();
        let status = bridge.status(10).await;
        assert_eq!(status["connected"], json!(false));
        assert_eq!(status["connectError"], json!("not connected in tests"));
        assert_eq!(status["identity"]["dedicatedAgent"], json!(true));
        assert_eq!(status["policy"]["readOnly"], json!(true));
        assert_eq!(status["transport"], Value::Null);
        let err = bridge
            .call_operation(GROUPS_CREATE, json!({}))
            .await
            .unwrap_err();
        assert!(err.message.contains("not connected"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_call_is_sent_as_a_signed_document_and_its_answer_returned() {
        let (base, served) = one_shot_vtc(
            "200 OK",
            reply_doc(
                &format!("{GROUPS_CREATE}#response"),
                json!({ "group": { "groupId": "grp_0123456789abcdef" } }),
            ),
        )
        .await;
        let client = Arc::new(VtcClient::with_key(&base, VTC_DID, holder()));
        let bridge = VtcMcp::new(
            client,
            identity(),
            Guard::default(),
            Arc::new(Recorder::default()),
        );
        assert_eq!(bridge.status(0).await["transport"], json!("HTTPS"));
        let payload = json!({
            "name": "Gardeners",
            "kind": "static",
            "visibility": "members",
            "showMembers": "members",
            "reason": "the allotment working group",
        });
        let answer = bridge
            .call_operation(GROUPS_CREATE, payload.clone())
            .await
            .unwrap();
        assert_eq!(answer["group"]["groupId"], "grp_0123456789abcdef");
        let document = served.await.unwrap();
        assert_eq!(document["type"], GROUPS_CREATE);
        assert_eq!(document["payload"], payload);
        assert_eq!(document["recipient"], VTC_DID);
        assert!(document["proof"].is_object());
    }

    #[tokio::test]
    async fn a_refusal_carries_the_communitys_document_and_an_unpinned_uri_sends_nothing() {
        let (base, served) = one_shot_vtc(
            "403 Forbidden",
            reply_doc(
                "https://trusttasks.org/spec/trust-task-error/0.3",
                json!({ "code": "permissionDenied", "message": "not a manager of this group" }),
            ),
        )
        .await;
        let client = Arc::new(VtcClient::with_key(&base, VTC_DID, holder()));
        let bridge = VtcMcp::new(
            client,
            identity(),
            Guard::default(),
            Arc::new(Recorder::default()),
        );
        let err = bridge
            .call_operation(
                GROUPS_CREATE,
                json!({
                    "name": "x", "kind": "static", "visibility": "members",
                    "showMembers": "members", "reason": "r",
                }),
            )
            .await
            .unwrap_err();
        assert!(err.message.contains("not a manager"), "{}", err.message);
        served.await.unwrap();

        // Nothing listens any more: an unpinned URI must be refused before a send.
        let err = bridge
            .call_operation(
                "https://trusttasks.org/spec/vtc/groups/create/9.9",
                json!({}),
            )
            .await
            .unwrap_err();
        assert!(err.message.contains("will not send"), "{}", err.message);
    }

    #[test]
    fn a_parked_answer_is_an_outcome_not_an_error() {
        let value = outcome(Err(VtcError::Parked {
            action_id: "act_1".into(),
            message: "needs two approvals".into(),
        }))
        .unwrap();
        assert_eq!(value["status"], "parked");
        assert_eq!(value["actionId"], "act_1");
    }

    /// VTI-LNK-127: a refusal with a hand-off becomes the `step-up` link for
    /// the person, never the inline request to approve; one without stays an
    /// error.
    #[test]
    fn vti_lnk_127_a_hand_off_becomes_the_persons_step_up_link() {
        let now = 1_791_460_800; // 2026-10-08T12:00:00Z
        let refusal = |handoff: Option<Value>| {
            let mut details = json!({
                "stepUpRequest": {
                    "subject": "did:key:z6Mkadmin",
                    "reason": "Invite an approver",
                    "challenge": "c",
                    "boundTo": "b",
                },
            });
            if let Some(h) = handoff {
                details["stepUpHandoff"] = h;
            }
            VtcError::Refused {
                document: json!({
                    "type": "https://trusttasks.org/spec/trust-task-error/0.3",
                    "issuer": VTC_DID,
                    "payload": { "code": "permissionDenied", "details": details },
                })
                .to_string(),
            }
        };
        let value = outcome_at(
            Err(refusal(Some(json!({
                "handle": "Hk2pQ9xV4mT7rW1sZ8yN3A",
                "expiresAt": "2026-10-08T12:04:00Z",
                "show": vtc_client::step_up::REQUESTS_SHOW,
            })))),
            now,
        )
        .unwrap();
        assert_eq!(value["status"], "stepUpRequired");
        assert_eq!(value["subject"], "did:key:z6Mkadmin");
        assert_eq!(value["linkExpiresAt"], now + 240);
        let link = value["link"].as_str().unwrap();
        assert!(
            link.starts_with("https://link.trustoverip.org/t#_from="),
            "{link}"
        );
        assert!(link.ends_with("&_type=/vti/flow/step-up/0.1"), "{link}");
        assert!(value.get("challenge").is_none() && value.get("boundTo").is_none());

        assert!(outcome_at(Err(refusal(None)), now).is_err());
    }

    /// #2594: a community's refusal is a tool result the model reads, with
    /// the community's own code, never `-32603 internal error`.
    #[test]
    fn a_refusal_is_a_tool_result_carrying_the_communitys_code() {
        let err = outcome(Err(VtcError::Refused {
            document: json!({
                "type": "https://trusttasks.org/spec/trust-task-error/0.3",
                "issuer": VTC_DID,
                "payload": { "code": "permissionDenied", "message": "not a manager" },
            })
            .to_string(),
        }))
        .unwrap_err();
        assert_eq!(err.kind, "refused");
        assert!(err.message.contains("not a manager"), "{}", err.message);
        assert_eq!(
            err.details.as_ref().unwrap()["code"],
            json!("permissionDenied")
        );
        assert!(err.next.as_deref().unwrap().contains("vtc_whoami"));

        let result = err.into_call_result();
        assert_eq!(result.is_error, Some(true));

        let unpinned = outcome(Err(VtcError::UnpinnedTask {
            type_uri: "https://trusttasks.org/spec/vtc/x/9.9".into(),
            reason: "not pinned".into(),
        }))
        .unwrap_err();
        assert_eq!(unpinned.kind, "notPinned");
    }

    /// Once the community has said what it serves, an operation outside that
    /// is refused before anything is sent, naming the versions it does serve.
    #[tokio::test]
    async fn an_operation_the_community_does_not_serve_is_not_sent() {
        // Nothing listens: a send would fail as a transport error.
        let client = Arc::new(VtcClient::with_key(
            "http://127.0.0.1:9/v1",
            VTC_DID,
            holder(),
        ));
        let bridge = VtcMcp::new(
            client,
            identity(),
            Guard::default(),
            Arc::new(Recorder::default()),
        );
        let served_version = GROUPS_CREATE.rsplit_once('/').unwrap().1.to_string();
        *bridge.served.write().await = Some(vec![GROUPS_CREATE.to_string()]);
        let family = GROUPS_CREATE.rsplit_once('/').unwrap().0;
        let err = bridge
            .call_operation(&format!("{family}/9.9"), json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.kind, "notServed");
        assert_eq!(
            err.details.as_ref().unwrap()["servedVersions"],
            json!([served_version])
        );
        assert!(check_served(GROUPS_CREATE, &[GROUPS_CREATE.to_string()]).is_none());
    }
}
