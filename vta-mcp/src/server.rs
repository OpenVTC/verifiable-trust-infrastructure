//! The MCP server handler: a bridge from MCP tool calls to the VTA.
//!
//! The whole VTA management surface is reachable through two generic tools —
//! `vta_list_operations` (the Trust Task catalog) and `vta_call` (invoke any
//! operation by URI) — so an MCP-speaking host (Claude Desktop, an agent
//! framework, …) can drive contexts, keys, acl, did-management, device, vault,
//! seeds, audit, backup, etc. with no custom code. Convenience `#[tool]`s wrap
//! the most common operations with typed schemas, plus the client-side bits
//! (`resolve_did`, `issue_vp`) that aren't Trust Tasks. Results are JSON content.
//!
//! Tools that touch secrets (`vault_release`) seal/open `didcomm-authcrypt`
//! envelopes and therefore require the underlying client to be on the DIDComm
//! transport; on REST they surface a clear error rather than failing opaquely.
//!
//! ## Three things every call goes through
//!
//! 1. **[`crate::guard`]** — the local per-operation gate, because an MCP host
//!    approves a *tool* and this bridge's most useful tool is "invoke any
//!    operation". Every convenience tool declares the Trust Task URI it wraps,
//!    so `--read-only` cannot be side-stepped by calling `sign` instead of
//!    `vta_call`.
//! 2. **[`crate::observability`]** — a start line, a finish line with duration
//!    and outcome, and a redacted record in the ring buffer (and the audit file
//!    when one is configured).
//! 3. **The VTA** — which is, and remains, the authority. Everything above is a
//!    second gate in front of it, never a substitute for it.
//!
//! Nothing here grants access. The bridge identity's role, ACL and context
//! scope decide what actually happens.

use std::sync::Arc;
use std::time::Instant;

use crate::guard::{Decision, Guard, Risk, classify};
use crate::observability::{CallRecord, Recorder, redact};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, ServerCapabilities, ServerInfo,
};
use rmcp::service::{Peer, RequestContext};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, elicit_safe, tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vta_sdk::agent_session::AgentSession;
use vta_sdk::error::VtaError;
use vta_sdk::protocols::key_management::sign::SignAlgorithm;

/// The Trust Task URI each convenience tool **actually sends**.
///
/// Not "the newest version of that task" — the one the SDK dispatches. The
/// audit log names the wire version that went out, and the local policy is
/// applied to the same string the VTA will see, so both have to track
/// `VtaClient`'s call sites rather than the freshest constant. Several are the
/// deprecated `0.1` forms for exactly that reason; they move when
/// `vta_sdk::client` moves, not before.
#[allow(deprecated)]
mod wire {
    use vta_sdk::trust_tasks as t;

    /// `trust-task-discovery/0.1` — what `supported_trust_tasks` asks.
    pub const DISCOVERY: &str = t::TASK_TRUST_TASK_DISCOVERY_0_1;
    /// `keys/list/0.1`.
    pub const KEYS_LIST: &str = t::TASK_KEYS_LIST_0_1;
    /// `keys/sign/0.1` — the signing oracle.
    pub const KEYS_SIGN: &str = t::TASK_KEYS_SIGN_0_1;
    /// `vault/list/0.1`.
    pub const VAULT_LIST: &str = t::TASK_VAULT_LIST_0_1;
    /// `vault/get/0.1`.
    pub const VAULT_GET: &str = t::TASK_VAULT_GET_0_1;
    /// `vault/release/0.1`.
    pub const VAULT_RELEASE: &str = t::TASK_VAULT_RELEASE_0_1;
    /// `device/heartbeat/0.1`.
    pub const DEVICE_HEARTBEAT: &str = t::TASK_DEVICE_HEARTBEAT_0_1;
}

/// Resource URI for the bridge's own state.
const RESOURCE_STATUS: &str = "vta://status";
/// Resource URI for the dispatchable operation catalog.
const RESOURCE_OPERATIONS: &str = "vta://operations";
/// Resource URI for the in-memory record of recent calls.
const RESOURCE_RECENT: &str = "vta://calls/recent";

/// Map an SDK error onto an MCP tool error. The VTA's typed errors carry the
/// operator-facing message; surface it verbatim to the agent.
fn to_mcp(e: VtaError) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Wrap a serializable result as an MCP tool result with pretty-printed JSON
/// text content. (Returning the raw `CallToolResult` rather than a typed
/// `Json<T>` avoids rmcp deriving an output schema — `serde_json::Value` has no
/// fixed object schema, which the MCP spec rejects.)
fn ok_json(value: impl serde::Serialize) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(&value)
        .map_err(|e| McpError::internal_error(format!("serialising result: {e}"), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupportedTasksParams {
    /// Slug-glob patterns, ORed. `*` matches every task; `acl/*` matches a
    /// family; anything else is an exact slug. Omit for everything.
    ///
    /// Patterns match the slug — the part after
    /// `https://trusttasks.org/spec/` — so `acl/*`, not the full URI. An
    /// unmatched pattern returns an empty list rather than an error, so a
    /// wrong prefix looks like "serves nothing".
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListKeysParams {
    /// Pagination offset (default 0).
    #[serde(default)]
    pub offset: Option<u64>,
    /// Max keys to return (default 50).
    #[serde(default)]
    pub limit: Option<u64>,
    /// Filter by key status (e.g. `active`).
    #[serde(default)]
    pub status: Option<String>,
    /// Filter by context id.
    #[serde(default)]
    pub context_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignParams {
    /// The key id to sign with (from `list_keys`).
    pub key_id: String,
    /// The UTF-8 text to sign. Its bytes are signed as-is.
    pub text: String,
    /// Signature algorithm: `EdDSA` (default) or `ES256`.
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultListParams {
    /// Optional wire filter object (e.g. `{ "contextId": "...", "tag": "..." }`).
    /// Omit for all entries the caller can read.
    #[serde(default)]
    pub filters: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultGetParams {
    /// The vault entry id.
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultReleaseParams {
    /// The vault entry id to release.
    pub id: String,
    /// Optional site-target object the release is scoped to.
    #[serde(default)]
    pub target: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeviceHeartbeatParams {
    /// Updated platform string, if changed.
    #[serde(default)]
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VtaCallParams {
    /// The Trust Task operation URI to invoke (from `vta_list_operations`),
    /// e.g. `https://trusttasks.org/spec/contexts/list/1.0`.
    pub operation: String,
    /// The operation's request payload as a JSON object. Omit (or `{}`) for
    /// operations that take no parameters.
    #[serde(default)]
    pub payload: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveDidParams {
    /// The DID to resolve (any method the resolver supports).
    pub did: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IssueVpParams {
    /// The verifier's `presentation_definition` (DCQL query) as JSON.
    pub presentation_definition: Value,
    /// The credentials the agent holds, as a JSON array of
    /// `{ id, format, claims, vc, vct?, doctype?, supportsHolderBinding? }`.
    pub held_credentials: Value,
    /// The verifier's challenge nonce, bound into the VP proof.
    pub nonce: String,
    /// The verifier (audience) the VP is bound to.
    pub audience: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StatusParams {
    /// How many recent calls to include (default 10, max 100). Pass 0 for none.
    #[serde(default)]
    pub recent_calls: Option<usize>,
}

// A single boolean, deliberately: an elicitation form the operator has to read
// carefully is one they will stop reading. The *message* carries the operation
// name and its risk class; the answer is yes or no.
//
// Note the doc comment below is not an internal one — `schemars` copies it into
// the elicitation schema, so the host renders it to the operator. Keep it to
// what a person answering a prompt needs.
/// Approve this VTA operation?
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Approval {
    /// Approve this operation? Answering no refuses the call.
    pub approve: bool,
}
elicit_safe!(Approval);

/// The agent's own holder identity, used to sign Verifiable Presentations
/// locally (the key never leaves this process). Configured out-of-band — never
/// supplied over MCP.
#[derive(Clone)]
pub struct HolderIdentity {
    /// The holder DID.
    pub did: String,
    /// Verification-method fragment (e.g. `key-0`).
    pub vm_fragment: String,
    /// The holder Ed25519 signing key, multibase-encoded.
    pub key_multibase: String,
}

/// Who this bridge is authenticated as — resolved before connecting, so it can
/// be reported even when the connection failed.
#[derive(Debug, Clone, Default)]
pub struct BridgeIdentity {
    /// The [`vta_sdk::agent_connect::ConnectMode`] label.
    pub mode: String,
    /// The agent's own DID, in the two DIDComm modes.
    pub agent_did: Option<String>,
    /// The VTA being talked to.
    pub vta_did: Option<String>,
    /// The mediator DIDComm rides.
    pub mediator_did: Option<String>,
    /// Whether this is a dedicated agent identity rather than a replayed
    /// operator login. Reported because it is the single most important fact
    /// about how much damage a compromised host could do.
    pub dedicated_agent: bool,
}

impl BridgeIdentity {
    fn to_json(&self) -> Value {
        json!({
            "mode": self.mode,
            "agentDid": self.agent_did,
            "vtaDid": self.vta_did,
            "mediatorDid": self.mediator_did,
            "dedicatedAgent": self.dedicated_agent,
        })
    }
}

/// MCP server bridging to a single authenticated agent session.
#[derive(Clone)]
pub struct VtaMcp {
    /// `None` when the initial connect failed — see [`VtaMcp::degraded`].
    agent: Option<Arc<AgentSession>>,
    /// Why the connect failed, in degraded mode.
    connect_error: Option<Arc<str>>,
    identity: Arc<BridgeIdentity>,
    /// Optional holder identity enabling the `issue_vp` tool.
    holder: Option<Arc<HolderIdentity>>,
    guard: Arc<Guard>,
    recorder: Arc<Recorder>,
    started: Arc<str>,
}

/// One in-flight guarded call. Created by [`VtaMcp::begin`], consumed by
/// [`CallGuard::finish`] — which is what writes the finish line and the audit
/// record, so a tool cannot return without being recorded.
struct CallGuard {
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
    /// Record the outcome and hand back the result unchanged.
    fn finish(self, result: Result<Value, McpError>) -> Result<CallToolResult, McpError> {
        let duration_ms = self.started.elapsed().as_millis();
        let (outcome, error) = match &result {
            Ok(_) => ("ok", None),
            Err(e) => ("error", Some(e.message.to_string())),
        };
        self.emit(outcome, error, duration_ms);
        match result {
            Ok(value) => ok_json(value),
            Err(e) => Err(e),
        }
    }

    /// Record a call that never reached the VTA.
    fn refuse(self, outcome: &'static str, message: String) -> Result<CallToolResult, McpError> {
        let duration_ms = self.started.elapsed().as_millis();
        self.emit(outcome, Some(message.clone()), duration_ms);
        Err(McpError::invalid_request(message, None))
    }

    fn emit(&self, outcome: &'static str, error: Option<String>, duration_ms: u128) {
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
impl VtaMcp {
    /// A connected bridge.
    pub fn new(
        agent: Arc<AgentSession>,
        holder: Option<Arc<HolderIdentity>>,
        identity: BridgeIdentity,
        guard: Guard,
        recorder: Arc<Recorder>,
    ) -> Self {
        Self {
            agent: Some(agent),
            connect_error: None,
            identity: Arc::new(identity),
            holder,
            guard: Arc::new(guard),
            recorder,
            started: crate::observability::now_rfc3339().into(),
        }
    }

    /// A bridge that failed to connect but serves MCP anyway.
    ///
    /// A server that exits before it speaks MCP appears to the host as *no
    /// tools at all* — the model cannot even report the problem, and the
    /// operator sees an empty tool list with no explanation. Serving in a
    /// degraded state means `vta_status` still answers, every other tool
    /// returns the connect error verbatim, and the failure is legible from
    /// inside the session that hit it.
    pub fn degraded(
        error: String,
        holder: Option<Arc<HolderIdentity>>,
        identity: BridgeIdentity,
        guard: Guard,
        recorder: Arc<Recorder>,
    ) -> Self {
        Self {
            agent: None,
            connect_error: Some(error.into()),
            identity: Arc::new(identity),
            holder,
            guard: Arc::new(guard),
            recorder,
            started: crate::observability::now_rfc3339().into(),
        }
    }

    /// The VTA client behind the session — every tool that talks to the VTA
    /// routes through this, and it is the single place the degraded state is
    /// turned into an error a model can read.
    fn client(&self) -> Result<&vta_sdk::client::VtaClient, McpError> {
        match &self.agent {
            Some(agent) => Ok(agent.client()),
            None => Err(McpError::internal_error(
                format!(
                    "this vta-mcp bridge is not connected to its VTA: {}. Fix the connection and \
                     restart the MCP server; `vta_status` reports the configuration it tried.",
                    self.connect_error.as_deref().unwrap_or("unknown error")
                ),
                None,
            )),
        }
    }

    /// Gate, log and (where the policy asks) confirm one call.
    ///
    /// `operation` is the Trust Task URI the tool resolves to — `None` only for
    /// the two purely local tools. `args` is passed through [`redact`] here, so
    /// no caller can forget to.
    async fn begin(
        &self,
        tool: &'static str,
        operation: Option<&str>,
        args: Value,
        peer: &Peer<RoleServer>,
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
            args: redact(&args),
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
                Err(Box::new(guard.refuse("denied", reason)))
            }
            Decision::Confirm(prompt) => match self.confirm(peer, &prompt).await {
                Ok(true) => Ok(guard),
                Ok(false) => Err(Box::new(
                    guard.refuse("declined", format!("{prompt} — declined by the operator.")),
                )),
                Err(reason) => Err(Box::new(guard.refuse("denied", reason))),
            },
        }
    }

    /// Ask the human. `Err` means no answer could be obtained at all, which is
    /// refused rather than waved through — a confirmation gate that fails open
    /// is not a gate.
    async fn confirm(&self, peer: &Peer<RoleServer>, prompt: &str) -> Result<bool, String> {
        match peer.elicit::<Approval>(prompt.to_string()).await {
            Ok(Some(approval)) => Ok(approval.approve),
            Ok(None) => Ok(false),
            Err(rmcp::service::ElicitationError::UserDeclined)
            | Err(rmcp::service::ElicitationError::UserCancelled)
            | Err(rmcp::service::ElicitationError::NoContent) => Ok(false),
            Err(rmcp::service::ElicitationError::CapabilityNotSupported) => Err(format!(
                "{prompt} — this MCP host cannot ask you (it does not support elicitation), so the \
                 bridge refused rather than proceeding unconfirmed. Restart vta-mcp with \
                 `--confirm never` to drop the prompt, or `--allow <slug>` to permit just this \
                 operation."
            )),
            Err(e) => Err(format!("{prompt} — could not obtain confirmation: {e}")),
        }
    }

    /// Replaces the old `vta_capabilities` tool, which #1043 retired along with
    /// the task behind it.
    ///
    /// The rename is not cosmetic: the old tool promised "enabled features,
    /// advertised services, WebVH servers, and DID-creation modes" — four
    /// answers, three of which were better held elsewhere and one of which
    /// (`didCreationModes`) described a vocabulary nothing else used. What an
    /// agent actually needs before calling something is whether the VTA serves
    /// it, and that is a question with a canonical answer.
    #[tool(
        description = "Discover which Trust Tasks the connected VTA serves. Optionally narrow with \
                       slug-glob patterns such as 'acl/*' or 'vta/webvh/*'; omit for everything. \
                       Ask this before assuming an operation exists — calling one the VTA does not \
                       serve fails as a transport timeout rather than a clear error.",
        annotations(
            title = "Supported Trust Tasks",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vta_supported_tasks(
        &self,
        Parameters(p): Parameters<SupportedTasksParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vta_supported_tasks",
                Some(wire::DISCOVERY),
                json!({ "patterns": p.patterns }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let patterns: Vec<&str> = p.patterns.iter().map(String::as_str).collect();
        let result = match self.client() {
            Ok(client) => client
                .supported_trust_tasks(&patterns)
                .await
                .map(|t| json!(t))
                .map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "List the signing keys available on the VTA.",
        annotations(
            title = "List keys",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_keys(
        &self,
        Parameters(p): Parameters<ListKeysParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "list_keys",
                Some(wire::KEYS_LIST),
                json!({
                    "offset": p.offset,
                    "limit": p.limit,
                    "status": p.status,
                    "contextId": p.context_id,
                }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => client
                .list_keys(
                    p.offset.unwrap_or(0),
                    p.limit.unwrap_or(50),
                    p.status.as_deref(),
                    p.context_id.as_deref(),
                )
                .await
                .map(|k| json!(k))
                .map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Sign UTF-8 text with a VTA-held key via the signing oracle (the private key \
                       never leaves the VTA). Returns the signature.",
        annotations(
            title = "Sign with a VTA key",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn sign(
        &self,
        Parameters(p): Parameters<SignParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // `text` is deliberately not in the recorded arguments — `redact` elides
        // it, and what gets signed is the caller's business, not the log's.
        let call = match self
            .begin(
                "sign",
                Some(wire::KEYS_SIGN),
                json!({ "keyId": p.key_id, "algorithm": p.algorithm, "text": p.text }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let algorithm = match p.algorithm.as_deref() {
            Some("ES256") | Some("es256") => SignAlgorithm::ES256,
            Some("EdDSA") | Some("eddsa") | None => SignAlgorithm::EdDSA,
            Some(other) => {
                return call.refuse(
                    "error",
                    format!("unknown algorithm '{other}' (expected EdDSA or ES256)"),
                );
            }
        };
        let result = match self.client() {
            Ok(client) => client
                .sign(&p.key_id, p.text.as_bytes(), algorithm)
                .await
                .map(|resp| {
                    // `SignResponse` is deserialize-only; project its fields.
                    json!({
                        "keyId": resp.key_id,
                        "signature": resp.signature,
                        "algorithm": resp.algorithm,
                    })
                })
                .map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "List secrets-vault entry metadata (no secret material).",
        annotations(
            title = "List vault entries",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vault_list(
        &self,
        Parameters(p): Parameters<VaultListParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let filters = p.filters.unwrap_or_else(|| json!({}));
        let call = match self
            .begin(
                "vault_list",
                Some(wire::VAULT_LIST),
                json!({ "filters": filters }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => client.vault_list(filters).await.map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Fetch a single vault entry's metadata by id (no secret material).",
        annotations(
            title = "Get a vault entry",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vault_get(
        &self,
        Parameters(p): Parameters<VaultGetParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vault_get",
                Some(wire::VAULT_GET),
                json!({ "id": p.id }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => client.vault_get(&p.id).await.map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Release a vault secret sealed to this client and return the cleartext. \
                       Requires the DIDComm transport (the secret is opened with the client's own \
                       keys). The cleartext enters the model's context — do not call it to 'check' \
                       a secret exists; use vault_get for that.",
        annotations(
            title = "Release a vault secret",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vault_release(
        &self,
        Parameters(p): Parameters<VaultReleaseParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "vault_release",
                Some(wire::VAULT_RELEASE),
                json!({ "id": p.id, "target": p.target }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = self.release_secret(&p).await;
        call.finish(result)
    }

    /// The two-step release: ask the VTA for the sealed envelope, then open it
    /// locally with this client's own keys.
    async fn release_secret(&self, p: &VaultReleaseParams) -> Result<Value, McpError> {
        let client = self.client()?;
        let response = client
            .vault_release_entry(&p.id, p.target.clone())
            .await
            .map_err(to_mcp)?;
        match response
            .get("sealedSecret")
            .and_then(|s| s.get("jwe"))
            .and_then(|j| j.as_str())
        {
            Some(jwe) => client.open_sealed_secret(jwe).await.map_err(to_mcp),
            // No openable envelope (e.g. an unsupported variant) — hand back the
            // raw response so the caller can see what came back.
            None => Ok(response),
        }
    }

    #[tool(
        description = "Check this device in with the VTA (refreshes last-seen) and return any \
                       queued operations.",
        annotations(
            title = "Device heartbeat",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn device_heartbeat(
        &self,
        Parameters(p): Parameters<DeviceHeartbeatParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin(
                "device_heartbeat",
                Some(wire::DEVICE_HEARTBEAT),
                json!({ "platform": p.platform }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => client
                .device_heartbeat(p.platform.as_deref())
                .await
                .map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "List every VTA operation reachable via `vta_call` — the catalog of \
                       dispatcher-routed Trust Task URIs (contexts, keys, acl, did-management, \
                       webvh, did-templates, device, vault, seeds, audit, backup, discovery, …), \
                       each with the risk class this bridge assigns it and whether its local \
                       policy would allow, confirm or refuse it. Pre-login auth and attestation \
                       are excluded (handled by the bridge itself / not vta_call-able).",
        annotations(
            title = "List VTA operations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vta_list_operations(
        &self,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin("vta_list_operations", None, json!({}), &peer)
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        call.finish(Ok(self.operations_catalog()))
    }

    /// The catalog `vta_call` can reach, annotated with this bridge's own view
    /// of each entry. Shared with the `vta://operations` resource.
    fn operations_catalog(&self) -> Value {
        // Exactly the set `vta_call` can invoke — ALL_URIS minus the REST-routed
        // (pre-login auth + attestation) operations.
        let mut uris = vta_sdk::trust_tasks::dispatch_routed_uris();
        uris.sort_unstable();
        let operations: Vec<Value> = uris
            .into_iter()
            .map(|uri| {
                json!({
                    "operation": uri,
                    "risk": classify(uri).label(),
                    "policy": self.guard.decide(uri).label(),
                })
            })
            .collect();
        json!({ "policy": self.guard.summary(), "operations": operations })
    }

    #[tool(
        description = "Invoke ANY VTA Trust Task operation by URI with a JSON payload — the \
                       generic gateway to the full management surface (contexts, keys, acl, \
                       did-management, device, vault, seeds, audit, backup, …). Use \
                       `vta_list_operations` to discover URIs and to see which ones this bridge \
                       will allow. Subject to the bridge identity's role/ACL at the VTA, and to \
                       the bridge's own local policy.",
        annotations(
            title = "Call any VTA operation",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn vta_call(
        &self,
        Parameters(p): Parameters<VtaCallParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let payload = p.payload.unwrap_or_else(|| json!({}));
        let call = match self
            .begin(
                "vta_call",
                Some(&p.operation),
                json!({ "operation": p.operation, "payload": payload }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => client
                .dispatch_trust_task(&p.operation, payload, 30)
                .await
                .map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Resolve any DID to its DID document via the shared resolver cache \
                       (independent of the VTA's own identity).",
        annotations(
            title = "Resolve a DID",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn resolve_did(
        &self,
        Parameters(p): Parameters<ResolveDidParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self
            .begin("resolve_did", None, json!({ "did": p.did }), &peer)
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let result = match self.client() {
            Ok(client) => client
                .resolve_did(&p.did)
                .await
                .map(|d| json!(d))
                .map_err(to_mcp),
            Err(e) => Err(e),
        };
        call.finish(result)
    }

    #[tool(
        description = "Issue a holder-bound Verifiable Presentation (OID4VP vp_token) for a \
                       verifier's presentation_definition from the supplied held credentials, \
                       signed with this agent's holder key. Requires the bridge to be configured \
                       with a holder identity.",
        annotations(
            title = "Issue a Verifiable Presentation",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn issue_vp(
        &self,
        Parameters(p): Parameters<IssueVpParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Not a Trust Task — it never reaches the VTA — but it signs with a key
        // this process holds, so it is classified and gated as `keys/sign`
        // would be. A bridge running `--read-only` must not be a signing
        // oracle by another name.
        let call = match self
            .begin(
                "issue_vp",
                Some(wire::KEYS_SIGN),
                json!({ "audience": p.audience, "nonce": p.nonce }),
                &peer,
            )
            .await
        {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let Some(holder) = self.holder.clone() else {
            return call.refuse(
                "error",
                "issue_vp is unavailable: no holder identity configured (set VTA_MCP_HOLDER_DID + \
                 VTA_MCP_HOLDER_KEY)"
                    .to_string(),
            );
        };
        let held: Vec<vta_sdk::vp::HeldCredential> =
            match serde_json::from_value(p.held_credentials) {
                Ok(held) => held,
                Err(e) => return call.refuse("error", format!("held_credentials: {e}")),
            };
        let result = vta_sdk::vp::issue_vp_token(
            &holder.did,
            &holder.vm_fragment,
            &holder.key_multibase,
            &p.presentation_definition,
            &held,
            &p.nonce,
            &p.audience,
        )
        .await
        .map(|token| json!(token))
        .map_err(|e| McpError::internal_error(format!("issue_vp: {e}"), None));
        call.finish(result)
    }

    #[tool(
        description = "Report what this bridge is: which identity it authenticated as, which \
                       transports it is using, its local operation policy, how many calls it has \
                       served, and the most recent ones. Ask this first when a VTA tool fails or \
                       behaves unexpectedly.",
        annotations(
            title = "Bridge status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vta_status(
        &self,
        Parameters(p): Parameters<StatusParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call = match self.begin("vta_status", None, json!({}), &peer).await {
            Ok(call) => call,
            Err(refused) => return *refused,
        };
        let limit = p.recent_calls.unwrap_or(10).min(100);
        call.finish(Ok(self.status(limit)))
    }

    /// The status document, shared by the tool and the `vta://status` resource.
    fn status(&self, recent: usize) -> Value {
        let transports = match self.agent.as_ref().map(|a| a.client()) {
            Some(client) => json!({
                "trustTasks": client.trust_task_transport().to_string(),
                "protocolMessages": client.protocol_message_transport().to_string(),
            }),
            None => Value::Null,
        };
        json!({
            "connected": self.agent.is_some(),
            "connectError": self.connect_error.as_deref(),
            "startedAt": &*self.started,
            "version": env!("CARGO_PKG_VERSION"),
            "identity": self.identity.to_json(),
            "transports": transports,
            "policy": {
                "summary": self.guard.summary(),
                "readOnly": self.guard.read_only,
                "confirm": self.guard.confirm.label(),
                "allow": self.guard.allow,
                "deny": self.guard.deny,
            },
            "holderIdentity": self.holder.as_ref().map(|h| json!({
                "did": h.did,
                "verificationMethod": format!("{}#{}", h.did, h.vm_fragment),
            })),
            "calls": self.recorder.counters().snapshot(),
            "auditLog": self.recorder.audit_path().map(|p| p.display().to_string()),
            "recentCalls": self.recorder.recent(recent),
        })
    }
}

#[tool_handler]
impl ServerHandler for VtaMcp {
    fn get_info(&self) -> ServerInfo {
        // `Implementation` / `InitializeResult` are `#[non_exhaustive]`, so build
        // them via constructors + field assignment rather than struct literals.
        let mut server_info = Implementation::from_build_env();
        server_info.name = "vta-mcp".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();

        // Tools and resources only. The MCP `logging` capability would put
        // these lines in the host's UI, but it is deprecated by SEP-2577 and
        // slated for removal — the runtime log goes to stderr (which hosts
        // capture) and the call record is readable as `vta://calls/recent`.
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(server_info)
        .with_instructions(
            "Bridges a Verifiable Trust Agent (VTA) to MCP. Convenience tools: \
             vta_supported_tasks, list_keys, sign (signing oracle), vault_list, vault_get, \
             vault_release (DIDComm only), device_heartbeat, resolve_did, issue_vp. For the FULL \
             management surface (contexts, keys, acl, did-management, webvh, did-templates, \
             device, vault, seeds, audit, backup, …) use vta_list_operations to discover operation \
             URIs and vta_call to invoke any of them. Call vta_status when anything fails — it \
             reports the bridge's identity, transports, local policy and recent calls. \
             All access is bounded by the bridge identity's VTA role/ACL, and additionally by this \
             bridge's local policy: some operations are refused outright and some ask the operator \
             to approve them first. Secrets never leave the VTA except via vault_release / \
             issue_vp to this client, and vault_release puts cleartext in the conversation.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(RESOURCE_STATUS, "VTA bridge status")
                .with_description(
                    "Identity, transports, local policy, call counters and recent calls.",
                )
                .with_mime_type("application/json"),
            Resource::new(RESOURCE_OPERATIONS, "VTA operation catalog")
                .with_description(
                    "Every Trust Task URI vta_call can reach, with its risk class and this \
                     bridge's policy decision.",
                )
                .with_mime_type("application/json"),
            Resource::new(RESOURCE_RECENT, "Recent VTA calls")
                .with_description(
                    "The last 100 calls this bridge served, redacted — what it has been doing.",
                )
                .with_mime_type("application/json"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let body = match request.uri.as_str() {
            RESOURCE_STATUS => self.status(10),
            RESOURCE_OPERATIONS => self.operations_catalog(),
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
    use crate::guard::ConfirmLevel;

    fn bridge() -> VtaMcp {
        VtaMcp::degraded(
            "not connected in tests".into(),
            None,
            BridgeIdentity {
                mode: "did:key-didcomm".into(),
                agent_did: Some("did:key:zAgent".into()),
                vta_did: Some("did:webvh:example.com:vta".into()),
                mediator_did: Some("did:key:zMed".into()),
                dedicated_agent: true,
            },
            Guard {
                read_only: true,
                confirm: ConfirmLevel::Destructive,
                ..Guard::default()
            },
            Arc::new(Recorder::default()),
        )
    }

    /// The generated tool router must expose exactly the bridge's tool set —
    /// guards against a tool being dropped or renamed without notice.
    #[test]
    fn tool_router_exposes_the_expected_tools() {
        let router = VtaMcp::tool_router();
        let expected = [
            "vta_supported_tasks",
            "list_keys",
            "sign",
            "vault_list",
            "vault_get",
            "vault_release",
            "device_heartbeat",
            "vta_list_operations",
            "vta_call",
            "resolve_did",
            "issue_vp",
            "vta_status",
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

    /// The Trust Task URI each tool routes through, or `None` for the two that
    /// never leave the process. A second copy of what the tool bodies pass to
    /// `begin` — deliberately, so that changing one without the other is caught
    /// here rather than in production.
    const TOOL_OPERATIONS: &[(&str, Option<&str>)] = &[
        ("vta_supported_tasks", Some(wire::DISCOVERY)),
        ("list_keys", Some(wire::KEYS_LIST)),
        ("sign", Some(wire::KEYS_SIGN)),
        ("vault_list", Some(wire::VAULT_LIST)),
        ("vault_get", Some(wire::VAULT_GET)),
        ("vault_release", Some(wire::VAULT_RELEASE)),
        ("device_heartbeat", Some(wire::DEVICE_HEARTBEAT)),
        ("vta_list_operations", None),
        ("vta_call", None), // classified per call, from the URI the caller names
        ("resolve_did", None),
        ("issue_vp", Some(wire::KEYS_SIGN)),
        ("vta_status", None),
    ];

    /// Hosts render `readOnlyHint` and some gate on it, so a mutating tool
    /// claiming to be read-only is a security bug, not a cosmetic one. Each
    /// annotation is checked against the *classifier's* verdict on the URI the
    /// tool actually calls, so the two cannot drift apart.
    #[test]
    fn tool_annotations_agree_with_the_risk_classifier() {
        for tool in VtaMcp::tool_router().list_all() {
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("tool {} has no annotations", tool.name));
            assert!(
                annotations.title.is_some(),
                "tool {} has no annotation title",
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
                        "tool {} claims readOnlyHint={claims_read_only} but {uri} classifies as \
                         {risk}",
                        tool.name
                    );
                    assert_eq!(
                        annotations.destructive_hint.unwrap_or(true),
                        destructive,
                        "tool {} destructiveHint disagrees with {uri} being {risk}",
                        tool.name
                    );
                }
                // The local-only tools: two reads and the generic gateway,
                // which is annotated destructive because it can be.
                None => assert_eq!(
                    claims_read_only,
                    tool.name != "vta_call",
                    "tool {} readOnlyHint is wrong for a local-only tool",
                    tool.name
                ),
            }
        }
    }

    /// Every tool that reaches the VTA must declare the URI it wraps, or the
    /// local policy is unenforceable on it. The two local-only tools are the
    /// documented exceptions.
    #[test]
    fn the_convenience_tools_are_gated_under_a_real_uri() {
        let bridge = bridge();
        // `sign` is Sensitive, so a --read-only bridge refuses it even though
        // the operator never typed `keys/sign`.
        assert!(matches!(
            bridge.guard.decide(wire::KEYS_SIGN),
            Decision::Deny(_)
        ));
        assert!(matches!(
            bridge.guard.decide(wire::VAULT_RELEASE),
            Decision::Deny(_)
        ));
        // Reads still pass.
        assert_eq!(bridge.guard.decide(wire::KEYS_LIST), Decision::Allow);
    }

    #[test]
    fn status_reports_the_degraded_state_rather_than_hiding_it() {
        let bridge = bridge();
        let status = bridge.status(10);
        assert_eq!(status["connected"], json!(false));
        assert_eq!(status["connectError"], json!("not connected in tests"));
        assert_eq!(status["identity"]["dedicatedAgent"], json!(true));
        assert_eq!(status["policy"]["readOnly"], json!(true));
        assert_eq!(status["transports"], Value::Null);
    }

    #[test]
    fn a_degraded_bridge_explains_itself_instead_of_panicking() {
        let bridge = bridge();
        // `VtaClient` is not `Debug`, so `unwrap_err` is unavailable.
        let Err(err) = bridge.client() else {
            panic!("a degraded bridge must not hand out a client");
        };
        assert!(err.message.contains("not connected in tests"), "{err:?}");
        assert!(err.message.contains("vta_status"), "{err:?}");
    }

    #[test]
    fn the_operations_catalog_carries_risk_and_policy() {
        let bridge = bridge();
        let catalog = bridge.operations_catalog();
        let ops = catalog["operations"].as_array().unwrap();
        assert!(!ops.is_empty());
        for op in ops {
            assert!(op["risk"].is_string(), "{op}");
            assert!(op["policy"].is_string(), "{op}");
        }
        // A --read-only bridge must say so in the catalog, not only at call
        // time — the model reads this to decide what to attempt.
        assert!(
            ops.iter()
                .any(|o| o["policy"] == json!("deny") && o["risk"] == json!("destructive"))
        );
    }
}
