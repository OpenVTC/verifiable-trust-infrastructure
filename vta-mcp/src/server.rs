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
//! All access is bounded by the bridge identity's VTA role/ACL.

use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use vta_sdk::agent_session::AgentSession;
use vta_sdk::error::VtaError;
use vta_sdk::protocols::key_management::sign::SignAlgorithm;

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
    Ok(CallToolResult::success(vec![Content::text(text)]))
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

/// MCP server bridging to a single authenticated agent session.
#[derive(Clone)]
pub struct VtaMcp {
    agent: Arc<AgentSession>,
    /// Optional holder identity enabling the `issue_vp` tool.
    holder: Option<Arc<HolderIdentity>>,
}

#[tool_router]
impl VtaMcp {
    pub fn new(agent: Arc<AgentSession>, holder: Option<Arc<HolderIdentity>>) -> Self {
        Self { agent, holder }
    }

    /// The VTA client behind the session — every tool routes through this.
    fn client(&self) -> &vta_sdk::client::VtaClient {
        self.agent.client()
    }

    #[tool(
        description = "Discover the connected VTA's capabilities: enabled features, advertised services, WebVH servers, and supported DID-creation modes."
    )]
    async fn vta_capabilities(&self) -> Result<CallToolResult, McpError> {
        let caps = self.client().capabilities().await.map_err(to_mcp)?;
        ok_json(caps)
    }

    #[tool(description = "List the signing keys available on the VTA.")]
    async fn list_keys(
        &self,
        Parameters(p): Parameters<ListKeysParams>,
    ) -> Result<CallToolResult, McpError> {
        let keys = self
            .client()
            .list_keys(
                p.offset.unwrap_or(0),
                p.limit.unwrap_or(50),
                p.status.as_deref(),
                p.context_id.as_deref(),
            )
            .await
            .map_err(to_mcp)?;
        ok_json(keys)
    }

    #[tool(
        description = "Sign UTF-8 text with a VTA-held key via the signing oracle (the private key never leaves the VTA). Returns the signature."
    )]
    async fn sign(
        &self,
        Parameters(p): Parameters<SignParams>,
    ) -> Result<CallToolResult, McpError> {
        let algorithm = match p.algorithm.as_deref() {
            Some("ES256") | Some("es256") => SignAlgorithm::ES256,
            Some("EdDSA") | Some("eddsa") | None => SignAlgorithm::EdDSA,
            Some(other) => {
                return Err(McpError::invalid_params(
                    format!("unknown algorithm '{other}' (expected EdDSA or ES256)"),
                    None,
                ));
            }
        };
        let resp = self
            .client()
            .sign(&p.key_id, p.text.as_bytes(), algorithm)
            .await
            .map_err(to_mcp)?;
        // `SignResponse` is deserialize-only; project its fields into JSON.
        ok_json(serde_json::json!({
            "keyId": resp.key_id,
            "signature": resp.signature,
            "algorithm": resp.algorithm,
        }))
    }

    #[tool(description = "List secrets-vault entry metadata (no secret material).")]
    async fn vault_list(
        &self,
        Parameters(p): Parameters<VaultListParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = self
            .client()
            .vault_list(p.filters.unwrap_or_else(|| serde_json::json!({})))
            .await
            .map_err(to_mcp)?;
        ok_json(result)
    }

    #[tool(description = "Fetch a single vault entry's metadata by id (no secret material).")]
    async fn vault_get(
        &self,
        Parameters(p): Parameters<VaultGetParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = self.client().vault_get(&p.id).await.map_err(to_mcp)?;
        ok_json(result)
    }

    #[tool(
        description = "Release a vault secret sealed to this client and return the cleartext. Requires the DIDComm transport (the secret is opened with the client's own keys)."
    )]
    async fn vault_release(
        &self,
        Parameters(p): Parameters<VaultReleaseParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut payload = serde_json::json!({ "id": p.id });
        if let Some(t) = p.target {
            payload["target"] = t;
        }
        let response = self.client().vault_release(payload).await.map_err(to_mcp)?;
        match response
            .get("sealedSecret")
            .and_then(|s| s.get("jwe"))
            .and_then(|j| j.as_str())
        {
            Some(jwe) => {
                let secret = self
                    .client()
                    .open_sealed_secret(jwe)
                    .await
                    .map_err(to_mcp)?;
                ok_json(secret)
            }
            // No openable envelope (e.g. an unsupported variant) — hand back the
            // raw response so the caller can see what came back.
            None => ok_json(response),
        }
    }

    #[tool(
        description = "Check this device in with the VTA (refreshes last-seen) and return any queued operations."
    )]
    async fn device_heartbeat(
        &self,
        Parameters(p): Parameters<DeviceHeartbeatParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = self
            .client()
            .device_heartbeat(p.platform.as_deref())
            .await
            .map_err(to_mcp)?;
        ok_json(result)
    }

    #[tool(
        description = "List every VTA operation reachable via `vta_call` — the catalog of dispatcher-routed Trust Task URIs (contexts, keys, acl, did-management, webvh, did-templates, device, vault, seeds, audit, backup, discovery, …). Pre-login auth and attestation are excluded (handled by the bridge itself / not vta_call-able)."
    )]
    async fn vta_list_operations(&self) -> Result<CallToolResult, McpError> {
        // Exactly the set `vta_call` can invoke — ALL_URIS minus the REST-routed
        // (pre-login auth + attestation) operations.
        let mut ops = vta_sdk::trust_tasks::dispatch_routed_uris();
        ops.sort_unstable();
        ok_json(serde_json::json!({ "operations": ops }))
    }

    #[tool(
        description = "Invoke ANY VTA Trust Task operation by URI with a JSON payload — the generic gateway to the full management surface (contexts, keys, acl, did-management, device, vault, seeds, audit, backup, …). Use `vta_list_operations` to discover URIs. Subject to the bridge identity's role/ACL."
    )]
    async fn vta_call(
        &self,
        Parameters(p): Parameters<VtaCallParams>,
    ) -> Result<CallToolResult, McpError> {
        let payload = p.payload.unwrap_or_else(|| serde_json::json!({}));
        let result = self
            .client()
            .dispatch_trust_task(&p.operation, payload, 30)
            .await
            .map_err(to_mcp)?;
        ok_json(result)
    }

    #[tool(
        description = "Resolve any DID to its DID document via the shared resolver cache (independent of the VTA's own identity)."
    )]
    async fn resolve_did(
        &self,
        Parameters(p): Parameters<ResolveDidParams>,
    ) -> Result<CallToolResult, McpError> {
        let doc = self.client().resolve_did(&p.did).await.map_err(to_mcp)?;
        ok_json(doc)
    }

    #[tool(
        description = "Issue a holder-bound Verifiable Presentation (OID4VP vp_token) for a verifier's presentation_definition from the supplied held credentials, signed with this agent's holder key. Requires the bridge to be configured with a holder identity."
    )]
    async fn issue_vp(
        &self,
        Parameters(p): Parameters<IssueVpParams>,
    ) -> Result<CallToolResult, McpError> {
        let holder = self.holder.as_ref().ok_or_else(|| {
            McpError::invalid_request(
                "issue_vp is unavailable: no holder identity configured \
                 (set VTA_MCP_HOLDER_DID + VTA_MCP_HOLDER_KEY)",
                None,
            )
        })?;
        let held: Vec<vta_sdk::vp::HeldCredential> = serde_json::from_value(p.held_credentials)
            .map_err(|e| McpError::invalid_params(format!("held_credentials: {e}"), None))?;
        let vp_token = vta_sdk::vp::issue_vp_token(
            &holder.did,
            &holder.vm_fragment,
            &holder.key_multibase,
            &p.presentation_definition,
            &held,
            &p.nonce,
            &p.audience,
        )
        .await
        .map_err(|e| McpError::internal_error(format!("issue_vp: {e}"), None))?;
        ok_json(vp_token)
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

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server_info)
            .with_instructions(
                "Bridges a Verifiable Trust Agent (VTA) to MCP. Convenience tools: \
                 vta_capabilities, list_keys, sign (signing oracle), vault_list, vault_get, \
                 vault_release (DIDComm only), device_heartbeat, resolve_did, issue_vp. \
                 For the FULL management surface (contexts, keys, acl, did-management, webvh, \
                 did-templates, device, vault, seeds, audit, backup, …) use vta_list_operations \
                 to discover operation URIs and vta_call to invoke any of them. All access is \
                 bounded by the bridge identity's VTA role/ACL; secrets never leave the VTA \
                 except via vault_release / issue_vp to this client.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::VtaMcp;

    /// The generated tool router must expose exactly the bridge's tool set —
    /// guards against a tool being dropped or renamed without notice.
    #[test]
    fn tool_router_exposes_the_expected_tools() {
        let router = VtaMcp::tool_router();
        let expected = [
            "vta_capabilities",
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
}
