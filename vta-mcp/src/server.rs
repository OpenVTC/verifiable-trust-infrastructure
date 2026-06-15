//! The MCP server handler: a thin bridge from MCP tool calls to `VtaClient`.
//!
//! Each `#[tool]` maps one-to-one onto an SDK method so an MCP-speaking agent
//! host (Claude Desktop, an agent framework, …) can use a VTA's capabilities —
//! signing oracle, secrets vault, device check-in, discovery — with no custom
//! code. Results are returned as JSON content.
//!
//! Tools that touch secrets (`vault_release`) seal/open `didcomm-authcrypt`
//! envelopes and therefore require the underlying client to be on the DIDComm
//! transport; on REST they surface a clear error rather than failing opaquely.

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

/// MCP server bridging to a single authenticated agent session.
#[derive(Clone)]
pub struct VtaMcp {
    agent: Arc<AgentSession>,
}

#[tool_router]
impl VtaMcp {
    pub fn new(agent: Arc<AgentSession>) -> Self {
        Self { agent }
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
                "Bridges a Verifiable Trust Agent (VTA) to MCP. Tools: vta_capabilities, \
                 list_keys, sign (signing oracle), vault_list, vault_get, vault_release \
                 (DIDComm only), device_heartbeat. Use list_keys to find a key id before \
                 sign; secrets never leave the VTA except via vault_release to this client.",
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
