use serde::{Deserialize, Serialize};

/// Body for the agent-name enable/disable Trust Tasks
/// (`spec/vta/webvh/agent-name/{enable,disable}/1.0`).
///
/// Both verbs carry the same shape: the hosted DID and the name's local
/// part (the `alice` in `/@alice`, without the leading `@`). The agent
/// resolves the current DID document, edits its `alsoKnownAs` to
/// claim/no-longer-claim `https://<domain>/@<name>`, signs a new version,
/// and submits it to the hosting server's `agent-name/{enable,disable}`
/// endpoint. The hosting domain is the DID's own host — derived from the
/// `did:webvh` identifier, not carried here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameBody {
    pub did: String,
    pub name: String,
}

/// Result of an agent-name enable/disable Trust Task.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameResultBody {
    pub did: String,
    pub name: String,
    /// `true` for enable (now served), `false` for disable (parked).
    pub enabled: bool,
}
