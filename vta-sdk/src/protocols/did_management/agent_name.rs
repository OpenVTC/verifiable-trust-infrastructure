use serde::{Deserialize, Serialize};

/// Body for the four agent-name Trust Tasks
/// (`spec/vta/webvh/agent-name/{set,remove,enable,disable}/1.0`).
///
/// All four carry the same shape: the hosted DID and the name's local
/// part (the `alice` in `/@alice`, without the leading `@`). The agent
/// resolves the current DID document, edits its `alsoKnownAs` to
/// claim/no-longer-claim `https://<domain>/@<name>`, signs a new version,
/// and submits it to the hosting server's matching `agent-name/{op}`
/// endpoint. The hosting domain is the DID's own host — derived from the
/// `did:webvh` identifier, not carried here.
///
/// The verb lives in the task's `type` URI, not in this body, so the
/// wallet's consent screen can classify each one independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameBody {
    pub did: String,
    pub name: String,
}

/// Result of an agent-name Trust Task.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameResultBody {
    pub did: String,
    pub name: String,
    /// Whether the name resolves after the operation: `true` for `set`
    /// and `enable`, `false` for `disable` and `remove`.
    ///
    /// It does **not** distinguish parked from released — `disable` and
    /// `remove` both report `false`, and they differ in whether the name
    /// stays reserved to this DID. The caller knows which verb it sent, so
    /// the distinction is in the request rather than duplicated here.
    pub enabled: bool,
}
