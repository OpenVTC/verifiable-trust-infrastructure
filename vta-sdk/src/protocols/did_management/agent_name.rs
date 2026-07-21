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

/// One name in a DID's agent-name registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameEntry {
    /// The local part, without the `@`.
    pub name: String,
    /// Whether the name currently resolves.
    ///
    /// `false` means **parked, not gone**: the name is still reserved to this
    /// DID and nobody else can claim it.
    pub enabled: bool,
    /// Unix seconds when the name was first bound to this DID.
    pub created_at: u64,
}

/// Body for `spec/vta/webvh/agent-name/list/1.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameListBody {
    /// The hosted DID — a full `did:webvh:…` or a bare SCID.
    pub did: String,
}

/// Result of `spec/vta/webvh/agent-name/list/1.0` — the DID's registry as the
/// hosting control plane holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameListResultBody {
    pub did: String,
    /// Every name bound to this DID, parked ones included.
    pub names: Vec<AgentNameEntry>,
}

/// Body for `spec/vta/webvh/agent-name/check/1.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameCheckBody {
    /// The DID whose host the name is checked against. Availability is
    /// domain-scoped, and the domain is the DID's own host — the same rule
    /// the mutating verbs use.
    pub did: String,
    /// The name's local part, without the `@`.
    pub name: String,
}

/// Result of `spec/vta/webvh/agent-name/check/1.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentNameCheckResultBody {
    /// The canonicalised local part.
    pub name: String,
    /// The domain the answer applies to.
    pub domain: String,
    /// Free to claim: neither reserved nor already bound on this domain.
    pub available: bool,
    /// On the host's reserved list (`@admin`, `@support`, …) — unavailable
    /// but well-formed, which is distinct from a malformed name (an error).
    pub reserved: bool,
}
