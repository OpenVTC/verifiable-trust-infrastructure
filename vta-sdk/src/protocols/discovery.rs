use serde::{Deserialize, Serialize};

/// Empty request body for the capabilities discovery operation.
/// Exists so the trust-task envelope's `payload` field has a typed
/// shape; the operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesBody {}

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/discovery/1.0";

pub const DISCOVER_CAPABILITIES: &str =
    "https://firstperson.network/protocols/discovery/1.0/discover-capabilities";
pub const DISCOVER_CAPABILITIES_RESULT: &str =
    "https://firstperson.network/protocols/discovery/1.0/discover-capabilities-result";

/// Response to `trust-task-discovery/0.1` — the Trust Task types an agent
/// serves.
///
/// Deliberately a local mirror of the framework crate's `Response` rather than a
/// re-export: the SDK's `client` feature does not otherwise pull the generated
/// spec types, and the shape is two members. Kept `deny_unknown_fields`-free so
/// a responder at a later framework revision — which MAY add members — still
/// decodes here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SupportedTasksResponse {
    /// The Type URIs this agent serves, matching the requested patterns.
    pub supported_types: Vec<String>,
    /// MAJOR.MINOR of the Trust Tasks framework spec the responder targets.
    ///
    /// Optional in 0.1 and RECOMMENDED afterwards, so absent is a legitimate
    /// answer from an older peer rather than a malformed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_version: Option<String>,
}

/// Response describing the VTA's capabilities and enabled features.
///
/// # `rename_all` here is load-bearing
///
/// #1000 added the aliases below without it, which made them no-ops: an alias
/// equal to the member's own serialized name accepts what is already accepted.
/// So this kept emitting snake_case while its siblings moved, and read — to
/// anyone glancing at the attributes — as though it had been folded.
///
/// It stayed that way through #1034 because this body was also served on the
/// REST route `GET /capabilities`, and re-casing a public discovery endpoint is
/// a change to readers nobody can enumerate. That route is gone (#1039), so the
/// only consumers left are Trust-Task and DIDComm callers who decode this very
/// struct — and the fold is free.
/// # Reduced to the delta (#1039)
///
/// This carried `features` and `services` — booleans for webvh / didcomm / tee
/// / rest. Both are gone, because **the DID document is authoritative for which
/// protocols a party speaks** (see the workspace CLAUDE.md), and a second
/// answer to the same question is a second answer that can be wrong.
///
/// It was not hypothetically wrong, either. `services` was read from local
/// config while a peer resolves the DID document, and runtime service
/// management can change what is advertised without the config moving —
/// so the two could disagree about the very thing a caller was asking.
/// `features` reported compile-time `cfg!` flags, which say what the binary
/// *could* serve rather than what it *does*; the honest version of that
/// question is now `trust-task-discovery/0.1`, answered from the dispatch
/// table.
///
/// What remains is genuinely VTA-specific inventory that neither the DID
/// document nor task discovery covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    /// Crate version of the VTA service.
    pub version: String,
    /// Configured WebVH servers available for DID creation.
    #[serde(alias = "webvh_servers")]
    pub webvh_servers: Vec<WebvhServerInfo>,
    /// Supported DID creation modes.
    #[serde(alias = "did_creation_modes")]
    pub did_creation_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebvhServerInfo {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}
