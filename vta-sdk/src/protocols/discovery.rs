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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    /// Crate version of the VTA service.
    pub version: String,
    /// Enabled features/modules.
    pub features: FeaturesInfo,
    /// Enabled services (REST, DIDComm).
    pub services: ServicesInfo,
    /// Configured WebVH servers available for DID creation.
    #[serde(alias = "webvh_servers")]
    pub webvh_servers: Vec<WebvhServerInfo>,
    /// Supported DID creation modes.
    #[serde(alias = "did_creation_modes")]
    pub did_creation_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FeaturesInfo {
    pub webvh: bool,
    pub didcomm: bool,
    pub tee: bool,
    pub rest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServicesInfo {
    pub rest: bool,
    pub didcomm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebvhServerInfo {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}
