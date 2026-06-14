use serde::{Deserialize, Serialize};

/// Empty request body for the capabilities discovery operation.
/// Exists so the trust-task envelope's `payload` field has a typed
/// shape; the operation takes no input parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CapabilitiesBody {}

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/discovery/1.0";

pub const DISCOVER_CAPABILITIES: &str =
    "https://firstperson.network/protocols/discovery/1.0/discover-capabilities";
pub const DISCOVER_CAPABILITIES_RESULT: &str =
    "https://firstperson.network/protocols/discovery/1.0/discover-capabilities-result";

/// Response describing the VTA's capabilities and enabled features.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CapabilitiesResponse {
    /// Crate version of the VTA service.
    pub version: String,
    /// Enabled features/modules.
    pub features: FeaturesInfo,
    /// Enabled services (REST, DIDComm).
    pub services: ServicesInfo,
    /// Configured WebVH servers available for DID creation.
    pub webvh_servers: Vec<WebvhServerInfo>,
    /// Supported DID creation modes.
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
