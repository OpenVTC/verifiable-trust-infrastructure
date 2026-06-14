use serde::{Deserialize, Serialize};

/// Supported TEE platform types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(utoipa::ToSchema)]
pub enum TeeType {
    SevSnp,
    Nitro,
    Simulated,
}

impl std::fmt::Display for TeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeType::SevSnp => write!(f, "sev_snp"),
            TeeType::Nitro => write!(f, "nitro"),
            TeeType::Simulated => write!(f, "simulated"),
        }
    }
}

/// TEE detection result.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TeeStatus {
    pub tee_type: TeeType,
    pub detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_version: Option<String>,
}

/// Hardware-signed attestation report.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttestationReport {
    pub tee_type: TeeType,
    /// Base64-encoded platform-specific attestation evidence.
    pub evidence: String,
    /// Hex-encoded nonce that was bound into the report.
    pub nonce: String,
    /// Unix timestamp when the report was generated.
    pub generated_at: u64,
    /// VTA DID bound into the report as user_data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
}

/// Request body for `POST /attestation/report`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttestationRequest {
    /// Client-provided nonce (hex, 32 bytes) to prevent replay.
    pub nonce: String,
}
