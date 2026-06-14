use serde::{Deserialize, Serialize};

/// Signing algorithms supported by the VTA sign-request protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SignAlgorithm {
    /// Ed25519 / EdDSA signing.
    EdDSA,
    /// ECDSA with P-256 / ES256 signing.
    ES256,
}

/// Body of a sign-request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SignRequestBody {
    /// Key ID to sign with (must be an active key the caller has access to).
    pub key_id: String,
    /// Base64url-encoded payload bytes to sign.
    pub payload: String,
    /// Signing algorithm to use (must match the key type).
    pub algorithm: SignAlgorithm,
}

/// Body of a sign-result message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SignResultBody {
    /// Key ID that was used.
    pub key_id: String,
    /// Base64url-encoded signature bytes.
    pub signature: String,
    /// Algorithm used.
    pub algorithm: SignAlgorithm,
}

impl std::fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignAlgorithm::EdDSA => write!(f, "eddsa"),
            SignAlgorithm::ES256 => write!(f, "es256"),
        }
    }
}
