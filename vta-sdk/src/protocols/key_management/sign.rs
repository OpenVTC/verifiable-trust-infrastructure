use serde::{Deserialize, Serialize};

/// Signing algorithms supported by the VTA sign-request protocol.
/// Signing algorithms, spelled as the IANA JOSE registry spells them —
/// which is what the canonical `keys/_shared/0.1/sign-algorithm` enumeration
/// publishes. The pre-fold lowercase forms are accepted on intake so a producer
/// written against them keeps working while it migrates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SignAlgorithm {
    /// Ed25519 / EdDSA signing.
    #[serde(rename = "EdDSA", alias = "eddsa")]
    EdDSA,
    /// ECDSA with P-256 / ES256 signing.
    #[serde(rename = "ES256", alias = "es256")]
    ES256,
}

/// Body of a sign-request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SignRequestBody {
    /// Key ID to sign with. Must be **active**, and the consumer enforces the
    /// caller's authority over it — this is not merely a caller-side
    /// precondition.
    ///
    /// Because the VTA signs the bytes it is given without inspecting them,
    /// *which keys a caller may name* is the whole of the authorization story,
    /// so callers reasoning about identity separation depend on it. The
    /// guarantee, in order: the caller must be authorized in the key's context;
    /// the context's `signable_keys` policy must permit the key (binding even a
    /// super-admin); and a key with no context is super-admin-only.
    ///
    /// **Scoped per context, not per key id** — holding a context authorizes
    /// every key in it, so a signer acting for several identities needs a
    /// context each. See `docs/02-vta/integration-guide.md` §"What authorizes a
    /// sign request".
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    /// Base64url-encoded payload bytes to sign.
    pub payload: String,
    /// Signing algorithm to use (must match the key type).
    pub algorithm: SignAlgorithm,
}

/// Body of a sign-result message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SignResultBody {
    /// Key ID that was used.
    #[serde(rename = "keyId", alias = "key_id")]
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
