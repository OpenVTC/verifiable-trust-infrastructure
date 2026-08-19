use serde::{Deserialize, Serialize};

use crate::keys::KeyType;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct GetKeySecretBody {
    #[serde(alias = "key_id")]
    pub key_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct GetKeySecretResultBody {
    #[serde(alias = "key_id")]
    pub key_id: String,
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    #[serde(alias = "public_key_multibase")]
    pub public_key_multibase: String,
    #[serde(alias = "private_key_multibase")]
    pub private_key_multibase: String,
}

// Manual Debug — `private_key_multibase` is the raw private key as
// returned from the signing oracle. Redact via `{:?}` so callers
// can't accidentally tracing-log it. Serialize is unchanged for the
// sealed-transfer envelope that legitimately carries it.
impl std::fmt::Debug for GetKeySecretResultBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetKeySecretResultBody")
            .field("key_id", &self.key_id)
            .field("key_type", &self.key_type)
            .field("public_key_multibase", &self.public_key_multibase)
            .field("private_key_multibase", &"<redacted>")
            .finish()
    }
}
