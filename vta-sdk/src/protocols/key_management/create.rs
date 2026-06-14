use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::{KeyOrigin, KeyStatus, KeyType};

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateKeyBody {
    pub key_type: KeyType,
    pub derivation_path: String,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

// Manual Debug — `mnemonic` is the BIP-39 phrase that recovers the
// key being imported. Redact via `{:?}` so any tracing call site or
// panic-with-debug can't leak it. Serialize is unchanged.
impl std::fmt::Debug for CreateKeyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateKeyBody")
            .field("key_type", &self.key_type)
            .field("derivation_path", &self.derivation_path)
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .field("label", &self.label)
            .field("context_id", &self.context_id)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateKeyResultBody {
    pub key_id: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    #[serde(default = "default_derived")]
    pub origin: KeyOrigin,
    pub created_at: DateTime<Utc>,
}

fn default_derived() -> KeyOrigin {
    KeyOrigin::Derived
}
