use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::{KeyOrigin, KeyStatus, KeyType};

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyBody {
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    #[serde(alias = "derivation_path")]
    pub derivation_path: String,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    #[serde(alias = "context_id")]
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

/// The realized key record, in the canonical camelCase shape. A strict subset
/// of `keys/_shared/0.1/key-record#KeyRecord`'s members, so it validates as one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateKeyResultBody {
    #[serde(alias = "key_id")]
    pub key_id: String,
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    #[serde(alias = "derivation_path")]
    pub derivation_path: String,
    #[serde(alias = "public_key")]
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    #[serde(default = "default_derived")]
    pub origin: KeyOrigin,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
}

/// `keys/create/0.1` response — the realized record under `key`.
///
/// Nested rather than flattened because the canonical `keys/*` family carries
/// one record shape across create, show and import, so a consumer comparing
/// records between them cannot end up looking at two spellings of the same
/// thing. Mirrors `acl/*`'s `{ entry }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateKeyResponseBody {
    pub key: CreateKeyResultBody,
}

fn default_derived() -> KeyOrigin {
    KeyOrigin::Derived
}
