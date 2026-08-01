use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KeyType {
    Ed25519,
    X25519,
    /// ECDSA P-256 key for ES256 signing.
    P256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KeyStatus {
    Active,
    Revoked,
}

/// Whether a key was derived from the BIP-32 seed or imported externally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KeyOrigin {
    Derived,
    Imported,
}

fn default_derived() -> KeyOrigin {
    KeyOrigin::Derived
}

/// One key as the maintainer holds it — canonical
/// `keys/_shared/0.1/key-record#KeyRecord`.
///
/// The **wire** names are canonical camelCase; the Rust field names are the
/// maintainer's historical snake_case ones, kept so every call site did not
/// have to move in the same change. Snake_case is additionally accepted on
/// *intake* via aliases, so a producer written against the pre-fold shape keeps
/// working while it migrates — emission is canonical either way.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KeyRecord {
    #[serde(alias = "key_id")]
    pub key_id: String,
    #[serde(alias = "derivation_path")]
    pub derivation_path: String,
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    pub status: KeyStatus,
    #[serde(alias = "public_key")]
    pub public_key: String,
    pub label: Option<String>,
    #[serde(default, alias = "context_id")]
    pub context_id: Option<String>,
    #[serde(default, alias = "seed_id")]
    pub seed_id: Option<u32>,
    #[serde(default = "default_derived")]
    pub origin: KeyOrigin,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "ed25519"),
            KeyType::X25519 => write!(f, "x25519"),
            KeyType::P256 => write!(f, "p256"),
        }
    }
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "active"),
            KeyStatus::Revoked => write!(f, "revoked"),
        }
    }
}
