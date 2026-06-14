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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KeyRecord {
    pub key_id: String,
    pub derivation_path: String,
    pub key_type: KeyType,
    pub status: KeyStatus,
    pub public_key: String,
    pub label: Option<String>,
    #[serde(default)]
    pub context_id: Option<String>,
    #[serde(default)]
    pub seed_id: Option<u32>,
    #[serde(default = "default_derived")]
    pub origin: KeyOrigin,
    pub created_at: DateTime<Utc>,
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
