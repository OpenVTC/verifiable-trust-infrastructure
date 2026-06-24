use serde::{Deserialize, Serialize};

use super::sign::SignAlgorithm;
use crate::keys::KeyType;

/// Body of an **ephemeral** derive-and-sign request: derive a key at
/// `derivation_path` from the VTA's seed, sign `payload`, and return the
/// signature — **without persisting a key record**.
///
/// Unlike `sign` (which signs with a stored, registered key), this is a
/// one-shot oracle over the seed's derivation tree. It lets a trusted admin
/// (e.g. a fleet manager whose fleet seed *is* this VTA's seed) act as any
/// derived child identity — such as a per-VTA super-admin at
/// `m/26'/9'/<idx>'` — without leaving a `KeyRecord` per action. Admin-gated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeriveAndSignBody {
    /// Key type to derive (currently only `Ed25519` is supported).
    pub key_type: KeyType,
    /// BIP-32 derivation path, e.g. `m/26'/9'/0'`.
    pub derivation_path: String,
    /// Base64url-encoded payload bytes to sign.
    pub payload: String,
    /// Signing algorithm (must match the key type).
    pub algorithm: SignAlgorithm,
}

/// Body of a derive-and-sign result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeriveAndSignResultBody {
    /// The derived public key (multibase, multicodec-prefixed) — so the caller
    /// learns the `did:key` it just signed as.
    pub public_key: String,
    /// Base64url-encoded signature bytes.
    pub signature: String,
    /// Algorithm used.
    pub algorithm: SignAlgorithm,
}
