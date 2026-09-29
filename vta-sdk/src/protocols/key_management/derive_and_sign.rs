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
/// `m/26'/9'/<idx>'` — without leaving a `KeyRecord` per action.
///
/// **Super-admin only, and `derivation_path` must lie strictly inside
/// `m/26'/9'` with every index hardened.** The caller chooses the identity it
/// signs as, so the VTA confines this oracle to the delegated-identity subtree:
/// it never signs as a key a record exists for, the VTA's own included. A
/// context-scoped admin, or a path outside the subtree, gets `permissionDenied`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeriveAndSignBody {
    /// Key type to derive (currently only `Ed25519` is supported).
    #[serde(alias = "key_type")]
    pub key_type: KeyType,
    /// BIP-32 derivation path, e.g. `m/26'/9'/0'`.
    #[serde(alias = "derivation_path")]
    pub derivation_path: String,
    /// Base64url-encoded payload bytes to sign.
    pub payload: String,
    /// Signing algorithm (must match the key type).
    pub algorithm: SignAlgorithm,
}

/// Body of a derive-and-sign result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeriveAndSignResultBody {
    /// The derived public key (multibase, multicodec-prefixed) — so the caller
    /// learns the `did:key` it just signed as.
    #[serde(alias = "public_key")]
    pub public_key: String,
    /// Base64url-encoded signature bytes.
    pub signature: String,
    /// Algorithm used.
    pub algorithm: SignAlgorithm,
}
