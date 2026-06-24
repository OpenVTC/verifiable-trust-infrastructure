use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::keys::KeyType;

/// Body of a **derive-and-sign-document** request: derive an Ed25519 key at
/// `derivation_path` from the VTA's seed and attach an `eddsa-jcs-2022`
/// Data-Integrity proof to `document` — signed *as the derived key*, persisting
/// no key record.
///
/// This is the DI-signing counterpart of `derive-and-sign` (which signs raw
/// bytes). It lets a fleet manager whose fleet seed *is* this VTA's seed obtain
/// a properly DI-signed document (e.g. an `auth/authenticate/0.1` Trust Task)
/// signed by a per-VTA super-admin at `m/26'/9'/<idx>'`, so the seed never
/// leaves the VTA. The proof is produced with the same crate a verifier uses,
/// so it's correct by construction. Admin-gated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeriveAndSignDocumentBody {
    /// Key type to derive (currently only `Ed25519`).
    pub key_type: KeyType,
    /// BIP-32 derivation path, e.g. `m/26'/9'/0'`.
    pub derivation_path: String,
    /// The proof-less JSON document to sign (any `proof` is stripped first).
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub document: Value,
    /// Proof purpose (default `assertionMethod`, matching the DI-signed REST
    /// auth flow).
    #[serde(default)]
    pub proof_purpose: Option<String>,
}

/// Result of a derive-and-sign-document request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeriveAndSignDocumentResultBody {
    /// The derived signer's `did:key` (the super-admin identity the document was
    /// signed as).
    pub signer_did: String,
    /// The signed document, with the Data-Integrity `proof` grafted on.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub document: Value,
}
