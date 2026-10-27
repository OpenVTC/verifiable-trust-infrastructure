//! Wire payloads for `spec/vta/contexts/set-issuer-key/0.1`.
//!
//! Designates the key that signs credentials issued **as a context's own DID**
//! (`spec/vta/credentials/issue-in-context/0.1`).
//!
//! Its own task rather than a member on `contexts/update/1.0`: that task has a
//! published schema which forbids additional properties, so a designation sent
//! there is refused on the wire before any handler sees it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::create::CreateContextResultBody;

/// `spec/vta/contexts/set-issuer-key/0.1` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SetContextIssuerKeyBody {
    /// The context whose key is being designated.
    pub id: String,
    /// The key to designate, or `None` to clear the designation (after which
    /// the context can no longer issue or prove for that purpose).
    ///
    /// The key must live in `id`'s context: the designation is what lets a
    /// context-scoped caller issue *without* naming a key, so one pointing
    /// outside the context would hand that caller a key it cannot otherwise
    /// reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Which designation this sets.
    ///
    /// Omitted, it sets the context's **credential issuer** key. Given a
    /// `proofPurpose` (`authentication`, `assertionMethod`), it sets the key
    /// that produces Data-Integrity proofs for that purpose — a DID document
    /// declares a different verification method per purpose, so these are
    /// genuinely different keys rather than one key described twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1). Not interpreted.
    ///
    /// Present alongside `deny_unknown_fields` for the reason the rest of the
    /// family carries it: the published payload schemas allow an `ext`, so a
    /// producer sending one would otherwise have its whole document refused,
    /// while `deny_unknown_fields` still catches a typo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

impl SetContextIssuerKeyBody {
    /// Designate `key_id` as `id`'s credential issuer key.
    pub fn new(id: String, key_id: Option<String>) -> Self {
        Self {
            id,
            key_id,
            proof_purpose: None,
            ext: None,
        }
    }

    /// Designate `key_id` as `id`'s proof key for `proof_purpose`.
    pub fn for_proof_purpose(id: String, key_id: Option<String>, proof_purpose: String) -> Self {
        Self {
            id,
            key_id,
            proof_purpose: Some(proof_purpose),
            ext: None,
        }
    }
}

/// The updated context record.
pub type SetContextIssuerKeyResultBody = CreateContextResultBody;
