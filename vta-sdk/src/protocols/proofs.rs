//! Wire payloads for `spec/vta/proofs/attach/0.1`.
//!
//! Attaches an `eddsa-jcs-2022` Data-Integrity proof to a document, signed with
//! a **persisted key in a context**, authorized by that context.
//!
//! The VTA frames the signed bytes itself — canonicalize, build the proof
//! config, hash — so this is a *proof producer*, not a signing oracle over
//! caller-supplied bytes. That is the security property the task exists for:
//! a caller can obtain a proof it is authorized to obtain, and cannot obtain a
//! signature over anything else.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `spec/vta/proofs/attach/0.1` request body.
///
/// Carries **no key id**. The key is a function of (context, `proofPurpose`):
/// a DID document declares a different verification method per purpose, which
/// a caller-supplied key id could not express correctly anyway. Deriving it is
/// also what keeps the task server-built — letting the caller choose the key
/// would undercut the property this task exists to provide.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AttachProofBody {
    /// The context to sign as.
    pub context_id: String,
    /// The document to prove. Any existing `proof` member is replaced.
    pub document: Value,
    /// The meaning of the signature (`authentication`, `assertionMethod`).
    /// Constrained to an allow-list: a proof purpose is a claim about what the
    /// signature means, so an unrecognised one would mint a signature whose
    /// meaning the VTA never agreed to.
    pub proof_purpose: String,
    /// Verifier-supplied replay-protection challenge.
    ///
    /// **Accepted but currently refused.** The `eddsa-jcs-2022` implementation
    /// in use carries no `challenge` member, so a proof claiming to be bound to
    /// one could not be. Refusing is the safe reading: silently dropping it
    /// would return a proof the caller believes is replay-bound and is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// Verifier domain. Accepted but currently refused, for the same reason as
    /// [`challenge`](Self::challenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The verification method the caller **expects** to sign.
    ///
    /// An assertion, not a selector. A mismatch is refused rather than signed
    /// with the other key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_verification_method: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1). Not interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

impl AttachProofBody {
    /// Build a body from the members the schema requires. The type is
    /// `#[non_exhaustive]`; set the optional members on the returned value.
    pub fn new(context_id: String, document: Value, proof_purpose: String) -> Self {
        Self {
            context_id,
            document,
            proof_purpose,
            challenge: None,
            domain: None,
            expected_verification_method: None,
            ext: None,
        }
    }
}

/// `spec/vta/proofs/attach/0.1` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachProofResponse {
    /// The document with its `proof` attached.
    pub document: Value,
    /// The verification method that signed, echoed back because the caller did
    /// not choose it.
    pub verification_method: String,
}
