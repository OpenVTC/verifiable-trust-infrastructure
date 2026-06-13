//! Single `eddsa-jcs-2022` Data-Integrity proof verifier for Trust Task
//! documents (P1.4).
//!
//! Two `/auth/*` paths need to verify a holder's DI proof on a Trust Task and
//! recover the cryptographically-proven signer DID: the canonical REST
//! authenticate path (`routes/auth.rs::verify_authenticate_proof`, signer
//! unknown a priori) and the did-signed step-up gate
//! (`routes/trust_tasks/step_up.rs::verify_did_signed_gate`, signer checked
//! against the document issuer). They had drifted into two copies of the same
//! extract → round-trip → verify-proofless-doc logic; this is the one
//! implementation both delegate to.
//!
//! `did:key` resolution is local (no network I/O) — the mobile holder key is
//! always a `did:key`, matching the engine's signing side.

use affinidi_data_integrity::{DataIntegrityProof, DidKeyResolver, VerifyOptions};
use serde_json::Value;
use trust_tasks_rs::TrustTask;

/// Why a Trust Task DI-proof verification failed. Callers map these onto their
/// own transport error types (`AppError::Authentication`, `GateError`, …).
#[derive(Debug)]
pub enum DiProofError {
    /// The document carries no `proof`.
    NoProof,
    /// The `proof` block is not a Data-Integrity proof.
    NotDataIntegrity,
    /// The proof's `verificationMethod` carries no DID.
    NoDid,
    /// The signature failed to verify (carries the underlying reason).
    VerifyFailed(String),
}

impl std::fmt::Display for DiProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProof => write!(f, "document has no proof"),
            Self::NotDataIntegrity => write!(f, "proof is not a Data Integrity proof"),
            Self::NoDid => write!(f, "proof verificationMethod carries no DID"),
            Self::VerifyFailed(e) => write!(f, "proof verification failed: {e}"),
        }
    }
}

/// Verify the `eddsa-jcs-2022` Data-Integrity proof on `doc` and return the
/// proven signer DID — the base DID (before `#`) of the proof's
/// `verificationMethod`.
///
/// The signature is verified over the document with its `proof` block removed
/// (`eddsa-jcs-2022` canonicalises the proofless document via JCS). The
/// returned DID is *proven*, not merely claimed; binding it to an expected
/// identity (session DID, document issuer) is the caller's job.
pub async fn verify_trust_task_proof(doc: &TrustTask<Value>) -> Result<String, DiProofError> {
    let proof = doc.proof.as_ref().ok_or(DiProofError::NoProof)?;

    // The framework `Proof` round-trips into a `DataIntegrityProof` (same shape;
    // the mobile engine builds it the same way).
    let di: DataIntegrityProof = serde_json::to_value(proof)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or(DiProofError::NotDataIntegrity)?;

    let signer_did = di
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
        .to_string();
    if signer_did.is_empty() {
        return Err(DiProofError::NoDid);
    }

    let mut unsigned = doc.clone();
    unsigned.proof = None;
    di.verify(&unsigned, &DidKeyResolver, VerifyOptions::new())
        .await
        .map_err(|e| DiProofError::VerifyFailed(e.to_string()))?;

    Ok(signer_did)
}
