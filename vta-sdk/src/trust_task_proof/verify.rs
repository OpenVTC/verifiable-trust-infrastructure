//! Single `eddsa-jcs-2022` Data-Integrity proof verifier for Trust Task
//! documents (P1.4).
//!
//! Every place that verifies a holder's DI proof on a Trust Task and recovers
//! the cryptographically-proven signer DID delegates here. In the **VTA**: the
//! canonical REST authenticate path (`routes/auth.rs::
//! verify_authenticate_proof`, signer unknown a priori) and the did-signed
//! step-up gate (`trust_tasks/step_up.rs::verify_did_signed_gate`, signer
//! checked against the document issuer). In the **VTC**: the same REST
//! authenticate path, and the join-request dispatcher's holder-binding check
//! (`trust_tasks/helpers.rs::verify_trust_task_proof`).
//!
//! It started as one implementation in the VTA that had already drifted into
//! two copies there, then a third when the VTC ported it. It lives in
//! `vti-common` because *both services verify the same holder proof over the
//! same wire shape* — a divergence between them is a divergence in what a
//! signature means, which is not a thing to let happen twice.
//!
//! # Which DIDs may sign
//!
//! Any DID that can name a key. A proof's `verificationMethod` is resolved by
//! [`TrustTaskVmResolver`](super::vm_resolver::TrustTaskVmResolver), which
//! handles `did:key` locally and every other method through the configured DID
//! cache — so `did:webvh:<scid>:example.com:glenn#key-0` signs a Trust Task
//! exactly as a `did:key` does.
//!
//! This used to be `did:key` only, on the reasoning that the mobile holder key
//! is always a `did:key` and it kept proof verification off the network on an
//! unauthenticated route. The first half was never true of the whole surface:
//! every DID this workspace provisions for an integration is a `did:webvh`, so
//! the restriction meant a provisioned integration could not sign a Trust Task
//! at all. The second half is a real cost and is bounded rather than dismissed
//! — see the resolver's own module docs, and
//! [`verify_trust_task_proof`], whose `did:key`-only behaviour is unchanged for
//! callers that want it.

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};

use super::vm_resolver::TrustTaskVmResolver;
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

impl DiProofError {
    /// The underlying verifier detail, for the operator's log only.
    ///
    /// Deliberately not reachable through [`Display`]: that rendering goes on
    /// the wire, and this is exactly what Framework 0.5.0 forbids putting
    /// there. Log it beside the rejection; never return it.
    #[must_use]
    pub fn cause(&self) -> Option<&str> {
        match self {
            Self::VerifyFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for DiProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProof => write!(f, "document has no proof"),
            Self::NotDataIntegrity => write!(f, "proof is not a Data Integrity proof"),
            Self::NoDid => write!(f, "proof verificationMethod carries no DID"),
            // Framework 0.5.0, *What a `message` May Not Say*: a `message`
            // MUST NOT reveal "resolver, verifier, or key-status internals",
            // normative for every code rather than for `identityMismatch`
            // alone. This `Display` reaches the wire through
            // `PermissionDenied { reason }`, so interpolating the underlying
            // verifier error published which cryptosuite ran, whether the key
            // resolved, and how it failed — to a party that is, on the
            // unauthenticated routes, not yet anybody.
            //
            // The producer needs to know its proof did not verify and that
            // retrying unchanged will not help. It does not need to know why,
            // and every additional word is an oracle. The cause is available
            // to the operator through [`Self::cause`].
            Self::VerifyFailed(_) => write!(f, "proof verification failed"),
        }
    }
}

/// Verify the proof on `doc` **against `did:key` only**, with no network I/O.
///
/// The narrow form, kept for callers whose signer is a `did:key` by
/// construction and who do not want an unauthenticated request to be able to
/// trigger DID resolution. Anything that must accept a provisioned
/// integration's `did:webvh` holder wants
/// [`verify_trust_task_proof_with`] and a configured resolver.
pub async fn verify_trust_task_proof(doc: &TrustTask<Value>) -> Result<String, DiProofError> {
    verify_trust_task_proof_with(doc, &TrustTaskVmResolver::did_key_only()).await
}

/// Verify the `eddsa-jcs-2022` Data-Integrity proof on `doc` and return the
/// proven signer DID — the base DID (before `#`) of the proof's
/// `verificationMethod`.
///
/// The signature is verified over the document with its `proof` block removed
/// (`eddsa-jcs-2022` canonicalises the proofless document via JCS). The
/// returned DID is *proven*, not merely claimed; binding it to an expected
/// identity (session DID, document issuer) is the caller's job — and remains so
/// however the verification method resolved. A proof by
/// `did:webvh:…:someone-else#key-0` verifies perfectly well; that it is not the
/// party you expected is a separate check, and not one this function makes.
pub async fn verify_trust_task_proof_with(
    doc: &TrustTask<Value>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
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
    di.verify(&unsigned, resolver, VerifyOptions::new())
        .await
        .map_err(|e| DiProofError::VerifyFailed(e.to_string()))?;

    Ok(signer_did)
}
