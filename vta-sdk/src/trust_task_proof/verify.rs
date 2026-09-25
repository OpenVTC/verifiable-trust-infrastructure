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

use super::vm_resolver::{ProofRelationship, TrustTaskVmResolver};
use serde::Serialize;
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
    /// The proof declares a purpose other than the one this document needs.
    WrongPurpose {
        /// The purpose the document needs.
        expected: &'static str,
    },
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
            Self::WrongPurpose { expected } => {
                write!(f, "proof must be made for `{expected}`")
            }
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
/// # Generic over the payload, and why that is the point
///
/// A proof is taken over the document, and the payload's Rust *shape* is not
/// part of it — `eddsa-jcs-2022` canonicalises whatever serialises. Pinning this
/// to `TrustTask<Value>` therefore constrained nothing cryptographically while
/// forcing every typed caller to convert first.
///
/// That conversion is not free and not safe-by-inspection: re-serialising a
/// document *before* checking its signature is the one place in the path that
/// could change what was signed. `vta_sdk::tsp_binding::wrap_envelope` hand-rolls
/// its JSON specifically to avoid the same hazard on the carriage side. A
/// dispatcher that hands handlers `TrustTask<P>` (which is what registering by
/// type gives you) would have made that round trip mandatory on every
/// proof-checking handler.
///
/// Existing `&TrustTask<Value>` call sites are unaffected — `P` infers to
/// `Value`.
pub async fn verify_trust_task_proof_with<P: Serialize + Clone + Sync>(
    doc: &TrustTask<P>,
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

/// The `proofPurpose` of a human approver's own decision: a
/// `task-consent/decision` or a step-up `approve-response`.
pub const APPROVAL_PROOF_PURPOSE: &str = "assertionMethod";

/// Verify a human approver's decision (`task-consent/decision`, step-up
/// `approve-response`) and return the proven signer DID.
///
/// Everything [`verify_trust_task_proof_with`] checks, plus: the proof is made
/// for [`APPROVAL_PROOF_PURPOSE`], and its `verificationMethod` is listed under
/// the signer's `assertionMethod` relationship. A decision is the approver's
/// attestation, not an operational message, and a proof made for
/// `authentication` is refused. This matches the did-hosting RP's
/// `verify_approval` (affinidi-webvh-service #213), which is where a wallet's
/// decisions are also sent.
///
/// Binding the signer to the approver the caller expects remains the caller's
/// job, as with [`verify_trust_task_proof_with`].
pub async fn verify_approval_proof_with<P: Serialize + Clone + Sync>(
    doc: &TrustTask<P>,
    resolver: &TrustTaskVmResolver,
) -> Result<String, DiProofError> {
    let proof = doc.proof.as_ref().ok_or(DiProofError::NoProof)?;
    let di: DataIntegrityProof = serde_json::to_value(proof)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or(DiProofError::NotDataIntegrity)?;
    if di.proof_purpose != APPROVAL_PROOF_PURPOSE {
        return Err(DiProofError::WrongPurpose {
            expected: APPROVAL_PROOF_PURPOSE,
        });
    }
    verify_trust_task_proof_with(
        doc,
        &resolver
            .clone()
            .requiring(ProofRelationship::AssertionMethod),
    )
    .await
}

/// [`verify_approval_proof_with`] against `did:key` only, with no network I/O.
pub async fn verify_approval_proof(doc: &TrustTask<Value>) -> Result<String, DiProofError> {
    verify_approval_proof_with(doc, &TrustTaskVmResolver::did_key_only()).await
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use affinidi_data_integrity::SignOptions;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    /// A `did:peer:2` whose one Ed25519 key is published under `purpose_code`
    /// (`A` = assertionMethod only, `D` = capabilityDelegation only; `V` would
    /// be both authentication and assertionMethod), and its signing secret.
    fn peer(purpose_code: char, seed: u8) -> (String, Secret) {
        let probe = Secret::generate_ed25519(None, Some(&[seed; 32]));
        let mb = probe.get_public_keymultibase().expect("public key");
        let did = format!("did:peer:2.{purpose_code}{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#key-1")), Some(&[seed; 32]));
        (did, secret)
    }

    async fn decision(issuer: &str, secret: &Secret, purpose: &str) -> TrustTask<Value> {
        let mut doc = json!({
            "id": "urn:uuid:decision-1",
            "type": "https://trusttasks.org/spec/task-consent/decision/0.1",
            "issuer": issuer,
            "recipient": "did:web:vta.example",
            "issuedAt": "2026-09-25T10:00:00Z",
            "payload": { "decision": "approve" },
        });
        let proof =
            DataIntegrityProof::sign(&doc, secret, SignOptions::new().with_proof_purpose(purpose))
                .await
                .expect("sign");
        doc["proof"] = serde_json::to_value(proof).unwrap();
        serde_json::from_value(doc).unwrap()
    }

    /// An approver's decision verifies only as an `assertionMethod` proof by a
    /// key the approver lists under `assertionMethod`.
    #[tokio::test]
    async fn an_approval_is_an_assertion_by_an_assertion_key() {
        let (asserting, secret) = peer('A', 3);
        let ok = decision(&asserting, &secret, "assertionMethod").await;
        assert_eq!(verify_approval_proof(&ok).await.unwrap(), asserting);

        // The right key, made for `authentication`.
        let operational = decision(&asserting, &secret, "authentication").await;
        assert!(matches!(
            verify_approval_proof(&operational).await,
            Err(DiProofError::WrongPurpose {
                expected: "assertionMethod"
            })
        ));

        // Declared `assertionMethod`, by a key the DID does not list under
        // `assertionMethod`: the general verifier accepts the signature, the
        // approval verifier does not.
        let (delegating, secret) = peer('D', 4);
        let misfiled = decision(&delegating, &secret, "assertionMethod").await;
        verify_trust_task_proof(&misfiled)
            .await
            .expect("the signature itself is valid");
        let err = verify_approval_proof(&misfiled).await.unwrap_err();
        assert!(
            err.cause().is_some_and(|c| c.contains("assertionMethod")),
            "{err:?}"
        );

        // And the relationship is the one asked for: an assertion-only key is
        // not an authentication key.
        let authentication_only =
            TrustTaskVmResolver::did_key_only().requiring(ProofRelationship::Authentication);
        let err = verify_trust_task_proof_with(&ok, &authentication_only)
            .await
            .unwrap_err();
        assert!(
            err.cause().is_some_and(|c| c.contains("authentication")),
            "{err:?}"
        );
    }
}
