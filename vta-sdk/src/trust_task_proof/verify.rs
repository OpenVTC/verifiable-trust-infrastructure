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

use affinidi_data_integrity::{DataIntegrityError, DataIntegrityProof, VerifyOptions};

use super::vm_resolver::TrustTaskVmResolver;
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
    /// The verification-method resolver could not retrieve the signer's key
    /// (network/rate-limit/lookup failure) — distinct from the signature
    /// itself being wrong. Renders identically to [`Self::VerifyFailed`] on
    /// the wire (see that variant's `Display` arm for why); a caller that
    /// verifies its own outbound reply may branch on this variant directly to
    /// tell "could not retrieve the key" apart from "proof is invalid".
    ResolverFailed(String),
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
            Self::ResolverFailed(e) | Self::VerifyFailed(e) => Some(e),
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
            //
            // `ResolverFailed` renders identically and deliberately: it is
            // the same `DataIntegrityError::Resolver` distinction one layer
            // down, exposed to callers who branch on the variant itself
            // rather than on this text — this text still must not tell an
            // unauthenticated caller whether the difference was "could not
            // reach the resolver" versus "the signature was wrong".
            Self::ResolverFailed(_) | Self::VerifyFailed(_) => {
                write!(f, "proof verification failed")
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
        .map_err(|e| match e {
            DataIntegrityError::Resolver(msg) => DiProofError::ResolverFailed(msg),
            other => DiProofError::VerifyFailed(other.to_string()),
        })?;

    Ok(signer_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chokepoint this whole split exists to protect: every inbound call
    /// site that stringifies a `DiProofError` (the ~12 unauthenticated routes
    /// this variant must stay invisible to) does so through `Display`/`.to_string()`
    /// alone. If this ever diverges, every one of those routes starts leaking
    /// which failure mode occurred, one call site at a time — this is the one
    /// place that regression is caught for all of them at once.
    #[test]
    fn resolver_failed_and_verify_failed_render_identically() {
        let resolver_failed = DiProofError::ResolverFailed("some resolver detail".to_string());
        let verify_failed = DiProofError::VerifyFailed("some other detail".to_string());
        assert_eq!(resolver_failed.to_string(), verify_failed.to_string());
        assert_eq!(resolver_failed.to_string(), "proof verification failed");
    }

    /// The operator-facing detail must still be recoverable for both variants
    /// — opacity is a wire-facing property, not an operator one.
    #[test]
    fn cause_surfaces_the_detail_for_both_variants() {
        assert_eq!(
            DiProofError::ResolverFailed("did not resolve".to_string()).cause(),
            Some("did not resolve")
        );
        assert_eq!(
            DiProofError::VerifyFailed("bad signature".to_string()).cause(),
            Some("bad signature")
        );
        assert_eq!(DiProofError::NoProof.cause(), None);
    }

    /// A `did:webvh` verification method against a resolver configured for
    /// `did:key` only fails at resolution — no network, no signature check
    /// ever runs — and that failure must classify as `ResolverFailed`, not
    /// `VerifyFailed`. Mirrors the "no resolver configured" case that a
    /// `did:webvh`-only TEE VTA's own reply hits in production (FTL-29595).
    #[tokio::test]
    async fn a_resolver_failure_classifies_as_resolver_failed() {
        let doc: TrustTask<Value> = serde_json::from_value(serde_json::json!({
            "id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "type": "https://trusttasks.org/spec/vta/contexts/create/1.0",
            "issuer": "did:webvh:QmScid:example.com:glenn",
            "recipient": "did:key:z6MkVta",
            "payload": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:webvh:QmScid:example.com:glenn#key-0",
                "created": "2026-08-29T00:00:00Z",
                "proofValue": "z2aBcD"
            }
        }))
        .expect("a well-formed Trust Task");

        let err = verify_trust_task_proof_with(&doc, &TrustTaskVmResolver::did_key_only())
            .await
            .expect_err("did:key-only cannot resolve a did:webvh key");
        assert!(
            matches!(err, DiProofError::ResolverFailed(_)),
            "expected ResolverFailed, got {err:?}"
        );
    }

    /// The same resolver failure, reached through the identical production
    /// path as the case above, but this time the proof carries a real
    /// `did:key` signature that simply does not verify — classified as
    /// `VerifyFailed`, and — the actual regression this pair guards — renders
    /// the same wire text as the resolver failure above.
    #[tokio::test]
    async fn an_actual_bad_signature_classifies_as_verify_failed_with_identical_wire_text() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut seed_secret = vec![0x80, 0x26];
        seed_secret.extend_from_slice(&[7u8; 32]);
        let secret_mb = multibase::encode(multibase::Base::Base58Btc, &seed_secret);

        let signed = crate::trust_task_sign::build_signed(
            "https://trusttasks.org/spec/vta/contexts/create/1.0",
            serde_json::json!({}),
            &did,
            &secret_mb,
            "did:key:z6MkVta",
        )
        .await
        .expect("build a validly-signed document");
        let mut doc: TrustTask<Value> = serde_json::from_str(&signed).expect("signed doc parses");

        // Corrupt the signature so it no longer verifies. A single-character
        // flip keeps the multibase string decodable (same length, same
        // alphabet), so this exercises "signature does not verify" rather
        // than "proof is malformed" — the failure this split must not
        // reclassify as a resolver problem.
        let proof = doc.proof.as_mut().expect("document is signed");
        let last = proof.proof_value.pop().expect("non-empty proofValue");
        proof.proof_value.push(if last == '1' { '2' } else { '1' });

        let err = verify_trust_task_proof_with(&doc, &TrustTaskVmResolver::did_key_only())
            .await
            .expect_err("a corrupted signature must not verify");
        assert!(
            matches!(err, DiProofError::VerifyFailed(_)),
            "expected VerifyFailed, got {err:?}"
        );

        // The invariant that matters: whichever of the two failed, the wire
        // text is the same one an unauthenticated caller would have seen for
        // the resolver failure above.
        assert_eq!(err.to_string(), "proof verification failed");
    }
}
