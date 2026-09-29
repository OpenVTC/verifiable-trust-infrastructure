//! Reading the proof block of a document that may carry more than one proof.
//!
//! # Why this exists
//!
//! W3C Data Integrity allows a document to carry several proofs, and the
//! multi-year post-quantum transition is the reason to use it: a credential
//! signed with **both** Ed25519 and ML-DSA-44 can be verified by a classical
//! verifier and a post-quantum one, neither needing to know about the other.
//! `affinidi-data-integrity` has had `sign_multi` / `verify_multi` for this
//! since it was written, and until now nothing in this workspace called them.
//!
//! Every verification path here read the proof as a single object:
//!
//! ```ignore
//! let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())?;
//! ```
//!
//! A two-proof credential arrives as a JSON **array**, so that deserialize
//! fails and the credential is rejected as malformed. Which means the stack
//! could not have accepted a hybrid credential from anyone — including one it
//! issued itself, had issuance been wired first. That ordering is why
//! verification moves before issuance.
//!
//! # Acceptance rule
//!
//! `RequireAll`: at least one proof, and **every** proof present must verify.
//! A proof that is present but does not verify — a bad signature, a key the
//! issuer did not authorise for the proof's purpose (VTI-KEY-022), a proof
//! declaring the wrong purpose — is a refusal, not an absence: otherwise
//! anyone could append a proof to a credential and have its failure ignored.
//!
//! One kind of proof is set aside rather than refused: a proof whose
//! `cryptosuite` this build does not implement. A verifier cannot check it,
//! so it neither counts toward the "at least one" nor refuses the set — that
//! is what lets a hybrid credential carry a suite a classical verifier has
//! never heard of. A verifier that needs a particular suite says so with
//! [`require_suites`], and a set whose required suite is absent is refused.
//! A malformed proof, or a known suite whose proof fails, is never skipped.
//!
//! # The rule that is not about cryptography
//!
//! **Every proof that verifies must name the same issuer.** A document carrying
//! a valid proof from Alice and a valid proof from Bob is not "verified" in any
//! sense a single answer can express, and a caller handed one `Ok` would
//! reasonably assume one signer. Refusing is the only honest answer, and it also
//! closes the obvious trick: appending a proof from a party the reader trusts
//! more.

use serde_json::Value as JsonValue;

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions, crypto_suites::CryptoSuite};
use vti_common::auth::{ProofPurpose, PurposeBound, PurposeVmResolver};

/// The proofs on `value` that this build can verify, whether it carries one
/// or several.
///
/// A bare object is one proof — the shape everything in this workspace emits
/// today, and the reason this is not simply `Vec::deserialize`. A proof whose
/// `cryptosuite` this build does not implement is left out (see the module
/// docs); if that leaves nothing, the document is refused, because a verifier
/// that can check none of its proofs has no basis to accept it.
pub(crate) fn proof_set(proof_value: &JsonValue) -> Result<Vec<DataIntegrityProof>, String> {
    let raw: Vec<&JsonValue> = match proof_value {
        JsonValue::Array(items) => items.iter().collect(),
        single => vec![single],
    };
    if raw.is_empty() {
        return Err(
            "proof block is an empty array; a document with no proof is unsigned, \
                    which is a different thing from one whose proofs did not verify"
                .to_string(),
        );
    }

    let mut proofs = Vec::with_capacity(raw.len());
    for (i, v) in raw.iter().enumerate() {
        if unsupported_suite(v) {
            continue;
        }
        proofs.push(
            serde_json::from_value::<DataIntegrityProof>((*v).clone()).map_err(|e| {
                // The index matters: with several proofs, "did not parse" alone
                // leaves a caller unable to tell which one is malformed.
                format!("proof {i} did not parse as a Data Integrity proof: {e}")
            })?,
        );
    }
    if proofs.is_empty() {
        return Err(
            "no proof uses a cryptosuite this verifier implements, so none can be checked"
                .to_string(),
        );
    }
    Ok(proofs)
}

/// A Data Integrity proof naming, as a string, a `cryptosuite` this build
/// does not implement. Anything else — including a proof with no suite, or a
/// suite that is not a string — is left for the parser to refuse.
fn unsupported_suite(v: &JsonValue) -> bool {
    v.get("type").and_then(JsonValue::as_str) == Some("DataIntegrityProof")
        && v.get("cryptosuite")
            .and_then(JsonValue::as_str)
            .is_some_and(|suite| CryptoSuite::try_from(suite).is_err())
}

/// Local policy: refuse `proofs` unless each of `required` suites is among
/// them. Apply it to the output of [`proof_set`] after [`accept_all`], which
/// has already required every one of them to verify.
#[allow(dead_code)] // no verifier requires a suite yet; the hook is the policy's
pub(crate) fn require_suites(
    proofs: &[DataIntegrityProof],
    required: &[CryptoSuite],
) -> Result<(), String> {
    match required
        .iter()
        .find(|suite| !proofs.iter().any(|p| p.cryptosuite == **suite))
    {
        None => Ok(()),
        Some(missing) => Err(format!(
            "this verifier requires a {missing} proof, and the document carries none"
        )),
    }
}

/// The issuer DID a proof's `verificationMethod` names, before the fragment.
pub(crate) fn proof_signer_did(proof: &DataIntegrityProof) -> &str {
    proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default()
}

/// Verify one proof over `doc` for `expected` — the purpose the document is
/// relied on for (VTI-KEY-022): `assertionMethod` for a credential, which is an
/// attestation, and `authentication` for a presentation or a holder binding,
/// which proves control of an identifier.
///
/// The proof must declare that purpose, and its key is resolved for it, so a
/// key its DID document lists only for another purpose — or only for key
/// agreement — cannot make the proof.
pub(crate) async fn verify_one<S>(
    proof: &DataIntegrityProof,
    doc: &S,
    resolver: &(dyn PurposeVmResolver + '_),
    expected: ProofPurpose,
) -> Result<(), String>
where
    S: serde::Serialize + Sync,
{
    let bound = PurposeBound::for_proof(resolver, proof).map_err(|e| e.to_string())?;
    if bound.purpose() != expected {
        return Err(format!(
            "proofPurpose is {}, but this document is relied on for {expected}",
            bound.purpose()
        ));
    }
    proof
        .verify(doc, &bound, VerifyOptions::new())
        .await
        .map_err(|e| e.to_string())
}

/// Apply the acceptance rule to the outcome of verifying each proof.
///
/// `outcomes` pairs each proof's signer DID with whether it verified. Every
/// proof must have verified, there must be at least one, and they must all
/// name one signer, which is returned.
pub(crate) fn accept_all(outcomes: &[(String, Result<(), String>)]) -> Result<String, String> {
    let Some((first, _)) = outcomes.first() else {
        return Err("no proof to verify; a document with no proof is unsigned".to_string());
    };

    // Report every failure, not just the first: with a hybrid credential the
    // interesting information is usually *which* suite failed.
    let reasons: Vec<String> = outcomes
        .iter()
        .enumerate()
        .filter_map(|(i, (_, r))| r.as_ref().err().map(|e| format!("proof {i}: {e}")))
        .collect();
    if !reasons.is_empty() {
        return Err(format!(
            "{} of {} proofs did not verify, and every proof present must — {}",
            reasons.len(),
            outcomes.len(),
            reasons.join("; ")
        ));
    }

    if outcomes.iter().any(|(did, _)| did != first) {
        return Err(
            "proofs verify for two different issuers; a document signed by more than one \
             party cannot be reported as verified for one of them"
                .to_string(),
        );
    }
    Ok(first.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn a_proof(vm: &str) -> JsonValue {
        json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-01-01T00:00:00Z",
            "verificationMethod": vm,
            "proofPurpose": "assertionMethod",
            "proofValue": "z2V1p3vLnQ8kZ9YbW3xJ5tR7mN4qS6dF8gH1jK2lM3nP",
        })
    }

    /// A single proof object still reads as one proof — everything this
    /// workspace emits today is this shape, and the change must not require a
    /// document to become an array to stay valid.
    #[test]
    fn a_bare_object_is_one_proof() {
        let set = proof_set(&a_proof("did:example:alice#key-0")).expect("parses");
        assert_eq!(set.len(), 1);
    }

    /// The case the old code could not read at all.
    #[test]
    fn an_array_is_a_proof_set() {
        let set = proof_set(&json!([
            a_proof("did:example:alice#key-0"),
            a_proof("did:example:alice#key-pq"),
        ]))
        .expect("parses");
        assert_eq!(set.len(), 2);
    }

    /// A malformed proof names its position, because "did not parse" alone
    /// leaves a caller with several proofs unable to tell which.
    #[test]
    fn a_malformed_proof_is_identified_by_index() {
        let err = proof_set(&json!([
            a_proof("did:example:alice#key-0"),
            json!({"type": "nope"})
        ]))
        .expect_err("the second proof is not a Data Integrity proof");
        assert!(err.contains("proof 1"), "unexpected: {err}");
    }

    /// A proof in a suite this build does not implement is set aside, not
    /// refused: the rest of the set is still checked.
    #[test]
    fn an_unsupported_suite_is_skipped() {
        let mut pq = a_proof("did:example:alice#key-pq");
        pq["cryptosuite"] = json!("example-future-2030");
        let set = proof_set(&json!([a_proof("did:example:alice#key-0"), pq])).expect("parses");
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].verification_method, "did:example:alice#key-0");
    }

    /// A set of which this verifier can check nothing is refused.
    #[test]
    fn only_unsupported_suites_is_refused() {
        let mut pq = a_proof("did:example:alice#key-pq");
        pq["cryptosuite"] = json!("example-future-2030");
        let err = proof_set(&pq).expect_err("nothing to check");
        assert!(err.contains("no proof uses a cryptosuite"), "{err}");
    }

    /// A proof with no suite is malformed, not unsupported.
    #[test]
    fn a_proof_with_no_suite_is_not_skipped() {
        let mut p = a_proof("did:example:alice#key-0");
        p.as_object_mut().unwrap().remove("cryptosuite");
        assert!(proof_set(&json!([a_proof("did:example:alice#key-0"), p])).is_err());
    }

    /// Policy may require a suite; its absence refuses the set.
    #[test]
    fn a_required_suite_must_be_present() {
        let set = proof_set(&a_proof("did:example:alice#key-0")).expect("parses");
        require_suites(&set, &[CryptoSuite::EddsaJcs2022]).expect("present");
        let err = require_suites(
            &set,
            &[CryptoSuite::EddsaJcs2022, CryptoSuite::EcdsaJcs2019],
        )
        .expect_err("ecdsa absent");
        assert!(err.contains("ecdsa-jcs-2019"), "{err}");
    }

    /// An empty array is distinguished from an unsigned document.
    #[test]
    fn an_empty_array_says_what_it_is() {
        let err = proof_set(&json!([])).expect_err("empty");
        assert!(err.contains("unsigned"), "unexpected: {err}");
    }

    /// **A present-but-invalid proof is a refusal.** One good proof beside one
    /// that does not verify is not a verified document: otherwise anyone can
    /// append a proof to a credential and have its failure ignored.
    #[test]
    fn one_failing_proof_refuses_the_set() {
        let did = "did:example:alice".to_string();
        let err = accept_all(&[
            (
                did.clone(),
                Err("key not listed under assertionMethod".into()),
            ),
            (did.clone(), Ok(())),
        ])
        .expect_err("a failing proof refuses the set");
        assert!(err.contains("1 of 2 proofs"), "unexpected: {err}");
        assert!(err.contains("assertionMethod"), "unexpected: {err}");
    }

    /// Every proof verifying is accepted, and names the one signer.
    #[test]
    fn every_proof_verifying_is_accepted() {
        let did = "did:example:alice".to_string();
        let out = accept_all(&[(did.clone(), Ok(())), (did.clone(), Ok(()))]).expect("all verify");
        assert_eq!(out, did);
    }

    /// At least one proof is required.
    #[test]
    fn an_empty_outcome_set_is_refused() {
        assert!(accept_all(&[]).is_err());
    }

    /// When nothing verifies, every reason is reported.
    ///
    /// With a hybrid credential the interesting fact is usually *which* suite
    /// failed, and a first-error-only message hides exactly that.
    #[test]
    fn no_verifying_proof_reports_every_reason() {
        let err = accept_all(&[
            ("did:example:alice".into(), Err("bad signature".into())),
            ("did:example:alice".into(), Err("unsupported suite".into())),
        ])
        .expect_err("nothing verified");
        assert!(err.contains("bad signature"), "unexpected: {err}");
        assert!(err.contains("unsupported suite"), "unexpected: {err}");
    }

    /// **The rule that is not about cryptography.** Two valid proofs from two
    /// different issuers is not a verified document.
    ///
    /// Both signatures are real here; that is what makes it worth refusing. A
    /// caller handed one `Ok` and one DID would reasonably believe one party
    /// signed — and the obvious trick is appending a proof from someone the
    /// reader trusts more.
    #[test]
    fn proofs_from_two_issuers_are_refused_even_when_both_verify() {
        let err = accept_all(&[
            ("did:example:alice".into(), Ok(())),
            ("did:example:mallory".into(), Ok(())),
        ])
        .expect_err("two issuers cannot be reported as one");
        assert!(err.contains("two different issuers"), "unexpected: {err}");
        assert!(
            !err.contains("mallory"),
            "no identifiers in the refusal: {err}"
        );
    }

    // ─── Real proofs through the real resolver ──────────────────────────

    use crate::credentials::vm_resolver::DidVmResolver;
    use affinidi_data_integrity::SignOptions;
    use affinidi_secrets_resolver::secrets::Secret;
    use vti_common::auth::ProofPurpose;

    /// A did:key signer for `seed`, and the document every test signs.
    fn did_key_signer(seed: u8) -> (String, Secret) {
        let probe = Secret::generate_ed25519(None, Some(&[seed; 32]));
        let mb = probe.get_public_keymultibase().expect("multikey");
        let vm = format!("did:key:{mb}#{mb}");
        (
            vm.clone(),
            Secret::generate_ed25519(Some(&vm), Some(&[seed; 32])),
        )
    }

    async fn signed_proof(secret: &Secret, purpose: &str, doc: &JsonValue) -> DataIntegrityProof {
        DataIntegrityProof::sign(doc, secret, SignOptions::new().with_proof_purpose(purpose))
            .await
            .expect("sign")
    }

    fn doc() -> JsonValue {
        json!({ "type": ["VerifiableCredential"], "credentialSubject": { "id": "did:example:s" } })
    }

    /// did:key's one key is authorised for both purposes, as did:key defines.
    #[tokio::test]
    async fn a_did_key_proof_verifies_for_both_purposes() {
        let (_, secret) = did_key_signer(0x31);
        let resolver = DidVmResolver::new(None);
        for (purpose, expected) in [
            ("assertionMethod", ProofPurpose::AssertionMethod),
            ("authentication", ProofPurpose::Authentication),
        ] {
            let proof = signed_proof(&secret, purpose, &doc()).await;
            verify_one(&proof, &doc(), &resolver, expected)
                .await
                .unwrap_or_else(|e| panic!("{purpose}: {e}"));
        }
    }

    /// A genuine signature for the wrong purpose is refused: a credential is
    /// relied on as an attestation, and an `authentication` proof is not one.
    #[tokio::test]
    async fn a_proof_for_another_purpose_is_refused() {
        let (_, secret) = did_key_signer(0x32);
        let proof = signed_proof(&secret, "authentication", &doc()).await;
        let err = verify_one(
            &proof,
            &doc(),
            &DidVmResolver::new(None),
            ProofPurpose::AssertionMethod,
        )
        .await
        .expect_err("wrong purpose");
        assert!(err.contains("relied on for assertionMethod"), "{err}");

        let proof = signed_proof(&secret, "keyAgreement", &doc()).await;
        assert!(
            verify_one(
                &proof,
                &doc(),
                &DidVmResolver::new(None),
                ProofPurpose::AssertionMethod
            )
            .await
            .is_err()
        );
    }

    /// A did:key names exactly one method; any other fragment is not its key.
    #[tokio::test]
    async fn a_did_key_with_a_foreign_fragment_is_refused() {
        let (vm, _) = did_key_signer(0x33);
        let did = vm.split('#').next().unwrap();
        let err = DidVmResolver::new(None)
            .resolve_ed25519(&format!("{did}#key-0"), ProofPurpose::AssertionMethod)
            .await
            .expect_err("#key-0 is not a did:key method");
        assert!(err.to_string().contains("fragment must repeat"), "{err}");
    }

    /// **The proof-set rule end to end.** A valid proof beside a tampered one
    /// from the same signer is refused.
    #[tokio::test]
    async fn a_proof_set_with_one_invalid_proof_is_refused() {
        let (vm, secret) = did_key_signer(0x34);
        let good = signed_proof(&secret, "assertionMethod", &doc()).await;
        let mut bad = good.clone();
        bad.proof_value = Some(
            signed_proof(&secret, "assertionMethod", &json!({"other": 1}))
                .await
                .proof_value
                .expect("proofValue"),
        );
        let resolver = DidVmResolver::new(None);
        let did = vm.split('#').next().unwrap().to_string();
        let mut outcomes = Vec::new();
        for p in [&good, &bad] {
            outcomes.push((
                did.clone(),
                verify_one(p, &doc(), &resolver, ProofPurpose::AssertionMethod).await,
            ));
        }
        assert!(outcomes[0].1.is_ok(), "{:?}", outcomes[0].1);
        let err = accept_all(&outcomes).expect_err("one invalid proof refuses the set");
        assert!(err.contains("1 of 2 proofs"), "{err}");
    }
}
