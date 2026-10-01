//! Reading and verifying the proof block of a document that may carry more
//! than one proof.
//!
//! # Why this exists
//!
//! W3C Data Integrity allows a document to carry several proofs, and the
//! multi-year post-quantum transition is the reason to use it: a credential
//! signed with **both** Ed25519 and ML-DSA-44 can be verified by a classical
//! verifier and a post-quantum one, neither needing to know about the other.
//! A VTC holding several signing keys signs every credential it issues once per
//! key, so its `proof` is a JSON **array**:
//!
//! ```json
//! "proof": [
//!   { "cryptosuite": "eddsa-jcs-2022",   "verificationMethod": "did:…#key-0", … },
//!   { "cryptosuite": "mldsa44-jcs-2024", "verificationMethod": "did:…#key-2", … }
//! ]
//! ```
//!
//! A verifier that reads `proof` as one object refuses every such credential
//! (VTI-44: the vault refused every membership card a multi-key VTC issued).
//! This module is the one implementation every verifier in the workspace uses —
//! it began in `vtc-service` and moved here so the vault, the vetting client
//! and the VTC cannot disagree about what a proof set means.
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
//! **Every proof that verifies must name the same signer.** A document carrying
//! a valid proof from Alice and a valid proof from Bob is not "verified" in any
//! sense a single answer can express, and a caller handed one `Ok` would
//! reasonably assume one signer. Refusing is the only honest answer, and it also
//! closes the obvious trick: appending a proof from a party the reader trusts
//! more.
//!
//! # Verify over what was received
//!
//! [`verify_proof_set`] verifies each proof over the received JSON with the
//! top-level `proof` removed — never over a re-serialised typed struct, which
//! can differ from the signed bytes in ways JCS will notice.

use serde_json::Value as JsonValue;

use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions, crypto_suites::CryptoSuite};

use super::purpose::{ProofPurpose, PurposeBound, PurposeVmResolver};

/// The proofs on `proof_value` that this build can verify, whether it carries
/// one or several.
///
/// A bare object is one proof — the historical shape, and the reason this is
/// not simply `Vec::deserialize`. A proof whose `cryptosuite` this build does
/// not implement is left out (see the module docs); if that leaves nothing, the
/// document is refused, because a verifier that can check none of its proofs
/// has no basis to accept it. A malformed proof is refused, naming its index.
pub fn proof_set(proof_value: &JsonValue) -> Result<Vec<DataIntegrityProof>, String> {
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
/// them. Apply it to the output of [`proof_set`] (or
/// [`VerifiedProofSet::proofs`]) after [`accept_all`], which has already
/// required every one of them to verify.
pub fn require_suites(
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

/// The signer DID a proof's `verificationMethod` names, before the fragment.
#[must_use]
pub fn proof_signer_did(proof: &DataIntegrityProof) -> &str {
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
pub async fn verify_one<S>(
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
pub fn accept_all(outcomes: &[(String, Result<(), String>)]) -> Result<String, String> {
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

/// Why [`verify_proof_set`] refused a document.
///
/// [`Display`](std::fmt::Display) names the rule that failed; the detail
/// strings carry verifier output, which names no key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofSetError {
    /// The document has no top-level `proof`.
    #[error("document has no proof")]
    Missing,
    /// The document is not a JSON object, so it has no proof to strip.
    #[error("signed document is not a JSON object")]
    NotAnObject,
    /// The proof block is unreadable: an empty array, a malformed proof, or no
    /// proof in a suite this build implements.
    #[error("proof block is unreadable: {0}")]
    Unreadable(String),
    /// A proof did not verify, or the proofs name more than one signer.
    #[error("proof set did not verify: {0}")]
    NotVerified(String),
}

/// A document whose proof set verified under the acceptance rule — only
/// constructable by [`verify_proof_set`].
#[derive(Debug, Clone)]
pub struct VerifiedProofSet {
    signer: String,
    proofs: Vec<DataIntegrityProof>,
}

impl VerifiedProofSet {
    /// The one DID every checked proof was made by. The caller binds it to the
    /// party the document names (a credential's `issuer`, a card's publisher).
    #[must_use]
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// The proofs that were checked, all of which verified. Proofs in a suite
    /// this build does not implement are not among them.
    #[must_use]
    pub fn proofs(&self) -> &[DataIntegrityProof] {
        &self.proofs
    }

    /// The signer DID, consuming the set.
    #[must_use]
    pub fn into_signer(self) -> String {
        self.signer
    }
}

/// Verify the proof block of `signed` — one proof object or a proof set —
/// under the acceptance rule in the module docs, every proof bound to
/// `expected` purpose and resolved through `resolver`.
///
/// Each proof is verified over `signed` as received, with its top-level
/// `proof` removed. Returns the one signer every checked proof names; binding
/// that signer to the party the document claims is the caller's job.
pub async fn verify_proof_set(
    signed: &JsonValue,
    expected: ProofPurpose,
    resolver: &(dyn PurposeVmResolver + '_),
) -> Result<VerifiedProofSet, ProofSetError> {
    let map = signed.as_object().ok_or(ProofSetError::NotAnObject)?;
    let proof_value = map.get("proof").ok_or(ProofSetError::Missing)?;
    let proofs = proof_set(proof_value).map_err(ProofSetError::Unreadable)?;

    let mut unsigned = map.clone();
    unsigned.remove("proof");
    let unsigned = JsonValue::Object(unsigned);

    let mut outcomes = Vec::with_capacity(proofs.len());
    for proof in &proofs {
        let did = proof_signer_did(proof).to_string();
        let r = verify_one(proof, &unsigned, resolver, expected).await;
        outcomes.push((did, r));
    }
    let signer = accept_all(&outcomes).map_err(ProofSetError::NotVerified)?;
    Ok(VerifiedProofSet { signer, proofs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_task_proof::TrustTaskVmResolver;
    use affinidi_data_integrity::{DataIntegrityError, ResolvedKey, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;
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

    /// A single proof object still reads as one proof — the historical shape
    /// must not have to become an array to stay valid.
    #[test]
    fn a_bare_object_is_one_proof() {
        let set = proof_set(&a_proof("did:example:alice#key-0")).expect("parses");
        assert_eq!(set.len(), 1);
    }

    /// The case the old single-object readers could not read at all.
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

    // ─── Real proofs through a real resolver ────────────────────────────

    /// A did:key signer for `seed`, with its one method id.
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
        let resolver = TrustTaskVmResolver::did_key_only();
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
        let resolver = TrustTaskVmResolver::did_key_only();
        let proof = signed_proof(&secret, "authentication", &doc()).await;
        let err = verify_one(&proof, &doc(), &resolver, ProofPurpose::AssertionMethod)
            .await
            .expect_err("wrong purpose");
        assert!(err.contains("relied on for assertionMethod"), "{err}");

        let proof = signed_proof(&secret, "keyAgreement", &doc()).await;
        assert!(
            verify_one(&proof, &doc(), &resolver, ProofPurpose::AssertionMethod)
                .await
                .is_err()
        );
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
        let resolver = TrustTaskVmResolver::did_key_only();
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

    // ─── verify_proof_set over a hybrid (Ed25519 + ML-DSA-44) signer ────

    const ISSUER: &str = "did:web:issuer.example";

    /// Resolves a fixed set of verification methods, for any purpose — the
    /// DID document a multi-key issuer would publish, without the network.
    struct FixedKeys(Vec<(String, ResolvedKey)>);

    #[async_trait::async_trait]
    impl PurposeVmResolver for FixedKeys {
        async fn resolve_vm_for_purpose(
            &self,
            vm: &str,
            _purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            self.0
                .iter()
                .find(|(id, _)| id == vm)
                .map(|(_, k)| k.clone())
                .ok_or_else(|| DataIntegrityError::Resolver(format!("unknown method {vm}")))
        }
    }

    fn key_of(secret: &Secret) -> (String, ResolvedKey) {
        (
            secret.id.clone(),
            ResolvedKey::new(secret.get_key_type(), secret.get_public_bytes().to_vec()),
        )
    }

    /// `#key-0` Ed25519 and `#key-2` ML-DSA-44, both under [`ISSUER`] — the
    /// shape of the field VTC's credentials.
    fn hybrid_keys() -> (Secret, Secret) {
        (
            Secret::generate_ed25519(Some(&format!("{ISSUER}#key-0")), Some(&[0x41; 32])),
            Secret::generate_ml_dsa_44(Some(&format!("{ISSUER}#key-2")), Some(&[0x42; 32])),
        )
    }

    /// Sign `doc` once per key, writing `proof` as the array a multi-key VTC
    /// emits.
    async fn sign_set(mut doc: JsonValue, secrets: &[&Secret], purpose: &str) -> JsonValue {
        let signers: Vec<&dyn affinidi_data_integrity::signer::Signer> = secrets
            .iter()
            .map(|s| *s as &dyn affinidi_data_integrity::signer::Signer)
            .collect();
        let proofs = DataIntegrityProof::sign_multi(
            &doc,
            &signers,
            SignOptions::new().with_proof_purpose(purpose),
        )
        .await
        .expect("sign_multi");
        doc["proof"] = serde_json::to_value(&proofs).unwrap();
        doc
    }

    /// VTI-44: a credential signed by an Ed25519 **and** an ML-DSA-44 key
    /// verifies, and both proofs are checked.
    #[tokio::test]
    async fn vti_44_a_hybrid_proof_set_verifies() {
        let (ed, pq) = hybrid_keys();
        let resolver = FixedKeys(vec![key_of(&ed), key_of(&pq)]);
        let signed = sign_set(doc(), &[&ed, &pq], "assertionMethod").await;
        assert!(signed["proof"].is_array());

        let verified = verify_proof_set(&signed, ProofPurpose::AssertionMethod, &resolver)
            .await
            .expect("both proofs verify");
        assert_eq!(verified.signer(), ISSUER);
        assert_eq!(verified.proofs().len(), 2);
        require_suites(
            verified.proofs(),
            &[CryptoSuite::EddsaJcs2022, CryptoSuite::MlDsa44Jcs2024],
        )
        .expect("both suites were checked");
    }

    /// VTI-44: tampering with the document after signing fails every proof,
    /// and tampering with one proof alone still refuses the set.
    #[tokio::test]
    async fn vti_44_one_tampered_proof_refuses_the_set() {
        let (ed, pq) = hybrid_keys();
        let resolver = FixedKeys(vec![key_of(&ed), key_of(&pq)]);
        let signed = sign_set(doc(), &[&ed, &pq], "assertionMethod").await;

        // Replace the ML-DSA proof's value with one over another document.
        let other = sign_set(json!({"other": 1}), &[&ed, &pq], "assertionMethod").await;
        let mut tampered = signed.clone();
        tampered["proof"][1]["proofValue"] = other["proof"][1]["proofValue"].clone();
        let err = verify_proof_set(&tampered, ProofPurpose::AssertionMethod, &resolver)
            .await
            .expect_err("one bad proof refuses the set");
        assert!(
            matches!(&err, ProofSetError::NotVerified(d) if d.contains("1 of 2 proofs")),
            "{err:?}"
        );

        let mut altered = signed;
        altered["credentialSubject"]["id"] = json!("did:example:mallory");
        assert!(
            verify_proof_set(&altered, ProofPurpose::AssertionMethod, &resolver)
                .await
                .is_err()
        );
    }

    /// A proof from a second party appended to a genuine one is refused, even
    /// though both signatures are real.
    #[tokio::test]
    async fn vti_44_a_proof_from_another_signer_refuses_the_set() {
        let (ed, _) = hybrid_keys();
        let stranger =
            Secret::generate_ed25519(Some("did:web:stranger.example#key-0"), Some(&[0x43; 32]));
        let resolver = FixedKeys(vec![key_of(&ed), key_of(&stranger)]);
        let signed = sign_set(doc(), &[&ed, &stranger], "assertionMethod").await;
        let err = verify_proof_set(&signed, ProofPurpose::AssertionMethod, &resolver)
            .await
            .expect_err("two signers");
        assert!(
            matches!(&err, ProofSetError::NotVerified(d) if d.contains("two different issuers")),
            "{err:?}"
        );
    }

    /// A single proof object still verifies through the high-level helper, and
    /// the wrong expected purpose is refused.
    #[tokio::test]
    async fn vti_44_a_single_proof_object_still_verifies() {
        let (vm, secret) = did_key_signer(0x35);
        let mut signed = doc();
        signed["proof"] =
            serde_json::to_value(signed_proof(&secret, "assertionMethod", &doc()).await).unwrap();
        assert!(signed["proof"].is_object());
        let resolver = TrustTaskVmResolver::did_key_only();
        let verified = verify_proof_set(&signed, ProofPurpose::AssertionMethod, &resolver)
            .await
            .expect("verifies");
        assert_eq!(verified.signer(), vm.split('#').next().unwrap());
        assert!(
            verify_proof_set(&signed, ProofPurpose::Authentication, &resolver)
                .await
                .is_err()
        );
    }

    /// No proof, and a non-object document, are refused with their own reason.
    #[tokio::test]
    async fn an_unsigned_document_is_refused() {
        let resolver = TrustTaskVmResolver::did_key_only();
        assert_eq!(
            verify_proof_set(&doc(), ProofPurpose::AssertionMethod, &resolver)
                .await
                .unwrap_err(),
            ProofSetError::Missing
        );
        assert_eq!(
            verify_proof_set(&json!([1]), ProofPurpose::AssertionMethod, &resolver)
                .await
                .unwrap_err(),
            ProofSetError::NotAnObject
        );
    }
}
