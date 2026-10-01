//! Reading the proof block of a document that may carry more than one proof.
//!
//! The implementation — the proof-set acceptance rule (`RequireAll` over the
//! checkable proofs, at least one, one signer), the skip-unknown-suite rule
//! and purpose binding (VTI-KEY-022) — lives in
//! [`vta_sdk::trust_task_proof::proof_set`], so the VTC, the VTA's vault and
//! the vetting client share one reading of a proof set (VTI-44). This module
//! re-exports what the VTC's verifiers call, and keeps the tests that pin the
//! VTC's own [`DidVmResolver`](super::vm_resolver::DidVmResolver) to it.

pub(crate) use vta_sdk::trust_task_proof::proof_set::{
    accept_all, proof_set, proof_signer_did, verify_one,
};

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::DataIntegrityProof;
    use serde_json::{Value as JsonValue, json};

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
