//! AAL step-up gate verification (`auth/step-up/approve-response/0.1`).
//!
//! The relying party (this VTA) elevates a session only when the approve-
//! response carries exactly one verifiable cryptographic gate, per the spec's
//! consumer conformance rules:
//!
//! - **did-signed** — the document's Data Integrity proof (`eddsa-jcs-2022`)
//!   verifies under a key the subject controls, and the proof's
//!   `verificationMethod` DID equals the subject. [`verify_did_signed_gate`].
//! - **webauthn** — the carried assertion verifies per WebAuthn L2 §7.2 against
//!   the bound challenge (handled by the approve-response handler reusing
//!   `verify_passkey_login`).
//!
//! This module is the did-signed verifier; the handler that consumes the
//! pending step-up, dispatches on `evidence.kind`, and elevates the session
//! lands alongside it.

use affinidi_data_integrity::{DataIntegrityProof, DidKeyResolver, VerifyOptions};
use serde_json::Value;
use trust_tasks_rs::TrustTask;

/// Why a step-up gate failed to verify. Maps to the spec's approve-response
/// error codes in the handler.
#[derive(Debug, PartialEq)]
pub(super) enum GateError {
    /// No verifiable gate present (`no_gate`).
    NoGate,
    /// The proof's verificationMethod DID is not the session subject
    /// (`subject_mismatch`).
    SubjectMismatch,
    /// The framework proof is present but failed verification (`proof_invalid`).
    ProofInvalid(String),
}

/// Verify the **did-signed** gate on an approve-response document.
///
/// `expected_subject` is the session's subject (the handler has already checked
/// it equals the payload `subject` and the document `issuer`). Here we bind the
/// *cryptographic* identity: the proof's `verificationMethod` DID MUST equal it,
/// and the `eddsa-jcs-2022` signature MUST verify under that `did:key`.
///
/// `did:key` resolution is local (no I/O); the mobile holder key is always a
/// `did:key`, matching the engine's signing side.
#[allow(dead_code)] // wired by the approve-response handler (next in this slice)
pub(super) async fn verify_did_signed_gate(
    doc: &TrustTask<Value>,
    expected_subject: &str,
) -> Result<(), GateError> {
    let proof = doc.proof.as_ref().ok_or(GateError::NoGate)?;

    // The framework `Proof` round-trips into a `DataIntegrityProof` (same shape;
    // the mobile engine builds it the same way).
    let di: DataIntegrityProof = serde_json::to_value(proof)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| GateError::ProofInvalid("not a Data Integrity proof".to_string()))?;

    // Bind identity: the signing key's DID must be the subject. The resolver
    // confirms the signature is by this verificationMethod; this check ties
    // that VM to the subject so a valid proof by a *different* DID can't elevate.
    let vm_did = di.verification_method.split('#').next().unwrap_or_default();
    if vm_did != expected_subject {
        return Err(GateError::SubjectMismatch);
    }

    // Verify over the document with the proof removed (eddsa-jcs-2022
    // canonicalizes the proofless document; the signature lives on `di`).
    let mut unsigned = doc.clone();
    unsigned.proof = None;
    di.verify(&unsigned, &DidKeyResolver, VerifyOptions::new())
        .await
        .map_err(|e| GateError::ProofInvalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::prepare_sign_input;
    use ed25519_dalek::{Signer, SigningKey};
    use multibase::Base;
    use serde_json::json;
    use trust_tasks_rs::Proof;

    /// did:key for an Ed25519 verifying key (multicodec 0xed01 + key, base58btc).
    fn did_key(sk: &SigningKey) -> (String, String) {
        let pk = sk.verifying_key();
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(pk.as_bytes());
        let mb = multibase::encode(Base::Base58Btc, mc);
        (format!("did:key:{mb}"), mb)
    }

    /// Build an approve-response-shaped TrustTask and attach a did-signed
    /// eddsa-jcs-2022 proof from `sk` (mirrors the engine's signing side).
    fn signed_doc(sk: &SigningKey, subject: &str, vm: &str) -> TrustTask<Value> {
        // Build a TrustTask<Value> by deserialization (for_payload needs
        // P: Payload, which Value isn't) — proofless, ready to sign.
        let doc_json = json!({
            "id": "approve-resp-1",
            "type": "https://trusttasks.org/spec/auth/step-up/approve-response/0.1",
            "issuer": subject,
            "recipient": "did:web:vta.example",
            "payload": {
                "subject": subject,
                "sessionId": "sess-1",
                "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
                "decision": "approved",
                "grantedAcr": "aal2",
            },
        });
        let mut doc: TrustTask<Value> = serde_json::from_value(doc_json).unwrap();

        let mut di = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: CryptoSuite::EddsaJcs2022,
            created: Some("2026-05-31T00:00:00Z".to_string()),
            verification_method: vm.to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            context: None,
        };
        let input = prepare_sign_input(&doc, &di, CryptoSuite::EddsaJcs2022).unwrap();
        let sig = sk.sign(&input);
        di.proof_value = Some(multibase::encode(Base::Base58Btc, sig.to_bytes()));
        let proof_json = serde_json::to_value(&di).unwrap();
        doc.proof = Some(serde_json::from_value::<Proof>(proof_json).unwrap());
        doc
    }

    #[tokio::test]
    async fn verifies_a_did_signed_approve_response() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let (did, mb) = did_key(&sk);
        let vm = format!("{did}#{mb}");
        let doc = signed_doc(&sk, &did, &vm);
        assert_eq!(verify_did_signed_gate(&doc, &did).await, Ok(()));
    }

    #[tokio::test]
    async fn rejects_when_proof_absent() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let (did, mb) = did_key(&sk);
        let vm = format!("{did}#{mb}");
        let mut doc = signed_doc(&sk, &did, &vm);
        doc.proof = None;
        assert_eq!(
            verify_did_signed_gate(&doc, &did).await,
            Err(GateError::NoGate)
        );
    }

    #[tokio::test]
    async fn rejects_when_vm_did_is_not_the_subject() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let (did, mb) = did_key(&sk);
        let vm = format!("{did}#{mb}");
        let doc = signed_doc(&sk, &did, &vm);
        // Same valid proof, but a different expected subject.
        assert_eq!(
            verify_did_signed_gate(&doc, "did:key:zSomeoneElse").await,
            Err(GateError::SubjectMismatch)
        );
    }

    #[tokio::test]
    async fn rejects_a_tampered_document() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let (did, mb) = did_key(&sk);
        let vm = format!("{did}#{mb}");
        let mut doc = signed_doc(&sk, &did, &vm);
        // Tamper the payload after signing → signature no longer verifies.
        doc.payload = json!({ "subject": did, "decision": "approved", "tampered": true });
        assert!(matches!(
            verify_did_signed_gate(&doc, &did).await,
            Err(GateError::ProofInvalid(_))
        ));
    }
}
