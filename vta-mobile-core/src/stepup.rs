//! AAL step-up — build the `auth/step-up/approve-response` document for both
//! gates the spec defines:
//!
//! - **WebAuthn** ([`build_approve_response_webauthn`]) — the carried passkey
//!   assertion over the challenge is the gate; no framework proof is attached.
//! - **DID-signed** ([`build_approve_response_did_signed`]) — a Data Integrity
//!   proof (`eddsa-jcs-2022`) over the document is the gate, signed by the
//!   subject's key. The private key never enters Rust: `affinidi-data-integrity`
//!   produces the canonical signing input, the native [`crate::keys::Signer`]
//!   signs it in the enclave, and we assemble the proof from the signature.

use chrono::DateTime;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::step_up::approve_response::v0_2 as approve_response;

use crate::error::FfiError;
use crate::keys::Signer;
use crate::proof::attach_did_signed_proof;

/// A WebAuthn assertion produced natively (`ASAuthorization` / Credential
/// Manager). Binary fields are base64url-encoded, mirroring
/// `AuthenticatorAssertionResponse`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WebAuthnAssertion {
    /// The credential id (used for both `id` and `rawId`).
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    /// Present for discoverable credentials; maps the assertion to a subject.
    pub user_handle: Option<String>,
}

/// The envelope + echo fields for an approve-response. `id` and `issued_at` are
/// supplied by the native layer (which owns identifiers and the clock), keeping
/// these builders pure and deterministic.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ApproveResponseDraft {
    /// Document id (e.g. a fresh UUID).
    pub id: String,
    /// The approver's DID (document `issuer`).
    pub issuer_did: String,
    /// The relying party's DID (document `recipient`).
    pub recipient_did: String,
    /// RFC 3339 timestamp for `issuedAt` (and the proof's `created`).
    pub issued_at: String,
    /// Echoed verbatim from the request.
    pub subject: String,
    pub session_id: String,
    /// The step-up challenge; the gate signs/binds over it.
    pub challenge: String,
    /// The acr the approver believes it demonstrated (e.g. `"aal2"`).
    pub granted_acr: Option<String>,
}

/// Build a passkey-backed `auth/step-up/approve-response/0.2`: decision
/// `approved`, `evidence.kind = webauthn` carrying `assertion`. The assertion is
/// the gate, so no framework proof is attached. Returns the serialized Trust
/// Task JSON for the native layer to send back to the relying party.
#[uniffi::export]
pub fn build_approve_response_webauthn(
    draft: ApproveResponseDraft,
    assertion: WebAuthnAssertion,
) -> Result<String, FfiError> {
    let evidence = approve_response::Evidence::Webauthn(approve_response::AssertionResponse {
        id: assertion.credential_id.clone(),
        raw_id: assertion.credential_id,
        type_: serde_json::Value::String("public-key".to_string()),
        response: approve_response::AssertionResponseResponse {
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
            signature: assertion.signature,
            user_handle: assertion.user_handle,
        },
        authenticator_attachment: None,
        client_extension_results: serde_json::Map::new(),
    });
    let doc = assemble_doc(
        &draft,
        evidence,
        approve_response::PayloadDecision::Approved,
        None,
    )?;
    serialize(&doc)
}

/// Build a DID-signed `auth/step-up/approve-response/0.2`: decision `approved`,
/// `evidence.kind = didSigned`, gated by a Data Integrity proof
/// (`eddsa-jcs-2022`) over the document. `signer` is the native enclave key
/// (the holder/subject key) — its private material never enters this crate;
/// it only signs the canonical input produced here.
#[uniffi::export]
pub fn build_approve_response_did_signed(
    draft: ApproveResponseDraft,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let mut doc = assemble_doc(
        &draft,
        approve_response::Evidence::DidSigned,
        approve_response::PayloadDecision::Approved,
        None,
    )?;
    attach_did_signed_proof(&mut doc, &*signer, &draft.issued_at)?;
    serialize(&doc)
}

/// Build a DID-signed **denial** `auth/step-up/approve-response/0.2`: decision
/// `denied`, carrying the human `reason`, gated by the same `eddsa-jcs-2022`
/// proof as an approval. A denial is a *signed refusal* — the VTA verifies the
/// gate (so an injection can't forge it), audits `step_up_denied`, and elevates
/// nothing. This is how the operator says "no" from the device.
#[uniffi::export]
pub fn build_approve_response_denied(
    draft: ApproveResponseDraft,
    reason: String,
    signer: Box<dyn Signer>,
) -> Result<String, FfiError> {
    let mut doc = assemble_doc(
        &draft,
        approve_response::Evidence::DidSigned,
        approve_response::PayloadDecision::Denied,
        Some(reason),
    )?;
    attach_did_signed_proof(&mut doc, &*signer, &draft.issued_at)?;
    serialize(&doc)
}

/// Build the approve-response envelope + payload (no proof) for a given gate +
/// decision.
fn assemble_doc(
    draft: &ApproveResponseDraft,
    evidence: approve_response::Evidence,
    decision: approve_response::PayloadDecision,
    denied_reason: Option<String>,
) -> Result<TrustTask<approve_response::Payload>, FfiError> {
    let issued_at = DateTime::parse_from_rfc3339(&draft.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);

    let payload = approve_response::Payload {
        subject: approve_response::PayloadSubject::try_from(draft.subject.clone()).map_err(conv)?,
        session_id: approve_response::PayloadSessionId::try_from(draft.session_id.clone())
            .map_err(conv)?,
        challenge: approve_response::PayloadChallenge::try_from(draft.challenge.clone())
            .map_err(conv)?,
        decision,
        denied_reason,
        granted_acr: draft.granted_acr.clone(),
        evidence: Some(evidence),
        ext: None,
    };

    let mut doc = TrustTask::for_payload(draft.id.clone(), payload);
    doc.issuer = Some(draft.issuer_did.clone());
    doc.recipient = Some(draft.recipient_did.clone());
    doc.issued_at = Some(issued_at);
    Ok(doc)
}

fn serialize(doc: &TrustTask<approve_response::Payload>) -> Result<String, FfiError> {
    serde_json::to_string(doc).map_err(|e| FfiError::InvalidInput {
        reason: format!("failed to serialize approve-response: {e}"),
    })
}

/// Map a `trust-tasks-rs` newtype `ConversionError` (e.g. challenge below the
/// 16-byte minimum) to an FFI error.
fn conv<E: ::std::fmt::Display>(e: E) -> FfiError {
    FfiError::InvalidInput {
        reason: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> ApproveResponseDraft {
        ApproveResponseDraft {
            id: "approve-resp-aaaa".to_string(),
            issuer_did: "did:web:alice.example".to_string(),
            recipient_did: "did:web:bank.example".to_string(),
            issued_at: "2026-05-23T14:00:30Z".to_string(),
            subject: "did:web:alice.example".to_string(),
            session_id: "ec5d3c89-3f49-49b2-9d7d-2a8c0a8a7b9b".to_string(),
            challenge: "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ".to_string(),
            granted_acr: Some("aal2".to_string()),
        }
    }

    fn assertion() -> WebAuthnAssertion {
        WebAuthnAssertion {
            credential_id: "Y3JlZF8xYTJiM2M".to_string(),
            client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0".to_string(),
            authenticator_data: "TXltSXNUaGVBdXRoRGF0YQ".to_string(),
            signature: "U2lnbmF0dXJlVmFsdWVCYXNlNjQ".to_string(),
            user_handle: Some("dXNyXzhmMmMxZDRlOWE3YjMwNTY".to_string()),
        }
    }

    #[test]
    fn builds_webauthn_approve_response_shape() {
        let json = build_approve_response_webauthn(draft(), assertion()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["type"],
            "https://trusttasks.org/spec/auth/step-up/approve-response/0.2"
        );
        assert_eq!(v["payload"]["decision"], "approved");
        assert_eq!(v["payload"]["evidence"]["kind"], "webauthn");
        // No framework proof: the assertion is the gate.
        assert!(v.get("proof").is_none());
    }

    #[test]
    fn webauthn_output_round_trips_back_through_the_typed_parser() {
        let json = build_approve_response_webauthn(draft(), assertion()).unwrap();
        let doc: TrustTask<approve_response::Payload> = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            doc.payload.evidence,
            Some(approve_response::Evidence::Webauthn(_))
        ));
    }

    #[test]
    fn rejects_short_challenge() {
        let mut d = draft();
        d.challenge = "short".to_string(); // below the 16-char minimum
        let err = build_approve_response_webauthn(d, assertion()).unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_bad_issued_at() {
        let mut d = draft();
        d.issued_at = "not-a-timestamp".to_string();
        let err = build_approve_response_webauthn(d, assertion()).unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_non_did_key_signer() {
        struct WebSigner;
        impl Signer for WebSigner {
            fn did(&self) -> String {
                "did:web:alice.example".to_string()
            }
            fn sign(&self, _payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                unreachable!("vm derivation fails before signing")
            }
        }
        let err = build_approve_response_did_signed(draft(), Box::new(WebSigner)).unwrap_err();
        assert!(matches!(err, FfiError::InvalidInput { .. }));
    }

    /// End-to-end: build a DID-signed response with a test key standing in for
    /// the enclave Signer, then verify the produced Data Integrity proof with
    /// `affinidi-data-integrity` against that key. Proves the canonicalization +
    /// proofValue assembly are correct (a real RP would verify the same way).
    #[test]
    fn did_signed_response_verifies_against_the_holder_key() {
        use affinidi_data_integrity::DataIntegrityProof;
        use ed25519_dalek::{Signer as _, SigningKey};
        use multibase::Base;

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        // did:key for the Ed25519 public key: multicodec 0xed01 + key, base58btc.
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(pk.as_bytes());
        let mb = multibase::encode(Base::Base58Btc, mc);
        let did = format!("did:key:{mb}");

        struct EnclaveStub {
            sk: SigningKey,
            did: String,
        }
        impl Signer for EnclaveStub {
            fn did(&self) -> String {
                self.did.clone()
            }
            fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                Ok(self.sk.sign(&payload).to_bytes().to_vec())
            }
        }

        let json = build_approve_response_did_signed(
            draft(),
            Box::new(EnclaveStub {
                sk,
                did: did.clone(),
            }),
        )
        .unwrap();

        // 0.2 wire form: the type URI is `/0.2` and did-signed evidence
        // serializes as the camelCase `didSigned` (the sole 0.1→0.2 change).
        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            raw["type"],
            "https://trusttasks.org/spec/auth/step-up/approve-response/0.2"
        );
        assert_eq!(raw["payload"]["evidence"]["kind"], "didSigned");

        let doc: TrustTask<approve_response::Payload> = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            doc.payload.evidence,
            Some(approve_response::Evidence::DidSigned)
        ));
        let proof = doc
            .proof
            .clone()
            .expect("did-signed proof must be attached");
        let di: DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(&proof).unwrap()).unwrap();
        assert_eq!(di.verification_method, format!("{did}#{mb}"));

        let mut unsigned = doc;
        unsigned.proof = None;
        di.verify_with_public_key(
            &unsigned,
            pk.as_bytes(),
            affinidi_data_integrity::VerifyOptions::default(),
        )
        .expect("the did-signed proof must verify against the holder's key");
    }

    /// A denial is a *signed* refusal: decision `denied`, the human reason, a
    /// didSigned gate, and a verifiable proof (so an injection can't forge it).
    #[test]
    fn denied_response_is_signed_and_carries_the_reason() {
        use affinidi_data_integrity::DataIntegrityProof;
        use ed25519_dalek::{Signer as _, SigningKey};
        use multibase::Base;

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key();
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(pk.as_bytes());
        let mb = multibase::encode(Base::Base58Btc, mc);
        let did = format!("did:key:{mb}");

        struct EnclaveStub {
            sk: SigningKey,
            did: String,
        }
        impl Signer for EnclaveStub {
            fn did(&self) -> String {
                self.did.clone()
            }
            fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                Ok(self.sk.sign(&payload).to_bytes().to_vec())
            }
        }

        let json = build_approve_response_denied(
            draft(),
            "not something I authorized".to_string(),
            Box::new(EnclaveStub {
                sk,
                did: did.clone(),
            }),
        )
        .unwrap();

        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            raw["type"],
            "https://trusttasks.org/spec/auth/step-up/approve-response/0.2"
        );
        assert_eq!(raw["payload"]["decision"], "denied");
        assert_eq!(raw["payload"]["deniedReason"], "not something I authorized");
        assert_eq!(raw["payload"]["evidence"]["kind"], "didSigned");

        // The refusal is cryptographically signed, verifiable against the key.
        let doc: TrustTask<approve_response::Payload> = serde_json::from_str(&json).unwrap();
        let proof = doc.proof.clone().expect("a denial must be signed");
        let di: DataIntegrityProof =
            serde_json::from_value(serde_json::to_value(&proof).unwrap()).unwrap();
        let mut unsigned = doc;
        unsigned.proof = None;
        di.verify_with_public_key(
            &unsigned,
            pk.as_bytes(),
            affinidi_data_integrity::VerifyOptions::default(),
        )
        .expect("the denial's proof must verify against the holder's key");
    }
}
