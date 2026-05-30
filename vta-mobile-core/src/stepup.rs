//! AAL step-up — build the `auth/step-up/approve-response` document.
//!
//! **Slice 2b: the WebAuthn-gated builder.** The carried passkey assertion over
//! the step-up challenge is the cryptographic gate, so no framework proof is
//! attached (per the approve-response spec). The DID-signed gate — which signs
//! the document via the native [`crate::keys::Signer`] callback — is the next
//! slice, and needs Data Integrity proof construction.

use chrono::DateTime;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::step_up::approve_response::v0_1 as approve_response;

use crate::error::FfiError;

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
/// this builder pure and deterministic.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ApproveResponseDraft {
    /// Document id (e.g. a fresh UUID).
    pub id: String,
    /// The approver's DID (document `issuer`).
    pub issuer_did: String,
    /// The relying party's DID (document `recipient`).
    pub recipient_did: String,
    /// RFC 3339 timestamp for `issuedAt`.
    pub issued_at: String,
    /// Echoed verbatim from the request.
    pub subject: String,
    pub session_id: String,
    /// The step-up challenge; the assertion's `clientDataJSON` signs over it.
    pub challenge: String,
    /// The acr the approver believes it demonstrated (e.g. `"aal2"`).
    pub granted_acr: Option<String>,
}

/// Build a passkey-backed `auth/step-up/approve-response/0.1`: decision
/// `approved`, `evidence.kind = webauthn` carrying `assertion`. The assertion is
/// the gate, so no framework proof is attached. Returns the serialized Trust
/// Task JSON for the native layer to send back to the relying party.
#[uniffi::export]
pub fn build_approve_response_webauthn(
    draft: ApproveResponseDraft,
    assertion: WebAuthnAssertion,
) -> Result<String, FfiError> {
    let issued_at = DateTime::parse_from_rfc3339(&draft.issued_at)
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("issued_at is not an RFC 3339 timestamp: {e}"),
        })?
        .with_timezone(&chrono::Utc);

    let payload = approve_response::Payload {
        subject: approve_response::PayloadSubject::try_from(draft.subject).map_err(conv)?,
        session_id: approve_response::PayloadSessionId::try_from(draft.session_id).map_err(conv)?,
        challenge: approve_response::PayloadChallenge::try_from(draft.challenge).map_err(conv)?,
        decision: approve_response::PayloadDecision::Approved,
        denied_reason: None,
        granted_acr: draft.granted_acr,
        evidence: Some(approve_response::Evidence::Webauthn(
            approve_response::AssertionResponse {
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
            },
        )),
        ext: None,
    };

    let mut doc = TrustTask::for_payload(draft.id, payload);
    doc.issuer = Some(draft.issuer_did);
    doc.recipient = Some(draft.recipient_did);
    doc.issued_at = Some(issued_at);

    serde_json::to_string(&doc).map_err(|e| FfiError::InvalidInput {
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
            "https://trusttasks.org/spec/auth/step-up/approve-response/0.1"
        );
        assert_eq!(v["issuer"], "did:web:alice.example");
        assert_eq!(v["recipient"], "did:web:bank.example");
        assert_eq!(v["payload"]["decision"], "approved");
        assert_eq!(v["payload"]["grantedAcr"], "aal2");
        assert_eq!(v["payload"]["evidence"]["kind"], "webauthn");
        assert_eq!(
            v["payload"]["evidence"]["assertion"]["response"]["signature"],
            "U2lnbmF0dXJlVmFsdWVCYXNlNjQ"
        );
        // No framework proof: the assertion is the gate.
        assert!(v.get("proof").is_none());
    }

    #[test]
    fn output_round_trips_back_through_the_typed_parser() {
        let json = build_approve_response_webauthn(draft(), assertion()).unwrap();
        // Deserializing into the typed envelope proves the built document is a
        // structurally-valid approve-response.
        let doc: TrustTask<approve_response::Payload> = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            doc.payload.evidence,
            Some(approve_response::Evidence::Webauthn(_))
        ));
        assert!(matches!(
            doc.payload.decision,
            approve_response::PayloadDecision::Approved
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
}
