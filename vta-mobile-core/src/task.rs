//! Trust Task parsing — wraps `trust-tasks-rs` generated types.
//!
//! **Slice 2.** Parses an inbound `auth/step-up/approve-request` so the native
//! app can show the user the reason and decide which evidence gate to satisfy.
//! Building the signed/passkey-backed `approve-response` is the next slice
//! (needs newtype construction + the WebAuthn assertion record); proof
//! verification (async, crypto) follows that.

use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::step_up::approve_request::v0_1 as approve_request;

use crate::error::FfiError;

/// The fields of an `auth/step-up/approve-request` the native consent UI needs
/// to display and to decide how to respond.
#[derive(Debug, Clone, uniffi::Record)]
pub struct StepUpRequest {
    /// The relying party that issued the request (document `issuer`), if present.
    pub relying_party: Option<String>,
    /// The VID whose session is being elevated.
    pub subject: String,
    /// Opaque session id; echoed back verbatim in the response.
    pub session_id: String,
    /// base64url challenge the response must bind.
    pub challenge: String,
    /// Human-readable reason — MUST be shown to the user verbatim for consent.
    pub reason: String,
    /// The acr the relying party wants (e.g. `"aal2"`), if specified.
    pub target_acr: Option<String>,
    /// Evidence gates the relying party will accept (`"did-signed"` / `"webauthn"`).
    /// Empty when the request did not constrain it (any supported kind is allowed).
    pub acceptable_evidence: Vec<String>,
    /// Whether the request carried WebAuthn options — i.e. the relying party
    /// wants a passkey-backed elevation and supplied the ceremony parameters.
    pub webauthn_requested: bool,
    /// Structured authorization context (raw JSON), when the request carries one
    /// under the reverse-DNS `payload.ext` key `org.openvtc.authorization-context`
    /// — e.g. a Cierge cross-domain share / spend / tool ask. The native layer
    /// decodes and renders it as the approval card; absent for a plain
    /// login-elevation step-up (the UI falls back to `reason`).
    pub authorization_context: Option<String>,
}

/// Reverse-DNS `payload.ext` key (SPEC §4.5.1) under which the VTA embeds the
/// structured authorization context. Kept in lockstep with the VTA
/// (`vta-service` `EXT_KEY_AUTHZ_CONTEXT`).
const EXT_KEY_AUTHZ_CONTEXT: &str = "org.openvtc.authorization-context";

/// Parse an inbound `auth/step-up/approve-request/0.1` Trust Task document.
///
/// Deserialises and structurally validates the document via `trust-tasks-rs`
/// (well-formed envelope + required payload fields + a valid Type URI), then
/// surfaces the fields the native consent UI needs. Returns [`FfiError::Decode`]
/// if the input is not a well-formed approve-request.
#[uniffi::export]
pub fn parse_step_up_request(json: String) -> Result<StepUpRequest, FfiError> {
    let doc: TrustTask<approve_request::Payload> =
        serde_json::from_str(&json).map_err(|e| FfiError::Decode {
            reason: format!("not a valid auth/step-up/approve-request document: {e}"),
        })?;
    // Pull the structured authorization context (if any) from `payload.ext` by
    // its reverse-DNS key, as a raw JSON string for the native layer to decode.
    // Read from a lenient Value copy so we don't depend on the generated `Ext`
    // newtype's key API; the typed parse above already validated the envelope,
    // so this re-parse cannot fail.
    let authorization_context = serde_json::from_str::<serde_json::Value>(&json)
        .ok()
        .and_then(|v| {
            v.get("payload")
                .and_then(|p| p.get("ext"))
                .and_then(|e| e.get(EXT_KEY_AUTHZ_CONTEXT))
                .map(|c| c.to_string())
        });

    let p = doc.payload;
    Ok(StepUpRequest {
        relying_party: doc.issuer,
        subject: p.subject.to_string(),
        session_id: p.session_id.to_string(),
        challenge: p.challenge.to_string(),
        reason: p.reason.to_string(),
        target_acr: p.target_acr,
        acceptable_evidence: p
            .acceptable_evidence
            .unwrap_or_default()
            .iter()
            .map(|e| e.to_string())
            .collect(),
        webauthn_requested: p.webauthn.is_some(),
        authorization_context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The passkey-backed request example from the approve-request spec.
    const PASSKEY_REQUEST: &str = r#"{
      "id": "step-up-2345-6789-01bc-def123456789",
      "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
      "issuer": "did:web:bank.example",
      "recipient": "did:web:alice.example",
      "issuedAt": "2026-05-23T14:00:00Z",
      "payload": {
        "subject": "did:web:alice.example",
        "sessionId": "ec5d3c89-3f49-49b2-9d7d-2a8c0a8a7b9b",
        "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
        "reason": "Confirm transfer of $1,000 to did:web:bob.example",
        "targetAcr": "aal2",
        "acceptableEvidence": ["webauthn"],
        "webauthn": {
          "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
          "rpId": "bank.example",
          "userVerification": "required",
          "allowCredentials": [{ "type": "public-key", "id": "Y3JlZF8xYTJiM2M" }]
        },
        "ttl": 120
      }
    }"#;

    #[test]
    fn parses_passkey_backed_request() {
        let r = parse_step_up_request(PASSKEY_REQUEST.to_string()).unwrap();
        assert_eq!(r.relying_party.as_deref(), Some("did:web:bank.example"));
        assert_eq!(r.subject, "did:web:alice.example");
        assert_eq!(r.session_id, "ec5d3c89-3f49-49b2-9d7d-2a8c0a8a7b9b");
        assert_eq!(r.challenge, "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ");
        assert!(r.reason.starts_with("Confirm transfer"));
        assert_eq!(r.target_acr.as_deref(), Some("aal2"));
        assert_eq!(r.acceptable_evidence, vec!["webauthn".to_string()]);
        assert!(r.webauthn_requested);
    }

    #[test]
    fn parses_minimal_did_signed_request() {
        // No acceptableEvidence / webauthn → empty list, not requested.
        let json = r#"{
          "id": "x",
          "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
          "issuer": "did:web:bank.example",
          "payload": {
            "subject": "did:web:alice.example",
            "sessionId": "s1",
            "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
            "reason": "Approve sign-in"
          }
        }"#;
        let r = parse_step_up_request(json.to_string()).unwrap();
        assert!(r.acceptable_evidence.is_empty());
        assert!(!r.webauthn_requested);
        assert_eq!(r.target_acr, None);
        // No ext → no structured context (the UI falls back to `reason`).
        assert!(r.authorization_context.is_none());
    }

    #[test]
    fn parses_authorization_context_from_ext() {
        // A Cierge share ask carried under the reverse-DNS `ext` key.
        let json = r#"{
          "id": "x",
          "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
          "issuer": "did:webvh:vta",
          "payload": {
            "subject": "did:webvh:operator",
            "sessionId": "s1",
            "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
            "reason": "finance wants to share salaryBand with travel",
            "ext": {
              "org.openvtc.authorization-context": {
                "type": "https://openvtc.org/cierge/authorization-context/0.1",
                "summary": "finance wants to share salaryBand with travel",
                "risk": "high",
                "action": { "kind": "share", "from": "finance", "to": "travel", "ttlSeconds": 3600 }
              }
            }
          }
        }"#;
        let r = parse_step_up_request(json.to_string()).unwrap();
        // Surfaced as a raw JSON string for the native layer to decode + render.
        let ctx = r
            .authorization_context
            .expect("authorization_context present");
        let v: serde_json::Value = serde_json::from_str(&ctx).unwrap();
        assert_eq!(v["action"]["kind"], "share");
        assert_eq!(v["risk"], "high");
        assert_eq!(
            v["summary"],
            "finance wants to share salaryBand with travel"
        );
    }

    #[test]
    fn rejects_non_request_json() {
        let err = parse_step_up_request("{\"not\":\"a request\"}".to_string()).unwrap_err();
        assert!(matches!(err, FfiError::Decode { .. }));
    }
}
