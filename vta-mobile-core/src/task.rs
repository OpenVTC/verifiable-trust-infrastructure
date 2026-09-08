//! Trust Task parsing — wraps `trust-tasks-rs` generated types.
//!
//! Parses the two inbound documents a person is shown and asked to answer:
//! `auth/step-up/approve-request` (`0.1` or `0.2`), so the native app can show
//! the reason and decide which evidence gate to satisfy, and
//! `consent/approve-request/0.1`, the prompt asking whether an agent may read
//! or take part in one conversation.
//!
//! **Both go through the same gate, and that is the point of this module.**
//! Before anything is surfaced, the document's own `eddsa-jcs-2022` Data
//! Integrity proof is verified against the caller-supplied enrolled-executor
//! allowlist ([`crate::proof::verify_signed_request`]) — an unverifiable
//! request returns [`FfiError::UntrustedIssuer`] and the device MUST NOT
//! prompt. Step-up had this from the start; the consent prompt did not, and
//! for a while was neither signed by the VTA (#1177) nor checked here (#1323).
//! The signed/passkey-backed `approve-response` builders live in
//! [`crate::stepup`].

use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::auth::step_up::approve_request::{v0_1, v0_2};
use trust_tasks_rs::specs::consent::approve_request::v0_1 as consent_v0_1;

use crate::error::FfiError;

/// The fields of an `auth/step-up/approve-request` the native consent UI needs
/// to display and to decide how to respond.
#[derive(Debug, Clone, uniffi::Record)]
pub struct StepUpRequest {
    /// The relying party that issued the request — the **proven** signer of the
    /// document's Data Integrity proof, guaranteed to be in the caller's
    /// enrolled-executor allowlist.
    pub relying_party: String,
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
    /// Evidence gates the relying party will accept (`"did-signed"` /
    /// `"webauthn"`). Empty when the request did not constrain it (any
    /// supported kind is allowed). The `0.2` wire spelling `didSigned` is
    /// normalised to `did-signed`, so the native layer switches on one set of
    /// strings regardless of the request version.
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

/// Type URIs of the request document versions this approver renders. `0.2`
/// differs from `0.1` only in the `acceptableEvidence` spelling
/// (`didSigned` vs `did-signed`).
const STEP_UP_REQUEST_0_1: &str = "https://trusttasks.org/spec/auth/step-up/approve-request/0.1";
const STEP_UP_REQUEST_0_2: &str = "https://trusttasks.org/spec/auth/step-up/approve-request/0.2";

/// Verify and parse an inbound `auth/step-up/approve-request/0.1` or `/0.2`
/// Trust Task document.
///
/// `trusted_issuers` is the enrolled-executor allowlist the native layer holds:
/// the enrolled VTA's DID plus any granted executor DIDs. The request's Data
/// Integrity proof is verified first ([`crate::proof::verify_signed_request`]);
/// an unverifiable request returns [`FfiError::UntrustedIssuer`] and MUST NOT
/// be prompted on. Async because verification resolves the issuer's DID for its
/// key material (through the crate's shared resolver cache).
///
/// The document is then deserialised and structurally validated via
/// `trust-tasks-rs` (well-formed envelope + required payload fields) and the
/// fields the native consent UI needs are surfaced. Returns
/// [`FfiError::Decode`] if the input is not a well-formed approve-request.
#[uniffi::export(async_runtime = "tokio")]
pub async fn parse_step_up_request(
    json: String,
    trusted_issuers: Vec<String>,
) -> Result<StepUpRequest, FfiError> {
    let v: serde_json::Value = serde_json::from_str(&json).map_err(|e| FfiError::Decode {
        reason: format!("not valid JSON: {e}"),
    })?;

    let type_uri = v.get("type").and_then(|t| t.as_str()).unwrap_or_default();
    if type_uri != STEP_UP_REQUEST_0_1 && type_uri != STEP_UP_REQUEST_0_2 {
        return Err(FfiError::Decode {
            reason: "not an auth/step-up/approve-request/0.1 or /0.2 document".to_string(),
        });
    }

    // The gate: no valid proof from an enrolled executor, no prompt.
    let relying_party = crate::proof::verify_signed_request(&v, &trusted_issuers).await?;

    // Pull the structured authorization context (if any) from `payload.ext` by
    // its reverse-DNS key, as a raw JSON string for the native layer to decode.
    // Read from the lenient Value so we don't depend on the generated `Ext`
    // newtype's key API.
    let authorization_context = v
        .get("payload")
        .and_then(|p| p.get("ext"))
        .and_then(|e| e.get(EXT_KEY_AUTHZ_CONTEXT))
        .map(|c| c.to_string());

    // Typed parse per version. The two payloads are field-for-field identical;
    // only the `acceptableEvidence` enum spelling differs, normalised by
    // `normalize_evidence` so the FFI surface is version-independent.
    macro_rules! surface {
        ($payload_ty:ty) => {{
            let doc: TrustTask<$payload_ty> =
                serde_json::from_str(&json).map_err(|e| FfiError::Decode {
                    reason: format!("not a valid auth/step-up/approve-request document: {e}"),
                })?;
            let p = doc.payload;
            StepUpRequest {
                relying_party,
                subject: p.subject.to_string(),
                session_id: p.session_id.to_string(),
                challenge: p.challenge.to_string(),
                reason: p.reason.to_string(),
                target_acr: p.target_acr,
                acceptable_evidence: p
                    .acceptable_evidence
                    .unwrap_or_default()
                    .iter()
                    .map(|e| normalize_evidence(e.to_string()))
                    .collect(),
                webauthn_requested: p.webauthn.is_some(),
                authorization_context,
            }
        }};
    }

    Ok(if type_uri == STEP_UP_REQUEST_0_1 {
        surface!(v0_1::Payload)
    } else {
        surface!(v0_2::Payload)
    })
}

/// Type URI of the consent prompt this approver renders.
const CONSENT_REQUEST_0_1: &str = "https://trusttasks.org/spec/consent/approve-request/0.1";

/// The fields of a `consent/approve-request` the native consent UI needs.
///
/// Every one of these comes out of the **verified** document. That is not a
/// stylistic preference: the prompt asks a person to let an agent read a
/// conversation, and a renderer that took the conversation's label from the
/// raw JSON while taking the agent's DID from the verified copy would be
/// showing a sentence that no single signer ever asserted.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ConsentRequest {
    /// The **proven** signer of the document's proof, guaranteed to be in the
    /// caller's enrolled-executor allowlist.
    pub issuer: String,
    /// DID of the agent the decision is about. Consent is granted to one agent
    /// rather than to the service hosting it, so this is the identity the
    /// approver is deciding about and the one a later revocation names.
    pub agent: String,
    /// Messaging platform the conversation lives on, as the bridge names it.
    pub platform: String,
    /// The bridge's opaque handle for the conversation. Deliberately not a
    /// phone number or a group link: it exists so a decision can be matched to
    /// a conversation without the matching key being personal data.
    pub conversation_ref: String,
    /// `dm`, `group`, … — how the conversation is shaped.
    pub kind: String,
    /// What is being asked for: `receive` or `converse`.
    pub scope: String,
    /// Single-use value the approver's decision MUST echo. Without it a
    /// decision is a free-floating assertion that cannot be shown to answer
    /// *this* prompt rather than an earlier one.
    pub challenge: String,
    /// Human-readable label for the conversation — "Signal group 'Family'".
    ///
    /// **Chosen by the requesting party, so the native layer MUST treat it as
    /// untrusted text**: escape it, bound its length, and never let it displace
    /// `agent` / `platform` / `conversation_ref` as the basis of the decision.
    /// It is here because `conversation_ref` is opaque by design, and an
    /// approver asked to decide about an identifier that means nothing to them
    /// will either always allow or always deny.
    pub display_hint: Option<String>,
    /// Digest of the message that prompted this request, when there is one, so
    /// an approver deciding a `receive` scope can confirm a real message is
    /// arriving. A digest rather than the content: showing the message in order
    /// to ask would disclose the very thing the decision gates.
    pub first_message_digest: Option<String>,
}

/// Verify and parse an inbound `consent/approve-request/0.1` document.
///
/// The sibling of [`parse_step_up_request`], and deliberately the same shape.
/// `trusted_issuers` is the enrolled-executor allowlist the native layer holds;
/// `approver` is this device's own approver identity.
///
/// Three refusals, in order, and each is a different fault:
///
/// 1. not a consent prompt → [`FfiError::Decode`];
/// 2. no valid proof from an enrolled issuer → [`FfiError::UntrustedIssuer`],
///    the spec's `untrusted_issuer` condition — **the device MUST NOT prompt**;
/// 3. `recipient` is somebody else → [`FfiError::NotForThisApprover`]. An
///    authentic prompt for another approver, arriving here, is misrouting or a
///    replay aimed at whoever will tap first; the `recipient` member exists to
///    be read, and until this function existed it was written and never read.
///
/// Async because verification resolves the issuer's DID for its key material,
/// through the crate's shared resolver cache.
#[uniffi::export(async_runtime = "tokio")]
pub async fn parse_consent_request(
    json: String,
    trusted_issuers: Vec<String>,
    approver: String,
) -> Result<ConsentRequest, FfiError> {
    let v: serde_json::Value = serde_json::from_str(&json).map_err(|e| FfiError::Decode {
        reason: format!("not valid JSON: {e}"),
    })?;

    let type_uri = v.get("type").and_then(|t| t.as_str()).unwrap_or_default();
    if type_uri != CONSENT_REQUEST_0_1 {
        return Err(FfiError::Decode {
            reason: "not a consent/approve-request/0.1 document".to_string(),
        });
    }

    // The gate: no valid proof from an enrolled executor, no prompt.
    let issuer = crate::proof::verify_signed_request(&v, &trusted_issuers).await?;

    // Addressed here? Read after the proof rather than before it, so a
    // document nobody signed is refused as unverifiable rather than as
    // misaddressed — the more serious of the two, and the one whose `recipient`
    // could say anything at all.
    let recipient = v.get("recipient").and_then(|r| r.as_str()).ok_or_else(|| {
        FfiError::NotForThisApprover {
            recipient: "(absent)".to_string(),
        }
    })?;
    if recipient != approver {
        return Err(FfiError::NotForThisApprover {
            recipient: recipient.to_string(),
        });
    }

    let doc: TrustTask<consent_v0_1::Payload> =
        serde_json::from_str(&json).map_err(|e| FfiError::Decode {
            reason: format!("not a valid consent/approve-request document: {e}"),
        })?;
    let p = doc.payload;
    Ok(ConsentRequest {
        issuer,
        agent: p.subject.agent.to_string(),
        platform: p.subject.platform.to_string(),
        conversation_ref: p.subject.conversation_ref.to_string(),
        kind: p.subject.kind.to_string(),
        scope: p.scope.to_string(),
        challenge: p.challenge.to_string(),
        display_hint: p.display_hint.map(|h| h.to_string()),
        first_message_digest: p.first_message_digest.map(|d| d.to_string()),
    })
}

/// Map the `0.2` camelCase evidence spelling onto the `0.1` form the native
/// layers already switch on. `webauthn` is spelled identically in both.
fn normalize_evidence(kind: String) -> String {
    if kind == "didSigned" {
        "did-signed".to_string()
    } else {
        kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::test_support::{did_for, sign_as};

    /// Seed of the enrolled relying party the happy-path tests sign as.
    const EXECUTOR: u8 = 17;
    /// Seed of a key holder the device is *not* enrolled with.
    const STRANGER: u8 = 18;

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

    /// `base` re-issued by a deterministic `did:key` relying party and (unless
    /// `signer` is `None`) signed, as a JSON string ready for the parse.
    async fn issued_by(base: &str, issuer_seed: u8, signer: Option<u8>) -> String {
        let mut v: serde_json::Value = serde_json::from_str(base).unwrap();
        v["issuer"] = serde_json::Value::String(did_for(issuer_seed));
        if let Some(s) = signer {
            sign_as(&mut v, s).await;
        }
        v.to_string()
    }

    fn enrolled() -> Vec<String> {
        vec![did_for(EXECUTOR)]
    }

    // ── consent/approve-request ────────────────────────────────────────────
    //
    // The same four questions the step-up cases ask, because the prompt is the
    // same kind of thing: a person is shown a sentence and taps a button that
    // grants an agent access to a conversation. Until #1323 the VTA signed this
    // document and nothing here read the signature, so a prompt from anyone at
    // all rendered identically to a real one.

    /// This device's approver identity — what the VTA addresses a prompt to.
    const APPROVER: &str = "did:web:alice.example";

    /// Shaped as `vta-service`'s `consent.rs` builds it: the wire subject
    /// (`platform` / `conversationRef` / `kind` / `agent`), the scope, the
    /// challenge, and the two optional members.
    const CONSENT_REQUEST: &str = r#"{
      "id": "urn:uuid:5f0f6f1e-6f5a-4f2f-9a1e-8f2b6d2c0a11",
      "type": "https://trusttasks.org/spec/consent/approve-request/0.1",
      "issuer": "did:web:agent.example",
      "recipient": "did:web:alice.example",
      "issuedAt": "2026-09-08T12:00:00Z",
      "payload": {
        "subject": {
          "platform": "signal",
          "conversationRef": "conv-1",
          "kind": "group",
          "agent": "did:key:zAgent"
        },
        "scope": "receive",
        "challenge": "Q29uc2VudENoYWxsZW5nZVhZ",
        "displayHint": "Signal group 'Family'",
        "firstMessageDigest": "zQmFakeDigest"
      }
    }"#;

    #[tokio::test]
    async fn a_signed_consent_prompt_from_an_enrolled_issuer_is_surfaced() {
        let json = issued_by(CONSENT_REQUEST, EXECUTOR, Some(EXECUTOR)).await;
        let r = parse_consent_request(json, enrolled(), APPROVER.to_string())
            .await
            .unwrap();
        assert_eq!(
            r.issuer,
            did_for(EXECUTOR),
            "the PROVEN signer, not the claimed one"
        );
        assert_eq!(r.agent, "did:key:zAgent");
        assert_eq!(r.platform, "signal");
        assert_eq!(r.conversation_ref, "conv-1");
        assert_eq!(r.kind, "group");
        assert_eq!(r.scope, "receive");
        assert_eq!(r.challenge, "Q29uc2VudENoYWxsZW5nZVhZ");
        assert_eq!(r.display_hint.as_deref(), Some("Signal group 'Family'"));
        assert_eq!(r.first_message_digest.as_deref(), Some("zQmFakeDigest"));
    }

    #[tokio::test]
    async fn an_unsigned_consent_prompt_is_refused() {
        // #1177's document exactly: everything else in order, no proof. It
        // reached a phone and rendered.
        let json = issued_by(CONSENT_REQUEST, EXECUTOR, None).await;
        let err = parse_consent_request(json, enrolled(), APPROVER.to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(err, FfiError::UntrustedIssuer { .. }),
            "an unsigned prompt must not reach a person: {err:?}"
        );
    }

    #[tokio::test]
    async fn a_consent_prompt_from_an_unenrolled_issuer_is_refused() {
        // Correctly signed, by someone this device has never enrolled. The
        // signature proves who wrote it and says nothing about whether they may
        // ask.
        let json = issued_by(CONSENT_REQUEST, STRANGER, Some(STRANGER)).await;
        let err = parse_consent_request(json, enrolled(), APPROVER.to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_consent_prompt_addressed_to_another_approver_is_refused() {
        // Authentic, enrolled, and not for this person. Refusing it is what
        // stops a valid prompt being replayed wherever someone will tap first,
        // and it is the only thing the `recipient` member was ever for.
        let json = issued_by(CONSENT_REQUEST, EXECUTOR, Some(EXECUTOR)).await;
        let err = parse_consent_request(json, enrolled(), "did:web:bob.example".to_string())
            .await
            .unwrap_err();
        match err {
            FfiError::NotForThisApprover { recipient } => assert_eq!(recipient, APPROVER),
            other => panic!("expected a misaddressing refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_step_up_request_is_not_a_consent_prompt() {
        // The two parsers must not accept each other's documents: the fields a
        // person is shown differ, and a step-up rendered as a consent card
        // would ask about a conversation that is not what is being elevated.
        let json = issued_by(PASSKEY_REQUEST, EXECUTOR, Some(EXECUTOR)).await;
        let err = parse_consent_request(json, enrolled(), APPROVER.to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::Decode { .. }), "{err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parses_a_signed_passkey_backed_request() {
        let json = issued_by(PASSKEY_REQUEST, EXECUTOR, Some(EXECUTOR)).await;
        let r = parse_step_up_request(json, enrolled()).await.unwrap();
        assert_eq!(r.relying_party, did_for(EXECUTOR), "the proven signer");
        assert_eq!(r.subject, "did:web:alice.example");
        assert_eq!(r.session_id, "ec5d3c89-3f49-49b2-9d7d-2a8c0a8a7b9b");
        assert_eq!(r.challenge, "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ");
        assert!(r.reason.starts_with("Confirm transfer"));
        assert_eq!(r.target_acr.as_deref(), Some("aal2"));
        assert_eq!(r.acceptable_evidence, vec!["webauthn".to_string()]);
        assert!(r.webauthn_requested);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parses_a_signed_0_2_request_normalising_evidence() {
        // 0.2 spells the DID-signed gate `didSigned`; the surface stays
        // `did-signed` so native switch statements are version-independent.
        let json = r#"{
          "id": "x",
          "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.2",
          "payload": {
            "subject": "did:web:alice.example",
            "sessionId": "s1",
            "challenge": "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ",
            "reason": "Approve sign-in",
            "acceptableEvidence": ["didSigned"]
          }
        }"#;
        let json = issued_by(json, EXECUTOR, Some(EXECUTOR)).await;
        let r = parse_step_up_request(json, enrolled()).await.unwrap();
        assert_eq!(r.acceptable_evidence, vec!["did-signed".to_string()]);
        assert!(!r.webauthn_requested);
        assert_eq!(r.target_acr, None);
        // No ext → no structured context (the UI falls back to `reason`).
        assert!(r.authorization_context.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parses_authorization_context_from_ext() {
        // A Cierge share ask carried under the reverse-DNS `ext` key.
        let json = r#"{
          "id": "x",
          "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
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
        let json = issued_by(json, EXECUTOR, Some(EXECUTOR)).await;
        let r = parse_step_up_request(json, enrolled()).await.unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_non_request_json() {
        let err = parse_step_up_request("{\"not\":\"a request\"}".to_string(), vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::Decode { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_request_without_a_proof() {
        // The exact document the old lenient slice accepted — now refused.
        let json = issued_by(PASSKEY_REQUEST, EXECUTOR, None).await;
        let err = parse_step_up_request(json, enrolled()).await.unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_valid_proof_from_a_non_enrolled_did() {
        let json = issued_by(PASSKEY_REQUEST, STRANGER, Some(STRANGER)).await;
        let err = parse_step_up_request(json, enrolled()).await.unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_an_issuer_verification_method_mismatch() {
        // Signed by the stranger's key while claiming the enrolled relying
        // party as issuer. Enroll both DIDs so the test isolates the
        // issuer≡verificationMethod binding itself.
        let json = issued_by(PASSKEY_REQUEST, EXECUTOR, Some(STRANGER)).await;
        let err = parse_step_up_request(json, vec![did_for(EXECUTOR), did_for(STRANGER)])
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_request_tampered_after_signing() {
        let mut v: serde_json::Value =
            serde_json::from_str(&issued_by(PASSKEY_REQUEST, EXECUTOR, Some(EXECUTOR)).await)
                .unwrap();
        // The attack the proof exists to stop: the consent prose rewritten in
        // flight by whoever carries the message.
        v["payload"]["reason"] = serde_json::json!("Confirm transfer of $1 to did:web:bob.example");
        let err = parse_step_up_request(v.to_string(), enrolled())
            .await
            .unwrap_err();
        assert!(matches!(err, FfiError::UntrustedIssuer { .. }));
    }
}
