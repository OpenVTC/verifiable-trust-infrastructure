//! `POST /v1/join-requests` — REST submit (M1.8.1) + a shared
//! inner `submit_inner` the DIDComm handler (M1.8.2) calls into.
//!
//! ## Holder binding
//!
//! Phase 1 plan §D4 requires only the holder-binding proof: the
//! signature must verify against the applicant_did's intrinsic
//! Ed25519 public key (did:key only — did:webvh resolution lands
//! in Phase 2).
//!
//! Wire shape:
//!
//! ```text
//! {
//!   "applicantDid": "did:key:z…",
//!   "vp":               { … opaque JSON … },
//!   "registryConsent":  ? bool,
//!   "extensions":       ? object,
//!   "signature":        "<hex Ed25519 signature>"
//! }
//! ```
//!
//! Canonical signing payload:
//!
//! ```text
//! "vtc-join-request/v1\0" || canonical_json({
//!   "applicantDid":     applicant_did,
//!   "vp":               vp,
//!   "registryConsent":  registry_consent (default false),
//!   "extensions":       extensions (default null),
//! })
//! ```
//!
//! `canonical_json` is just `serde_json::to_vec` on a
//! key-ordered object — sufficient because both sides agree on
//! the field ordering via the typed struct.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, JoinRequestData, JoinRequestRejectedData};
use vti_common::error::AppError;

use crate::ceremony::execute::{self, AdmitOutcome};
use crate::ceremony::{
    Actor, Context, Credential, CredentialStatus, EffectOutcome, EffectPlan, Evidence, Facts,
    Presentation, Purpose, State as FactsState, Subject, Verdict, VerifiedFacts,
};
use crate::community::load_profile;
use crate::join::{JoinRequest, JoinStatus, JoinTransport, store_join_request};
use crate::members::list_members;
use crate::policy::{PolicyPurpose, extract::extract_vp_claims, load_active_compiled};
use crate::server::AppState;

pub const JOIN_REQUEST_SUBMIT_DOMAIN_TAG: &[u8] = b"vtc-join-request/v1\0";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitRequestBody {
    pub applicant_did: String,
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
    /// Hex-encoded Ed25519 signature.
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitResponse {
    pub request_id: Uuid,
    pub status: String,
    /// Issued VMC — present only when the join policy **auto-admitted**
    /// (verdict `allow`). The applicant, who proved holder-binding,
    /// receives their membership credential inline. `None` when the
    /// request was queued (`pending`/`deferred`) or rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    /// Issued role VEC — same delivery story as [`Self::vmc`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
}

/// What [`submit_inner`] produced: the persisted request + the
/// credentials minted if the policy auto-admitted (verdict `allow`).
pub struct JoinSubmitOutcome {
    pub request: JoinRequest,
    pub admit: Option<Box<AdmitOutcome>>,
}

pub async fn submit(
    State(state): State<AppState>,
    Json(req): Json<SubmitRequestBody>,
) -> Result<(StatusCode, Json<SubmitResponse>), AppError> {
    let outcome = submit_inner(
        &state,
        req.applicant_did,
        req.vp,
        req.registry_consent,
        req.extensions,
        Some(&req.signature),
        JoinTransport::Rest,
    )
    .await?;

    let (vmc, role_vec) = match &outcome.admit {
        Some(a) => (
            Some(
                serde_json::to_value(&a.vmc)
                    .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?,
            ),
            Some(
                serde_json::to_value(&a.role_vec)
                    .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?,
            ),
        ),
        None => (None, None),
    };

    Ok((
        StatusCode::CREATED,
        Json(SubmitResponse {
            request_id: outcome.request.id,
            status: outcome.request.status.to_string(),
            vmc,
            role_vec,
        }),
    ))
}

/// Shared inner implementation called by both REST and the DIDComm
/// handler — the join ceremony's decide → effect spine.
///
/// `signature` is `Some` for REST (where the wire must carry an
/// explicit holder-binding signature) and `None` for DIDComm (where
/// the DIDComm envelope's authcrypt sender already authenticates
/// `applicant_did`).
///
/// The active `join` decision policy classifies the verified
/// submission:
/// - `allow` → **auto-admit** via the [`EffectPlan::Admit`] executor;
///   the request lands `Approved` and the credentials are returned.
/// - `refer` → `Pending` (queued for admin review → the approve route).
/// - `request_more` → `Deferred` (more evidence needed).
/// - `deny` → `Rejected`, with the verdict stored on `policy_decision`.
pub async fn submit_inner(
    state: &AppState,
    applicant_did: String,
    vp: JsonValue,
    registry_consent: bool,
    extensions: JsonValue,
    signature_hex: Option<&str>,
    transport: JoinTransport,
) -> Result<JoinSubmitOutcome, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // 1. Holder binding (REST only).
    if let Some(hex_sig) = signature_hex {
        verify_holder_signature(&applicant_did, &vp, registry_consent, &extensions, hex_sig)?;
    }

    // 2. The lossy `vp_claims` projection is still stored on the row
    // for the admin show + the approve path; the decision pipeline
    // reads structured Facts instead (assembled below).
    let vp_claims = extract_vp_claims(&vp);

    // 3. Decide: assemble verified Facts and run the active join policy.
    let facts = assemble_join_facts(state, &applicant_did, &vp).await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Join,
    )
    .await?;
    let verdict = crate::ceremony::decide(&verified, &policy)?;

    // 4. Build the request + realize the verdict.
    let mut request = JoinRequest::new(applicant_did.clone(), vp);
    request.vp_claims = vp_claims;
    request.registry_consent = registry_consent;
    request.extensions = extensions;

    let mut admit: Option<Box<AdmitOutcome>> = None;
    let rejected = matches!(verdict, Verdict::Deny(_));
    match &verdict {
        Verdict::Allow(allow) => {
            // Auto-admit: the join effect (admit + issue VMC) runs now.
            // A duplicate ACL (re-submit by an existing member) surfaces
            // as the executor's `Conflict` → 409.
            let role = allow.role.clone().unwrap_or_else(|| "member".to_string());
            let plan = EffectPlan::Admit {
                subject: applicant_did.clone(),
                role,
                obligations: allow.obligations.clone(),
            };
            if let EffectOutcome::Admitted(creds) =
                execute::apply(state, plan, &applicant_did).await?
            {
                admit = Some(creds);
            }
            request.status = JoinStatus::Approved;
        }
        Verdict::Refer(_) => request.status = JoinStatus::Pending,
        Verdict::RequestMore(_) => {
            request.status = JoinStatus::Deferred;
            request.policy_decision = Some(serde_json::to_value(&verdict)?);
        }
        Verdict::Deny(_) => {
            request.status = JoinStatus::Rejected;
            request.policy_decision = Some(serde_json::to_value(&verdict)?);
        }
    }
    store_join_request(&state.join_requests_ks, &request).await?;

    // 5. Audit — Rejected for a policy deny; Submitted otherwise.
    if rejected {
        audit_writer
            .write(
                &applicant_did,
                None,
                AuditEvent::JoinRequestRejected(JoinRequestRejectedData {
                    request_id: request.id.to_string(),
                    reason: "policy denied".into(),
                }),
            )
            .await?;
    } else {
        audit_writer
            .write(
                &applicant_did,
                None,
                AuditEvent::JoinRequestSubmitted(JoinRequestData {
                    request_id: request.id.to_string(),
                    transport: transport.as_str().to_string(),
                }),
            )
            .await?;
    }

    info!(
        request_id = %request.id,
        applicant = %applicant_did,
        transport = transport.as_str(),
        verdict = verdict.effect(),
        "join request submitted"
    );
    Ok(JoinSubmitOutcome { request, admit })
}

// ---------------------------------------------------------------------------
// Join facts assembly (decision-pipeline input)
// ---------------------------------------------------------------------------

/// Assemble purpose-`join` [`Facts`] from a verified submission. The
/// applicant is the actor + subject (self-join); the VP becomes the
/// verified presentation the policy decides over.
async fn assemble_join_facts(
    state: &AppState,
    applicant_did: &str,
    vp: &JsonValue,
) -> Result<Facts, AppError> {
    let community_did = load_profile(&state.community_ks)
        .await?
        .map(|p| p.community_did)
        .unwrap_or_default();
    let member_count = list_members(&state.members_ks).await?.len() as u64;

    Ok(Facts {
        purpose: Purpose::Join,
        now: Utc::now(),
        // The applicant proved holder-binding at the route layer; they
        // are not (yet) a member, so they carry no community role.
        actor: Actor {
            did: applicant_did.to_string(),
            role: None,
            authenticated: true,
        },
        subject: Subject {
            did: applicant_did.to_string(),
        },
        context: Context {
            community_did,
            channel: "rest".to_string(),
            member_count,
        },
        evidence: Evidence {
            invitation: None,
            presentation: Some(presentation_from_vp(applicant_did, vp)),
            request: None,
        },
        state: FactsState {
            subject_member: None,
        },
    })
}

/// Project the VP into the verified [`Presentation`] the policy reads.
/// Holder-binding is already checked (`verified: true`). Credentials
/// surface with `issuer_trusted: false` / `status: valid` — issuer
/// trust (TRQP) and status-list resolution are follow-ups; the
/// structured shape is what matters for the decision contract.
fn presentation_from_vp(applicant_did: &str, vp: &JsonValue) -> Presentation {
    let holder = vp
        .get("holder")
        .and_then(|h| match h {
            JsonValue::String(s) => Some(s.clone()),
            JsonValue::Object(o) => o.get("id").and_then(|i| i.as_str()).map(str::to_string),
            _ => None,
        })
        .unwrap_or_else(|| applicant_did.to_string());

    let credentials = vp
        .get("verifiableCredential")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(credential_from_vc).collect())
        .unwrap_or_default();

    Presentation {
        verified: true,
        holder,
        credentials,
    }
}

/// Pull one VC into a [`Credential`]. JWT-encoded VCs (bare strings)
/// are skipped — full JWT-VP support lands with VP verification.
fn credential_from_vc(vc: &JsonValue) -> Option<Credential> {
    let obj = vc.as_object()?;
    let credential_type = obj
        .get("type")
        .and_then(|t| match t {
            JsonValue::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str())
                .find(|s| *s != "VerifiableCredential")
                .map(str::to_string),
            JsonValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "VerifiableCredential".to_string());
    let issuer = match obj.get("issuer") {
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Object(o)) => o
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };
    Some(Credential {
        credential_type,
        issuer,
        issuer_trusted: false,
        status: CredentialStatus::Valid,
        claims: obj
            .get("credentialSubject")
            .cloned()
            .unwrap_or(JsonValue::Null),
        valid_until: None,
    })
}

/// Verify the Ed25519 signature over the canonical signing
/// payload (see module docs).
fn verify_holder_signature(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
    signature_hex: &str,
) -> Result<(), AppError> {
    let pubkey_bytes =
        affinidi_crypto::did_key::did_key_to_ed25519_pub(applicant_did).map_err(|e| {
            AppError::Validation(format!("applicant_did is not a parseable did:key: {e}"))
        })?;
    let verifying = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
        AppError::Validation(format!(
            "applicant_did decodes to an invalid Ed25519 pubkey: {e}"
        ))
    })?;

    let payload = canonical_payload(applicant_did, vp, registry_consent, extensions)?;
    let signing_bytes = signing_bytes(&payload);

    let raw_sig = hex::decode(signature_hex)
        .map_err(|e| AppError::Validation(format!("signature is not hex: {e}")))?;
    let signature = Signature::from_slice(&raw_sig).map_err(|e| {
        AppError::Validation(format!("signature is not a 64-byte Ed25519 value: {e}"))
    })?;

    verifying
        .verify(&signing_bytes, &signature)
        .map_err(|e| AppError::Validation(format!("holder-binding signature failed: {e}")))?;
    Ok(())
}

/// Canonical signing payload — a typed struct serialised via
/// `serde_json::to_vec` with the field order pinned by the
/// derive. Both sides build this identically by going through the
/// same struct.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    applicant_did: &'a str,
    vp: &'a JsonValue,
    registry_consent: bool,
    extensions: &'a JsonValue,
}

fn canonical_payload(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&CanonicalPayload {
        applicant_did,
        vp,
        registry_consent,
        extensions,
    })
    .map_err(|e| AppError::Internal(format!("canonical payload serialize: {e}")))
}

/// Domain-tag prefixed bytes the signer hashes over.
fn signing_bytes(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(JOIN_REQUEST_SUBMIT_DOMAIN_TAG.len() + payload.len());
    buf.extend_from_slice(JOIN_REQUEST_SUBMIT_DOMAIN_TAG);
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
// Tests — signing primitive + sign-then-verify round trip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn pair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0xAB; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        (sk, did)
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"placeholder"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        verify_holder_signature(&did, &vp, false, &JsonValue::Null, &sig_hex).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let (_a_sk, a_did) = pair();
        let other = SigningKey::from_bytes(&[0xCD; 32]);
        let vp = serde_json::json!({});
        let payload = canonical_payload(&a_did, &vp, false, &JsonValue::Null).unwrap();
        let sig = other.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        let err = verify_holder_signature(&a_did, &vp, false, &JsonValue::Null, &sig_hex)
            .expect_err("wrong signer must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"original"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        // Same signature, different VP body.
        let tampered = serde_json::json!({"vp":"changed"});
        let err = verify_holder_signature(&did, &tampered, false, &JsonValue::Null, &sig_hex)
            .expect_err("tampered VP must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_garbage_signature() {
        let (_sk, did) = pair();
        let err =
            verify_holder_signature(&did, &JsonValue::Null, false, &JsonValue::Null, "not-hex")
                .expect_err("garbage sig must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_non_did_key_applicant() {
        let err = verify_holder_signature(
            "did:web:example.com",
            &JsonValue::Null,
            false,
            &JsonValue::Null,
            "00",
        )
        .expect_err("non-did:key must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }
}
