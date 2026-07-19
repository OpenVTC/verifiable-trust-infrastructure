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

use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose;
use serde_json::{Value, json};
use trust_tasks_rs::specs::auth::step_up::approve_response::v0_1 as approve_response;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;

use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::auth::session::{get_session, now_epoch, update_session};
use crate::operations::passkey_login::{
    VtaVmResolver, enumerate_passkey_vms, verify_passkey_login,
};
use crate::server::AppState;
use vti_common::acl::{delegated_any_approver_covers, get_acl_entry};
use vti_common::auth::step_up::{
    ConsumeOutcome, consume_pending_step_up, new_pending_step_up, store_pending_step_up,
};
use vti_common::store::KeyspaceHandle;

// The step-up gate engine lives in the operations layer (P2.4); the
// route-layer wrappers below (`require_step_up`, the `RequireStepUp` extractor)
// turn its `StepUpDecision` into a `403`/reject + approve-request push.
use crate::operations::step_up::{StepUpDecision, resolve_step_up};

use super::helpers::{TrustTaskOutcome, reject_with, success_response};

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
/// `expected_signer` is the document `issuer` — the approver (the subject in
/// self step-up, the authorized delegated approver otherwise; the handler
/// authorizes which one it is before calling). Here we bind the *cryptographic*
/// identity: the proof's `verificationMethod` DID MUST equal the signer, and the
/// `eddsa-jcs-2022` signature MUST verify under that `did:key`.
///
/// `did:key` resolution is local (no I/O); the mobile holder key is always a
/// `did:key`, matching the engine's signing side.
pub(super) async fn verify_did_signed_gate(
    doc: &TrustTask<Value>,
    expected_signer: &str,
) -> Result<(), GateError> {
    use crate::auth::di_proof::DiProofError;

    // Verify the eddsa-jcs-2022 proof via the single shared verifier (P1.4),
    // which returns the cryptographically-proven signer DID.
    let signer_did = crate::auth::di_proof::verify_trust_task_proof(doc)
        .await
        .map_err(|e| match e {
            DiProofError::NoProof => GateError::NoGate,
            DiProofError::NotDataIntegrity => {
                GateError::ProofInvalid("not a Data Integrity proof".to_string())
            }
            DiProofError::NoDid | DiProofError::VerifyFailed(_) => {
                GateError::ProofInvalid(e.to_string())
            }
        })?;

    // Bind identity: the proven signer must be the expected signer (the document
    // `issuer`), so a valid proof by some *other* DID can't stand in for the
    // approver.
    if signer_did != expected_signer {
        return Err(GateError::SubjectMismatch);
    }

    Ok(())
}

/// A `task_failed` reject carrying a spec error code (e.g.
/// `auth/step-up/approve-response:challenge_unknown`) as the reason.
fn step_up_failure(code: &str) -> RejectReason {
    RejectReason::TaskFailed {
        reason: code.to_string(),
        details: None,
    }
}

/// AAL ordinal for the `aal1 < aal2 < aal3` ceiling/floor comparison.
fn acr_rank(acr: &str) -> u8 {
    match acr {
        "aal3" => 3,
        "aal2" => 2,
        "aal1" => 1,
        _ => 0,
    }
}

fn gate_err_to_reject(e: GateError) -> RejectReason {
    match e {
        GateError::NoGate => step_up_failure("auth/step-up/approve-response:no_gate"),
        GateError::SubjectMismatch => {
            step_up_failure("auth/step-up/approve-response:subject_mismatch")
        }
        GateError::ProofInvalid(_) => {
            step_up_failure("auth/step-up/approve-response:proof_invalid")
        }
    }
}

/// Verify the **webauthn** gate: map the carried assertion to
/// [`vti_webauthn::AssertionPayload`], resolve `credential.id` to one of the
/// subject's passkey verification methods, and verify per WebAuthn L2 §7.2
/// against the bound challenge (reusing [`verify_passkey_login`], exactly as
/// `auth/passkey/login/finish` does). Returns the `assertion_invalid` reject on
/// any verification failure.
async fn verify_webauthn_gate(
    state: &AppState,
    approver: &str,
    challenge: &str,
    assertion: &approve_response::AssertionResponse,
) -> Result<(), RejectReason> {
    let did_resolver = state
        .did_resolver
        .clone()
        .ok_or_else(|| RejectReason::InternalError {
            reason: "DID resolver not configured".to_string(),
        })?;
    let public_url = state
        .config
        .read()
        .await
        .public_url
        .clone()
        .ok_or_else(|| RejectReason::InternalError {
            reason: "public_url not configured".to_string(),
        })?;
    let config = vti_webauthn::VerifierConfig::from_public_url(&public_url, true).map_err(|e| {
        RejectReason::InternalError {
            reason: format!("verifier config: {e}"),
        }
    })?;
    let resolver = VtaVmResolver::new(did_resolver);

    let invalid = || step_up_failure("auth/step-up/approve-response:assertion_invalid");
    let dec = |s: &str| {
        general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .or_else(|_| general_purpose::URL_SAFE.decode(s.as_bytes()))
    };

    let credential_id = dec(&assertion.id).map_err(|_| invalid())?;

    // Resolve credential.id → the approver's passkey VM (spec: resolve the
    // credential to the approver, whom the handler has already authorized for
    // the subject — the subject itself in self mode, the delegated approver
    // otherwise).
    let vms = enumerate_passkey_vms(&resolver, approver)
        .await
        .map_err(|e| RejectReason::InternalError {
            reason: format!("passkey VM enumeration: {e}"),
        })?;
    let vm = vms
        .into_iter()
        .find(|v| v.credential_id == credential_id)
        .ok_or_else(invalid)?;

    let payload = vti_webauthn::AssertionPayload {
        credential_id,
        authenticator_data: dec(&assertion.response.authenticator_data).map_err(|_| invalid())?,
        client_data_json: dec(&assertion.response.client_data_json).map_err(|_| invalid())?,
        signature: dec(&assertion.response.signature).map_err(|_| invalid())?,
        verification_method: vm.vm_url,
    };

    verify_passkey_login(&payload, challenge.as_bytes(), &resolver, &config)
        .await
        .map(|_| ())
        .map_err(|_| invalid())
}

/// Handler for `auth/step-up/approve-response/0.1` **and** `/0.2`.
///
/// Consumes the approver's ratification of a pending step-up and, on a verified
/// gate, elevates the *subject's* session `amr`/`acr`. Follows the spec's
/// relying-party conformance rules; the bearer JWT (`auth`) identifies the
/// caller (the approver, who signs and submits the document as itself), and the
/// approve-response's gate (did-signed proof or webauthn assertion) is the
/// second factor.
///
/// Self **and** delegated: the document `issuer`/signer is the *approver*, which
/// is the subject in self step-up (`issuer == subject`) or a distinct party in
/// delegated step-up (`issuer == AclEntry.stepUp.approver`, recorded on the
/// pending step-up at mint). The gate is verified against the issuer key; the
/// issuer is authorized against the recorded approver before the subject's
/// session is elevated.
///
/// Dual-accept: 0.2 differs from 0.1 only in the `evidence.kind` discriminator
/// value (`did-signed`→`didSigned`). Because the approver signs the payload,
/// the document MUST NOT be mutated; instead the typed (v0_1) parse runs over a
/// down-converted *copy*, while proof verification and the echoed response use
/// the original `doc` — so a 0.2 request verifies against its 0.2 bytes and
/// receives a `…/0.2#response`. (`kebabize` is idempotent on already-kebab
/// values, so the down-convert is a no-op for a genuine 0.1 request — one code
/// path serves both versions.)
pub(super) async fn handle_approve_response(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // 1. Parse the typed payload from a version-normalised copy (see above).
    let payload: approve_response::Payload = {
        let mut payload_value = doc.payload.clone();
        super::wire_v0_2::kebabize_paths(&mut payload_value, &["evidence.kind"]);
        match serde_json::from_value(payload_value) {
            Ok(p) => p,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("payload parse: {e}"),
                    },
                );
            }
        }
    };
    let subject = payload.subject.to_string();
    let session_id = payload.session_id.to_string();
    let challenge = payload.challenge.to_string();

    // 2. Signer self-consistency: the approver signs the document and submits it
    //    as itself, so the bearer caller MUST be the document `issuer`. Whether
    //    that issuer is the subject (self) or a distinct authorized approver
    //    (delegated) is decided in step 4b, once the consumed pending step-up
    //    tells us who the relying party addressed the request to. The proof VM
    //    is bound to `issuer` in the gate step (4/5).
    let Some(issuer) = doc.issuer.as_deref().map(str::to_string) else {
        return reject_with(
            &doc,
            step_up_failure("auth/step-up/approve-response:subject_mismatch"),
        );
    };
    if auth.did != issuer {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "the approve-response issuer must be the authenticated caller".to_string(),
            },
        );
    }

    // 3. Locate + consume the pending step-up by echoed challenge (single use).
    let pending = match consume_pending_step_up(&state.sessions_ks, &challenge, now_epoch()).await {
        Ok(ConsumeOutcome::Found(p)) => *p,
        Ok(ConsumeOutcome::NotFound) => {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:challenge_unknown"),
            );
        }
        Ok(ConsumeOutcome::Expired) => {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:challenge_expired"),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "step-up consume failed");
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("step-up lookup: {e}"),
                },
            );
        }
    };
    if pending.subject != subject || pending.session_id != session_id {
        return reject_with(
            &doc,
            step_up_failure("auth/step-up/approve-response:subject_mismatch"),
        );
    }

    // 4b. Authorize the signer. The gate (4/5) proves the proof VM == issuer;
    //     this ties that issuer to the step-up the relying party minted.
    if pending.approver_any {
        // delegated-any: no single bound approver. The issuer must meet the
        // maintainer's criterion — an admin whose contexts cover the subject's
        // (super-admin covers all). Expired approver entries can't ratify.
        let now = now_epoch();
        let issuer_entry = match get_acl_entry(&state.acl_ks, &issuer).await {
            Ok(Some(e)) if !e.is_expired(now) => e,
            _ => {
                return reject_with(
                    &doc,
                    step_up_failure("auth/step-up/approve-response:approver_unauthorized"),
                );
            }
        };
        let subject_entry = match get_acl_entry(&state.acl_ks, &subject).await {
            Ok(Some(e)) => e,
            _ => {
                return reject_with(
                    &doc,
                    step_up_failure("auth/step-up/approve-response:approver_unauthorized"),
                );
            }
        };
        if !delegated_any_approver_covers(&issuer_entry, &subject_entry) {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:approver_unauthorized"),
            );
        }
    } else {
        // self / delegated: the relying party elevates only for the approver it
        // addressed the request to — the subject itself (self) or the delegated
        // approver recorded at mint. An in-flight record written before the
        // `approver` field existed has it empty → fall back to self.
        let authorized_signer = if pending.approver.is_empty() {
            subject.as_str()
        } else {
            pending.approver.as_str()
        };
        if issuer != authorized_signer {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:approver_unauthorized"),
            );
        }
    }

    // 4. A `denied` decision is a signed refusal — verify the did-signed gate
    //    (against the approver/issuer key), audit, and elevate nothing.
    if payload.decision == approve_response::PayloadDecision::Denied {
        if let Err(e) = verify_did_signed_gate(&doc, &issuer).await {
            return reject_with(&doc, gate_err_to_reject(e));
        }
        audit!(
            "auth.step_up_denied",
            actor = &subject,
            resource = &session_id,
            outcome = "declined"
        );
        return success_response(
            &doc,
            json!({
                "status": "rejected",
                "reason": payload.denied_reason.unwrap_or_else(|| "user declined".to_string()),
            }),
        );
    }

    // 5. Approved — verify exactly one cryptographic gate, bound to the
    //    *signer* (the issuer/approver), which is the subject in self mode and
    //    the authorized delegated approver otherwise.
    let factor: &str = match payload.evidence.as_ref() {
        None | Some(approve_response::Evidence::DidSigned) => {
            if let Err(e) = verify_did_signed_gate(&doc, &issuer).await {
                return reject_with(&doc, gate_err_to_reject(e));
            }
            "did"
        }
        Some(approve_response::Evidence::Webauthn(assertion)) => {
            match verify_webauthn_gate(state, &issuer, &challenge, assertion).await {
                Ok(()) => "passkey",
                Err(reason) => return reject_with(&doc, reason),
            }
        }
    };

    // 6. AAL ceiling/floor: elevate to the requested targetAcr, which MUST be
    //    ≤ the approver's grantedAcr (default aal2). Otherwise `acr_unsatisfied`.
    let granted = payload.granted_acr.as_deref().unwrap_or("aal2");
    let target = pending.target_acr.as_str();
    if acr_rank(target) > acr_rank(granted) {
        return reject_with(
            &doc,
            step_up_failure("auth/step-up/approve-response:acr_unsatisfied"),
        );
    }

    // 7. Load + elevate the session.
    let mut session = match get_session(&state.sessions_ks, &session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:challenge_unknown"),
            );
        }
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("session lookup: {e}"),
                },
            );
        }
    };
    if !session.amr.iter().any(|m| m == factor) {
        session.amr.push(factor.to_string());
    }
    session.acr = target.to_string(); // ≤ granted, enforced above
    // Bound the elevation. For an intrinsic-sender (DIDComm/TSP) session — whose
    // acr is read straight off this row on every subsequent message — the window
    // is what stops a single approval from granting permanent aal2:
    // `resolve_did_session` downgrades back to aal1 once it lapses. A REST
    // session ignores this field for now (its short access-token TTL bounds
    // elevation); a later phase wires REST into the same read-time downgrade.
    session.acr_expires_at = Some(now_epoch().saturating_add(STEP_UP_ELEVATION_TTL_SECS));
    if let Err(e) = update_session(&state.sessions_ks, &session).await {
        return reject_with(
            &doc,
            RejectReason::InternalError {
                reason: format!("session update: {e}"),
            },
        );
    }
    audit!(
        "auth.step_up",
        actor = &subject,
        resource = &session_id,
        outcome = "success"
    );

    // 8. Elevated ack with the updated session snapshot. The client refreshes
    //    to mint a new access token at the elevated acr (refresh preserves it).
    let issued_at = chrono::DateTime::from_timestamp(session.created_at as i64, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    let expires_at = session
        .refresh_expires_at
        .and_then(|e| chrono::DateTime::from_timestamp(e as i64, 0))
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    success_response(
        &doc,
        json!({
            "status": "elevated",
            "session": {
                "id": session.session_id,
                "subject": session.did,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "amr": session.amr,
                "acr": session.acr,
            },
        }),
    )
}

/// Target assurance level and lifetime for a minted step-up challenge.
const STEP_UP_TARGET_ACR: &str = "aal2";
const STEP_UP_TTL_SECS: u64 = 300;
/// How long a step-up elevation stays in force on the elevated session, after
/// which the raised `acr` lapses back to `aal1`. Matches the REST access-token
/// lifetime so intrinsic-sender and REST callers see the same elevation window.
/// A caller that received approval retries immediately, so this is comfortably
/// long enough while keeping the standing grant short.
const STEP_UP_ELEVATION_TTL_SECS: u64 = 900; // 15m

/// Mint a pending step-up and build the `auth/step-up/approve-request/0.1`
/// document the AAL1 caller hands to its approver (wallet / VTA).
///
/// A fresh challenge is bound server-side to the caller's
/// `{session_id, subject, targetAcr=aal2, acceptableEvidence}` via the
/// pending-step-up store; the approver's `approve-response` is later consumed by
/// [`handle_approve_response`]. Shared by both gate surfaces — the REST `403`
/// ([`issue_step_up_challenge`]) and the trust-task reject ([`require_step_up`]).
/// Returns the approve-request document, or `Err(())` if the pending step-up
/// could not be persisted (the caller maps that to a 5xx / internal-error reject).
/// The default step-up reason when the gated request carries no structured
/// authorization context (or one without a `summary`).
const DEFAULT_STEP_UP_REASON: &str = "this operation requires a stepped-up (AAL2) session";

/// Reverse-DNS `payload.ext` key (SPEC §4.5.1) under which the structured
/// authorization context rides in the approve-request. The mobile engine reads
/// the same key.
const EXT_KEY_AUTHZ_CONTEXT: &str = "org.openvtc.authorization-context";

/// Pick the reason string + optional structured authorization context from a
/// gated request's payload. A request MAY carry a `payload.authorizationContext`
/// (e.g. a Cierge share/spend/tool ask); when it does, its human `summary`
/// becomes the reason so even a context-unaware renderer shows something
/// meaningful. Pure — unit-tested.
fn reason_and_context(payload: &Value) -> (&str, Option<&Value>) {
    let ctx = payload.get("authorizationContext");
    let reason = ctx
        .and_then(|c| c.get("summary"))
        .and_then(|s| s.as_str())
        .unwrap_or(DEFAULT_STEP_UP_REASON);
    (reason, ctx)
}

async fn mint_pending_step_up(
    sessions_ks: &KeyspaceHandle,
    vta_did: &str,
    subject: &str,
    recipient: &str,
    approver_any: bool,
    session_id: &str,
    reason: &str,
    // Optional structured context describing *what* is being authorized, shown
    // to the approver's device verbatim (e.g. a Cierge cross-domain share /
    // spend / tool ask). Embedded under the spec's `payload.ext` extension map
    // (the payload is `deny_unknown_fields`, so a bespoke top-level field would
    // break every typed consumer). `None` leaves the payload byte-identical to
    // the reason-only form.
    authorization_context: Option<&Value>,
) -> Result<Value, ()> {
    let acceptable = vec!["did-signed".to_string(), "webauthn".to_string()];

    // 256 bits of challenge entropy (two UUIDv4s) — comfortably over the spec's
    // ≥128-bit / ≥16-char minimum, using deps already present.
    let mut raw = Vec::with_capacity(32);
    raw.extend_from_slice(Uuid::new_v4().as_bytes());
    raw.extend_from_slice(Uuid::new_v4().as_bytes());
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&raw);

    let pending = new_pending_step_up(
        challenge.clone(),
        session_id,
        subject,
        // The authorized signer of the eventual approve-response: the subject
        // itself for `self`, or the delegated approver the request is addressed
        // to. Empty for `delegated-any` (authorization is by criterion, not a
        // bound approver — `approver_any` selects that path).
        recipient,
        approver_any,
        STEP_UP_TARGET_ACR,
        acceptable.clone(),
        STEP_UP_TTL_SECS,
    );
    if let Err(e) = store_pending_step_up(sessions_ks, &pending).await {
        tracing::error!(error = %e, "failed to persist pending step-up");
        return Err(());
    }

    let mut doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
        "issuer": vta_did,
        "payload": {
            "subject": subject,
            "sessionId": session_id,
            "challenge": challenge,
            "reason": reason,
            "targetAcr": STEP_UP_TARGET_ACR,
            "acceptableEvidence": acceptable,
            "ttl": STEP_UP_TTL_SECS,
        },
    });
    // Address the request to the approver for `self`/`delegated`; `delegated-any`
    // has no single recipient (any qualifying admin may ratify), so the field is
    // omitted and the carried request is relayed to an eligible approver.
    if !approver_any && !recipient.is_empty() {
        doc["recipient"] = json!(recipient);
    }
    // Carry the structured authorization context when the gated op supplied one,
    // under a reverse-DNS-namespaced `ext` key (SPEC §4.5.1) so the payload stays
    // spec-valid for `deny_unknown_fields` typed consumers (e.g. the mobile
    // engine's `parse_step_up_request`).
    if let Some(ctx) = authorization_context {
        doc["payload"]["ext"] = json!({ EXT_KEY_AUTHZ_CONTEXT: ctx });
    }
    Ok(doc)
}

/// Mint a pending step-up and return the REST `403` that *carries the
/// approve-request* an AAL1 caller must satisfy to elevate.
///
/// This is the relying-party initiation half (the chosen "403 carries the
/// approve-request" trigger model) for REST routes; applied via the
/// [`RequireStepUp`] extractor.
pub(crate) async fn issue_step_up_challenge(
    sessions_ks: &KeyspaceHandle,
    vta_did: &str,
    subject: &str,
    recipient: &str,
    approver_any: bool,
    session_id: &str,
    reason: &str,
    authorization_context: Option<&Value>,
) -> Response {
    let approve_request = match mint_pending_step_up(
        sessions_ks,
        vta_did,
        subject,
        recipient,
        approver_any,
        session_id,
        reason,
        authorization_context,
    )
    .await
    {
        Ok(ar) => ar,
        Err(()) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                br#"{"error":"internal_error"}"#.to_vec(),
            )
                .into_response();
        }
    };
    // Backward-compatible with the prior 403 shape (`error` + `requiredAcr`),
    // plus the carried approve-request a step-up-aware client acts on.
    let body = json!({
        "error": "step_up_required",
        "requiredAcr": STEP_UP_TARGET_ACR,
        "approveRequest": approve_request,
    });
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// REST `403` for the **fail-closed** case: the operation requires AAL2 but no
/// step-up method exists for the caller (a `delegated` floor with no
/// `stepUp.approver` on the caller's ACL entry). Unlike
/// [`issue_step_up_challenge`], this carries **no** approve-request — there's
/// nothing the caller can do to elevate until an operator registers an
/// approver, so we deny rather than hand back a request that can't be satisfied.
fn step_up_denied_response() -> Response {
    let body = json!({
        "error": "step_up_required",
        "requiredAcr": STEP_UP_TARGET_ACR,
        "reason": "no step-up approver is configured for this subject; an operator must register one",
    });
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// Trust Task `type` of a step-up approve-request (also the DIDComm message
/// `type` used when pushing one to an approver).
#[cfg(feature = "didcomm")]
const STEP_UP_APPROVE_REQUEST_TYPE: &str =
    "https://trusttasks.org/spec/auth/step-up/approve-request/0.1";

/// Pure route selection for a delegated push: given the approver DID and the
/// VTA's configured mediator, pick the mediator to forward through.
///
/// DID-driven so it extends to routable DIDs: a `did:key` approver (the v1
/// mobile holder) has no DIDComm service endpoint, so it routes through the
/// VTA's own (shared) mediator — the holder registers its `did:key` with the
/// same mediator and picks the message up there. Future `did:peer` / `did:webvh`
/// approvers advertise their own mediator service and route there instead (not
/// yet wired → `None`, so the relay fallback applies).
pub(super) fn approver_mediator(approver_did: &str, configured: Option<&str>) -> Option<String> {
    if !approver_did.starts_with("did:key:") {
        return None;
    }
    configured.filter(|m| !m.is_empty()).map(str::to_string)
}

/// Deliver a signed Trust-Task document to `recipient` over **TSP** when we have
/// fresh learn-from-inbound proof it's listening on TSP (a `did:key` device
/// can't advertise `#tsp`, so its inbound TSP frames are the only signal — see
/// [`crate::messaging::tsp_reach`]). Routes the bare document bytes through the
/// shared mediator; §3 resolved to 3c (relationship-free routed send — see
/// `docs/05-design-notes/tsp-outbound-send.md`), so no relationship setup is
/// needed. Returns `true` if delivered over TSP, `false` to fall back to DIDComm
/// (not TSP-reachable, TSP transport not connected on this node, or a send error).
#[cfg(feature = "tsp")]
pub(super) async fn try_push_over_tsp(
    state: &AppState,
    recipient: &str,
    mediator_did: &str,
    doc: &Value,
) -> bool {
    if !state.tsp_reach.fresh(recipient) {
        return false;
    }
    let (Some(atm), Some(profile)) = (state.atm.as_ref(), state.tsp_profile.as_ref()) else {
        return false; // TSP transport not connected on this node
    };
    let body = match serde_json::to_vec(doc) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, recipient = %recipient, "serialising TSP push failed; DIDComm fallback");
            return false;
        }
    };
    // inner sealed end-to-end to the device, outer sealed to the mediator — the
    // same routed shape the inbound loop uses for its replies.
    match atm
        .tsp()
        .send_routed(
            profile,
            &[mediator_did.to_string(), recipient.to_string()],
            &body,
        )
        .await
    {
        Ok(_) => {
            tracing::debug!(recipient = %recipient, "delivered Trust-Task over TSP (learn-from-inbound)");
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, recipient = %recipient, "TSP push failed; falling back to DIDComm");
            false
        }
    }
}

/// Best-effort proactive delivery of a delegated step-up approve-request to the
/// approver's device over DIDComm, by buffering a forward through the resolved
/// mediator. No-op for self-approval (`recipient == caller`). Failures are
/// swallowed — the `403`/reject still carries the approve-request as a relay
/// fallback, so the proxied push is an enhancement, never a hard dependency.
async fn maybe_push_step_up(
    state: &AppState,
    recipient: &str,
    caller_did: &str,
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))]
    approve_request: &Value,
) {
    if recipient == caller_did {
        return; // self mode — the caller satisfies its own step-up.
    }
    let mediator_did = {
        let cfg = state.config.read().await;
        approver_mediator(
            recipient,
            cfg.messaging.as_ref().map(|m| m.mediator_did.as_str()),
        )
    };
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))]
    let Some(mediator_did) = mediator_did else {
        tracing::debug!(
            approver = %recipient,
            "no mediator route for delegated approver; relying on the relay fallback"
        );
        return;
    };
    // Prefer TSP when the device was recently seen on it (learn-from-inbound);
    // a fresh hit delivers over TSP and rings the doorbell, otherwise fall
    // through to the DIDComm path below.
    #[cfg(feature = "tsp")]
    if try_push_over_tsp(state, recipient, &mediator_did, approve_request).await {
        #[cfg(feature = "didcomm")]
        trigger_gateway_wake(state, recipient, &mediator_did).await;
        return;
    }
    #[cfg(feature = "didcomm")]
    {
        let pending = crate::messaging::registry::PendingResponse {
            recipient_did: recipient.to_string(),
            message_type: STEP_UP_APPROVE_REQUEST_TYPE.to_string(),
            body: approve_request.clone(),
            thread_id: approve_request
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        if let Err(e) = state
            .mediator_registry
            .buffer_outbound(&mediator_did, pending)
            .await
        {
            tracing::warn!(
                error = %e, approver = %recipient, mediator = %mediator_did,
                "failed to buffer delegated step-up push; relay fallback applies"
            );
        }

        // Actually deliver it: send the approve-request straight to the
        // approver's device over the mediator. `buffer_outbound` alone never
        // reaches the device (nothing drains it in steady state); this is the
        // send. The device replies later with a separate approve-response, so
        // it's fire-and-forget from this thread. Delivery-critical, so it goes
        // Guaranteed: durably queued + retried across websocket reconnects
        // (a bare send silently dropped the frame mid-reconnect — R1.1), keyed
        // by the approve-request id so retries dedup. The reject still carries
        // the approveRequest as the relay fallback if the window elapses.
        if let Err(e) = state
            .didcomm_bridge
            .send_guaranteed(
                "vta-main",
                recipient,
                STEP_UP_APPROVE_REQUEST_TYPE,
                approve_request.clone(),
                approve_request
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                Duration::from_secs(STEP_UP_TTL_SECS),
            )
            .await
        {
            tracing::warn!(
                error = %e, approver = %recipient,
                "delegated step-up push enqueue failed; relay fallback applies"
            );
        }
    }

    // VTA-trigger: wake the approver's device via its push gateway so a
    // backgrounded device is roused now, rather than only finding the queued
    // approve-request on its next voluntary pickup. Best-effort.
    #[cfg(feature = "didcomm")]
    trigger_gateway_wake(state, recipient, &mediator_did).await;
}

/// Send a `push/wake` to the approver device's push gateway over DIDComm
/// (spawned, best-effort): a contentless doorbell telling the device to connect
/// to `approver_mediator` and drain the queued `approve-request`. No-op if the
/// approver has no wake channel (set via `device/set-wake`) or its gateway isn't
/// a DID. The VTA authenticates to the gateway as the authcrypt sender (it is on
/// the handle's allowlist, provisioned at set-wake).
#[cfg(feature = "didcomm")]
pub(super) async fn trigger_gateway_wake(
    state: &AppState,
    recipient: &str,
    approver_mediator: &str,
) {
    /// DIDComm message type that carries a Trust Task envelope in its body.
    const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

    let wake = match get_acl_entry(&state.acl_ks, recipient).await {
        Ok(Some(entry)) => entry.device.and_then(|d| d.wake),
        _ => None,
    };
    let Some(wake) = wake else {
        return; // approver has no push wake channel — mediator queue + pickup applies.
    };
    if !wake.gateway.starts_with("did:") {
        return; // URL gateway → HTTPS path (follow-up).
    }
    let vta_did = state.config.read().await.vta_did.clone();
    let wake_doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/push/wake/0.1",
        "issuer": vta_did,
        "recipient": wake.gateway,
        "payload": {
            "handle": wake.handle,
            "v": 1,
            "mediator": approver_mediator,
            "urgency": "interactive",
        },
    });
    let bridge = state.didcomm_bridge.clone();
    let gateway = wake.gateway.clone();
    let approver = recipient.to_string();
    tokio::spawn(async move {
        match bridge
            .send_and_wait(
                &gateway,
                TRUST_TASK_ENVELOPE_TYPE,
                wake_doc,
                TRUST_TASK_ENVELOPE_TYPE,
                vta_sdk::protocols::PROBLEM_REPORT_TYPE,
                15,
            )
            .await
        {
            Ok(_) => {
                tracing::info!(gateway = %gateway, approver = %approver, "push/wake sent to gateway")
            }
            Err(e) => tracing::warn!(
                error = %e, gateway = %gateway, approver = %approver,
                "push/wake to gateway failed (best-effort)"
            ),
        }
    });
}

/// Trust-task analogue of [`issue_step_up_challenge`]: enforce a stepped-up
/// (AAL2) session inside a dispatcher handler.
///
/// Returns `None` when the session already satisfies AAL2. Otherwise mints a
/// pending step-up and returns a routed **reject** whose `details` carry the
/// `approveRequest`, mirroring the REST `403` so a step-up-aware client acts on
/// it the same way over either transport.
///
/// Call it *after* the handler's role check, so a caller lacking the role still
/// gets a permission error rather than a step-up prompt.
pub(super) async fn require_step_up(
    state: &AppState,
    auth: &AuthClaims,
    op_class: &str,
    doc: &TrustTask<Value>,
) -> Option<TrustTaskOutcome> {
    if auth.acr == STEP_UP_TARGET_ACR {
        return None;
    }
    // Trust-task gated ops (grant, change-role, revoke, context-delete,
    // key-revoke) are all escalating — they never qualify for the
    // non-escalation carve-out.
    let (recipient, approver_any) =
        match resolve_step_up(&state.config, &state.acl_ks, op_class, &auth.did, false).await {
            StepUpDecision::Allow => return None,
            StepUpDecision::Require { recipient } => (recipient, false),
            StepUpDecision::RequireAny => (String::new(), true),
            StepUpDecision::Deny => {
                return Some(reject_with(
                    doc,
                    RejectReason::TaskFailed {
                        reason: "auth:step_up_required".to_string(),
                        details: Some(json!({
                            "requiredAcr": STEP_UP_TARGET_ACR,
                            "reason": "no step-up approver is configured for this subject",
                        })),
                    },
                ));
            }
        };
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .unwrap_or_default();
    // A gated request MAY carry a structured authorization context (e.g. a
    // Cierge cross-domain share / spend / tool ask) at
    // `payload.authorizationContext`. Thread it into the approve-request so the
    // approver's device renders *what* is being authorized, and prefer its human
    // `summary` as the `reason` so a context-unaware renderer still shows
    // something meaningful.
    let (reason, authorization_context) = reason_and_context(&doc.payload);
    let reject = match mint_pending_step_up(
        &state.sessions_ks,
        &vta_did,
        &auth.did,
        &recipient,
        approver_any,
        &auth.session_id,
        reason,
        authorization_context,
    )
    .await
    {
        Ok(approve_request) => {
            // Delegated mode: proactively push the approve-request to the
            // approver's device over DIDComm. Best-effort — the carried
            // `approveRequest` below remains the relay fallback. Skipped for
            // `delegated-any` (no single approver device to target).
            if !approver_any {
                maybe_push_step_up(state, &recipient, &auth.did, &approve_request).await;
            }
            RejectReason::TaskFailed {
                reason: "auth:step_up_required".to_string(),
                details: Some(json!({
                    "requiredAcr": STEP_UP_TARGET_ACR,
                    "approveRequest": approve_request,
                })),
            }
        }
        Err(()) => RejectReason::InternalError {
            reason: "failed to initiate step-up".to_string(),
        },
    };
    Some(reject_with(doc, reject))
}

/// Initiate a **self-approve** step-up for a task the Policy Decision Point
/// decided requires it (a Rego `requireStepUp`), independent of the config
/// floors. Mints a `PendingStepUp` whose approver is the subject itself and
/// rejects the task with the `approve-request` — the caller elevates their own
/// session (via a stronger factor) and re-submits.
///
/// This is the policy-driven analogue of [`require_step_up`], which resolves the
/// approver from config/ACL. Delegated (someone-else-approves) approval is the
/// job of the consent flow, not step-up.
pub(super) async fn initiate_self_step_up(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> TrustTaskOutcome {
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .unwrap_or_default();
    let (reason, authorization_context) = reason_and_context(&doc.payload);
    let reject = match mint_pending_step_up(
        &state.sessions_ks,
        &vta_did,
        &auth.did,
        &auth.did, // self-approve: the subject is its own approver
        false,
        &auth.session_id,
        reason,
        authorization_context,
    )
    .await
    {
        Ok(approve_request) => {
            maybe_push_step_up(state, &auth.did, &auth.did, &approve_request).await;
            RejectReason::TaskFailed {
                reason: "auth:step_up_required".to_string(),
                details: Some(json!({
                    "requiredAcr": STEP_UP_TARGET_ACR,
                    "approveRequest": approve_request,
                })),
            }
        }
        Err(()) => RejectReason::InternalError {
            reason: "failed to initiate step-up".to_string(),
        },
    };
    reject_with(doc, reject)
}

/// Stable operation-class identifiers used to resolve step-up floors.
/// These are the gated VTA operations; they mirror the canonical
/// `acl/*` / `context/*` / `key/*` slugs the `auth/step-up/policy` spec uses for
/// its `Floor.operation`. Re-exported from [`vti_common::auth::step_up::op_class`]
/// so the gate and the policy-management `unknownOperation` check share one
/// source of truth.
// The op-class constants now live with the gate engine in
// `operations::step_up`; re-export them here so this module's handlers,
// extractor markers, and the `super::step_up::op::*` call sites across the
// trust-task slices keep their path unchanged.
pub use crate::operations::step_up::op;

/// Compile-time operation-class marker for the [`RequireStepUp`] extractor.
/// Each gated REST route names its op-class via a zero-sized type so the
/// extractor can resolve the matching policy floor without reading the body.
pub trait StepUpOp {
    const OP_CLASS: &'static str;
    /// `true` when the operation is *structurally* non-escalating: it acts
    /// only on the caller's own entry and preserves role/scopes (e.g. self
    /// key-rotation via `acl/swap-key`). Such an op is eligible for a floor's
    /// `allow_aal1_if_non_escalating` carve-out without inspecting the request
    /// body — the non-escalation property is guaranteed by the operation
    /// itself. Escalating ops (grant, change-role, …) leave this `false` and
    /// fail closed when a method is absent.
    const IS_NON_ESCALATING: bool = false;
}

macro_rules! step_up_op {
    ($name:ident, $class:expr) => {
        pub struct $name;
        impl StepUpOp for $name {
            const OP_CLASS: &'static str = $class;
        }
    };
    ($name:ident, $class:expr, non_escalating) => {
        pub struct $name;
        impl StepUpOp for $name {
            const OP_CLASS: &'static str = $class;
            const IS_NON_ESCALATING: bool = true;
        }
    };
}

step_up_op!(AclGrantOp, op::ACL_GRANT);
step_up_op!(AclChangeRoleOp, op::ACL_CHANGE_ROLE);
step_up_op!(AclRevokeOp, op::ACL_REVOKE);
step_up_op!(AclSwapKeyOp, op::ACL_SWAP_KEY, non_escalating);
step_up_op!(ContextDeleteOp, op::CONTEXT_DELETE);

/// Request extractor enforcing a **stepped-up (AAL2)** session for a
/// specific operation-class `O`.
///
/// A zero-sized marker: it gates, it does not carry claims. Pair it with the
/// handler's role extractor (`AdminAuth`, `ManageAuth`, …), which yields the
/// claims — `RequireStepUp` only asserts the session reached AAL2 *when the
/// policy floor for `O::OP_CLASS` requires it*. On a gated AAL1 session it
/// mints a pending step-up and rejects with the `403`-carrying-approve-request
/// ([`issue_step_up_challenge`]). Applied to the AAL2-gated REST routes; the
/// trust-task equivalents use [`require_step_up`].
pub struct RequireStepUp<O: StepUpOp>(std::marker::PhantomData<O>);

impl<O: StepUpOp> FromRequestParts<AppState> for RequireStepUp<O> {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let claims = AuthClaims::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        if claims.acr == "aal2" {
            return Ok(RequireStepUp(std::marker::PhantomData));
        }
        // Resolve the floor for this route's operation-class, honoring the
        // non-escalation carve-out (`O::IS_NON_ESCALATING`) and, for delegated
        // modes, routing to the caller's configured approver.
        let (recipient, approver_any) = match resolve_step_up(
            &state.config,
            &state.acl_ks,
            O::OP_CLASS,
            &claims.did,
            O::IS_NON_ESCALATING,
        )
        .await
        {
            StepUpDecision::Allow => return Ok(RequireStepUp(std::marker::PhantomData)),
            StepUpDecision::Require { recipient } => (recipient, false),
            StepUpDecision::RequireAny => (String::new(), true),
            StepUpDecision::Deny => return Err(step_up_denied_response()),
        };
        let vta_did = state
            .config
            .read()
            .await
            .vta_did
            .clone()
            .unwrap_or_default();
        Err(issue_step_up_challenge(
            &state.sessions_ks,
            &vta_did,
            &claims.did,
            &recipient,
            approver_any,
            &claims.session_id,
            "this operation requires a stepped-up (AAL2) session",
            // REST-gated routes carry no structured authorization context.
            None,
        )
        .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::DataIntegrityProof;
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::prepare_sign_input;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use multibase::Base;
    use serde_json::json;

    #[test]
    fn approver_mediator_routes_did_key_to_configured_mediator() {
        // did:key approver → the shared (VTA-configured) mediator.
        assert_eq!(
            approver_mediator("did:key:z6MkApprover", Some("did:web:mediator")),
            Some("did:web:mediator".to_string())
        );
        // No (or empty) configured mediator → no route (relay fallback).
        assert_eq!(approver_mediator("did:key:z6MkApprover", None), None);
        assert_eq!(approver_mediator("did:key:z6MkApprover", Some("")), None);
        // Future routable DIDs advertise their own mediator; not wired yet → None.
        assert_eq!(
            approver_mediator("did:webvh:scid:host:approver", Some("did:web:mediator")),
            None
        );
    }

    #[tokio::test]
    async fn issue_step_up_challenge_mints_pending_and_403s() {
        use vti_common::auth::step_up::get_pending_step_up;
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();

        let resp = issue_step_up_challenge(
            &ks,
            "did:web:vta.example",
            "did:key:zHolder",
            // self-approval: recipient == subject
            "did:key:zHolder",
            false,
            "sess-9",
            "rotate keys",
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "step_up_required");
        assert_eq!(v["requiredAcr"], "aal2");
        assert_eq!(
            v["approveRequest"]["type"],
            "https://trusttasks.org/spec/auth/step-up/approve-request/0.1"
        );
        assert_eq!(v["approveRequest"]["issuer"], "did:web:vta.example");
        assert_eq!(v["approveRequest"]["recipient"], "did:key:zHolder");
        assert_eq!(v["approveRequest"]["payload"]["sessionId"], "sess-9");
        assert_eq!(v["approveRequest"]["payload"]["targetAcr"], "aal2");
        assert_eq!(v["approveRequest"]["payload"]["reason"], "rotate keys");
        let challenge = v["approveRequest"]["payload"]["challenge"]
            .as_str()
            .expect("challenge string");

        // The pending step-up was minted + bound to the caller, ready for the
        // matching approve-response to consume.
        let pending = get_pending_step_up(&ks, challenge).await.unwrap().unwrap();
        assert_eq!(pending.session_id, "sess-9");
        assert_eq!(pending.subject, "did:key:zHolder");
        // self-approval recorded the subject as its own authorized approver.
        assert_eq!(pending.approver, "did:key:zHolder");
        assert_eq!(pending.target_acr, "aal2");
        assert_eq!(
            pending.acceptable_evidence,
            vec!["did-signed".to_string(), "webauthn".to_string()]
        );
    }

    #[test]
    fn reason_and_context_prefers_summary_and_passes_context_through() {
        // No context → generic reason, no context.
        let no_ctx = json!({ "holder": "did:key:z" });
        let (r, c) = reason_and_context(&no_ctx);
        assert_eq!(r, DEFAULT_STEP_UP_REASON);
        assert!(c.is_none());

        // Context with a summary → the summary IS the reason; context passes through.
        let payload = json!({
            "authorizationContext": {
                "summary": "finance wants to share salaryBand with travel",
                "action": { "kind": "share", "from": "finance", "to": "travel" }
            }
        });
        let (r, c) = reason_and_context(&payload);
        assert_eq!(r, "finance wants to share salaryBand with travel");
        assert_eq!(c.unwrap()["action"]["kind"], "share");

        // Context without a summary → generic reason, but context still carried.
        let summariless = json!({ "authorizationContext": { "action": {} } });
        let (r, c) = reason_and_context(&summariless);
        assert_eq!(r, DEFAULT_STEP_UP_REASON);
        assert!(c.is_some());
    }

    #[tokio::test]
    async fn step_up_challenge_embeds_authorization_context() {
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();

        let ctx = json!({
            "type": "https://openvtc.org/cierge/authorization-context/0.1",
            "summary": "finance wants to share salaryBand with travel",
            "risk": "high",
            "action": { "kind": "share", "from": "finance", "to": "travel", "ttlSeconds": 3600 },
        });
        let resp = issue_step_up_challenge(
            &ks,
            "did:web:vta.example",
            "did:key:zHolder",
            "did:key:zHolder",
            false,
            "sess-ctx",
            "finance wants to share salaryBand with travel",
            Some(&ctx),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let payload = &v["approveRequest"]["payload"];
        // The structured context rode into the approve-request under the
        // reverse-DNS `ext` key (spec-valid for deny_unknown_fields consumers)…
        let ctx = &payload["ext"]["org.openvtc.authorization-context"];
        assert_eq!(ctx["action"]["kind"], "share");
        assert_eq!(ctx["risk"], "high");
        assert_eq!(ctx["action"]["ttlSeconds"], 3600);
        // …and the reason echoes the human summary.
        assert_eq!(
            payload["reason"],
            "finance wants to share salaryBand with travel"
        );
    }
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

        let mut di = DataIntegrityProof::new(
            CryptoSuite::EddsaJcs2022,
            vm.to_string(),
            "assertionMethod".to_string(),
            None,
            Some("2026-05-31T00:00:00Z".to_string()),
            None,
        );
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
