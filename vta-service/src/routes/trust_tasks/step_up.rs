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
use vti_common::auth::step_up::{
    ConsumeOutcome, consume_pending_step_up, new_pending_step_up, store_pending_step_up,
};
use vti_common::store::KeyspaceHandle;

use super::helpers::{parse_payload, reject_with, success_response};

/// URIs dispatched by this slice (aggregated by the dispatcher's parity harness).
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
pub(super) const DISPATCHED_URIS: &[&str] =
    &[vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1];

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
    subject: &str,
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

    // Resolve credential.id → the subject's passkey VM (spec: resolve the
    // credential to a subject and verify it equals the session's subject).
    let vms = enumerate_passkey_vms(&resolver, subject)
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

/// Handler for `auth/step-up/approve-response/0.1`.
///
/// Consumes the approver's ratification of a pending step-up and, on a verified
/// gate, elevates the (caller's own) session's `amr`/`acr`. Follows the spec's
/// relying-party conformance rules; the bearer JWT (`auth`) identifies the
/// caller, and the approve-response's gate (did-signed proof or webauthn
/// assertion) is the second factor.
pub(super) async fn handle_approve_response(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    // 1. Parse the typed payload.
    let payload: approve_response::Payload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let subject = payload.subject.to_string();
    let session_id = payload.session_id.to_string();
    let challenge = payload.challenge.to_string();

    // 2. Subject binding: the document issuer AND the bearer caller must be the
    //    subject (same-session step-up — the caller elevates their own session).
    if doc.issuer.as_deref() != Some(subject.as_str()) {
        return reject_with(
            &doc,
            step_up_failure("auth/step-up/approve-response:subject_mismatch"),
        );
    }
    if auth.did != subject {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "caller is not the subject of this step-up".to_string(),
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

    // 4. A `denied` decision is a signed refusal — verify the did-signed gate,
    //    audit, and elevate nothing.
    if payload.decision == approve_response::PayloadDecision::Denied {
        if let Err(e) = verify_did_signed_gate(&doc, &subject).await {
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

    // 5. Approved — verify exactly one cryptographic gate.
    let factor: &str = match payload.evidence.as_ref() {
        None | Some(approve_response::Evidence::DidSigned) => {
            if let Err(e) = verify_did_signed_gate(&doc, &subject).await {
                return reject_with(&doc, gate_err_to_reject(e));
            }
            "did"
        }
        Some(approve_response::Evidence::Webauthn(assertion)) => {
            match verify_webauthn_gate(state, &subject, &challenge, assertion).await {
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
async fn mint_pending_step_up(
    sessions_ks: &KeyspaceHandle,
    vta_did: &str,
    subject: &str,
    session_id: &str,
    reason: &str,
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
        STEP_UP_TARGET_ACR,
        acceptable.clone(),
        STEP_UP_TTL_SECS,
    );
    if let Err(e) = store_pending_step_up(sessions_ks, &pending).await {
        tracing::error!(error = %e, "failed to persist pending step-up");
        return Err(());
    }

    Ok(json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
        "issuer": vta_did,
        "recipient": subject,
        "payload": {
            "subject": subject,
            "sessionId": session_id,
            "challenge": challenge,
            "reason": reason,
            "targetAcr": STEP_UP_TARGET_ACR,
            "acceptableEvidence": acceptable,
            "ttl": STEP_UP_TTL_SECS,
        },
    }))
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
    session_id: &str,
    reason: &str,
) -> Response {
    let approve_request =
        match mint_pending_step_up(sessions_ks, vta_did, subject, session_id, reason).await {
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
) -> Option<Response> {
    if auth.acr == STEP_UP_TARGET_ACR {
        return None;
    }
    let (vta_did, gated) = {
        let cfg = state.config.read().await;
        // Resolve the step-up floor for this operation-class (most specific
        // floor, else the `*` catch-all, else none). A disabled policy
        // yields `None` → not gated → the operation proceeds at AAL1.
        let gated = cfg.auth.step_up.floor_for(op_class).requires_aal2();
        (cfg.vta_did.clone().unwrap_or_default(), gated)
    };
    if !gated {
        return None;
    }
    let reject = match mint_pending_step_up(
        &state.sessions_ks,
        &vta_did,
        &auth.did,
        &auth.session_id,
        "this operation requires a stepped-up (AAL2) session",
    )
    .await
    {
        Ok(approve_request) => RejectReason::TaskFailed {
            reason: "auth:step_up_required".to_string(),
            details: Some(json!({
                "requiredAcr": STEP_UP_TARGET_ACR,
                "approveRequest": approve_request,
            })),
        },
        Err(()) => RejectReason::InternalError {
            reason: "failed to initiate step-up".to_string(),
        },
    };
    Some(reject_with(doc, reject))
}

/// Stable operation-class identifiers used to resolve step-up floors.
/// These are the gated VTA operations; they mirror the canonical
/// `acl/*` / `context/*` / `key/*` slugs the `auth/step-up/policy/0.1`
/// spec uses for its `Floor.operation`.
pub mod op {
    pub const ACL_GRANT: &str = "acl/grant";
    pub const ACL_CHANGE_ROLE: &str = "acl/change-role";
    pub const ACL_REVOKE: &str = "acl/revoke";
    pub const ACL_SWAP_KEY: &str = "acl/swap-key";
    pub const CONTEXT_DELETE: &str = "context/delete";
    pub const KEY_REVOKE: &str = "key/revoke";
}

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
        let (vta_did, gated) = {
            let cfg = state.config.read().await;
            // Resolve the floor for this route's operation-class. A disabled
            // policy (or no matching floor) is not gated → proceed at AAL1.
            // Non-escalation carve-out: a floor that requires AAL2 still
            // admits a structurally non-escalating op (e.g. self key-rotation
            // via `acl/swap-key`) at AAL1 when it sets
            // `allow_aal1_if_non_escalating` — so a holder with no authenticator
            // yet can still rotate. Escalating ops never qualify.
            let gated = match cfg.auth.step_up.floor_record(O::OP_CLASS) {
                None => false,
                Some(f) => {
                    f.mode.requires_aal2()
                        && !(f.allow_aal1_if_non_escalating && O::IS_NON_ESCALATING)
                }
            };
            (cfg.vta_did.clone().unwrap_or_default(), gated)
        };
        if !gated {
            return Ok(RequireStepUp(std::marker::PhantomData));
        }
        Err(issue_step_up_challenge(
            &state.sessions_ks,
            &vta_did,
            &claims.did,
            &claims.session_id,
            "this operation requires a stepped-up (AAL2) session",
        )
        .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::prepare_sign_input;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use multibase::Base;
    use serde_json::json;

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
        let ks = store.keyspace("sessions").unwrap();

        let resp = issue_step_up_challenge(
            &ks,
            "did:web:vta.example",
            "did:key:zHolder",
            "sess-9",
            "rotate keys",
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
        assert_eq!(pending.target_acr, "aal2");
        assert_eq!(
            pending.acceptable_evidence,
            vec!["did-signed".to_string(), "webauthn".to_string()]
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
