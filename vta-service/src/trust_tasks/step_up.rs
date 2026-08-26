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
//!
//! The *request* leg (`auth/step-up/approve-request/0.2`, minted by
//! [`mint_pending_step_up`]) is **signed by this VTA** — `eddsa-jcs-2022`,
//! `assertionMethod`, issuer DID == the proof's `verificationMethod` DID —
//! the same shape as `task-consent` ([`super::consent_request`]) and the
//! spec's REQUIRED proof. Both request legs put prose (`reason`) in front of
//! a human, so the request must be attributable to its issuer, and the signed
//! document doubles as retainable evidence of exactly what was asked. The
//! challenge binding still carries the decision's freshness — the signature
//! authenticates the ask, the challenge scopes the approval.

// Only the DIDComm send below bounds its delivery window.
#[cfg(feature = "didcomm")]
use std::time::Duration;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use base64::Engine as _;
use base64::engine::general_purpose;
use serde_json::{Value, json};
use trust_tasks_rs::specs::auth::step_up::approve_response::v0_1 as approve_response;
// Only the DIDComm sends name the envelope; TSP carries the document bytes
// directly, so this is unused when the binding is compiled out. Imported from the
// binding crate rather than copied — one source, no local literals (#900).
#[cfg(feature = "didcomm")]
use trust_tasks_didcomm::ENVELOPE_TYPE as TRUST_TASK_ENVELOPE_TYPE;
#[cfg(feature = "didcomm")]
use trust_tasks_rs::specs::push::wake::v0_2 as push_wake;
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
/// `auth/step-up/approve-response:challengeUnknown`) as the reason.
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
        GateError::NoGate => step_up_failure("auth/step-up/approve-response:noGate"),
        GateError::SubjectMismatch => {
            step_up_failure("auth/step-up/approve-response:subjectMismatch")
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

    let invalid = || step_up_failure("auth/step-up/approve-response:assertionInvalid");
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
            step_up_failure("auth/step-up/approve-response:subjectMismatch"),
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
                step_up_failure("auth/step-up/approve-response:challengeUnknown"),
            );
        }
        Ok(ConsumeOutcome::Expired) => {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:challengeExpired"),
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
            step_up_failure("auth/step-up/approve-response:subjectMismatch"),
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
                    step_up_failure("auth/step-up/approve-response:approverUnauthorized"),
                );
            }
        };
        let subject_entry = match get_acl_entry(&state.acl_ks, &subject).await {
            Ok(Some(e)) => e,
            _ => {
                return reject_with(
                    &doc,
                    step_up_failure("auth/step-up/approve-response:approverUnauthorized"),
                );
            }
        };
        if !delegated_any_approver_covers(&issuer_entry, &subject_entry) {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:approverUnauthorized"),
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
                step_up_failure("auth/step-up/approve-response:approverUnauthorized"),
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
            step_up_failure("auth/step-up/approve-response:acrUnsatisfied"),
        );
    }

    // 7. Load + elevate the session.
    let mut session = match get_session(&state.sessions_ks, &session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return reject_with(
                &doc,
                step_up_failure("auth/step-up/approve-response:challengeUnknown"),
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
    // Bound the elevation. The window is what stops a single approval from
    // granting permanent aal2, on both transports:
    // - intrinsic-sender (DIDComm/TSP) reads `acr` straight off this row on
    //   every subsequent message, so `resolve_did_session` downgrades it back
    //   to aal1 once the deadline passes;
    // - REST's `StepUpAuth` reads this deadline directly, so a lapsed window
    //   fails the gate without the row needing to be rewritten.
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

/// Load the VTA's `{vta_did}#key-0` issuer key for signing a step-up
/// approve-request. Thin wrapper over
/// [`crate::operations::credentials::load_vta_issuer_secret`] (the same key
/// task-consent requests are signed with) that logs the failure and flattens
/// the error to `Err(())` for the gate surfaces' internal-error mapping.
async fn load_step_up_signing_secret(state: &AppState, vta_did: &str) -> Result<Secret, ()> {
    crate::operations::credentials::load_vta_issuer_secret(state, vta_did, "step-up")
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load VTA issuer key for step-up approve-request");
        })
}

/// Mint a pending step-up and build the **signed**
/// `auth/step-up/approve-request/0.2` document the AAL1 caller hands to its
/// approver (wallet / VTA). 0.2 differs from 0.1 only in the type URI and the
/// `acceptableEvidence` spelling (`did-signed` → `didSigned`); every fielded
/// receiver (vta-mobile-core, the browser plugin) accepts both request
/// flavors, so the mint moved cleanly to 0.2 (#870's deferred follow-up).
///
/// A fresh challenge is bound server-side to the caller's
/// `{session_id, subject, targetAcr=aal2, acceptableEvidence}` via the
/// pending-step-up store; the approver's `approve-response` is later consumed by
/// [`handle_approve_response`]. One caller: [`initiate_self_step_up`], reached
/// from the gate's `requireStepUp` disposition — the two floor-driven wrappers
/// that used to share it are gone.
///
/// The document carries the spec's REQUIRED Data-Integrity proof
/// (`eddsa-jcs-2022`, `assertionMethod`), signed with `secret` — the VTA's
/// `{vta_did}#key-0` issuer key — so the `reason` a human reads is attributable
/// to this VTA and the request is retainable evidence of what was asked (see
/// the module doc). Signing happens *last*, over the complete document
/// (including `recipient` and `payload.ext`).
///
/// Returns the approve-request document, or `Err(())` if the pending step-up
/// could not be persisted or the document could not be signed (the caller maps
/// that to a 5xx / internal-error reject).
async fn mint_pending_step_up(
    sessions_ks: &KeyspaceHandle,
    vta_did: &str,
    secret: &Secret,
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
    // The *stored* pending record keeps the kebab canonical form
    // (`did-signed`) that `vti_common::auth::step_up` documents — it's internal
    // state, not wire. The 0.2 wire spelling is camelCase (`didSigned`).
    let acceptable = vec!["did-signed".to_string(), "webauthn".to_string()];
    let acceptable_wire = vec!["didSigned".to_string(), "webauthn".to_string()];

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
        "type": STEP_UP_APPROVE_REQUEST_TYPE,
        "issuer": vta_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "subject": subject,
            "sessionId": session_id,
            "challenge": challenge,
            "reason": reason,
            "targetAcr": STEP_UP_TARGET_ACR,
            "acceptableEvidence": acceptable_wire,
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
    // Sign the complete document (spec: proof REQUIRED) — same pattern as
    // `consent_request::mint_signed_requests`. The proof's verificationMethod
    // resolves under the VTA DID, so issuer DID == proof VM DID.
    let proof = match DataIntegrityProof::sign(
        &doc,
        secret,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to sign step-up approve-request");
            return Err(());
        }
    };
    match serde_json::to_value(&proof) {
        Ok(p) => doc["proof"] = p,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize step-up approve-request proof");
            return Err(());
        }
    }
    Ok(doc)
}

/// Trust Task `type` of a step-up approve-request. 0.2 — both fielded approver
/// stacks (vta-mobile-core #871, the browser plugin) accept 0.1 and 0.2 request
/// URIs.
///
/// This is the **document's** type, and only that. It is no longer the DIDComm
/// message type: that is `trust_tasks_didcomm::ENVELOPE_TYPE`, and naming this
/// one there is precisely the defect fixed in this change. `mint_pending_step_up`
/// now reads the constant instead of repeating the literal, so the document and
/// this name cannot drift apart — which is why the gate came off, the mint site
/// not being DIDComm-specific.
const STEP_UP_APPROVE_REQUEST_TYPE: &str =
    "https://trusttasks.org/spec/auth/step-up/approve-request/0.2";

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
        // `webvh`, not `didcomm`: `AppState::mediator_registry` only exists
        // under `webvh`, while `PendingResponse`'s module needs only
        // `didcomm`. The comment below is explicit that this buffer never
        // reaches the device on its own — the send that follows is the
        // delivery path, and it stays on `didcomm`.
        #[cfg(feature = "webvh")]
        {
            let pending = crate::messaging::registry::PendingResponse {
                recipient_did: recipient.to_string(),
                // The DIDComm binding's envelope type, NOT the task type. A
                // conformant approver unwraps `ENVELOPE_TYPE` and reads the
                // `TrustTask` from the body; anything else it rejects, and
                // rejects *silently* — "not an envelope" is indistinguishable
                // from "not addressed to me". This path had the same defect as
                // the consent request (#900) and nobody noticed, because the
                // relay fallback below hides it: the reject still carries the
                // approveRequest, so the flow completes via the slow path and
                // only the proactive push is dead.
                //
                // `STEP_UP_APPROVE_REQUEST_TYPE` remains the document's own
                // `type` — it moved into the envelope, it did not disappear.
                // TSP is untouched above: it carries the document bytes
                // directly, so the wrapper belongs to the DIDComm binding, not
                // to the task.
                message_type: TRUST_TASK_ENVELOPE_TYPE.to_string(),
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
                // Envelope type, per the DIDComm binding — see the buffer above.
                TRUST_TASK_ENVELOPE_TYPE,
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
        "type": "https://trusttasks.org/spec/push/wake/0.2",
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
            Ok(reply) => match wake_reply_status(&reply.body) {
                Some(push_wake::ResponseStatus::TokenUnregistered) => tracing::warn!(
                    gateway = %gateway, approver = %approver,
                    "push/wake: gateway reports tokenUnregistered — dead platform token, \
                     handle dropped; mediator queue + pickup fallback applies"
                ),
                Some(push_wake::ResponseStatus::Delivered) => {
                    tracing::info!(gateway = %gateway, approver = %approver, "push/wake delivered by gateway")
                }
                None => tracing::info!(
                    gateway = %gateway, approver = %approver,
                    "push/wake sent to gateway (no recognizable 0.2 response status)"
                ),
            },
            Err(e) => tracing::warn!(
                error = %e, gateway = %gateway, approver = %approver,
                "push/wake to gateway failed (best-effort)"
            ),
        }
    });
}

/// Extract the `push/wake/0.2#response` status from the gateway's reply — the
/// DIDComm envelope body is the Trust Task response document, so the status
/// lives at `payload.status`. Returns `None` when the reply carries no
/// recognizable 0.2 status; that includes the retired 0.1 kebab-case
/// `token-unregistered`, which the 0.2 clean cutover no longer accepts.
#[cfg(feature = "didcomm")]
fn wake_reply_status(envelope_body: &Value) -> Option<push_wake::ResponseStatus> {
    envelope_body
        .pointer("/payload/status")
        .and_then(|s| serde_json::from_value(s.clone()).ok())
}

/// Initiate a **self-approve** step-up for a task the Policy Decision Point
/// decided requires it (a rule's `requireStepUp`). Mints a `PendingStepUp`
/// whose approver is the subject itself and rejects the task with the
/// `approve-request` — the caller elevates their own session (via a stronger
/// factor) and re-submits.
///
/// This is the only way a step-up is initiated. It replaced `require_step_up`,
/// which resolved an approver from the `[auth.step_up]` floors and could
/// therefore address the request to a third party. Someone-else-approves is the
/// consent flow's job (`requireConsent` + an approver set), which carries a
/// threshold, re-checks at consume time that the approvers are still
/// authorized, and shows the human a signed statement of the effects —
/// none of which a delegated step-up floor ever did.
pub(super) async fn initiate_self_step_up(
    state: &AppState,
    auth: &AuthClaims,
    payload: &Value,
) -> RejectReason {
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .unwrap_or_default();
    let (reason, authorization_context) = reason_and_context(payload);
    let secret = match load_step_up_signing_secret(state, &vta_did).await {
        Ok(s) => s,
        Err(()) => {
            return RejectReason::InternalError {
                reason: "failed to initiate step-up".to_string(),
            };
        }
    };
    match mint_pending_step_up(
        &state.sessions_ks,
        &vta_did,
        &secret,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::DataIntegrityProof;
    use affinidi_data_integrity::crypto_suites::CryptoSuite;
    use affinidi_data_integrity::prepare_sign_input;
    use ed25519_dalek::{Signer, SigningKey};
    use multibase::Base;
    use serde_json::json;

    #[cfg(feature = "didcomm")]
    #[test]
    fn wake_reply_status_parses_camel_case_token_unregistered() {
        // push/wake/0.2 renamed the status value `token-unregistered` →
        // `tokenUnregistered` (the only wire-visible 0.1→0.2 change).
        let reply = json!({
            "type": "https://trusttasks.org/spec/push/wake/0.2#response",
            "payload": { "status": "tokenUnregistered" },
        });
        assert_eq!(
            wake_reply_status(&reply),
            Some(push_wake::ResponseStatus::TokenUnregistered)
        );
    }

    #[cfg(feature = "didcomm")]
    #[test]
    fn wake_reply_status_parses_delivered() {
        let reply = json!({
            "type": "https://trusttasks.org/spec/push/wake/0.2#response",
            "payload": { "status": "delivered" },
        });
        assert_eq!(
            wake_reply_status(&reply),
            Some(push_wake::ResponseStatus::Delivered)
        );
    }

    #[cfg(feature = "didcomm")]
    #[test]
    fn wake_reply_status_rejects_retired_kebab_case_and_junk() {
        // Clean cutover: the 0.1 kebab-case value is NOT accepted.
        let legacy = json!({ "payload": { "status": "token-unregistered" } });
        assert_eq!(wake_reply_status(&legacy), None);
        // Missing / malformed payloads degrade to None (best-effort logging).
        assert_eq!(wake_reply_status(&json!({})), None);
        assert_eq!(wake_reply_status(&json!({ "payload": {} })), None);
    }

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

    /// The minted approve-request is well-formed, signed, and bound to a
    /// pending step-up the matching approve-response can consume.
    ///
    /// This drove `issue_step_up_challenge` — the REST `403`-shaping wrapper —
    /// until the extractor that called it was retired with the config floors.
    /// The 403 shape is now `AppError::ApprovalRequired`'s, covered where that
    /// lives; what is specific to step-up, and what this keeps, is the document
    /// and the pending record behind it.
    #[tokio::test]
    async fn minting_a_step_up_binds_a_pending_and_signs_the_request() {
        use vti_common::auth::step_up::get_pending_step_up;
        use vti_common::config::StoreConfig;
        use vti_common::store::Store;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();

        // A did:key issuer so the minted proof can be verified end-to-end with
        // the same shared verifier the gates use (did:key resolves locally).
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let (vta_did, mb) = did_key(&sk);
        let secret = issuer_secret(&sk, &format!("{vta_did}#{mb}"));

        let v = json!({
            "approveRequest": mint_pending_step_up(
                &ks,
                &vta_did,
                &secret,
                "did:key:zHolder",
                // self-approval: recipient == subject
                "did:key:zHolder",
                false,
                "sess-9",
                "rotate keys",
                None,
            )
            .await
            .expect("mint succeeds"),
        });

        assert_eq!(
            v["approveRequest"]["type"],
            "https://trusttasks.org/spec/auth/step-up/approve-request/0.2"
        );
        assert_eq!(v["approveRequest"]["issuer"], vta_did);
        assert_eq!(v["approveRequest"]["recipient"], "did:key:zHolder");
        assert_eq!(v["approveRequest"]["payload"]["sessionId"], "sess-9");
        assert_eq!(v["approveRequest"]["payload"]["targetAcr"], "aal2");
        assert_eq!(v["approveRequest"]["payload"]["reason"], "rotate keys");
        // 0.2 wire spelling: camelCase `didSigned` (0.1 said `did-signed`).
        assert_eq!(
            v["approveRequest"]["payload"]["acceptableEvidence"],
            json!(["didSigned", "webauthn"])
        );
        let challenge = v["approveRequest"]["payload"]["challenge"]
            .as_str()
            .expect("challenge string");
        assert!(
            challenge.len() >= 16,
            "challenge must carry ≥128 bits: {challenge}"
        );

        // The approve-request is signed (spec: proof REQUIRED) — an
        // eddsa-jcs-2022 assertionMethod proof whose verificationMethod DID is
        // the issuer, and the signature verifies over the served document.
        let proof = &v["approveRequest"]["proof"];
        assert_eq!(proof["type"], "DataIntegrityProof", "{v}");
        assert_eq!(proof["cryptosuite"], "eddsa-jcs-2022", "{v}");
        assert_eq!(proof["proofPurpose"], "assertionMethod", "{v}");
        let task: TrustTask<Value> = serde_json::from_value(v["approveRequest"].clone()).unwrap();
        let signer = crate::auth::di_proof::verify_trust_task_proof(&task)
            .await
            .expect("approve-request proof verifies");
        assert_eq!(
            signer, vta_did,
            "issuer DID == proof verificationMethod DID"
        );

        // The pending step-up was minted + bound to the caller, ready for the
        // matching approve-response to consume.
        let pending = get_pending_step_up(&ks, challenge).await.unwrap().unwrap();
        assert_eq!(pending.session_id, "sess-9");
        assert_eq!(pending.subject, "did:key:zHolder");
        // self-approval recorded the subject as its own authorized approver.
        assert_eq!(pending.approver, "did:key:zHolder");
        assert_eq!(pending.target_acr, "aal2");
        // The stored record keeps the internal kebab canonical form even
        // though the 0.2 wire says `didSigned` (it's state, not wire).
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
        let sk = SigningKey::from_bytes(&[43u8; 32]);
        let (vta_did, mb) = did_key(&sk);
        let secret = issuer_secret(&sk, &format!("{vta_did}#{mb}"));

        let v = json!({
            "approveRequest": mint_pending_step_up(
                &ks,
                &vta_did,
                &secret,
                "did:key:zHolder",
                "did:key:zHolder",
                false,
                "sess-ctx",
                "finance wants to share salaryBand with travel",
                Some(&ctx),
            )
            .await
            .expect("mint succeeds"),
        });

        // The `ext` context rides *inside* the signed surface — the proof
        // covers it (SPEC: "The optional `ext` extension is part of the signed
        // surface").
        let task: TrustTask<Value> = serde_json::from_value(v["approveRequest"].clone()).unwrap();
        let signer = crate::auth::di_proof::verify_trust_task_proof(&task)
            .await
            .expect("approve-request proof verifies over ext");
        assert_eq!(signer, vta_did);
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

    /// A signing `Secret` for `sk` with verification-method `id` — the shape
    /// `load_vta_issuer_secret` hands the production mint path.
    fn issuer_secret(sk: &SigningKey, id: &str) -> Secret {
        Secret::generate_ed25519(Some(id), Some(sk.as_bytes()))
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

#[cfg(all(test, feature = "didcomm", feature = "webvh"))]
mod envelope_push_tests {
    use crate::messaging::registry::MediatorBinding;
    use serde_json::json;

    const MEDIATOR: &str = "did:example:mediator";
    const APPROVER: &str = "did:key:zStepUpApprover";
    const CALLER: &str = "did:key:zCaller";

    /// The delegated step-up push goes out under the **envelope** type, with the
    /// task type inside the document.
    ///
    /// This one mattered most and showed least. Step-up approvals to a device
    /// were broken on this path the whole time, and nothing surfaced it: the
    /// reject still carries the `approveRequest` as a relay fallback, so the
    /// ceremony completes by the slow route while the proactive push lands in a
    /// void — delivered, acked, unreadable.
    #[tokio::test]
    async fn delegated_step_up_push_is_an_envelope() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;

        state
            .mediator_registry
            .record_activate(MediatorBinding {
                mediator_did: MEDIATOR.into(),
                endpoint: "https://mediator.test".into(),
            })
            .await;
        {
            let mut cfg = state.config.write().await;
            cfg.messaging = Some(vti_common::config::MessagingConfig {
                mediator_url: String::new(),
                mediator_did: MEDIATOR.into(),
                mediator_host: None,
                setup_acl: false,
                drain_inbox_on_start: false,
            });
        }

        // The shape `mint_pending_step_up` produces: a Trust Task document whose
        // own `type` is the approve-request URI.
        let approve_request = json!({
            "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": super::STEP_UP_APPROVE_REQUEST_TYPE,
            "issuer": "did:key:zVta",
            "payload": { "subject": CALLER, "challenge": "c" },
        });

        super::maybe_push_step_up(&state, APPROVER, CALLER, &approve_request).await;

        let pushed = state.mediator_registry.take_outbound(MEDIATOR).await;
        assert_eq!(pushed.len(), 1, "the approver is pushed exactly once");
        assert_eq!(
            pushed[0].message_type,
            trust_tasks_didcomm::ENVELOPE_TYPE,
            "the DIDComm message must carry the binding's envelope type"
        );
        assert_eq!(
            pushed[0].body.get("type").and_then(|t| t.as_str()),
            Some(super::STEP_UP_APPROVE_REQUEST_TYPE),
            "the task type belongs in the enveloped document, not on the envelope"
        );
        assert_eq!(pushed[0].recipient_did, APPROVER);
    }

    /// Self-approval is not a delegation, so nothing is pushed at all.
    #[tokio::test]
    async fn self_approval_pushes_nothing() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        state
            .mediator_registry
            .record_activate(MediatorBinding {
                mediator_did: MEDIATOR.into(),
                endpoint: "https://mediator.test".into(),
            })
            .await;

        super::maybe_push_step_up(&state, CALLER, CALLER, &json!({})).await;

        assert!(
            state
                .mediator_registry
                .take_outbound(MEDIATOR)
                .await
                .is_empty(),
            "a caller satisfying its own step-up must not ring its own phone"
        );
    }
}
