//! `auth/step-up/approve-response` — the answer to an operation-bound step-up.
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::routing::{Routes, on};
use super::*;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    on!(routes, vti_specs::auth::step_up::approve_response::v0_7::Payload => handle_step_up_approve_response)
}

/// `auth/step-up/approve-response/0.7` — the answer to an operation-bound
/// step-up ([`STEP_UP_APPROVE_RESPONSE_TYPE`]).
///
/// Before the pending step-up is looked up (consumer item 1a), so a refused
/// answer leaves the challenge for the right one:
///
/// - **A proof, when present, is the approver's own.** The spine has verified
///   it — made for `assertionMethod`, by a key the signer lists under
///   `assertionMethod` — and refused a delegated signing key's (a console
///   key's) as `subjectMismatch` before dispatch. Here the signer must be
///   `payload.subject` itself (`subjectMismatch`): this service asks only
///   self step-ups.
/// - **No proof** is heard only for an approval carrying `webauthn` evidence
///   (0.7 producer item 5a) — the admin console's answer, whose only key is a
///   delegation. A `didSigned` or `approverSigned` answer, or any denial,
///   without one is `proofRequired`. The unsigned answer must name the subject
///   as its `issuer` (producer item 1, `subjectMismatch`), and its credential
///   must be a passkey registered to someone here
///   ([`unsigned_answer_admissible`], `assertionInvalid` /
///   `credentialUnknown`); [`crate::acl::bound_step_up::approve`] then
///   requires it to be the subject's and user-verified.
///
/// An approval carrying `approverSigned` goes to
/// [`crate::acl::bound_step_up::approve_with_statement`]; everything else
/// (`webauthn`, a refusal) to [`crate::acl::bound_step_up::approve`]. What the
/// gesture authorizes is read from this service's record of the refusal,
/// never from this document — so an unsigned answer decides nothing the
/// assertion and that record do not (item 4a). This service only issues bound
/// step-ups here, so the answer is `recorded` or `rejected`, never `elevated`.
pub(super) async fn handle_step_up_approve_response(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::acl::bound_step_up::{self, ApproveError, Approved};
    use step_up_approve_response::error_codes as codes;

    let payload: step_up_approve_response::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let refuse = |code: trust_tasks_rs::DeclaredErrorCode, message: &str, hint: Option<&str>| {
        reject_with_code(
            &doc,
            extended_code(code.code),
            message,
            hint.map(|h| serde_json::json!({ "reason": h })),
        )
    };
    let signed = match ctx.verified_signer.as_deref() {
        Some(signer) if signer == payload.subject.as_str() => true,
        Some(_) => {
            return refuse(
                codes::SUBJECT_MISMATCH,
                "an approve-response must be signed by the subject's own DID",
                None,
            );
        }
        None => false,
    };
    if !signed {
        let passkey_approval = payload.decision
            == step_up_approve_response::PayloadDecision::Approved
            && matches!(
                payload.evidence,
                Some(step_up_approve_response::Evidence::Webauthn { .. })
            );
        if !passkey_approval {
            return reject_with(&doc, RejectReason::ProofRequired);
        }
        if doc.issuer.as_deref() != Some(payload.subject.as_str()) {
            return refuse(
                codes::SUBJECT_MISMATCH,
                "an unsigned approve-response names the approver — the subject — as its issuer",
                None,
            );
        }
        if !unsigned_answer_admissible(state, &payload).await {
            return refuse(
                codes::ASSERTION_INVALID,
                "the passkey that made this assertion is not registered here",
                Some("credentialUnknown"),
            );
        }
    }

    let approver_signed = matches!(
        payload.evidence,
        Some(step_up_approve_response::Evidence::ApproverSigned { .. })
    );
    let outcome = if approver_signed {
        if payload.decision != step_up_approve_response::PayloadDecision::Approved {
            // A refusal is the subject's signed statement (0.7 producer item
            // 6); it carries no factor.
            return refuse(
                codes::NO_GATE,
                "a refusal is signed by the subject and carries no approver statement \
                 (evidence.kind = didSigned)",
                None,
            );
        }
        // The statement exactly as received: `doc.payload` is the JSON the
        // bytes parsed to, so the approver's proof is checked over the members
        // it signed (VTI-45), never over a re-serialisation of the typed
        // `AttestStatement`.
        let Some(statement) = doc.payload.pointer("/evidence/statement") else {
            return refuse(codes::STATEMENT_INVALID, "no statement", None);
        };
        bound_step_up::approve_with_statement(
            state,
            payload.subject.as_str(),
            payload.challenge.as_str(),
            payload.session_id.is_some(),
            statement,
        )
        .await
    } else {
        bound_step_up::approve(state, &payload, signed).await
    };
    match outcome {
        Ok(Approved::Recorded { bound_to }) => success_response(
            &doc,
            serde_json::json!({ "status": "recorded", "boundTo": bound_to }),
        ),
        Ok(Approved::Declined { reason }) => success_response(
            &doc,
            serde_json::json!({ "status": "rejected", "reason": reason }),
        ),
        Err(ApproveError::ChallengeUnknown) => refuse(
            codes::CHALLENGE_UNKNOWN,
            "no pending step-up matches this challenge",
            None,
        ),
        Err(ApproveError::ChallengeExpired) => refuse(
            codes::CHALLENGE_EXPIRED,
            "the step-up this challenge belonged to has expired; send the operation again",
            None,
        ),
        Err(ApproveError::SubjectMismatch) => refuse(
            codes::SUBJECT_MISMATCH,
            "the subject, the session or the passkey's owner does not match the pending step-up",
            None,
        ),
        Err(ApproveError::NoGate) => refuse(
            codes::NO_GATE,
            "this step-up did not accept that kind of evidence; answer with one the request's \
             `accepts` lists",
            None,
        ),
        Err(ApproveError::AssertionInvalid(hint)) => refuse(
            codes::ASSERTION_INVALID,
            "the passkey assertion did not verify",
            Some(hint),
        ),
        Err(ApproveError::StatementInvalid) => refuse(
            codes::STATEMENT_INVALID,
            "the step-up approver's statement is not valid for this step-up",
            None,
        ),
        Err(ApproveError::ApproverNotBound) => refuse(
            codes::APPROVER_NOT_BOUND,
            "the statement is not signed by a step-up approver bound to the subject",
            None,
        ),
        Err(ApproveError::ProofRequired) => reject_with(&doc, RejectReason::ProofRequired),
        Err(ApproveError::Internal(e)) => app_error_to_reject(&doc, &e),
    }
}

/// Whether an **unsigned** approve-response's assertion names a credential
/// registered here at all — a session passkey or a step-up passkey. Settled
/// before the pending step-up is taken, so an assertion by a stranger's
/// authenticator cannot spend a challenge it was never asked.
/// [`crate::acl::bound_step_up::approve`] checks, once the assertion has
/// verified, that the credential is the subject's own.
pub(super) async fn unsigned_answer_admissible(
    state: &AppState,
    payload: &step_up_approve_response::Payload,
) -> bool {
    use base64::Engine as _;
    let Some(step_up_approve_response::Evidence::Webauthn { assertion }) =
        payload.evidence.as_ref()
    else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&assertion.raw_id) else {
        return false;
    };
    let cred = hex::encode(raw);
    for ks in [&state.passkey_ks, &state.step_up_passkeys_ks] {
        if let Ok(Some(_)) =
            vti_common::auth::passkey::store::get_passkey_user_by_cred(ks, &cred).await
        {
            return true;
        }
    }
    false
}
