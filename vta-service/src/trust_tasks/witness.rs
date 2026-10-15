//! The witnessed-party tasks — `vta/witness/open/0.1`, `vta/witness/present/0.1` and
//! `vta/witness/accept/0.1` (trust-tasks-tf #779, rules in `vta/_shared/0.5/CONVENTIONS.md`).
//!
//! The engine is [`crate::operations::witness`]; this slice is the dispatch surface over it:
//!
//! - **Capability-gated** before anything is read: `witness-request` (registered upstream as
//!   `witnessRequest`) for all three. It is not `sign`, and `sign` does not satisfy it
//!   (conventions §4).
//! - **Context-gated** in the engine: the keys of the session's DIDs, the credentials and the
//!   session record are all found only among the contexts the caller may act in.
//! - **Audited** with the caller, the context, the session and the witness — never a
//!   presentation, a challenge or a member DID (`vta/witness/accept/0.1`, *Retention*).
//!
//! Every refusal is the code the task declares for it, or the framework's standard code where
//! the conventions say so (§7), so it survives TSP, DIDComm and HTTPS alike as a typed
//! `trust-task-error`.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::specs::vta::witness as spec;
use trust_tasks_rs::{DeclaredErrorCode, RejectReason, TrustTask};
use vti_common::acl::Capability;

use crate::auth::AuthClaims;
use crate::operations::witness::{self as engine, WitnessError};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, require_capability, success_response,
};

/// The task-declared code for each engine refusal a task can reach.
struct Codes {
    not_found: Option<DeclaredErrorCode>,
    credential_mismatch: Option<DeclaredErrorCode>,
    member_link_unsupported: Option<DeclaredErrorCode>,
    witness_unresolvable: Option<DeclaredErrorCode>,
    session_unknown: Option<DeclaredErrorCode>,
    response_invalid: Option<DeclaredErrorCode>,
    vwc_invalid: Option<DeclaredErrorCode>,
}

const NONE: Codes = Codes {
    not_found: None,
    credential_mismatch: None,
    member_link_unsupported: None,
    witness_unresolvable: None,
    session_unknown: None,
    response_invalid: None,
    vwc_invalid: None,
};

/// Answer a refusal with the code the task declares, or the standard one the conventions name.
fn refuse(doc: &TrustTask<Value>, e: WitnessError, codes: &Codes) -> TrustTaskOutcome {
    let message = e.to_string();
    let declared = match &e {
        WitnessError::NotFound(_) => codes.not_found,
        WitnessError::CredentialMismatch(_) => codes.credential_mismatch,
        WitnessError::MemberLinkUnsupported(_) => codes.member_link_unsupported,
        WitnessError::WitnessUnresolvable(_) => codes.witness_unresolvable,
        WitnessError::SessionUnknown => codes.session_unknown,
        WitnessError::ResponseInvalid(_) => codes.response_invalid,
        WitnessError::VwcInvalid(_) => codes.vwc_invalid,
        WitnessError::PermissionDenied(_) => {
            return reject_with(doc, RejectReason::PermissionDenied { reason: message });
        }
        WitnessError::Malformed(_) => {
            return reject_with(doc, RejectReason::MalformedRequest { reason: message });
        }
        WitnessError::App(_) => None,
    };
    match (declared, e) {
        (Some(code), _) => reject_declared(doc, code, message),
        (None, WitnessError::App(a)) => app_error_to_reject(doc, a),
        // A refusal the task declares no code for is a defect in this slice: say so rather
        // than invent a code no consumer can look up.
        (None, _) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} has no code for this refusal: {message}", doc.type_uri),
            },
        ),
    }
}

/// Answer with `value` rendered through the task's generated response type `R`, so a response
/// that drifted from its schema fails here rather than at a consumer.
fn respond<R: DeserializeOwned + Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

async fn audit(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    session_id: &str,
    context: Option<&str>,
    witness: &str,
) {
    let detail = format!("witness {witness}");
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        Some(session_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        context,
        Some(&detail),
    )
    .await
    {
        tracing::warn!(error = %e, action, "audit record failed for a witnessed-party task");
    }
}

async fn gate(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(), TrustTaskOutcome> {
    require_capability(
        state,
        auth,
        doc,
        Capability::WitnessRequest,
        "acting as the principal's witnessed party",
    )
    .await
}

/// `vta/witness/open/0.1`.
pub(super) async fn handle_open(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::open::v0_1 as t;
    if let Err(r) = gate(state, auth, &doc).await {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let membership = p.get("membership");
    let req = engine::OpenRequest {
        witness: str_of(p, "witness").unwrap_or_default(),
        relationship_did: str_of(p, "relationshipDid").unwrap_or_default(),
        counterparty_did: str_of(p, "counterpartyDid").unwrap_or_default(),
        relationship_thread_id: str_of(p, "relationshipThreadId").unwrap_or_default(),
        relationship_credential_id: str_of(p, "relationshipCredentialId").unwrap_or_default(),
        membership_credential_id: membership.and_then(|m| str_of(m, "credentialId")),
        member_did: membership.and_then(|m| str_of(m, "memberDid")),
        store_as: str_of(p, "storeAs"),
    };
    let witness = req.witness.to_string();
    match engine::open(state, auth, req).await {
        Ok(opened) => {
            audit(
                state,
                "witness.open",
                auth,
                &opened.session_id,
                opened.context_id.as_deref(),
                &witness,
            )
            .await;
            respond::<t::Response>(
                &doc,
                json!({
                    "sessionId": opened.session_id,
                    "document": opened.document,
                    "expiresAt": opened.expires_at,
                }),
            )
        }
        Err(e) => refuse(
            &doc,
            e,
            &Codes {
                not_found: Some(t::error_codes::NOT_FOUND),
                credential_mismatch: Some(t::error_codes::CREDENTIAL_MISMATCH),
                member_link_unsupported: Some(t::error_codes::MEMBER_LINK_UNSUPPORTED),
                witness_unresolvable: Some(t::error_codes::WITNESS_UNRESOLVABLE),
                ..NONE
            },
        ),
    }
}

/// `vta/witness/present/0.1`.
pub(super) async fn handle_present(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::present::v0_1 as t;
    if let Err(r) = gate(state, auth, &doc).await {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let session_id = str_of(&doc.payload, "sessionId")
        .unwrap_or_default()
        .to_string();
    // The witness's answer exactly as handed back — never a re-serialisation of a parsed copy.
    let response = doc.payload.get("response").cloned().unwrap_or(Value::Null);
    match engine::present(state, auth, &session_id, &response).await {
        Ok(presented) => {
            audit(
                state,
                "witness.present",
                auth,
                &session_id,
                presented.context_id.as_deref(),
                &presented.witness,
            )
            .await;
            respond::<t::Response>(
                &doc,
                json!({ "sessionId": session_id, "document": presented.document }),
            )
        }
        Err(e) => refuse(
            &doc,
            e,
            &Codes {
                not_found: Some(t::error_codes::NOT_FOUND),
                credential_mismatch: Some(t::error_codes::CREDENTIAL_MISMATCH),
                session_unknown: Some(t::error_codes::SESSION_UNKNOWN),
                response_invalid: Some(t::error_codes::RESPONSE_INVALID),
                ..NONE
            },
        ),
    }
}

/// `vta/witness/accept/0.1`.
pub(super) async fn handle_accept(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::accept::v0_1 as t;
    if let Err(r) = gate(state, auth, &doc).await {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let session_id = str_of(&doc.payload, "sessionId")
        .unwrap_or_default()
        .to_string();
    let response = doc.payload.get("response").cloned().unwrap_or(Value::Null);
    match engine::accept(state, auth, &session_id, &response).await {
        Ok(accepted) => {
            if !accepted.repeated {
                audit(
                    state,
                    "witness.accept",
                    auth,
                    &session_id,
                    accepted.context_id.as_deref(),
                    &accepted.witness,
                )
                .await;
            }
            respond::<t::Response>(
                &doc,
                json!({
                    "sessionId": session_id,
                    "credentialId": accepted.credential_id,
                    "witness": accepted.witness,
                    "vwcDigestMultibase": accepted.vwc_digest_multibase,
                    "evidence": {
                        "session": accepted.session_document,
                        "outcome": accepted.outcome,
                    },
                }),
            )
        }
        Err(e) => refuse(
            &doc,
            e,
            &Codes {
                session_unknown: Some(t::error_codes::SESSION_UNKNOWN),
                response_invalid: Some(t::error_codes::RESPONSE_INVALID),
                vwc_invalid: Some(t::error_codes::VWC_INVALID),
                ..NONE
            },
        ),
    }
}

#[cfg(test)]
#[path = "witness_tests.rs"]
mod tests;
