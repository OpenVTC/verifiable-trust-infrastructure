// Helpers return an owned `TrustTaskOutcome` (status + serialised document
// bytes) rather than the large `Result<_, Response>` the VTA uses — the
// transport adapters render it for REST or DIDComm.
#![allow(clippy::result_large_err)]

//! Shared helpers for the VTC Trust Task dispatcher.
//!
//! The service-agnostic answers — `TrustTaskOutcome`, `reject_with` and its
//! siblings, `success_response`, the unrouted refusals — are
//! `vti_trust_task_server`'s, re-exported here so every handler names them
//! from one place. What stays is the VTC's own:
//!
//! - `app_error_to_reject` — the shared mapping, plus an operation parked for
//!   other administrators' approval answered as a next-step document.
//! - `task_error_to_reject` — a [`TaskError`](crate::error::TaskError),
//!   including the bound step-up refusal.
//! - `next_step_response` / `verdict_response`.
//! - `verify_trust_task_proof` and the as-received verifiers over this
//!   community's DID resolver, and `is_approval_type`.

use axum::http::StatusCode;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;
use vta_sdk::protocols::trust_task_reject_reasons as reasons;
use vti_common::error::AppError;

use crate::server::AppState;

use vta_sdk::protocols::join_requests::VerdictResponse;

pub(crate) use vti_trust_task_server::TrustTaskOutcome;
pub(crate) use vti_trust_task_server::reject::{
    acknowledge, declared_code, error_response, extended_code, framework_error_type_uri,
    parse_payload, reject_with, reject_with_code, reject_with_code_because, success_response,
    unrouted_error_response,
};

/// Map an `AppError` into a routed Trust Task refusal
/// ([`vti_trust_task_server::reject::app_error_to_reject`]), with one VTC
/// addition: an operation parked for other administrators' approval
/// (VTI-APV-017) is not a refusal at all, and is answered with a next-step
/// document. Every gate's caller already propagates its outcome as an
/// `AppError`, so the parked answer rides the same path and is rendered here,
/// once.
pub(crate) fn app_error_to_reject<P>(doc: &TrustTask<P>, err: &AppError) -> TrustTaskOutcome {
    if let AppError::ApprovalRequired { code, details } = err
        && *code == crate::admin_actions::ACTION_PARKED
    {
        return next_step_response(doc, details);
    }
    vti_trust_task_server::reject::app_error_to_reject(doc, err)
}

/// Map a [`TaskError`](crate::error::TaskError) into a routed rejection.
///
/// An undeclared error goes through [`app_error_to_reject`] unchanged. A
/// declared one goes out under its task's extended code (SPEC §8.5) — the
/// thing the generic mapping cannot do, and the reason `withdraw` (#1591) and
/// `supplement` (#1593) each grew a hand-written arm. A `NotFound` /
/// `Conflict` / `Gone` keeps its `details.reason` marker beside the code, so a
/// client that does not know the code still recovers the typed variant.
pub(crate) fn task_error_to_reject<P>(
    doc: &TrustTask<P>,
    err: &crate::error::TaskError,
) -> TrustTaskOutcome {
    use crate::error::TaskError;
    match err {
        TaskError::App(e) => app_error_to_reject(doc, e),
        // The same refusal `settle_signed_gate` answers a grant with.
        TaskError::StepUp { request, .. } => reject_with_code(
            doc,
            trust_tasks_rs::TrustTaskCode::Standard(trust_tasks_rs::StandardCode::PermissionDenied),
            "a passkey gesture bound to this operation is required",
            Some(crate::acl::bound_step_up::refusal_details(request)),
        ),
        TaskError::Declared { code, error } => {
            let message = error.to_string();
            let marker = match error {
                AppError::NotFound(_) => Some(reasons::NOT_FOUND),
                AppError::Conflict(_) | AppError::IdempotencyKeyConflict => Some(reasons::CONFLICT),
                AppError::Gone(_) => Some(reasons::GONE),
                _ => None,
            };
            let code = declared_code(code);
            match marker {
                Some(reason) => reject_with_code_because(doc, code, message, None, reason),
                None => reject_with_code(doc, code, message, None),
            }
        }
    }
}

/// `trust-task-next-step/0.1` — the reserved framework answer (SPEC §8.6) for
/// an operation understood but not completable in isolation: here, one parked
/// in the action list. Addressed back to the requester on the request's
/// thread, like a `#response`, and answered `202 Accepted`: neither a result
/// nor a failure.
pub(crate) fn next_step_response<P>(doc: &TrustTask<P>, details: &Value) -> TrustTaskOutcome {
    let payload =
        crate::admin_actions::next_step_payload(&doc.id, &doc.type_uri.to_string(), details);
    let mut next = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    next.type_uri = super::action_tasks::NEXT_STEP_TYPE
        .parse()
        .expect("the next-step Type URI parses");
    match serde_json::to_vec(&next) {
        Ok(body) => TrustTaskOutcome {
            status: StatusCode::ACCEPTED,
            body,
        },
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("next-step serialisation: {e}"),
            },
        ),
    }
}

/// Convenience wrapper over [`success_response`] for the `request`/`present`
/// verbs, whose response payload is always a [`VerdictResponse`].
pub(crate) fn verdict_response(
    doc: &TrustTask<Value>,
    verdict: VerdictResponse,
) -> TrustTaskOutcome {
    success_response(doc, verdict)
}

/// Verify the holder's `eddsa-jcs-2022` Data-Integrity proof on `doc` and
/// return the proven signer DID — the base DID (before `#`) of the proof's
/// `verificationMethod`.
///
/// Thin adapter over [`vti_common::auth::verify_trust_task_proof`],
/// the single implementation both services share. This used to be a *port* of
/// the VTA's copy; a proof means the same thing at both ends of the mesh, so a
/// second implementation was only ever a chance for the two to disagree. Only
/// the error mapping is local — the join dispatcher renders `AppError`.
///
/// The signature is verified over the document with its `proof` removed
/// (`eddsa-jcs-2022` canonicalises the proofless document via JCS). The
/// returned DID is *proven*, not merely claimed — binding it to an expected
/// identity is the caller's job. `did:key` resolution is local (no network).
///
/// Typed, so it verifies a re-serialisation of `doc`: for a document this
/// service built. A document that arrived over the network is verified as
/// received, with [`verify_received_trust_task_proof`] (VTI-45).
pub(crate) async fn verify_trust_task_proof(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<String, AppError> {
    vti_common::auth::verify_trust_task_proof_with(doc, &state.trust_task_vm_resolver())
        .await
        .map_err(vti_common::auth::proof_refusal)
}

/// [`verify_trust_task_proof`] over the document **as received** — `received`
/// is the JSON the inbound bytes parsed to, unmodified. Only this form sees the
/// members exactly as the producer signed them: a typed `TrustTask` rewrites
/// timestamps (`.000Z`, `+00:00`) and drops `null` optional members, either of
/// which refuses a correctly signed document (VTI-45).
pub(crate) async fn verify_received_trust_task_proof(
    state: &AppState,
    received: &Value,
) -> Result<String, AppError> {
    vti_trust_task_server::verify::verify_received_proof(&state.trust_task_vm_resolver(), received)
        .await
}

/// Verify a human approver's own decision (a `task-consent/decision` or a
/// step-up `approve-response`) — **as received**, see
/// [`verify_received_trust_task_proof`] — and return the proven signer DID.
///
/// [`verify_trust_task_proof`], plus the rule every approval verifier in the
/// mesh holds (the VTA, the did-hosting RP's `verify_approval`): the proof is
/// made for `assertionMethod`, by a key the signer lists under
/// `assertionMethod`. An approval is the approver's attestation, not an
/// operational message, so a proof made for `authentication` is refused. A
/// signer DID that does not resolve is refused, never passed through.
pub(crate) async fn verify_received_approval_proof(
    state: &AppState,
    received: &Value,
    type_uri: &str,
) -> Result<String, AppError> {
    vti_trust_task_server::verify::verify_received_approval_proof(
        &state.trust_task_vm_resolver(),
        received,
        type_uri,
    )
    .await
}

/// Whether `type_uri` is a human approver's own decision, whose proof the
/// spine holds to [`verify_received_approval_proof`] rather than
/// [`verify_trust_task_proof`].
pub(crate) fn is_approval_type(type_uri: &str) -> bool {
    type_uri == super::STEP_UP_APPROVE_RESPONSE_TYPE
        || type_uri == crate::acl::admin_consent::DECISION_TYPE
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The `did:key` for a one-byte test seed, plus the private-key
    /// multibase `vta_sdk::trust_task_sign::build_signed` accepts.
    fn did_key_from_seed(seed_byte: u8) -> (String, String) {
        use ed25519_dalek::SigningKey;
        let seed = [seed_byte; 32];
        let sk = SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        (did, multibase::encode(multibase::Base::Base58Btc, &buf))
    }

    /// This is the join dispatcher's holder-binding check on an
    /// unauthenticated request — one of the ~12 inbound routes FTL-29595 fix
    /// direction 3 must leave byte-identical: a resolver failure and an
    /// actual bad signature must render the same `AppError::Unauthorized`,
    /// or an anonymous caller learns whether a DID resolves at all.
    #[tokio::test]
    async fn a_resolver_failure_and_a_bad_signature_render_identically() {
        let tv = crate::test_support::build_test_vtc().await;

        // Resolver failure: a `did:webvh` verification method against a
        // did:key-only resolver (this test VTC has none configured) —
        // refused before any signature check runs.
        let resolver_fail_doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000020",
            "type": "https://trusttasks.org/spec/acl/list/0.3",
            "issuer": "did:webvh:QmScid:example.com:glenn",
            "recipient": "did:webvh:vtc.example.com:abc",
            "payload": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:webvh:QmScid:example.com:glenn#key-0",
                "created": "2026-01-01T00:00:00Z",
                "proofValue": "z2aBcD"
            }
        }))
        .expect("well-formed document");

        // Bad signature: a real did:key, signed, then corrupted.
        let (signer_did, secret_mb) = did_key_from_seed(31);
        let signed = vta_sdk::trust_task_sign::build_signed(
            "https://trusttasks.org/spec/acl/list/0.3",
            json!({}),
            &signer_did,
            &secret_mb,
            "did:webvh:vtc.example.com:abc",
        )
        .await
        .expect("build a validly-signed document");
        let mut bad_sig_doc: TrustTask<Value> =
            serde_json::from_str(&signed).expect("signed doc parses");
        let proof = bad_sig_doc.proof.as_mut().expect("document is signed");
        let last = proof.proof_value.pop().expect("non-empty proofValue");
        proof.proof_value.push(if last == '1' { '2' } else { '1' });

        let resolver_failure = verify_trust_task_proof(&tv.state, &resolver_fail_doc).await;
        let bad_signature = verify_trust_task_proof(&tv.state, &bad_sig_doc).await;

        match (resolver_failure, bad_signature) {
            (Err(AppError::Unauthorized(a)), Err(AppError::Unauthorized(b))) => {
                assert_eq!(
                    a, b,
                    "a resolver failure must render exactly as a bad signature does"
                );
            }
            other => panic!("expected both to be Unauthorized errors, got {other:?}"),
        }
    }
}
