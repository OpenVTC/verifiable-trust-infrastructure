//! `credential-exchange/request` and `credential-exchange/present` on the spine
//! — the two steps a holder sends the VTC.
//!
//! Issuance runs `offer → request → issue`, presentation `query → present`. Each
//! step is its own Trust Task, and none of the five defines a response document:
//! the counterparty's answer is the **next task in the thread**, which the VTC
//! pushes to the holder over whichever transport it speaks
//! ([`crate::credentials::delivery::push_document`]). What goes back on the
//! transport that carried the step is only the empty `#response` courtesy
//! acknowledgement of SPEC §4.4.2, which the holder must not rely on.
//!
//! These used to be bare DIDComm messages typed as their task URI, answered
//! in-band with a bare DIDComm reply. `bindings/didcomm/0.2` §2 requires a
//! consumer to refuse that carriage, it skipped the spine's proof, freshness,
//! recipient and replay checks, and no other transport could carry it. On the
//! spine they get all of those, over TSP, DIDComm and HTTPS alike.

use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::credential_exchange::{ISSUE, IssueBody, PresentBody, RequestBody};
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, JoinRequestSubmitReceiptBody,
};

use super::JoinAuthCtx;
use super::helpers::{
    TrustTaskOutcome, acknowledge, app_error_to_reject, parse_payload, reject_with,
};
use crate::credentials::delivery::{Thread, push_document};
use crate::server::AppState;

/// The thread a step belongs to: its `threadId`, or — for a step that opens a
/// thread — its own `id`.
fn thread_of(doc: &TrustTask<Value>) -> &str {
    doc.thread_id.as_deref().unwrap_or(&doc.id)
}

/// `credential-exchange/request/0.1` — redeem an offer and push the credential
/// back as `credential-exchange/issue` on the offer's thread.
///
/// What authorizes the release is the OID4VCI key-binding proof inside the
/// request, which [`crate::credentials::redeem`] requires to be by a key of the
/// DID the offer was made for — the credential is bound to that key, never to
/// whoever carried the request (the spec's MUST). The `issue` goes to the
/// proven sender of the request, as the in-band reply it replaces did.
pub(super) async fn handle_request(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let holder_did = match super::resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: RequestBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    let response = match crate::credentials::redeem(
        &state.join_requests_ks,
        &body.credential_request,
        chrono::Utc::now(),
        &crate::credentials::vm_resolver::DidVmResolver::new(state.did_resolver.clone()),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    let issue = IssueBody {
        credential_response: Some(response),
        sealed: None,
    };
    let payload = match serde_json::to_value(&issue) {
        Ok(v) => v,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("issue serialise: {e}"),
                },
            );
        }
    };
    if let Err(e) = push_document(
        state,
        &holder_did,
        ISSUE,
        payload,
        Thread::Reply(thread_of(&doc)),
    )
    .await
    {
        return app_error_to_reject(&doc, &e);
    }
    acknowledge(&doc)
}

/// `credential-exchange/present/0.1` — the holder's answer to a join query:
/// verify the presentation against the single-use challenge the query opened,
/// decide the join, deliver any credentials an auto-admit earned to the proven
/// holder, and push the `join-requests/submit-receipt` on the query's thread to
/// whoever sent the present.
pub(super) async fn handle_present(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Whoever sent the present hears the outcome; the credentials an admit
    // earns go to the holder the presentation proved. They differ when a
    // relayer carries the present for the holder.
    let sender_did = match super::resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: PresentBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // The present answers the query, whose id is the thread the challenge is
    // keyed by. A present that names no thread cannot be matched to one.
    let Some(thread_id) = doc.thread_id.clone() else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "present carries no threadId to correlate its challenge".into(),
            },
        );
    };

    let now = chrono::Utc::now();
    let challenge = match crate::credentials::present_challenge::consume(
        &state.join_requests_ks,
        &thread_id,
        now,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    let outcome = match crate::routes::join_requests::present::present_and_decide_join(
        state,
        &body.vp_token,
        &challenge.aud,
        &challenge.nonce,
        // The same thread the challenge was keyed by: the exchange every
        // presented credential's `taskContext` is resolved against.
        &thread_id,
        ctx.transport,
        now,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let applicant_did = outcome.request.applicant_did.clone();

    // On auto-admit, deliver the issued MembershipCredential (+ role VAC) to the
    // proven holder — the receipt below says only that the request was decided,
    // so without this the credential it just earned would never reach it.
    // Best-effort: the credential is already issued + persisted, so a delivery
    // failure is logged (the holder/admin can re-fetch), not fatal.
    if let Some(admit) = outcome.admit.as_deref() {
        if let Err(e) = crate::credentials::delivery::deliver_membership_credentials(
            state,
            &applicant_did,
            admit,
        )
        .await
        {
            tracing::warn!(holder = %applicant_did, request = %outcome.request.id, error = %e, "membership-credential delivery failed; credential is issued and can be re-delivered");
        } else {
            tracing::info!(holder = %applicant_did, request = %outcome.request.id, "queued membership credentials for delivery to holder");
        }
    }

    let status = serde_json::to_value(outcome.request.status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let receipt = JoinRequestSubmitReceiptBody {
        request_id: outcome.request.id,
        status,
    };
    let payload = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("receipt serialise: {e}"),
                },
            );
        }
    };
    // The join is decided whatever happens to the receipt, so a push failure is
    // not a failure of the present: the holder can ask `join-requests/status`.
    if let Err(e) = push_document(
        state,
        &sender_did,
        JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
        payload,
        Thread::Reply(&thread_id),
    )
    .await
    {
        tracing::warn!(to = %sender_did, error = %e, "submit receipt could not be queued; the join is decided and join-requests/status reports it");
    }
    acknowledge(&doc)
}
