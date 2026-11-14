//! The join-request verbs (`vtc/join-requests/*`: submit, manifest, status,
//! supplement, withdraw, decide) and a member's own leave.
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::routing::{Routes, on};
use super::*;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, vti_specs::vtc::join_requests::submit::v0_3::Payload => handle_submit);
    let routes =
        on!(routes, vti_specs::vtc::join_requests::manifest::v0_4::Payload => handle_manifest);
    let routes = on!(routes, vti_specs::vtc::join_requests::status::v0_1::Payload => handle_status);
    let routes =
        on!(routes, vti_specs::vtc::join_requests::withdraw::v0_1::Payload => handle_withdraw);
    let routes =
        on!(routes, vti_specs::vtc::join_requests::supplement::v0_1::Payload => handle_supplement);
    let routes =
        on!(routes, vti_specs::vtc::members::self_remove::v0_1::Payload => handle_self_remove);
    on!(routes, vti_specs::vtc::join_requests::decide::v0_1::Payload => handle_join_decide)
}

// ─── submit / request ────────────────────────────────────────────────────

pub(super) async fn handle_submit(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: JoinRequestSubmitBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    // Both transports authenticate the holder (REST proof / DIDComm sender)
    // and bind audience + freshness via the document recipient + expiry, so
    // the spine runs with no separate holder-binding signature.
    let outcome = match crate::join::submit_inner(
        state,
        applicant_did,
        body.vp,
        body.registry_consent,
        body.extensions,
        body.attributes
            .into_iter()
            .map(|a| crate::join::SubmittedAttribute {
                r#type: a.claim_type,
                value: a.value,
            })
            .collect(),
        body.criterion,
        None,
        ctx.transport,
    )
    .await
    {
        Ok(o) => o,
        // The applicant already has an open request. Answered as a typed code
        // with a machine-readable annex rather than the bare `taskFailed` the
        // generic mapping would produce: the whole defect Keyring reported
        // (VTI-04) was that a client could not tell this apart from any other
        // submit failure, nor learn which request was in the way, without
        // parsing English prose.
        //
        // `vtc/join-requests/submit` declares no code for this, so the code is
        // consumer-minted under the slug of the request being processed, which
        // SPEC.md §8.5 permits explicitly. A client that does not recognise it
        // falls back to `taskFailed` by the same section's rule, so this is
        // additive for every existing caller.
        Err(crate::join::SubmitRefusal::AlreadyOpen { request_id, status }) => {
            let refusal = crate::join::SubmitRefusal::AlreadyOpen { request_id, status };
            return reject_with_code_because(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_REQUEST_ALREADY_OPEN),
                AppError::from(refusal).to_string(),
                Some(serde_json::json!({
                    "requestId": request_id.to_string(),
                    "status": status.to_string(),
                })),
                reasons::CONFLICT,
            );
        }
        // A current member applying again. Consumer-minted beside
        // `requestAlreadyOpen`, for the same reason: a client must be able to
        // tell "sign in instead" from every other refusal without parsing prose.
        Err(crate::join::SubmitRefusal::AlreadyMember) => {
            return reject_with_code_because(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_ALREADY_MEMBER),
                AppError::from(crate::join::SubmitRefusal::AlreadyMember).to_string(),
                None,
                reasons::CONFLICT,
            );
        }
        // The specification's own codes, with the types in `details`, so a
        // client can ask the applicant for exactly what is missing — or drop
        // exactly what it over-shared — without parsing a sentence.
        Err(crate::join::SubmitRefusal::AttributesMissing(types)) => {
            let details = serde_json::json!({ "types": types });
            return reject_with_code(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_ATTRIBUTES_MISSING),
                AppError::from(crate::join::SubmitRefusal::AttributesMissing(types)).to_string(),
                Some(details),
            );
        }
        Err(crate::join::SubmitRefusal::AttributesUnrequested(types)) => {
            let details = serde_json::json!({ "types": types });
            return reject_with_code(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_ATTRIBUTES_UNREQUESTED),
                AppError::from(crate::join::SubmitRefusal::AttributesUnrequested(types))
                    .to_string(),
                Some(details),
            );
        }
        Err(crate::join::SubmitRefusal::PresentationInvalid(reason)) => {
            return reject_with_code(
                &doc,
                extended_code(SUBMIT_ERR_PRESENTATION_INVALID),
                reason,
                None,
            );
        }
        // The community's criteria are its join rules; with none published it
        // accepts nobody, and says so rather than queueing what it will never
        // decide.
        Err(crate::join::SubmitRefusal::NotAccepting) => {
            return reject_with_code(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_NOT_ACCEPTING),
                AppError::from(crate::join::SubmitRefusal::NotAccepting).to_string(),
                None,
            );
        }
        Err(crate::join::SubmitRefusal::CriterionUnknown(digest)) => {
            let details = serde_json::json!({ "criterion": digest });
            return reject_with_code(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_CRITERION_UNKNOWN),
                AppError::from(crate::join::SubmitRefusal::CriterionUnknown(digest)).to_string(),
                Some(details),
            );
        }
        Err(crate::join::SubmitRefusal::Challenge(r)) => {
            return challenge_reject(
                &doc,
                crate::vetting::challenge_refusal::ChallengeTask::Submit,
                &r,
            );
        }
        Err(crate::join::SubmitRefusal::Other(e)) => return app_error_to_reject(&doc, &e),
    };

    match outcome_to_verdict(&outcome) {
        Ok(v) => verdict_response(&doc, v),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// A refused hidden-vetting challenge, answered under its own code.
///
/// Until these codes existed every way a challenge could fail went out as one
/// `malformedRequest`, and a client could not tell an applicant whether they
/// had simply taken too long or were sending a proof built over the wrong
/// challenge. Neither `submit` nor `supplement` declares a code for it, so the
/// codes are consumer-minted under the task's own slug (SPEC §8.5, as
/// `requestAlreadyOpen` is), with the generic `details.reason` marker beside
/// them for a client that does not know the code, and `expiredAt` for an
/// expired one. The message never carries the challenge value.
pub(super) fn challenge_reject<P>(
    doc: &TrustTask<P>,
    task: crate::vetting::challenge_refusal::ChallengeTask,
    refusal: &crate::vetting::challenge_refusal::ChallengeRefusal,
) -> TrustTaskOutcome {
    reject_with_code_because(
        doc,
        extended_code(refusal.code(task)),
        refusal.to_string(),
        refusal.details(),
        refusal.marker(),
    )
}

/// Map the ceremony spine's [`JoinSubmitOutcome`] onto the wire
/// [`VerdictResponse`]. Auto-admit → `allow` (credentials inline);
/// `Pending` → `refer`; `Deferred` → `request_more`; `Rejected` → `deny`.
pub(super) fn outcome_to_verdict(outcome: &JoinSubmitOutcome) -> Result<VerdictResponse, AppError> {
    use crate::ceremony::verdict::Verdict as PolicyVerdict;

    let request_id = outcome.request.id;

    if let Some(admit) = &outcome.admit {
        let role = outcome
            .request
            .policy_decision
            .clone()
            .and_then(|pd| serde_json::from_value::<PolicyVerdict>(pd).ok())
            .and_then(|v| match v {
                PolicyVerdict::Allow(a) => a.role,
                _ => None,
            });
        let vmc = serde_json::to_value(&admit.vmc)
            .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?;
        let role_vac = serde_json::to_value(&admit.role_vac)
            .map_err(|e| AppError::Internal(format!("serialise role VAC: {e}")))?;
        return Ok(VerdictResponse::allow(
            request_id,
            role,
            Some(vmc),
            Some(role_vac),
        ));
    }

    // No auto-admit: shape the verdict from the persisted decision.
    let decision = outcome
        .request
        .policy_decision
        .clone()
        .and_then(|pd| serde_json::from_value::<PolicyVerdict>(pd).ok());

    let verdict = match decision {
        Some(PolicyVerdict::RequestMore(rm)) => VerdictResponse {
            request_id,
            verdict: jr::Verdict {
                effect: jr::VerdictEffect::RequestMore,
                with: jr::VerdictWith {
                    needs: rm.needs,
                    presentation_definition: Some(rm.presentation_definition),
                    ..Default::default()
                },
            },
        },
        Some(PolicyVerdict::Deny(d)) => VerdictResponse::deny(request_id, d.code, d.reason),
        Some(PolicyVerdict::Refer(r)) => {
            VerdictResponse::refer(request_id, r.queue, r.reason.unwrap_or_default())
        }
        // A `Pending` request with an `Allow`/absent decision (no auto-admit
        // path) is still queued for an admin: surface as `refer`.
        _ => VerdictResponse::refer(
            request_id,
            "admin-review",
            "queued for an admin decision (approve/reject)",
        ),
    };
    Ok(verdict)
}

// ─── manifest (public by default) ──────────────────────────────────────────

/// Whether this caller is one the community can name.
///
/// Either proof of identity will do, because the two transports prove it
/// differently and both are real: over REST a signed document names its signer
/// (`verified_signer`), over DIDComm the authcrypt envelope names its sender
/// (`sender_did`). Requiring the REST form on a DIDComm caller — or the reverse
/// — would refuse a party the transport has already identified.
pub(super) fn caller_is_identified(ctx: &JoinAuthCtx) -> bool {
    ctx.verified_signer.is_some() || ctx.sender_did.is_some()
}

/// The join manifest (`vtc/join-requests/manifest/0.4`), with the directory's
/// disclosure statement.
///
/// Public unless the community has turned public discovery off — see
/// [`discovery_refusal`].
pub(super) async fn handle_manifest(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use vta_sdk::protocols::join_requests::manifest::v0_4;
    if let Err(reject) = parse_spec_payload::<v0_4::Payload>(&doc) {
        return reject;
    }
    if let Some(refusal) = discovery_refusal(state, ctx, &doc).await {
        return refusal;
    }
    crate::routes::join_requests::manifest::manifest(state)
        .await
        .map(|r| success_response(&doc, r))
        .unwrap_or_else(|e| app_error_to_reject(&doc, &e))
}

/// The refusal for an unidentified caller when the community has turned public
/// discovery off, else `None`.
///
/// Shared by everything an applicant reads before applying — the join manifest
/// and the directory's disclosure statement — so that a reader who may see the
/// one may see the other: the statement is part of what an applicant is told
/// before they apply (VTI-DIR-130). An identified caller is answered exactly as
/// before — see [`JoinDiscovery`](crate::community::profile::JoinDiscovery).
/// The refusal is `permissionDenied` with a sentence saying *how* to ask rather
/// than only that this failed: a client that reads "not public" and stops has
/// been told the wrong thing, because the same question over an identified
/// transport still answers.
pub(super) async fn discovery_refusal(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Option<TrustTaskOutcome> {
    if caller_is_identified(ctx) {
        return None;
    }
    let public =
        match crate::community::join_discovery::load_join_discovery(&state.community_ks).await {
            Ok(setting) => setting.public,
            // A setting that cannot be read is not a reason to stop answering a
            // question that has always been public: failing open keeps a storage
            // fault from looking like a closed community, and what these reads
            // carry was already published.
            Err(e) => {
                tracing::warn!(error = %e, "join discovery unreadable; answering the read");
                true
            }
        };
    (!public).then(|| {
        reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: "this community does not publish its join requirements to callers \
                         it cannot identify — ask over DIDComm, or with a signed Trust Task \
                         document"
                    .to_string(),
            },
        )
    })
}

// ─── status ────────────────────────────────────────────────────────────────

pub(super) async fn handle_status(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: JoinRequestStatusBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    // No `requestId` means "what is my open request?" — the applicant is already
    // authenticated by the authcrypt sender, and at most one request per
    // applicant is open (the submit dedup), so the community can resolve it.
    //
    // This is the only form of the poll available to an applicant whose first
    // correlated reply was lost: the id it would otherwise quote is the
    // community's, learned from that reply, so it holds nothing this VTC
    // recognises. The response carries `requestId`, so answering once also
    // repairs the applicant's record for every later poll.
    let result = match body.request_id {
        Some(request_id) => {
            crate::routes::join_requests::status::status_inner(
                state,
                request_id,
                applicant_did,
                body.resend_credentials,
            )
            .await
        }
        None => {
            crate::routes::join_requests::status::status_by_applicant(
                state,
                applicant_did,
                body.resend_credentials,
            )
            .await
        }
    };

    match result {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── members ─────────────────────────────────────────────────────────────

/// `members/self-remove/0.1` as a Trust Task document — the member-initiated
/// leave (R-L-1).
///
/// Actor == subject, and the leave policy allows self-leave unconditionally
/// (spec §10.2) with the no-last-admin invariant still enforced in the effect
/// stage. A member performs it over any transport this dispatcher serves —
/// over DIDComm, in the binding envelope.
///
/// The bare-body DIDComm handler that predated this (typed as the task, with
/// none of the spine's freshness, recipient or proof checks) was retired for
/// Keyring VTI-42; this is now the only path.
/// `vtc/join-requests/supplement/0.1` — the applicant answers the community's
/// request for more evidence, against the request they already have open.
///
/// Holder-bound like `withdraw`: [`resolve_holder`] proves the caller, and
/// that proven identity is the authorization, because ownership of the request
/// is the entitlement and an applicant holds nothing else to check.
///
/// The success path deliberately runs through [`outcome_to_verdict`] and
/// [`verdict_response`] — submit's own — because a supplement's response *is*
/// submit's response. A second projection here would be a second place for the
/// four verdict effects to be rendered, and they would drift.
pub(super) async fn handle_supplement(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::join::SupplementRefusal;

    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: jr::supplement::v0_1::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    let request_id = match body.request_id.as_ref().map(|r| uuid::Uuid::parse_str(r)) {
        None => None,
        Some(Ok(id)) => Some(id),
        Some(Err(e)) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("requestId is not a UUID: {e}"),
                },
            );
        }
    };

    let outcome = match crate::join::supplement_inner(
        state,
        &applicant_did,
        request_id,
        Value::Object(body.vp.clone()),
        Value::Object(body.extensions.clone()),
        ctx.transport,
    )
    .await
    {
        Ok(o) => o,
        // All three are spec-declared, so each goes out as itself. The generic
        // mapping would flatten them into one `taskFailed`, and "nothing to
        // supplement", "nothing has been asked of you" and "already decided"
        // are three different things for an applicant to do next.
        Err(e @ SupplementRefusal::NotFound(_)) => {
            return reject_with_code_because(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUPPLEMENT_ERR_NOT_FOUND),
                AppError::from(e).to_string(),
                None,
                reasons::NOT_FOUND,
            );
        }
        Err(SupplementRefusal::NotAwaitingEvidence { request_id, status }) => {
            let refusal = SupplementRefusal::NotAwaitingEvidence { request_id, status };
            return reject_with_code_because(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUPPLEMENT_ERR_NOT_AWAITING_EVIDENCE),
                AppError::from(refusal).to_string(),
                Some(serde_json::json!({
                    "requestId": request_id.to_string(),
                    "status": status.to_string(),
                })),
                reasons::CONFLICT,
            );
        }
        Err(SupplementRefusal::AlreadyDecided { request_id, status }) => {
            let refusal = SupplementRefusal::AlreadyDecided { request_id, status };
            return reject_with_code_because(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUPPLEMENT_ERR_ALREADY_DECIDED),
                AppError::from(refusal).to_string(),
                Some(serde_json::json!({
                    "requestId": request_id.to_string(),
                    "status": status.to_string(),
                })),
                reasons::GONE,
            );
        }
        Err(SupplementRefusal::Challenge(r)) => {
            return challenge_reject(
                &doc,
                crate::vetting::challenge_refusal::ChallengeTask::Supplement,
                &r,
            );
        }
        Err(SupplementRefusal::Other(e)) => return app_error_to_reject(&doc, &e),
    };

    match outcome_to_verdict(&outcome) {
        Ok(v) => verdict_response(&doc, v),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/join-requests/withdraw/0.1` — the applicant closes their own request.
///
/// Holder-bound like `self-remove`: [`resolve_holder`] proves the caller
/// (authcrypt sender on DIDComm, document proof signer on REST) and refuses a
/// document whose `issuer` names anyone else. That proven identity *is* the
/// authorization — the spec's entitlement is ownership of the request, and an
/// applicant holds no membership or capability to check instead.
pub(super) async fn handle_withdraw(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: jr::withdraw::v0_1::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    // Every member is optional, so an empty payload is the common case: the
    // proven caller identifies the applicant and at most one request is open.
    let request_id = match body.request_id.as_ref().map(|r| uuid::Uuid::parse_str(r)) {
        None => None,
        Some(Ok(id)) => Some(id),
        Some(Err(e)) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("requestId is not a UUID: {e}"),
                },
            );
        }
    };

    match crate::join::orchestrate::withdraw_inner(
        state,
        &applicant_did,
        request_id,
        body.reason.as_ref().map(|r| r.to_string()),
    )
    .await
    {
        Ok(request) => {
            // Built through the generated builder rather than a JSON literal,
            // so the response cannot drift from the schema that defines it.
            let response = match jr::withdraw::v0_1::Response::builder()
                .request_id(request.id.to_string())
                .status(jr::withdraw::v0_1::ResponseStatus::Withdrawn)
                .try_into()
            {
                Ok(r) => r,
                Err(e) => {
                    return reject_with(
                        &doc,
                        RejectReason::InternalError {
                            reason: format!("withdraw response failed its own schema: {e}"),
                        },
                    );
                }
            };
            success_response::<_, jr::withdraw::v0_1::Response>(&doc, response)
        }
        // The spec declares both of these, so they go out as themselves. The
        // generic `app_error_to_reject` would flatten each into a bare
        // `taskFailed` carrying only English, which is precisely what an
        // applicant's client cannot branch on — and telling "nothing to
        // withdraw" apart from "already decided" is the whole point of
        // declaring two codes.
        Err(e @ AppError::NotFound(_)) => reject_with_code_because(
            &doc,
            extended_code(jr::JOIN_REQUEST_WITHDRAW_ERR_NOT_FOUND),
            e.to_string(),
            None,
            reasons::NOT_FOUND,
        ),
        Err(e @ AppError::Gone(_)) => reject_with_code_because(
            &doc,
            extended_code(jr::JOIN_REQUEST_WITHDRAW_ERR_ALREADY_DECIDED),
            e.to_string(),
            None,
            reasons::GONE,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

pub(super) async fn handle_self_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: jr::SelfRemoveBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let disposition = match body
        .disposition
        .as_deref()
        .map(crate::messaging::parse_disposition)
        .transpose()
    {
        Ok(d) => d,
        Err(reason) => return reject_with(&doc, RejectReason::MalformedRequest { reason }),
    };

    match crate::ceremony::orchestrate::remove_inner(
        state,
        &member_did,
        &member_did,
        disposition,
        String::new(),
        // A self-leave: nobody else's authority ends, so nothing to bind.
        None,
    )
    .await
    {
        Ok(outcome) => success_response(
            &doc,
            jr::SelfRemoveReceiptBody {
                did: outcome.did,
                disposition: outcome.disposition,
                removed: outcome.removed,
            },
        ),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the join decision + the community profile (#1641 phase 2, batch 2) ──

/// `vtc/join-requests/decide/0.1` — admit or refuse a pending applicant.
///
/// Administrator only, read from the signer's ACL entry — the same
/// `VtcRole::Admin` the REST route's `AdminAuth` demanded, and the only gate
/// that route applies. There is no context scoping on either door: a VTC
/// community is one scope, and a join request belongs to the community rather
/// than to a context within it.
///
/// # Why the double-issue this task could suffer is already closed
///
/// Approving issues a membership credential and a role endorsement. Executed
/// twice, it issues two of each — and a redelivery from the mediator is the
/// routine case, not an attack (SPEC §7.2 item 11). The spine claims the
/// document's `id` **before** dispatching here and settles it after, so a
/// redelivery is answered with the *recorded* response and never reaches this
/// function. That is the ordering §6a of the design note requires, and it is
/// why this arm is not the place to add an idempotency check of its own: a
/// check-then-act at the handler is the TOCTOU the claim exists to close.
///
/// The `notPending` refusal is a second line rather than that guard. It
/// catches a *second, different* decision document aimed at a request already
/// decided — which is a conflict the operator should see, not a duplicate to
/// absorb.
pub(super) async fn handle_join_decide(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor =
        match capable_signer(state, ctx, &doc, crate::acl::Capability::JoinDecide, None).await {
            Ok(a) => a,
            Err(reject) => return reject,
        };
    let checked: join_decide::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // The REST route takes the request id as a typed path segment; here it
    // rides the payload as a string, so the parse is this arm's to make. A
    // non-UUID id never named a request, so it is a malformed payload rather
    // than the task's declared `notFound` — which would tell an operator a
    // request had been deleted when what they sent was not an id at all.
    let id = match uuid::Uuid::parse_str(checked.id.as_str()) {
        Ok(id) => id,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                &AppError::Validation(format!("`id` is not a join-request id: {e}")),
            );
        }
    };
    let decision = match &checked.decision {
        join_decide::PayloadDecision::Approved => {
            crate::routes::join_requests::decide::Decision::Approved
        }
        join_decide::PayloadDecision::Rejected => {
            crate::routes::join_requests::decide::Decision::Rejected
        }
        // `PayloadDecision` is `#[non_exhaustive]`, so a later registry version
        // may add an outcome this build has no handling for. Refusing is the
        // only honest answer: mapping an unknown decision onto either of the
        // two known ones would admit or foreclose an applicant on a decision
        // nobody made.
        other => {
            return app_error_to_reject(
                &doc,
                &AppError::Validation(format!("unsupported `decision`: {other}")),
            );
        }
    };
    let body = crate::routes::join_requests::decide::DecideBody {
        decision,
        reason: checked.reason.as_ref().map(|r| r.as_str().to_string()),
    };
    match crate::routes::join_requests::decide::decide_inner(
        state,
        &actor.did,
        ctx.transport.as_str(),
        id,
        body,
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

#[cfg(test)]
mod join_discovery_tests {
    //! The predicate the manifest gate rests on.
    use super::*;

    fn ctx(sender: Option<&str>, signer: Option<&str>) -> JoinAuthCtx {
        JoinAuthCtx {
            transport: JoinTransport::Rest,
            sender_did: sender.map(str::to_string),
            verified_signer: signer.map(str::to_string),
        }
    }

    /// Both transports prove who is asking, in their own way, and either is
    /// enough. Requiring the REST form of the proof from a DIDComm caller
    /// would refuse a party the envelope already named.
    #[test]
    fn either_transports_proof_of_who_is_asking_counts() {
        assert!(caller_is_identified(&ctx(None, Some("did:key:zSigner"))));
        assert!(caller_is_identified(&ctx(Some("did:peer:sender"), None)));
        assert!(caller_is_identified(&ctx(
            Some("did:peer:sender"),
            Some("did:key:zSigner")
        )));
    }

    /// The anonymous read — no signature, no envelope — is the only one the
    /// setting can turn off, and the only one it needs to.
    #[test]
    fn a_caller_that_proves_nothing_is_unidentified() {
        assert!(!caller_is_identified(&ctx(None, None)));
    }
}

/// The join decision and the community-profile edit, served as signed Trust
/// Task documents — **#1641 phase 2, batch 2**.
///
/// `vtc/join-requests/decide/0.1` and `vtc/community/profile/update/0.1` both
/// declare `proof` REQUIRED and were served only as flat-payload REST behind a
/// bearer JWT. They are now bound here as well, on batch 1's terms.
///
/// What these tests hold beyond batch 1's, and why:
///
/// - **`decide` has a consequence a replay would duplicate.** Approving issues
///   a membership credential and a role endorsement, so a decision executed
///   twice issues two of each — the first migrated verb where a second
///   execution is materially wrong rather than merely redundant.
///   `vti_ops_025_a_replayed_decision_does_not_issue_a_second_credential`
///   drives the redelivery through the issuance path and checks the credential
///   the member ends up holding, not only the reply.
/// - **The gate each bearer route applied must still refuse what it refused.**
///   Both routes apply exactly `AdminAuth` and nothing further — no
///   super-admin bar, no context scoping — so the tests hold that shape: a
///   member is refused, a context-scoped admin is *not*.
/// - **The `#response` schema.** Both arms answer with the route's own
///   response struct, so a drift from the published schema would be invisible
///   until a client hit it; the document endpoint does not carry the
///   router-level `response_conformance` layer that covers the REST doors.
#[cfg(test)]
mod join_decide_profile_tests {
    use super::*;
    use crate::acl::VtcRole;
    use crate::community::{CommunityProfile, load_profile, store_profile};
    use crate::join::{JoinRequest, JoinStatus, get_join_request, store_join_request};
    use crate::members::get_member;
    use crate::test_support::{TEST_VTC_DID, TestVtc};
    use crate::trust_tasks::test_fixtures::{
        assert_conforms, dispatch, error_code, payload_of, seed_acl, sign, signed, unsigned,
    };
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    const APPLICANT: &str = "did:key:zApplicant";
    const PUBLIC_URL: &str = "https://vtc.example.com";

    struct Fixture {
        vtc: TestVtc,
        /// `VtcRole::Admin`, unrestricted.
        admin: Party,
        /// `VtcRole::Admin` scoped to one context. Still an administrator —
        /// neither of these verbs asks the super-admin question, so this
        /// caller must be admitted, and a gate copied one notch too tight is
        /// as much a regression as one copied too loose.
        scoped_admin: Party,
        /// `VtcRole::Member` — authenticated, authorized for none of this.
        member: Party,
    }

    async fn fixture() -> Fixture {
        // `with_audit` because both verbs refuse rather than act when they
        // cannot record what they did; `with_signers` because approving mints
        // a VMC and a role VAC, and the spine signs its replies;
        // `with_public_url` because the credentials name the status list by
        // URL.
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .with_public_url(PUBLIC_URL)
            .build()
            .await;
        crate::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .expect("install default policies");
        // Both status lists, as `server::run` seeds them at boot: approving
        // allocates a slot in each, and an unseeded list fails the issuance
        // as an internal error rather than as anything a caller could read.
        for purpose in [
            affinidi_status_list::StatusPurpose::Revocation,
            affinidi_status_list::StatusPurpose::Suspension,
        ] {
            crate::status_list::ensure_initial(
                &vtc.state.status_lists_ks,
                purpose,
                format!("{PUBLIC_URL}/v1/status-lists/{purpose}"),
            )
            .await
            .expect("seed the status list");
        }
        store_profile(
            &vtc.state.community_ks,
            &CommunityProfile::new(TEST_VTC_DID, "Example Community"),
        )
        .await
        .expect("seed the community profile");

        let admin = Party::new();
        let scoped_admin = Party::new();
        let member = Party::new();
        seed_acl(&vtc, &admin.did, VtcRole::Admin, vec![]).await;
        seed_acl(
            &vtc,
            &scoped_admin.did,
            VtcRole::Admin,
            vec!["ctx-a".to_string()],
        )
        .await;
        seed_acl(&vtc, &member.did, VtcRole::Member, vec![]).await;

        Fixture {
            vtc,
            admin,
            scoped_admin,
            member,
        }
    }

    /// A pending join request from `APPLICANT`, ready to be decided.
    async fn pending_request(vtc: &TestVtc) -> uuid::Uuid {
        let req = JoinRequest::new(APPLICANT, json!({}));
        let id = req.id;
        store_join_request(&vtc.state.join_requests_ks, &req)
            .await
            .expect("seed a pending join request");
        id
    }

    // ─── the premise ─────────────────────────────────────────────────────

    /// If the registry ever relaxed one of these declarations, every test
    /// below would be asserting nothing. This one says so first.
    #[test]
    fn every_moved_task_declares_the_proof_these_tests_assume() {
        for uri in [JOIN_DECIDE_TYPE, COMMUNITY_PROFILE_UPDATE_TYPE] {
            let policy = vti_specs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
            assert!(
                policy.is_proof_required,
                "{uri} no longer declares proof REQUIRED — these tests now assert \
                 nothing, and the design note should be re-read"
            );
        }
    }

    // ─── VTI-OPS-020: a proof by the issuer, authorized from their ACL ────

    /// **VTI-OPS-020.** A signed admin document admits the applicant, and the
    /// reply is the task's own response shape.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_approves_a_join_request() {
        let fix = fixture().await;
        let id = pending_request(&fix.vtc).await;

        let doc = signed(
            &fix.admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": id.to_string(), "decision": "approved" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "a signed admin document must be accepted: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["requestId"], id.to_string());
        assert_eq!(payload_of(&out)["status"], "approved");
        assert!(
            payload_of(&out)["vmc"].is_object(),
            "approval delivers the membership credential inline"
        );
        assert_conforms::<join_decide::Response>(&out);

        let member = get_member(&fix.vtc.state.members_ks, APPLICANT)
            .await
            .expect("read member")
            .expect("the applicant is now a member");
        assert!(member.current_vmc_id.is_some());
    }

    /// **VTI-OPS-020.** A signed admin document edits the community profile,
    /// and the reply conforms to the published `#response`.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_updates_the_profile() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "name": "Renamed Community", "description": "A better blurb." }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["profile"]["name"], "Renamed Community");
        assert_conforms::<community_profile_update::Response>(&out);

        let stored = load_profile(&fix.vtc.state.community_ks)
            .await
            .expect("read profile")
            .expect("row");
        assert_eq!(stored.name, "Renamed Community");
        assert_eq!(stored.description, "A better blurb.");
    }

    /// **VTI-OPS-020.** The same documents with their proofs stripped are
    /// refused with the framework's own code, and nothing happens.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_admin_document_is_refused() {
        let fix = fixture().await;
        let id = pending_request(&fix.vtc).await;

        for (uri, payload) in [
            (
                JOIN_DECIDE_TYPE,
                json!({ "id": id.to_string(), "decision": "approved" }),
            ),
            (COMMUNITY_PROFILE_UPDATE_TYPE, json!({ "name": "Hijacked" })),
        ] {
            let doc = unsigned(&fix.admin, uri, payload);
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{uri}: SPEC §7.2 item 7 names the code: {}",
                String::from_utf8_lossy(&out.body)
            );
        }

        assert_eq!(
            get_join_request(&fix.vtc.state.join_requests_ks, id)
                .await
                .expect("read request")
                .expect("row")
                .status,
            JoinStatus::Pending,
            "an unsigned decision must not have decided anything"
        );
        assert_eq!(
            load_profile(&fix.vtc.state.community_ks)
                .await
                .expect("read profile")
                .expect("row")
                .name,
            "Example Community",
        );
    }

    /// Authorization is the **signer's ACL entry**, not a bearer token: a
    /// correctly signed document from a member is refused, which is what
    /// `AdminAuth` refused on both REST routes.
    #[tokio::test]
    async fn a_non_admin_signer_is_refused_both_verbs() {
        let fix = fixture().await;
        let id = pending_request(&fix.vtc).await;

        for (uri, payload) in [
            (
                JOIN_DECIDE_TYPE,
                json!({ "id": id.to_string(), "decision": "approved" }),
            ),
            (COMMUNITY_PROFILE_UPDATE_TYPE, json!({ "name": "Hijacked" })),
        ] {
            let doc = signed(&fix.member, uri, payload).await;
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{uri}: a member is not an administrator: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
        assert!(
            get_member(&fix.vtc.state.members_ks, APPLICANT)
                .await
                .expect("read member")
                .is_none(),
            "the refused decision must not have admitted anybody"
        );
    }

    /// A DID with **no ACL row at all** is refused the same way — the
    /// signature verifies, and verifying a signature is not authorization.
    #[tokio::test]
    async fn a_signer_with_no_acl_row_is_refused() {
        let fix = fixture().await;
        let stranger = Party::new();
        let doc = signed(
            &stranger,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "name": "Hijacked" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    /// **Each verb takes its own capability** (`vtc-admin-roles.md` §4): a
    /// moderator holds `vtc.join.decide` and decides, and does not hold
    /// `vtc.surface.admin`, so it may not edit the profile.
    #[tokio::test]
    async fn a_moderator_may_decide_and_may_not_edit_the_profile() {
        let fix = fixture().await;
        let id = pending_request(&fix.vtc).await;

        let doc = signed(
            &fix.scoped_admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": id.to_string(), "decision": "rejected", "reason": "not this time" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "a moderator holds vtc.join.decide: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["status"], "rejected");

        let doc = signed(
            &fix.scoped_admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "name": "Scoped Rename" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "the profile takes vtc.surface.admin: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    // ─── the operations' own refusals ────────────────────────────────────

    /// The declared `notFound`, carried as a code rather than flattened into
    /// `taskFailed` — the same code the REST route puts in its body.
    #[tokio::test]
    async fn an_unknown_request_is_the_declared_not_found() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": uuid::Uuid::new_v4().to_string(), "decision": "approved" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::routes::join_requests::decide::DECIDE_ERR_NOT_FOUND),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// An `id` that is not a join-request id is a **malformed payload**, not
    /// the declared `notFound`. Answering `notFound` would tell an operator a
    /// request had been deleted when what they sent was never an id.
    #[tokio::test]
    async fn an_id_that_is_not_an_id_is_malformed_not_not_found() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": "not-a-uuid", "decision": "approved" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some("malformedRequest"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// A *second, different* decision aimed at an already-decided request is
    /// the declared `notPending`. This is not the duplicate guard — it is the
    /// conflict an operator should see.
    #[tokio::test]
    async fn a_second_decision_on_a_decided_request_is_not_pending() {
        let fix = fixture().await;
        let id = pending_request(&fix.vtc).await;

        let first = signed(
            &fix.admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": id.to_string(), "decision": "approved" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &first).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        // A fresh document — new `id`, so the accepted-id record has nothing
        // to say about it — carrying the opposite decision.
        let second = signed(
            &fix.admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": id.to_string(), "decision": "rejected" }),
        )
        .await;
        assert_ne!(first.id, second.id, "these must be distinct documents");
        let out = dispatch(&fix.vtc, &second).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::routes::join_requests::decide::DECIDE_ERR_NOT_PENDING),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// A field failing validation is the task's own `validationFailed`.
    #[tokio::test]
    async fn a_bad_profile_field_is_the_declared_validation_failure() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            // Not an http(s) URL — refused so it cannot reach an `<img src>`
            // on the public page.
            json!({ "logoUrl": "javascript:alert(1)" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::routes::community::profile::PROFILE_UPDATE_ERR_VALIDATION_FAILED),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// An **omitted** member leaves the stored value alone — the distinction
    /// the double parse exists for.
    ///
    /// The generated `Payload` types `extensions` as a map with `default`, so
    /// once parsed an absent bag and an empty one are the same value, and
    /// mapping that straight through would clear the community's extensions on
    /// every update that did not mention them. The handler reads the raw
    /// payload for exactly this.
    #[tokio::test]
    async fn an_omitted_member_does_not_clear_what_it_did_not_mention() {
        let fix = fixture().await;
        let set = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({
                "logoUrl": "https://example.com/logo.png",
                "extensions": { "org": "acme" },
            }),
        )
        .await;
        assert!(dispatch(&fix.vtc, &set).await.status.is_success());

        let other = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "name": "Still Logoed" }),
        )
        .await;
        assert!(dispatch(&fix.vtc, &other).await.status.is_success());

        let stored = load_profile(&fix.vtc.state.community_ks)
            .await
            .expect("read profile")
            .expect("row");
        assert_eq!(
            stored.logo_url.as_deref(),
            Some("https://example.com/logo.png"),
            "an omitted `logoUrl` must leave the stored one alone"
        );
        assert_eq!(
            stored.extensions,
            json!({ "org": "acme" }),
            "and an omitted `extensions` must not clear the bag"
        );
    }

    /// An explicit `null` **does not** clear a nullable member, on either
    /// door — a divergence from the published task, recorded here rather than
    /// left for a client to discover.
    ///
    /// `vtc/community/profile/update/0.1` says the nullable members "may be
    /// explicitly set to `null` to clear them". They cannot be:
    /// `CommunityProfileUpdate` types them `Option<Option<String>>` but
    /// declares no double-option deserializer, and serde maps an explicit
    /// `null` onto the *outer* `None` — which this operation reads as "leave
    /// unchanged". That is the store's behaviour rather than the transport's,
    /// so it predates this binding and holds identically on the bearer route.
    /// What #1641 phase 2 is answerable for is that the two doors agree, and
    /// they do; fixing it is a change to `CommunityProfileUpdate` that moves
    /// both doors at once and belongs in its own.
    #[tokio::test]
    async fn an_explicit_null_does_not_yet_clear_a_nullable_member() {
        let fix = fixture().await;
        let set = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "logoUrl": "https://example.com/logo.png" }),
        )
        .await;
        assert!(dispatch(&fix.vtc, &set).await.status.is_success());

        let clear = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "logoUrl": null }),
        )
        .await;
        let out = dispatch(&fix.vtc, &clear).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(
            load_profile(&fix.vtc.state.community_ks)
                .await
                .expect("read profile")
                .expect("row")
                .logo_url
                .as_deref(),
            Some("https://example.com/logo.png"),
            "the logo survives a `null` the specification says should clear it"
        );
    }

    // ─── VTI-OPS-025 / -026: the accepted-id record, on a verb that issues ─

    /// **VTI-OPS-025 — the one this batch exists to get right.**
    ///
    /// A redelivered approval is answered with the outcome already recorded
    /// for it, and **does not issue a second membership credential**. The
    /// mediator re-pushes an undelivered inbox as a matter of routine, so this
    /// is the ordinary case rather than an attack, and without the spine's
    /// claim-before-execute the applicant would end up holding two VMCs with
    /// two status-list slots — one of which nobody could later revoke, because
    /// only the last write is on the member row.
    #[tokio::test]
    async fn vti_ops_025_a_replayed_decision_does_not_issue_a_second_credential() {
        let fix = fixture().await;
        let id = pending_request(&fix.vtc).await;
        let doc = signed(
            &fix.admin,
            JOIN_DECIDE_TYPE,
            json!({ "id": id.to_string(), "decision": "approved" }),
        )
        .await;

        let first = dispatch(&fix.vtc, &doc).await;
        assert!(
            first.status.is_success(),
            "{}",
            String::from_utf8_lossy(&first.body)
        );
        let issued = get_member(&fix.vtc.state.members_ks, APPLICANT)
            .await
            .expect("read member")
            .expect("the applicant is a member");
        let first_vmc_id = issued.current_vmc_id.clone().expect("a VMC was issued");
        let first_slot = issued.status_list_index;

        let second = dispatch(&fix.vtc, &doc).await;
        assert!(
            second.status.is_success(),
            "the redelivery must be answered, not refused: {}",
            String::from_utf8_lossy(&second.body)
        );
        assert_eq!(
            payload_of(&second),
            payload_of(&first),
            "the recorded outcome is what a redelivery is answered with — a \
             second execution would have answered `notPending` instead"
        );

        let after = get_member(&fix.vtc.state.members_ks, APPLICANT)
            .await
            .expect("read member")
            .expect("row");
        assert_eq!(
            after.current_vmc_id.as_deref(),
            Some(first_vmc_id.as_str()),
            "the member still holds the credential the first execution issued"
        );
        assert_eq!(
            after.status_list_index, first_slot,
            "and no second status-list slot was burned"
        );
    }

    /// **VTI-OPS-026.** A *different* document under an already-spent `id` is
    /// `idConflict` — not absorbed as a retry, and not executed.
    #[tokio::test]
    async fn vti_ops_026_a_different_document_under_a_spent_id_conflicts() {
        let fix = fixture().await;
        let first = signed(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "name": "First Name" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &first).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        let mut collider = unsigned(
            &fix.admin,
            COMMUNITY_PROFILE_UPDATE_TYPE,
            json!({ "name": "Second Name" }),
        );
        collider.id.clone_from(&first.id);
        let collider = sign(&fix.admin, collider).await;
        let out = dispatch(&fix.vtc, &collider).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("idConflict"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(
            load_profile(&fix.vtc.state.community_ks)
                .await
                .expect("read profile")
                .expect("row")
                .name,
            "First Name",
            "the conflicting document must not have executed"
        );
    }
}
