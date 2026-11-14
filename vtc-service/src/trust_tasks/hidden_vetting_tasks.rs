//! Hidden vetting's community half (`vtc/vetting/vetters/pcs-*`,
//! `vtc/vetting/hidden/*`; feature `vetting-pcs`).
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::routing::{Routes, on};
use super::*;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes =
        on!(routes, vti_specs::vtc::vetting::vetters::pcs_root::v0_1::Payload => handle_pcs_root);
    let routes = on!(routes, vti_specs::vtc::vetting::vetters::pcs_tokens::v0_1::Payload => handle_pcs_tokens);
    let routes = on!(routes, vti_specs::vtc::vetting::vetters::event_mode::v0_1::Payload => handle_event_mode);
    let routes =
        on!(routes, vti_specs::vtc::vetting::pcs_challenge::v0_1::Payload => handle_pcs_challenge);
    let routes = on!(routes, vti_specs::vtc::vetting::vetters::pcs_binding::show::v0_1::Payload => handle_pcs_binding_show);
    let routes = on!(routes, vti_specs::vtc::vetting::vetters::pcs_binding::reset::v0_1::Payload => handle_pcs_binding_reset);
    let routes = on!(routes, vti_specs::vtc::vetting::hidden::publish::v0_1::Payload => handle_hidden_publish);
    let routes = on!(routes, vti_specs::vtc::vetting::hidden::withdraw::v0_1::Payload => handle_hidden_withdraw);
    on!(routes, vti_specs::vtc::vetting::hidden::show::v0_1::Payload => handle_hidden_show)
}

/// `vtc/vetting/vetters/pcs-root/0.1` — a vetter enrols for a class label.
///
/// The sender is the proven signer, and it is the member the community checks its records for:
/// a live vetter grant, no credential under this label yet, and the identifier they were bound
/// to. Every one of those is [`crate::vetting::pcs_issue::enrol`]'s, read from the store.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_pcs_root(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    match crate::vetting::pcs_tasks::handle_pcs_root(state, &member_did, &doc).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/pcs-tokens/0.1` — a vetter draws its tick of the drip.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_pcs_tokens(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    match crate::vetting::pcs_tasks::handle_pcs_tokens(state, &member_did, &doc).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/event-mode/0.1` — a vetter asks to vet at a named event.
///
/// The request is only ever a request. Approving it is an act by an admin of the community,
/// through the criterion that publishes the event — deliberately not a Trust Task, because a task
/// the vetter could send is a task a vetter could be made to send.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_event_mode(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    match crate::vetting::pcs_tasks::handle_event_mode(state, &member_did, &doc).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/pcs-challenge/0.1` — an applicant asks for the nonce its proof must bind.
///
/// Open to any party the community would take a submission from, which is the same entitlement
/// that admits them to apply: the challenge confers no standing, it only makes one submission
/// unrepeatable.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_pcs_challenge(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    match crate::vetting::pcs_tasks::handle_pcs_challenge(state, &applicant_did, &doc).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/pcs-binding/show/0.1` — a member reads their own hidden-vetting binding.
///
/// The sender is the proven signer, and the answer is about them only: the request names nobody.
/// Membership is checked in [`crate::vetting::pcs_tasks::handle_binding_show`].
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_pcs_binding_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    match crate::vetting::pcs_tasks::handle_binding_show(state, &member_did, &doc).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/pcs-binding/reset/0.1` — an administrator resets a vetter's
/// hidden-vetting binding after the key behind it was lost.
///
/// Held to `vtc.vetting.manage`, the capability `vtc/vetting/vetters/grant` takes (reset/0.1
/// Authorization), resolved as for every administrative task — the proven signer, or the
/// administrator a console key acts for. Like the grant, it is not parked for a second
/// administrator: it confers nothing, and binds no new identifier while the old one could still
/// attest.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_pcs_binding_reset(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let admin_did = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::VettingManage,
        None,
    )
    .await
    {
        Ok(claims) => claims.did,
        Err(reject) => return reject,
    };
    match crate::vetting::pcs_tasks::handle_binding_reset(state, &admin_did, &doc).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/hidden/publish/0.1` — turn on (or rotate) hidden-vetter admission for a
/// criterion. Admin only, read from the signer's ACL entry — the same `VtcRole::Admin` the REST
/// route's `AdminAuth` demanded, and the only gate that route applied. Was `POST /vetting/hidden`;
/// the derivation itself is
/// [`crate::routes::vetting_hidden::publish_hidden_vetting_core`], shared with that route.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_hidden_publish(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // The signer is kept: an event approval it adds must name it (publish/0.1 item 9), and the
    // consent gate (VTI-APV-023) is the signer's.
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::VettingManage,
        None,
    )
    .await
    {
        Ok(claims) => claims,
        Err(reject) => return reject,
    };
    let payload: vti_specs::vtc::vetting::hidden::publish::v0_1::Payload =
        match parse_spec_payload(&doc) {
            Ok(p) => p,
            Err(reject) => return reject,
        };
    let live_periods = payload
        .live_periods
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>();
    let live_token_labels = payload
        .live_token_labels
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>();
    let events = if payload.events.is_empty() {
        None
    } else {
        match serde_json::to_value(&payload.events) {
            Ok(v) => Some(v),
            Err(e) => {
                return app_error_to_reject(
                    &doc,
                    &AppError::Internal(format!("encode events: {e}")),
                );
            }
        }
    };
    match crate::routes::vetting_hidden::publish_hidden_vetting_core(
        state,
        &actor,
        &doc,
        payload.criterion_id.to_string(),
        if live_periods.is_empty() {
            None
        } else {
            Some(live_periods)
        },
        if live_token_labels.is_empty() {
            None
        } else {
            Some(live_token_labels)
        },
        payload.drip_per_tick.map(|n| n.get() as usize),
        payload.tick_length.as_ref().map(|t| t.to_string()),
        events,
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(crate::routes::vetting_hidden::Halted::Refused(e)) => task_error_to_reject(&doc, &e),
        Err(crate::routes::vetting_hidden::Halted::Gate(outcome)) => outcome,
    }
}

/// `vtc/vetting/hidden/withdraw/0.1` — turn hidden-vetter admission off for a criterion. The
/// same gate as publish, `VettingManage`, read from the signer's ACL entry.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_hidden_withdraw(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::VettingManage,
        None,
    )
    .await
    {
        Ok(claims) => claims,
        Err(reject) => return reject,
    };
    let payload: vti_specs::vtc::vetting::hidden::withdraw::v0_1::Payload =
        match parse_spec_payload(&doc) {
            Ok(p) => p,
            Err(reject) => return reject,
        };
    match crate::routes::vetting_hidden::withdraw_hidden_vetting_core(
        state,
        &actor,
        &doc,
        payload.criterion_id.to_string(),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(crate::routes::vetting_hidden::Halted::Refused(e)) => task_error_to_reject(&doc, &e),
        Err(crate::routes::vetting_hidden::Halted::Gate(outcome)) => outcome,
    }
}

/// `vtc/vetting/hidden/show/0.1` — a criterion's stored hidden-vetting configuration, with the
/// enrolment and event-demand counts. Administrators only (`VettingManage`): it names who
/// approved each event.
#[cfg(feature = "vetting-pcs")]
pub(super) async fn handle_hidden_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(
        state,
        ctx,
        &doc,
        crate::acl::Capability::VettingManage,
        None,
    )
    .await
    {
        return reject;
    }
    let payload: vti_specs::vtc::vetting::hidden::show::v0_1::Payload =
        match parse_spec_payload(&doc) {
            Ok(p) => p,
            Err(reject) => return reject,
        };
    match crate::routes::vetting_hidden::show_hidden_vetting_core(
        state,
        payload.criterion_id.to_string(),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}
