//! `vtc/members/personhood/{challenge,assert}`.
//!
//! Moved out of `trust_tasks/mod.rs` (#2579); the spine glue and the router
//! stay there.

use super::routing::{Routes, on};
use super::*;

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, vti_specs::vtc::members::personhood::challenge::v0_1::Payload => handle_personhood_challenge);
    on!(routes, vti_specs::vtc::members::personhood::assert::v0_2::Payload => handle_personhood_assert)
}

// ─── personhood ──────────────────────────────────────────────────────────

/// `vtc/members/personhood/challenge/0.1` — mint the single-use nonce the
/// assert presentation must carry.
///
/// The caller must be a member of this community: over REST the route sits
/// behind `AuthClaims`, and the membership check here is what that means on
/// a transport with no session. The *subject* may be another member, which
/// is the in-person ceremony — an administrator mints the challenge, reads
/// the derived match code to the person in front of them, and that person's
/// own client answers it.
///
/// Minting for someone else confers nothing on its own. The nonce is bound
/// to the subject DID, and the only thing that can spend it is a
/// presentation signed by that DID's key.
pub(super) async fn handle_personhood_challenge(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let caller = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: pc::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    // Membership check on the *caller*, standing in for the REST route's
    // session. A stranger who can reach the mediator is not a member.
    match crate::acl::get_acl_entry(&state.acl_ks, &caller).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::PermissionDenied {
                    reason: format!("{caller} is not a member of this community"),
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    }

    match crate::routes::members::personhood::challenge_inner(state, &body.did).await {
        Ok(res) => success_response(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/personhood/assert/0.2` — present the evidence and, if the
/// community's policy accepts it, take the personhood flag.
///
/// The proven sender must be the subject. `assert/0.2` declares
/// `exposure.actsAsSubject: true` — "the asserting member is the subject …
/// exercising their own authority over their own personhood state" — so on
/// a transport that proves who sent the bytes, the party executing is the
/// party being asserted about.
///
/// That check is belt-and-braces rather than the gate. The gate is the
/// presentation, exactly as the published task says: its `holder` must
/// equal the subject and its `proof.challenge` must be the paired nonce,
/// and [`challenge_inner`](crate::routes::members::personhood::challenge_inner)'s
/// counterpart enforces both regardless of who relayed the document.
pub(super) async fn handle_personhood_assert(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let caller = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: pa::Payload = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    if *body.did != caller {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "personhood is asserted by its subject; {caller} cannot assert for {}",
                    *body.did
                ),
            },
        );
    }

    let presentation = match serde_json::to_value(&body.presentation) {
        Ok(v) => v,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("presentation is not representable as JSON: {e}"),
                },
            );
        }
    };

    // The outcome evidence of each witnessing session a VWC in the presentation
    // cites (VTI-CMP-023), in the payload's own `outcomeEvidence`, read as
    // received: each document's proof and task digest are taken over its members.
    let evidence = match crate::credentials::witness::outcome_evidence_from_payload(&doc.payload) {
        Ok(e) => e,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: e.to_string(),
                },
            );
        }
    };

    match crate::routes::members::personhood::assert_inner(
        state,
        &body.did,
        &presentation,
        &evidence,
    )
    .await
    {
        Ok(res) => success_response(&doc, res),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}
