#![allow(clippy::result_large_err)]

//! The VTC member-facing **Trust Task document** dispatcher.
//!
//! This is the wire adapter the join ceremony grew up into: each holder- or
//! public-facing verb (`submit`/`request`, `manifest`, `status`)
//! is a [`trust_tasks_rs::TrustTask`] document, as are the member-initiated
//! `members/self-remove` and `members/vmc` (whose optional `requestId`
//! closes an approved join — the retired `accept` verb's semantics). The
//! success reply is a framework `#response` document (a [`VerdictResponse`]
//! for `submit`, a read body for `manifest`/`status`); every failure — invalid
//! VIC, expired, malformed, duplicate — is a framework `trust-task-error`
//! document, never a DIDComm problem-report and never a `deny` verdict
//! (`deny` is a *policy* refusal of a verified request; an error means the
//! request never reached the policy). See
//! `docs/05-design-notes/vtc-ceremony-protocol.md` §3.
//!
//! ## Transports
//!
//! Both REST and DIDComm render from the one [`dispatch_trust_task_core`]:
//! - **REST**: the request body is the document; the holder is authenticated
//!   by the document's `eddsa-jcs-2022` proof ([`verify_trust_task_proof`]).
//! - **DIDComm**: the message `type` is the Trust Task URL, the body is the
//!   document, and the authcrypt sender authenticates the holder.
//!
//! ## Auth is per-verb (unlike the VTA's uniform-`AuthClaims` dispatcher)
//!
//! The join family is mostly unauthenticated/holder-bound: `submit` and
//! `status` are bound to the holder DID (no ACL entry needed);
//! `manifest` is public. The operator-facing `decide`/`list`/
//! `show` verbs stay on their existing JWT-gated REST routes and are *not*
//! routed here. `present` belongs to the `credential-exchange` family and is
//! handled there.
//!
//! The personhood pair (`members/personhood/{challenge,assert}`) is the
//! member-facing half of a family whose `revoke` verb stays operator-side on
//! REST. Both carry their own gate — challenge requires the caller to be a
//! member, assert requires the sender to *be* the subject — because "an
//! authenticated session", which is what the REST routes rest on, has no
//! equivalent on a transport that only proves who sent the bytes.

// `pub(crate)` only so sibling modules' tests can take the framework error
// version from `framework_error_type_uri()` rather than each naming it. The
// module's items are individually `pub(crate)` already; this widens the path,
// not the surface.
pub(crate) mod helpers;

// The schema-conformance sweep (#1059): every bound, published `spec/vtc/*`
// URI must speak that URI's wire shape. Lives in `src` rather than `tests`
// because its census is derived from `DISPATCHED_URIS` below, which no
// integration test can see.
#[cfg(test)]
mod conformance;

use serde_json::Value;
use trust_tasks_rs::specs::vtc::members::personhood::{assert::v0_1 as pa, challenge::v0_1 as pc};
use trust_tasks_rs::{RejectReason, TrustTask};

use vti_common::error::AppError;

use vta_sdk::protocols::join_requests::{
    self as jr, JoinRequestStatusBody, JoinRequestSubmitBody, VerdictResponse,
};
use vta_sdk::protocols::members::{self as mem, MemberVmcBody, MemberVmcReceiptBody};

use crate::join::{JoinSubmitOutcome, JoinTransport};
use crate::server::AppState;

pub(crate) use helpers::TrustTaskOutcome;
// The one spelling of the framework error document's Type URI in this crate.
// Re-exported so the messaging layer labels a type-less reply with the same
// value the reject path emits, rather than a second literal.
pub(crate) use helpers::framework_error_type_uri;
use helpers::{
    app_error_to_reject, body_parse_error_response, parse_payload, reject_with, success_response,
    verdict_response, verify_trust_task_proof,
};

/// The transport-resolved caller identity threaded into the dispatcher.
///
/// `sender_did` is the DIDComm authcrypt sender (already cryptographically
/// authenticated); it is `None` over REST, where the holder is recovered
/// from the document proof instead.
pub(crate) struct JoinAuthCtx {
    pub transport: JoinTransport,
    pub sender_did: Option<String>,
}

impl JoinAuthCtx {
    /// The DIDComm context: the authcrypt sender is the proven holder.
    pub fn didcomm(sender_did: String) -> Self {
        Self {
            transport: JoinTransport::DIDComm,
            sender_did: Some(sender_did),
        }
    }

    /// The REST context: the holder is proven by the document proof.
    // Consumed by the REST transport adapter (the per-verb routes' rewire to
    // the document endpoint); kept here as the symmetric counterpart to
    // [`Self::didcomm`].
    #[allow(dead_code)]
    pub fn rest() -> Self {
        Self {
            transport: JoinTransport::Rest,
            sender_did: None,
        }
    }
}

/// The transport-neutral dispatch spine. Parses the document, runs the
/// framework's basic validation (expiry + recipient), then routes by
/// `type` to the matching verb handler.
pub(crate) async fn dispatch_trust_task_core(
    state: &AppState,
    ctx: &JoinAuthCtx,
    body: &[u8],
) -> TrustTaskOutcome {
    // 1. Parse the envelope.
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => return body_parse_error_response(&e.to_string()),
    };

    // 2. Framework §7.2 — expiry + recipient enforcement. The recipient
    //    binding (document `recipient` must equal this VTC's DID) is the
    //    replay defence that the bespoke `audience` field used to provide.
    //    Skipped while the VTC has no DID configured (setup).
    if let Some(vtc_did) = state.config.read().await.vtc_did.clone()
        && let Err(reason) = doc.validate_basic(chrono::Utc::now(), &vtc_did)
    {
        return reject_with(&doc, reason);
    }

    // 3. Dispatch by type URI.
    let type_uri = doc.type_uri.to_string();
    match type_uri.as_str() {
        jr::JOIN_REQUEST_SUBMIT_TYPE => handle_submit(state, ctx, doc).await,
        jr::JOIN_REQUEST_MANIFEST_TYPE => handle_manifest(state, doc).await,
        jr::JOIN_REQUEST_STATUS_TYPE => handle_status(state, ctx, doc).await,
        jr::MEMBER_SELF_REMOVE_TYPE => handle_self_remove(state, ctx, doc).await,
        mem::MEMBER_VMC_TYPE => handle_member_vmc(state, ctx, doc).await,
        PERSONHOOD_CHALLENGE_TYPE => handle_personhood_challenge(state, ctx, doc).await,
        PERSONHOOD_ASSERT_TYPE => handle_personhood_assert(state, ctx, doc).await,
        other => reject_with(
            &doc,
            RejectReason::UnsupportedType {
                type_uri: other.to_string(),
            },
        ),
    }
}

/// The Trust Task URIs this dispatcher routes. Kept in lockstep with the
/// `match` above by the `dispatcher_routes_every_dispatched_uri` test.
///
/// This set is also exactly what is reachable **over TSP**, since the TSP
/// inbound path (#833) hands every frame to this dispatcher and has no
/// protocol-message surface behind it. A verb that is not here is a verb a
/// member cannot perform over TSP.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const DISPATCHED_URIS: &[&str] = &[
    jr::JOIN_REQUEST_SUBMIT_TYPE,
    jr::JOIN_REQUEST_MANIFEST_TYPE,
    jr::JOIN_REQUEST_STATUS_TYPE,
    jr::MEMBER_SELF_REMOVE_TYPE,
    mem::MEMBER_VMC_TYPE,
    PERSONHOOD_CHALLENGE_TYPE,
    PERSONHOOD_ASSERT_TYPE,
];

/// `vtc/members/personhood/challenge/0.1` — mint the single-use nonce
/// the assert presentation must be bound to.
pub(crate) const PERSONHOOD_CHALLENGE_TYPE: &str =
    <pc::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/personhood/assert/0.1` — present the evidence.
pub(crate) const PERSONHOOD_ASSERT_TYPE: &str = <pa::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Resolve the proven holder DID for a holder-bound verb. DIDComm → the
/// authcrypt sender; REST → the document proof signer. When the document
/// carries an `issuer`, it must match the proven identity (anti-spoof).
async fn resolve_holder(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome> {
    let proven = match &ctx.sender_did {
        Some(did) => did.clone(),
        None => match verify_trust_task_proof(state, doc).await {
            Ok(did) => did,
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        },
    };
    if let Some(issuer) = doc.issuer.as_deref() {
        let issuer_base = issuer.split('#').next().unwrap_or(issuer);
        if issuer_base != proven {
            return Err(reject_with(
                doc,
                RejectReason::PermissionDenied {
                    reason: format!(
                        "document issuer ({issuer_base}) does not match the authenticated holder ({proven})"
                    ),
                },
            ));
        }
    }
    Ok(proven)
}

// ─── submit / request ────────────────────────────────────────────────────

async fn handle_submit(
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
        None,
        ctx.transport,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match outcome_to_verdict(&outcome) {
        Ok(v) => verdict_response(&doc, v),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Map the ceremony spine's [`JoinSubmitOutcome`] onto the wire
/// [`VerdictResponse`]. Auto-admit → `allow` (credentials inline);
/// `Pending` → `refer`; `Deferred` → `request_more`; `Rejected` → `deny`.
fn outcome_to_verdict(outcome: &JoinSubmitOutcome) -> Result<VerdictResponse, AppError> {
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
        let role_vec = serde_json::to_value(&admit.role_vec)
            .map_err(|e| AppError::Internal(format!("serialise role VEC: {e}")))?;
        return Ok(VerdictResponse::allow(
            request_id,
            role,
            Some(vmc),
            Some(role_vec),
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

// ─── manifest (public) ─────────────────────────────────────────────────────

async fn handle_manifest(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    match crate::routes::join_requests::manifest::manifest_inner(state).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── status ────────────────────────────────────────────────────────────────

async fn handle_status(
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
                None,
            )
            .await
        }
        None => {
            crate::routes::join_requests::status::status_by_applicant(state, applicant_did).await
        }
    };

    match result {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── members ─────────────────────────────────────────────────────────────

/// `members/self-remove/0.1` as a Trust Task document — the member-initiated
/// leave (R-L-1).
///
/// Same spine as the DIDComm protocol-message handler
/// (`messaging::member_self_remove_handler`): actor == subject, and the leave
/// policy allows self-leave unconditionally (spec §10.2) with the
/// no-last-admin invariant still enforced in the effect stage. What the
/// document form adds is reach — a member can now perform it over **any**
/// transport this dispatcher serves, TSP included, rather than DIDComm only.
///
/// The bare-body handler stays for existing senders; both produce the same
/// receipt payload, so a migrating client sees no behaviour change.
async fn handle_self_remove(
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
        Err(e) => app_error_to_reject(&doc, &e),
    }
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
async fn handle_personhood_challenge(
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
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/personhood/assert/0.1` — present the evidence and, if the
/// community's policy accepts it, take the personhood flag.
///
/// The proven sender must be the subject. `assert/0.1` declares
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
async fn handle_personhood_assert(
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

    match crate::routes::members::personhood::assert_inner(state, &body.did, &presentation).await {
        Ok(res) => success_response(&doc, res),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `members/vmc/0.1` as a Trust Task document — a member submits their
/// reciprocal VMC (the member → community half of the membership pair),
/// optionally closing an approved join request via `requestId` (the retired
/// `join-requests/accept` semantics).
///
/// Same spine as the DIDComm handler: `receive_member_vmc_inner` verifies the
/// issuer / subject binding and the DI proof before storing it on the member
/// row. The proven member comes from [`resolve_holder`], so the authenticated
/// identity is the transport's (DIDComm authcrypt sender / TSP sender VID) or
/// the document proof signer — never a self-asserted `issuer`.
async fn handle_member_vmc(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: MemberVmcBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // `request_id` travels as a string (the SDK's `members` module compiles
    // featureless, without `uuid`); a malformed id is a framework reject, not
    // a lookup miss.
    let request_id = match body
        .request_id
        .as_deref()
        .map(uuid::Uuid::parse_str)
        .transpose()
    {
        Ok(r) => r,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("requestId is not a UUID: {e}"),
                },
            );
        }
    };

    match crate::members::inbound_vmc::receive_member_vmc_inner(
        state, member_did, body.vc, request_id,
    )
    .await
    {
        Ok(outcome) => success_response(
            &doc,
            MemberVmcReceiptBody {
                member_did: outcome.member_did,
                vmc_id: outcome.vmc_id,
                status: "stored".to_string(),
                request_id: outcome.request_id.map(|u| u.to_string()),
            },
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every URI the dispatcher declares as routed must be a member-facing
    /// request URI declared elsewhere, and vice-versa — so a new verb can't
    /// be added to one side without the other.
    ///
    /// The two personhood entries come from `trust_tasks_rs::specs` rather
    /// than `vta_sdk::protocols`: they have no hand-written SDK constant
    /// because their wire types are generated from the published schema.
    /// Naming the generated `TYPE_URI` keeps the same property — the URI
    /// this dispatcher answers on is the one the spec publishes, not a
    /// string that happens to match today.
    #[test]
    fn dispatcher_routes_every_dispatched_uri() {
        let declared = [
            jr::JOIN_REQUEST_SUBMIT_TYPE,
            jr::JOIN_REQUEST_MANIFEST_TYPE,
            jr::JOIN_REQUEST_STATUS_TYPE,
            jr::MEMBER_SELF_REMOVE_TYPE,
            mem::MEMBER_VMC_TYPE,
            <pc::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <pa::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ];
        for u in DISPATCHED_URIS {
            assert!(
                declared.contains(u),
                "dispatched URI is not a declared request URI: {u}"
            );
        }
        assert_eq!(DISPATCHED_URIS.len(), declared.len());
    }

    /// The request URIs must parse as framework `TypeUri`s (the `/spec/`
    /// path shape), otherwise an inbound document would never deserialise.
    #[test]
    fn dispatched_uris_are_canonical_type_uris() {
        for u in DISPATCHED_URIS {
            let parsed: Result<trust_tasks_rs::TypeUri, _> = u.parse();
            assert!(
                parsed.is_ok(),
                "dispatched URI is not a canonical TypeUri: {u}"
            );
        }
    }

    /// The two member verbs are what #185 needs over TSP, and the TSP inbound
    /// path reaches a verb only through this dispatcher — so their absence
    /// would be an `UnsupportedType` on the wire, not a compile error.
    #[test]
    fn member_verbs_are_dispatched() {
        for u in [jr::MEMBER_SELF_REMOVE_TYPE, mem::MEMBER_VMC_TYPE] {
            assert!(
                DISPATCHED_URIS.contains(&u),
                "member verb not reachable over TSP: {u}"
            );
        }
    }

    /// The whole point of routing personhood here: a member client that
    /// speaks Trust Tasks over messaging can run the ceremony. Before this,
    /// personhood was REST-only, so `openvtc` — which talks to the VTC over
    /// DIDComm/TSP and holds no bearer token — could not reach it at all.
    #[test]
    fn personhood_verbs_are_dispatched() {
        for u in [PERSONHOOD_CHALLENGE_TYPE, PERSONHOOD_ASSERT_TYPE] {
            assert!(
                DISPATCHED_URIS.contains(&u),
                "personhood verb not reachable over TSP: {u}"
            );
        }
    }

    mod personhood {
        use super::*;
        use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
        use crate::test_support::TestVtc;
        use serde_json::json;

        const MEMBER: &str = "did:key:zPersonhoodMember";
        const STRANGER: &str = "did:key:zNotAMember";

        async fn fixture() -> TestVtc {
            let vtc = TestVtc::builder().with_signers(true).build().await;
            store_acl_entry(
                &vtc.state.acl_ks,
                &VtcAclEntry {
                    did: MEMBER.into(),
                    role: VtcRole::Member,
                    label: None,
                    allowed_contexts: vec![],
                    created_at: 0,
                    created_by: "did:key:vtc-install".into(),
                    updated_at: None,
                    updated_by: None,
                    expires_at: None,
                },
            )
            .await
            .expect("seed member ACL");
            vtc
        }

        /// The fixture leaves `vtc_did` unset, so `validate_basic`'s
        /// recipient binding is skipped — these tests are about the
        /// per-verb auth the handlers add, not the framework envelope
        /// checks that run ahead of every verb alike.
        fn document(type_uri: &str, payload: serde_json::Value) -> Vec<u8> {
            let doc = TrustTask::new(
                uuid::Uuid::new_v4().to_string(),
                type_uri.parse().expect("dispatched URI parses as TypeUri"),
                payload,
            );
            serde_json::to_vec(&doc).expect("serialize document")
        }

        /// The reply body as text. `TrustTaskOutcome` keeps raw bytes so the
        /// wire output is byte-identical to direct serialisation.
        fn rendered(out: &TrustTaskOutcome) -> String {
            String::from_utf8_lossy(&out.body).into_owned()
        }

        /// Happy path over messaging: a member mints their own challenge and
        /// the reply carries the spoken match code, same as over REST.
        #[tokio::test]
        async fn a_member_can_mint_a_challenge_over_messaging() {
            let vtc = fixture().await;
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(MEMBER.into()),
                &document(PERSONHOOD_CHALLENGE_TYPE, json!({ "did": MEMBER })),
            )
            .await;

            let body = rendered(&out);
            assert!(
                body.contains("challengeId"),
                "expected a challenge in the reply, got: {body}"
            );
            assert!(
                body.contains(crate::members::match_code::MATCH_CODE_EXT_KEY),
                "the messaging reply must carry the match code the REST reply does, got: {body}"
            );
        }

        /// The membership check standing in for the REST route's session.
        /// Without it, anyone who can reach the mediator could mint
        /// challenges against this community's members.
        #[tokio::test]
        async fn a_stranger_cannot_mint_a_challenge() {
            let vtc = fixture().await;
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(STRANGER.into()),
                &document(PERSONHOOD_CHALLENGE_TYPE, json!({ "did": MEMBER })),
            )
            .await;

            let body = rendered(&out);
            assert!(
                !body.contains("challengeId"),
                "a non-member minted a challenge: {body}"
            );
            assert!(
                body.contains("not a member"),
                "expected a permission refusal naming membership, got: {body}"
            );
        }

        /// `assert/0.1` declares `actsAsSubject: true`. On a transport that
        /// proves the sender, one member must not be able to assert
        /// personhood in another's name — even though the presentation gate
        /// would also stop them, because a caller should be refused before
        /// the daemon starts verifying someone else's credentials.
        #[tokio::test]
        async fn one_member_cannot_assert_personhood_for_another() {
            let vtc = fixture().await;
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(STRANGER.into()),
                &document(
                    PERSONHOOD_ASSERT_TYPE,
                    json!({
                        "did": MEMBER,
                        "presentation": { "type": ["VerifiablePresentation"], "holder": MEMBER },
                    }),
                ),
            )
            .await;

            let body = rendered(&out);
            assert!(
                body.contains("asserted by its subject"),
                "expected the subject-binding refusal, got: {body}"
            );
        }
    }
}
