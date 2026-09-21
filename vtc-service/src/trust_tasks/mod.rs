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
use vta_sdk::protocols::vetting::{
    self as vetting_wire, revoke_statement::v0_1 as revoke_statement,
};

use crate::join::{JoinSubmitOutcome, JoinTransport};
use crate::routes::join_requests::manifest::ManifestVersion;
use crate::server::AppState;

pub(crate) use helpers::TrustTaskOutcome;
// The one spelling of the framework error document's Type URI in this crate.
// Re-exported so the messaging layer labels a type-less reply with the same
// value the reject path emits, rather than a second literal.
pub(crate) use helpers::framework_error_type_uri;
use helpers::{
    app_error_to_reject, body_parse_error_response, parse_payload, reject_with, reject_with_code,
    success_response, verdict_response, verify_trust_task_proof,
};

/// The transport-resolved caller identity threaded into the dispatcher.
///
/// `sender_did` is the DIDComm authcrypt sender (already cryptographically
/// authenticated); it is `None` over REST, where the holder is recovered
/// from the document proof instead.
pub(crate) struct JoinAuthCtx {
    pub transport: JoinTransport,
    pub sender_did: Option<String>,
    /// The DID that signed this document's Data-Integrity proof, verified by
    /// the spine against the document **as received**.
    ///
    /// `None` when the task's specification does not require a proof, or when
    /// the context was built by a transport rather than by the spine.
    ///
    /// # Why the spine and not the handler
    ///
    /// A proof covers the document as it was sent. A handler that has been
    /// handed a typed payload can only re-derive those bytes if its payload type
    /// round-trips losslessly — and none promises to: parse a document into a
    /// type that does not know one of its fields and the field is gone, so the
    /// canonicalisation differs and a valid proof fails. Verifying here, once,
    /// against the bytes that arrived, is what makes typed handlers possible at
    /// all. Pinned by `vta-sdk/tests/typed_proof_verify.rs`.
    pub verified_signer: Option<String>,
}

impl JoinAuthCtx {
    /// The DIDComm context: the authcrypt sender is the proven holder.
    pub fn didcomm(sender_did: String) -> Self {
        Self {
            transport: JoinTransport::DIDComm,
            sender_did: Some(sender_did),
            verified_signer: None,
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
            verified_signer: None,
        }
    }

    /// The same context with `verified_signer` filled in by the spine.
    fn with_verified_signer(&self, signer: Option<String>) -> Self {
        Self {
            transport: self.transport,
            sender_did: self.sender_did.clone(),
            verified_signer: signer,
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

    // 3. Framework §7.2 item 8 — the proof, verified here against the document
    //    **as received**, because this is the last point at which those bytes
    //    exist: past dispatch a handler holds a payload that may have dropped a
    //    member it does not know, and canonicalising that yields different bytes
    //    and refuses a valid proof.
    //
    //    ## Verify what is here; do not demand what the transport already proved
    //
    //    The obvious rule — verify wherever the published specification says
    //    `proof` is REQUIRED — is wrong for this service, and the join tests say
    //    so immediately. `join-requests/submit/0.2` declares a proof REQUIRED,
    //    and over DIDComm the applicant carries none: authcrypt proved the
    //    sender, and the document rides inside that envelope. Enforcing the
    //    specification's flag here refuses every join over DIDComm and TSP with
    //    "document has no proof".
    //
    //    That gap between the published requirement and what this service
    //    accepts is real and predates this change; it is not something to close
    //    by silently breaking the transport. So the rule is the one the
    //    framework's own HTTPS binding uses for exactly this situation
    //    (`require_attribution`): attribution must come from *somewhere* — a
    //    verified proof, or a transport-authenticated peer. A present proof is
    //    always checked; an absent one is the transport's business, and each
    //    handler already knows which it needs. The `rooms/*` arms demand a
    //    verified signer and refuse without one, which is exactly what those
    //    handlers did for themselves before.
    let type_uri = doc.type_uri.to_string();
    let ctx = if doc.proof.is_some() {
        match verify_trust_task_proof(state, &doc).await {
            Ok(signer) => &ctx.with_verified_signer(Some(signer)),
            // A proof that is present and does not verify is always fatal,
            // whatever the transport proved separately.
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    } else {
        ctx
    };

    // 3b. SPEC §7.2 item 11 — the duplicate-execution record.
    //
    // Every transport that reaches this spine is at-least-once. The mediator
    // re-pushes a recipient's whole undelivered inbox when a socket enables
    // live delivery and when a duplicate socket displaces an existing session,
    // so a frame this VTC has already handled arrives again as a matter of
    // routine — not as an attack. Without a record, the second copy is executed
    // a second time.
    //
    // Expiry and the recipient binding (step 2) do not close this. Both are
    // properties of the document, and a redelivered copy satisfies them exactly
    // as the first did — which is the point: it *is* the first document.
    //
    // Deliberately the same mechanism the VTA uses rather than a cache of this
    // service's own. `ReplayGuard` is digest-keyed, so a *different* document
    // arriving under an already-spent `id` is `idConflict` rather than being
    // silently absorbed as a retry, and it claims before dispatch, so two
    // simultaneous deliveries cannot both pass a check-then-act test.
    //
    // Placed after the proof check so an unauthenticated flood cannot spend
    // another sender's ids, matching where the webvh control plane puts its own
    // gate and for the same reason.
    let doc_id = doc.id.clone();
    let digest = match trust_tasks_rs::document_digest(&doc) {
        Ok(d) => d,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!(
                        "cannot canonicalise the document to key its replay record: {e}"
                    ),
                },
            );
        }
    };
    let now = chrono::Utc::now();
    let retain_until = retention_policy().record_expiry(&doc, now);
    match trust_tasks_rs::ReplayGuard::claim(&*REPLAY_GUARD, &doc_id, &digest, retain_until, now)
        .await
    {
        Ok(trust_tasks_rs::ReplayVerdict::Fresh) => {}
        Ok(trust_tasks_rs::ReplayVerdict::Duplicate {
            prior_response,
            in_flight,
        }) => {
            // §7.2 (*Disposition of a duplicate*): "In no case is a duplicate
            // reported as `taskFailed`; the task did not fail, it already
            // happened." A redelivery is the common case here, so answering it
            // with the original result is not a courtesy — it is what keeps a
            // caller whose reply was lost from retrying forever.
            return match prior_response {
                Some(v) => match serde_json::to_vec(&v) {
                    Ok(body) => TrustTaskOutcome {
                        status: axum::http::StatusCode::OK,
                        body,
                    },
                    Err(e) => reject_with(
                        &doc,
                        RejectReason::InternalError {
                            reason: format!("prior response is unserialisable: {e}"),
                        },
                    ),
                },
                // Still running: `202` is the only honest code. `200` claims a
                // result that does not exist yet and `409` a conflict that does
                // not exist — it is the same document.
                None if in_flight => TrustTaskOutcome {
                    status: axum::http::StatusCode::ACCEPTED,
                    body: Vec::new(),
                },
                None => TrustTaskOutcome {
                    status: axum::http::StatusCode::NO_CONTENT,
                    body: Vec::new(),
                },
            };
        }
        Ok(trust_tasks_rs::ReplayVerdict::Conflict) => {
            return reject_with(&doc, RejectReason::IdConflict);
        }
        // Fail closed. A consumer that cannot establish whether a document is a
        // duplicate has not satisfied item 11, so it must not execute — and
        // `unavailable` is retryable, which is the truthful signal.
        Err(e) => {
            tracing::error!(error = %e, id = %doc_id, "replay guard unavailable");
            return reject_with(&doc, RejectReason::Unavailable { retry_after: None });
        }
        // `ReplayVerdict` is `#[non_exhaustive]`. Every variant it has gained so
        // far is a reason *not* to run the task; guessing permissively on an
        // unknown one is how a duplicate-execution defence stops defending.
        Ok(other) => {
            tracing::error!(
                verdict = ?other,
                id = %doc_id,
                "replay guard returned a verdict this build does not know",
            );
            return reject_with(&doc, RejectReason::Unavailable { retry_after: None });
        }
    }

    // 4. Dispatch by type URI, then sign what comes back.
    let outcome = dispatch_typed(state, ctx, doc, &type_uri).await;
    let outcome = sign_success_response(state, outcome).await;

    // Close out the claim taken at 3b.
    //
    // - **Succeeded** → record the response, so the redelivery this guard
    //   exists to absorb is answered with the result rather than with silence.
    // - **Failed** → release. A document refused downstream of the claim would
    //   otherwise burn its `id`, and a corrected resend under the same `id`
    //   would come back `idConflict` for as long as the record is retained.
    {
        let guard: &dyn trust_tasks_rs::ReplayGuard = &*REPLAY_GUARD;
        if outcome.status.is_success() {
            let recorded = serde_json::from_slice::<serde_json::Value>(&outcome.body).ok();
            if let Err(e) = guard.record_response(&doc_id, recorded.as_ref()).await {
                // Not fatal: the effect happened and the claim stands, so item 11
                // still holds. Only the answer-a-retry courtesy is lost.
                tracing::warn!(error = %e, id = %doc_id, "replay guard: response not recorded");
            }
        } else if let Err(e) = guard.release(&doc_id, &digest).await {
            tracing::warn!(error = %e, id = %doc_id, "replay guard: claim not released");
        }
    }

    outcome
}

/// Process-local duplicate-execution records (SPEC §7.2 item 11).
///
/// In-memory on purpose. Cross-restart replay is not what this defends against:
/// the records it would need are exactly the ones a restart makes unreachable
/// anyway, and the redelivery window it does cover is far shorter than an
/// uptime. Capacity-bounded, so a burst of distinct documents cannot grow it
/// without limit.
///
/// Single-process, like the VTA's. Behind a load balancer two replicas would
/// each accept the same document once; a VTC is not deployed that way today,
/// and making this durable is the change to make when one is.
static REPLAY_GUARD: std::sync::LazyLock<trust_tasks_rs::InMemoryReplayGuard> =
    std::sync::LazyLock::new(trust_tasks_rs::InMemoryReplayGuard::default);

/// How long a duplicate-execution record is kept.
///
/// **Retention only** — this is not an acceptance policy and must not become
/// one. The VTC does not enforce a freshness window today (many of its
/// producers stamp no `issuedAt`), and turning one on here would refuse
/// documents this service accepts now. What the policy supplies is the
/// fallback horizon for a document carrying no `expiresAt`: without it such a
/// record would be held until capacity evicted it.
///
/// The bound may only ever be *longer* than the window in which a document is
/// still executable. Shorter is the direction §7.2 forbids — a replay arriving
/// while the document is still acceptable, with its record already dropped,
/// runs twice.
fn retention_policy() -> trust_tasks_rs::FreshnessPolicy {
    trust_tasks_rs::FreshnessPolicy::consequential()
}

/// Attach this community's Data-Integrity proof to a success response.
///
/// # Why here and not at each `success_response`
///
/// Signing is the same decision taken once per handler, and there are twenty-one
/// of them. Forgetting once is a task whose response is unattributable, and
/// nothing downstream would notice — which is exactly how every response came to
/// be unsigned in the first place. The spine is where the framework's inbound
/// checks already live; the outbound one belongs beside them.
///
/// # Why this was missing, and what it cost
///
/// SPEC §7.3 item 7: where a specification declares no separate requirement for
/// the *response*, the request's applies to it — "an omission can never weaken a
/// variant". 265 published specifications declare a single
/// `proofRequirement: REQUIRED`, so their responses require a proof, and this
/// service attached none to any of them.
///
/// Nothing went red because no consumer verifies one either. Producers not
/// signing and consumers not checking is a mutually consistent silence, and the
/// cost is that **no answer this service has ever given is evidence of
/// anything**: a member cannot show a third party what the host told them, and
/// cannot be contradicted when they misreport it.
///
/// # Scope
///
/// Success responses only. An *error response*'s `type` resolves to the
/// framework's `trust-task-error` specification, whose own requirement is
/// RECOMMENDED rather than REQUIRED (SPEC §8.1, and §7.3's note that the error
/// variant is deliberately not declarable by a task). Signing those is a
/// separate decision with its own rationale — a retained compliance refusal is
/// the case that argues for it — and is not smuggled in here.
///
/// A community with no signer configured (setup, before provisioning) returns
/// the document unsigned rather than failing: it has nothing to sign with, and
/// refusing to answer would make an unprovisioned VTC unusable rather than
/// merely unattributable.
async fn sign_success_response(state: &AppState, outcome: TrustTaskOutcome) -> TrustTaskOutcome {
    if !outcome.status.is_success() {
        return outcome;
    }
    let Some(signer) = state.credential_signer.clone() else {
        return outcome;
    };

    let mut doc: Value = match serde_json::from_slice(&outcome.body) {
        Ok(d) => d,
        Err(e) => {
            // The spine built this document a moment ago, so this cannot happen
            // without a bug above. Answer unsigned rather than turning a
            // successful operation into a failure over its envelope.
            tracing::error!(error = %e, "success response is not JSON; returning it unsigned");
            return outcome;
        }
    };
    if let Err(e) = signer.sign_doc(&mut doc).await {
        tracing::error!(error = %e, "could not sign the success response; returning it unsigned");
        return outcome;
    }
    match serde_json::to_vec(&doc) {
        Ok(body) => TrustTaskOutcome {
            status: outcome.status,
            body,
        },
        Err(e) => {
            tracing::error!(error = %e, "could not serialise the signed response");
            outcome
        }
    }
}

async fn dispatch_typed(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> TrustTaskOutcome {
    // Every `rooms/*` operation is authorized against the DID that **signed the
    // request**, so an unsigned one has nothing to authorize and is refused.
    //
    // That refusal is not new: each of these handlers used to call
    // `verify_trust_task_proof` itself and return this same rejection. The
    // verification moved to the spine; the requirement did not move anywhere.
    // Stated as a guard here rather than assumed, because `verified_signer` is
    // `None` for every transport-authenticated task that carries no proof — the
    // normal case for join over DIDComm — and defaulting to an empty presenter
    // would authorize a room operation against nobody.
    let rooms_presenter = ctx.verified_signer.as_deref();

    match type_uri {
        jr::JOIN_REQUEST_SUBMIT_TYPE => handle_submit(state, ctx, doc).await,
        jr::JOIN_REQUEST_MANIFEST_TYPE => {
            handle_manifest(state, ctx, doc, ManifestVersion::V0_1).await
        }
        jr::JOIN_REQUEST_MANIFEST_0_2_TYPE => {
            handle_manifest(state, ctx, doc, ManifestVersion::V0_2).await
        }
        jr::JOIN_REQUEST_STATUS_TYPE => handle_status(state, ctx, doc).await,
        jr::JOIN_REQUEST_WITHDRAW_TYPE => handle_withdraw(state, ctx, doc).await,
        jr::MEMBER_SELF_REMOVE_TYPE => handle_self_remove(state, ctx, doc).await,
        mem::MEMBER_VMC_TYPE => handle_member_vmc(state, ctx, doc).await,
        vetting_wire::VETTING_REVOKE_STATEMENT_TYPE => {
            handle_revoke_statement(state, ctx, doc).await
        }
        vetting_wire::VETTING_VETTER_GRANT_TYPE => handle_vetter_grant(state, ctx, doc).await,
        vetting_wire::VETTING_VETTER_PROFILE_TYPE => handle_vetter_profile(state, ctx, doc).await,
        vetting_wire::VETTING_VETTER_LIST_TYPE => handle_vetter_list(state, ctx, doc).await,
        vetting_wire::VETTING_VETTER_RESEND_TYPE => handle_vetter_resend(state, ctx, doc).await,
        // The rooms family. Note what these still do not take: no `ctx`, and no auth
        // claims. A room operation is authorized by the authority chain the room itself
        // issued, never by this service's ACL, roster, or the caller's session —
        // invariant I5 of `docs/05-design-notes/data-rooms.md`, and what makes a room
        // portable.
        //
        // They do take the **verified signer**, which is not a weakening of that: it is
        // a cryptographic fact about the request, not an authority this service confers.
        // The handlers used to derive it themselves; they cannot once they hold a typed
        // payload, because re-deriving the signed bytes from a parsed payload is sound
        // only for a type that round-trips losslessly. See `JoinAuthCtx::
        // verified_signer`.
        // Every `rooms/*` task, in one arm, because the dispatcher *is* the
        // routing table: each registration names a payload type and the
        // framework derives the URI from it. There is no second list to keep in
        // step — which is what this replaces. Eleven hand-written arms had to
        // agree with `ROOMS_DISPATCHED_URIS` by hand, and had already failed to:
        // `rooms/records/curate` was dispatched and named in neither array, so
        // every version hint this service emitted was wrong about it.
        uri if crate::rooms::handlers::serves(uri) => {
            // A room operation is authorized against the DID that signed the
            // request, so an unsigned one has nothing to authorize. The spine
            // verified any proof that was present; absent, there is no signer.
            let Some(presenter) = rooms_presenter else {
                return reject_with(&doc, trust_tasks_rs::RejectReason::ProofRequired);
            };
            crate::rooms::handlers::dispatch(state, doc, presenter).await
        }
        PERSONHOOD_CHALLENGE_TYPE => handle_personhood_challenge(state, ctx, doc).await,
        PERSONHOOD_ASSERT_TYPE => handle_personhood_assert(state, ctx, doc).await,
        other => unsupported_type_or_version(&doc, other),
    }
}

#[cfg(test)]
mod spine_proof_tests {
    use super::*;

    /// The rule the spine actually follows, and the one it must not.
    ///
    /// The tempting rule is "verify wherever the published specification says
    /// `proof` is REQUIRED". This test exists because that rule is wrong here,
    /// and wrong in a way that takes the service down rather than tightening it:
    /// `join-requests/submit` declares a proof REQUIRED, and over DIDComm the
    /// applicant sends none — authcrypt proved the sender and the document rides
    /// inside that envelope. Enforcing the flag refuses every join over DIDComm
    /// and TSP.
    ///
    /// So the assertion is inverted from what it looks like it should be: these
    /// URIs demand a proof *per the specification* while this service accepts
    /// them without one. That divergence is real and predates the spine change.
    /// It is recorded here so the next person to reach for `spec_policy_for` as
    /// an enforcement gate meets it as a failing test rather than as a total
    /// outage.
    #[test]
    fn a_transport_authenticated_task_declares_a_proof_it_does_not_carry() {
        let declares_required = |uri: &str| {
            trust_tasks_rs::schema_index::spec_policy_for(uri)
                .is_some_and(|policy| policy.is_proof_required)
        };

        assert!(
            declares_required(jr::JOIN_REQUEST_SUBMIT_TYPE),
            "if this is now false the specification changed, and the comment \
             above — plus the rule in the spine — should be re-read"
        );
    }

    /// And the rooms family, where the requirement *is* enforced — by the arms
    /// in `dispatch_typed`, which refuse without a verified signer exactly as
    /// each handler used to refuse for itself.
    ///
    /// The two together are the whole rule: a present proof is always verified,
    /// an absent one is the transport's business, and a handler that needs a
    /// signed identity says so.
    #[test]
    fn every_rooms_task_declares_the_proof_its_arm_requires() {
        for uri in vti_rooms::wire::ROOMS_DISPATCHED_URIS {
            let policy = trust_tasks_rs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
            assert!(
                policy.is_proof_required,
                "{uri}: its arm refuses without a verified signer, so the \
                 specification had better agree that one is required"
            );
        }
    }
}

/// The family of a Trust Task Type URI: everything before its trailing version
/// segment.
///
/// `…/spec/vtc/join-requests/submit/0.2` → `…/spec/vtc/join-requests/submit`.
/// The version is always the last path segment (SPEC §3.1), so a plain
/// `rsplit_once('/')` is the whole rule — no version grammar to parse, and a
/// URI with no `/` simply has no family rather than panicking.
fn task_family(type_uri: &str) -> Option<&str> {
    type_uri.rsplit_once('/').map(|(family, _version)| family)
}

/// Reject a type URI this dispatcher has no arm for, distinguishing the two
/// failures that used to wear one code.
///
/// "I have never heard of this task" and "I know this task, at a different
/// version" send the operator to completely different places — the first to
/// whether the verb exists at all, the second to which side is out of date —
/// and only the second is recoverable by upgrading something.
///
/// So a URI whose family this VTC *does* dispatch is rejected as
/// `unsupportedVersion` — SPEC's code for exactly this, "the consumer
/// recognizes the type but not at this MAJOR.MINOR" — naming the versions
/// actually served in `message` and in `details.servedVersions`. Anything else
/// stays `unsupportedType`.
///
/// This is the VTC half of #1220, which did the same on the VTA after an
/// operator spent an hour reading `unsupported type: …/provision/integration/0.3`
/// as "this agent cannot provision" when it meant "this agent is older than
/// your client". The VTC is more exposed to that reading, not less: its
/// `spec/vtc/*` families are mid-migration, so a member client and a community
/// can legitimately be at different versions of the same verb.
///
/// Both `details` members are bounded by construction — `servedVersions` comes
/// from a `const` of seven, and `requestedType` echoes a `TypeUri` the
/// framework already parsed and already puts in `message` — but they still go
/// through `reject_with_code`'s `bound_details`, because "bounded by
/// construction" is a property of today's callers rather than of the funnel.
fn unsupported_type_or_version(doc: &TrustTask<Value>, type_uri: &str) -> TrustTaskOutcome {
    use trust_tasks_rs::{StandardCode, TrustTaskCode};
    use vta_sdk::protocols::trust_task_reject_details as details;

    let family = task_family(type_uri);
    // Both halves of what this service serves: the URIs still routed by the
    // match below, and the ones the rooms dispatcher derives from its
    // registrations. The second used to be a `const` array copied by hand from
    // the arms — this reads the routing table itself, so a version hint cannot
    // name a task nobody serves, nor omit one that is served.
    let mut served: Vec<&str> = DISPATCHED_URIS
        .iter()
        .copied()
        .chain(crate::rooms::handlers::served_uris())
        .filter(|uri| family.is_some() && task_family(uri) == family)
        .collect();
    served.sort_unstable();
    served.dedup();

    if served.is_empty() {
        // Message kept byte-identical to the framework's own
        // `RejectReason::UnsupportedType` rendering so a consumer matching on
        // it does not break; `details.requestedType` is the same fact
        // machine-readably, which is the half the framework's shape leaves out.
        return reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::UnsupportedType),
            format!("unsupported type: {type_uri}"),
            Some(serde_json::json!({ details::REQUESTED_TYPE: type_uri })),
        );
    }

    reject_with_code(
        doc,
        TrustTaskCode::Standard(StandardCode::UnsupportedVersion),
        format!(
            "unsupported version: {type_uri} — this VTC serves {}",
            served.join(", ")
        ),
        Some(serde_json::json!({
            details::REQUESTED_TYPE: type_uri,
            details::SERVED_VERSIONS: served,
        })),
    )
}

/// The Trust Task URIs this dispatcher routes. Kept in lockstep with the
/// `match` above by the `dispatcher_routes_every_dispatched_uri` test.
///
/// This set is also exactly what is reachable **over TSP**, since the TSP
/// inbound path (#833) hands every frame to this dispatcher and has no
/// protocol-message surface behind it. A verb that is not here is a verb a
/// member cannot perform over TSP.
///
/// Read at runtime as well as by the parity test:
/// [`unsupported_type_or_version`] answers an unrouted URI from this list, so
/// the migration hint a client receives cannot name a version this VTC does
/// not actually serve.
pub(crate) const DISPATCHED_URIS: &[&str] = &[
    jr::JOIN_REQUEST_SUBMIT_TYPE,
    jr::JOIN_REQUEST_MANIFEST_TYPE,
    // 0.2 adds the per-criterion vetting requirements and `requirementsDigest`.
    jr::JOIN_REQUEST_MANIFEST_0_2_TYPE,
    jr::JOIN_REQUEST_STATUS_TYPE,
    // The applicant closing their own request. Paired with `status` above: the
    // poll is how they learn the community asked for more, and this is how
    // they decline to supply it.
    jr::JOIN_REQUEST_WITHDRAW_TYPE,
    jr::MEMBER_SELF_REMOVE_TYPE,
    mem::MEMBER_VMC_TYPE,
    // A vetter withdrawing a statement (OpenVTC vetting design §9.6).
    vetting_wire::VETTING_REVOKE_STATEMENT_TYPE,
    // An admin naming a vetter — also mounted on REST as `POST /v1/vetting/vetters`.
    vetting_wire::VETTING_VETTER_GRANT_TYPE,
    // The vetter registry: a vetter publishing a profile, anyone identified
    // finding vetters, and a vetter asking for their grant credential again
    // (resend is also mounted for admins as `POST /v1/vetting/vetters/{memberDid}/resend`).
    vetting_wire::VETTING_VETTER_PROFILE_TYPE,
    vetting_wire::VETTING_VETTER_LIST_TYPE,
    vetting_wire::VETTING_VETTER_RESEND_TYPE,
    PERSONHOOD_CHALLENGE_TYPE,
    PERSONHOOD_ASSERT_TYPE,
    // rooms/* — top-level, not `spec/vtc/*`: a room's protocol is host-neutral, so
    // filing it under a service prefix would encode into the URI the one thing the
    // design exists to avoid. The vtc conformance sweep scopes to `spec/vtc/` and so
    // does not cover these; they are pinned by `rooms_dispatch_matches_wire` below.
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
            return reject_with_code(
                &doc,
                extended_code(jr::JOIN_REQUEST_SUBMIT_ERR_REQUEST_ALREADY_OPEN),
                AppError::from(refusal).to_string(),
                Some(serde_json::json!({
                    "requestId": request_id.to_string(),
                    "status": status.to_string(),
                })),
            );
        }
        Err(crate::join::SubmitRefusal::Other(e)) => return app_error_to_reject(&doc, &e),
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

// ─── vetting statement withdrawal ──────────────────────────────────────────

/// `vtc/vetting/revoke-statement/0.1` — a vetter withdraws a statement.
///
/// The sender is the proven signer (REST document proof or DIDComm authcrypt).
/// What a notice may do, and who may send one, is decided in
/// [`crate::vetting::revocation::withdraw`].
async fn handle_revoke_statement(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let vetter_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: revoke_statement::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let answer = crate::vetting::revocation::withdraw(state, &vetter_did, &body)
        .await
        .and_then(|notice| {
            revoke_statement::Response::try_from(
                revoke_statement::Response::builder().recorded_at(notice.recorded_at),
            )
            .map_err(|e| AppError::Internal(format!("revoke-statement response: {e}")))
        });
    match answer {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/grant/0.1` — an admin names a member a vetter.
///
/// The sender is the proven signer; whether they may grant (community Admin,
/// read from the ACL row) and whom (a current member) is decided in
/// [`crate::vetting::vetters::grant`], the same path `POST /v1/vetting/vetters`
/// takes.
async fn handle_vetter_grant(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let admin_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: vetting_wire::vetters::grant::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::vetters::grant(state, &admin_did, &body).await {
        Ok(grant) => success_response(&doc, grant.response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Parse a published task's payload as received: the JSON is validated against
/// the published schema before it is parsed — a generated constructor can
/// normalise what it reads — and then the rules no schema can state are applied
/// ([`vetting_wire::read_checked`]). A payload failing any of it is
/// `malformedRequest`.
fn parse_checked_payload<P>(doc: &TrustTask<Value>) -> Result<P, TrustTaskOutcome>
where
    P: trust_tasks_rs::Payload + serde::de::DeserializeOwned + vetting_wire::CheckShape,
{
    vetting_wire::read_checked::<P>(&doc.payload).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        )
    })
}

/// A specification-extended error code, `<slug>:<local>`, as a framework code.
fn extended_code(code: &str) -> trust_tasks_rs::TrustTaskCode {
    let (slug, local) = code
        .rsplit_once(':')
        .expect("an extended code is <slug>:<local>");
    trust_tasks_rs::TrustTaskCode::Extended {
        slug: slug.to_string(),
        local: local.to_string(),
    }
}

/// `vtc/vetting/vetters/profile/0.1` — a vetter publishes their profile.
///
/// The sender is the proven signer and the only vetter whose profile it can
/// write. Who may publish is decided in [`crate::vetting::profiles::publish`];
/// a sender without a live grant is refused with the task's `notEligible`.
async fn handle_vetter_profile(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let vetter_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: vetting_wire::vetters::profile::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::profiles::publish(state, &vetter_did, &body, doc.issued_at).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::Forbidden(reason)) => reject_with_code(
            &doc,
            extended_code(vetting_wire::VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE),
            reason,
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/list/0.1` — find listed vetters.
///
/// Any identified caller, member or applicant. [`resolve_holder`] is what
/// refuses an unidentified one — no proof over REST, no authenticated sender
/// otherwise — with `permissionDenied`, before anything is read.
async fn handle_vetter_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = resolve_holder(state, ctx, &doc).await {
        return reject;
    }
    let body: vetting_wire::vetters::list::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::profiles::list(state, &body).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/vetting/vetters/resend/0.1` — a vetter asks for their grant credential
/// again. Always the sender's own grant.
async fn handle_vetter_resend(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::{StandardCode, TrustTaskCode};

    let vetter_did = match resolve_holder(state, ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    if let Err(reject) = parse_checked_payload::<vetting_wire::vetters::resend::v0_1::Payload>(&doc)
    {
        return reject;
    }
    match crate::vetting::vetters::resend(state, &vetter_did, &vetter_did).await {
        Ok(response) => success_response(&doc, response),
        Err(AppError::NotFound(reason)) => reject_with_code(
            &doc,
            extended_code(vetting_wire::VETTING_VETTER_RESEND_ERR_NOT_GRANTED),
            reason,
            None,
        ),
        Err(AppError::ServiceError { status, message })
            if status == axum::http::StatusCode::SERVICE_UNAVAILABLE =>
        {
            reject_with_code(
                &doc,
                TrustTaskCode::Standard(StandardCode::Unavailable),
                message,
                None,
            )
        }
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── manifest (public by default) ──────────────────────────────────────────

/// Whether this caller is one the community can name.
///
/// Either proof of identity will do, because the two transports prove it
/// differently and both are real: over REST a signed document names its signer
/// (`verified_signer`), over DIDComm the authcrypt envelope names its sender
/// (`sender_did`). Requiring the REST form on a DIDComm caller — or the reverse
/// — would refuse a party the transport has already identified.
fn caller_is_identified(ctx: &JoinAuthCtx) -> bool {
    ctx.verified_signer.is_some() || ctx.sender_did.is_some()
}

/// Both manifest versions share one read; the version the document names
/// decides the shape of the answer.
///
/// Public unless the community has turned public discovery off, in which case
/// an unidentified caller is refused and an identified one is answered exactly
/// as before — see [`JoinDiscovery`](crate::community::profile::JoinDiscovery).
/// The refusal is `permissionDenied` with a sentence saying *how* to ask rather
/// than only that this failed: a client that reads "not public" and stops has
/// been told the wrong thing, because the same question over an identified
/// transport still answers.
async fn handle_manifest(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: ManifestVersion,
) -> TrustTaskOutcome {
    use crate::routes::join_requests::manifest::{manifest_v0_1, manifest_v0_2};
    if !caller_is_identified(ctx) {
        let public = match crate::community::join_discovery::load_join_discovery(
            &state.community_ks,
        )
        .await
        {
            Ok(setting) => setting.public,
            // A setting that cannot be read is not a reason to stop answering a
            // question that has always been public: failing open keeps a
            // storage fault from looking like a closed community, and the
            // manifest carries nothing that was not already published.
            Err(e) => {
                tracing::warn!(error = %e, "join discovery unreadable; answering the manifest");
                true
            }
        };
        if !public {
            return reject_with(
                &doc,
                RejectReason::PermissionDenied {
                    reason: "this community does not publish its join requirements to callers \
                             it cannot identify — ask over DIDComm, or with a signed Trust Task \
                             document"
                        .to_string(),
                },
            );
        }
    }
    let answer = match version {
        ManifestVersion::V0_1 => manifest_v0_1(state)
            .await
            .map(|r| success_response(&doc, r)),
        ManifestVersion::V0_2 => manifest_v0_2(state)
            .await
            .map(|r| success_response(&doc, r)),
    };
    answer.unwrap_or_else(|e| app_error_to_reject(&doc, &e))
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
/// `vtc/join-requests/withdraw/0.1` — the applicant closes their own request.
///
/// Holder-bound like `self-remove`: [`resolve_holder`] proves the caller
/// (authcrypt sender on DIDComm, document proof signer on REST) and refuses a
/// document whose `issuer` names anyone else. That proven identity *is* the
/// authorization — the spec's entitlement is ownership of the request, and an
/// applicant holds no membership or capability to check instead.
async fn handle_withdraw(
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
        Err(e @ AppError::NotFound(_)) => reject_with_code(
            &doc,
            extended_code(jr::JOIN_REQUEST_WITHDRAW_ERR_NOT_FOUND),
            e.to_string(),
            None,
        ),
        Err(e @ AppError::Gone(_)) => reject_with_code(
            &doc,
            extended_code(jr::JOIN_REQUEST_WITHDRAW_ERR_ALREADY_DECIDED),
            e.to_string(),
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

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

    fn error_doc(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("rejection is a framework error document")
    }

    /// A request document to reject from. Its own type is irrelevant — the
    /// rejection is built from the URI passed in, not from this.
    fn request_doc() -> TrustTask<Value> {
        let uri: trust_tasks_rs::TypeUri = jr::JOIN_REQUEST_MANIFEST_TYPE
            .parse()
            .expect("manifest uri");
        TrustTask::new("urn:uuid:test", uri, serde_json::json!({}))
    }

    /// A family split on its trailing version segment, nothing else.
    ///
    /// Written against synthetic paths: a `trusttasks.org/spec/` literal
    /// anywhere under `vtc-service/src` is read by `trust_task_manifest`'s
    /// census as an assertion that the registry publishes that task, and a
    /// test fixture is not one.
    #[test]
    fn task_family_strips_only_the_version_segment() {
        assert_eq!(
            task_family("scheme://host/spec/vtc/a/b/0.2"),
            Some("scheme://host/spec/vtc/a/b")
        );
        assert_eq!(task_family("no-slashes-at-all"), None);
    }

    /// A verb this VTC has never heard of still gets `unsupportedType`.
    ///
    /// The version arm must not swallow the plain case: "I do not implement
    /// this" and "I implement this at another version" are different answers
    /// and only the second is fixed by upgrading something.
    #[test]
    fn an_unknown_family_is_still_unsupported_type() {
        let outcome =
            unsupported_type_or_version(&request_doc(), "scheme://host/spec/vtc/nope/1.0");
        let doc = error_doc(outcome);
        assert_eq!(doc["payload"]["code"], "unsupportedType");
        assert!(doc["payload"]["details"].get("servedVersions").is_none());
    }

    /// A known family at an unknown version names the versions served.
    ///
    /// The VTC half of #1220. Its `spec/vtc/*` families are mid-migration, so
    /// a member client and a community can legitimately sit at different
    /// versions of the same verb — which makes a bare `unsupported type` read
    /// as "this community cannot do this" when it means "one of us is older".
    ///
    /// Built from `DISPATCHED_URIS` rather than a literal, so the fixture
    /// cannot claim a version this VTC does not serve.
    #[test]
    fn a_known_family_at_an_unknown_version_names_what_is_served() {
        let real = DISPATCHED_URIS
            .first()
            .expect("the dispatcher routes at least one URI");
        let family = task_family(real).expect("a task URI has a family");
        let bogus = format!("{family}/99.99");

        let doc = error_doc(unsupported_type_or_version(&request_doc(), &bogus));

        assert_eq!(doc["payload"]["code"], "unsupportedVersion");
        let message = doc["payload"]["message"].as_str().expect("a message");
        assert!(
            message.contains(real),
            "the message must name the served version; got {message}"
        );
        assert_eq!(doc["payload"]["details"]["servedVersions"][0], *real);
        assert_eq!(doc["payload"]["details"]["requestedType"], bogus);
    }

    /// The migration hint never names a *neighbouring* family.
    ///
    /// `join-requests/submit` and `join-requests/status` share a long prefix
    /// and are different verbs; offering one as the version to migrate onto
    /// would send a client at a task that cannot serve its request.
    #[test]
    fn a_neighbouring_family_is_not_offered_as_a_version() {
        let real = DISPATCHED_URIS
            .first()
            .expect("the dispatcher routes at least one URI");
        let family = task_family(real).expect("a task URI has a family");
        let bogus = format!("{family}/99.99");

        let doc = error_doc(unsupported_type_or_version(&request_doc(), &bogus));
        let served = doc["payload"]["details"]["servedVersions"]
            .as_array()
            .expect("servedVersions is an array");

        for entry in served {
            let uri = entry.as_str().expect("a URI string");
            assert_eq!(
                task_family(uri),
                Some(family),
                "{uri} is a different family and must not be offered as a version of {family}"
            );
        }
    }

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
            jr::JOIN_REQUEST_MANIFEST_0_2_TYPE,
            jr::JOIN_REQUEST_STATUS_TYPE,
            jr::JOIN_REQUEST_WITHDRAW_TYPE,
            jr::MEMBER_SELF_REMOVE_TYPE,
            mem::MEMBER_VMC_TYPE,
            vetting_wire::VETTING_REVOKE_STATEMENT_TYPE,
            vetting_wire::VETTING_VETTER_GRANT_TYPE,
            vetting_wire::VETTING_VETTER_PROFILE_TYPE,
            vetting_wire::VETTING_VETTER_LIST_TYPE,
            vetting_wire::VETTING_VETTER_RESEND_TYPE,
            <pc::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <pa::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ];
        // `rooms/*` is no longer checked here, because there is no longer a copy
        // to check.
        //
        // This assertion used to compare `DISPATCHED_URIS` against
        // `ROOMS_DISPATCHED_URIS` — two hand-maintained lists of the same fact,
        // which is exactly the shape that had already failed:
        // `rooms/records/curate` was dispatched by the `match` and named in
        // neither array, so the census passed while curate was missing from
        // every version hint this VTC emitted.
        //
        // The rooms family now routes through `rooms::handlers::dispatcher()`,
        // where the URI is derived from each registered payload type. The served
        // list *is* `registered_uris()`, so there is nothing for a census to
        // disagree with — and `rooms_dispatcher_serves_every_wire_uri` below
        // holds the one claim that still needs holding: that the registrations
        // cover the family.
        for u in DISPATCHED_URIS {
            assert!(
                declared.contains(u),
                "dispatched URI is not a declared request URI: {u}"
            );
        }
        assert_eq!(DISPATCHED_URIS.len(), declared.len());
    }

    /// The rooms dispatcher serves every URI `vti_rooms` puts on the wire.
    ///
    /// The one thing registration-by-type cannot check for itself: that no verb
    /// was *forgotten*. A missing `.on_async` is silent — the task simply is not
    /// served — so this compares the dispatcher's own list against the family's
    /// wire constants, which `vti-rooms/tests/schema_conformance.rs` in turn
    /// pins against the published `TYPE_URI`s.
    #[test]
    fn rooms_dispatcher_serves_every_wire_uri() {
        let served = crate::rooms::handlers::served_uris();
        for uri in vti_rooms::wire::ROOMS_DISPATCHED_URIS {
            assert!(
                served.contains(uri),
                "`{uri}` is on the wire but no handler is registered for it — a \
                 client would be told it is unsupported at every version"
            );
        }
        assert_eq!(
            served.len(),
            vti_rooms::wire::ROOMS_DISPATCHED_URIS.len(),
            "the dispatcher serves something the wire module does not name: {served:?}"
        );
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

        /// **Every success response carries this community's proof.**
        ///
        /// SPEC §7.3 item 7: a specification declaring a single
        /// `proofRequirement: REQUIRED` binds its *response* as well as its
        /// request — "an omission can never weaken a variant" — and 265
        /// published specifications declare exactly that. This service attached
        /// a proof to none of them until the spine started signing.
        ///
        /// Nothing caught it because no consumer verifies one either, which is
        /// why the guard is here rather than left to a client: a mutually
        /// consistent silence between producer and consumer stays silent.
        #[tokio::test]
        async fn a_success_response_is_signed() {
            let vtc = fixture().await;
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(MEMBER.into()),
                &document(PERSONHOOD_CHALLENGE_TYPE, json!({ "did": MEMBER })),
            )
            .await;

            let doc: serde_json::Value =
                serde_json::from_slice(&out.body).expect("the reply is a JSON document");
            let proof = doc.get("proof").unwrap_or_else(|| {
                panic!(
                    "a success response carries no proof, so nothing this community says is \
                     attributable: {}",
                    rendered(&out)
                )
            });
            assert_eq!(
                proof.get("cryptosuite").and_then(|v| v.as_str()),
                Some("eddsa-jcs-2022"),
                "unexpected cryptosuite: {proof}"
            );
            assert!(
                proof.get("proofValue").and_then(|v| v.as_str()).is_some(),
                "the proof carries no signature: {proof}"
            );
        }

        /// A community with no signer answers **unsigned rather than failing**.
        ///
        /// It has nothing to sign with, and refusing would make an
        /// unprovisioned VTC unusable rather than merely unattributable — the
        /// wrong direction to err in, since the operation itself succeeded.
        #[tokio::test]
        async fn a_community_with_no_signer_still_answers() {
            let vtc = TestVtc::builder().with_signers(false).build().await;
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
            .expect("seed the member");

            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(MEMBER.into()),
                &document(PERSONHOOD_CHALLENGE_TYPE, json!({ "did": MEMBER })),
            )
            .await;

            assert!(
                out.status.is_success(),
                "an unsigned answer is still an answer: {}",
                rendered(&out)
            );
            let doc: serde_json::Value =
                serde_json::from_slice(&out.body).expect("the reply is a JSON document");
            assert!(doc.get("proof").is_none(), "signed without a signer");
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
