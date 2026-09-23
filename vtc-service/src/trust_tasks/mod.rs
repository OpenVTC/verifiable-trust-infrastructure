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
//! `manifest` is public. `present` belongs to the `credential-exchange` family
//! and is handled there.
//!
//! **Administrator verbs are routed here too**, since #1641 phase 2 — the
//! admin-facing member verbs were the first batch, `join-requests/decide` and
//! `community/profile/update` the second. Their authority is not a bearer
//! token (this endpoint reads none) but the **verified signer's ACL entry**,
//! read at execution time; see [`admin_signer`]. The remaining operator-facing
//! verbs (`list`, `show`, the config and backup pairs, …) are still served
//! only on their JWT-gated REST routes, and moving them is what the rest of
//! phase 2 is.
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

// The accepted-document-id record (VTI-OPS-025…027). `pub(crate)` because
// VTI-OPS-027 makes it every binding's, not this spine's: the dispatcher below
// is its first caller, a bearer REST route is its second (#1641 phase 2).
pub(crate) mod accepted_ids;

// The schema-conformance sweep (#1059): every bound, published `spec/vtc/*`
// URI must speak that URI's wire shape. Lives in `src` rather than `tests`
// because its census is derived from `DISPATCHED_URIS` below, which no
// integration test can see.
#[cfg(test)]
mod conformance;

// The declared-error-code census (#1600): every extended error code a bound,
// published `spec/vtc/*` task declares must be witnessed by a test that
// observes the service emitting it. Derived from the same census as
// `conformance`, and from `trust_tasks_rs::schema_index::error_codes_for`.
#[cfg(test)]
mod error_code_census;

use serde_json::Value;
use trust_tasks_rs::specs::vtc::members::personhood::{assert::v0_1 as pa, challenge::v0_1 as pc};
// The admin-facing member verbs (#1641 phase 2). Their wire types are
// generated from the published schemas, so there is no hand-written SDK
// constant to import and the Type URIs below are read off the payload types.
use trust_tasks_rs::specs::vtc::members::{
    admin_remove::v0_1 as member_admin_remove, credentials::v0_1 as member_credentials,
    purge::v0_1 as member_purge, update::v0_1 as member_update,
};
// The admin verbs #1641 phase 2 batch 2 moved: the join decision and the
// community profile edit. Same story — generated wire types, Type URIs read
// off the payload types.
use trust_tasks_rs::specs::vtc::community::profile::update::v0_1 as community_profile_update;
use trust_tasks_rs::specs::vtc::join_requests::decide::v0_1 as join_decide;
use trust_tasks_rs::{RejectReason, TrustTask};

use vta_sdk::protocols::trust_task_reject_reasons as reasons;
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
    app_error_to_reject, body_parse_error_response, extended_code, parse_payload, reject_with,
    reject_with_code, reject_with_code_because, success_response, task_error_to_reject,
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
    ///
    /// The envelope arm builds its context field by field, because an
    /// unauthenticated sender there is `None` rather than a refusal; this
    /// shorthand is for a caller that already holds a proven DID.
    #[allow(dead_code)]
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

/// The transport-neutral dispatch spine. Parses the document, holds it to the
/// specification it names, then routes by `type` to the matching verb handler.
///
/// In order: the acceptance window over `issuedAt` (VTI-OPS-024), expiry and
/// the recipient binding (VTI-OPS-023), the flag-driven rules the
/// specification itself declares — `proof`, `recipient` and `issuedAt`
/// REQUIRED, and audience binding (VTI-OPS-020, VTI-OPS-021), verification of
/// any `proof` present against the document's own `issuer`, and the
/// duplicate-execution record (VTI-OPS-025…027). Every one of them is reached
/// identically from REST, DIDComm and TSP, which is VTI-OPS-021's point.
///
/// Every one of those checks is unconditional. There is no configuration that
/// relaxes any of them — `docs/05-design-notes/vtc-trust-task-proof-enforcement.md`
/// has the whole argument, including the one transitional allowance #1641
/// shipped with and why it is gone.
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

    // One instant for every temporal decision in this dispatch. The acceptance
    // window and the replay record's retention are the *same* bound (SPEC
    // §7.2, *Bounding the record*), so reading the clock twice could place
    // them on opposite sides of it.
    let now = chrono::Utc::now();

    // 2. Framework §7.2 item 13 — the timestamp bounds, and VTI-OPS-024's
    //    acceptance window. Checked first because it is decided from the
    //    document alone, before any resolution, verification or execution
    //    work, and because one of its rules changes how the other reads.
    if let Err(reason) = doc.validate_freshness(now, &freshness_policy()) {
        return reject_with(&doc, reason);
    }

    // 2b. Framework §7.2 items 4 + 5 — expiry + recipient enforcement. The
    //    recipient binding (document `recipient` must equal this VTC's DID) is
    //    the replay defence that the bespoke `audience` field used to provide.
    //    Skipped while the VTC has no DID configured (setup).
    let vtc_did = state.config.read().await.vtc_did.clone();
    if let Some(vtc_did) = vtc_did
        && let Err(reason) = doc.validate_basic(now, &vtc_did)
    {
        return reject_with(&doc, reason);
    }

    let type_uri = doc.type_uri.to_string();

    // 2c. SPEC §7.2's *flag-driven* checks — the ones the published
    //    specification declares rather than this consumer chooses:
    //
    //    * item 5b — `recipient` REQUIRED
    //    * item 7a — `proof` REQUIRED  → `proofRequired`
    //    * item 8  — audience binding (proof present, no in-band recipient, on
    //                a non-bearer specification)
    //    * §7.3 17 — `issuedAt` REQUIRED
    //
    // ## Why this is here now, and what it replaces
    //
    // Until #1641 this spine verified a proof whenever one was present and
    // otherwise took attribution from the transport — including for the nine
    // dispatched tasks whose own definitions declare `proof` REQUIRED. The
    // comment that stood here argued the transport had already proved the
    // sender, so demanding a proof would refuse every join over DIDComm and
    // TSP.
    //
    // That argument is refused by three documents at once, and none of them is
    // ambiguous:
    //
    // - **VTI-OPS-021 / VTI-OPS-093.** "A node MUST apply the same document
    //   requirements on every transport. A transport that authenticates its
    //   sender MUST NOT be treated as relieving a producer of addressing or
    //   signing the document it sends." A binding may not weaken the
    //   requirement on the strength of a transport property.
    // - **The DIDComm binding's own §5.** "A *Trust Task specification* that
    //   declares `proof` as REQUIRED overrides this binding-level allowance:
    //   the in-band `proof` is mandatory regardless of transport, because such
    //   specifications produce documents intended to be replayable past the
    //   original transport hop." The allowance the old rule leaned on is
    //   disclaimed by the very binding that grants it.
    // - **That binding's §6**, on where the guarantee stops: "At the message.
    //   The envelope is discarded on unwrap, and the guarantee does not travel
    //   with the document." Authcrypt tells this service who handed it the
    //   bytes. It leaves nothing behind that a third party — an auditor, a
    //   registry, the member themselves — could check afterwards.
    //
    // Read off `spec_policy_for`, never a list kept here: a list of URIs whose
    // requirement is published elsewhere is a list that drifts, and the
    // requirement moves when the specification does.
    //
    // The policy is enforced **as the registry states it**. #1641 shipped with
    // one transitional narrowing — `require_declared_proof = false` cleared
    // `is_proof_required` where the transport had authenticated the sender,
    // because `openvtc-core` sent five of these documents unsigned. openvtc#371
    // signs them, which was that switch's stated removal condition, so the
    // narrowing and the config key are gone. Nothing may reintroduce a
    // per-deployment relaxation here: VTI-OPS-093 forbids a binding weakening a
    // document requirement on a transport property, and a switch that lets an
    // operator do it is the same weakening with a longer path.
    //
    // `None` means this build knows no specification for the URI. The
    // dispatcher refuses an unrouted URI a few lines below
    // (`unsupported_type_or_version`), so there is no silently-unchecked task
    // here — only tasks whose definitions this build cannot read, which is the
    // `rooms/*`-shaped case the arms guard for themselves.
    if let Some(policy) = trust_tasks_rs::schema_index::spec_policy_for(&type_uri)
        && let Err(reason) = policy.enforce(&doc)
    {
        tracing::info!(
            type_uri,
            ?reason,
            "document refused by its specification's own policy"
        );
        return reject_with(&doc, reason);
    }

    // 3. Framework §7.2 item 7, *first* clause — the proof, verified here
    //    against the document **as received**, because this is the last point
    //    at which those bytes exist: past dispatch a handler holds a payload
    //    that may have dropped a member it does not know, and canonicalising
    //    that yields different bytes and refuses a valid proof.
    //
    //    §4.7 binds the proof to the in-band `issuer`: the `verificationMethod`
    //    "MUST resolve to verification material controlled by the *party*
    //    identified by the document's `issuer` member". A valid proof by some
    //    *other* DID is not a proof by the issuer, and without this check the
    //    signature would establish only that somebody signed something —
    //    which is not what `verified_signer` is read as downstream.
    let ctx = if doc.proof.is_some() {
        match verify_trust_task_proof(state, &doc).await {
            Ok(signer) => {
                if doc.issuer.as_deref() != Some(signer.as_str()) {
                    tracing::warn!(
                        type_uri,
                        issuer = ?doc.issuer,
                        %signer,
                        "proof verifies under a key the document's issuer does not control"
                    );
                    return reject_with(
                        &doc,
                        RejectReason::ProofInvalid {
                            reason: "the proof's verificationMethod does not belong to the \
                                     document's issuer (SPEC §4.7)"
                                .to_string(),
                        },
                    );
                }
                &ctx.with_verified_signer(Some(signer))
            }
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
    // The record is digest-keyed, so a *different* document arriving under an
    // already-spent `id` is `idConflict` rather than being silently absorbed as
    // a retry, and it claims before dispatch, so two simultaneous deliveries
    // cannot both pass a check-then-act test.
    //
    // It lives in the store, not in this process, because **VTI-OPS-027**
    // requires the record to be shared across every binding this node exposes
    // — see [`accepted_ids`]. The dispatcher is its first caller; the bearer
    // REST routes #1641 phase 2 migrates are its second, and they must be able
    // to consult the same rows, or replay protection is defeated by presenting
    // the document at the other door.
    //
    // Placed after the proof check so an unauthenticated flood cannot spend
    // another sender's ids, matching where the webvh control plane puts its own
    // gate and for the same reason.
    let claim = match state
        .accepted_ids()
        .claim(&doc, retain_until(&doc, now), now)
        .await
    {
        Ok(accepted_ids::Acceptance::Fresh(claim)) => claim,
        Ok(accepted_ids::Acceptance::Duplicate {
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
        Ok(accepted_ids::Acceptance::Conflict) => {
            return reject_with(&doc, RejectReason::IdConflict);
        }
        // Fail closed. A consumer that cannot establish whether a document is a
        // duplicate has not satisfied item 11, so it must not execute — and
        // `unavailable` is retryable, which is the truthful signal.
        //
        // `Acceptance` is this crate's own enum rather than the library's
        // `#[non_exhaustive] ReplayVerdict`, so the arm that used to catch a
        // verdict this build did not know is gone: a new variant here is a
        // compile error at this match, which is the stronger form of the same
        // guard.
        Err(e) => return reject_with(&doc, e.reject_reason()),
    };

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
    if outcome.status.is_success() {
        let recorded = serde_json::from_slice::<serde_json::Value>(&outcome.body).ok();
        claim.completed(recorded.as_ref()).await;
    } else {
        claim.release().await;
    }

    outcome
}

/// The acceptance window this VTC is willing to act inside — **VTI-OPS-024**,
/// SPEC §7.2 item 13, and the bound the accepted-id record's retention is
/// derived from.
///
/// # Acceptance and retention are one bound
///
/// This used to be a `retention_policy()` whose documentation said, in terms,
/// "**retention only** — this is not an acceptance policy and must not become
/// one", because many of this service's producers stamped no `issuedAt`. §7.2
/// (*Bounding the record*) makes that separation unavailable: a consumer
/// "**MUST NOT** accept for execution a document older than the window over
/// which it retains records", and one that "can establish neither an
/// `expiresAt` nor an age for a document has no window in which to place it,
/// and **MUST NOT** execute a *consequential Trust Task* on it". A record kept
/// for a window nothing is measured against is a record whose horizon is
/// capacity eviction, which makes the defence weakest exactly when the service
/// is busiest.
///
/// # Why ten minutes, and 60 seconds of skew
///
/// The library's `DEFAULT_MAX_AGE` is five minutes, "long enough to survive a
/// mediator queue, a retry with backoff, and a modest clock disagreement".
/// This service reaches members through a mediator that holds messages while a
/// recipient reconnects, so it takes double that — the same window
/// `vta-service` settled on, for the same reason, so a document that one
/// accepts is not stale at the other. The skew tolerance is the library's
/// `DEFAULT_SKEW`, 60 seconds, which is SPEC §4.2's own "typically ≤ 60s".
///
/// # Why `issuedAt` is required, and what that costs
///
/// Without it two shapes escape the window. A document carrying neither
/// timestamp is refused anyway — as `Stale { Unboundable }`, which renders as
/// the wire code `expired`, telling a producer to wait when what it must do is
/// reissue with the member it omitted. And a document carrying only
/// `expiresAt` is accepted for however long its *producer* chose, which would
/// let the producer decide how long this consumer must remember its `id`.
/// Requiring `issuedAt` makes the last instant an accepted document can return
/// provable — `issuedAt + max_age + skew` — which is what [`retain_until`]
/// caps on.
///
/// The cost is exact: the one shape that moves from accepted to refused is
/// **`expiresAt` present, `issuedAt` absent**. Every VTI producer stamps
/// `issuedAt` (`vta_sdk::trust_task_sign::build_unsigned`, and
/// `VtaClient::dispatch_trust_task` for every transport), and 52 of the 95
/// specifications this service binds declare the member REQUIRED in any case.
fn freshness_policy() -> trust_tasks_rs::FreshnessPolicy {
    trust_tasks_rs::FreshnessPolicy::default()
        .with_max_age(chrono::TimeDelta::minutes(10))
        .requiring_issued_at()
}

/// How long the duplicate-execution record for `doc` must be kept — the end of
/// this consumer's willingness to execute it, which SPEC §7.2 makes the same
/// instant as the end of the record's required retention.
///
/// `FreshnessPolicy::record_expiry` takes a producer-supplied `expiresAt`
/// **verbatim**, so a document stamped `expiresAt = now + 10 years` would pin
/// its `id` in the accepted-id record for ten years — an entry held long past
/// the last moment it could be needed, crowding out the records that are.
/// `requiring_issued_at` above makes the cap provable: a document with no
/// `issuedAt` never reaches here, and one that did reach here is refused once
/// `issuedAt + max_age + skew` has passed.
///
/// The cap only ever moves the instant **earlier than a producer asked for**,
/// never earlier than the acceptance window. Shortening retention below the
/// window is the direction §7.2 forbids: a replay arriving while the document
/// is still acceptable, with its record already dropped, executes twice.
fn retain_until(
    doc: &TrustTask<Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let policy = freshness_policy();
    let expiry = policy.record_expiry(doc, now)?;
    match (doc.issued_at, policy.max_age) {
        (Some(issued_at), Some(max_age)) => Some(expiry.min(issued_at + max_age + policy.skew)),
        // Unreachable while `require_issued_at` holds; if that ever changes,
        // over-retaining is the safe direction to fail in.
        _ => Some(expiry),
    }
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
    // Since #1641 the spine refuses a proof-less `rooms/*` document before this
    // arm is reached, because every one of them declares `proof` REQUIRED and
    // `spec_policy_for` is now enforced — so this guard is belt to that brace.
    // It stays: `verified_signer` is `Option`, and defaulting to an empty
    // presenter would authorize a room operation against nobody.
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
        jr::JOIN_REQUEST_SUPPLEMENT_TYPE => handle_supplement(state, ctx, doc).await,
        jr::MEMBER_SELF_REMOVE_TYPE => handle_self_remove(state, ctx, doc).await,
        mem::MEMBER_VMC_TYPE => handle_member_vmc(state, ctx, doc).await,
        vetting_wire::VETTING_REVOKE_STATEMENT_TYPE => {
            handle_revoke_statement(state, ctx, doc).await
        }
        vetting_wire::VETTING_VETTER_GRANT_TYPE => handle_vetter_grant(state, ctx, doc).await,
        vetting_wire::VETTING_VETTER_PROFILE_TYPE => handle_vetter_profile(state, ctx, doc).await,
        vetting_wire::VETTING_VETTER_LIST_TYPE => handle_vetter_list(state, ctx, doc).await,
        vetting_wire::VETTING_VETTER_SHOW_TYPE => handle_vetter_show(state, ctx, doc).await,
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
        // The admin-facing member verbs. Each is authorized from the verified
        // signer's ACL entry — never from a bearer token, which this endpoint
        // does not read — see [`admin_signer`].
        MEMBER_CREDENTIALS_TYPE => handle_member_credentials(state, ctx, doc).await,
        MEMBER_UPDATE_TYPE => handle_member_update(state, ctx, doc).await,
        MEMBER_ADMIN_REMOVE_TYPE => handle_member_admin_remove(state, ctx, doc).await,
        MEMBER_PURGE_TYPE => handle_member_purge(state, ctx, doc).await,
        JOIN_DECIDE_TYPE => handle_join_decide(state, ctx, doc).await,
        COMMUNITY_PROFILE_UPDATE_TYPE => handle_community_profile_update(state, ctx, doc).await,
        other => unsupported_type_or_version(&doc, other),
    }
}

/// The spine's document-level gate: VTI-OPS-020 (a proof by the issuer),
/// VTI-OPS-021 / -093 (the same requirements on every transport), VTI-OPS-024
/// (the acceptance window) and VTI-OPS-025…027 (the replay record).
///
/// # What this module used to say, and why it no longer does
///
/// It held one test, `a_transport_authenticated_task_declares_a_proof_it_does_
/// not_carry`, whose assertion was deliberately inverted: it recorded that
/// `join-requests/submit` declares a proof REQUIRED *while this service accepts
/// it without one*, so that "the next person to reach for `spec_policy_for` as
/// an enforcement gate meets it as a failing test rather than as a total
/// outage."
///
/// The warning was right about the consequence and wrong about the conclusion.
/// Three documents refuse the leniency outright — VTI-OPS-021, VTI-OPS-093, and
/// the DIDComm binding's own §5 ("a *Trust Task specification* that declares
/// `proof` as REQUIRED overrides this binding-level allowance"). So the gate is
/// now the specification's, and the outage it predicted was real for exactly
/// one client: `openvtc-core`, which sent five of these documents unsigned.
///
/// #1641 met that by gating the refusal behind `[trust_tasks]
/// require_declared_proof`, default `false`, whose rustdoc carried an exact
/// removal condition — "when `openvtc-core` signs the five documents above, the
/// default flips and this field goes with it". openvtc#371 signs them, so the
/// gate is gone and every test here now asserts against the requirement
/// directly, on all three transports.
///
/// See `docs/05-design-notes/vtc-trust-task-proof-enforcement.md`.
#[cfg(test)]
mod spine_proof_tests {
    use super::*;
    use crate::test_support::{TEST_VTC_DID, build_test_vtc};
    use serde_json::json;

    // One holder: a `did:key` and the private key behind it, minted the same
    // way the rooms fixtures mint theirs.
    use vti_rooms_dtg::test_support::Party as Holder;

    fn holder() -> Holder {
        Holder::new()
    }

    /// The unsigned document, exactly as it goes on the wire minus the proof.
    /// `build_unsigned` is the SDK's own builder, so `issuer`, `recipient` and
    /// `issuedAt` are set the way every real producer sets them and the tests
    /// vary only what they mean to.
    fn unsigned(h: &Holder, uri: &str, payload: Value) -> TrustTask<Value> {
        vta_sdk::trust_task_sign::build_unsigned(uri, payload, &h.did, TEST_VTC_DID)
            .expect("build the document")
    }

    async fn signed(h: &Holder, doc: TrustTask<Value>) -> TrustTask<Value> {
        let mut doc = doc;
        let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&h.did, &h.secret_multibase)
            .expect("a did:key names its own verification method");
        vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
            .await
            .expect("sign the document");
        doc
    }

    /// The `code` of the `trust-task-error` an outcome carries, or `None` when
    /// the outcome is not an error document.
    fn error_code(out: &TrustTaskOutcome) -> Option<String> {
        let doc: Value = serde_json::from_slice(&out.body).ok()?;
        doc.pointer("/payload/code")?.as_str().map(str::to_string)
    }

    async fn dispatch(state: &AppState, doc: &TrustTask<Value>) -> TrustTaskOutcome {
        let body = serde_json::to_vec(doc).expect("a document serialises");
        dispatch_trust_task_core(state, &JoinAuthCtx::rest(), &body).await
    }

    /// The URI these tests drive. `vtc/join-requests/status/0.1` declares
    /// `proof` REQUIRED and needs no seeded community state to reach its
    /// handler, so what the spine does is the only thing that varies.
    const UNDER_TEST: &str = jr::JOIN_REQUEST_STATUS_TYPE;

    /// The premise the rest of this module rests on. If the registry ever
    /// relaxes the declaration, these tests are asserting nothing and this one
    /// says so first.
    #[test]
    fn the_task_under_test_declares_a_proof_required() {
        let policy = trust_tasks_rs::schema_index::spec_policy_for(UNDER_TEST)
            .expect("the task under test has a published spec policy");
        assert!(
            policy.is_proof_required,
            "{UNDER_TEST} no longer declares proof REQUIRED — these tests now \
             assert nothing, and the design note should be re-read"
        );
    }

    /// **VTI-OPS-020 / VTI-OPS-021.** A task whose specification declares
    /// `proof` REQUIRED is refused when it carries none, with the framework's
    /// own code for exactly that.
    #[tokio::test]
    async fn vti_ops_020_a_proof_required_task_is_refused_without_a_proof() {
        let tv = build_test_vtc().await;
        let h = holder();
        let out = dispatch(&tv.state, &unsigned(&h, UNDER_TEST, json!({}))).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "SPEC §7.2 item 7 names the code: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// …and accepted with one. "Accepted" here means the spine let it through
    /// to the handler, which is the whole of what the spine decides — the
    /// handler then answers for a status poll on a request that does not
    /// exist, and that answer is not this module's business.
    #[tokio::test]
    async fn vti_ops_020_the_same_document_is_accepted_once_it_is_signed() {
        let tv = build_test_vtc().await;
        let h = holder();
        let doc = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;
        let out = dispatch(&tv.state, &doc).await;

        assert_ne!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "a signed document must reach its handler: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_ne!(
            error_code(&out).as_deref(),
            Some("proofInvalid"),
            "the spine must accept a proof it can verify: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// **VTI-OPS-020.** SPEC §4.7: the proof's `verificationMethod` "MUST
    /// resolve to verification material controlled by the *party* identified by
    /// the document's `issuer`". A valid signature by some *other* holder is
    /// not a proof by the issuer, and before #1641 it satisfied the
    /// requirement — establishing only that somebody signed something, which is
    /// not what `verified_signer` is read as downstream.
    #[tokio::test]
    async fn vti_ops_020_a_proof_by_a_key_the_issuer_does_not_control_is_refused() {
        let tv = build_test_vtc().await;
        let issuer = holder();
        let impostor = holder();

        // Addressed from `issuer`, signed by `impostor`.
        let doc = signed(&impostor, unsigned(&issuer, UNDER_TEST, json!({}))).await;
        let out = dispatch(&tv.state, &doc).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("proofInvalid"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// **VTI-OPS-024.** A document issued longer ago than the acceptance
    /// window is outside it, and `expired` is the code for a document that was
    /// once acceptable and no longer is.
    #[tokio::test]
    async fn vti_ops_024_an_issued_at_older_than_the_window_is_refused() {
        let tv = build_test_vtc().await;
        let h = holder();
        let mut doc = unsigned(&h, UNDER_TEST, json!({}));
        doc.issued_at = Some(chrono::Utc::now() - chrono::TimeDelta::hours(2));
        let doc = signed(&h, doc).await;

        assert_eq!(
            error_code(&dispatch(&tv.state, &doc).await).as_deref(),
            Some("expired"),
        );
    }

    /// **VTI-OPS-024**, the other end of the window, and the skew tolerance
    /// that bounds it. SPEC §7.2 item 13 makes a future-dated document
    /// `malformedRequest` rather than `expired`: it was never acceptable, so
    /// telling the producer to wait would be wrong — it must reissue.
    #[tokio::test]
    async fn vti_ops_024_a_future_dated_issued_at_is_malformed_not_expired() {
        let tv = build_test_vtc().await;
        let h = holder();
        let mut doc = unsigned(&h, UNDER_TEST, json!({}));
        doc.issued_at = Some(chrono::Utc::now() + chrono::TimeDelta::minutes(30));
        let doc = signed(&h, doc).await;

        assert_eq!(
            error_code(&dispatch(&tv.state, &doc).await).as_deref(),
            Some("malformedRequest"),
        );
    }

    /// …and a document inside the skew tolerance is not. 30 seconds ahead of
    /// this consumer's clock is an ordinary clock disagreement, and refusing it
    /// would make the window depend on whose NTP is better.
    #[tokio::test]
    async fn vti_ops_024_a_document_inside_the_skew_tolerance_is_accepted() {
        let tv = build_test_vtc().await;
        let h = holder();
        let mut doc = unsigned(&h, UNDER_TEST, json!({}));
        doc.issued_at = Some(chrono::Utc::now() + chrono::TimeDelta::seconds(30));
        let doc = signed(&h, doc).await;
        let out = dispatch(&tv.state, &doc).await;

        assert_ne!(
            error_code(&out).as_deref(),
            Some("malformedRequest"),
            "60s of skew is SPEC §4.2's own tolerance: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// Give `h` an open join request, so a status poll from them **succeeds**.
    ///
    /// The replay tests below need that: the spine releases a claim whose
    /// dispatch failed — deliberately, so a corrected resend under the same
    /// `id` is not refused as a conflict for the rest of the retention window
    /// — and a test driving a failing task would therefore assert against a
    /// record that was never kept.
    async fn seed_open_request(state: &AppState, h: &Holder) {
        let request =
            crate::join::JoinRequest::new(h.did.clone(), serde_json::json!({ "vp": "x" }));
        crate::join::storage::store_join_request(&state.join_requests_ks, &request)
            .await
            .expect("seed an open join request");
    }

    /// **VTI-OPS-020's replay half (VTI-OPS-025…027), SPEC §7.2 item 11.** The
    /// same document delivered twice executes once. A duplicate is answered
    /// with the original result rather than an error — "in no case is a
    /// duplicate reported as `taskFailed`; the task did not fail, it already
    /// happened" — so the assertion is that the second answer is the first.
    ///
    /// Compared as parsed JSON rather than as bytes: the duplicate path
    /// re-serialises the recorded `Value`, and `serde_json` without
    /// `preserve_order` alphabetises a `Map`'s keys, so the two are the same
    /// document and not the same bytes.
    #[tokio::test]
    async fn vti_ops_025_a_replayed_document_is_answered_not_executed_again() {
        let tv = build_test_vtc().await;
        let h = holder();
        seed_open_request(&tv.state, &h).await;
        let doc = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;

        let first = dispatch(&tv.state, &doc).await;
        assert!(
            first.status.is_success(),
            "the fixture must reach a succeeding handler, or the claim is \
             released and the second dispatch runs fresh: {}",
            String::from_utf8_lossy(&first.body)
        );

        let second = dispatch(&tv.state, &doc).await;
        assert_eq!(first.status, second.status);

        let as_json = |out: &TrustTaskOutcome| -> Value {
            serde_json::from_slice(&out.body).expect("the answer is a document")
        };
        assert_eq!(
            as_json(&first),
            as_json(&second),
            "a redelivery is the same document, so it gets the same answer"
        );
    }

    /// **SPEC §7.2 item 11's conflict half.** A *different* document under an
    /// already-spent `id` is `idConflict`, never absorbed as a retry — which is
    /// why the record is keyed by digest rather than by `id` alone.
    #[tokio::test]
    async fn vti_ops_025_a_different_document_reusing_an_id_is_a_conflict() {
        let tv = build_test_vtc().await;
        let h = holder();
        seed_open_request(&tv.state, &h).await;

        let first = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;
        let out = dispatch(&tv.state, &first).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        // Same `id`, different content: a different document, not a retry.
        let mut second = unsigned(&h, UNDER_TEST, json!({}));
        second.id = first.id.clone();
        second.issued_at = Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1));
        let second = signed(&h, second).await;

        assert_eq!(
            error_code(&dispatch(&tv.state, &second).await).as_deref(),
            Some("idConflict"),
        );
    }

    /// **VTI-OPS-024 + VTI-OPS-026.** Acceptance and retention are one bound.
    /// `record_expiry` takes a producer-supplied `expiresAt` verbatim, so
    /// without the cap a document stamped ten years out would pin its `id`
    /// for ten years — retention long past the last instant the document could
    /// still be accepted, crowding out the records that can be drawn on.
    #[test]
    fn vti_ops_026_retention_is_capped_at_the_end_of_the_acceptance_window() {
        let h = holder();
        let now = chrono::Utc::now();
        let mut doc = unsigned(&h, UNDER_TEST, json!({}));
        doc.issued_at = Some(now);
        doc.expires_at = Some(now + chrono::TimeDelta::days(3650));

        let policy = freshness_policy();
        let until = retain_until(&doc, now).expect("a document with an issuedAt is boundable");

        assert_eq!(
            until,
            now + policy.max_age.expect("the window is set") + policy.skew,
            "retention may not outlast the window in which the document is \
             still executable"
        );
    }

    /// …and it never moves the instant *earlier* than that window. Shortening
    /// retention below acceptance is the direction §7.2 forbids: a replay
    /// arriving while the document is still acceptable, with its record
    /// already dropped, executes twice.
    #[test]
    fn vti_ops_026_a_short_expiry_does_not_shorten_retention_below_the_window() {
        let h = holder();
        let now = chrono::Utc::now();
        let mut doc = unsigned(&h, UNDER_TEST, json!({}));
        doc.issued_at = Some(now);
        doc.expires_at = Some(now + chrono::TimeDelta::seconds(30));

        let until = retain_until(&doc, now).expect("boundable");
        assert_eq!(
            until,
            now + chrono::TimeDelta::seconds(30),
            "a producer that says its document lapses in 30s has said the \
             record may be dropped then — it is unacceptable after that too"
        );
    }

    /// **VTI-OPS-021 / VTI-OPS-093.** One unsigned document, offered on every
    /// transport this service accepts, refused on every one of them.
    ///
    /// # Why this replaced three tests, and why the conclusion moved
    ///
    /// #1641 shipped this ground as three: a REST document was refused; the
    /// same document over DIDComm, carrying an authcrypt sender, was
    /// **accepted** under the shipped default; and it was refused once the
    /// operator set `[trust_tasks] require_declared_proof = true`. The middle
    /// one existed to pin a transitional allowance, so that flipping the
    /// default would be "a visible change to a test rather than a silent
    /// change in behaviour". This is that change, made visible.
    ///
    /// The allowance had exactly one reason: `openvtc-core` built
    /// `join-requests/{submit,status}`, `members/{self-remove,vmc}` and
    /// `members/personhood/assert` with no proof attached. openvtc#371 signs
    /// all five, which is the removal condition #1659 wrote down. So the
    /// assertion is not relaxed to match the code — it is inverted to match a
    /// requirement that never had a transport term in it: "a node MUST apply
    /// the same document requirements on every transport", and a transport that
    /// authenticates its sender "MUST NOT be treated as relieving a producer of
    /// addressing or signing the document it sends".
    ///
    /// Driving all three transports from one body is the point rather than
    /// thoroughness: the old tests each asserted about a single transport, so
    /// between them they could have agreed with VTI-OPS-021 on two and
    /// disagreed on the third without anything noticing.
    #[tokio::test]
    async fn vti_ops_021_a_missing_proof_is_refused_on_every_transport() {
        let tv = build_test_vtc().await;
        let h = holder();
        let body =
            serde_json::to_vec(&unsigned(&h, UNDER_TEST, json!({}))).expect("serialise document");

        for ctx in [
            JoinAuthCtx::rest(),
            JoinAuthCtx::didcomm(h.did.clone()),
            // TSP, whose sender VID is authenticated the way authcrypt's sender
            // is. It has no constructor — the messaging bridge builds one
            // inline — so this is that shape, written out.
            JoinAuthCtx {
                transport: JoinTransport::Tsp,
                sender_did: Some(h.did.clone()),
                verified_signer: None,
            },
        ] {
            let transport = ctx.transport.as_str();
            let out = dispatch_trust_task_core(&tv.state, &ctx, &body).await;

            assert_eq!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{transport}: an authenticated sender is not a proof by the issuer: {}",
                String::from_utf8_lossy(&out.body),
            );
        }
    }

    /// …and the refusal is about the missing proof, not about the transport.
    ///
    /// Without this, the test above would pass equally on a spine that refused
    /// every DIDComm and TSP document outright — which is a way of satisfying
    /// "the same requirements on every transport" that takes the community
    /// offline. Each iteration signs a fresh document: the same one dispatched
    /// three times is a replay, and the second answer would be a replay of the
    /// first rather than a new decision.
    #[tokio::test]
    async fn vti_ops_021_the_same_document_signed_is_accepted_on_every_transport() {
        let tv = build_test_vtc().await;
        let h = holder();

        for ctx in [
            JoinAuthCtx::rest(),
            JoinAuthCtx::didcomm(h.did.clone()),
            JoinAuthCtx {
                transport: JoinTransport::Tsp,
                sender_did: Some(h.did.clone()),
                verified_signer: None,
            },
        ] {
            let transport = ctx.transport.as_str();
            let doc = signed(&h, unsigned(&h, UNDER_TEST, json!({}))).await;
            let body = serde_json::to_vec(&doc).expect("serialise document");
            let out = dispatch_trust_task_core(&tv.state, &ctx, &body).await;

            assert_ne!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{transport}: a signed document must reach its handler: {}",
                String::from_utf8_lossy(&out.body),
            );
            assert_ne!(
                error_code(&out).as_deref(),
                Some("proofInvalid"),
                "{transport}: the spine must accept a proof it can verify: {}",
                String::from_utf8_lossy(&out.body),
            );
        }
    }

    /// The rooms family, where the requirement was already enforced by the
    /// arms in `dispatch_typed` before the spine took it on. Kept because the
    /// arms' guard is now belt to the spine's brace, and a specification that
    /// relaxed the declaration would leave that guard standing alone.
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

    /// The proof-REQUIRED tasks this dispatcher serves, named by the registry
    /// rather than by a literal list here. A task that stops declaring a proof
    /// — or one that starts — moves this number, and moving it should be a
    /// decision somebody took rather than a diff nobody read.
    ///
    /// It also counts the migration. #1641 phase 2 moves the VTC's bearer-token
    /// tasks onto this binding in batches, and each batch adds its tasks here;
    /// the first added four (`members/{credentials,update,admin-remove,purge}`)
    /// to the nine the spine already served.
    #[test]
    fn the_dispatched_set_declares_the_proofs_the_design_note_records() {
        let required: Vec<&str> = DISPATCHED_URIS
            .iter()
            .copied()
            .chain(crate::rooms::handlers::served_uris())
            .filter(|uri| {
                trust_tasks_rs::schema_index::spec_policy_for(uri)
                    .is_some_and(|p| p.is_proof_required)
            })
            .collect();

        assert_eq!(
            required.len(),
            26,
            "the design note records 9 `vtc/*` + 11 `rooms/*` + the 4 admin \
             member verbs #1641 phase 2 batch 1 moved + the 2 batch 2 moved \
             (`join-requests/decide`, `community/profile/update`); got {required:?}"
        );
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
    // The applicant answering the community's request for more, against the
    // request they already have open. The third of the trio a deferral needs:
    // `status` is how they learn what is wanted, this is how they supply it,
    // and `withdraw` is how they decline to.
    jr::JOIN_REQUEST_SUPPLEMENT_TYPE,
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
    vetting_wire::VETTING_VETTER_SHOW_TYPE,
    vetting_wire::VETTING_VETTER_RESEND_TYPE,
    PERSONHOOD_CHALLENGE_TYPE,
    PERSONHOOD_ASSERT_TYPE,
    // The admin-facing member verbs (#1641 phase 2). Each also remains mounted
    // on its bearer-JWT REST route as a documented transitional path; this is
    // the binding that holds the document requirements their specifications
    // declare — proof, recipient, `issuedAt`, and the accepted-id record.
    MEMBER_CREDENTIALS_TYPE,
    MEMBER_UPDATE_TYPE,
    MEMBER_ADMIN_REMOVE_TYPE,
    MEMBER_PURGE_TYPE,
    // Batch 2: the join decision and the community-profile edit, on the same
    // terms — the bearer routes stay mounted as documented transitional paths.
    JOIN_DECIDE_TYPE,
    COMMUNITY_PROFILE_UPDATE_TYPE,
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

/// `vtc/members/credentials/0.1` — read one member's credential bodies.
pub(crate) const MEMBER_CREDENTIALS_TYPE: &str =
    <member_credentials::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/update/0.1` — update a member's role or metadata.
pub(crate) const MEMBER_UPDATE_TYPE: &str =
    <member_update::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/admin-remove/0.1` — an administrator removes another member.
pub(crate) const MEMBER_ADMIN_REMOVE_TYPE: &str =
    <member_admin_remove::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/purge/0.1` — irreversibly erase a member record.
pub(crate) const MEMBER_PURGE_TYPE: &str =
    <member_purge::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/join-requests/decide/0.1` — admit or refuse a pending applicant.
pub(crate) const JOIN_DECIDE_TYPE: &str =
    <join_decide::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/community/profile/update/0.1` — edit the community's public profile.
pub(crate) const COMMUNITY_PROFILE_UPDATE_TYPE: &str =
    <community_profile_update::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/join-requests/submit:presentationInvalid` — the presentation is not
/// the applicant's own.
pub(crate) const SUBMIT_ERR_PRESENTATION_INVALID: &str =
    trust_tasks_rs::specs::vtc::join_requests::submit::v0_2::error_codes::PRESENTATION_INVALID.code;

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
        body.attributes
            .into_iter()
            .map(|a| crate::join::SubmittedAttribute {
                r#type: a.claim_type,
                value: a.value,
            })
            .collect(),
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
            .map_err(|e| AppError::Internal(format!("revoke-statement response: {e}")).into())
        });
    match answer {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
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
        Err(e) => task_error_to_reject(&doc, &e),
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

/// `vtc/vetting/vetters/show/0.1` — one vetter's grant status, by DID.
///
/// Identified callers only, like the listing: the answer is about a named
/// third party's standing in this community.
async fn handle_vetter_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = resolve_holder(state, ctx, &doc).await {
        return reject;
    }
    let body: vetting_wire::vetters::show::v0_1::Payload = match parse_checked_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::vetting::profiles::show(state, &body).await {
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
        // `notGranted` is a `NotFound` underneath, and its local part is not
        // `notFound`, so #1602's client-side rule does not recover it — the
        // marker is the only thing that does.
        Err(AppError::NotFound(reason)) => reject_with_code_because(
            &doc,
            extended_code(vetting_wire::VETTING_VETTER_RESEND_ERR_NOT_GRANTED),
            reason,
            None,
            reasons::NOT_FOUND,
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
async fn handle_supplement(
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
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

// ─── the admin-facing member verbs (#1641 phase 2) ───────────────────────

/// The administrator a signed admin document is authorized as.
///
/// # Why this is not the bearer route's gate, and why it is not weaker
///
/// The REST routes these four verbs also sit on take `AdminAuth`: a live
/// session whose JWT says `role: admin`. That claim was itself written from the
/// caller's ACL row — `map_vtc_role_to_auth_role` admits only `VtcRole::Admin`
/// — at the moment the session was minted, and nothing re-reads it afterwards.
///
/// Here there is no session, because a signed document is not a session: the
/// proof says who authored *this document*, and **VTI-OPS-020** is satisfied by
/// that rather than by a transport. So authority is read from the ACL entry
/// [`crate::acl::resolve_auth_role`] finds for the verified signer, **at the
/// time the document is executed**. That is the same rule the bearer route
/// applies, evaluated later: a row removed, expired, or demoted since the
/// session began refuses here and would not have refused there.
///
/// What does change is the revocation lever. A bearer session is killed by
/// revoking the session; a signed document is refused by removing or expiring
/// the ACL row, which is the only authority it ever rested on. That is
/// deliberate — `docs/05-design-notes/vtc-trust-task-proof-enforcement.md` §1
/// — and it is why nothing here consults `sessions_ks`.
///
/// The signer is taken from [`JoinAuthCtx::verified_signer`], which the spine
/// filled in from the proof it verified against the document's own `issuer`
/// (SPEC §4.7) — never from the transport. All four of these specifications
/// declare `proof` REQUIRED, so the spine has already refused a document
/// carrying none; the `None` arm is belt to that brace, exactly as the
/// `rooms/*` arm keeps its own.
async fn admin_signer(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<vti_common::auth::extractor::AuthClaims, TrustTaskOutcome> {
    let Some(signer) = ctx.verified_signer.clone() else {
        return Err(reject_with(doc, RejectReason::ProofRequired));
    };
    let (role, allowed_contexts) = crate::acl::resolve_auth_role(&state.acl_ks, &signer)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?;
    Ok(vti_common::auth::extractor::AuthClaims {
        did: signer,
        role,
        allowed_contexts,
        ..Default::default()
    })
}

/// Validate a payload against its published schema and hand back the
/// generated type.
///
/// The generated `Payload` carries `deny_unknown_fields` and the required set,
/// and `validate_value` adds what serde cannot see — `const`, `enum`,
/// `pattern`, `minLength`. The bearer routes get the first half from their
/// hand-written bodies and the second from nothing at all, so this door is the
/// stricter of the two.
fn parse_spec_payload<P>(doc: &TrustTask<Value>) -> Result<P, TrustTaskOutcome>
where
    P: trust_tasks_rs::validate::ValidatedPayload + serde::de::DeserializeOwned,
{
    if let Err(e) = P::validate_value(&doc.payload) {
        return Err(reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        ));
    }
    parse_payload::<P>(doc)
}

/// `vtc/members/credentials/0.1` — the membership pair's bodies for one member.
///
/// Administrator only. The read is audited against the **signer**, which is the
/// point of the task declaring a proof: the specification's own rationale is
/// that "the record of who read a member's credentials is the only thing that
/// makes the disclosure accountable afterwards", and a bearer token names a
/// session rather than a key.
async fn handle_member_credentials(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let body: member_credentials::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::members::credentials::read_member_credentials(
        state,
        &actor.did,
        body.did.as_str(),
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        // The task's one declared code, carried as a code rather than flattened
        // into `taskFailed` (SPEC §8.5) — the same distinction the REST route's
        // `CredentialsError` makes in its body.
        Err(crate::routes::members::credentials::CredentialsError::NotFound(message)) => {
            task_error_to_reject(
                &doc,
                &crate::error::TaskError::declared(
                    crate::routes::members::credentials::MEMBER_CREDENTIALS_ERR_NOT_FOUND,
                    AppError::NotFound(message),
                ),
            )
        }
        Err(crate::routes::members::credentials::CredentialsError::Other(e)) => {
            app_error_to_reject(&doc, &e)
        }
    }
}

/// `vtc/members/update/0.1` — update a member's role or metadata.
///
/// Administrator only, and `role: admin` is refused with the task's own
/// `adminRoleForbidden` — the gate is on the transition, not on the route, so
/// it holds identically on both doors.
///
/// # Why the payload is read twice
///
/// The generated `Payload` types `extensions` as a plain map with `default`, so
/// an absent `extensions` and an empty one are the same value once parsed —
/// and the operation's rule is that an absent field leaves the member's
/// extensions **unchanged** while an empty object replaces them. Reading the
/// same JSON into the route's own `UpdateMemberRequest`, whose fields are
/// `Option`, keeps that distinction. The generated parse still runs, and runs
/// first, because it is what validates the document against its published
/// schema.
async fn handle_member_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: member_update::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let req: crate::routes::members::update::UpdateMemberRequest = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::members::update::update_member_inner(
        state,
        &actor,
        checked.did.as_str(),
        req,
    )
    .await
    {
        Ok(envelope) => success_response(&doc, envelope),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/admin-remove/0.1` — an administrator removes another member.
async fn handle_member_admin_remove(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: member_admin_remove::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // Same reason as `update` above: `disposition` and `reason` are optional
    // and the route's body type is the one that says so.
    let body: crate::routes::members::remove::RemoveBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::members::remove::admin_remove_inner(
        state,
        &actor.did,
        checked.did.as_str(),
        body,
    )
    .await
    {
        Ok(outcome) => success_response(
            &doc,
            crate::routes::members::remove::RemoveResponse::from(outcome),
        ),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `vtc/members/purge/0.1` — irreversibly erase a member record.
///
/// **Super-administrator only**, which is a stricter gate than the other three
/// and must stay one: the bearer route takes `SuperAdminAuth`, so the signed
/// door asks [`AuthClaims::require_super_admin`] the same question —
/// `Role::Admin` **and** an unrestricted [`vti_common::acl::ActScope`]. Reading
/// `allowed_contexts.is_empty()` here instead would be the exact inversion
/// `CLAUDE.md` names: empty means *unrestricted* for an admin and *authorized
/// nowhere* for anybody else.
async fn handle_member_purge(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if let Err(e) = actor.require_super_admin() {
        return app_error_to_reject(&doc, &e);
    }
    let checked: member_purge::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // The REST route validates the path segment; here the DID rides the
    // payload, and `purge_member` does not validate it for us.
    if let Err(e) = vti_common::identifier::validate_did("did", checked.did.as_str()) {
        return app_error_to_reject(&doc, &e);
    }
    match crate::ceremony::purge_member(state, &actor.did, checked.did.as_str()).await {
        Ok(outcome) => success_response(
            &doc,
            crate::routes::members::remove::RemoveResponse::from(outcome),
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
async fn handle_join_decide(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
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

/// `vtc/community/profile/update/0.1` — edit the community's public profile.
///
/// Administrator only, from the signer's ACL entry — `AdminAuth`'s question,
/// and the only one the REST route asks.
///
/// # Why the payload is read twice
///
/// The same reason `members/update` reads it twice. The generated `Payload`
/// types `extensions` as a map with `default`, so once parsed an **absent**
/// bag and an empty one are the same value — and this task's rule is that
/// absent leaves the field unchanged while a supplied value replaces it.
/// Mapping the generated type straight through would clear the community's
/// extensions on every update that did not mention them. The route's own
/// `CommunityProfileUpdate` types it `Option<Value>` and keeps the
/// distinction. The generated parse still runs, and runs first, because it is
/// what validates the document against its published schema.
///
/// The nullable members (`logoUrl`, `publicUrl`, `contactEmail`) are a
/// *different* case and the double read does not rescue them: the published
/// task says an explicit `null` clears them, and
/// `CommunityProfileUpdate`'s `Option<Option<String>>` has no double-option
/// deserializer, so serde folds `null` onto the outer `None` and the operation
/// reads it as "unchanged". That is the store's behaviour, identical on the
/// bearer route, and it is pinned by
/// `an_explicit_null_does_not_yet_clear_a_nullable_member` rather than left
/// for a client to find.
async fn handle_community_profile_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let _checked: community_profile_update::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let update: crate::community::CommunityProfileUpdate = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    match crate::routes::community::profile::update_profile_inner(state, &actor.did, update).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
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
        Err(e) => task_error_to_reject(&doc, &e),
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
        Err(e) => task_error_to_reject(&doc, &e),
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
        Err(e) => task_error_to_reject(&doc, &e),
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
            jr::JOIN_REQUEST_SUPPLEMENT_TYPE,
            jr::MEMBER_SELF_REMOVE_TYPE,
            mem::MEMBER_VMC_TYPE,
            vetting_wire::VETTING_REVOKE_STATEMENT_TYPE,
            vetting_wire::VETTING_VETTER_GRANT_TYPE,
            vetting_wire::VETTING_VETTER_PROFILE_TYPE,
            vetting_wire::VETTING_VETTER_LIST_TYPE,
            vetting_wire::VETTING_VETTER_SHOW_TYPE,
            vetting_wire::VETTING_VETTER_RESEND_TYPE,
            <pc::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <pa::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <member_credentials::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <member_update::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <member_admin_remove::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <member_purge::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <join_decide::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            <community_profile_update::Payload as trust_tasks_rs::Payload>::TYPE_URI,
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
        use vti_rooms_dtg::test_support::Party;

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
        ///
        /// The envelope is still the one a real producer sends. `issuedAt` and
        /// `recipient` are both required of these specifications, and the spine
        /// enforces them ahead of any handler since #1641; a bare
        /// `TrustTask::new` was refused as `malformedRequest` before the verb
        /// under test was ever reached.
        ///
        /// **No `proof`, and that is not leniency.**
        /// `vtc/members/personhood/challenge/0.1` declares `proof` OPTIONAL, so
        /// the spine asks for none and the authcrypt sender is the whole of the
        /// caller's identity — which is exactly what these tests are about. Its
        /// sibling `assert/0.1` *does* declare `proof` REQUIRED, and since
        /// #1672 there is no setting that makes an unsigned one acceptable; the
        /// one test that drives it uses [`signed_document`] instead.
        fn document(type_uri: &str, payload: serde_json::Value) -> Vec<u8> {
            let mut doc = TrustTask::new(
                uuid::Uuid::new_v4().to_string(),
                type_uri.parse().expect("dispatched URI parses as TypeUri"),
                payload,
            );
            doc.recipient = Some(crate::test_support::TEST_VTC_DID.to_string());
            doc.issued_at = Some(chrono::Utc::now());
            serde_json::to_vec(&doc).expect("serialize document")
        }

        /// The same envelope, issued by `from` and carrying `from`'s
        /// Data-Integrity proof — what a producer sends for a task that
        /// declares `proof` REQUIRED.
        ///
        /// `from` is a real `did:key` with the secret behind it, because the
        /// spine verifies the proof against the document's own `issuer`
        /// (SPEC §4.7): a placeholder string like [`MEMBER`] can address a
        /// document but cannot sign one.
        async fn signed_document(
            from: &Party,
            type_uri: &str,
            payload: serde_json::Value,
        ) -> Vec<u8> {
            let mut doc = vta_sdk::trust_task_sign::build_unsigned(
                type_uri,
                payload,
                &from.did,
                crate::test_support::TEST_VTC_DID,
            )
            .expect("build the document");
            let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(
                &from.did,
                &from.secret_multibase,
            )
            .expect("a did:key names its own verification method");
            vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
                .await
                .expect("sign the document");
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
        ///
        /// The document is **signed**, and that is the point of the fixture
        /// change #1672 made here. `assert/0.1` declares `proof` REQUIRED; this
        /// test used to send an unsigned one over DIDComm, which reached the
        /// handler only through the transitional allowance the same change
        /// removes. Left alone it would now stop at `proofRequired` and go on
        /// passing for a reason that has nothing to do with subject binding —
        /// a green test asserting nothing. Signing it puts the caller's
        /// identity where the handler reads it from (`verified_signer`, bound
        /// to the document's own `issuer`), so the refusal under test is still
        /// the one being produced.
        #[tokio::test]
        async fn one_member_cannot_assert_personhood_for_another() {
            let vtc = fixture().await;
            let stranger = Party::new();
            let out = dispatch_trust_task_core(
                &vtc.state,
                &JoinAuthCtx::didcomm(stranger.did.clone()),
                &signed_document(
                    &stranger,
                    PERSONHOOD_ASSERT_TYPE,
                    json!({
                        "did": MEMBER,
                        "presentation": { "type": ["VerifiablePresentation"], "holder": MEMBER },
                    }),
                )
                .await,
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

/// The helpers below are `pub(super)` so [`join_decide_profile_tests`] — batch
/// 2's tests — build and dispatch documents exactly as these do. Two harnesses
/// for one binding would diverge, and the first thing to drift would be what
/// "signed" means.
///
/// The admin-facing member verbs, served as signed Trust Task documents —
/// **#1641 phase 2, batch 1**.
///
/// Four tasks (`vtc/members/{credentials,update,admin-remove,purge}`) whose
/// specifications declare `proof` REQUIRED were served only as flat-payload
/// REST behind a bearer JWT, so they got none of what the spine enforces: no
/// proof, no recipient binding, no acceptance window, and nothing in the
/// accepted-id record. They are now bound here as well.
///
/// What these tests hold, and why each one is here:
///
/// - **VTI-OPS-020** — the document carries a proof by its issuer, and that
///   issuer's **ACL entry** is what authorizes the operation. A bearer token is
///   not read on this endpoint at all.
/// - **VTI-OPS-025 / -026 / -027** — a redelivered document is answered with
///   the recorded outcome rather than executed again, a *different* document
///   under a spent `id` is `idConflict`, and the record is the shared
///   store-backed one. All three come from the spine's claim; these drive them
///   through a real admin verb, because the failure they guard against
///   ("purge executed twice") is only visible at a verb with an effect.
/// - **The gate the bearer route applied must still refuse what it refused.**
///   Losing one silently is the risk in the whole migration, so each refusal
///   the REST extractors made has a test here: not an admin (`AdminAuth`), and
///   for `purge` a context-scoped admin who is not a super-admin
///   (`SuperAdminAuth`). Plus the operations' own refusals — unknown member,
///   `role: admin`.
#[cfg(test)]
mod members_admin_tests {
    use super::*;
    use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
    use crate::members::{Member, get_member, store_member};
    use crate::test_support::{TEST_VTC_DID, TestVtc};
    use serde_json::json;
    use vti_rooms_dtg::test_support::Party;

    /// The member these documents act on. Never one of the signers, so an
    /// `admin-remove` cannot collide with the "use /members/me" guard.
    const TARGET: &str = "did:key:zTargetMember";

    struct Fixture {
        vtc: TestVtc,
        /// `VtcRole::Admin`, unrestricted — a super-admin, so every verb here
        /// including `purge` is open to them.
        admin: Party,
        /// `VtcRole::Admin` **scoped to one context** — an admin, but not a
        /// super-admin. `SuperAdminAuth` refuses this caller and `AdminAuth`
        /// does not, which is the distinction `purge` rests on.
        scoped_admin: Party,
        /// `VtcRole::Member` — authenticated, authorized for none of this.
        member: Party,
    }

    pub(super) async fn seed_acl(vtc: &TestVtc, did: &str, role: VtcRole, contexts: Vec<String>) {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                allowed_contexts: contexts,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .expect("seed ACL row");
    }

    async fn fixture() -> Fixture {
        // `with_audit` because every one of these verbs writes an audit row and
        // refuses rather than acting when it cannot; `with_signers` because the
        // removal ceremony re-mints credentials and the spine signs its replies.
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        crate::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .expect("install default policies");

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

        // The subject these documents name: a member row *and* an ACL row,
        // which is what `members/credentials` means by "is a member".
        seed_acl(&vtc, TARGET, VtcRole::Member, vec![]).await;
        store_member(&vtc.state.members_ks, &Member::fresh(TARGET))
            .await
            .expect("seed target member");

        Fixture {
            vtc,
            admin,
            scoped_admin,
            member,
        }
    }

    /// The document as a real producer builds it — `issuer`, `recipient` and
    /// `issuedAt` set by the SDK's own builder — but unsigned.
    pub(super) fn unsigned(from: &Party, type_uri: &str, payload: Value) -> TrustTask<Value> {
        vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, TEST_VTC_DID)
            .expect("build the document")
    }

    pub(super) async fn sign(from: &Party, mut doc: TrustTask<Value>) -> TrustTask<Value> {
        let key =
            vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
                .expect("a did:key names its own verification method");
        vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
            .await
            .expect("sign the document");
        doc
    }

    pub(super) async fn signed(from: &Party, type_uri: &str, payload: Value) -> TrustTask<Value> {
        sign(from, unsigned(from, type_uri, payload)).await
    }

    pub(super) async fn dispatch(vtc: &TestVtc, doc: &TrustTask<Value>) -> TrustTaskOutcome {
        let body = serde_json::to_vec(doc).expect("a document serialises");
        dispatch_trust_task_core(&vtc.state, &JoinAuthCtx::rest(), &body).await
    }

    pub(super) fn body_of(out: &TrustTaskOutcome) -> Value {
        serde_json::from_slice(&out.body).unwrap_or(Value::Null)
    }

    /// The `code` of a `trust-task-error` reply, or `None` when the reply is a
    /// success document.
    pub(super) fn error_code(out: &TrustTaskOutcome) -> Option<String> {
        body_of(out)
            .pointer("/payload/code")?
            .as_str()
            .map(str::to_string)
    }

    pub(super) fn payload_of(out: &TrustTaskOutcome) -> Value {
        body_of(out)
            .pointer("/payload")
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// Validate a success reply's payload against the task's published
    /// `#response` schema.
    ///
    /// The router-level `response_conformance` layer that guards every REST
    /// route keys on the `Trust-Task` **header**, which the document endpoint
    /// does not use — so it does not reach these replies, and this is what
    /// stands in for it. It matters most for `update`, whose arm answers with
    /// the route's own `MemberEnvelope` rather than the generated type: a drift
    /// between the two would otherwise be invisible until a client hit it.
    pub(super) fn assert_conforms<R: trust_tasks_rs::validate::ValidatedPayload>(
        out: &TrustTaskOutcome,
    ) {
        let payload = payload_of(out);
        R::validate_value(&payload).unwrap_or_else(|e| {
            panic!("response does not match its published schema: {e}\n{payload}")
        });
    }

    // ─── the premise ─────────────────────────────────────────────────────

    /// If the registry ever relaxed one of these declarations, every test below
    /// would be asserting nothing. This one says so first.
    #[test]
    fn every_moved_task_declares_the_proof_these_tests_assume() {
        for uri in [
            MEMBER_CREDENTIALS_TYPE,
            MEMBER_UPDATE_TYPE,
            MEMBER_ADMIN_REMOVE_TYPE,
            MEMBER_PURGE_TYPE,
        ] {
            let policy = trust_tasks_rs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published spec policy"));
            assert!(
                policy.is_proof_required,
                "{uri} no longer declares proof REQUIRED — these tests now assert \
                 nothing, and the design note should be re-read"
            );
        }
    }

    // ─── VTI-OPS-020: a proof by the issuer, authorized from their ACL ────

    /// **VTI-OPS-020.** A signed document from an admin is accepted and
    /// answered with the task's own response shape.
    #[tokio::test]
    async fn vti_ops_020_a_signed_admin_document_reads_member_credentials() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "a signed admin document must be accepted: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["did"], TARGET);
        assert_eq!(payload_of(&out)["memberVmcBound"], false);
        assert_conforms::<member_credentials::Response>(&out);
    }

    /// **VTI-OPS-020.** The *same* document with its proof stripped is refused
    /// with the framework's own code — the transport proved nothing and there
    /// is nothing else to authorize against.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_admin_document_is_refused() {
        let fix = fixture().await;
        for uri in [
            MEMBER_CREDENTIALS_TYPE,
            MEMBER_UPDATE_TYPE,
            MEMBER_ADMIN_REMOVE_TYPE,
            MEMBER_PURGE_TYPE,
        ] {
            let doc = unsigned(&fix.admin, uri, json!({ "did": TARGET }));
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("proofRequired"),
                "{uri}: SPEC §7.2 item 7 names the code: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
        // …and nothing was removed by the unsigned `admin-remove` / `purge`.
        assert!(
            get_member(&fix.vtc.state.members_ks, TARGET)
                .await
                .expect("read member")
                .is_some(),
            "an unsigned document must not have had an effect"
        );
    }

    /// Authorization is the **signer's ACL entry**, not a bearer token: a
    /// correctly signed document from a DID with no admin row is refused, which
    /// is what `AdminAuth` refused on the REST route.
    #[tokio::test]
    async fn a_non_admin_signer_is_refused_every_admin_member_verb() {
        let fix = fixture().await;
        for uri in [
            MEMBER_CREDENTIALS_TYPE,
            MEMBER_UPDATE_TYPE,
            MEMBER_ADMIN_REMOVE_TYPE,
            MEMBER_PURGE_TYPE,
        ] {
            let doc = signed(&fix.member, uri, json!({ "did": TARGET })).await;
            let out = dispatch(&fix.vtc, &doc).await;
            assert_eq!(
                error_code(&out).as_deref(),
                Some("permissionDenied"),
                "{uri}: a member is not an administrator: {}",
                String::from_utf8_lossy(&out.body)
            );
        }
    }

    /// A DID with **no ACL row at all** is refused the same way — the signature
    /// verifies, and verifying a signature is not authorization.
    #[tokio::test]
    async fn a_signer_with_no_acl_row_is_refused() {
        let fix = fixture().await;
        let stranger = Party::new();
        let doc = signed(&stranger, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    /// An **expired** ACL row no longer authorizes, which the bearer route
    /// could not notice: its JWT was minted while the row was live and nothing
    /// re-reads it. This is the one place the signed door is strictly stricter.
    #[tokio::test]
    async fn an_expired_admin_acl_row_no_longer_authorizes() {
        let fix = fixture().await;
        let lapsed = Party::new();
        store_acl_entry(
            &fix.vtc.state.acl_ks,
            &VtcAclEntry {
                did: lapsed.did.clone(),
                role: VtcRole::Admin,
                label: None,
                allowed_contexts: vec![],
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: Some(1),
            },
        )
        .await
        .expect("seed a lapsed admin row");

        let doc = signed(&lapsed, MEMBER_CREDENTIALS_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
    }

    // ─── the scope gate `purge` rests on ─────────────────────────────────

    /// **The `SuperAdminAuth` gate, kept.** `purge` is irreversible and the
    /// REST route demanded a super-admin; a context-scoped admin passes
    /// `AdminAuth` and must still be refused here.
    ///
    /// Decided through `ActScope`, never `allowed_contexts.is_empty()` — for a
    /// non-admin that emptiness means the opposite.
    #[tokio::test]
    async fn a_context_scoped_admin_may_not_purge() {
        let fix = fixture().await;
        let doc = signed(
            &fix.scoped_admin,
            MEMBER_PURGE_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("permissionDenied"),
            "purge is super-admin only: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(
            get_member(&fix.vtc.state.members_ks, TARGET)
                .await
                .expect("read member")
                .is_some(),
            "the refused purge must not have erased the member"
        );
    }

    /// …and the same caller *is* an administrator for the other three, exactly
    /// as `AdminAuth` admitted them. A gate copied one notch too tight is as
    /// much a regression as one copied too loose.
    #[tokio::test]
    async fn a_context_scoped_admin_may_still_read_credentials() {
        let fix = fixture().await;
        let doc = signed(
            &fix.scoped_admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "a context-scoped admin passes AdminAuth and must pass here: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    // ─── the operations' own refusals ────────────────────────────────────

    /// The declared `notFound`, carried as a code rather than flattened into
    /// `taskFailed` — the same code the REST route puts in its body.
    #[tokio::test]
    async fn an_unknown_member_is_the_declared_not_found() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": "did:key:zNobodyAtAll" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::routes::members::credentials::MEMBER_CREDENTIALS_ERR_NOT_FOUND),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// `role: admin` is refused with the task's `adminRoleForbidden` on this
    /// door too. The gate is on the transition, not on the route (#1645), so
    /// adding a second door must not add a second way past it.
    #[tokio::test]
    async fn update_still_refuses_promotion_to_admin() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "role": "admin" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some(crate::routes::members::update::UPDATE_ERR_ADMIN_ROLE_FORBIDDEN),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        let acl = get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
            .await
            .expect("read ACL")
            .expect("the target still has a row");
        assert_eq!(acl.role, VtcRole::Member, "and nothing was changed");
    }

    /// A metadata update a signed document really does apply.
    #[tokio::test]
    async fn update_applies_a_metadata_change_from_a_signed_document() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "label": "Ada Lovelace", "publishConsent": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        assert_conforms::<member_update::Response>(&out);

        let acl = get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
            .await
            .expect("read ACL")
            .expect("row");
        assert_eq!(acl.label.as_deref(), Some("Ada Lovelace"));
        // The ACL row records *the signer* as the author of the change, which
        // is the attribution the task's proof requirement exists for.
        assert_eq!(acl.updated_by.as_deref(), Some(fix.admin.did.as_str()));
    }

    /// An **omitted** `extensions` leaves the member's own extensions alone.
    ///
    /// The generated payload types `extensions` as a plain map with `default`,
    /// so absent and empty are one value once parsed — and mapping that
    /// straight through would silently clear the bag on every update that did
    /// not mention it. The handler reads the raw payload for exactly this.
    #[tokio::test]
    async fn an_omitted_extensions_member_does_not_clear_the_bag() {
        let fix = fixture().await;
        let mut member = Member::fresh(TARGET);
        member.extensions = json!({ "org": "acme" });
        store_member(&fix.vtc.state.members_ks, &member)
            .await
            .expect("seed extensions");

        let doc = signed(
            &fix.admin,
            MEMBER_UPDATE_TYPE,
            json!({ "did": TARGET, "publishConsent": true }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        let after = get_member(&fix.vtc.state.members_ks, TARGET)
            .await
            .expect("read member")
            .expect("row");
        assert_eq!(after.extensions, json!({ "org": "acme" }));
    }

    /// An administrator removing another member, over the signed door.
    #[tokio::test]
    async fn admin_remove_departs_the_member_from_a_signed_document() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_ADMIN_REMOVE_TYPE,
            json!({ "did": TARGET, "reason": "ToS violation" }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(payload_of(&out)["did"], TARGET);
        assert_eq!(payload_of(&out)["removed"], true);
        assert_conforms::<member_admin_remove::Response>(&out);
        assert!(
            get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
                .await
                .expect("read ACL")
                .is_none(),
            "the departed member keeps no authorization"
        );
    }

    /// A super-admin purging a member, over the signed door.
    #[tokio::test]
    async fn purge_erases_the_member_from_a_signed_document() {
        let fix = fixture().await;
        let doc = signed(&fix.admin, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &doc).await;

        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
        assert_conforms::<member_purge::Response>(&out);
        assert!(
            get_member(&fix.vtc.state.members_ks, TARGET)
                .await
                .expect("read member")
                .is_none(),
            "purge erases the row"
        );
    }

    // ─── VTI-OPS-025 / -026 / -027: the accepted-id record ───────────────

    /// **VTI-OPS-025.** A redelivered document is answered with the outcome
    /// already recorded for it, not executed a second time.
    ///
    /// Driven through `purge`, because that is where a second execution would
    /// actually show: the member is gone after the first, so re-running would
    /// answer the declared `notFound` instead of the original success.
    #[tokio::test]
    async fn vti_ops_025_a_redelivered_document_is_answered_not_re_executed() {
        let fix = fixture().await;
        let doc = signed(&fix.admin, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;

        let first = dispatch(&fix.vtc, &doc).await;
        assert!(
            first.status.is_success(),
            "{}",
            String::from_utf8_lossy(&first.body)
        );

        let second = dispatch(&fix.vtc, &doc).await;
        assert!(
            second.status.is_success(),
            "the redelivery must be answered, not refused: {}",
            String::from_utf8_lossy(&second.body)
        );
        assert_eq!(
            payload_of(&second),
            payload_of(&first),
            "the recorded outcome is what a redelivery is answered with"
        );
    }

    /// **VTI-OPS-026.** A *different* document under an already-spent `id` is
    /// `idConflict` — not absorbed as a retry, and not executed.
    #[tokio::test]
    async fn vti_ops_026_a_different_document_under_a_spent_id_conflicts() {
        let fix = fixture().await;
        let second_target = "did:key:zSecondTarget";
        seed_acl(&fix.vtc, second_target, VtcRole::Member, vec![]).await;
        store_member(&fix.vtc.state.members_ks, &Member::fresh(second_target))
            .await
            .expect("seed second member");

        let first = signed(&fix.admin, MEMBER_PURGE_TYPE, json!({ "did": TARGET })).await;
        let out = dispatch(&fix.vtc, &first).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        // Same `id`, different subject — the shape the record exists to catch.
        let mut collider = unsigned(
            &fix.admin,
            MEMBER_PURGE_TYPE,
            json!({ "did": second_target }),
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
        assert!(
            get_member(&fix.vtc.state.members_ks, second_target)
                .await
                .expect("read member")
                .is_some(),
            "the conflicting document must not have executed"
        );
    }

    /// **VTI-OPS-027.** The record these verbs consult is the shared,
    /// store-backed one, reachable from any binding — not a map private to this
    /// dispatcher. Read back through `AppState::accepted_ids`, which is the
    /// handle a second binding would use.
    #[tokio::test]
    async fn vti_ops_027_the_spent_id_is_visible_to_any_binding() {
        let fix = fixture().await;
        let doc = signed(
            &fix.admin,
            MEMBER_CREDENTIALS_TYPE,
            json!({ "did": TARGET }),
        )
        .await;
        let out = dispatch(&fix.vtc, &doc).await;
        assert!(
            out.status.is_success(),
            "{}",
            String::from_utf8_lossy(&out.body)
        );

        let now = chrono::Utc::now();
        let again = fix
            .vtc
            .state
            .accepted_ids()
            .claim(&doc, retain_until(&doc, now), now)
            .await
            .expect("the record is readable");
        assert!(
            matches!(again, accepted_ids::Acceptance::Duplicate { .. }),
            "a second binding must see the id the dispatcher spent"
        );
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
    use super::members_admin_tests::{
        assert_conforms, dispatch, error_code, payload_of, seed_acl, sign, signed, unsigned,
    };
    use super::*;
    use crate::acl::VtcRole;
    use crate::community::{CommunityProfile, load_profile, store_profile};
    use crate::join::{JoinRequest, JoinStatus, get_join_request, store_join_request};
    use crate::members::get_member;
    use crate::test_support::{TEST_VTC_DID, TestVtc};
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
        // a VMC and a role VEC, and the spine signs its replies;
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
            let policy = trust_tasks_rs::schema_index::spec_policy_for(uri)
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

    /// **Neither verb is super-admin-only, and neither is context-scoped.**
    /// Both bearer routes take `AdminAuth`, which a context-scoped admin
    /// satisfies, so this door must admit them too.
    #[tokio::test]
    async fn a_context_scoped_admin_may_decide_and_may_edit_the_profile() {
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
            "a context-scoped admin passes AdminAuth and must pass here: {}",
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
        assert!(
            out.status.is_success(),
            "{}",
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
