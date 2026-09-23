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

// The declared-error-code census (#1600): every extended error code a bound,
// published `spec/vtc/*` task declares must be witnessed by a test that
// observes the service emitting it. Derived from the same census as
// `conformance`, and from `trust_tasks_rs::schema_index::error_codes_for`.
#[cfg(test)]
mod error_code_census;

use serde_json::Value;
use trust_tasks_rs::specs::vtc::members::personhood::{assert::v0_1 as pa, challenge::v0_1 as pc};
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
/// `docs/05-design-notes/vtc-trust-task-proof-enforcement.md` has the whole
/// argument, including the one transitional allowance and what ends it.
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
    let (vtc_did, require_declared_proof) = {
        let config = state.config.read().await;
        (
            config.vtc_did.clone(),
            config.trust_tasks.require_declared_proof,
        )
    };
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
    // `None` means this build knows no specification for the URI. The
    // dispatcher refuses an unrouted URI a few lines below
    // (`unsupported_type_or_version`), so there is no silently-unchecked task
    // here — only tasks whose definitions this build cannot read, which is the
    // `rooms/*`-shaped case the arms guard for themselves.
    if let Some(policy) = trust_tasks_rs::schema_index::spec_policy_for(&type_uri) {
        let policy =
            narrow_for_transitional_allowance(policy, &doc, ctx, require_declared_proof, &type_uri);
        if let Err(reason) = policy.enforce(&doc) {
            tracing::info!(
                type_uri,
                ?reason,
                "document refused by its specification's own policy"
            );
            return reject_with(&doc, reason);
        }
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
    let retain_until = retain_until(&doc, now);
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

/// The specification's policy with the **one** transitional allowance applied,
/// or unchanged — see [`crate::config::TrustTasksConfig::require_declared_proof`]
/// for why the allowance exists and what ends it.
///
/// Returns a *policy*, not a decision about a refusal, so every other rule
/// `SpecPolicy::enforce` applies still runs. That distinction is load-bearing:
/// `enforce` returns on its first failure, so skipping the whole call on a
/// waived `proofRequired` would also skip the `issuedAt` and audience-binding
/// rules that come after it, and a flag-driven rule the library adds later
/// would arrive inside a branch somebody had to remember to narrow. Narrowing
/// the input instead means the allowance can only ever relax the one flag it
/// names.
///
/// Three conditions, all required:
///
/// 1. the specification declares `proof` REQUIRED and the document carries
///    none — a *missing* proof, never an invalid one;
/// 2. the operator has not turned enforcement on; and
/// 3. the transport authenticated the sender. Over REST nothing does, so a
///    REST document with no proof is refused whatever this is set to — which
///    is the whole point of the allowance: it substitutes one form of
///    attribution for another, and cannot substitute for none.
///
/// Every waiver logs, at `warn!`, naming the requirement it is standing down
/// and the task it stood down for. A carve-out nobody can count is how the
/// divergence this closes came to be.
fn narrow_for_transitional_allowance(
    policy: trust_tasks_rs::SpecPolicy,
    doc: &TrustTask<Value>,
    ctx: &JoinAuthCtx,
    require_declared_proof: bool,
    type_uri: &str,
) -> trust_tasks_rs::SpecPolicy {
    if require_declared_proof || !policy.is_proof_required || doc.proof.is_some() {
        return policy;
    }
    let Some(sender) = ctx.sender_did.as_deref() else {
        return policy;
    };
    tracing::warn!(
        type_uri,
        sender,
        requirement = "VTI-OPS-021",
        "accepting a document with no proof for a task whose specification declares one \
         REQUIRED, on the strength of the transport-authenticated sender alone. Set \
         `[trust_tasks] require_declared_proof = true` to refuse it.",
    );
    trust_tasks_rs::SpecPolicy {
        is_proof_required: false,
        ..policy
    }
}

/// The acceptance window this VTC is willing to act inside — **VTI-OPS-024**,
/// SPEC §7.2 item 13, and the bound [`REPLAY_GUARD`]'s retention is derived
/// from.
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
/// its `id` in [`REPLAY_GUARD`] for ten years — an entry held long past the
/// last moment it could be needed, crowding out the records that are.
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
/// now the specification's, the outage it predicted is real for exactly one
/// client, and that client is named in
/// [`crate::config::TrustTasksConfig::require_declared_proof`] rather than
/// papered over here.
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

    /// **VTI-OPS-021 / VTI-OPS-093.** The transitional allowance in
    /// [`crate::config::TrustTasksConfig::require_declared_proof`] does **not**
    /// reach a REST document. Over REST nothing authenticates the sender, so
    /// there is no attribution for a missing proof to be substituted by — and
    /// the allowance is a substitution, not a suspension.
    #[tokio::test]
    async fn vti_ops_093_the_transitional_allowance_never_reaches_rest() {
        let tv = build_test_vtc().await;
        assert!(
            !tv.state
                .config
                .read()
                .await
                .trust_tasks
                .require_declared_proof,
            "the fixture runs with the shipped default, which is the lenient one"
        );
        let h = holder();

        assert_eq!(
            error_code(&dispatch(&tv.state, &unsigned(&h, UNDER_TEST, json!({}))).await).as_deref(),
            Some("proofRequired"),
            "a REST document has no transport-authenticated sender to stand in"
        );
    }

    /// The allowance, where it does apply: a transport-authenticated sender
    /// over DIDComm, under the shipped default. This is the one path #1641
    /// leaves open, and it is pinned so that flipping the default is a visible
    /// change to a test rather than a silent change in behaviour.
    #[tokio::test]
    async fn vti_ops_021_a_transport_authenticated_sender_is_accepted_while_the_allowance_stands() {
        let tv = build_test_vtc().await;
        let h = holder();
        let body =
            serde_json::to_vec(&unsigned(&h, UNDER_TEST, json!({}))).expect("serialise document");

        let out =
            dispatch_trust_task_core(&tv.state, &JoinAuthCtx::didcomm(h.did.clone()), &body).await;

        assert_ne!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "while `require_declared_proof` is false, an authcrypt sender stands in: {}",
            String::from_utf8_lossy(&out.body)
        );
    }

    /// …and does not once the operator turns enforcement on. Same document,
    /// same transport, one config line apart.
    #[tokio::test]
    async fn vti_ops_021_the_same_didcomm_document_is_refused_once_enforcement_is_on() {
        let tv = build_test_vtc().await;
        tv.state
            .config
            .write()
            .await
            .trust_tasks
            .require_declared_proof = true;
        let h = holder();
        let body =
            serde_json::to_vec(&unsigned(&h, UNDER_TEST, json!({}))).expect("serialise document");

        let out =
            dispatch_trust_task_core(&tv.state, &JoinAuthCtx::didcomm(h.did.clone()), &body).await;

        assert_eq!(
            error_code(&out).as_deref(),
            Some("proofRequired"),
            "{}",
            String::from_utf8_lossy(&out.body)
        );
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

    /// The nine `vtc/*` tasks #1641 is about, named by the registry rather than
    /// by a literal list here. A task that stops declaring a proof — or one
    /// that starts — moves this number, and moving it should be a decision
    /// somebody took rather than a diff nobody read.
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
            20,
            "the design note records 9 `vtc/*` + 11 `rooms/*`; got {required:?}"
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
/// Same spine as the DIDComm protocol-message handler
/// (`messaging::member_self_remove_handler`): actor == subject, and the leave
/// policy allows self-leave unconditionally (spec §10.2) with the
/// no-last-admin invariant still enforced in the effect stage. What the
/// document form adds is reach — a member can now perform it over **any**
/// transport this dispatcher serves, TSP included, rather than DIDComm only.
///
/// The bare-body handler stays for existing senders; both produce the same
/// receipt payload, so a migrating client sees no behaviour change.
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
        ///
        /// The envelope is still the one a real producer sends. `issuedAt` and
        /// `recipient` are both required of these specifications, and the spine
        /// enforces them ahead of any handler since #1641; a bare
        /// `TrustTask::new` was refused as `malformedRequest` before the verb
        /// under test was ever reached. No `proof`: these five run over
        /// DIDComm, where the transitional allowance stands (see
        /// [`crate::config::TrustTasksConfig::require_declared_proof`]) — which
        /// is itself worth having under test from a second direction.
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
