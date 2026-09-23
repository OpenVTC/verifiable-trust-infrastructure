//! The join-submit orchestration spine — holder-binding verification, the
//! decide -> auto-admit-effect -> audit pipeline, and the join-request
//! persistence — moved out of `routes/join_requests/submit.rs` (P2.1) so it
//! lives beside the join lifecycle it drives (`crate::join`) and is shared by
//! every entry point (REST submit, DIDComm, credential-exchange present)
//! without a `crate::routes::...` back-reference. The route handler keeps only
//! the wire body/response types + auth extraction.
//!
//! Also hosts `emit_admit_audit` (the `MemberAdded` + `VmcIssued` + `VecIssued`
//! envelopes a member admission records) — shared with the manual-approve route
//! (`routes::join_requests::decide::decide`).

use serde::Serialize;
use serde_json::Value as JsonValue;
use tracing::{info, warn};
use uuid::Uuid;

use affinidi_vc::VerifiableCredential;
use vti_common::audit::{
    AuditEvent, AuditWriter, CredentialIssuedData, JoinRequestData, JoinRequestRejectedData,
    JoinRequestSupplementedData, JoinRequestWithdrawnData, MemberAddedData,
};
use vti_common::error::AppError;

use crate::ceremony::execute::{self, AdmitOutcome, top_level_id};
use crate::ceremony::facts::Invitation;
use crate::ceremony::{
    Credential, CredentialStatus, EffectOutcome, EffectPlan, Evidence, Facts, FactsInputs,
    Presentation, Purpose, Verdict, VerifiedFacts, assemble_facts,
};
use crate::credentials::invitation_verify::{
    ConsumedInvitation, mark_consumed, verify_presented_invitation,
};
use crate::credentials::vec::VEC_TYPE;
use crate::credentials::vmc::VMC_TYPE;
use crate::join::{
    JoinDecision, JoinRequest, JoinStatus, JoinTransport, list_join_requests, store_join_request,
};
use crate::policy::{PolicyPurpose, extract::extract_vp_claims, load_active_compiled};
use crate::server::AppState;
use crate::vetting::VettingFacts;

pub const JOIN_REQUEST_SUBMIT_DOMAIN_TAG: &[u8] = b"vtc-join-request/v1\0";

/// How old a join-submit holder signature's `created` may be (seconds).
/// Bounds replay of a captured body to this window; the per-applicant
/// open-request dedup closes the in-window concurrent-replay gap (P0.13).
const JOIN_SUBMIT_FRESHNESS_SECS: i64 = 300;
/// Tolerated clock skew for a `created` slightly in the future.
const JOIN_SUBMIT_FUTURE_SKEW_SECS: i64 = 60;
/// The REST holder-binding inputs threaded into [`submit_inner`]. `None` on the
/// DIDComm path, where the authcrypt envelope authenticates the sender (and is
/// addressed to this VTC), so no separate signed audience/freshness is needed.
pub struct HolderBinding<'a> {
    pub signature_hex: &'a str,
    pub audience: &'a str,
    pub created: i64,
}
/// What [`submit_inner`] produced: the persisted request + the
/// credentials minted if the policy auto-admitted (verdict `allow`).
pub struct JoinSubmitOutcome {
    pub request: JoinRequest,
    pub admit: Option<Box<AdmitOutcome>>,
}
/// Why a submit was refused, where the reason carries data the wire needs.
///
/// `submit_inner` reports every other failure as an [`AppError`] and is
/// converted back to one by [`From`], so the REST route and the legacy DIDComm
/// problem-report path are unchanged — an `AlreadyOpen` still reaches them as
/// the same `Conflict` they answered before.
///
/// The Trust Task handler is the one caller that matches the variant, because
/// it is the one surface that can carry a typed code and a `details` annex. It
/// exists so the handler does not have to *re-read* the open request to
/// describe it: the dedup guard already holds the id and the status at the
/// moment it fires, and re-deriving them afterwards would race a concurrent
/// decision on the very request being described.
#[derive(Debug)]
pub enum SubmitRefusal {
    /// The applicant already has an open request. Carries what the guard saw.
    AlreadyOpen {
        request_id: Uuid,
        status: JoinStatus,
    },
    /// A required requested attribute was not answered. Carries the types.
    AttributesMissing(Vec<String>),
    /// An answer named a type the community does not request. Carries the
    /// types. Refused rather than trimmed — see
    /// [`crate::community::requested_attributes`].
    AttributesUnrequested(Vec<String>),
    /// The presentation cannot be the applicant's own: its `holder` names a
    /// party other than the proven submitter (`submit:presentationInvalid`).
    PresentationInvalid(String),
    /// Everything else, unchanged.
    Other(AppError),
}

impl From<AppError> for SubmitRefusal {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<SubmitRefusal> for AppError {
    fn from(r: SubmitRefusal) -> Self {
        match r {
            // The prose stays exactly as the non-Trust-Task surfaces already
            // render it; only the Trust Task path reads the structure instead.
            SubmitRefusal::AlreadyOpen { request_id, status } => AppError::Conflict(format!(
                "an open join request already exists (id {request_id}, status {status}); \
                 withdraw it with vtc/join-requests/withdraw/0.1, or await its decision, \
                 before resubmitting"
            )),
            SubmitRefusal::AttributesMissing(types) => AppError::Validation(format!(
                "this community asks for {} and the submission does not answer it; add it and \
                 resubmit",
                types.join(", ")
            )),
            SubmitRefusal::AttributesUnrequested(types) => AppError::Validation(format!(
                "this community does not ask for {}; remove it and resubmit — nothing was stored",
                types.join(", ")
            )),
            SubmitRefusal::PresentationInvalid(reason) => AppError::Validation(reason),
            SubmitRefusal::Other(e) => e,
        }
    }
}

/// Shared inner implementation called by both REST and the DIDComm
/// handler — the join ceremony's decide → effect spine.
///
/// `signature` is `Some` for REST (where the wire must carry an
/// explicit holder-binding signature) and `None` for DIDComm (where
/// the DIDComm envelope's authcrypt sender already authenticates
/// `applicant_did`).
///
/// The active `join` decision policy classifies the verified
/// submission:
/// - `allow` → **auto-admit** via the [`EffectPlan::Admit`] executor;
///   the request lands `Approved` and the credentials are returned.
/// - `refer` → `Pending` (queued for admin review → the approve route).
/// - `request_more` → `Deferred` (more evidence needed).
/// - `deny` → `Rejected`, with the verdict stored on `policy_decision`.
pub async fn submit_inner(
    state: &AppState,
    applicant_did: String,
    vp: JsonValue,
    registry_consent: bool,
    extensions: JsonValue,
    attributes: Vec<super::SubmittedAttribute>,
    binding: Option<HolderBinding<'_>>,
    transport: JoinTransport,
) -> Result<JoinSubmitOutcome, SubmitRefusal> {
    // 1. Holder binding (REST only): audience + freshness + signature. The
    // DIDComm path (`binding == None`) is authenticated + addressed by the
    // authcrypt envelope, so it skips this.
    if let Some(b) = binding.as_ref() {
        // Audience: the signed payload must name THIS VTC, so a body captured
        // for another community can't be replayed here (P0.13).
        let vtc_did = state
            .config
            .read()
            .await
            .vtc_did
            .clone()
            .ok_or_else(|| AppError::Internal("vtc_did not configured".into()))?;
        if b.audience != vtc_did {
            return Err(AppError::Validation(format!(
                "join-request audience ({}) does not match this VTC ({vtc_did})",
                b.audience
            ))
            .into());
        }
        // Freshness: a stale captured body is rejected; small future skew ok.
        let now = crate::auth::session::now_epoch() as i64;
        if b.created < now - JOIN_SUBMIT_FRESHNESS_SECS
            || b.created > now + JOIN_SUBMIT_FUTURE_SKEW_SECS
        {
            return Err(AppError::Validation(
                "join-request `created` is outside the freshness window — re-sign and resubmit"
                    .into(),
            )
            .into());
        }
        verify_holder_signature(
            &applicant_did,
            &vp,
            registry_consent,
            &extensions,
            b.audience,
            b.created,
            b.signature_hex,
        )?;
    }

    // 1a. The presentation must be the applicant's own. `submit/0.2` makes
    //     this the whole authorization: the VP's holder MUST equal the proof
    //     signer, "admitting one party on another's evidence" otherwise. Only
    //     the holder *binding* is checked here — the raw-VP path verifies no
    //     embedded credential, which is why `presentation_from_vp` surfaces
    //     none of their claims — but a holder naming somebody else is refused
    //     with the declared `presentationInvalid` rather than decided on.
    if let Err(reason) = check_presentation_holder(&applicant_did, &vp) {
        return Err(SubmitRefusal::PresentationInvalid(reason));
    }

    // 1b. Requested attributes: answered as the manifest asks, and nothing
    // more. Checked before dedup and before anything is stored, so an
    // over-shared value is never written anywhere — not even onto a request
    // that is then refused for another reason.
    let requested =
        crate::community::requested_attributes::load_requested(&state.community_ks).await?;
    let answers: Vec<crate::community::requested_attributes::Answer> = attributes
        .iter()
        .map(|a| (a.r#type.clone(), a.value.clone()))
        .collect();
    match crate::community::requested_attributes::check_answers(&requested, &answers) {
        Ok(()) => {}
        Err(crate::community::requested_attributes::AnswersRefused::Missing(t)) => {
            return Err(SubmitRefusal::AttributesMissing(t));
        }
        Err(crate::community::requested_attributes::AnswersRefused::Unrequested(t)) => {
            return Err(SubmitRefusal::AttributesUnrequested(t));
        }
    }

    // 2. Dedup: at most one open (Pending/Deferred) request per applicant
    // (P0.13). Blocks replay of a captured body while a request is open and
    // caps unbounded accumulation. An already-admitted applicant is caught
    // later by the admit duplicate-ACL guard.
    if let Some(existing) = find_open_request(&state.join_requests_ks, &applicant_did).await? {
        // Report the status, not just the id. "Withdraw or await its decision"
        // is advice the applicant cannot act on without knowing which of the
        // two they are in: a `deferred` request is waiting on *them*, and is
        // the case `vtc/join-requests/withdraw/0.1` exists for, while a
        // `pending` one is waiting on the community and will move on its own.
        //
        // Returned as structure rather than prose so the Trust Task surface can
        // answer `submit:requestAlreadyOpen` with a machine-readable annex.
        // Reading the row here rather than in the handler is deliberate: this
        // is the instant the guard fired, so the status cannot have moved under
        // a concurrent decision by the time it is described.
        let status = crate::join::storage::get_join_request(&state.join_requests_ks, existing)
            .await?
            // A row the guard just matched and that has vanished since is not a
            // state worth inventing a name for; `Pending` is the conservative
            // reading, and the id is what the applicant acts on either way.
            .map_or(JoinStatus::Pending, |r| r.status);
        return Err(SubmitRefusal::AlreadyOpen {
            request_id: existing,
            status,
        });
    }

    // 3. The lossy `vp_claims` projection is still stored on the row
    // for the admin show + the approve path; the decision pipeline
    // reads structured Facts instead (assembled below).
    let vp_claims = extract_vp_claims(&vp);

    // 4. Invitation (VIC): if the VP carries an InvitationCredential, verify it
    // (proof + holder-binding + validity + revocation). A present-but-invalid
    // invitation is a hard Forbidden here, before policy. A verified invitation
    // becomes a policy fact, with `consumed` resolved from the single-use ledger
    // so the policy (`has_valid_invitation`) can reject a redeemed invite. The
    // VIC `id` is kept so an auto-admit can burn it (step 6).
    let invitation_fact = match verify_presented_invitation(state, &applicant_did, &vp).await? {
        Some(vi) => {
            let consumed = crate::credentials::invitation_verify::is_consumed(
                &state.consumed_invitations_ks,
                &vi.id,
            )
            .await?;
            Some((vi.id.clone(), vi.to_fact(consumed)))
        }
        None => None,
    };
    let consume_invitation_id = invitation_fact.as_ref().map(|(id, _)| id.clone());
    let invitation = invitation_fact.map(|(_, fact)| fact);

    // Diagnostic: "my VIC-bearing join is still pending" almost always comes down
    // to one of the three policy facts below. The default `join.rego` auto-admits
    // only on `verified && issuer_trusted && !consumed`; a verified invitation
    // that still refers failed `issuer_trusted` (issuer ≠ this VTC's own DID and
    // not registry-recognised) or `consumed` (single-use, already redeemed). Log
    // the facts + the issuer-vs-own-DID comparison so the cause is in the record,
    // not inferred. A VP that carried `verifiableCredential` but produced no
    // invitation fact is logged too — the credential wasn't an InvitationCredential.
    match &invitation {
        Some(inv) => {
            let own_did = state.config.read().await.vtc_did.clone();
            info!(
                applicant = %applicant_did,
                vic_issuer = %inv.issuer,
                vtc_own_did = own_did.as_deref().unwrap_or("<unset>"),
                verified = inv.verified,
                issuer_trusted = inv.issuer_trusted,
                consumed = inv.consumed,
                "join: invitation presented — auto-admit needs verified && issuer_trusted && !consumed"
            );
        }
        None => {
            if let Some(vc) = vp.get("verifiableCredential") {
                // Dump the shape + each credential's `type` so a VIC that wasn't
                // recognised is self-explanatory: a missing `InvitationCredential`
                // tag, a non-array `verifiableCredential`, or the lossy `vp_claims`
                // projection mistakenly sent as the VP all show up here.
                let cred_types: Vec<String> = vc
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .map(|c| {
                                c.get("type")
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| "<no type>".to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                info!(
                    applicant = %applicant_did,
                    is_array = vc.is_array(),
                    credential_types = ?cred_types,
                    "join: VP carried `verifiableCredential` but no InvitationCredential was \
                     extracted — auto-admit-on-invitation cannot fire"
                );
            }
        }
    }

    // 5. Decide: assemble verified Facts (the route-layer holder-binding
    // makes this presentation `verified`) and run the active join policy.
    let presentation = presentation_from_vp(&applicant_did, &vp);
    // No thread: this is a synchronous REST submission, not a trust task
    // exchange. Nothing here can be `sameExchange`, which is the honest answer
    // — there is no exchange to be the same as.
    // Peer vetting: verify and count any identity-vetting statements against the
    // criterion the applicant gathered for (OpenVTC vetting design §10). `None`
    // when no published criterion requires vetting.
    let vetting =
        crate::vetting::vetting_facts(state, &applicant_did, &vp, &extensions, chrono::Utc::now())
            .await?;
    let vetting_record = vetting.clone();
    let verdict = decide_join(
        state,
        &applicant_did,
        presentation,
        invitation,
        vetting,
        None,
    )
    .await?;

    // 6. Realize the verdict (store + audit + auto-admit on allow). On an
    // invitation-driven admit the VIC is burned in the single-use ledger.
    let outcome = realize_join_verdict(
        state,
        &applicant_did,
        vp,
        vp_claims,
        registry_consent,
        extensions,
        attributes,
        verdict,
        transport,
        consume_invitation_id,
    )
    .await?;

    // 7. Keep the vetting facts the decision read, beside the request. After
    // the request is durable, and best effort: the decision already stands,
    // and a missing record costs the admin view and the vetter sweep the
    // detail (the member reads as admitted without vetting), not the admission.
    if let Some(facts) = vetting_record
        && let Err(e) = super::storage::store_vetting_facts(
            &state.join_requests_ks,
            outcome.request.id,
            &facts,
            chrono::Utc::now(),
        )
        .await
    {
        warn!(
            request = %outcome.request.id,
            error = %e,
            "vetting facts not recorded for a decided join request"
        );
    }
    Ok(outcome)
}

/// Assemble verified join [`Facts`] from a `presentation` and run the active
/// join policy, returning the [`Verdict`]. The caller supplies a `presentation`
/// it has already established as `verified` (route-layer holder-binding for the
/// VP path; cryptographic `vp_token` verification for the credential-exchange
/// path).
///
/// `thread_id` is the trust task exchange the evidence arrived on, or `None` on
/// the unthreaded REST path. It is what each credential's `taskContext` verdict
/// is resolved against, so passing `None` where a thread exists would not error
/// — it would quietly make every credential unbindable.
pub async fn decide_join(
    state: &AppState,
    applicant_did: &str,
    presentation: Presentation,
    invitation: Option<Invitation>,
    vetting: Option<VettingFacts>,
    thread_id: Option<&str>,
) -> Result<Verdict, AppError> {
    // Kept to expand a generic `vetting` need after the policy decides.
    let vetting_for_needs = vetting.clone();
    let facts = assemble_join_facts(
        state,
        applicant_did,
        presentation,
        invitation,
        vetting,
        thread_id,
    )
    .await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Join,
    )
    .await?;
    let mut verdict = crate::ceremony::decide(&verified, &policy)?;
    if let Verdict::RequestMore(more) = &mut verdict {
        crate::vetting::expand_needs(&mut more.needs, vetting_for_needs.as_ref());
    }
    Ok(verdict)
}

/// Realize a join [`Verdict`]: build + persist the [`JoinRequest`], auto-admit on
/// `allow` (the [`EffectPlan::Admit`] executor issues the VMC), and write the
/// audit event. Shared by the VP submit and the credential-exchange present path.
#[allow(clippy::too_many_arguments)]
/// Apply a policy verdict to a join request row: set its status, record the
/// decision, and run the admit effect when the verdict allows.
///
/// Extracted from [`realize_join_verdict`] so that a *second* decision on an
/// existing request can reach the same code. `realize_join_verdict` decides a
/// request it is creating; [`supplement_inner`] decides one that already
/// exists, and the two must agree about what each effect means — a supplement
/// that admitted an applicant by a different path than a submission would be a
/// second implementation of admission, which is the thing worth not having.
///
/// Mutates `request` in place and returns the admit outcome when there is one.
async fn apply_verdict_to_request(
    state: &AppState,
    request: &mut JoinRequest,
    verdict: &Verdict,
    applicant_did: &str,
    consume_invitation_id: Option<String>,
    audit_writer: &AuditWriter,
) -> Result<Option<Box<AdmitOutcome>>, AppError> {
    let mut admit: Option<Box<AdmitOutcome>> = None;
    match verdict {
        Verdict::Allow(allow) => {
            // Auto-admit: the join effect (admit + issue VMC) runs now.
            // A duplicate ACL (re-submit by an existing member) surfaces
            // as the executor's `Conflict` → 409.
            let role = allow.role.clone().unwrap_or_else(|| "member".to_string());
            let plan = EffectPlan::Admit {
                subject: applicant_did.to_string(),
                role: role.clone(),
                obligations: allow.obligations.clone(),
                // The applicant's opt-in, off the row this verdict decides —
                // the submitted one, or the supplemented one it replaced.
                publish_consent: request.registry_consent,
            };
            if let EffectOutcome::Admitted(creds) =
                execute::apply(state, plan, applicant_did).await?
            {
                // Deliver the issued VMC + role VEC to the applicant's wallet
                // over DIDComm — mirrors the approve path. Best-effort: the
                // credentials are already issued (and returned inline on the
                // REST path), so a delivery failure (no mediator, unreachable
                // holder) is logged, not fatal. This closes the gap where a
                // DIDComm auto-admit issued credentials but never sent them —
                // the receipt only carries the request id + status.
                if let Err(e) = crate::credentials::delivery::deliver_membership_credentials(
                    state,
                    applicant_did,
                    &creds,
                )
                .await
                {
                    warn!(
                        applicant = %applicant_did,
                        error = %e,
                        "membership-credential delivery failed on auto-admit; credentials issued",
                    );
                }
                // Record the admit effect's audit envelopes (MemberAdded +
                // VmcIssued + VecIssued) — the same set the manual-approve path
                // emits. Policy auto-admit has no human approver, so the
                // applicant (whose submission triggered the admission) is the
                // actor. Closes the gap where auto-admitted credentials were
                // issued with no audit trail.
                emit_admit_audit(
                    audit_writer,
                    applicant_did,
                    applicant_did,
                    &creds,
                    &role,
                    Some(request.id.to_string()),
                )
                .await?;
                admit = Some(creds);

                // Burn a single-use invitation now that the admit succeeded. The
                // `consumed` ledger row blocks a later re-redeem (e.g. re-join
                // after leaving); best-effort — the member is already admitted,
                // so a ledger write failure is logged, not fatal.
                if let Some(vic_id) = consume_invitation_id.as_deref() {
                    let record = ConsumedInvitation {
                        applicant: applicant_did.to_string(),
                        consumed_at: chrono::Utc::now(),
                        via_join_request_id: request.id.to_string(),
                    };
                    match mark_consumed(&state.consumed_invitations_ks, vic_id, &record).await {
                        Ok(true) => {}
                        Ok(false) => warn!(
                            vic_id = %vic_id,
                            applicant = %applicant_did,
                            "invitation was already consumed at admit time (concurrent redeem)",
                        ),
                        Err(e) => warn!(
                            vic_id = %vic_id,
                            error = %e,
                            "failed to record invitation consumption; member admitted",
                        ),
                    }

                    // Flag the freshly-admitted member as invitation-joined so
                    // the admin UI can badge them. Best-effort metadata patch —
                    // the member + credentials already exist.
                    match crate::members::get_member(&state.members_ks, applicant_did).await {
                        Ok(Some(mut m)) => {
                            m.joined_via_invitation = true;
                            if let Err(e) =
                                crate::members::store_member(&state.members_ks, &m).await
                            {
                                warn!(
                                    applicant = %applicant_did,
                                    error = %e,
                                    "failed to flag member joined_via_invitation",
                                );
                            }
                        }
                        Ok(None) => warn!(
                            applicant = %applicant_did,
                            "admitted member row missing when flagging joined_via_invitation",
                        ),
                        Err(e) => warn!(
                            applicant = %applicant_did,
                            error = %e,
                            "failed to load member to flag joined_via_invitation",
                        ),
                    }
                }
            }
            request.status = JoinStatus::Approved;
        }
        Verdict::Refer(_) => request.status = JoinStatus::Pending,
        Verdict::RequestMore(_) => {
            request.status = JoinStatus::Deferred;
            request.policy_decision = Some(serde_json::to_value(verdict)?);
        }
        Verdict::Deny(d) => {
            request.status = JoinStatus::Rejected;
            request.policy_decision = Some(serde_json::to_value(verdict)?);
            // The same refusal, in the shape the applicant's poll reads.
            // `policy_decision` keeps the whole verdict for the audit
            // trail; this carries the part the applicant is owed, plus
            // the decision time the verdict has no room for.
            request.decision = Some(JoinDecision {
                code: d.code.clone(),
                reason: d.reason.clone(),
                decided_at: chrono::Utc::now(),
            });
        }
    }
    Ok(admit)
}

pub async fn realize_join_verdict(
    state: &AppState,
    applicant_did: &str,
    vp: JsonValue,
    vp_claims: JsonValue,
    registry_consent: bool,
    extensions: JsonValue,
    attributes: Vec<super::SubmittedAttribute>,
    verdict: Verdict,
    transport: JoinTransport,
    consume_invitation_id: Option<String>,
) -> Result<JoinSubmitOutcome, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let mut request = JoinRequest::new(applicant_did.to_string(), vp);
    request.vp_claims = vp_claims;
    request.registry_consent = registry_consent;
    request.extensions = extensions;
    request.attributes = attributes;

    let rejected = matches!(verdict, Verdict::Deny(_));
    let admit = apply_verdict_to_request(
        state,
        &mut request,
        &verdict,
        applicant_did,
        consume_invitation_id,
        audit_writer,
    )
    .await?;
    store_join_request(&state.join_requests_ks, &request).await?;

    // Audit — Rejected for a policy deny; Submitted otherwise.
    if rejected {
        audit_writer
            .write(
                applicant_did,
                None,
                AuditEvent::JoinRequestRejected(JoinRequestRejectedData {
                    request_id: request.id.to_string(),
                    reason: "policy denied".into(),
                    // The serialized Deny verdict (with its `code`) the
                    // policy returned, recorded above on the request.
                    policy_decision: request.policy_decision.clone(),
                }),
            )
            .await?;
    } else {
        audit_writer
            .write(
                applicant_did,
                None,
                AuditEvent::JoinRequestSubmitted(JoinRequestData {
                    request_id: request.id.to_string(),
                    transport: transport.as_str().to_string(),
                }),
            )
            .await?;
    }

    info!(
        request_id = %request.id,
        applicant = %applicant_did,
        transport = transport.as_str(),
        verdict = verdict.effect(),
        "join request realized"
    );
    Ok(JoinSubmitOutcome { request, admit })
}

// ---------------------------------------------------------------------------
// Join facts assembly (decision-pipeline input)
// ---------------------------------------------------------------------------

/// Assemble purpose-`join` [`Facts`] from a verified submission. The
/// applicant is the actor + subject (self-join); the VP becomes the
/// verified presentation the policy decides over.
async fn assemble_join_facts(
    state: &AppState,
    applicant_did: &str,
    presentation: Presentation,
    invitation: Option<Invitation>,
    vetting: Option<VettingFacts>,
    thread_id: Option<&str>,
) -> Result<Facts, AppError> {
    // The applicant proved holder-binding (route-layer for the VP path,
    // cryptographic kb-jwt for the credential-exchange path) but is not (yet) a
    // member, so they carry no community role and no subject member-state. The
    // `invitation` slot is populated when the applicant presented a verified VIC
    // (see `verify_presented_invitation`); the policy decides over it.
    assemble_facts(
        state,
        FactsInputs {
            purpose: Purpose::Join,
            actor_did: applicant_did.to_string(),
            actor_role: None,
            subject_did: applicant_did.to_string(),
            subject_member: None,
            evidence: Evidence {
                vetting,
                invitation,
                presentation: Some(presentation),
                request: None,
            },
            thread_id: thread_id.map(str::to_string),
        },
    )
    .await
}

/// The VP's `holder` — a DID string, or an object carrying one as `id`.
fn vp_holder(vp: &JsonValue) -> Option<&str> {
    match vp.get("holder")? {
        JsonValue::String(s) => Some(s.as_str()),
        JsonValue::Object(o) => o.get("id").and_then(|i| i.as_str()),
        _ => None,
    }
}

/// Refuse a presentation whose `holder` names someone other than the proven
/// applicant. An absent holder is read as the applicant — the VP is carried in
/// a document the applicant signed, so it cannot be anybody else's — but a
/// holder that is *stated* must be the applicant, compared on the base DID.
fn check_presentation_holder(applicant_did: &str, vp: &JsonValue) -> Result<(), String> {
    let Some(holder) = vp_holder(vp) else {
        return Ok(());
    };
    let holder_base = holder.split('#').next().unwrap_or(holder);
    if holder_base == applicant_did {
        Ok(())
    } else {
        Err(format!(
            "the presentation's holder ({holder_base}) is not the submitting applicant \
             ({applicant_did}); a join presentation must be the applicant's own"
        ))
    }
}

/// Project the VP into the [`Presentation`] the policy reads.
///
/// `verified: true` reflects the **presentation-level** holder-binding the
/// route already checked (`verify_holder_signature` over the canonical
/// payload) — the applicant proved control of `applicant_did`. It does **not**
/// mean the *embedded VCs* were verified: this raw-VP path performs no
/// per-credential proof / issuer / status resolution (that is the
/// `vp_token` / credential-exchange `present` path). So each projected
/// credential is fail-safe — `issuer_trusted: false`, `holder_bound: false`,
/// `status: unknown` (not `valid` — its status list was never read), and
/// **`claims: null`** so a policy that branches on credential claims cannot be
/// fooled into auto-admitting on a forged VC presented under a verified
/// holder-binding (P0.12). The raw claims are still surfaced for the admin
/// show / approve UI via the request row's separate `vp_claims` projection.
fn presentation_from_vp(applicant_did: &str, vp: &JsonValue) -> Presentation {
    let holder = vp
        .get("holder")
        .and_then(|h| match h {
            JsonValue::String(s) => Some(s.clone()),
            JsonValue::Object(o) => o.get("id").and_then(|i| i.as_str()).map(str::to_string),
            _ => None,
        })
        .unwrap_or_else(|| applicant_did.to_string());

    let credentials = vp
        .get("verifiableCredential")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(credential_from_vc).collect())
        .unwrap_or_default();

    Presentation {
        verified: true,
        holder,
        credentials,
    }
}

/// Pull one VC into a [`Credential`]. JWT-encoded VCs (bare strings)
/// are skipped — full JWT-VP support lands with VP verification.
fn credential_from_vc(vc: &JsonValue) -> Option<Credential> {
    let obj = vc.as_object()?;
    let credential_type = obj
        .get("type")
        .and_then(|t| match t {
            JsonValue::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str())
                .find(|s| *s != "VerifiableCredential")
                .map(str::to_string),
            JsonValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "VerifiableCredential".to_string());
    let issuer = match obj.get("issuer") {
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Object(o)) => o
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };
    Some(Credential {
        credential_type,
        issuer,
        issuer_trusted: false,
        // The raw-VP submit path verifies NOTHING about the embedded VC — not
        // its issuer proof, not its holder-key binding (no `kb-jwt` / holder
        // proof / pseudonym check like the vp_token path), and not its
        // status-list state. So every trust signal is fail-safe: `unknown`
        // status (the list was never read — not `valid`), `issuer_trusted` /
        // `holder_bound` false, and **null claims** so a claims-reading policy
        // cannot auto-admit on attacker-supplied claim values (P0.12). A policy
        // that needs the claims must run the verifying `present` path.
        status: CredentialStatus::Unknown,
        holder_bound: false,
        claims: JsonValue::Null,
        valid_until: None,
        // Absent, not `Unresolved`. This path never looked, and `Unresolved`
        // says it looked and found nothing — a policy reading it would treat
        // "we did not check" as "the digest names no edge we hold", which is
        // the fail-safe direction here only by accident.
        witness_binding: None,
        // Likewise absent rather than `Absent`: this path reads no credential
        // property under a verified signature, so it has nothing to say about
        // where the credential came from. `Absent` would assert that the
        // credential carries no `taskContext`, which we did not check.
        task_context: None,
    })
}

/// Verify the Ed25519 signature over the canonical signing
/// payload (see module docs).
#[allow(clippy::too_many_arguments)]
fn verify_holder_signature(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
    audience: &str,
    created: i64,
    signature_hex: &str,
) -> Result<(), AppError> {
    let payload = canonical_payload(
        applicant_did,
        vp,
        registry_consent,
        extensions,
        audience,
        created,
    )?;
    crate::holder_signature::verify_domain_signed(
        applicant_did,
        JOIN_REQUEST_SUBMIT_DOMAIN_TAG,
        &payload,
        signature_hex,
    )
    .map_err(AppError::Validation)
}

/// Canonical signing payload — a typed struct serialised via
/// `serde_json::to_vec` with the field order pinned by the
/// derive. Both sides build this identically by going through the
/// same struct.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    applicant_did: &'a str,
    vp: &'a JsonValue,
    registry_consent: bool,
    extensions: &'a JsonValue,
    /// P0.13 audience + freshness binding.
    audience: &'a str,
    created: i64,
}

fn canonical_payload(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
    audience: &str,
    created: i64,
) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&CanonicalPayload {
        applicant_did,
        vp,
        registry_consent,
        extensions,
        audience,
        created,
    })
    .map_err(|e| AppError::Internal(format!("canonical payload serialize: {e}")))
}

/// Find an applicant's open (Pending/Deferred) join request, if any.
///
/// Two callers, both relying on the same invariant that at most one is open per
/// applicant: the submit dedup that establishes it (P0.13), and the id-less
/// status poll (`status_by_applicant`), which is only well-defined because of
/// it — an applicant that has lost the community's request id can ask about
/// "my open request" and get exactly one answer.
// `pub` rather than `pub(crate)` so the withdraw tests can assert the release
// directly: that a withdrawn row stops matching the guard is the half of the
// task the applicant actually feels, and asserting it through a route would
// test the route instead. `vtc-service` is `publish = false`, so widening this
// costs nothing outside the workspace.
pub async fn find_open_request(
    ks: &vti_common::store::KeyspaceHandle,
    applicant_did: &str,
) -> Result<Option<Uuid>, AppError> {
    let all = list_join_requests(ks).await?;
    Ok(all
        .into_iter()
        .find(|r| {
            r.applicant_did == applicant_did
                && matches!(r.status, JoinStatus::Pending | JoinStatus::Deferred)
        })
        .map(|r| r.id))
}

pub async fn emit_admit_audit(
    audit_writer: &AuditWriter,
    actor_did: &str,
    subject_did: &str,
    creds: &AdmitOutcome,
    role: &str,
    via_join_request_id: Option<String>,
) -> Result<(), AppError> {
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::MemberAdded(MemberAddedData {
                role: role.to_string(),
                via_join_request_id,
            }),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::VmcIssued(credential_issued_data(
                &creds.vmc,
                Some(creds.status_list_index),
            )?),
        )
        .await?;
    audit_writer
        .write(
            actor_did,
            Some(subject_did),
            AuditEvent::VecIssued(credential_issued_data(&creds.role_vec, None)?),
        )
        .await?;
    Ok(())
}

/// Build a [`CredentialIssuedData`] payload from a signed VC.
pub(crate) fn credential_issued_data(
    vc: &VerifiableCredential,
    status_list_index: Option<u32>,
) -> Result<CredentialIssuedData, AppError> {
    let id = top_level_id(vc).ok_or_else(|| {
        AppError::Internal("credential is missing top-level `id` — issuance dropped it".into())
    })?;
    let credential_type = vc
        .types
        .iter()
        .find(|t| *t == VMC_TYPE || *t == VEC_TYPE)
        .cloned()
        .ok_or_else(|| AppError::Internal("credential carries neither VMC nor VEC type".into()))?;
    let valid_from = vc
        .valid_from
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validFrom".into()))?;
    let valid_until = vc
        .valid_until
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validUntil".into()))?;
    Ok(CredentialIssuedData {
        credential_id: id,
        credential_type,
        valid_from,
        valid_until,
        status_list_index,
    })
}

/// Domain-tag prefixed bytes the signer hashes over. Verification goes
/// through [`crate::holder_signature::verify_domain_signed`]; this
/// remains for the round-trip tests that must *produce* the same bytes.
#[cfg(test)]
fn signing_bytes(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(JOIN_REQUEST_SUBMIT_DOMAIN_TAG.len() + payload.len());
    buf.extend_from_slice(JOIN_REQUEST_SUBMIT_DOMAIN_TAG);
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
/// Why a supplement was refused. Shaped like [`SubmitRefusal`] and for the
/// same reason: the Trust Task surface answers each of these with its own
/// spec-declared code, and the generic `AppError` mapping would flatten all
/// three into one `taskFailed` carrying only prose.
#[derive(Debug)]
pub enum SupplementRefusal {
    /// No open request for this applicant, or the named one is not theirs.
    /// Conflated deliberately — see [`withdraw_inner`].
    NotFound(String),
    /// The request is open and theirs, but the community has asked them for
    /// nothing: it is queued for a decision the community owes.
    NotAwaitingEvidence {
        request_id: Uuid,
        status: JoinStatus,
    },
    /// Approved, rejected or already withdrawn.
    AlreadyDecided {
        request_id: Uuid,
        status: JoinStatus,
    },
    /// Everything else, unchanged.
    Other(AppError),
}

impl From<AppError> for SupplementRefusal {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<SupplementRefusal> for AppError {
    fn from(r: SupplementRefusal) -> Self {
        match r {
            SupplementRefusal::NotFound(m) => AppError::NotFound(m),
            SupplementRefusal::NotAwaitingEvidence { request_id, status } => {
                AppError::Conflict(format!(
                    "join request {request_id} is {status}, not deferred — the community has not \
                     asked for more evidence, so there is nothing to supplement"
                ))
            }
            SupplementRefusal::AlreadyDecided { request_id, status } => AppError::Gone(format!(
                "join request {request_id} is already {status} and cannot be supplemented"
            )),
            SupplementRefusal::Other(e) => e,
        }
    }
}

/// Answer a community's request for more evidence, against the request the
/// applicant already has open (`vtc/join-requests/supplement/0.1`).
///
/// The applicant is the authority, exactly as on [`withdraw_inner`]:
/// `applicant_did` is the proven caller and a request is supplementable only
/// by the applicant recorded on it.
///
/// ## The presentation replaces; it does not accumulate
///
/// `vp` becomes the request's presentation outright, and the policy is
/// re-evaluated against it alone. Merging it with what came before would
/// produce a claim set the applicant never presented and no single proof
/// covers, so the community could not say what was actually asserted at the
/// moment it admitted them.
///
/// **Vetting travels in the presentation and is therefore replaced with it.**
/// `vetting_facts` reads attestations out of the VP's `verifiableCredential`
/// array, so a supplement that omits them is one with no vetting and the
/// policy reads it that way. The per-request `StoredVettingFacts` row is a
/// record — the admin view, the vetter sweep, tracing a withdrawn statement to
/// the admissions it counted toward — and is deliberately *not* fed back into
/// this decision; doing so would count evidence the applicant is no longer
/// presenting. The spec says this normatively, after a first draft of it said
/// the opposite (dtgwg-trust-tasks-tf #531).
///
/// ## Only a deferred request
///
/// A `Pending` request waits on the community, not on the applicant. Accepting
/// evidence into it would replace what a maintainer is reviewing underneath
/// them, so it is refused with `NotAwaitingEvidence`.
#[allow(clippy::too_many_arguments)]
pub async fn supplement_inner(
    state: &AppState,
    applicant_did: &str,
    request_id: Option<Uuid>,
    vp: JsonValue,
    extensions: JsonValue,
    transport: JoinTransport,
) -> Result<JoinSubmitOutcome, SupplementRefusal> {
    let ks = &state.join_requests_ks;
    let not_found =
        || SupplementRefusal::NotFound(format!("no open join request for {applicant_did}"));

    // The spec's rule: prefer a supplied id over inferring from the caller.
    let id = match request_id {
        Some(id) => id,
        None => find_open_request(ks, applicant_did)
            .await?
            .ok_or_else(not_found)?,
    };
    let mut request = crate::join::storage::get_join_request(ks, id)
        .await?
        .ok_or_else(not_found)?;
    if request.applicant_did != applicant_did {
        return Err(not_found());
    }

    let previous_status = request.status;
    match previous_status {
        JoinStatus::Deferred => {}
        JoinStatus::Pending => {
            return Err(SupplementRefusal::NotAwaitingEvidence {
                request_id: id,
                status: previous_status,
            });
        }
        decided => {
            return Err(SupplementRefusal::AlreadyDecided {
                request_id: id,
                status: decided,
            });
        }
    }

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // An invitation presented now counts exactly as one presented at submit:
    // the policy re-runs over the whole new presentation, and an invitation in
    // it is part of that presentation. Consumption is the extracted verdict
    // applier's job, so the burn happens once, on the same path as a
    // submission's.
    // Mirrors the submit spine's shape, including the `is_consumed` lookup —
    // the policy fact must be able to say "this invite was already redeemed".
    let invitation_fact = match verify_presented_invitation(state, applicant_did, &vp).await? {
        Some(vi) => {
            let consumed = crate::credentials::invitation_verify::is_consumed(
                &state.consumed_invitations_ks,
                &vi.id,
            )
            .await?;
            Some((vi.id.clone(), vi.to_fact(consumed)))
        }
        None => None,
    };
    let consume_invitation_id = invitation_fact.as_ref().map(|(id, _)| id.clone());
    let invitation = invitation_fact.map(|(_, fact)| fact);

    // The same holder binding submit enforces: a supplement that carried
    // somebody else's presentation would decide this applicant on their
    // evidence. `supplement/0.1` declares no code for it, so it is the
    // framework's `malformedRequest`.
    check_presentation_holder(applicant_did, &vp).map_err(AppError::Validation)?;
    let presentation = presentation_from_vp(applicant_did, &vp);
    let vetting =
        crate::vetting::vetting_facts(state, applicant_did, &vp, &extensions, chrono::Utc::now())
            .await?;
    let vetting_record = vetting.clone();
    let verdict = decide_join(
        state,
        applicant_did,
        presentation,
        invitation,
        vetting,
        None,
    )
    .await?;

    // The replacement itself, before the verdict is applied: the row the
    // policy's effects act on is the one carrying the evidence it read.
    request.vp_claims = extract_vp_claims(&vp);
    request.vp = vp;
    request.extensions = extensions;

    let admit = apply_verdict_to_request(
        state,
        &mut request,
        &verdict,
        applicant_did,
        consume_invitation_id,
        audit_writer,
    )
    .await?;
    store_join_request(ks, &request).await?;

    // Not `JoinRequestSubmitted`: nothing was submitted. Conflating them would
    // make a community's audit trail report more applications than it
    // received, and lose that an admission was granted on the second set of
    // evidence rather than the first.
    audit_writer
        .write(
            applicant_did,
            Some(applicant_did),
            AuditEvent::JoinRequestSupplemented(JoinRequestSupplementedData {
                request_id: id.to_string(),
                verdict_effect: verdict.effect().to_string(),
                previous_status: previous_status.to_string(),
            }),
        )
        .await?;

    // The vetting record follows the evidence: after the request is durable,
    // and best effort, exactly as the submit spine does it.
    if let Some(facts) = vetting_record
        && let Err(e) =
            super::storage::store_vetting_facts(ks, id, &facts, chrono::Utc::now()).await
    {
        warn!(
            request = %id,
            error = %e,
            "vetting facts not recorded for a supplemented join request"
        );
    }

    info!(
        request_id = %id,
        applicant = %applicant_did,
        transport = transport.as_str(),
        verdict = verdict.effect(),
        previous_status = %previous_status,
        "join request supplemented"
    );
    Ok(JoinSubmitOutcome { request, admit })
}

/// Close an applicant's own open join request.
///
/// The applicant is the authority: `applicant_did` is the **proven** caller
/// (authcrypt sender on DIDComm, document proof signer on REST), and a request
/// is withdrawable only by the applicant recorded on it. That match is the
/// entitlement — not membership, not a capability, neither of which an
/// applicant has, which is why they are applying
/// (`vtc/join-requests/withdraw/0.1` § Authorization).
///
/// `request_id` is OPTIONAL for the reason it is optional on the status poll:
/// an applicant whose submit response was lost never received an id, and the
/// id-less form is the only one available to them. When it is supplied it is
/// preferred over inferring the request from the caller, as the spec requires.
///
/// ## Why the two refusals are shaped differently
///
/// A request that does not exist, and one that exists but belongs to somebody
/// else, both answer `NotFound`. Distinguishing them would let a caller probe
/// whether a given request id exists on this community — the same
/// enumeration-resistance reasoning the vault's read paths use.
///
/// A request that has already been decided answers `Gone` instead, because the
/// applicant *is* entitled to know the outcome of their own request, and
/// because no retry will change it.
pub async fn withdraw_inner(
    state: &AppState,
    applicant_did: &str,
    request_id: Option<Uuid>,
    reason: Option<String>,
) -> Result<JoinRequest, AppError> {
    let ks = &state.join_requests_ks;

    // The spec's rule: prefer a supplied id over inferring from the caller.
    let id = match request_id {
        Some(id) => id,
        None => find_open_request(ks, applicant_did).await?.ok_or_else(|| {
            AppError::NotFound(format!("no open join request for {applicant_did}"))
        })?,
    };

    let mut request = crate::join::storage::get_join_request(ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no open join request for {applicant_did}")))?;

    // Ownership, and the reason it is conflated with absence above.
    if request.applicant_did != applicant_did {
        return Err(AppError::NotFound(format!(
            "no open join request for {applicant_did}"
        )));
    }

    match request.status {
        JoinStatus::Pending | JoinStatus::Deferred => {}
        decided => {
            return Err(AppError::Gone(format!(
                "join request {id} is already {decided} and cannot be withdrawn"
            )));
        }
    }

    let previous_status = request.status.to_string();
    request.status = JoinStatus::Withdrawn;
    crate::join::storage::store_join_request(ks, &request).await?;

    // The applicant's words go to the audit log, not onto the row. `decision`
    // means *refusal* — `decision_for_applicant` reconstructs one — so writing
    // a withdrawal there would make a withdrawn request read as rejected, and
    // the `JoinRequest` component is canonically typed, so it has no member of
    // its own to take. The audit entry is the community's record of the
    // withdrawal, which is what the spec asks for.
    if let Some(writer) = state.audit_writer.as_ref() {
        // Actor and subject are the same party here, and that is the point:
        // the applicant acts on their own request. Every other join audit
        // event has an operator as actor and the applicant as subject.
        writer
            .write(
                applicant_did,
                Some(applicant_did),
                AuditEvent::JoinRequestWithdrawn(JoinRequestWithdrawnData {
                    request_id: id.to_string(),
                    reason: reason.filter(|r| !r.trim().is_empty()),
                    previous_status,
                }),
            )
            .await?;
    }

    // Reaching `Withdrawn` does two things beyond recording the fact: the
    // dedup guard (`find_open_request`) stops matching this row, so the
    // applicant may submit again; and the row becomes terminal-retainable, so
    // the retention sweeper prunes it on the community's own schedule rather
    // than holding it forever as `Deferred` did.
    tracing::info!(
        request_id = %id,
        applicant = %applicant_did,
        "join request withdrawn by its applicant"
    );

    Ok(request)
}

// ---------------------------------------------------------------------------
// Tests — signing primitive + sign-then-verify round trip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn pair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0xAB; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        (sk, did)
    }

    const AUD: &str = "did:key:zThisVtc";
    const CREATED: i64 = 1_900_000_000;

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"placeholder"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        verify_holder_signature(&did, &vp, false, &JsonValue::Null, AUD, CREATED, &sig_hex)
            .unwrap();
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let (_a_sk, a_did) = pair();
        let other = SigningKey::from_bytes(&[0xCD; 32]);
        let vp = serde_json::json!({});
        let payload =
            canonical_payload(&a_did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = other.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        let err =
            verify_holder_signature(&a_did, &vp, false, &JsonValue::Null, AUD, CREATED, &sig_hex)
                .expect_err("wrong signer must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"original"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        // Same signature, different VP body.
        let tampered = serde_json::json!({"vp":"changed"});
        let err = verify_holder_signature(
            &did,
            &tampered,
            false,
            &JsonValue::Null,
            AUD,
            CREATED,
            &sig_hex,
        )
        .expect_err("tampered VP must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_tampered_audience() {
        // P0.13: the audience is part of the signed payload, so re-pointing it
        // (cross-community replay) breaks the signature.
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"x"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null, AUD, CREATED).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        let err = verify_holder_signature(
            &did,
            &vp,
            false,
            &JsonValue::Null,
            "did:key:zOtherVtc",
            CREATED,
            &sig_hex,
        )
        .expect_err("re-pointed audience must fail the signature");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_garbage_signature() {
        let (_sk, did) = pair();
        let err = verify_holder_signature(
            &did,
            &JsonValue::Null,
            false,
            &JsonValue::Null,
            AUD,
            CREATED,
            "not-hex",
        )
        .expect_err("garbage sig must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_non_did_key_applicant() {
        let err = verify_holder_signature(
            "did:web:example.com",
            &JsonValue::Null,
            false,
            &JsonValue::Null,
            AUD,
            CREATED,
            "00",
        )
        .expect_err("non-did:key must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    // ── P0.12: embedded VCs on the raw-VP submit path are fail-safe ──

    #[test]
    fn presentation_from_vp_does_not_present_unverified_vc_claims() {
        // A forged VC with attacker-chosen claims, presented under a
        // (separately-verified) holder binding. The raw-VP path verifies none
        // of the embedded VC, so its claims/status/trust signals must be
        // fail-safe — otherwise a policy reading `credentials[].claims` would
        // auto-admit on forged content.
        let applicant = "did:key:zApplicant";
        let vp = serde_json::json!({
            "type": "VerifiablePresentation",
            "holder": applicant,
            "verifiableCredential": [
                {
                    "issuer": "did:key:zForgedIssuer",
                    "type": ["VerifiableCredential", "EmailCredential"],
                    "credentialSubject": { "email": "ceo@acme.com" }
                }
            ]
        });

        let p = presentation_from_vp(applicant, &vp);

        // Presentation-level holder-binding is the route's verdict; the policy
        // gate (assemble) still passes so a legitimate submit lands pending.
        assert!(p.verified, "holder-binding is verified at the route");
        assert_eq!(p.holder, applicant);
        assert_eq!(p.credentials.len(), 1);

        let c = &p.credentials[0];
        // Structural metadata is fine to surface…
        assert_eq!(c.credential_type, "EmailCredential");
        assert_eq!(c.issuer, "did:key:zForgedIssuer");
        // …but every trust signal must be fail-safe.
        assert!(!c.issuer_trusted, "issuer not vetted on the raw path");
        assert!(!c.holder_bound, "no per-credential holder proof checked");
        assert_eq!(
            c.status,
            CredentialStatus::Unknown,
            "status list was never read — must not claim `valid`"
        );
        assert_eq!(
            c.claims,
            JsonValue::Null,
            "unverified VC claims must NOT be surfaced to the policy"
        );
    }

    #[test]
    fn presentation_from_vp_with_no_embedded_vcs_is_holder_binding_only() {
        // The common case: a bare holder-binding VP (no credentials). The
        // presentation is verified (so the submit lands pending) and carries
        // no credentials for a policy to (mis)trust.
        let applicant = "did:key:zApplicant";
        let vp = serde_json::json!({ "type": "VerifiablePresentation", "holder": applicant });
        let p = presentation_from_vp(applicant, &vp);
        assert!(p.verified);
        assert!(p.credentials.is_empty());
    }
}
