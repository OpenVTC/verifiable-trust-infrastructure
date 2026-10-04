//! **Queue items** — the community's existing human decisions, surfaced in
//! the action list (`docs/05-design-notes/vtc-action-list.md` §8.2, *Existing
//! queues*), as category `queue`.
//!
//! | Kind | Raised when | Approve | Decline |
//! |---|---|---|---|
//! | `gitNs.breakGlass.review` | a break-glass is recorded unratified | `git-ns/right/ratify` | `git-ns/right/revoke` |
//! | `member.join.review` | a join request is referred for review (`admission: review`) | `vtc/join-requests/decide` `approved` | `… rejected` |
//! | `vetting.withdrawal.review` | a withdrawn vetting statement leaves a current membership resting on it (`needsReview`) | keep the member | `vtc/members/admin-remove` |
//!
//! No wire task changes. Each item's `typeUri` names a **record type** — never
//! sent, never dispatched, like a grants review's — and its payload is that
//! record: what the decider is shown, and what the decision is executed
//! against through the operation that always decided it, with that
//! operation's own checks, audit and notices. A break-glass ratified here is
//! ratified exactly as `git-ns/right/ratify` ratifies one (its `Critical` row,
//! its notice, the rule that an unratified record never counts toward the
//! last-owner and last-admin invariants); a join approved here is admitted
//! exactly as the Join requests page admits one.
//!
//! ## How a queue item differs from an approval
//!
//! - **One decision, either way.** Threshold one (`_shared` `threshold` is
//!   absent for `queue`); approving runs one operation, declining runs the
//!   other. A decline is not an abort here: rejecting a join, revoking a
//!   break-glass and starting a removal are decisions in their own right.
//! - **Deciders hold the capability** the decision is about
//!   ([`admin_consent::may_decide`]) — `vtc.join.decide`, `vtc.vetting.manage`,
//!   `git.ns.admin` at the namespace — never the party it is about (the
//!   break-glass's subject, the applicant, the member).
//!   Single-administrator mode changes nothing: this is a decision, not a
//!   consent, and a sole administrator holding the capability simply decides
//!   it. (A break-glass is never ratified by its own subject, mode or no mode —
//!   `git-ns/right/ratify` refuses `selfRatification`.)
//! - **It never expires** and nobody cancels it. A break-glass never lapses
//!   into acceptance: its item stays until another administrator decides.
//! - **The record decides when it closes.** Decided by any route — the Join
//!   requests page, `git-ns/right/ratify` sent directly, a member removed from
//!   the Members page — the item closes ([`settle`], and at once through the
//!   hooks [`join_decided`] and [`break_glass_ended`]), so the item and the
//!   page show the same state.
//! - **A refused decision leaves it open.** If the operation refuses (the
//!   decider's own authority is an unratified break-glass, the applicant was
//!   meanwhile withdrawn), nothing is written and the item waits still.
//!
//! Raised by the operation that creates the record, and again by the sweeper
//! for any record that should have an item and has none ([`reconcile`]) —
//! a crash between the record and its item, a restored backup — so none is
//! lost (R2.1). Deciders who gain the capability later are given a slot by the
//! sweeper ([`refresh_slots`]).

use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::task_consent::{self, effects::StatePin};

use super::{
    ACTION_LOCK, ActionRecord, Approval, ApproverSlot, Category, ClosedReason, Decided,
    DecisionError, RequesterStepUp, Status, all, audit, in_flight_remove, load, push_requests,
    rfc3339, save, summary, wire_key,
};
use crate::acl::CapRef;
use crate::acl::admin_consent::{self, Act};
use crate::auth::session::now_epoch;
use crate::server::AppState;

/// A queue item never lapses. Its `expires_at` only orders it and bounds a
/// signed request's `expiresAt`; the wire never shows it.
const QUEUE_HORIZON_SECS: u64 = 10 * 365 * 24 * 3600;

/// `queue-done:<key>` — a vetting review decided in the action list, so the
/// sweeper never raises the same withdrawal for the same member again once
/// the item has left the 30-day history.
const DONE_PREFIX: &str = "queue-done:";

/// The record type an act's items are raised under.
pub(crate) fn type_uri(act: Act) -> &'static str {
    match act {
        Act::BreakGlassReview => summary::BREAK_GLASS_REVIEW_URI,
        Act::JoinReview => summary::JOIN_REVIEW_URI,
        Act::VettingReview => summary::VETTING_REVIEW_URI,
        _ => "",
    }
}

fn join_key(id: Uuid) -> String {
    format!("join:{id}")
}

fn break_glass_key(resource: &str, right: &str, subject: &str, at: &str) -> String {
    format!("breakGlass:{resource}|{right}|{subject}|{at}")
}

fn vetting_key(issuer: &str, statement_id: &str, member: &str) -> String {
    format!("vetting:{issuer}|{statement_id}|{member}")
}

fn done_key(key: &str) -> String {
    format!("{DONE_PREFIX}{key}")
}

fn new_challenge() -> String {
    // 256 bits, as an approval's: the per-decider binding and the salt.
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn slot_for(act: Act, payload: &Value, did: &str) -> Result<ApproverSlot, AppError> {
    let challenge = new_challenge();
    Ok(ApproverSlot {
        did: did.to_string(),
        wire_digest: task_consent::wire_digest(type_uri(act), payload, &challenge)?,
        challenge,
    })
}

async fn community_did(state: &AppState) -> String {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "did:key:vtc-community".into())
}

/// What raising an item needs.
struct QueueSpec {
    act: Act,
    key: String,
    requester: String,
    subject: String,
    stake: Vec<CapRef>,
    payload: Value,
    summary: String,
}

/// Raise `spec` as a queue item, unless an open one for its record exists (or,
/// for a vetting review, one was decided). `Ok(Some(id))` when raised now.
///
/// Never subject to the action-list limits (§7a.1): a busy join queue must not
/// stop an administrator acting, and nobody asked for these.
async fn raise(state: &AppState, spec: QueueSpec) -> Result<Option<String>, AppError> {
    let now = now_epoch();
    let type_uri = type_uri(spec.act);
    let digest = task_consent::payload_digest(type_uri, &spec.payload)?;
    let deciders = admin_consent::approvers_for(
        state,
        spec.act,
        &spec.stake,
        &spec.requester,
        &spec.subject,
        now,
    )
    .await?;
    let mut slots = Vec::with_capacity(deciders.len());
    for did in &deciders {
        slots.push(slot_for(spec.act, &spec.payload, did)?);
    }
    let rec = ActionRecord {
        id: format!("act-{}", uuid::Uuid::new_v4().simple()),
        kind: spec.act.kind(type_uri).to_string(),
        act: spec.act,
        stake: spec.stake,
        type_uri: type_uri.to_string(),
        payload: spec.payload,
        digest,
        submitted_doc: Value::Null,
        submitted_signer: String::new(),
        transport: "host".into(),
        requester: spec.requester,
        subject: spec.subject.clone(),
        requester_step_up: RequesterStepUp {
            kind: "community".into(),
            credential_id: String::new(),
            bound_to: String::new(),
            at: now,
        },
        approver_set: spec.act.approver_set().to_string(),
        approvers: slots,
        // One decision by construction; never on the wire for `queue`.
        threshold: 1,
        approvals: Vec::new(),
        state_pin: StatePin {
            resource: spec.subject,
            version: String::new(),
        },
        summary_text: spec.summary,
        status: Status::Open,
        created_at: now,
        expires_at: now.saturating_add(QUEUE_HORIZON_SECS),
        executing_since: None,
        closed_at: None,
        closed_reason: None,
        closed_message: None,
        closed_by: None,
        result: None,
        result_secret: false,
        category: Category::Queue,
        cooling_off_until: None,
        execution_id: None,
        acknowledgers: None,
        approver_invite: None,
        consent_waived: false,
        queue_key: Some(spec.key.clone()),
        landed_now: None,
    };
    {
        let _guard = ACTION_LOCK.lock().await;
        let open = all(state)
            .await?
            .into_iter()
            .any(|r| r.status.is_open() && r.queue_key.as_deref() == Some(spec.key.as_str()));
        if open
            || state
                .admin_actions_ks
                .get_raw(done_key(&spec.key))
                .await?
                .is_some()
        {
            return Ok(None);
        }
        for slot in &rec.approvers {
            state
                .admin_actions_ks
                .insert_raw(wire_key(&slot.wire_digest), rec.id.as_bytes().to_vec())
                .await?;
        }
        save(state, &rec).await?;
    }
    audit(state, &rec, &rec.requester.clone(), "raised", Vec::new()).await;
    info!(
        action = %rec.id,
        kind = %rec.kind,
        deciders = rec.approvers.len(),
        "a queue item was raised in the action list (vtc-action-list.md §8.2)"
    );
    push_requests(state, &rec).await;
    Ok(Some(rec.id))
}

// ─── where the record stands ─────────────────────────────────────────────

/// Where the record a queue item surfaces stands now.
enum Resolution {
    /// Still waiting for a decision.
    Pending,
    /// Decided — by `by` when the record says who.
    Decided { approved: bool, by: Option<String> },
    /// Not decidable any more, for this reason.
    Gone(String),
}

async fn resolution(state: &AppState, rec: &ActionRecord) -> Result<Resolution, AppError> {
    let p = &rec.payload;
    let s = |k: &str| p[k].as_str().unwrap_or_default().to_string();
    Ok(match rec.act {
        Act::JoinReview => {
            let Ok(id) = Uuid::parse_str(&s("requestId")) else {
                return Ok(Resolution::Gone(
                    "the join request is not a valid id".into(),
                ));
            };
            match crate::join::get_join_request(&state.join_requests_ks, id).await? {
                None => Resolution::Gone("the join request no longer exists".into()),
                Some(r) => match r.status {
                    crate::join::JoinStatus::Pending => Resolution::Pending,
                    crate::join::JoinStatus::Approved => Resolution::Decided {
                        approved: true,
                        by: None,
                    },
                    crate::join::JoinStatus::Rejected => Resolution::Decided {
                        approved: false,
                        by: None,
                    },
                    other => Resolution::Gone(format!(
                        "the join request is {other} and no longer waits for a decision"
                    )),
                },
            }
        }
        Act::BreakGlassReview => {
            use crate::git_ns::break_glass::{RecordState, record_state};
            match record_state(
                state,
                &s("resource"),
                &s("right"),
                &s("subject"),
                &s("breakGlassAt"),
            )
            .await?
            {
                RecordState::Unratified => Resolution::Pending,
                RecordState::Ratified { by } => Resolution::Decided {
                    approved: true,
                    by: Some(by),
                },
                RecordState::Gone => Resolution::Gone(
                    "the break-glass is no longer held: it was revoked or resigned, or its \
                     namespace or repository changed"
                        .into(),
                ),
            }
        }
        Act::VettingReview => {
            let member = s("member");
            match crate::members::storage::get_member(&state.members_ks, &member).await? {
                Some(m) if m.removed_at.is_none() => Resolution::Pending,
                _ => Resolution::Gone(format!("{member} is no longer a member")),
            }
        }
        _ => Resolution::Pending,
    })
}

fn close_decided(rec: &mut ActionRecord, approved: bool, by: Option<String>, now: u64) {
    if approved {
        rec.close(Status::Completed, ClosedReason::ThresholdMet, None, now);
    } else {
        rec.close(Status::Declined, ClosedReason::Declined, None, now);
    }
    if rec.closed_message.is_none() && by.is_none() {
        rec.closed_message = Some("decided outside the action list".into());
    }
    rec.closed_by = by;
}

/// Close an open queue item whose record has been decided or has gone — the
/// lazy half of "the item and the page show the same state". `true` if it
/// changed. Called under [`ACTION_LOCK`] by [`super::settle`].
pub(super) async fn settle(
    state: &AppState,
    rec: &mut ActionRecord,
    now: u64,
) -> Result<bool, AppError> {
    match resolution(state, rec).await? {
        Resolution::Pending => Ok(false),
        Resolution::Decided { approved, by } => {
            close_decided(rec, approved, by, now);
            Ok(true)
        }
        Resolution::Gone(why) => {
            rec.close(Status::Cancelled, ClosedReason::Invalidated, Some(why), now);
            Ok(true)
        }
    }
}

/// A queue decision interrupted part-way (CLAUDE.md R2.1): the record says
/// whether it landed. If not, nothing was written and the item waits again —
/// a queue item never closes `failed` on a guess.
pub(super) async fn reconcile_interrupted(
    state: &AppState,
    rec: &mut ActionRecord,
    now: u64,
) -> Result<(), AppError> {
    match resolution(state, rec).await? {
        Resolution::Pending => reopen(rec),
        Resolution::Decided { approved, by } => close_decided(rec, approved, by, now),
        Resolution::Gone(why) => {
            rec.close(Status::Cancelled, ClosedReason::Invalidated, Some(why), now)
        }
    }
    Ok(())
}

fn reopen(rec: &mut ActionRecord) {
    rec.status = Status::Open;
    rec.execution_id = None;
    rec.executing_since = None;
}

// ─── deciding ─────────────────────────────────────────────────────────────

/// Run a decision on a queue item already persisted `executing`
/// ([`super::decide`]) and close it: approved → `completed`, declined →
/// `declined`, both naming the decider. A refusal by the operation reopens it
/// and is answered [`DecisionError::Refused`].
pub(super) async fn decide(
    state: &AppState,
    rec: ActionRecord,
    decider: &str,
    approve: bool,
    reason: Option<String>,
    evidence: Option<String>,
    payload_digest: String,
) -> Result<Decided, DecisionError> {
    let execution_id = rec.execution_id.clone().unwrap_or_default();
    let outcome = execute(state, &rec, decider, approve, reason.clone()).await;
    let closed = {
        let _guard = ACTION_LOCK.lock().await;
        let mut latest = load(state, &rec.id).await?.unwrap_or(rec);
        let now = now_epoch();
        let result = match outcome {
            Ok(result) => {
                if approve {
                    latest.approvals.push(Approval {
                        did: decider.to_string(),
                        at: now,
                        evidence,
                    });
                }
                close_decided(&mut latest, approve, Some(decider.to_string()), now);
                if !approve {
                    latest.closed_message = reason.filter(|r| !r.trim().is_empty());
                }
                latest.result = Some(result);
                if latest.act == Act::VettingReview
                    && let Some(key) = latest.queue_key.as_deref()
                {
                    // Decided here: never raised again for this withdrawal and
                    // this member.
                    state
                        .admin_actions_ks
                        .insert_raw(done_key(key), latest.id.as_bytes().to_vec())
                        .await?;
                }
                save(state, &latest).await?;
                Ok(latest)
            }
            Err(message) => {
                reopen(&mut latest);
                save(state, &latest).await?;
                Err(message)
            }
        };
        in_flight_remove(&execution_id);
        result
    };
    match closed {
        Ok(rec) => {
            audit(
                state,
                &rec,
                decider,
                if approve { "completed" } else { "declined" },
                vec![decider.to_string()],
            )
            .await;
            info!(action = %rec.id, decider, approve, "a queue item was decided in the action list");
            Ok(if approve {
                Decided::Granted {
                    action_id: rec.id,
                    payload_digest,
                    approvals: 1,
                    completed: true,
                    message: None,
                }
            } else {
                Decided::Denied {
                    action_id: rec.id,
                    payload_digest,
                }
            })
        }
        Err(message) => {
            warn!(decider, %message, "a queue item's operation refused the decision; it stays open");
            Err(DecisionError::Refused(message))
        }
    }
}

/// The operation each answer runs, as `decider`, with every check it makes.
/// `Ok(result)` once it has written; `Err(refusal)` when it wrote nothing.
async fn execute(
    state: &AppState,
    rec: &ActionRecord,
    decider: &str,
    approve: bool,
    reason: Option<String>,
) -> Result<Value, String> {
    let p = &rec.payload;
    let reason = reason.filter(|r| !r.trim().is_empty());
    match rec.act {
        Act::BreakGlassReview => {
            use trust_tasks_rs::specs::git_ns::right::{
                ratify::v0_1 as ratify, revoke::v0_3 as revoke,
            };
            if approve {
                let mut body = json!({
                    "right": p["right"],
                    "resource": p["resource"],
                    "subject": p["subject"],
                    "breakGlassAt": p["breakGlassAt"],
                });
                if let Some(r) = &reason {
                    body["statement"] = json!(r);
                }
                let payload: ratify::Payload = serde_json::from_value(body)
                    .map_err(|e| format!("the ratification could not be formed: {e}"))?;
                let response = crate::git_ns::break_glass::right_ratify(state, decider, payload)
                    .await
                    .map_err(|e| e.to_string())?;
                serde_json::to_value(response).map_err(|e| e.to_string())
            } else {
                let mut body = json!({
                    "right": p["right"],
                    "resource": p["resource"],
                    "subject": p["subject"],
                });
                if let Some(r) = &reason {
                    body["reason"] = json!(r);
                }
                let payload: revoke::Payload = serde_json::from_value(body)
                    .map_err(|e| format!("the revocation could not be formed: {e}"))?;
                let response = crate::git_ns::ops::right_revoke(state, decider, payload)
                    .await
                    .map_err(|e| e.to_string())?;
                serde_json::to_value(response).map_err(|e| e.to_string())
            }
        }
        Act::JoinReview => {
            use crate::routes::join_requests::decide::{DecideBody, Decision, decide_inner};
            let id = Uuid::parse_str(p["requestId"].as_str().unwrap_or_default())
                .map_err(|e| format!("the join request id does not parse: {e}"))?;
            let response = decide_inner(
                state,
                decider,
                "actionList",
                id,
                DecideBody {
                    decision: if approve {
                        Decision::Approved
                    } else {
                        Decision::Rejected
                    },
                    reason,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            // The credentials went to the applicant; the item keeps the outcome.
            Ok(json!({ "requestId": response.request_id, "status": response.status }))
        }
        Act::VettingReview => {
            let member = p["member"].as_str().unwrap_or_default().to_string();
            if approve {
                // Keeping the member writes nothing: the decision, its decider
                // and its audit row are the record that the admission stands.
                return Ok(json!({ "member": member, "kept": true }));
            }
            // Start removal: `vtc/members/admin-remove`, as the decider, with
            // every rule it applies — `vtc.members.manage`, the removal
            // policy, the consent an administrator's removal takes.
            crate::acl::require_capability(
                &state.acl_ks,
                decider,
                crate::acl::Capability::MembersManage,
                None,
            )
            .await
            .map_err(|_| {
                format!(
                    "starting {member}'s removal is vtc/members/admin-remove, which needs \
                     vtc.members.manage; ask an administrator who holds it, or keep the member"
                )
            })?;
            let (role, allowed_contexts) = crate::acl::resolve_auth_role(&state.acl_ks, decider)
                .await
                .map_err(|e| e.to_string())?;
            let claims = vti_common::auth::extractor::AuthClaims {
                did: decider.to_string(),
                role,
                allowed_contexts,
                ..Default::default()
            };
            let mut op_payload = json!({ "did": member });
            if let Some(r) = &reason {
                op_payload["reason"] = json!(r);
            }
            let outcome = crate::routes::members::remove::admin_remove_inner(
                state,
                &claims,
                &member,
                crate::routes::members::remove::RemoveBody {
                    disposition: None,
                    reason,
                },
                admin_consent::Operation {
                    type_uri: crate::trust_tasks::MEMBER_ADMIN_REMOVE_TYPE,
                    payload: &op_payload,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            serde_json::to_value(crate::routes::members::remove::RemoveResponse::from(
                outcome,
            ))
            .map_err(|e| e.to_string())
        }
        _ => Err("not a queue item".into()),
    }
}

// ─── closing by another route ────────────────────────────────────────────

/// Close the open item for `key`, decided elsewhere by `by`. Only an item
/// still `open`: one executing is this list's own decision, which closes
/// itself.
async fn close_open(state: &AppState, key: &str, approved: bool, by: &str) {
    let closed = {
        let _guard = ACTION_LOCK.lock().await;
        let found = match all(state).await {
            Ok(records) => records
                .into_iter()
                .find(|r| r.status == Status::Open && r.queue_key.as_deref() == Some(key)),
            Err(e) => {
                warn!(error = %e, "could not read the action list to close a queue item");
                return;
            }
        };
        let Some(mut rec) = found else {
            return;
        };
        close_decided(&mut rec, approved, Some(by.to_string()), now_epoch());
        if let Err(e) = save(state, &rec).await {
            warn!(action = %rec.id, error = %e, "could not close a queue item decided elsewhere");
            return;
        }
        rec
    };
    audit(
        state,
        &closed,
        by,
        if approved { "completed" } else { "declined" },
        vec![by.to_string()],
    )
    .await;
}

// ─── join review ─────────────────────────────────────────────────────────

fn join_spec(req: &crate::join::JoinRequest) -> QueueSpec {
    let act = Act::JoinReview;
    QueueSpec {
        act,
        key: join_key(req.id),
        requester: req.applicant_did.clone(),
        subject: req.applicant_did.clone(),
        stake: act.default_stake(),
        payload: json!({
            "requestId": req.id.to_string(),
            "applicant": req.applicant_did,
            "submittedAt": req.submitted_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }),
        summary: format!("Admit or reject {}", req.applicant_did),
    }
}

/// A join request was stored: referred for review (`Pending`) raises its item;
/// any other state closes an open one. Best-effort — the sweeper reconciles.
pub(crate) async fn join_changed(state: &AppState, req: &crate::join::JoinRequest) {
    use crate::join::JoinStatus;
    if req.status == JoinStatus::Pending {
        if let Err(e) = raise(state, join_spec(req)).await {
            warn!(request = %req.id, error = %e, "the join review could not be raised now; the sweeper will");
        }
        return;
    }
    // Not pending any more: settle its item, if it has one, now.
    settle_key(state, &join_key(req.id)).await;
}

/// Settle the open item for `key` against its record now, rather than at the
/// next read.
async fn settle_key(state: &AppState, key: &str) {
    let settled = {
        let _guard = ACTION_LOCK.lock().await;
        let found = match all(state).await {
            Ok(records) => records
                .into_iter()
                .find(|r| r.status == Status::Open && r.queue_key.as_deref() == Some(key)),
            Err(e) => {
                warn!(error = %e, "could not read the action list to settle a queue item");
                return;
            }
        };
        let Some(mut rec) = found else {
            return;
        };
        match settle(state, &mut rec, now_epoch()).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                warn!(action = %rec.id, error = %e, "could not settle a queue item");
                return;
            }
        }
        if let Err(e) = save(state, &rec).await {
            warn!(action = %rec.id, error = %e, "could not save a settled queue item");
            return;
        }
        rec
    };
    audit(
        state,
        &settled,
        &settled.requester.clone(),
        super::closing_stage(&settled),
        Vec::new(),
    )
    .await;
}

/// A join request was decided through `vtc/join-requests/decide` — the Join
/// requests page, `vtc-client`, or this list — by `by`.
pub(crate) async fn join_decided(state: &AppState, id: Uuid, approved: bool, by: &str) {
    close_open(state, &join_key(id), approved, by).await;
}

// ─── break-glass ratification ────────────────────────────────────────────

fn break_glass_spec(u: &crate::git_ns::break_glass::Unratified) -> Option<QueueSpec> {
    let payload = crate::git_ns::break_glass::review_record(&u.namespace, &u.resource, &u.row)?;
    let key = break_glass_key(
        payload["resource"].as_str().unwrap_or_default(),
        payload["right"].as_str().unwrap_or_default(),
        &u.row.subject,
        payload["breakGlassAt"].as_str().unwrap_or_default(),
    );
    Some(QueueSpec {
        act: Act::BreakGlassReview,
        key,
        // The administrator who broke the glass: shown it, never deciding it.
        requester: u.row.subject.clone(),
        subject: u.row.subject.clone(),
        stake: vec![crate::git_ns::break_glass::review_stake(&u.namespace)],
        summary: format!(
            "Ratify or revoke the break-glass that gave {} {} on {}",
            u.row.subject,
            u.row.right.as_str(),
            u.resource
        ),
        payload,
    })
}

/// A break-glass was recorded: raise its ratification item.
pub(crate) async fn raise_break_glass(
    state: &AppState,
    ns: &crate::git_ns::model::Namespace,
    resource: &crate::git_ns::model::Resource,
    row: &crate::git_ns::model::RightRow,
) {
    let u = crate::git_ns::break_glass::Unratified {
        namespace: ns.clone(),
        resource: resource.clone(),
        row: row.clone(),
    };
    let Some(spec) = break_glass_spec(&u) else {
        return;
    };
    if let Err(e) = raise(state, spec).await {
        warn!(subject = %row.subject, error = %e, "the break-glass ratification item could not be raised now; the sweeper will");
    }
}

/// A break-glass was ratified (`ratified`) or revoked by `by`, through any
/// door.
pub(crate) async fn break_glass_ended(
    state: &AppState,
    resource: &str,
    right: &str,
    subject: &str,
    at: &str,
    ratified: bool,
    by: &str,
) {
    close_open(
        state,
        &break_glass_key(resource, right, subject, at),
        ratified,
        by,
    )
    .await;
}

// ─── vetting withdrawal review ───────────────────────────────────────────

/// Raise a review for every current member whose admission rests on a
/// withdrawn vetting statement (`needsReview`) and has none.
pub(crate) async fn raise_vetting_reviews(state: &AppState) {
    if let Err(e) = try_raise_vetting_reviews(state, None).await {
        warn!(error = %e, "vetting withdrawal reviews could not be raised now; the sweeper will");
    }
}

/// `open`: the records already holding an open item, when the caller has read
/// them — skipped without a further look.
async fn try_raise_vetting_reviews(
    state: &AppState,
    open: Option<&std::collections::HashSet<String>>,
) -> Result<(), AppError> {
    use crate::routes::vetting::{RevocationReviewState, revocation_rows};
    let community = community_did(state).await;
    for row in revocation_rows(state).await? {
        if row.review_state != RevocationReviewState::NeedsReview {
            continue;
        }
        for member in &row.affected_members {
            let key = vetting_key(&row.issuer, &row.statement_id, member);
            if open.is_some_and(|o| o.contains(&key))
                || state
                    .admin_actions_ks
                    .get_raw(done_key(&key))
                    .await?
                    .is_some()
            {
                continue;
            }
            let act = Act::VettingReview;
            let mut payload = json!({
                "member": member,
                "issuer": row.issuer,
                "statementId": row.statement_id,
                "statementDigestMultibase": row.statement_digest_multibase,
                "recordedAt": rfc3339(row.recorded_at.timestamp().max(0) as u64),
                "joinRequests": row.affected_join_requests,
            });
            if let Some(r) = &row.reason {
                payload["reason"] = json!(r);
            }
            raise(
                state,
                QueueSpec {
                    act,
                    key,
                    requester: community.clone(),
                    subject: member.clone(),
                    stake: act.default_stake(),
                    payload,
                    summary: format!("Keep {member} or start their removal"),
                },
            )
            .await?;
        }
    }
    Ok(())
}

// ─── the sweeper's share ─────────────────────────────────────────────────

/// Raise every item a record should have and has none: a join request
/// referred for review, an unratified break-glass, a withdrawal a current
/// membership rests on. What makes the raising crash-safe — a record written
/// and its item lost is raised here — and what raises items for records a
/// restored backup brought back.
pub(crate) async fn reconcile(state: &AppState) -> Result<(), AppError> {
    // The records that already have an open item, read once: each minute's
    // pass then costs a lookup per record, not an approver set and a digest.
    // `raise` checks again under the lock, so a race raises nothing twice.
    let open: std::collections::HashSet<String> = all(state)
        .await?
        .into_iter()
        .filter(|r| r.status.is_open())
        .filter_map(|r| r.queue_key)
        .collect();
    for req in crate::join::list_join_requests(&state.join_requests_ks).await? {
        if req.status == crate::join::JoinStatus::Pending && !open.contains(&join_key(req.id)) {
            raise(state, join_spec(&req)).await?;
        }
    }
    for u in crate::git_ns::break_glass::unratified(state).await? {
        if let Some(spec) = break_glass_spec(&u)
            && !open.contains(&spec.key)
        {
            raise(state, spec).await?;
        }
    }
    if !crate::vetting::revocation::list_notices(&state.vetting_revocations_ks)
        .await?
        .is_empty()
    {
        try_raise_vetting_reviews(state, Some(&open)).await?;
    }
    Ok(())
}

/// Give a slot to every holder of an open item's capability who has none — an
/// administrator granted `vtc.join.decide` after the join was referred sees it
/// in **Waiting for me** at the next sweep. Slots are never taken away: one
/// who has lost the capability is no longer eligible, and is refused.
pub(crate) async fn refresh_slots(state: &AppState) -> Result<(), AppError> {
    let _guard = ACTION_LOCK.lock().await;
    let now = now_epoch();
    for mut rec in all(state).await? {
        if rec.category != Category::Queue || rec.status != Status::Open {
            continue;
        }
        let deciders = admin_consent::approvers_for(
            state,
            rec.act,
            &rec.stake,
            &rec.requester,
            &rec.subject,
            now,
        )
        .await?;
        let mut changed = false;
        for did in deciders {
            if rec.slot(&did).is_none() {
                let slot = slot_for(rec.act, &rec.payload, &did)?;
                state
                    .admin_actions_ks
                    .insert_raw(wire_key(&slot.wire_digest), rec.id.as_bytes().to_vec())
                    .await?;
                rec.approvers.push(slot);
                changed = true;
            }
        }
        if changed {
            save(state, &rec).await?;
        }
    }
    Ok(())
}

// ─── test support ────────────────────────────────────────────────────────

/// Every queue item of `kind`, oldest first.
#[cfg(test)]
pub(crate) async fn items_of_kind(state: &AppState, kind: &str) -> Vec<ActionRecord> {
    let mut out: Vec<ActionRecord> = all(state)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == kind)
        .collect();
    out.sort_by_key(|r| r.created_at);
    out
}

/// One action, read back.
#[cfg(test)]
pub(crate) async fn item(state: &AppState, id: &str) -> ActionRecord {
    load(state, id).await.unwrap().expect("the action exists")
}

/// `did`'s `task-consent/decision` on `action_id`, made with the challenge
/// their slot holds — what an approver's client sends after `show`.
#[cfg(test)]
pub(crate) async fn decide_as(
    state: &AppState,
    did: &str,
    action_id: &str,
    approve: bool,
    reason: Option<&str>,
) -> Result<Decided, DecisionError> {
    let rec = item(state, action_id).await;
    let slot = rec
        .slot(did)
        .unwrap_or_else(|| panic!("{did} holds no slot on {action_id}"))
        .clone();
    super::decide(
        state,
        did,
        super::DecisionInput {
            challenge: slot.challenge,
            payload_digest: slot.wire_digest,
            approve,
            reason: reason.map(str::to_string),
            action_id: Some(action_id.to_string()),
            evidence: None,
        },
    )
    .await
}
