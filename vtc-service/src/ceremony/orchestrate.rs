//! Per-ceremony orchestration spines — the `decide → effect` wiring that sits
//! between a route/messaging adapter and the [`crate::ceremony`] pipeline.
//!
//! These functions belong *beside* the pipeline they drive, not inside route
//! handlers (P2.1): a handler should only extract auth + body, call the
//! orchestration, and shape the response. Living here, they are unit-testable
//! without axum and shared across every entry point (REST, DIDComm, the
//! promote-to-admin step-up) without a `crate::routes::…` back-reference.
//!
//! Role-change is the first spine moved; leave + join follow.

use affinidi_status_list::StatusPurpose;
use serde_json::json;
use tracing::{info, warn};

use vti_common::audit::{AuditEvent, MemberRemovedData, StatusListFlippedData};
use vti_common::error::AppError;

use super::execute::{self, EffectOutcome};
use super::{
    Evidence, FactsInputs, Purpose, Verdict, VerifiedFacts, assemble_facts, decide,
    effects::EffectPlan, load_actor_role, member_state,
};
use crate::acl::{VtcRole, get_acl_entry};
use crate::error::TaskError;
use crate::members::{Disposition, get_member};
use crate::policy::{PolicyPurpose, load_active_compiled};
use crate::server::AppState;

/// The roles a completed role change moved between — the caller's audit input.
#[derive(Debug)]
pub struct RoleChangeResult {
    pub previous_role: String,
    pub new_role: String,
}

/// Serialises admin promotions per-process, across **every** entry point.
///
/// Inherited from the retired `promote-to-admin` endpoint, where it closed the
/// window between the already-admin check and the ACL write, and held by
/// `vtc/members/update` after that. It lives here now because the window is a
/// property of the *operation*, not of one route: with the lock on the handler,
/// a second door onto the same ACL row (`acl/change-role`) raced the first.
/// fjall is not multi-process safe, so a process-wide lock is the right
/// granularity.
static PROMOTE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Run a role change through the decision pipeline: assemble Facts → decide the
/// active `roleChange` policy → apply via the Remint executor. A policy `deny`
/// → 403; a `refer` → `StepUpRequired`.
///
/// ## The admin gate, and why it is not a parameter
///
/// This took a `step_up: bool` from its caller until #1645. That made the
/// *handler* the gate — the host invariant it fed
/// ([`Invariant::StepUpForAdmin`](super::Invariant)) could only check that
/// somebody had said `true`, and a second route reaching the same ACL row
/// simply said nothing. The elevation is now resolved here, from the caller's
/// live session ([`crate::acl::elevation::verified`]), so every path into a
/// role change is gated by construction and VTI-OPS-050/051 hold wherever the
/// transition is driven from.
///
/// Promotion to `admin` additionally:
///
/// - is serialised on [`PROMOTE_LOCK`], and
/// - re-reads the subject's ACL row **under that lock** and re-checks it
///   against `current_role`, so a promotion that raced another role write is a
///   409 rather than a silent overwrite of whatever landed in between.
pub async fn role_change_via_pipeline(
    state: &AppState,
    actor: &vti_common::auth::extractor::AuthClaims,
    subject_did: &str,
    current_role: &str,
    target_role: &str,
) -> Result<RoleChangeResult, AppError> {
    let actor_did = actor.did.as_str();
    let promoting = target_role == super::invariant::ADMIN_ROLE;

    // Held across the decision *and* the effect, because the effect is what
    // performs the write. Only promotions contend: every other transition is
    // already serialised by the executor's own `LAST_ADMIN_LOCK`.
    let _guard = if promoting {
        Some(PROMOTE_LOCK.lock().await)
    } else {
        None
    };

    // Re-read under the lock. The caller's `current_role` came from a read
    // taken before it, so an interleaved role write could have landed since —
    // which is exactly the compare-and-swap `acl/change-role` promises and the
    // already-an-admin re-check `members/update` used to do by hand.
    if promoting
        && let Some(live) = get_acl_entry(&state.acl_ks, subject_did).await?
        && live.role.to_string() != current_role
    {
        return Err(AppError::Conflict(format!(
            "state mismatch: {subject_did} currently holds role {}, not {current_role}",
            live.role
        )));
    }

    // The fact the host invariant reads, resolved from the session rather than
    // taken on trust. Only promotions need it, and reading it only for them
    // keeps a plain demotion off the session keyspace.
    let step_up = promoting && crate::acl::elevation::verified(actor, &state.sessions_ks).await;

    let facts = assemble_role_change_facts(
        state,
        actor_did,
        subject_did,
        current_role,
        target_role,
        step_up,
    )
    .await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::RoleChange,
    )
    .await?;

    let allow = match decide(&verified, &policy)? {
        Verdict::Allow(a) => a,
        Verdict::Refer(r) => {
            return Err(AppError::StepUpRequired(format!(
                "role change deferred to the {} queue — complete the step-up ceremony",
                r.queue
            )));
        }
        // The two host invariants this purpose carries are answered in their
        // own terms. A vetoed decision is rendered as a policy deny by
        // `decide`, and a caller told "denied by policy (step-up-required)"
        // has to reverse-engineer a passkey ceremony out of a code; the admin
        // console, which branches on `step_up_required`, would not recover at
        // all.
        Verdict::Deny(d) if d.code == super::Invariant::StepUpForAdmin.code() => {
            return Err(crate::acl::elevation::required(&format!(
                "promoting {subject_did} to admin"
            )));
        }
        Verdict::Deny(d) if d.code == super::Invariant::SelfPromotion.code() => {
            return Err(AppError::Forbidden(
                "you cannot promote yourself; admin elevation requires a separate admin \
                 caller to run acl/change-role (PATCH /v1/acl/<your-did>) for you"
                    .into(),
            ));
        }
        Verdict::Deny(d) => {
            return Err(AppError::Forbidden(format!(
                "role change denied by policy ({})",
                d.code
            )));
        }
        Verdict::RequestMore(_) => {
            return Err(AppError::Internal(
                "role-change policy returned request_more; role change is synchronous".into(),
            ));
        }
    };

    let granted = allow
        .role
        .ok_or_else(|| AppError::Internal("role-change allow carried no role".into()))?;

    let plan = EffectPlan::Remint {
        subject: subject_did.to_string(),
        role: granted.clone(),
    };
    let EffectOutcome::Reminted(outcome) = execute::apply(state, plan, actor_did).await? else {
        return Err(AppError::Internal(
            "remint effect did not produce an outcome".into(),
        ));
    };

    // Deliver the re-minted role VEC to the member's wallet over DIDComm so it
    // can present its updated role. Best-effort: the VEC is already issued and
    // persisted (the old one is short-lived and expires on its own validUntil —
    // role VECs carry no status entry), so a delivery failure is logged, not
    // fatal. `None` means the subject is an ACL entry with no member row (an
    // integration DID, say): there was no role VEC to re-mint and nobody to
    // deliver one to.
    if let Some(role_vec) = outcome.role_vec.as_ref()
        && let Err(e) =
            crate::credentials::delivery::deliver_credentials(state, subject_did, &[role_vec]).await
    {
        warn!(
            subject = %subject_did,
            error = %e,
            "role-VEC delivery failed on role change; the credential is issued and can be re-delivered"
        );
    }

    Ok(RoleChangeResult {
        previous_role: outcome.previous_role.to_string(),
        new_role: granted,
    })
}

/// Assemble purpose-`role-change` [`Facts`](super::Facts): the actor's role, the
/// subject's current member facts, and the requested `target_role`. `step_up`
/// flows into `evidence.request.step_up` so the policy's "admin with a verified
/// step-up" branch can fire on the promote path.
async fn assemble_role_change_facts(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
    current_role: &str,
    target_role: &str,
    step_up: bool,
) -> Result<super::Facts, AppError> {
    let subject_member = get_member(&state.members_ks, subject_did).await?;

    assemble_facts(
        state,
        FactsInputs {
            purpose: Purpose::RoleChange,
            actor_did: actor_did.to_string(),
            actor_role: load_actor_role(state, actor_did).await?,
            subject_did: subject_did.to_string(),
            // The subject's role on the facts is their *current* role (the
            // transition target lives in the evidence, below).
            subject_member: Some(member_state(
                current_role.to_string(),
                subject_member.as_ref(),
            )),
            evidence: Evidence {
                vetting: None,
                invitation: None,
                presentation: None,
                request: Some(json!({ "target_role": target_role, "step_up": step_up })),
            },
            // A role change is a synchronous admin action, not a trust task
            // exchange, and presents no credentials — there is nothing to bind
            // and no thread to bind it to.
            thread_id: None,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Leave ceremony
// ---------------------------------------------------------------------------

/// What a completed leave produced. The caller maps it to its wire response
/// (the REST `RemoveResponse`, the DIDComm self-remove receipt).
#[derive(Debug)]
pub struct LeaveOutcome {
    pub did: String,
    pub disposition: String,
    pub removed: bool,
}

use trust_tasks_rs::specs::vtc::members as members_specs;

/// `vtc/members/purge:notFound` — no member or tombstone for that DID.
pub const PURGE_ERR_NOT_FOUND: &str = members_specs::purge::v0_1::error_codes::NOT_FOUND.code;
/// `vtc/members/purge:lastAdministrator` — purging would leave no admin.
pub const PURGE_ERR_LAST_ADMINISTRATOR: &str =
    members_specs::purge::v0_1::error_codes::LAST_ADMINISTRATOR.code;
/// `vtc/members/admin-remove:notFound` — no member with that DID.
pub const ADMIN_REMOVE_ERR_NOT_FOUND: &str =
    members_specs::admin_remove::v0_1::error_codes::NOT_FOUND.code;
/// `vtc/members/self-remove:notMember` — the caller is not a member.
pub const SELF_REMOVE_ERR_NOT_MEMBER: &str =
    members_specs::self_remove::v0_1::error_codes::NOT_MEMBER.code;

/// Forcefully **purge** a member row — operator cleanup for a lingering
/// tombstone (a Tombstone/Historical departure left the Member row after its
/// ACL was deleted), or a hard delete of a live member. Hard-deletes the ACL
/// (if any) + Member row, decrements the row count, and best-effort flips the
/// revocation bit. Super-admin only at the route layer.
///
/// Unlike [`remove_inner`], this does **not** require an existing ACL (so it can
/// clean up tombstones) and does **not** run the removal policy — it's a
/// forceful admin op. The executor's no-last-admin invariant still applies, so
/// purging the sole admin is refused (`Conflict`).
pub async fn purge_member(
    state: &AppState,
    actor_did: &str,
    target_did: &str,
) -> Result<LeaveOutcome, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // Must have *something* to purge — a Member row and/or an ACL entry.
    let has_member = get_member(&state.members_ks, target_did).await?.is_some();
    let prior_acl = get_acl_entry(&state.acl_ks, target_did).await?;
    let has_acl = prior_acl.is_some();
    if !has_member && !has_acl {
        return Err(TaskError::declared(
            PURGE_ERR_NOT_FOUND,
            AppError::NotFound(format!("no member or tombstone to purge: {target_did}")),
        ));
    }

    // Reuse the single state-mutating seam with a forced Purge disposition.
    //
    // `depart`'s one `Conflict` is the no-last-admin invariant — everything
    // else it can fail with is a store fault — so it is the declared
    // `lastAdministrator`. The status and message are the executor's own.
    let EffectOutcome::Departed(outcome) = execute::apply(
        state,
        EffectPlan::Depart {
            subject: target_did.to_string(),
            disposition: Some("purge".to_string()),
        },
        actor_did,
    )
    .await
    .map_err(|e| match e {
        e @ AppError::Conflict(_) => TaskError::declared(PURGE_ERR_LAST_ADMINISTRATOR, e),
        e => TaskError::App(e),
    })?
    else {
        return Err(
            AppError::Internal("purge effect did not produce a departure outcome".into()).into(),
        );
    };

    audit_writer
        .write(
            actor_did,
            Some(target_did),
            AuditEvent::MemberRemoved(MemberRemovedData {
                disposition: "purge".into(),
                reason: "operator purge".into(),
                prior_role: prior_acl.as_ref().map(|a| a.role.to_string()),
            }),
        )
        .await?;
    if let Some(slot) = outcome.revoked_slot {
        audit_writer
            .write(
                actor_did,
                Some(target_did),
                AuditEvent::StatusListFlipped(StatusListFlippedData {
                    purpose: StatusPurpose::Revocation.to_string(),
                    index: slot,
                    revoked: true,
                }),
            )
            .await?;
    }

    for grant in &outcome.revoked_grants {
        crate::vetting::vetters::audit_revoked_grant(audit_writer, actor_did, target_did, grant)
            .await?;
    }

    info!(actor = actor_did, target = target_did, "member purged");

    // Tell them. Best-effort and after the fact: the purge is done and durable,
    // so a delivery problem must not fail the operator's request and leave them
    // believing it did not happen. `purged` rather than `adminRemoved` because
    // the two differ in what recourse the member has — this one deliberately
    // skipped the removal policy.
    crate::ceremony::removal_notice::send(
        state,
        target_did,
        vta_sdk::protocols::members::RemovalCode::Purged,
        "purge",
        None,
        &chrono::Utc::now().to_rfc3339(),
        actor_did,
    )
    .await;

    Ok(LeaveOutcome {
        did: target_did.to_string(),
        disposition: "purge".into(),
        removed: true,
    })
}

/// The leave ceremony's decide → resolve → effect → audit spine. Returns
/// `Ok(LeaveOutcome)` on departure, `Err(Forbidden)` when the policy denies, or
/// `Err(Conflict)` for the executor's no-last-admin invariant.
///
/// `actor_did` is the initiator (self for self-leave, admin for admin-remove) —
/// the policy distinguishes the two via `actor.did == subject.did`. `target_did`
/// is the subject being removed.
pub async fn remove_inner(
    state: &AppState,
    actor_did: &str,
    target_did: &str,
    disposition: Option<Disposition>,
    reason: String,
) -> Result<LeaveOutcome, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let target_acl = get_acl_entry(&state.acl_ks, target_did).await?;
    let target_member = get_member(&state.members_ks, target_did).await?;

    // Removal needs *a* subject, not specifically an ACL entry.
    //
    // This used to require the ACL row and 404 `member not found` without one,
    // which closed the only door out of the exact state an `acl/revoke` aimed
    // at a member left behind: a live member row, no authorization, and
    // credentials still unrevoked (#1194 stops new ones being created; this
    // is how the existing ones get cleaned up). The operator was told the
    // member did not exist while `members list` was warning about that very
    // row — two surfaces disagreeing about whether somebody is here.
    //
    // Only genuinely-absent is still `not found`: neither row.
    //
    // Which task's code that is follows from who is asking, the same way the
    // removal policy tells the two apart (`actor.did == subject.did`): a
    // member leaving is `self-remove:notMember` ("nothing to remove"), an
    // admin removing somebody is `admin-remove:notFound`.
    if target_acl.is_none() && target_member.is_none() {
        let code = if actor_did == target_did {
            SELF_REMOVE_ERR_NOT_MEMBER
        } else {
            ADMIN_REMOVE_ERR_NOT_FOUND
        };
        return Err(TaskError::declared(
            code,
            AppError::NotFound(format!("member not found: {target_did}")),
        ));
    }

    // The subject's role, for the removal policy and the audit row. With no
    // ACL entry there is no role to read, and `member` is the honest answer
    // rather than a cautious one: role *is* the ACL entry, so a subject
    // without one holds no authority — they cannot be the admin the policy
    // protects, and `depart`'s no-last-admin invariant reads the same absent
    // row and reaches the same conclusion.
    let subject_role = target_acl
        .as_ref()
        .map_or_else(|| VtcRole::Member.to_string(), |a| a.role.to_string());

    // Decide. Assemble verified leave Facts and run the active removal-purpose
    // decision policy. The no-last-admin invariant + the credential revocation
    // are the *effect* (executor below), not the policy.
    let facts = assemble_leave_facts(
        state,
        actor_did,
        target_did,
        &subject_role,
        target_member.as_ref(),
        disposition,
        &reason,
    )
    .await?;
    let verified = VerifiedFacts::assemble(facts).map_err(AppError::from)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Removal,
    )
    .await?;
    let allow = match decide(&verified, &policy)? {
        Verdict::Allow(a) => a,
        Verdict::Deny(d) => {
            return Err(
                AppError::Forbidden(format!("removal denied by policy ({})", d.code)).into(),
            );
        }
        // Leave is synchronous — a refer / request_more verdict is a
        // misconfigured policy for this purpose.
        Verdict::Refer(_) | Verdict::RequestMore(_) => {
            return Err(AppError::Internal(
                "removal policy returned a non-terminal verdict; leave is synchronous".into(),
            )
            .into());
        }
    };

    // Resolve the final disposition: the caller's explicit request wins; then
    // the member's `departure_preference`; then the policy's chosen disposition
    // (`with.disposition`); then `Tombstone`.
    let initial = disposition
        .or_else(|| target_member.as_ref().map(|m| m.departure_preference))
        .unwrap_or(Disposition::PolicyDefault);
    let resolved = match initial {
        Disposition::PolicyDefault => allow
            .disposition
            .as_deref()
            .and_then(parse_disposition_opt)
            .unwrap_or(Disposition::Tombstone),
        other => other,
    };

    // Effect: the no-last-admin invariant + ACL/Member removal + credential
    // revocation, via the ceremony effect executor (the single state-mutating
    // seam). A last-admin removal surfaces as the executor's `Conflict` → 409,
    // untouched state.
    let plan = EffectPlan::Depart {
        subject: target_did.to_string(),
        disposition: Some(disposition_wire(resolved).to_string()),
    };
    let EffectOutcome::Departed(outcome) = execute::apply(state, plan, actor_did).await? else {
        return Err(
            AppError::Internal("depart effect did not produce a departure outcome".into()).into(),
        );
    };
    let disposition_str = disposition_wire(outcome.disposition);

    audit_writer
        .write(
            actor_did,
            Some(target_did),
            AuditEvent::MemberRemoved(MemberRemovedData {
                disposition: disposition_str.into(),
                reason: reason.clone(),
                prior_role: target_acl.as_ref().map(|a| a.role.to_string()),
            }),
        )
        .await?;

    for grant in &outcome.revoked_grants {
        crate::vetting::vetters::audit_revoked_grant(audit_writer, actor_did, target_did, grant)
            .await?;
    }

    // M2.14: the executor flipped the revocation bit (best-effort). Emit the
    // audit event for the slot it reported.
    if let Some(slot) = outcome.revoked_slot {
        audit_writer
            .write(
                actor_did,
                Some(target_did),
                AuditEvent::StatusListFlipped(StatusListFlippedData {
                    purpose: StatusPurpose::Revocation.to_string(),
                    index: slot,
                    revoked: true,
                }),
            )
            .await?;
    }

    info!(
        actor = actor_did,
        target = target_did,
        disposition = disposition_str,
        reason_present = !reason.is_empty(),
        "member removed"
    );

    // Tell them — but only when somebody else decided. `remove_inner` serves
    // both the admin path and the DIDComm self-leave, and a member who chose to
    // leave already has their receipt; sending this as well would tell somebody
    // who left that they were removed.
    if actor_did != target_did {
        crate::ceremony::removal_notice::send(
            state,
            target_did,
            vta_sdk::protocols::members::RemovalCode::AdminRemoved,
            disposition_str,
            Some(reason.clone()),
            &chrono::Utc::now().to_rfc3339(),
            actor_did,
        )
        .await;
    }

    Ok(LeaveOutcome {
        did: target_did.to_string(),
        disposition: disposition_str.into(),
        removed: true,
    })
}

/// Wire string for a resolved (concrete) disposition. Mirrors the `Disposition`
/// serde representation; used for the outcome + audit + the `EffectPlan::Depart`
/// payload.
fn disposition_wire(d: Disposition) -> &'static str {
    match d {
        Disposition::Purge => "purge",
        Disposition::Tombstone => "tombstone",
        Disposition::Historical => "historical",
        Disposition::PolicyDefault => "policydefault",
    }
}

/// Read the actor's community role + the subject's member facts into a
/// purpose-`leave` [`Facts`](super::Facts) for the decision policy.
/// `subject_role` is the subject's ACL role (already fetched by the caller for
/// the 404 gate); `subject_member` is their member row, if any.
async fn assemble_leave_facts(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
    subject_role: &str,
    subject_member: Option<&crate::members::Member>,
    disposition: Option<Disposition>,
    reason: &str,
) -> Result<super::Facts, AppError> {
    // Ceremony request params: the operator's requested disposition + the
    // admin-supplied reason. Absent when neither is set.
    let request = if disposition.is_some() || !reason.is_empty() {
        let mut m = serde_json::Map::new();
        if let Some(d) = disposition {
            m.insert("disposition".into(), json!(disposition_wire(d)));
        }
        if !reason.is_empty() {
            m.insert("reason".into(), json!(reason));
        }
        Some(serde_json::Value::Object(m))
    } else {
        None
    };

    assemble_facts(
        state,
        FactsInputs {
            purpose: Purpose::Leave,
            actor_did: actor_did.to_string(),
            actor_role: load_actor_role(state, actor_did).await?,
            subject_did: subject_did.to_string(),
            subject_member: Some(member_state(subject_role.to_string(), subject_member)),
            evidence: Evidence {
                vetting: None,
                invitation: None,
                presentation: None,
                request,
            },
            // Unthreaded, and presents no credentials — see the role-change
            // spine above.
            thread_id: None,
        },
    )
    .await
}

/// Parse a disposition wire string into a concrete `Disposition`. Unknown /
/// `policydefault` → `None` (callers fall back to Tombstone).
fn parse_disposition_opt(s: &str) -> Option<Disposition> {
    match s {
        "purge" => Some(Disposition::Purge),
        "tombstone" => Some(Disposition::Tombstone),
        "historical" => Some(Disposition::Historical),
        _ => None,
    }
}

#[cfg(test)]
mod p0_14_role_change_policy_tests {
    //! P0.14: admin promotion must flow through `role_change_via_pipeline`, so
    //! the operator's `role_change.rego` governs the grant — and, since #1645,
    //! so do the host invariants the pipeline resolves for itself. These
    //! exercise the shared pipeline directly; the full UV ceremony is covered
    //! separately.
    use super::*;
    use affinidi_status_list::StatusPurpose;
    use chrono::Utc;
    use vti_common::auth::extractor::AuthClaims;
    use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

    use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
    use crate::members::{Member, store_member};
    use crate::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    use crate::test_support::TestVtc;

    const RP: &str = "https://vtc.example.com";
    const ADMIN: &str = "did:key:zPromoter";
    const SUBJECT: &str = "did:key:zCandidate";

    /// Claims for `did` backed by a real session row, elevated or not.
    ///
    /// `elevated` is the whole variable these tests turn: the pipeline reads
    /// the live session, so an "I stepped up" flag in the test would prove
    /// nothing about what the service does.
    async fn caller(vtc: &TestVtc, did: &str, elevated: bool) -> AuthClaims {
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        store_session(
            &vtc.state.sessions_ks,
            &Session {
                session_id: session_id.clone(),
                did: did.to_string(),
                challenge: String::new(),
                state: SessionState::Authenticated,
                created_at: now_epoch(),
                last_seen: now_epoch(),
                refresh_token: None,
                refresh_expires_at: None,
                tee_attested: false,
                amr: vec!["passkey".into()],
                acr: "aal2".into(),
                acr_expires_at: elevated.then(|| now_epoch() + 900),
                token_id: None,
                session_pubkey_b58btc: None,
            },
        )
        .await
        .unwrap();
        AuthClaims {
            did: did.to_string(),
            role: vti_common::acl::Role::Admin,
            session_id,
            amr: vec!["passkey".into()],
            acr: "aal2".into(),
            ..Default::default()
        }
    }

    async fn build() -> TestVtc {
        let vtc = TestVtc::builder()
            .with_signers(true)
            .with_public_url(RP)
            .build()
            .await;
        crate::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .expect("install default policies");
        for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
            crate::status_list::ensure_initial(
                &vtc.state.status_lists_ks,
                purpose,
                format!("{RP}/v1/status-lists/{purpose}"),
            )
            .await
            .expect("ensure status list");
        }
        seed(&vtc, ADMIN, VtcRole::Admin).await;
        seed(&vtc, SUBJECT, VtcRole::Member).await;
        vtc
    }

    async fn seed(vtc: &TestVtc, did: &str, role: VtcRole) {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                allowed_contexts: vec![],
                created_at: crate::auth::session::now_epoch(),
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
        store_member(&vtc.state.members_ks, &Member::fresh(did))
            .await
            .unwrap();
    }

    /// VTI-OPS-051: the elevation is read from the caller's session, so a
    /// promotion driven by an un-elevated admin session is refused whichever
    /// route drove it.
    #[tokio::test]
    async fn admin_promotion_without_a_live_step_up_is_refused() {
        let vtc = build().await;
        let actor = caller(&vtc, ADMIN, false).await;
        let err = role_change_via_pipeline(&vtc.state, &actor, SUBJECT, "member", "admin")
            .await
            .expect_err("an un-elevated session must not confer admin");
        assert!(
            matches!(err, AppError::StepUpRequired(_)),
            "the refusal must be the step-up signal, got {err:?}"
        );
        let acl = get_acl_entry(&vtc.state.acl_ks, SUBJECT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(acl.role, VtcRole::Member, "a refused promotion writes");
    }

    /// VTI-OPS-050: a second factor proves who is present, never that a second
    /// person agreed — so it does not buy self-promotion.
    #[tokio::test]
    async fn self_promotion_is_refused_even_with_a_live_step_up() {
        let vtc = build().await;
        let actor = caller(&vtc, ADMIN, true).await;
        seed(&vtc, "did:key:zSelf", VtcRole::Member).await;
        let mut actor = actor;
        actor.did = "did:key:zSelf".into();

        let err = role_change_via_pipeline(&vtc.state, &actor, "did:key:zSelf", "member", "admin")
            .await
            .expect_err("nobody promotes themselves");
        match err {
            AppError::Forbidden(msg) => assert!(
                msg.contains("acl/change-role"),
                "the refusal should name the replacement path, got {msg}"
            ),
            other => panic!("expected Forbidden, got {other:?}"),
        }
        let acl = get_acl_entry(&vtc.state.acl_ks, "did:key:zSelf")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(acl.role, VtcRole::Member);
    }

    /// The compare-and-swap the promotion path re-checks **under the lock**: a
    /// `current_role` that no longer matches the stored row is a race, not an
    /// instruction to overwrite whatever landed in between.
    #[tokio::test]
    async fn a_promotion_racing_another_role_write_is_a_conflict() {
        let vtc = build().await;
        let actor = caller(&vtc, ADMIN, true).await;
        // The caller read "member"; the row now says moderator.
        seed(&vtc, "did:key:zRaced", VtcRole::Moderator).await;

        let err = role_change_via_pipeline(&vtc.state, &actor, "did:key:zRaced", "member", "admin")
            .await
            .expect_err("a stale current_role must not promote");
        assert!(
            matches!(err, AppError::Conflict(_)),
            "expected a conflict, got {err:?}"
        );
    }

    #[tokio::test]
    async fn admin_promotion_with_step_up_is_allowed_by_default_policy() {
        let vtc = build().await;
        let actor = caller(&vtc, ADMIN, true).await;
        let granted = role_change_via_pipeline(&vtc.state, &actor, SUBJECT, "member", "admin")
            .await
            .expect("default policy allows admin promotion with a verified step-up");
        assert_eq!(granted.new_role, "admin");
        assert_eq!(granted.previous_role, "member");
        // The Remint executor wrote the new role.
        let acl = get_acl_entry(&vtc.state.acl_ks, SUBJECT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(acl.role, VtcRole::Admin);
    }

    #[tokio::test]
    async fn admin_promotion_is_403_when_policy_denies_even_with_step_up() {
        let vtc = build().await;
        // Activate a role_change policy that refuses every promotion.
        let src = "package vtc.role_change\nimport rego.v1\n\
                   default decision := {\"effect\": \"deny\", \"with\": {\"code\": \"frozen\"}}\n";
        let id = uuid::Uuid::new_v4();
        let sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(src.as_bytes()).into()
        };
        store_policy(
            &vtc.state.policies_ks,
            &Policy {
                id,
                purpose: PolicyPurpose::RoleChange,
                rego_source: src.into(),
                sha256: sha,
                activated_at: Some(Utc::now()),
                author_did: "did:key:test".into(),
                created_at: Utc::now(),
                version: 1,
                name: None,
                description: None,
            },
        )
        .await
        .unwrap();
        set_active_policy_id(&vtc.state.active_policies_ks, PolicyPurpose::RoleChange, id)
            .await
            .unwrap();

        let actor = caller(&vtc, ADMIN, true).await;
        let err = role_change_via_pipeline(&vtc.state, &actor, SUBJECT, "member", "admin")
            .await
            .expect_err("a deny policy must block the promotion even after a valid UV");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "deny → 403 Forbidden; got {err:?}"
        );
        // The ACL was left untouched.
        let acl = get_acl_entry(&vtc.state.acl_ks, SUBJECT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(acl.role, VtcRole::Member, "denied promotion must not write");
    }
}
