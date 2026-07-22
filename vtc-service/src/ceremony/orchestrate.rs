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
use crate::acl::get_acl_entry;
use crate::members::{Disposition, get_member};
use crate::policy::{PolicyPurpose, load_active_compiled};
use crate::server::AppState;

/// The roles a completed role change moved between — the caller's audit input.
#[derive(Debug)]
pub struct RoleChangeResult {
    pub previous_role: String,
    pub new_role: String,
}

/// Run a role change through the decision pipeline: assemble Facts → decide the
/// active `roleChange` policy → apply via the Remint executor. A policy `deny`
/// → 403; a `refer` (admin promotion needing step-up) → `StepUpRequired`.
///
/// `step_up` reports whether a verified reauth accompanies this change. The
/// PATCH path passes `false` (and refuses `admin` upstream); the
/// promote-to-admin endpoint passes `true` after its UV ceremony so the policy's
/// "admin with step-up" branch can allow. Shared by both so the operator's
/// `role_change.rego` governs *every* role transition, including the
/// highest-privilege admin grant (P0.14).
pub async fn role_change_via_pipeline(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
    current_role: &str,
    target_role: &str,
    step_up: bool,
) -> Result<RoleChangeResult, AppError> {
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
    // fatal.
    if let Err(e) =
        crate::credentials::delivery::deliver_credentials(state, subject_did, &[&outcome.role_vec])
            .await
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
                invitation: None,
                presentation: None,
                request: Some(json!({ "target_role": target_role, "step_up": step_up })),
            },
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
) -> Result<LeaveOutcome, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // Must have *something* to purge — a Member row and/or an ACL entry.
    let has_member = get_member(&state.members_ks, target_did).await?.is_some();
    let prior_acl = get_acl_entry(&state.acl_ks, target_did).await?;
    let has_acl = prior_acl.is_some();
    if !has_member && !has_acl {
        return Err(AppError::NotFound(format!(
            "no member or tombstone to purge: {target_did}"
        )));
    }

    // Reuse the single state-mutating seam with a forced Purge disposition.
    let EffectOutcome::Departed(outcome) = execute::apply(
        state,
        EffectPlan::Depart {
            subject: target_did.to_string(),
            disposition: Some("purge".to_string()),
        },
        actor_did,
    )
    .await?
    else {
        return Err(AppError::Internal(
            "purge effect did not produce a departure outcome".into(),
        ));
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

    info!(actor = actor_did, target = target_did, "member purged");
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
) -> Result<LeaveOutcome, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let target_acl = get_acl_entry(&state.acl_ks, target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;

    let target_member = get_member(&state.members_ks, target_did).await?;

    // Decide. Assemble verified leave Facts and run the active removal-purpose
    // decision policy. The no-last-admin invariant + the credential revocation
    // are the *effect* (executor below), not the policy.
    let facts = assemble_leave_facts(
        state,
        actor_did,
        target_did,
        &target_acl.role.to_string(),
        target_member.as_ref(),
        disposition,
        &reason,
    )
    .await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Removal,
    )
    .await?;
    let allow = match decide(&verified, &policy)? {
        Verdict::Allow(a) => a,
        Verdict::Deny(d) => {
            return Err(AppError::Forbidden(format!(
                "removal denied by policy ({})",
                d.code
            )));
        }
        // Leave is synchronous — a refer / request_more verdict is a
        // misconfigured policy for this purpose.
        Verdict::Refer(_) | Verdict::RequestMore(_) => {
            return Err(AppError::Internal(
                "removal policy returned a non-terminal verdict; leave is synchronous".into(),
            ));
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
        return Err(AppError::Internal(
            "depart effect did not produce a departure outcome".into(),
        ));
    };
    let disposition_str = disposition_wire(outcome.disposition);

    audit_writer
        .write(
            actor_did,
            Some(target_did),
            AuditEvent::MemberRemoved(MemberRemovedData {
                disposition: disposition_str.into(),
                reason: reason.clone(),
                prior_role: Some(target_acl.role.to_string()),
            }),
        )
        .await?;

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
                invitation: None,
                presentation: None,
                request,
            },
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
    //! P0.14: admin promotion must flow through `role_change_via_pipeline`
    //! (called by `promote_finish` with `step_up = true`), so the operator's
    //! `role_change.rego` governs the grant. These exercise the shared
    //! pipeline directly — the full UV ceremony is covered separately.
    use super::*;
    use affinidi_status_list::StatusPurpose;
    use chrono::Utc;

    use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
    use crate::members::{Member, store_member};
    use crate::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
    use crate::test_support::TestVtc;

    const RP: &str = "https://vtc.example.com";
    const ADMIN: &str = "did:key:zPromoter";
    const SUBJECT: &str = "did:key:zCandidate";

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

    #[tokio::test]
    async fn admin_promotion_with_step_up_is_allowed_by_default_policy() {
        let vtc = build().await;
        let granted = role_change_via_pipeline(
            &vtc.state, ADMIN, SUBJECT, "member", "admin", /* step_up */ true,
        )
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

        let err = role_change_via_pipeline(
            &vtc.state, ADMIN, SUBJECT, "member", "admin", /* step_up */ true,
        )
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
