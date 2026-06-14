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

use serde_json::json;
use tracing::warn;

use vti_common::error::AppError;

use super::execute::{self, EffectOutcome};
use super::{
    Evidence, FactsInputs, Purpose, Verdict, VerifiedFacts, assemble_facts, decide,
    effects::EffectPlan, load_actor_role, member_state,
};
use crate::members::get_member;
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
