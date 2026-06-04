//! `PATCH /v1/members/{did}` — M1.5.1.
//!
//! Non-role fields (publish consent, departure preference, extensions)
//! are written directly. A **role change** is the role-change ceremony:
//! it runs through the decision pipeline ([`crate::ceremony`]) —
//! assemble Facts → decide the active `roleChange` policy → apply via
//! the `Remint` executor arm (which updates the ACL role in place,
//! re-mints the role VEC, and enforces no-last-admin on demotion).
//!
//! `role=admin` is still refused on this surface: admin promotion fires
//! the step-up UV ceremony on its own endpoint
//! (`POST /v1/members/{did}/promote-to-admin`, spec §10.4), so the
//! policy's admin branch is reached there, not here.

use axum::Json;
use axum::extract::{Path, State};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use tracing::warn;

use vti_common::audit::{AuditEvent, MemberUpdatedData, RoleChangedData};

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry};
use crate::auth::AdminAuth;
use crate::ceremony::execute;
use crate::ceremony::{
    Actor, Context, EffectOutcome, EffectPlan, Evidence, Facts, MemberState, Purpose,
    State as FactsState, Subject, Verdict, VerifiedFacts,
};
use crate::community::load_profile;
use crate::error::AppError;
use crate::members::{Disposition, Member, get_member, list_members, store_member};
use crate::policy::{PolicyPurpose, load_active_compiled};
use crate::routes::members::read::MemberResponse;
use crate::server::AppState;

/// Body of the PATCH request. Every field is optional; a request
/// with no fields is a no-op (200 with the current row).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMemberRequest {
    pub role: Option<VtcRole>,
    pub publish_consent: Option<bool>,
    pub departure_preference: Option<Disposition>,
    pub extensions: Option<JsonValue>,
}

pub async fn update_member(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MemberResponse>, AppError> {
    // Role=Admin is forbidden on this surface — it routes to the
    // separate promote-to-admin endpoint (spec §10.4), where the
    // role-change policy's step-up branch is reached. Catch it early so
    // the response carries an operator-friendly hint.
    if matches!(req.role, Some(VtcRole::Admin)) {
        return Err(AppError::Validation(format!(
            "role=admin is not assignable via PATCH /v1/members/{{did}}; \
             use POST /v1/members/{did}/promote-to-admin (spec §10.4) \
             so the step-up UV ceremony fires."
        )));
    }

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let acl = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let mut member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    // Non-role field updates — written directly (not a ceremony).
    // Persisted *before* any role change so the Remint executor (which
    // re-reads the member to repoint its role VEC) sees them.
    let mut fields_changed: Vec<String> = Vec::new();
    if let Some(consent) = req.publish_consent
        && consent != member.publish_consent
    {
        member.publish_consent = consent;
        fields_changed.push("publishConsent".into());
    }
    if let Some(pref) = req.departure_preference
        && pref != member.departure_preference
    {
        member.departure_preference = pref;
        fields_changed.push("departurePreference".into());
    }
    if let Some(extensions) = req.extensions
        && extensions != member.extensions
    {
        member.extensions = extensions;
        fields_changed.push("extensions".into());
    }
    if !fields_changed.is_empty() {
        store_member(&state.members_ks, &member).await?;
    }

    // Role change → the role-change ceremony.
    let role_change = match req.role {
        Some(new_role) if new_role != acl.role => Some(new_role),
        _ => None,
    };
    if let Some(new_role) = role_change {
        let granted = role_change_via_pipeline(
            &state,
            &auth.0.did,
            &did,
            &acl.role.to_string(),
            &new_role.to_string(),
        )
        .await?;
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::RoleChanged(RoleChangedData {
                    previous_role: granted.previous_role,
                    new_role: granted.new_role,
                }),
            )
            .await?;
    }

    if !fields_changed.is_empty() {
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::MemberUpdated(MemberUpdatedData {
                    fields_changed: fields_changed.clone(),
                }),
            )
            .await?;
    }

    // Re-read the authoritative state for the response — the Remint
    // executor may have changed the ACL role + the member's role-VEC
    // pointer.
    let acl = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    Ok(Json(MemberResponse::from_pair_for_route(acl, member)))
}

struct RoleChangeResult {
    previous_role: String,
    new_role: String,
}

/// Run a (non-admin) role change through the decision pipeline:
/// assemble Facts → decide the active `roleChange` policy → apply via
/// the Remint executor. A policy `deny` → 403; a `refer` (admin
/// promotion needing step-up — not reachable here since admin is
/// refused upstream, but an operator policy could still refer) →
/// `StepUpRequired`.
async fn role_change_via_pipeline(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
    current_role: &str,
    target_role: &str,
) -> Result<RoleChangeResult, AppError> {
    let facts =
        assemble_role_change_facts(state, actor_did, subject_did, current_role, target_role)
            .await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::RoleChange,
    )
    .await?;

    let allow = match crate::ceremony::decide(&verified, &policy)? {
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

/// Assemble purpose-`role-change` [`Facts`]: the actor's role, the
/// subject's current member facts, and the requested `target_role`
/// (with `step_up: false` — PATCH carries no reauth; the step-up path
/// is the promote-to-admin endpoint).
async fn assemble_role_change_facts(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
    current_role: &str,
    target_role: &str,
) -> Result<Facts, AppError> {
    let actor_role = get_acl_entry(&state.acl_ks, actor_did)
        .await?
        .map(|e| e.role.to_string());
    let subject_member = get_member(&state.members_ks, subject_did).await?;

    let community_did = load_profile(&state.community_ks)
        .await?
        .map(|p| p.community_did)
        .unwrap_or_default();
    let member_count = list_members(&state.members_ks).await?.len() as u64;

    Ok(Facts {
        purpose: Purpose::RoleChange,
        now: Utc::now(),
        actor: Actor {
            did: actor_did.to_string(),
            role: actor_role,
            authenticated: true,
        },
        subject: Subject {
            did: subject_did.to_string(),
        },
        context: Context {
            community_did,
            channel: "rest".to_string(),
            member_count,
        },
        evidence: Evidence {
            invitation: None,
            presentation: None,
            request: Some(json!({ "target_role": target_role, "step_up": false })),
        },
        state: FactsState {
            subject_member: Some(MemberState {
                role: current_role.to_string(),
                status: subject_member
                    .as_ref()
                    .map(|m| {
                        if m.removed_at.is_some() {
                            "removed"
                        } else {
                            "active"
                        }
                    })
                    .unwrap_or("active")
                    .to_string(),
                joined_at: subject_member.map(|m| m.joined_at).unwrap_or_else(Utc::now),
                personhood: None,
            }),
        },
    })
}

// Re-export `from_pair` under a route-only alias so this module
// doesn't have to make the constructor public on `MemberResponse`.
impl MemberResponse {
    pub(crate) fn from_pair_for_route(acl: VtcAclEntry, member: Member) -> Self {
        // Inline the same join the read endpoints do — duplicating
        // the body (~10 lines) is cheaper than exposing a public
        // constructor that's only used by route handlers.
        Self {
            did: member.did,
            role: acl.role,
            label: acl.label,
            joined_at: member.joined_at,
            publish_consent: member.publish_consent,
            departure_preference: member.departure_preference,
            status_list_index: member.status_list_index,
            current_vmc_id: member.current_vmc_id,
            current_role_vec_id: member.current_role_vec_id,
            extensions: member.extensions,
            personhood: member.personhood,
            personhood_asserted_at: member.personhood_asserted_at,
        }
    }
}
