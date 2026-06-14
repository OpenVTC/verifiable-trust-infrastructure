//! `DELETE /v1/members/me` (M1.11.1) + `DELETE /v1/members/{did}`
//! (M1.12.1) — the **leave ceremony**.
//!
//! Both paths converge on `remove_inner`, which is the leave instance
//! of the ceremony decision pipeline ([`crate::ceremony`]):
//!
//! 1. **Facts** — `assemble_leave_facts` reads the actor's + subject's
//!    community roles into a purpose-`leave` [`Facts`] (`actor` may
//!    differ from `subject`: an admin removing a member, or a member
//!    removing themselves).
//! 2. **Decide** — the active `removal`-purpose decision policy
//!    (`data.vtc.removal.decision`) returns allow/deny. The default
//!    policy allows self-leave unconditionally and an admin removing a
//!    non-admin; it denies removing an admin.
//! 3. **Effect** — the verdict is applied by the effect executor
//!    ([`execute::apply`] with [`EffectPlan::Depart`]), which owns the
//!    no-last-admin invariant (→ 409, host-enforced), the ACL/Member
//!    deletion + disposition, and the credential revocation.
//!
//! Disposition precedence (resolved here, around the decision): the
//! caller's explicit request wins, then the member's
//! `departure_preference`, then the policy's chosen disposition, then
//! `tombstone`.

use affinidi_status_list::StatusPurpose;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use vti_common::audit::{AuditEvent, MemberRemovedData, StatusListFlippedData};
use vti_common::error::AppError;

use crate::acl::get_acl_entry;
use crate::auth::{AdminAuth, AuthClaims};
use crate::ceremony::execute;
use crate::ceremony::{
    Actor, Context, EffectOutcome, EffectPlan, Evidence, Facts, MemberState, Purpose,
    State as FactsState, Subject, Verdict, VerifiedFacts,
};
use crate::community::load_profile;
use crate::members::{Disposition, get_member};
use crate::policy::{PolicyPurpose, load_active_compiled};
use crate::server::AppState;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RemoveBody {
    #[serde(default)]
    pub disposition: Option<Disposition>,
    /// Optional admin-only reason. Self-remove ignores this (the
    /// member doesn't need to justify their own departure). Capped
    /// at 1024 chars at the route layer.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RemoveResponse {
    pub did: String,
    pub disposition: String,
    pub removed: bool,
}

const REASON_MAX: usize = 1024;

// ---------------------------------------------------------------------------
// DELETE /v1/members/me — M1.11.1
// ---------------------------------------------------------------------------

/// DELETE /members/me — self-leave ceremony. Auth: any authenticated member.
#[utoipa::path(
    delete, path = "/members/me", tag = "members",
    security(("bearer_jwt" = [])),
    request_body = RemoveBody,
    responses(
        (status = 200, description = "Member removed", body = RemoveResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Removal denied by policy"),
    ),
)]
pub async fn self_remove(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: Option<Json<RemoveBody>>,
) -> Result<(StatusCode, Json<RemoveResponse>), AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let target_did = auth.did.clone();
    // Self-leave: actor == subject. The decision policy allows this
    // unconditionally (it sees `actor.did == subject.did`); the
    // no-last-admin invariant still applies in the effect stage.
    let outcome = remove_inner(
        &state,
        &auth.did,
        &target_did,
        body.disposition,
        // Self-remove ignores any caller-supplied reason — the
        // departure is the member's own decision and doesn't carry
        // an externally-meaningful justification field.
        String::new(),
    )
    .await?;
    Ok((StatusCode::OK, Json(outcome)))
}

// ---------------------------------------------------------------------------
// DELETE /v1/members/{did} — M1.12.1 (REST only)
// ---------------------------------------------------------------------------

/// DELETE /members/{did} — admin removes another member. Auth: Admin.
#[utoipa::path(
    delete, path = "/members/{did}", tag = "members",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "Member DID")),
    request_body = RemoveBody,
    responses(
        (status = 200, description = "Member removed", body = RemoveResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin / removal denied by policy"),
        (status = 404, description = "Member not found"),
    ),
)]
pub async fn admin_remove(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(target_did): Path<String>,
    body: Option<Json<RemoveBody>>,
) -> Result<(StatusCode, Json<RemoveResponse>), AppError> {
    if admin.0.did == target_did {
        return Err(AppError::Validation(
            "use DELETE /v1/members/me to remove yourself — \
             DELETE /v1/members/{did} is for admins removing other members"
                .to_string(),
        ));
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let reason = body.reason.unwrap_or_default();
    if reason.len() > REASON_MAX {
        return Err(AppError::Validation(format!(
            "reason exceeds {REASON_MAX} chars (got {})",
            reason.len(),
        )));
    }
    let outcome = remove_inner(&state, &admin.0.did, &target_did, body.disposition, reason).await?;
    Ok((StatusCode::OK, Json(outcome)))
}

// ---------------------------------------------------------------------------
// Shared inner removal
// ---------------------------------------------------------------------------

/// The leave ceremony's decide → resolve → effect spine. Returns
/// `Ok(RemoveResponse)` on departure, `Err(Forbidden)` when the policy
/// denies, or `Err(Conflict)` for the executor's no-last-admin
/// invariant.
///
/// `actor_did` is the initiator (self for self-leave, admin for
/// admin-remove) — the policy distinguishes the two via `actor.did ==
/// subject.did`. `target_did` is the subject being removed.
pub async fn remove_inner(
    state: &AppState,
    actor_did: &str,
    target_did: &str,
    disposition: Option<Disposition>,
    reason: String,
) -> Result<RemoveResponse, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let target_acl = get_acl_entry(&state.acl_ks, target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;

    let target_member = get_member(&state.members_ks, target_did).await?;

    // Decide. Assemble verified leave Facts and run the active
    // removal-purpose decision policy. The no-last-admin invariant +
    // the credential revocation are the *effect* (executor below), not
    // the policy.
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
    let allow = match crate::ceremony::decide(&verified, &policy)? {
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

    // Resolve the final disposition: the caller's explicit request
    // wins; then the member's `departure_preference`; then the policy's
    // chosen disposition (`with.disposition`); then `Tombstone`.
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

    // Effect: the no-last-admin invariant + ACL/Member removal +
    // credential revocation, via the ceremony effect executor (the
    // single state-mutating seam). A last-admin removal surfaces as the
    // executor's `Conflict` → 409, untouched state.
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
            }),
        )
        .await?;

    // M2.14: the executor flipped the revocation bit (best-effort).
    // Emit the audit event for the slot it reported.
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

    Ok(RemoveResponse {
        did: target_did.to_string(),
        disposition: disposition_str.into(),
        removed: true,
    })
}

/// Wire string for a resolved (concrete) disposition. Mirrors the
/// `Disposition` serde representation; used for the response +
/// audit + the `EffectPlan::Depart` payload.
fn disposition_wire(d: Disposition) -> &'static str {
    match d {
        Disposition::Purge => "purge",
        Disposition::Tombstone => "tombstone",
        Disposition::Historical => "historical",
        Disposition::PolicyDefault => "policydefault",
    }
}

// ---------------------------------------------------------------------------
// Leave-ceremony facts assembly
// ---------------------------------------------------------------------------

/// Read the actor's community role + the subject's member facts into a
/// purpose-`leave` [`Facts`] for the decision policy. `subject_role` is
/// the subject's ACL role (already fetched by the caller for the 404
/// gate); `subject_member` is their member row, if any.
async fn assemble_leave_facts(
    state: &AppState,
    actor_did: &str,
    subject_did: &str,
    subject_role: &str,
    subject_member: Option<&crate::members::Member>,
    disposition: Option<Disposition>,
    reason: &str,
) -> Result<Facts, AppError> {
    let actor_role = get_acl_entry(&state.acl_ks, actor_did)
        .await?
        .map(|e| e.role.to_string());

    let subject_member_state = Some(MemberState {
        role: subject_role.to_string(),
        status: subject_member
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
    });

    let community_did = load_profile(&state.community_ks)
        .await?
        .map(|p| p.community_did)
        .unwrap_or_default();
    let member_count = state.member_count();

    // Ceremony request params: the operator's requested disposition +
    // the admin-supplied reason. Absent when neither is set.
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

    Ok(Facts {
        purpose: Purpose::Leave,
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
            request,
        },
        state: FactsState {
            subject_member: subject_member_state,
        },
    })
}

/// Parse a disposition wire string into a concrete `Disposition`.
/// Unknown / `policydefault` → `None` (callers fall back to Tombstone).
fn parse_disposition_opt(s: &str) -> Option<Disposition> {
    match s {
        "purge" => Some(Disposition::Purge),
        "tombstone" => Some(Disposition::Tombstone),
        "historical" => Some(Disposition::Historical),
        _ => None,
    }
}
