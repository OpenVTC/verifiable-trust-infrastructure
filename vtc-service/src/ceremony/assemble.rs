//! One facts-assembly path for every ceremony purpose.
//!
//! The four route handlers (join submit, leave, role-change, directory) each
//! built a [`Facts`] by hand, repeating the community-profile load, the cached
//! member count, the authenticated [`Actor`], and the [`MemberState`] shaping
//! (status from the tombstone, `joined_at`-or-now). This collapses that skeleton
//! into [`assemble_facts`] + two small helpers; the callers keep only what
//! genuinely differs per purpose — the evidence, and how the subject's role is
//! sourced.

use chrono::Utc;

use vti_common::error::AppError;

use crate::acl::get_acl_entry;
use crate::community::load_profile;
use crate::members::Member;
use crate::server::AppState;

use super::facts::{
    Actor, Context, Evidence, Facts, MemberState, Purpose, State as FactsState, Subject,
};

/// The per-purpose inputs to [`assemble_facts`]. Everything else — the clock,
/// the `"rest"` channel, the community profile, the cached member count, and
/// `authenticated: true` — is uniform across ceremonies.
pub struct FactsInputs {
    pub purpose: Purpose,
    pub actor_did: String,
    /// The actor's community role. `None` for a join (the applicant isn't a
    /// member yet); an ACL lookup ([`load_actor_role`]) for the rest.
    pub actor_role: Option<String>,
    pub subject_did: String,
    pub subject_member: Option<MemberState>,
    pub evidence: Evidence,
}

/// Build a [`Facts`] from the uniform community context plus the per-purpose
/// [`FactsInputs`].
pub async fn assemble_facts(state: &AppState, inputs: FactsInputs) -> Result<Facts, AppError> {
    let community_did = load_profile(&state.community_ks)
        .await?
        .map(|p| p.community_did)
        .unwrap_or_default();
    Ok(Facts {
        purpose: inputs.purpose,
        now: Utc::now(),
        actor: Actor {
            did: inputs.actor_did,
            role: inputs.actor_role,
            authenticated: true,
        },
        subject: Subject {
            did: inputs.subject_did,
        },
        context: Context {
            community_did,
            channel: "rest".to_string(),
            member_count: state.member_count(),
        },
        evidence: inputs.evidence,
        state: FactsState {
            subject_member: inputs.subject_member,
        },
    })
}

/// The actor's community role from the ACL (`None` when no ACL row exists).
pub async fn load_actor_role(state: &AppState, did: &str) -> Result<Option<String>, AppError> {
    Ok(get_acl_entry(&state.acl_ks, did)
        .await?
        .map(|e| e.role.to_string()))
}

/// Shape a subject's [`MemberState`] from its role + optional member row:
/// `status` from the row's tombstone (`removed`/`active`), `joined_at` from the
/// row (or now when the row is absent).
pub fn member_state(role: String, member: Option<&Member>) -> MemberState {
    MemberState {
        role,
        status: member
            .map(|m| {
                if m.removed_at.is_some() {
                    "removed"
                } else {
                    "active"
                }
            })
            .unwrap_or("active")
            .to_string(),
        joined_at: member.map(|m| m.joined_at).unwrap_or_else(Utc::now),
        personhood: None,
    }
}
