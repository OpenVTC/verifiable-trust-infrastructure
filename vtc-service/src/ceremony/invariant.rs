//! Host-enforced invariants — hard guards a policy can never override
//! (ceremony-pipeline design §5).
//!
//! Invariants are checked by the **host**, around the policy, not
//! encoded in Rego — so an operator's policy edit can never disable
//! them. The policy proposes a [`Verdict`]; [`enforce`] is the host's
//! veto. A violated invariant refuses the transition regardless of
//! what the policy said.
//!
//! ## What's enforced here (state-free invariants)
//!
//! These two are decidable from [`Facts`] + the policy's [`Verdict`]
//! alone, so they live here now:
//!
//! - **Privilege ceiling (join)** — a `join` policy may grant
//!   `member` / `moderator` / custom roles, **never `admin`**. Admin
//!   is reachable only through the role-change step-up path. A
//!   `join` policy that returns `allow{role:admin}` is vetoed.
//! - **Step-up for admin (role-change)** — role-change *is* the
//!   sanctioned admin-promotion path, but only with a verified
//!   step-up. The host re-checks that any `allow{role:admin}` carries
//!   `evidence.request.step_up == true`, so a policy edit can't grant
//!   admin without the reauth ceremony.
//!
//! ## Where the other §5 invariants live
//!
//! [`enforce`] is intentionally pure over `(Facts, Verdict)` — it is
//! the *pre-effect* veto. Two design §5 invariants are naturally
//! enforced elsewhere because they need more than the verdict:
//!
//! - **PII boundary (directory, registry)** — enforced in the
//!   **effect/projection** stage ([`super::effects::plan`]), not here:
//!   the projection intersects `allow.with.fields` with the
//!   community whitelist as it builds the field map, so a policy can't
//!   project a field outside the boundary. It belongs with the
//!   projection because that's the stage that handles the fields.
//! - **No-last-admin (leave, role-change)** — still deferred. Needs
//!   the community's current admin count from the ACL keyspace to
//!   refuse a transition that would drop it to zero. Lands with the
//!   async effect executor that reads that state. Listed here, not
//!   silently absent: the host does **not** yet guarantee it, and the
//!   leave / role-change executor must before it ships.

use super::facts::{Facts, Purpose};
use super::verdict::Verdict;

/// The community role that ceremonies may never self-grant through
/// the join path, and may grant through role-change only behind
/// step-up. Matches the literal the example policies branch on
/// (`input.evidence.request.target_role == "admin"`).
pub const ADMIN_ROLE: &str = "admin";

/// Which host invariant a [`Verdict`] tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invariant {
    /// Join tried to grant `admin`.
    PrivilegeCeiling,
    /// Role-change tried to grant `admin` without a verified step-up.
    StepUpForAdmin,
}

impl Invariant {
    /// Stable code for audit + the synthesized deny.
    pub fn code(self) -> &'static str {
        match self {
            Invariant::PrivilegeCeiling => "privilege-ceiling",
            Invariant::StepUpForAdmin => "step-up-required",
        }
    }
}

/// A policy decision the host vetoed. Carries which invariant fired
/// and a human-readable detail for the audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantViolation {
    pub invariant: Invariant,
    pub detail: String,
}

impl InvariantViolation {
    /// The denying [`Verdict`] the host substitutes for the vetoed
    /// decision — the transition is refused, tagged with the
    /// invariant code so the operator can see *why* their policy's
    /// allow didn't stick.
    pub fn into_deny(self) -> Verdict {
        Verdict::Deny(super::verdict::Deny {
            code: self.invariant.code().into(),
            reason: Some(self.detail),
        })
    }
}

/// Apply the host invariants to a policy's [`Verdict`].
///
/// Only an `allow` can violate an invariant — `deny` / `refer` /
/// `request_more` grant nothing, so they pass through untouched. On
/// veto, returns the [`InvariantViolation`]; the caller
/// ([`super::decide`]) converts it to a denying verdict and logs it.
pub fn enforce(facts: &Facts, verdict: Verdict) -> Result<Verdict, InvariantViolation> {
    let Verdict::Allow(allow) = &verdict else {
        return Ok(verdict);
    };

    let grants_admin = allow.role.as_deref() == Some(ADMIN_ROLE);

    match facts.purpose {
        // Join may never grant admin, full stop.
        Purpose::Join if grants_admin => Err(InvariantViolation {
            invariant: Invariant::PrivilegeCeiling,
            detail: "join policy may not grant the admin role".into(),
        }),
        // Role-change may grant admin only behind a verified step-up.
        Purpose::RoleChange if grants_admin && !step_up_verified(facts) => {
            Err(InvariantViolation {
                invariant: Invariant::StepUpForAdmin,
                detail: "admin promotion requires a verified step-up".into(),
            })
        }
        _ => Ok(verdict),
    }
}

/// Whether the facts carry a verified step-up signal
/// (`evidence.request.step_up == true`). Absent / non-`true` reads as
/// "not stepped up" — the host defaults to refusing admin promotion.
fn step_up_verified(facts: &Facts) -> bool {
    facts
        .evidence
        .request
        .as_ref()
        .and_then(|r| r.get("step_up"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::facts::{Actor, Context, Evidence, State, Subject};
    use crate::ceremony::verdict::Allow;
    use serde_json::json;

    fn facts(purpose: Purpose, request: serde_json::Value) -> Facts {
        Facts {
            purpose,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:zActor".into(),
                role: Some("admin".into()),
                authenticated: true,
            },
            subject: Subject {
                did: "did:key:zTarget".into(),
            },
            context: Context {
                community_did: "did:webvh:acme.example".into(),
                channel: "rest".into(),
                member_count: 10,
            },
            evidence: Evidence {
                invitation: None,
                presentation: None,
                request: Some(request),
            },
            state: State {
                subject_member: None,
            },
        }
    }

    fn allow_role(role: &str) -> Verdict {
        Verdict::Allow(Allow {
            role: Some(role.into()),
            ..Default::default()
        })
    }

    /// A join policy granting a non-admin role passes.
    #[test]
    fn join_member_grant_passes() {
        let f = facts(Purpose::Join, json!({}));
        assert_eq!(
            enforce(&f, allow_role("member")).unwrap(),
            allow_role("member")
        );
    }

    /// A join policy granting admin is vetoed by the privilege
    /// ceiling — converted to a deny tagged `privilege-ceiling`.
    #[test]
    fn join_admin_grant_is_vetoed() {
        let f = facts(Purpose::Join, json!({}));
        let violation = enforce(&f, allow_role("admin")).expect_err("join admin must be vetoed");
        assert_eq!(violation.invariant, Invariant::PrivilegeCeiling);
        match violation.into_deny() {
            Verdict::Deny(d) => assert_eq!(d.code, "privilege-ceiling"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    /// Role-change to admin *with* step-up is allowed through.
    #[test]
    fn role_change_admin_with_step_up_passes() {
        let f = facts(
            Purpose::RoleChange,
            json!({ "target_role": "admin", "step_up": true }),
        );
        assert_eq!(
            enforce(&f, allow_role("admin")).unwrap(),
            allow_role("admin")
        );
    }

    /// Role-change to admin *without* step-up is vetoed even though a
    /// policy returned allow — the host guards it regardless.
    #[test]
    fn role_change_admin_without_step_up_is_vetoed() {
        let f = facts(
            Purpose::RoleChange,
            json!({ "target_role": "admin", "step_up": false }),
        );
        let violation = enforce(&f, allow_role("admin")).expect_err("admin needs step-up");
        assert_eq!(violation.invariant, Invariant::StepUpForAdmin);

        // Absent step_up reads the same as false.
        let f2 = facts(Purpose::RoleChange, json!({ "target_role": "admin" }));
        assert!(enforce(&f2, allow_role("admin")).is_err());
    }

    /// Role-change to a non-admin role doesn't engage the step-up
    /// guard.
    #[test]
    fn role_change_non_admin_passes_without_step_up() {
        let f = facts(Purpose::RoleChange, json!({ "target_role": "moderator" }));
        assert_eq!(
            enforce(&f, allow_role("moderator")).unwrap(),
            allow_role("moderator")
        );
    }

    /// Non-allow verdicts are never touched by the invariant pass.
    #[test]
    fn non_allow_verdicts_pass_through() {
        let f = facts(Purpose::Join, json!({}));
        let refer = Verdict::Refer(super::super::verdict::Refer {
            queue: "moderator".into(),
            reason: None,
        });
        assert_eq!(enforce(&f, refer.clone()).unwrap(), refer);
    }
}
