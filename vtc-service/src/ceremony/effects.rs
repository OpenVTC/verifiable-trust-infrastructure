//! The Effects stage — turn a final [`Verdict`] into the concrete,
//! per-purpose state change it authorizes (ceremony-pipeline design
//! §5).
//!
//! Effects are "the only stage that mutates state, driven solely by
//! the verdict." This module splits that into two halves so the
//! decision logic stays pure and testable:
//!
//! 1. **Plan** (this module, now) — [`plan`] maps a `(VerifiedFacts,
//!    Verdict)` pair to a typed [`EffectPlan`]: the *intent* (admit
//!    this DID as `member`, project these fields, …). Pure, no I/O.
//! 2. **Apply** (next slice) — an async executor consumes the
//!    [`EffectPlan`] against `AppState`, reusing the existing
//!    issue-VMC / write-ACL / write-Member helpers (today's bespoke
//!    `routes::join_requests::decide::approve` becomes one such
//!    executor). Deliberately not wired here: it means refactoring a
//!    tested write path, which belongs in its own change.
//!
//! Splitting plan from apply mirrors the pipeline's discipline —
//! "decide what to do" (pure, the verdict + this plan) is separated
//! from "do it" (the single state-mutating stage).
//!
//! ## The directory effect is fully realized here
//!
//! Directory is the read-only ceremony: its `allow` carries a *field
//! projection*, not a write. The whole effect is computable from the
//! verified facts — so [`plan`] returns a finished
//! [`EffectPlan::Project`] with the actual field/value map, and this
//! is also where the **PII-boundary invariant** (pipeline §5) lands:
//! the projected fields are `allow.with.fields` ∩ the community's
//! whitelist, so a policy can never project a field outside the
//! boundary even if it names one.

use serde_json::{Map, Value as JsonValue};
use vti_common::error::AppError;

use super::facts::Purpose;
use super::verdict::Verdict;
use super::verify::VerifiedFacts;

/// The concrete, per-purpose intent a [`Verdict`] authorizes. The
/// async executor (next slice) turns the write variants into ACL /
/// Member / credential mutations; [`Self::Project`] is already
/// complete (directory is read-only).
#[derive(Debug, Clone, PartialEq)]
pub enum EffectPlan {
    /// Directory `allow` — return exactly these subject fields. The
    /// map is already filtered through the PII boundary; the executor
    /// just serializes it to the response.
    Project { fields: Map<String, JsonValue> },
    /// Join `allow` — admit `subject` with `role`, then discharge
    /// `obligations` (e.g. `reciprocate_vmc`). The executor writes
    /// the ACL + Member rows and issues the VMC + role VEC.
    Admit {
        subject: String,
        role: String,
        obligations: Vec<String>,
    },
    /// Leave `allow` — remove `subject` and wind down their
    /// credentials per `disposition`. The executor revokes the VMC +
    /// removes the ACL / Member rows.
    Depart {
        subject: String,
        disposition: Option<String>,
    },
    /// Role-change `allow` — re-mint `subject`'s role VEC at `role`
    /// and update the ACL row in place. The DID + VMC are unchanged.
    Remint { subject: String, role: String },
    /// No state change — the verdict was `deny` / `refer` /
    /// `request_more`. The outcome lives in the [`Verdict`] itself
    /// (refusal, queue, or Presentation Definition); the effect stage
    /// writes nothing.
    NoStateChange,
}

/// Plan the effect a verdict authorizes.
///
/// `pii_whitelist` is the community's directory field whitelist; it
/// is consulted only for the directory projection (ignored for other
/// purposes). The host supplies it from community config.
///
/// Returns [`AppError::Internal`] if an `allow` is missing a field
/// its purpose requires (e.g. a join `allow` with no `role`) — a
/// well-formed, invariant-checked verdict always carries what its
/// purpose needs, so a gap here is a policy/compiler bug, not caller
/// input.
pub fn plan(
    verified: &VerifiedFacts,
    verdict: &Verdict,
    pii_whitelist: &[String],
) -> Result<EffectPlan, AppError> {
    let Verdict::Allow(allow) = verdict else {
        return Ok(EffectPlan::NoStateChange);
    };

    let facts = verified.facts();
    let subject = facts.subject.did.clone();

    match facts.purpose {
        Purpose::Directory => Ok(EffectPlan::Project {
            fields: project_fields(
                verified,
                allow.fields.as_deref().unwrap_or(&[]),
                pii_whitelist,
            ),
        }),
        Purpose::Join => Ok(EffectPlan::Admit {
            subject,
            role: required_role(allow.role.as_deref(), "join")?,
            obligations: allow.obligations.clone(),
        }),
        Purpose::Leave => Ok(EffectPlan::Depart {
            subject,
            disposition: allow.disposition.clone(),
        }),
        Purpose::RoleChange => Ok(EffectPlan::Remint {
            subject,
            role: required_role(allow.role.as_deref(), "role-change")?,
        }),
    }
}

/// A grant whose purpose requires a role must carry one.
fn required_role(role: Option<&str>, purpose: &str) -> Result<String, AppError> {
    role.map(str::to_string).ok_or_else(|| {
        AppError::Internal(format!("{purpose} allow is missing the required `role`"))
    })
}

/// Build the directory projection: the subject's facts, restricted to
/// `allow.with.fields` ∩ `whitelist`.
///
/// The projection source is the **verified facts** the policy decided
/// over (`subject.did` + `state.subject_member`), not a fresh read —
/// the directory returns exactly the slice of what the policy saw
/// that it authorized. A requested field absent from the facts (e.g.
/// `extensions`, which the Phase-1 `MemberState` doesn't carry) is
/// simply omitted rather than invented.
fn project_fields(
    verified: &VerifiedFacts,
    requested: &[String],
    whitelist: &[String],
) -> Map<String, JsonValue> {
    let facts = verified.facts();

    // Source object: the subject member's fields plus the DID.
    let mut source = facts
        .state
        .subject_member
        .as_ref()
        .and_then(|m| serde_json::to_value(m).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    source.insert("did".into(), JsonValue::String(facts.subject.did.clone()));

    // PII boundary: a field is projected only if the policy asked for
    // it AND the community whitelist permits it AND the facts carry
    // it. The whitelist is the hard guard — intersecting here means a
    // policy can't widen the projection past the boundary.
    requested
        .iter()
        .filter(|f| whitelist.iter().any(|w| w == *f))
        .filter_map(|f| source.get(f).map(|v| (f.clone(), v.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::facts::{Actor, Context, Evidence, Facts, MemberState, State, Subject};
    use crate::ceremony::verdict::Allow;
    use serde_json::json;

    fn facts(purpose: Purpose, member: Option<MemberState>) -> Facts {
        Facts {
            purpose,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:zViewer".into(),
                role: Some("member".into()),
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
            evidence: Evidence::default(),
            state: State {
                subject_member: member,
            },
        }
    }

    fn member() -> MemberState {
        MemberState {
            role: "member".into(),
            status: "active".into(),
            joined_at: "2026-03-03T00:00:00Z".parse().unwrap(),
            personhood: None,
        }
    }

    fn verified(facts: Facts) -> VerifiedFacts {
        VerifiedFacts::assemble(facts).expect("verified")
    }

    fn allow(a: Allow) -> Verdict {
        Verdict::Allow(a)
    }

    /// A non-allow verdict plans no state change.
    #[test]
    fn deny_plans_no_state_change() {
        let v = verified(facts(Purpose::Join, None));
        let verdict = Verdict::default_deny();
        assert_eq!(plan(&v, &verdict, &[]).unwrap(), EffectPlan::NoStateChange);
    }

    /// A join allow plans an admit with the granted role + obligations.
    #[test]
    fn join_allow_plans_admit() {
        let v = verified(facts(Purpose::Join, None));
        let verdict = allow(Allow {
            role: Some("member".into()),
            obligations: vec!["reciprocate_vmc".into()],
            ..Default::default()
        });
        assert_eq!(
            plan(&v, &verdict, &[]).unwrap(),
            EffectPlan::Admit {
                subject: "did:key:zTarget".into(),
                role: "member".into(),
                obligations: vec!["reciprocate_vmc".into()],
            }
        );
    }

    /// A join allow without a role is a policy bug — Internal error.
    #[test]
    fn join_allow_without_role_errors() {
        let v = verified(facts(Purpose::Join, None));
        let verdict = allow(Allow::default());
        let err = plan(&v, &verdict, &[]).expect_err("join needs a role");
        assert!(matches!(err, AppError::Internal(_)), "got {err:?}");
    }

    /// A leave allow plans a departure carrying the disposition.
    #[test]
    fn leave_allow_plans_depart() {
        let v = verified(facts(Purpose::Leave, Some(member())));
        let verdict = allow(Allow {
            disposition: Some("revoke-vmc".into()),
            ..Default::default()
        });
        assert_eq!(
            plan(&v, &verdict, &[]).unwrap(),
            EffectPlan::Depart {
                subject: "did:key:zTarget".into(),
                disposition: Some("revoke-vmc".into()),
            }
        );
    }

    /// The directory projection returns exactly `with.fields` ∩
    /// whitelist, pulling values from the verified facts.
    #[test]
    fn directory_projection_intersects_fields_with_whitelist() {
        let v = verified(facts(Purpose::Directory, Some(member())));
        let verdict = allow(Allow {
            // Policy asks for did, role, joined_at, status.
            fields: Some(vec![
                "did".into(),
                "role".into(),
                "joined_at".into(),
                "status".into(),
            ]),
            ..Default::default()
        });
        // But the community whitelist only permits did + role.
        let whitelist = vec!["did".to_string(), "role".to_string()];

        match plan(&v, &verdict, &whitelist).unwrap() {
            EffectPlan::Project { fields } => {
                let got = JsonValue::Object(fields);
                assert_eq!(
                    got,
                    json!({ "did": "did:key:zTarget", "role": "member" }),
                    "status + joined_at must be dropped by the PII boundary",
                );
            }
            other => panic!("expected Project, got {other:?}"),
        }
    }

    /// A whitelisted-and-requested field that the facts don't carry
    /// (e.g. `extensions`) is omitted, not invented.
    #[test]
    fn directory_projection_omits_absent_facts() {
        let v = verified(facts(Purpose::Directory, Some(member())));
        let verdict = allow(Allow {
            fields: Some(vec!["did".into(), "extensions".into()]),
            ..Default::default()
        });
        let whitelist = vec!["did".to_string(), "extensions".to_string()];

        match plan(&v, &verdict, &whitelist).unwrap() {
            EffectPlan::Project { fields } => {
                assert_eq!(
                    JsonValue::Object(fields),
                    json!({ "did": "did:key:zTarget" })
                );
            }
            other => panic!("expected Project, got {other:?}"),
        }
    }

    /// A role-change allow plans a re-mint at the target role.
    #[test]
    fn role_change_allow_plans_remint() {
        let v = verified(facts(Purpose::RoleChange, Some(member())));
        let verdict = allow(Allow {
            role: Some("moderator".into()),
            ..Default::default()
        });
        assert_eq!(
            plan(&v, &verdict, &[]).unwrap(),
            EffectPlan::Remint {
                subject: "did:key:zTarget".into(),
                role: "moderator".into(),
            }
        );
    }
}
