//! The ceremony decision pipeline — one pipeline, every community
//! state transition an instance of it.
//!
//! Design: `docs/05-design-notes/vtc-ceremony-pipeline.md` (with the
//! catalog, Rule-IR, and protocol companions). The thesis: a
//! community has many governed transitions — joining, leaving, role
//! changes, directory queries — that share one shape:
//!
//! ```text
//! TRIGGER → GATHER → VERIFY (host) → FACTS → EVALUATE (<purpose>.rego)
//!         → VERDICT → EFFECTS (<purpose>)
//! ```
//!
//! Everything expensive to build — verification, the verdict model,
//! versioning, governance, the visual authoring compiler — is built
//! once here and inherited by every ceremony, rather than wired
//! bespoke per purpose as in the MVP.
//!
//! ## What this module contains (pipeline stage A — the spine)
//!
//! - [`facts`] — the purpose-agnostic [`Facts`] contract (the typed
//!   policy `input`), replacing the MVP's lossy `vp_claims`.
//! - [`verdict`] — the four-valued [`Verdict`] (`allow` / `deny` /
//!   `refer` / `request_more`), replacing the MVP's boolean.
//! - [`verify`] — the [`VerifiedFacts`] typestate: the gate that
//!   guarantees the policy only ever sees verified facts.
//! - [`evaluate`] — runs a purpose's policy over verified facts and
//!   parses the decision, with a host structural-totality backstop.
//! - [`invariant`] — the host-enforced hard guards a policy can't
//!   override (privilege ceiling, step-up); applied after evaluate.
//! - [`decide`] — the `evaluate → invariant` driver that turns a
//!   [`VerifiedFacts`] + the purpose's policy into a final
//!   [`Verdict`].
//! - [`effects`] — plans the per-purpose state change a verdict
//!   authorizes ([`effects::EffectPlan`]). The directory projection
//!   (read-only) is fully realized; the write plans (admit / depart /
//!   re-mint) are typed intents the executor applies.
//! - [`execute`] — the async effect executor ([`execute::apply`]):
//!   applies a plan against `AppState`. The **Admit** (join) write
//!   path is wired and is the op the manual approve route now goes
//!   through; **Depart** / **Remint** await their ceremonies.
//!
//! Still to land on top of this spine (pipeline §11): the Depart /
//! Remint executor arms (with their leave / role-change ceremonies)
//! and the remaining state-dependent invariant — no-last-admin (see
//! [`invariant`]).
//!
//! ## Relationship to the existing `policy` + `join` modules
//!
//! This is the greenfield pipeline; [`crate::policy`] (the regorus
//! engine plus persistence) is **reused** underneath it — `Verdict`
//! parses the decision object [`crate::policy::engine::evaluate`]
//! returns.
//! The MVP's bespoke [`crate::join`] flow and its `vp_claims`
//! projection are what this pipeline supersedes; they remain in place
//! until ceremonies are ported over (build-vs-reuse map, pipeline
//! §10).

pub mod assemble;
pub mod effects;
pub mod evaluate;
pub mod execute;
pub mod facts;
pub mod invariant;
pub mod verdict;
pub mod verify;

pub use assemble::{FactsInputs, assemble_facts, load_actor_role, member_state};
pub use effects::{EffectPlan, plan};
pub use evaluate::evaluate;
pub use execute::{AdmitOutcome, DepartOutcome, EffectOutcome, RemintOutcome, apply};
pub use facts::{
    Actor, Context, Credential, CredentialStatus, Evidence, Facts, Invitation, MemberState,
    Presentation, Purpose, State, Subject,
};
pub use invariant::{Invariant, InvariantViolation};
pub use verdict::{Allow, Deny, Refer, RequestMore, Verdict};
pub use verify::{VerifiedFacts, VerifyError};

use crate::policy::engine::CompiledPolicy;
use vti_common::error::AppError;

/// The Evaluate → Invariant driver: turn verified facts + the
/// purpose's compiled policy into a final [`Verdict`].
///
/// This is the host's decision spine (pipeline §2). It runs the
/// policy ([`evaluate`]) and then applies the host-enforced
/// invariants ([`invariant::enforce`]) the policy can't override. A
/// vetoed decision is converted to a denying verdict — tagged with
/// the invariant code — and logged: the policy *proposed* an allow
/// the host refused, which is an operator-visible misconfiguration,
/// not a caller error.
///
/// What this does **not** do is apply effects. The returned verdict
/// is the authoritative decision; the per-purpose effect handler
/// (issue / revoke / project) consumes it next — still to land
/// (pipeline §11).
pub fn decide(verified: &VerifiedFacts, policy: &CompiledPolicy) -> Result<Verdict, AppError> {
    let proposed = evaluate(verified, policy)?;
    match invariant::enforce(verified.facts(), proposed) {
        Ok(verdict) => Ok(verdict),
        Err(violation) => {
            tracing::warn!(
                purpose = verified.purpose().as_str(),
                invariant = violation.invariant.code(),
                detail = %violation.detail,
                "ceremony policy decision vetoed by host invariant",
            );
            Ok(violation.into_deny())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::engine::compile;
    use serde_json::json;
    use uuid::Uuid;

    fn join_facts() -> VerifiedFacts {
        let facts = Facts {
            purpose: Purpose::Join,
            now: "2026-05-30T12:00:00Z".parse().unwrap(),
            actor: Actor {
                did: "did:key:zHuman".into(),
                role: None,
                authenticated: true,
            },
            subject: Subject {
                did: "did:key:zHuman".into(),
            },
            context: Context {
                community_did: "did:webvh:acme.example".into(),
                channel: "rest".into(),
                member_count: 10,
            },
            evidence: Evidence::default(),
            state: State::default(),
        };
        VerifiedFacts::assemble(facts).expect("verified")
    }

    /// End-to-end driver: a (misconfigured) join policy that grants
    /// admin is run, the host invariant vetoes it, and `decide`
    /// returns a deny tagged `privilege-ceiling` — the policy's allow
    /// never takes effect.
    #[test]
    fn decide_vetoes_a_join_policy_that_grants_admin() {
        const ROGUE_JOIN: &str = r#"
package vtc.join

import future.keywords.if

default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# A misconfigured policy that tries to hand out admin on join.
decision := {"effect": "allow", "with": {"role": "admin"}} if {
    true
}
"#;
        let policy = compile(ROGUE_JOIN, Uuid::new_v4()).unwrap();
        let verdict = decide(&join_facts(), &policy).expect("decide");
        match verdict {
            Verdict::Deny(d) => assert_eq!(d.code, "privilege-ceiling"),
            other => panic!("expected host-vetoed deny, got {other:?}"),
        }
    }

    /// End-to-end happy path: a well-formed join policy granting
    /// `member` passes the invariants and `decide` returns the allow
    /// verbatim.
    #[test]
    fn decide_passes_a_well_formed_member_grant() {
        const GOOD_JOIN: &str = r#"
package vtc.join

import future.keywords.if

default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

decision := {"effect": "allow", "with": {"role": "member"}} if {
    input.actor.authenticated == true
}
"#;
        let policy = compile(GOOD_JOIN, Uuid::new_v4()).unwrap();
        let verdict = decide(&join_facts(), &policy).expect("decide");
        assert_eq!(
            verdict,
            Verdict::Allow(Allow {
                role: Some("member".into()),
                ..Default::default()
            })
        );
    }

    /// A policy returning `deny` is returned untouched — `decide`
    /// doesn't second-guess a refusal.
    #[test]
    fn decide_returns_policy_deny_untouched() {
        const DENY_JOIN: &str = r#"
package vtc.join

default decision := {"effect": "deny", "with": {"code": "closed"}}
"#;
        let policy = compile(DENY_JOIN, Uuid::new_v4()).unwrap();
        let verdict = decide(&join_facts(), &policy).expect("decide");
        assert_eq!(
            verdict,
            Verdict::from_decision(json!({ "effect": "deny", "with": { "code": "closed" } }))
                .unwrap()
        );
    }
}
