//! The Policy Decision Point (PDP).
//!
//! A maintainer-side Rego engine that decides the disposition of a Trust Task
//! before it is dispatched: `allow`, `deny`, `requireStepUp`, or
//! `requireConsent`. It replaces the inline "default allow" the vault handlers
//! carried, and generalises the vault-only policy of the 0.2 schema to any task
//! via `policy/_shared/0.3`.
//!
//! ## Design invariants
//!
//! - **Code decides, registry describes.** The authoritative `sideEffects` /
//!   `exposure` classification fed into [`types::PolicyInput`] comes from the
//!   compiled dispatch table ([`crate::trust_tasks`]), NOT from the published
//!   registry. Whoever controls the registry must not be able to lower the
//!   consent bar. (SPEC §7.3 items 13–14.)
//! - **Fail closed.** Every path that cannot produce an explicit `allow` — no
//!   policy fired, an evaluation error, a resource-budget abort, an
//!   unclassifiable input — resolves to `deny`. See [`decide`].
//! - **Priority-ordered, first-opinion-wins.** Policies run highest-priority
//!   first; the first whose `decision` rule fires is authoritative. A policy
//!   whose rule is undefined abstains rather than denying, so a narrow
//!   high-priority override can sit above a broad default.
//!
//! ## Layering
//!
//! - [`engine`] — the thin `regorus` wrapper (compile + evaluate one module).
//! - [`types`] — the Rust mirror of `policy/_shared/0.3`.
//! - [`decide`] — orchestration across the active policy set (this module).
//!
//! Persistence (the `policy:` keyspace), the `policy/*` Trust Task handlers,
//! per-request [`types::PolicyInput`] construction, and boot-installed default
//! policies land alongside this in the same PR series.

pub mod defaults;
pub mod engine;
pub mod input;
pub mod storage;
pub mod types;

pub use defaults::install_default_policy;
pub use engine::{CompiledPolicy, compile, evaluate_decision};
pub use input::build_policy_input;
pub use storage::load_active_for_context;
pub use types::{
    Consumer, Discloses, Disposition, Exposure, PolicyDecision, PolicyInput, PolicyModule,
    PolicyRequest, RequireConsent, SideEffectLevel, StepUp, TaskClass,
};

/// Decide a task's disposition across the priority-ordered active policy set.
///
/// Each entry is `(priority, compiled)`. Higher priority evaluates first; the
/// first policy whose `decision` rule fires wins. If every policy abstains — or
/// any evaluation errors or aborts — the result is a fail-closed `deny`.
///
/// This is the single choke point the vault call sites (and, later, every
/// dispatched task) route through, so the deny-by-default guarantee lives in
/// exactly one place.
pub fn decide(policies: &[(i32, CompiledPolicy)], input: &PolicyInput) -> PolicyDecision {
    let mut ordered: Vec<&(i32, CompiledPolicy)> = policies.iter().collect();
    // Descending priority; ties keep input order (stable sort).
    ordered.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority));

    for (_priority, compiled) in ordered {
        match engine::evaluate_decision(compiled, input) {
            Ok(Some(decision)) => return decision,
            Ok(None) => continue,
            Err(e) => {
                return PolicyDecision::default_deny(format!(
                    "policy {} evaluation failed: {e}",
                    compiled.id()
                ));
            }
        }
    }

    PolicyDecision::default_deny("no active policy returned a decision (default-deny)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(side_effects: SideEffectLevel) -> PolicyInput {
        PolicyInput {
            request: PolicyRequest {
                type_uri: "https://trusttasks.org/spec/vault/release/0.1".into(),
                kind: Some("release".into()),
                subject: None,
                payload_digest: None,
                side_effects,
                exposure: Exposure {
                    discloses: Discloses::Secret,
                    acts_as_subject: false,
                },
            },
            site: None,
            context_id: "ctx1".into(),
            consumer: Consumer {
                did: "did:key:zTest".into(),
                kind: None,
                device_id: None,
                last_user_verification_at: None,
                network_class: None,
                acr: None,
                amr: vec![],
            },
        }
    }

    fn policy(src: &str, id: &str) -> CompiledPolicy {
        compile(src, id).expect("test policy compiles")
    }

    #[test]
    fn empty_policy_set_denies() {
        let d = decide(&[], &input(SideEffectLevel::Mutating));
        assert_eq!(d.decision, Disposition::Deny);
    }

    #[test]
    fn all_abstain_denies() {
        // A policy that only opines on destructive tasks; given a mutating one
        // it abstains, so the set as a whole fails closed.
        let p = policy(
            r#"package vta.policy
               import rego.v1
               decision := {"decision": "deny"} if input.request.sideEffects == "destructive""#,
            "only-destructive",
        );
        let d = decide(&[(0, p)], &input(SideEffectLevel::Mutating));
        assert_eq!(d.decision, Disposition::Deny);
        assert!(d.explanation.unwrap().contains("default-deny"));
    }

    #[test]
    fn higher_priority_override_wins_over_broad_allow() {
        let broad_allow = policy(
            r#"package vta.policy
               import rego.v1
               decision := {"decision": "allow"}"#,
            "broad-allow",
        );
        let secret_stepup = policy(
            r#"package vta.policy
               import rego.v1
               decision := {"decision": "requireStepUp", "stepUp": {"method": "pushApproval"}} if {
                   input.request.exposure.discloses == "secret"
               }"#,
            "secret-stepup",
        );
        // Broad allow at priority 0, the secret override at priority 10.
        let d = decide(
            &[(0, broad_allow), (10, secret_stepup)],
            &input(SideEffectLevel::Mutating),
        );
        assert_eq!(
            d.decision,
            Disposition::RequireStepUp,
            "the higher-priority secret override must win over the broad allow"
        );
    }
}
