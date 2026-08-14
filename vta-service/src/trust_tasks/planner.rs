//! Dry-run the handler a task is about to invoke, and report what it would do.
//!
//! This is the bridge between the PDP's `requireConsent` and the plan/apply
//! split in the operations layer. When a policy says a task needs human
//! approval, *something* has to show the human what they are approving — and the
//! submitted payload is the wrong thing to show them, because a payload says
//! what was asked for while only the code about to run knows what will happen.
//!
//! A handler with no planner yields `None`. That is not "no consequences": it is
//! "the consequences could not be determined", and the consent surface is
//! required to say so rather than present the task as harmless.

use serde_json::Value;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::policy::effects::{Effect, StatePin};
use crate::server::AppState;

/// What a dry-run learned about the task it is about to run.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskPlan {
    /// What executing the task would do, for the approver to read.
    pub effects: Vec<Effect>,
    /// The prior state the effects were computed against — shown to the approver
    /// and asserted at execution.
    pub state_pin: Option<StatePin>,
    /// Executor-internal preconditions, re-asserted at execution.
    ///
    /// Deliberately *not* shown to the approver. They could not verify these in
    /// any case — the approver trusts the executor; that is design parameter
    /// one — and putting them on the wire would only invite a consent surface to
    /// render a number it cannot interpret.
    pub guards: Guards,
    /// The context whose admin authority this task acts under, when the executor
    /// can determine it (webvh update: the DID's context). Lets the consent gate
    /// require an approver who administers it before a delegation can confer
    /// execution authority. `None` for tasks with no context-scoped subject.
    pub subject_context: Option<String>,
    /// Whether the requester's own authority already covered the task. When
    /// `false`, the task is a cross-context proposal, executable only via a
    /// consented delegation from a context-admin approver.
    ///
    /// The serde default is `true` so wire/stored plans missing the field (and
    /// tasks with no delegation-aware planner) are never mistaken for delegated
    /// proposals. Do not read the derived `Default` (`false`) as a delegation
    /// signal — always extract via the `Option<TaskPlan>`-aware path in the gate.
    #[serde(default = "default_true")]
    pub requester_authorized: bool,
}

fn default_true() -> bool {
    true
}

// `Guards` / `WebvhPathCounter` moved to `vti_common::guards` so `vta-policy`'s
// consent model can name them without a cross-crate cycle; re-exported here so
// every `planner::Guards` reference keeps resolving.
// `WebvhPathCounter` is the type of `Guards::webvh_path_counter`, which is not
// itself feature-gated, so it stays part of this crate's public surface in every
// build even though only `webvh` code here names it.
#[cfg_attr(not(feature = "webvh"), allow(unused_imports))]
pub use vti_common::guards::{Guards, WebvhPathCounter};

/// Dry-run `type_uri`'s handler against `payload`.
///
/// `Ok(None)` means this executor has no dry-run for that handler — the caller
/// must treat the consequences as unknown, never as absent.
pub(super) async fn plan_task(
    state: &AppState,
    auth: &AuthClaims,
    type_uri: &str,
    payload: &Value,
) -> Result<Option<TaskPlan>, AppError> {
    #[cfg(feature = "webvh")]
    if type_uri == vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0 {
        return plan_webvh_update(state, auth, payload).await.map(Some);
    }

    let _ = (state, auth, type_uri, payload);
    Ok(None)
}

#[cfg(feature = "webvh")]
async fn plan_webvh_update(
    state: &AppState,
    auth: &AuthClaims,
    payload: &Value,
) -> Result<TaskPlan, AppError> {
    use crate::operations::did_webvh;

    // The handler's own payload type and option conversion — not a second copy.
    // A planner that parsed the payload differently from the handler could plan
    // one update and execute another.
    let req: super::webvh::UpdateDidWithDid = serde_json::from_value(payload.clone())
        .map_err(|e| AppError::Validation(format!("invalid webvh update payload: {e}")))?;
    let options = super::webvh::update_body_to_options(req.body)
        .map_err(|e| AppError::Validation(format!("invalid webvh update options: {e:?}")))?;

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let deps = did_webvh::WebvhDeps::from_app_state(state, did_resolver);

    let plan = did_webvh::plan_did_webvh_update(&deps, auth, &req.did, options)
        .await
        .map_err(dry_run_error)?;

    Ok(TaskPlan {
        effects: plan.to_effects(),
        state_pin: Some(plan.state_pin()),
        guards: Guards {
            webvh_path_counter: Some(WebvhPathCounter {
                base_path: plan.base_path.clone(),
                counter: plan.path_counter_pin,
            }),
        },
        subject_context: Some(plan.subject_context.clone()),
        requester_authorized: plan.requester_authorized,
    })
}

/// Map a dry-run failure onto the same typed [`AppError`] the *execute* path
/// would raise for the same cause, keeping "this happened while planning" in
/// the message.
///
/// Every failure here used to become `AppError::Internal`, which loses exactly
/// the detail that makes one diagnosable — and loses it in the worst place. The
/// planner runs on the consent path and only there, so this is the report an
/// approver-gated update produces: a DID this VTA does not hold, a context the
/// requester cannot act in, and a genuine signing bug all arrived as one opaque
/// `internalError`, while the *ungated* execution of the very same task
/// answered `taskFailed: did not found: …`. Routing through the existing
/// `From<UpdateDidWebvhError>` makes plan and execute agree on the variant, so
/// turning consent on can no longer make an error less legible than leaving it
/// off.
#[cfg(feature = "webvh")]
fn dry_run_error(err: crate::operations::did_webvh::UpdateDidWebvhError) -> AppError {
    // `From<UpdateDidWebvhError>` owns the variant choice (notably: NotFound
    // and Forbidden both collapse to NotFound so a plan cannot be used to probe
    // for DIDs in a context the caller can't see). Re-wrap in the same variant
    // rather than matching on the source error, so that policy stays in one
    // place and a new variant there needs no edit here.
    let framed = |msg: String| format!("webvh update dry-run: {msg}");
    match AppError::from(err) {
        AppError::NotFound(m) => AppError::NotFound(framed(m)),
        AppError::Conflict(m) => AppError::Conflict(framed(m)),
        AppError::Validation(m) => AppError::Validation(framed(m)),
        other => AppError::Internal(framed(other.to_string())),
    }
}

/// Re-run the dry-run at execution and check the world has not moved under the
/// approval.
///
/// A human in the loop makes the window minutes wide, so this is a real race,
/// not a theoretical one: the DID may have been updated, or another allocation
/// in the same context may have advanced the derivation counter so that the run
/// would now install a key nobody approved.
///
/// Returns `Err` describing what moved. A handler with no planner has nothing to
/// re-check and passes.
pub(super) async fn assert_plan_still_holds(
    state: &AppState,
    auth: &AuthClaims,
    type_uri: &str,
    payload: &Value,
    approved_pin: Option<&StatePin>,
    approved_guards: &Guards,
) -> Result<(), String> {
    let current = match plan_task(state, auth, type_uri, payload).await {
        Ok(Some(p)) => p,
        // Nothing to re-check.
        Ok(None) => return Ok(()),
        Err(e) => return Err(format!("could not re-plan the task at execution: {e}")),
    };
    check_unchanged(approved_pin, approved_guards, &current)
}

/// Compare what the approver was shown against what would happen now.
fn check_unchanged(
    approved_pin: Option<&StatePin>,
    approved_guards: &Guards,
    current: &TaskPlan,
) -> Result<(), String> {
    if current.state_pin.as_ref() != approved_pin {
        return Err(format!(
            "the subject's state changed while this task was awaiting approval (approved against \
             version {}, now {}). Re-submit to be shown the current effects.",
            approved_pin.map_or("none", |p| p.version.as_str()),
            current
                .state_pin
                .as_ref()
                .map_or("none", |p| p.version.as_str()),
        ));
    }

    if &current.guards != approved_guards {
        return Err(
            "the executor's key derivation moved while this task was awaiting approval, so it \
             would no longer install the keys the approver was shown. Re-submit to be shown the \
             current effects."
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(v: &str) -> StatePin {
        StatePin {
            resource: "did:webvh:example".into(),
            version: v.into(),
        }
    }

    fn guards(counter: u32) -> Guards {
        Guards {
            webvh_path_counter: Some(WebvhPathCounter {
                base_path: "m/1'/2'".into(),
                counter,
            }),
        }
    }

    fn plan(pin_v: &str, counter: u32) -> TaskPlan {
        TaskPlan {
            effects: vec![],
            state_pin: Some(pin(pin_v)),
            guards: guards(counter),
            subject_context: None,
            requester_authorized: true,
        }
    }

    #[test]
    fn an_unmoved_world_passes() {
        assert!(check_unchanged(Some(&pin("3-Qm")), &guards(7), &plan("3-Qm", 7)).is_ok());
    }

    /// The lost update. A human in the loop makes this window minutes wide, so
    /// the DID really can be updated between approval and execution — and the
    /// effects the approver signed off on were computed against the old state.
    #[test]
    fn a_moved_subject_is_refused() {
        let err = check_unchanged(Some(&pin("3-Qm")), &guards(7), &plan("4-Qm", 7)).unwrap_err();
        assert!(err.contains("3-Qm") && err.contains("4-Qm"), "{err}");
    }

    /// The subtler one: the DID has not moved, but another allocation in the same
    /// context advanced the derivation counter. Execution would now derive
    /// different keys than the ones the approver was shown — the effects would be
    /// a lie, and every signature over them would still verify.
    #[test]
    fn a_moved_derivation_counter_is_refused() {
        let err = check_unchanged(Some(&pin("3-Qm")), &guards(7), &plan("3-Qm", 8)).unwrap_err();
        assert!(err.contains("key derivation moved"), "{err}");
    }

    /// A task with no planner pins nothing and re-checks nothing — but it must
    /// not silently accept a pin it never issued.
    #[test]
    fn a_pin_appearing_from_nowhere_is_refused() {
        let unplanned = TaskPlan::default();
        assert!(check_unchanged(Some(&pin("3-Qm")), &Guards::default(), &unplanned).is_err());
    }

    /// Planning an update for a DID this VTA does not hold is a `NotFound`, the
    /// same answer the execute path gives. It used to be an `internalError`,
    /// which meant turning consent *on* made the report strictly worse than
    /// leaving it off: the ungated task said "did not found", the gated one
    /// said "internal error" and named nothing.
    #[cfg(feature = "webvh")]
    #[test]
    fn a_missing_did_plans_as_not_found() {
        let err = dry_run_error(crate::operations::did_webvh::UpdateDidWebvhError::NotFound(
            "SCID did:webvh:QmNope:example.com:agent not found".into(),
        ));
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
        // The cause survives the reframing — that string is the whole
        // diagnostic value of the error.
        assert!(err.to_string().contains("QmNope"), "{err}");
        assert!(err.to_string().contains("dry-run"), "{err}");
    }

    /// A context the requester cannot act in also plans as `NotFound`: the
    /// `From<UpdateDidWebvhError>` mapping deliberately collapses Forbidden
    /// into NotFound so a dry-run cannot be used to probe for DIDs in contexts
    /// the caller cannot see. Re-wrapping must not undo that.
    #[cfg(feature = "webvh")]
    #[test]
    fn a_forbidden_context_does_not_leak_through_the_plan() {
        let err = dry_run_error(
            crate::operations::did_webvh::UpdateDidWebvhError::Forbidden(
                "not an admin of context `payroll`".into(),
            ),
        );
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
    }

    /// A genuine library/signing failure is still internal — the point of the
    /// change is to stop flattening *everything* into that, not to stop using
    /// it where it is right.
    #[cfg(feature = "webvh")]
    #[test]
    fn a_library_failure_stays_internal() {
        let err = dry_run_error(crate::operations::did_webvh::UpdateDidWebvhError::Library(
            "chain validation: bad proof".into(),
        ));
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
    }
}
