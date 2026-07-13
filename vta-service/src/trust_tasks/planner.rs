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
}

/// Preconditions the executor checks for itself before committing.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Guards {
    /// The BIP-32 derivation-path counter the webvh planner peeked, and the
    /// group it peeked it from.
    ///
    /// A peek reserves nothing. If another allocation in the same context lands
    /// while a human is deciding, the real run derives *different keys* than the
    /// ones the approver was shown — so the counter has to be pinned and
    /// re-checked, or the approval authorizes a rotation to a key that never
    /// existed.
    pub webvh_path_counter: Option<WebvhPathCounter>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebvhPathCounter {
    pub base_path: String,
    pub counter: u32,
}

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
        .map_err(|e| AppError::Internal(format!("webvh update dry-run failed: {e}")))?;

    Ok(TaskPlan {
        effects: plan.to_effects(),
        state_pin: Some(plan.state_pin()),
        guards: Guards {
            webvh_path_counter: Some(WebvhPathCounter {
                base_path: plan.base_path.clone(),
                counter: plan.path_counter_pin,
            }),
        },
    })
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
}
