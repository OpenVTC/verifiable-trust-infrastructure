//! The `events` policy (`vtc.events`, VTI-EVT-080): may this event be created, changed or
//! published?
//!
//! Asked only after the community's own checks pass — the caller runs the calendar or hosts
//! the event, the settings are well formed — and able only to refuse. Nothing it returns makes
//! anyone a host or a registrant.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::{Calendar, EventRecord};
use crate::policy::engine::{CompiledPolicy, evaluate};
use crate::policy::model::PolicyPurpose;
use crate::server::AppState;

const DECISION_QUERY: &str = "data.vtc.events.decision";

/// What is being decided, and by whom.
pub struct Facts<'a> {
    /// `create` | `update` | `publish`.
    pub operation: &'static str,
    pub now: DateTime<Utc>,
    pub actor_did: &'a str,
    pub actor_role: Option<&'a str>,
    pub actor_runs_all: bool,
    pub calendar: &'a Calendar,
    pub event: &'a EventRecord,
    /// Empty on `create`: the event has no identifier the policy should read yet.
    pub event_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct Decision {
    effect: String,
    #[serde(default)]
    with: DecisionWith,
}

#[derive(Debug, Default, Deserialize)]
struct DecisionWith {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn input(f: &Facts<'_>) -> Value {
    let (start, end) = f
        .event
        .interval()
        .map(|(s, e)| (json!(s), json!(e)))
        .unwrap_or((Value::Null, Value::Null));
    let settings = f.event.settings();
    json!({
        "operation": f.operation,
        "now": f.now,
        "actor": {
            "did": f.actor_did,
            "role": f.actor_role,
            "runsAll": f.actor_runs_all,
        },
        "calendar": {
            "calendarId": f.calendar.calendar_id,
            "groupId": f.calendar.group_id,
            "community": f.calendar.community,
        },
        "event": {
            "eventId": f.event_id,
            "kind": f.event.kind,
            "status": f.event.status.as_str(),
            "listed": f.event.listed,
            "roster": f.event.roster.as_str(),
            "audienceScope": f.event.audience.get("scope"),
            "mode": match settings.mode {
                super::Mode::Open => "open",
                super::Mode::Approval => "approval",
                super::Mode::Closed => "closed",
            },
            "capacity": settings.capacity,
            "start": start,
            "end": end,
        },
    })
}

/// `Ok(None)`: allowed. `Ok(Some(message))`: the policy refused, saying why.
///
/// # Errors
/// A decision this service cannot read.
pub fn judge(policy: &CompiledPolicy, facts: &Facts<'_>) -> Result<Option<String>, AppError> {
    let results = match evaluate(policy, DECISION_QUERY, input(facts)) {
        Ok(r) => r,
        // A pathological policy fails closed, as every policy here does.
        Err(e @ AppError::ResourceExhausted(_)) => {
            tracing::warn!(error = %e, "events policy hit a resource bound; refusing");
            return Ok(Some(
                "the community's events policy could not decide".into(),
            ));
        }
        Err(e) => return Err(e),
    };
    let value = results.pointer("/result/0/expressions/0/value");
    let Some(value) = value.filter(|v| !matches!(v, Value::Object(o) if o.is_empty())) else {
        // A policy that answers nothing is refused rather than read as consent.
        return Ok(Some(
            "the community's events policy answered nothing".into(),
        ));
    };
    let decision: Decision = serde_json::from_value(value.clone()).map_err(|e| {
        AppError::Internal(format!(
            "the active events policy returned a decision this service cannot read: {e}"
        ))
    })?;
    match decision.effect.as_str() {
        "allow" => Ok(None),
        _ => Ok(Some(
            decision
                .with
                .reason
                .or(decision.with.code)
                .unwrap_or_else(|| "refused by the community's events policy".into()),
        )),
    }
}

/// [`judge`] under the community's active `events` policy. A community with no active policy
/// refuses: the shipped default is installed at boot, so its absence is a gap, not consent.
///
/// # Errors
/// A store failure or a decision this service cannot read.
pub async fn decide(state: &AppState, facts: &Facts<'_>) -> Result<Option<String>, AppError> {
    let policy = crate::policy::load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Events,
    )
    .await?;
    judge(&policy, facts)
}
