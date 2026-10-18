//! The `directoryWrite` policy (`vtc.directory_write`): may a card hold what
//! a write would leave on it?
//!
//! Asked only after the host's own checks pass, and only about a write that
//! could let someone see or find more (`card/update` item 5): a change that
//! only narrows is never refused. The policy can refuse; it cannot change the
//! card.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use vti_common::error::AppError;

use super::model::Card;
use crate::policy::engine::{CompiledPolicy, evaluate};

const DECISION_QUERY: &str = "data.vtc.directory_write.decision";

/// The write being judged.
pub struct WriteFacts<'a> {
    pub operation: &'static str,
    pub now: DateTime<Utc>,
    pub actor_did: &'a str,
    pub actor_role: Option<&'a str>,
    pub actor_directory_admin: bool,
    pub card: &'a Card,
    pub changed: &'a [String],
    /// Other members' nicknames, for a community that makes them unique.
    pub other_nicknames: Vec<String>,
}

/// A refusal: the field it names, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub field: Option<String>,
    pub message: String,
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
    field: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// `Ok(None)`: accepted. `Ok(Some(refusal))`: the policy refused.
pub fn judge(policy: &CompiledPolicy, facts: &WriteFacts<'_>) -> Result<Option<Refusal>, AppError> {
    let input = json!({
        "operation": facts.operation,
        "now": facts.now,
        "actor": {
            "did": facts.actor_did,
            "role": facts.actor_role,
            "directoryAdmin": facts.actor_directory_admin,
        },
        "subject": { "entryId": facts.card.entry_id },
        "card": {
            "values": facts.card.values,
            "visibility": facts.card.visibility,
            "discoverability": facts.card.discoverability,
            "introductions": facts.card.introductions,
        },
        "changed": facts.changed,
        "others": { "nicknames": facts.other_nicknames },
    });
    let results = match evaluate(policy, DECISION_QUERY, input) {
        Ok(r) => r,
        // A pathological policy fails closed, as every policy here does.
        Err(e @ AppError::ResourceExhausted(_)) => {
            tracing::warn!(error = %e, "directoryWrite policy hit a resource bound; refusing");
            return Ok(Some(Refusal {
                field: None,
                message: "the community's directory policy could not decide".into(),
            }));
        }
        Err(e) => return Err(e),
    };
    let value = results.pointer("/result/0/expressions/0/value");
    let Some(value) = value.filter(|v| !matches!(v, Value::Object(o) if o.is_empty())) else {
        // A policy that answers nothing is refused rather than read as consent.
        return Ok(Some(Refusal {
            field: None,
            message: "the community's directory policy answered nothing".into(),
        }));
    };
    let decision: Decision = serde_json::from_value(value.clone()).map_err(|e| {
        AppError::Internal(format!(
            "the active directoryWrite policy returned a decision this service cannot read: {e}"
        ))
    })?;
    match decision.effect.as_str() {
        "allow" => Ok(None),
        _ => Ok(Some(Refusal {
            field: decision.with.field,
            message: decision
                .with
                .reason
                .or(decision.with.code)
                .unwrap_or_else(|| "refused by the community's directory policy".into()),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::cards::fresh;
    use crate::directory::model::Settings;
    use crate::policy::engine::compile;

    fn facts(card: &Card) -> WriteFacts<'_> {
        WriteFacts {
            operation: "update",
            now: Utc::now(),
            actor_did: "did:example:carol",
            actor_role: Some("member"),
            actor_directory_admin: false,
            card,
            changed: &[],
            other_nicknames: vec!["ana".into()],
        }
    }

    #[test]
    fn the_shipped_default_allows() {
        let p = compile(
            crate::policy::default::default_source(crate::policy::PolicyPurpose::DirectoryWrite),
            uuid::Uuid::nil(),
        )
        .unwrap();
        let c = fresh("did:example:carol", &Settings::default(), None, Utc::now());
        assert_eq!(judge(&p, &facts(&c)).unwrap(), None);
    }

    #[test]
    fn a_policy_can_make_nicknames_unique() {
        let p = compile(
            r#"package vtc.directory_write
import rego.v1
default decision := {"effect": "allow"}
decision := {"effect": "deny", "with": {"code": "taken", "field": "nickname", "reason": "that nickname is taken"}} if {
    lower(input.card.values.nickname) in {lower(n) | some n in input.others.nicknames}
}
"#,
            uuid::Uuid::nil(),
        )
        .unwrap();
        let mut c = fresh("did:example:carol", &Settings::default(), None, Utc::now());
        c.values.insert("nickname".into(), json!("Ana"));
        assert_eq!(
            judge(&p, &facts(&c)).unwrap(),
            Some(Refusal {
                field: Some("nickname".into()),
                message: "that nickname is taken".into()
            })
        );
    }

    #[test]
    fn a_policy_that_answers_nothing_refuses() {
        let p = compile(
            "package vtc.directory_write\nimport rego.v1\n",
            uuid::Uuid::nil(),
        )
        .unwrap();
        let c = fresh("did:example:carol", &Settings::default(), None, Utc::now());
        assert!(judge(&p, &facts(&c)).unwrap().is_some());
    }
}
