//! Assemble a [`PolicyInput`] for a task about to be dispatched.
//!
//! The caller supplies the authoritative [`TaskClass`] it looked up from the
//! compiled dispatch table (`class_for`); this module never reads the registry.
//! An unclassified task (`class == None`) gets [`TaskClass::floor`] — the
//! fail-safe maximum — so an unknown task is treated as maximally consequential
//! rather than waved through.
//!
//! Subject and context are best-effort extractions from the payload's common
//! fields. A future refinement carries an explicit `subjectPath` per task (as
//! the registry does) rather than probing well-known field names.

use serde_json::Value;

use super::types::{Consumer, PolicyInput, PolicyRequest, TaskClass};

/// Payload fields that commonly identify the subject a task acts on, in
/// precedence order. Best-effort until an explicit per-task subjectPath exists.
const SUBJECT_FIELDS: &[&str] = &["did", "mnemonic", "subject", "target", "credentialId", "id"];

/// Payload fields that carry the trust-context id.
const CONTEXT_FIELDS: &[&str] = &["contextId", "context_id"];

/// The identifier the task acts on, by the same precedence `PolicyInput` uses —
/// so the subject a policy authorized is the subject an approver is shown.
pub fn subject_of(payload: &Value) -> Option<String> {
    first_string(payload, SUBJECT_FIELDS).map(str::to_string)
}

fn first_string<'a>(payload: &'a Value, fields: &[&str]) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|f| payload.get(*f).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
}

/// Build the [`PolicyInput`] the evaluator consumes.
///
/// - `class` is the authoritative classification from `class_for`; `None`
///   applies the fail-safe [`TaskClass::floor`].
/// - `caller_did` is the authenticated consumer's DID (from the auth claims).
/// - `caller_acr` / `caller_amr` are the session's assurance level + method
///   references (from the auth claims), so a policy can gate on step-up state.
///   An empty `caller_acr` is treated as "unset" (omitted).
/// - `payload` is the inbound task payload, probed for subject + context.
pub fn build_policy_input(
    type_uri: &str,
    payload: &Value,
    caller_did: &str,
    caller_acr: &str,
    caller_amr: &[String],
    class: Option<TaskClass>,
) -> PolicyInput {
    let class = class.unwrap_or_else(TaskClass::floor);
    // PolicyInput.contextId is required (minLength 1); fall back to "default"
    // so an untagged task still evaluates against the all-contexts policy.
    let context_id = first_string(payload, CONTEXT_FIELDS)
        .unwrap_or("default")
        .to_string();

    PolicyInput {
        request: PolicyRequest {
            type_uri: type_uri.to_string(),
            kind: None,
            subject: first_string(payload, SUBJECT_FIELDS).map(str::to_string),
            payload_digest: None,
            side_effects: class.side_effects,
            exposure: class.exposure,
        },
        site: None,
        context_id,
        consumer: Consumer {
            did: caller_did.to_string(),
            kind: None,
            device_id: None,
            last_user_verification_at: None,
            network_class: None,
            acr: (!caller_acr.is_empty()).then(|| caller_acr.to_string()),
            amr: caller_amr.to_vec(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::{Discloses, SideEffectLevel};
    use serde_json::json;

    #[test]
    fn uses_supplied_class_and_extracts_subject_and_context() {
        let payload = json!({ "did": "did:webvh:abc", "contextId": "ctxA", "foo": 1 });
        let class = Some(TaskClass::new(
            SideEffectLevel::Destructive,
            Discloses::None,
            false,
        ));
        let input = build_policy_input(
            "https://…/delete/0.1",
            &payload,
            "did:key:zCaller",
            "",
            &[],
            class,
        );

        assert_eq!(input.request.side_effects, SideEffectLevel::Destructive);
        assert_eq!(input.request.subject.as_deref(), Some("did:webvh:abc"));
        assert_eq!(input.context_id, "ctxA");
        assert_eq!(input.consumer.did, "did:key:zCaller");
    }

    #[test]
    fn unclassified_task_gets_the_fail_safe_floor() {
        let input = build_policy_input(
            "https://…/unknown/0.1",
            &json!({}),
            "did:key:z",
            "",
            &[],
            None,
        );
        // floor = mutating / secret / actsAsSubject — maximally consequential.
        assert_eq!(input.request.side_effects, SideEffectLevel::Mutating);
        assert_eq!(input.request.exposure.discloses, Discloses::Secret);
        assert!(input.request.exposure.acts_as_subject);
        assert_eq!(
            input.context_id, "default",
            "missing context falls back to default"
        );
        assert!(input.request.subject.is_none());
    }

    #[test]
    fn subject_precedence_prefers_did_over_mnemonic() {
        let payload = json!({ "mnemonic": "alice", "did": "did:webvh:xyz" });
        let input = build_policy_input("t", &payload, "c", "", &[], Some(TaskClass::floor()));
        assert_eq!(input.request.subject.as_deref(), Some("did:webvh:xyz"));
    }
}
