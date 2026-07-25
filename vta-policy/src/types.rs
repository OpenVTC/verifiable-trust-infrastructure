//! Rust mirror of the Trust Tasks `policy/_shared/0.3` schema.
//!
//! These types are the wire contract between the maintainer's Policy Decision
//! Point and the Rego evaluator. [`PolicyInput`] is what the VTA assembles per
//! request and hands to regorus as `input`; [`PolicyDecision`] is what a policy
//! module's `decision` rule returns. [`PolicyModule`] is the persisted Rego
//! source + metadata.
//!
//! Field casing matches the schema (camelCase on the wire) via serde renames,
//! because the JSON we build is fed verbatim to Rego and referenced by rule
//! authors as `input.request.sideEffects`, `input.consumer.deviceId`, etc.
//!
//! Source of truth: `dtgwg-trust-tasks-tf/specs/policy/_shared/0.3/policy.schema.json`.

use serde::{Deserialize, Serialize};

/// SPEC §7.3 item 13 — integrity effect on recipient state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SideEffectLevel {
    None,
    Mutating,
    Destructive,
}

/// SPEC §7.3 item 14 — sensitivity of data returned to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Discloses {
    None,
    Metadata,
    Secret,
}

/// SPEC §7.3 item 14 — the confidentiality-and-agency dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    pub discloses: Discloses,
    #[serde(rename = "actsAsSubject")]
    pub acts_as_subject: bool,
}

/// The authoritative §7.3 classification of a task. The PDP derives this from
/// the compiled handler it is about to invoke — NEVER from the published
/// registry — so whoever controls the registry cannot lower the consent bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskClass {
    #[serde(rename = "sideEffects")]
    pub side_effects: SideEffectLevel,
    pub exposure: Exposure,
}

impl TaskClass {
    pub const fn new(
        side_effects: SideEffectLevel,
        discloses: Discloses,
        acts_as_subject: bool,
    ) -> Self {
        Self {
            side_effects,
            exposure: Exposure {
                discloses,
                acts_as_subject,
            },
        }
    }

    /// The fail-safe floor a consumer applies to an unclassified or unresolvable
    /// task (SPEC §7.3 items 13–14): no weaker than `mutating`, no less exposed
    /// than a secret-disclosing act-as-subject. An unknown task is treated as
    /// maximally consequential so nothing slips through unprompted.
    pub const fn floor() -> Self {
        Self::new(SideEffectLevel::Mutating, Discloses::Secret, true)
    }
}

/// `PolicyInput.request` — what task is being authorized. Generalised in 0.3
/// from the vault triad to any Trust Task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    #[serde(rename = "typeUri")]
    pub type_uri: String,
    /// Optional coarse category retained from 0.2 (`proxyLogin`|`release`|…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Identifier the task acts on (value at the spec's `subjectPath`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Salted digest binding a delegated-execution consent flow to this payload.
    #[serde(
        rename = "payloadDigest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payload_digest: Option<String>,
    #[serde(rename = "sideEffects")]
    pub side_effects: SideEffectLevel,
    pub exposure: Exposure,
}

/// `PolicyInput.consumer` — who/what is asking. Device-aware so policy can
/// gate on user-verification recency and network class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consumer {
    pub did: String,
    /// ConsumerKind discriminator (Companion|Service); opaque JSON here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<serde_json::Value>,
    #[serde(rename = "deviceId", default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(
        rename = "lastUserVerificationAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_user_verification_at: Option<String>,
    #[serde(
        rename = "networkClass",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub network_class: Option<String>,
    /// The session's OIDC assurance level (`aal1` / `aal2`), so a policy can
    /// gate on step-up state — e.g. `sideEffects == "destructive" and
    /// consumer.acr != "aal2" => requireStepUp`. Extension beyond the 0.3
    /// schema (which carries `lastUserVerificationAt` as a coarser proxy); to
    /// be added to the schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// RFC 8176 authentication method references on the session
    /// (`did`, `passkey`, …). Lets a policy require a specific factor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
}

/// The structured input fed to the evaluator before dispatching a task.
///
/// NOTE: the 0.3 schema still marks `site` as required (inherited from the
/// vault-flow origin of PolicyInput). For a generic task there is no site, so
/// this mirror makes it optional and omits it when absent — regorus does not
/// validate against the JSON schema, and the `policy/evaluate` dry-run is the
/// only schema-validated surface. A follow-up should relax `site` to optional
/// in the schema itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub request: PolicyRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<serde_json::Value>,
    #[serde(rename = "contextId")]
    pub context_id: String,
    pub consumer: Consumer,
}

/// The disposition a policy returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Disposition {
    Allow,
    Deny,
    RequireStepUp,
    RequireConsent,
}

/// `PolicyDecision.stepUp` — which step-up method to demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUp {
    pub method: String,
    #[serde(
        rename = "ttlSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl_seconds: Option<u32>,
}

fn default_min_approvals() -> u32 {
    1
}

/// `PolicyDecision.requireConsent` — the approver constraint to satisfy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequireConsent {
    #[serde(rename = "approverSet")]
    pub approver_set: String,
    #[serde(rename = "excludeRequester", default)]
    pub exclude_requester: bool,
    #[serde(rename = "minApprovals", default = "default_min_approvals")]
    pub min_approvals: u32,
}

/// What a policy module's `decision` rule returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Disposition,
    /// Vault-flow-specific (`proxy`|`fill`); ignored for other task kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUp>,
    #[serde(
        rename = "requireConsent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_consent: Option<RequireConsent>,
    #[serde(
        rename = "ttlSecondsCap",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl_seconds_cap: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

impl PolicyDecision {
    /// The fail-closed decision the PDP synthesises when no policy returns a
    /// value, or evaluation fails, or the input is unclassifiable. Never
    /// permissive.
    pub fn default_deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Disposition::Deny,
            mode: None,
            step_up: None,
            require_consent: None,
            ttl_seconds_cap: None,
            explanation: Some(reason.into()),
        }
    }
}

/// A persisted Rego policy module (mirror of `$defs/PolicyModule`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyModule {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rego source. Entry point is the package's `decision` rule.
    pub module: String,
    /// Trust contexts this policy applies to; empty = all (the default policy).
    #[serde(rename = "appliesTo", default)]
    pub applies_to: Vec<String>,
    /// Higher runs first; first non-null `decision` wins.
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub version: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_effect_level_wire_casing() {
        assert_eq!(
            serde_json::to_value(SideEffectLevel::Destructive).unwrap(),
            serde_json::json!("destructive")
        );
    }

    #[test]
    fn disposition_wire_casing() {
        assert_eq!(
            serde_json::to_value(Disposition::RequireConsent).unwrap(),
            serde_json::json!("requireConsent")
        );
        assert_eq!(
            serde_json::to_value(Disposition::RequireStepUp).unwrap(),
            serde_json::json!("requireStepUp")
        );
    }

    #[test]
    fn policy_input_omits_absent_site_and_optionals() {
        let input = PolicyInput {
            request: PolicyRequest {
                type_uri: "https://trusttasks.org/spec/did-management/did/delete/0.1".into(),
                kind: None,
                subject: Some("did:webvh:abc".into()),
                payload_digest: None,
                side_effects: SideEffectLevel::Destructive,
                exposure: Exposure {
                    discloses: Discloses::None,
                    acts_as_subject: false,
                },
            },
            site: None,
            context_id: "ctx1".into(),
            consumer: Consumer {
                did: "did:key:zTest".into(),
                kind: None,
                device_id: Some("dev-1".into()),
                last_user_verification_at: None,
                network_class: None,
                acr: None,
                amr: vec![],
            },
        };
        let v = serde_json::to_value(&input).unwrap();
        assert!(v.get("site").is_none(), "absent site must be omitted");
        assert_eq!(v["request"]["sideEffects"], "destructive");
        assert_eq!(v["request"]["exposure"]["actsAsSubject"], false);
        assert_eq!(v["consumer"]["deviceId"], "dev-1");
        assert!(v["request"].get("payloadDigest").is_none());
    }

    #[test]
    fn decision_round_trips_from_rego_shape() {
        // The shape a Rego `decision` rule would emit for a consent demand.
        let j = serde_json::json!({
            "decision": "requireConsent",
            "requireConsent": { "approverSet": "operators", "excludeRequester": true }
        });
        let d: PolicyDecision = serde_json::from_value(j).unwrap();
        assert_eq!(d.decision, Disposition::RequireConsent);
        let rc = d.require_consent.unwrap();
        assert!(rc.exclude_requester);
        assert_eq!(rc.min_approvals, 1, "minApprovals defaults to 1");
    }
}
