//! The four-valued Verdict — the single `decision` object every
//! `<purpose>.rego` returns (ceremony-pipeline design §4).
//!
//! Replaces the MVP's boolean `allow`/`deny` (`vtc-mvp.md` §10.1)
//! with one discriminated object that generalizes across every
//! ceremony:
//!
//! | Effect         | Meaning (any ceremony)        | Join         | Leave              |
//! |----------------|-------------------------------|--------------|--------------------|
//! | `allow`        | the transition proceeds       | admit + VMC  | execute departure  |
//! | `deny`         | refused                       | reject       | refuse removal     |
//! | `refer`        | needs a human / quorum        | moderator    | second-admin       |
//! | `request_more` | needs more evidence (threaded)| return a PD  | require a reason   |
//!
//! `allow` is the only effect that carries a purpose-specific payload
//! ([`Allow`]); `deny` / `refer` / `request_more` are identical
//! across ceremonies, which is what lets one pipeline serve them all.
//!
//! ## Wire shape
//!
//! The compiled Rego emits `{"effect": "...", "with": {...}}` (see
//! the examples under `docs/05-design-notes/examples/*.rego`). The
//! adjacent `#[serde(tag = "effect", content = "with")]` tagging
//! mirrors that exactly. The host evaluates the policy, plucks the
//! decision object out of regorus's `QueryResults`
//! (`result[0].expressions[0].value`), and parses it here via
//! [`Verdict::from_decision`].

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use vti_common::error::AppError;

/// One policy decision. Discriminated by `effect`; the `with` payload
/// shape depends on the effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "effect", content = "with", rename_all = "snake_case")]
pub enum Verdict {
    /// The transition proceeds. Carries a purpose-specific payload —
    /// the role to grant (join / role-change), the disposition to
    /// apply (leave), or the fields to project (directory).
    Allow(Allow),
    /// The transition is refused outright.
    Deny(Deny),
    /// The decision is deferred to a human or a quorum — the ceremony
    /// thread stays open and resolves asynchronously.
    Refer(Refer),
    /// The actor must present more evidence — the ceremony thread
    /// continues with a returned Presentation Definition the client
    /// satisfies and re-submits.
    RequestMore(RequestMore),
}

/// `allow` payload. Every field is optional so the one struct serves
/// every ceremony: join populates `role` (+ `obligations`),
/// role-change populates `role`, leave populates `disposition`,
/// directory populates `fields`. The host's effect handler reads only
/// the fields its purpose defines.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Allow {
    /// Role to grant / set (join, role-change). Subject to the
    /// host-enforced privilege ceiling — a `join` policy naming
    /// `admin` here is rejected by the invariant check, not honoured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Departure disposition (leave) — e.g. how the member's
    /// credentials are wound down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    /// Fields to project (directory) — the whitelist the PII-boundary
    /// invariant intersects with what the policy allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    /// Obligations the host must discharge as part of the effect
    /// (e.g. `reciprocate_vmc` to form the bidirectional membership
    /// edge).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<String>,
}

/// `deny` payload — a machine-readable refusal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deny {
    /// Stable refusal code (e.g. `no-matching-route`,
    /// `credential-revoked`). Operator-facing surfaces map this to a
    /// message + a suggested fix.
    pub code: String,
    /// Optional human-readable elaboration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `refer` payload — route the open thread to a human/quorum queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Refer {
    /// The queue the decision is referred to (e.g. `moderator`,
    /// `second-admin`).
    pub queue: String,
    /// Optional context for the reviewer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `request_more` payload — ask the actor for additional evidence and
/// keep the thread open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestMore {
    /// What's missing, in the IR's `condition:value` shorthand (e.g.
    /// `agreed:code-of-conduct`). Legible to both humans and clients.
    #[serde(default)]
    pub needs: Vec<String>,
    /// A DIF Presentation Definition the client satisfies and
    /// re-presents. Free-form JSON in Phase 1 (the PD generator lands
    /// with the Rule-IR compiler).
    #[serde(default)]
    pub presentation_definition: JsonValue,
}

impl Verdict {
    /// Parse a verdict from the decision object a policy returned.
    ///
    /// `decision` is the value plucked out of regorus's
    /// `QueryResults` shape (`result[0].expressions[0].value`) — see
    /// [`crate::policy::engine::evaluate`]. A policy that returns a
    /// malformed decision (wrong `effect`, missing required `with`
    /// field) surfaces as [`AppError::Internal`]: the structural
    /// totality the compiler guarantees means a well-formed policy
    /// always yields a parseable decision, so a parse failure is a
    /// host/policy bug, not caller input.
    pub fn from_decision(decision: JsonValue) -> Result<Self, AppError> {
        serde_json::from_value(decision).map_err(|e| {
            AppError::Internal(format!("policy returned a malformed decision object: {e}"))
        })
    }

    /// The bare effect discriminant, for audit lines + metrics that
    /// don't care about the payload.
    pub fn effect(&self) -> &'static str {
        match self {
            Verdict::Allow(_) => "allow",
            Verdict::Deny(_) => "deny",
            Verdict::Refer(_) => "refer",
            Verdict::RequestMore(_) => "request_more",
        }
    }

    /// The structural-totality default the compiler appends to every
    /// policy: an unmatched evaluation denies. Constructed here so the
    /// host has a canonical fallback if it ever needs to synthesize
    /// one (e.g. a policy that evaluates to `undefined`).
    pub fn default_deny() -> Self {
        Verdict::Deny(Deny {
            code: "no-matching-route".into(),
            reason: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The join `allow` decision the example `join.rego` emits —
    /// `{"effect":"allow","with":{"role":"member","obligations":["reciprocate_vmc"]}}`.
    #[test]
    fn join_allow_round_trips_against_example_rego() {
        let decision = json!({
            "effect": "allow",
            "with": { "role": "member", "obligations": ["reciprocate_vmc"] }
        });
        let verdict = Verdict::from_decision(decision.clone()).unwrap();
        assert_eq!(
            verdict,
            Verdict::Allow(Allow {
                role: Some("member".into()),
                obligations: vec!["reciprocate_vmc".into()],
                ..Default::default()
            })
        );
        assert_eq!(verdict.effect(), "allow");
        assert_eq!(serde_json::to_value(&verdict).unwrap(), decision);
    }

    /// The `request_more` decision carries needs + a PD.
    #[test]
    fn request_more_carries_needs_and_pd() {
        let decision = json!({
            "effect": "request_more",
            "with": {
                "needs": ["agreed:code-of-conduct"],
                "presentation_definition": { "id": "vtc-join-coc" }
            }
        });
        let verdict = Verdict::from_decision(decision.clone()).unwrap();
        match &verdict {
            Verdict::RequestMore(rm) => {
                assert_eq!(rm.needs, vec!["agreed:code-of-conduct".to_string()]);
                assert_eq!(rm.presentation_definition, json!({ "id": "vtc-join-coc" }));
            }
            other => panic!("expected request_more, got {other:?}"),
        }
        assert_eq!(serde_json::to_value(&verdict).unwrap(), decision);
    }

    /// The compiler-appended structural-totality default.
    #[test]
    fn default_deny_decision_shape() {
        let decision = json!({ "effect": "deny", "with": { "code": "no-matching-route" } });
        let verdict = Verdict::from_decision(decision.clone()).unwrap();
        assert_eq!(verdict, Verdict::default_deny());
        assert_eq!(serde_json::to_value(&verdict).unwrap(), decision);
    }

    /// `refer` to the moderator queue (example `join.rego` P4).
    #[test]
    fn refer_to_queue() {
        let decision = json!({ "effect": "refer", "with": { "queue": "moderator" } });
        let verdict = Verdict::from_decision(decision.clone()).unwrap();
        assert_eq!(
            verdict,
            Verdict::Refer(Refer {
                queue: "moderator".into(),
                reason: None,
            })
        );
        assert_eq!(serde_json::to_value(&verdict).unwrap(), decision);
    }

    /// A malformed decision (unknown effect) is a host/policy bug, not
    /// caller input — it surfaces as `Internal`, not `Validation`.
    #[test]
    fn malformed_decision_is_internal_error() {
        let err = Verdict::from_decision(json!({ "effect": "explode", "with": {} }))
            .expect_err("unknown effect must fail");
        assert!(matches!(err, AppError::Internal(_)), "got {err:?}");
    }

    /// A leave `allow` populates `disposition`, not `role`.
    #[test]
    fn leave_allow_uses_disposition() {
        let decision = json!({ "effect": "allow", "with": { "disposition": "revoke-vmc" } });
        let verdict = Verdict::from_decision(decision.clone()).unwrap();
        assert_eq!(
            verdict,
            Verdict::Allow(Allow {
                disposition: Some("revoke-vmc".into()),
                ..Default::default()
            })
        );
        // role / fields / obligations are omitted from the wire form.
        assert_eq!(serde_json::to_value(&verdict).unwrap(), decision);
    }
}
