//! Join requests — spec §5.5 + §10.1.
//!
//! Phase 1 ships a manual-approval flow: applicants submit a
//! holder-bound VP, the request lands in `join_requests:` with
//! status `Pending`, and an admin / moderator approves or
//! rejects via the admin surface (M1.10). The policy-engine
//! step (`join.rego`) is Phase 2.
//!
//! ## What's deferred to Phase 2+
//!
//! - VP scoring against `join.rego`. Phase 1 records the VP as
//!   opaque JSON; Phase 2's policy step reads it back without a
//!   re-submit.
//! - VMC + role VEC issuance via the VTA oracle on approve.
//!   Phase 1's approve writes ACL + Member only.

pub mod orchestrate;
pub mod retention;
pub mod storage;

#[cfg(test)]
mod invitation_e2e_test;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

pub use orchestrate::{
    HolderBinding, JOIN_REQUEST_SUBMIT_DOMAIN_TAG, JoinSubmitOutcome, decide_join,
    emit_admit_audit, realize_join_verdict, submit_inner,
};
pub use retention::{JoinRequestsConfig, RetentionSweeper, default_retention_days};
pub use storage::{
    JOIN_REQUEST_EXTENSIONS_MAX_BYTES, JOIN_REQUEST_VP_MAX_BYTES, delete_join_request,
    get_join_request, list_join_requests, list_join_requests_paginated, store_join_request,
};

/// State of a join request through its lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(utoipa::ToSchema)]
pub enum JoinStatus {
    /// Submitted; awaiting admin / moderator decision.
    Pending,
    /// Admin / moderator approved; ACL + Member rows written.
    Approved,
    /// Admin / moderator rejected. Retained for the configured
    /// retention window then purged.
    Rejected,
    /// Applicant withdrew their request before a decision.
    /// Retained per same window as `Rejected`.
    Withdrawn,
    /// Policy engine signalled "decide later" (e.g. needs an
    /// out-of-band step before admission). Phase 2+.
    Deferred,
}

impl JoinStatus {
    /// Returns `true` for the statuses the 30-day retention
    /// sweeper prunes. `Pending` + `Deferred` rows stay until
    /// they reach a terminal state.
    pub fn is_terminal_retainable(self) -> bool {
        matches!(self, JoinStatus::Rejected | JoinStatus::Withdrawn)
    }
}

impl std::fmt::Display for JoinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinStatus::Pending => f.write_str("pending"),
            JoinStatus::Approved => f.write_str("approved"),
            JoinStatus::Rejected => f.write_str("rejected"),
            JoinStatus::Withdrawn => f.write_str("withdrawn"),
            JoinStatus::Deferred => f.write_str("deferred"),
        }
    }
}

/// One join request. Stored under `join_requests:<id>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct JoinRequest {
    pub id: Uuid,
    pub applicant_did: String,
    /// Opaque VP carried verbatim from the wire. Phase 1 never
    /// inspects it beyond the holder-binding check the route layer
    /// ran at submit time; Phase 2's policy step reads from
    /// [`Self::vp_claims`] (the canonical projection extracted at
    /// submit time), not from this field.
    pub vp: JsonValue,
    /// Canonical projection of [`Self::vp`] computed at submit
    /// time by [`crate::policy::extract::extract_vp_claims`] and
    /// fed to `join.rego` as `input.vp_claims`. Stored on the row
    /// so the approve flow doesn't have to re-extract (plan §D4).
    /// `null` on rows persisted before Phase 2.
    #[serde(default)]
    pub vp_claims: JsonValue,
    pub submitted_at: DateTime<Utc>,
    pub status: JoinStatus,
    /// Set by Phase 2's policy step on approve / reject. Always
    /// `None` in Phase 1.
    ///
    /// Omitted rather than sent as `null`: the canonical `JoinRequest`
    /// component types this `object`, not `["object", "null"]` as it does
    /// the neighbouring `vpClaims` and `decision`. It is not required, so
    /// absent is the conforming way to say "no policy decision" — `null` is
    /// a type error. It went out as `null` until #1099.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<JsonValue>,
    /// Whether the applicant consents to being published in the
    /// community's trust-registry record (spec §8). Default
    /// `false`; the operator-facing surface defers this decision
    /// to Phase 3.
    #[serde(default)]
    pub registry_consent: bool,
    /// Community-defined extensions slot (spec §3-M). Bounded by
    /// `JOIN_REQUEST_EXTENSIONS_MAX_BYTES` (16 KiB) at the route
    /// layer.
    /// Omitted when null. The canonical `JoinRequest` component types this
    /// `object` and does not require it, so absent is how "none" is spelled
    /// and `null` is a type error — the same shape as `policyDecision` in
    /// #1099. Found by the response-conformance layer on real traffic; the
    /// fixture set a non-empty object and so never saw it.
    #[serde(default, skip_serializing_if = "JsonValue::is_null")]
    pub extensions: JsonValue,
    /// Why this request was refused, for the applicant.
    ///
    /// Written by **both** rejection paths — the policy auto-deny at
    /// submit and the admin reject — so the status poll has one field
    /// to read rather than two shapes to reconcile. [`JoinDecision`]
    /// says why that matters.
    ///
    /// `None` for a request that has not been rejected, and for one
    /// rejected before this field existed (see
    /// [`JoinRequest::decision_for_applicant`], which reconstructs what
    /// it can from [`Self::policy_decision`]).
    #[serde(default)]
    pub decision: Option<JoinDecision>,
}

/// The refusal, in the form the applicant is owed it.
///
/// Both rejection paths reach the applicant through the same poll, but
/// the evidence used to sit in two different places and only one of them
/// was projected: an auto-deny left a serialized `Deny` verdict on
/// [`JoinRequest::policy_decision`], and an admin reject wrote the
/// operator's reason to the audit log and nowhere else. So an
/// admin-rejected applicant could never learn why — the correlated
/// ceremony reply is a one-shot delivery, and the poll that exists to
/// recover a missed one returned bare `{requestId, status}`.
///
/// One field written by both paths is the fix, and it is deliberately
/// *not* `policy_decision`: an operator's decision is not a policy
/// verdict, and recording it as one would make the audit trail lie about
/// where the refusal came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct JoinDecision {
    /// Stable refusal code. From the policy's `deny` verdict on the
    /// auto-deny path; [`vta_sdk::protocols::join_requests::ADMIN_REJECT_CODE`]
    /// on the admin path, where there is no verdict to source one from.
    pub code: String,
    /// Optional elaboration — the policy's `reason`, or the operator's
    /// words. Absent when the decider supplied none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the decision was taken — not when the poll answering it was
    /// produced. For an admin reject the two diverge by however long the
    /// applicant takes to poll.
    pub decided_at: DateTime<Utc>,
}

impl JoinRequest {
    /// Construct a fresh `Pending` request.
    pub fn new(applicant_did: impl Into<String>, vp: JsonValue) -> Self {
        Self {
            id: Uuid::new_v4(),
            applicant_did: applicant_did.into(),
            vp,
            vp_claims: JsonValue::Null,
            submitted_at: Utc::now(),
            status: JoinStatus::Pending,
            policy_decision: None,
            registry_consent: false,
            extensions: JsonValue::Null,
            decision: None,
        }
    }

    /// The refusal to show the applicant, or `None` if there isn't one.
    ///
    /// Reads [`Self::decision`] when it is set. When it is not, a request
    /// rejected before that field existed can still be answered from the
    /// serialized `Deny` verdict on [`Self::policy_decision`] — every
    /// auto-deny wrote one. The only thing lost to the fallback is the
    /// decision timestamp, which was never recorded then; `decided_at`
    /// stays `None` rather than being back-filled with a time that would
    /// be a guess.
    ///
    /// An **admin** reject predating the field has nothing to recover:
    /// its reason only ever reached the audit log. Those rows return
    /// `None` and the poll answers exactly as it did before.
    pub fn decision_for_applicant(
        &self,
    ) -> Option<(String, Option<String>, Option<DateTime<Utc>>)> {
        if self.status != JoinStatus::Rejected {
            return None;
        }
        if let Some(d) = &self.decision {
            return Some((d.code.clone(), d.reason.clone(), Some(d.decided_at)));
        }
        let verdict = self.policy_decision.clone()?;
        match serde_json::from_value::<crate::ceremony::Verdict>(verdict).ok()? {
            crate::ceremony::Verdict::Deny(d) => Some((d.code, d.reason, None)),
            _ => None,
        }
    }
}

/// Transport the request arrived over. Used by the audit event
/// (`JoinRequestData.transport`) so investigators can tell REST +
/// DIDComm submissions apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinTransport {
    Rest,
    DIDComm,
    /// Trust Spanning Protocol, received off the same mediator socket DIDComm
    /// uses (the transport tags which). Receive-side only: a TSP-delivered
    /// request is answered over TSP, but the VTC's *outbound-initiated* sends to
    /// members stay DIDComm until the Phase B flip
    /// (`docs/05-design-notes/tsp-enablement.md` §12, §14 Q4).
    Tsp,
}

impl JoinTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            JoinTransport::Rest => "rest",
            JoinTransport::DIDComm => "didcomm",
            JoinTransport::Tsp => "tsp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_status_terminal_retainable_only_for_rejected_and_withdrawn() {
        for (status, expected) in [
            (JoinStatus::Pending, false),
            (JoinStatus::Approved, false),
            (JoinStatus::Rejected, true),
            (JoinStatus::Withdrawn, true),
            (JoinStatus::Deferred, false),
        ] {
            assert_eq!(status.is_terminal_retainable(), expected, "{status:?}");
        }
    }

    #[test]
    fn join_status_display_is_lowercase() {
        assert_eq!(JoinStatus::Pending.to_string(), "pending");
        assert_eq!(JoinStatus::Approved.to_string(), "approved");
        assert_eq!(JoinStatus::Deferred.to_string(), "deferred");
    }

    #[test]
    fn join_request_new_uses_pending_status() {
        let r = JoinRequest::new("did:key:z", serde_json::json!({}));
        assert_eq!(r.status, JoinStatus::Pending);
        assert_eq!(r.policy_decision, None);
        assert!(!r.registry_consent);
    }

    #[test]
    fn join_transport_str_round_trip() {
        assert_eq!(JoinTransport::Rest.as_str(), "rest");
        assert_eq!(JoinTransport::DIDComm.as_str(), "didcomm");
    }

    // -- decision_for_applicant (#1052) ------------------------------------

    fn rejected(decision: Option<JoinDecision>, policy: Option<JsonValue>) -> JoinRequest {
        let mut r = JoinRequest::new("did:key:zApplicant", serde_json::json!({}));
        r.status = JoinStatus::Rejected;
        r.decision = decision;
        r.policy_decision = policy;
        r
    }

    #[test]
    fn a_stored_decision_is_returned_verbatim() {
        let at = Utc::now();
        let r = rejected(
            Some(JoinDecision {
                code: "membership-required".into(),
                reason: Some("members of the parent community only".into()),
                decided_at: at,
            }),
            None,
        );
        assert_eq!(
            r.decision_for_applicant(),
            Some((
                "membership-required".to_string(),
                Some("members of the parent community only".to_string()),
                Some(at),
            ))
        );
    }

    /// Rows rejected before `decision` existed are not lost: an auto-deny
    /// always wrote the serialized `Deny` verdict, so the code and reason are
    /// still recoverable. Only the timestamp is not — it was never recorded,
    /// and reporting `None` is honest where back-filling `Utc::now()` would
    /// tell the applicant they were rejected the instant they polled.
    #[test]
    fn a_legacy_auto_deny_row_falls_back_to_the_policy_verdict() {
        let r = rejected(
            None,
            Some(serde_json::json!({
                "effect": "deny",
                "with": { "code": "closed", "reason": "not accepting applications" }
            })),
        );
        assert_eq!(
            r.decision_for_applicant(),
            Some((
                "closed".to_string(),
                Some("not accepting applications".to_string()),
                None,
            )),
            "the code and reason survive; the never-recorded timestamp does not"
        );
    }

    /// A legacy **admin** reject has nothing to fall back to — its reason only
    /// ever reached the audit log, which the applicant cannot read. The poll
    /// answers exactly as it did before rather than inventing a code.
    #[test]
    fn a_legacy_admin_reject_row_yields_nothing() {
        assert_eq!(rejected(None, None).decision_for_applicant(), None);
    }

    /// A `request_more` verdict on `policy_decision` is not a refusal, and a
    /// `Deferred` row is not a rejected one. Neither may leak into the
    /// refusal fields.
    #[test]
    fn only_a_rejected_request_has_a_refusal() {
        let mut deferred = rejected(
            None,
            Some(serde_json::json!({
                "effect": "request_more",
                "with": { "needs": ["agreed:code-of-conduct"] }
            })),
        );
        // Still Rejected, but the stored verdict is not a deny.
        assert_eq!(deferred.decision_for_applicant(), None);

        // And a Deferred row never reports a refusal, whatever it carries.
        deferred.status = JoinStatus::Deferred;
        deferred.decision = Some(JoinDecision {
            code: "should-not-surface".into(),
            reason: None,
            decided_at: Utc::now(),
        });
        assert_eq!(deferred.decision_for_applicant(), None);
    }
}
