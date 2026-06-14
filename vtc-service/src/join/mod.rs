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

pub mod retention;
pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

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
    #[serde(default)]
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
    #[serde(default)]
    pub extensions: JsonValue,
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
}

impl JoinTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            JoinTransport::Rest => "rest",
            JoinTransport::DIDComm => "didcomm",
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
}
