//! `consent/*` Trust Task client methods.
//!
//! Drive the VTA consent gate from a messaging bridge (or operator tooling)
//! through the generic dispatcher ([`VtaClient::dispatch_trust_task`]) — there
//! is no dedicated REST route. See `vta-service`'s consent store and the
//! `consent/*` family in the dtgwg registry.
//!
//! `subject` is the platform-agnostic `{platform, conversationRef, kind, agent}`
//! object; `conversationRef` is the bridge's OPAQUE handle — never a raw
//! platform address.

use serde_json::Value;

use super::VtaClient;
use crate::error::VtaError;
use crate::protocols::consent_management::{
    ConsentApproverListBody, ConsentApproverSetBody, ConsentDecisionBody, ConsentListBody,
    ConsentRequestBody, ConsentRevokeBody,
};
use crate::trust_tasks;

/// Round-trip timeout (seconds) for consent trust tasks.
const CONSENT_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    /// `consent/request/1.0` — ask the VTA to gate an inbound conversation for an
    /// agent. Default-deny: if no live grant exists, a pending consent is minted
    /// for an approver. `scope` is `"receive"` or `"converse"`. `challenge` (≥128
    /// bits) is echoed by the matching decision.
    pub async fn consent_request(
        &self,
        subject: Value,
        scope: &str,
        challenge: &str,
        display_hint: Option<&str>,
        context_hint: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(ConsentRequestBody {
            subject,
            scope: scope.to_string(),
            challenge: challenge.to_string(),
            display_hint: display_hint.map(str::to_string),
            context_hint: context_hint.map(str::to_string),
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_REQUEST_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }

    /// `consent/decision/1.0` — allow or deny a conversation; records a grant.
    /// `effect` is `"allow"` or `"deny"`; `scope` (`"receive"`/`"converse"`) is
    /// required for allow. Echo `challenge` to answer a specific request;
    /// `expires_at` is an optional RFC-3339 grant TTL.
    pub async fn consent_decision(
        &self,
        subject: Value,
        effect: &str,
        scope: Option<&str>,
        challenge: Option<&str>,
        expires_at: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(ConsentDecisionBody {
            subject,
            effect: effect.to_string(),
            scope: scope.map(str::to_string),
            challenge: challenge.map(str::to_string),
            expires_at: expires_at.map(str::to_string),
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_DECISION_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }

    /// `consent/revoke/1.0` — withdraw a standing grant (revert to default-deny).
    pub async fn consent_revoke(
        &self,
        subject: Value,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(ConsentRevokeBody {
            subject,
            reason: reason.map(str::to_string),
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_REVOKE_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }

    /// `consent/list/1.0` — sync / point-check the grants a bridge enforces. All
    /// filters are optional; pass a full `subject` for a point-check.
    pub async fn consent_list(
        &self,
        agent: Option<&str>,
        platform: Option<&str>,
        subject: Option<Value>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(ConsentListBody {
            agent: agent.map(str::to_string),
            platform: platform.map(str::to_string),
            subject,
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_LIST_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }

    /// `consent/approver-set/1.0` — bind the operator who approves consent for
    /// `platform` within `context`, and how the prompt routes (`route` is
    /// `"wake"` or `"bridge-relay"`). Admin-gated.
    pub async fn consent_approver_set(
        &self,
        platform: &str,
        context: &str,
        approver: &str,
        route: Option<&str>,
        route_hint: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(ConsentApproverSetBody {
            platform: platform.to_string(),
            context: context.to_string(),
            approver: approver.to_string(),
            route: route.map(str::to_string),
            route_hint: route_hint.map(str::to_string),
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_APPROVER_SET_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }

    /// `consent/approver-list/1.0` — read the approver bindings, optionally
    /// filtered by `platform` / `context`.
    pub async fn consent_approver_list(
        &self,
        platform: Option<&str>,
        context: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(ConsentApproverListBody {
            platform: platform.map(str::to_string),
            context: context.map(str::to_string),
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_APPROVER_LIST_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }
}
