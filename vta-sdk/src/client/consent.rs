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

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
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
        let mut payload = json!({
            "subject": subject,
            "scope": scope,
            "challenge": challenge,
        });
        if let Some(h) = display_hint {
            payload["displayHint"] = json!(h);
        }
        if let Some(c) = context_hint {
            payload["contextHint"] = json!(c);
        }
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
        let mut payload = json!({
            "subject": subject,
            "effect": effect,
        });
        if let Some(s) = scope {
            payload["scope"] = json!(s);
        }
        if let Some(c) = challenge {
            payload["challenge"] = json!(c);
        }
        if let Some(e) = expires_at {
            payload["expiresAt"] = json!(e);
        }
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
        let mut payload = json!({ "subject": subject });
        if let Some(r) = reason {
            payload["reason"] = json!(r);
        }
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
        let mut payload = json!({});
        if let Some(a) = agent {
            payload["agent"] = json!(a);
        }
        if let Some(p) = platform {
            payload["platform"] = json!(p);
        }
        if let Some(s) = subject {
            payload["subject"] = s;
        }
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
        let mut payload = json!({
            "platform": platform,
            "context": context,
            "approver": approver,
        });
        if let Some(r) = route {
            payload["route"] = json!(r);
        }
        if let Some(h) = route_hint {
            payload["routeHint"] = json!(h);
        }
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
        let mut payload = json!({});
        if let Some(p) = platform {
            payload["platform"] = json!(p);
        }
        if let Some(c) = context {
            payload["context"] = json!(c);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_CONSENT_APPROVER_LIST_1_0,
            payload,
            CONSENT_TT_TIMEOUT,
        )
        .await
    }
}
