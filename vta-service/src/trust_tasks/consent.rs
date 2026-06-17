//! `consent/*` slice trust-task handlers — the VTA consent store.
//!
//! The VTA is the first gate for inbound bridged messaging: a bridge asks
//! whether a conversation may reach an AI agent (`consent/request`,
//! **default-deny**); an approver decides (`consent/decision`); the grant is
//! recorded and the bridge syncs it (`consent/list`) or it is withdrawn
//! (`consent/revoke`). See the `consent/*` family in the dtgwg registry and
//! `vti_common::consent`.
//!
//! Auth: the approver is the operator **bound for the (platform, context)** in
//! the approver registry (`consent/approver-set`), or the **enrolled bridge**
//! relaying the operator's out-of-band choice (bridge-attested). With no binding
//! configured, `consent/request` is default-denied (`noApprover`) and a context
//! admin is the fallback decider.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use vti_common::auth::session::now_epoch;
use vti_common::consent::{
    ApproverBinding, ConsentEffect, ConsentGrant, ConsentKind, ConsentRoute, ConsentScope,
    ConsentSubject, ConsumeConsent, consume_pending_consent, delete_consent_grant, get_approver,
    get_consent_grant, list_approvers, list_consent_grants, new_pending_consent, store_approver,
    store_consent_grant, store_pending_consent,
};
use vti_common::error::AppError;

use super::helpers::{TrustTaskOutcome, app_error_to_reject, parse_payload, success_response};
use crate::auth::AuthClaims;
use crate::server::AppState;

/// How long a pending consent stays answerable.
const PENDING_TTL_SECS: u64 = 600;

// ── Wire shapes (camelCase) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireSubject {
    platform: String,
    conversation_ref: String,
    kind: ConsentKind,
    agent: String,
}

impl From<WireSubject> for ConsentSubject {
    fn from(w: WireSubject) -> Self {
        ConsentSubject {
            platform: w.platform,
            conversation_ref: w.conversation_ref,
            kind: w.kind,
            agent: w.agent,
        }
    }
}

impl From<&ConsentSubject> for WireSubject {
    fn from(s: &ConsentSubject) -> Self {
        WireSubject {
            platform: s.platform.clone(),
            conversation_ref: s.conversation_ref.clone(),
            kind: s.kind,
            agent: s.agent.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestPayload {
    subject: WireSubject,
    scope: ConsentScope,
    challenge: String,
    #[serde(default)]
    context_hint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecisionPayload {
    subject: WireSubject,
    effect: ConsentEffect,
    #[serde(default)]
    scope: Option<ConsentScope>,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokePayload {
    subject: WireSubject,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListPayload {
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    subject: Option<WireSubject>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AckResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireGrant {
    subject: WireSubject,
    effect: ConsentEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<ConsentScope>,
    granted_by: String,
    granted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    evidence: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListResponse {
    grants: Vec<WireGrant>,
}

// Approver registry (Track A) wire shapes.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproverSetPayload {
    platform: String,
    context: String,
    approver: String,
    #[serde(default)]
    route: Option<ConsentRoute>,
    #[serde(default)]
    route_hint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproverListPayload {
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireApprover {
    platform: String,
    context: String,
    approver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<ConsentRoute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_hint: Option<String>,
}

impl From<ApproverBinding> for WireApprover {
    fn from(b: ApproverBinding) -> Self {
        WireApprover {
            platform: b.platform,
            context: b.context,
            approver: b.approver,
            route: b.route,
            route_hint: b.route_hint,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproverSetResponse {
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproverListResponse {
    approvers: Vec<WireApprover>,
}

fn epoch_to_rfc3339(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339()
}

fn rfc3339_to_epoch(s: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp().max(0) as u64)
}

impl From<ConsentGrant> for WireGrant {
    fn from(g: ConsentGrant) -> Self {
        WireGrant {
            subject: WireSubject::from(&g.subject),
            effect: g.effect,
            scope: g.scope,
            granted_by: g.granted_by,
            granted_at: epoch_to_rfc3339(g.granted_at),
            expires_at: g.expires_at.map(epoch_to_rfc3339),
            evidence: g.evidence,
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `consent/request/1.0` — a bridge asks the VTA to gate a conversation.
/// Default-deny: if no live grant exists, a pending consent is minted for an
/// approver to decide. Auth: an authenticated, write-capable bridge.
pub(super) async fn handle_request(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let payload: RequestPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let subject: ConsentSubject = payload.subject.into();
    let now = now_epoch();

    // Already decided (allow or deny, not expired) → don't re-prompt.
    match get_consent_grant(&state.consent_ks, &subject).await {
        Ok(Some(g)) if !g.is_expired(now) => {
            return success_response(
                &doc,
                AckResponse {
                    status: "accepted",
                    request_id: Some("existing-grant".to_string()),
                    grant_id: None,
                },
            );
        }
        Ok(_) => {}
        Err(e) => return app_error_to_reject(&doc, e),
    }

    let context = payload
        .context_hint
        .or_else(|| auth.default_context().map(str::to_string));

    // Resolve the approver for (platform, context). Default-deny: with no
    // approver bound, there is no one to route consent to → noApprover. Operators
    // bind one via consent/approver-set.
    let Some(ctx) = context.clone() else {
        return app_error_to_reject(
            &doc,
            AppError::Forbidden("consent/request: no context to resolve an approver".into()),
        );
    };
    let binding = match get_approver(&state.consent_approvers_ks, &subject.platform, &ctx).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                AppError::Forbidden(
                    "consent/request: no approver configured for this platform/context".into(),
                ),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Snapshot the prompt subject (camelCase) before `subject` is moved.
    let wire_subject = serde_json::to_value(WireSubject::from(&subject)).unwrap_or_default();

    let pending = new_pending_consent(
        subject,
        payload.scope,
        payload.challenge.clone(),
        auth.did.clone(),
        context,
        PENDING_TTL_SECS,
    );
    if let Err(e) = store_pending_consent(&state.consent_ks, &pending).await {
        return app_error_to_reject(&doc, e);
    }

    // Track B: a `wake`-routed approver is roused on their device with the prompt
    // to sign a did-signed `consent/decision`. Best-effort — the mediator queue
    // and the bridge-relay card remain fallbacks.
    if binding.route == Some(ConsentRoute::Wake) {
        maybe_wake_consent_approver(
            state,
            &binding.approver,
            wire_subject,
            payload.scope,
            &payload.challenge,
        )
        .await;
    }

    success_response(
        &doc,
        AckResponse {
            status: "accepted",
            request_id: Some(payload.challenge),
            grant_id: None,
        },
    )
}

/// DIDComm message type carrying a consent prompt to a `wake`-routed approver's
/// device, which renders it and replies with a signed `consent/decision`.
#[cfg(feature = "didcomm")]
const CONSENT_APPROVE_REQUEST_TYPE: &str =
    "https://trusttasks.org/spec/consent/approve-request/0.1";

/// Rouse a `wake`-routed approver: buffer the consent prompt to their mediator
/// and ring the push-gateway doorbell. Best-effort; mirrors the step-up wake
/// path (`maybe_push_step_up` + `trigger_gateway_wake`).
#[cfg(feature = "didcomm")]
async fn maybe_wake_consent_approver(
    state: &AppState,
    approver: &str,
    subject: Value,
    scope: ConsentScope,
    challenge: &str,
) {
    let mediator_did = {
        let cfg = state.config.read().await;
        super::step_up::approver_mediator(
            approver,
            cfg.messaging.as_ref().map(|m| m.mediator_did.as_str()),
        )
    };
    let Some(mediator_did) = mediator_did else {
        tracing::debug!(
            approver = %approver,
            "no mediator route for wake approver; mediator pickup / relay fallback applies"
        );
        return;
    };
    let approve_request = serde_json::json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": CONSENT_APPROVE_REQUEST_TYPE,
        "payload": { "subject": subject, "scope": scope, "challenge": challenge },
    });
    let pending = crate::messaging::registry::PendingResponse {
        recipient_did: approver.to_string(),
        message_type: CONSENT_APPROVE_REQUEST_TYPE.to_string(),
        body: approve_request.clone(),
        thread_id: approve_request
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };
    if let Err(e) = state
        .mediator_registry
        .buffer_outbound(&mediator_did, pending)
        .await
    {
        tracing::warn!(
            error = %e, approver = %approver, mediator = %mediator_did,
            "failed to buffer consent approve-request; mediator pickup applies"
        );
    }
    super::step_up::trigger_gateway_wake(state, approver, &mediator_did).await;
}

#[cfg(not(feature = "didcomm"))]
async fn maybe_wake_consent_approver(
    _state: &AppState,
    _approver: &str,
    _subject: Value,
    _scope: ConsentScope,
    _challenge: &str,
) {
}

/// `consent/decision/1.0` — an approver allows/denies; records a grant.
/// Auth: the enrolled bridge that requested (bridge-attested), or a context
/// admin (operator, did-signed).
pub(super) async fn handle_decision(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: DecisionPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let subject: ConsentSubject = payload.subject.into();
    let now = now_epoch();

    // Resolve + consume the pending request this decision answers (when echoed).
    let (evidence, scope_default, context) = if let Some(challenge) = &payload.challenge {
        match consume_pending_consent(&state.consent_ks, challenge, now).await {
            Ok(ConsumeConsent::Found(p)) => {
                if p.subject != subject {
                    return app_error_to_reject(
                        &doc,
                        AppError::Validation(
                            "consent/decision: challenge does not match subject".into(),
                        ),
                    );
                }
                let is_bridge = auth.did == p.requested_by;
                if !is_bridge {
                    // The issuer must be the approver bound for this
                    // (platform, context); fall back to a context admin only
                    // when no approver is configured.
                    let ctx = p.context.clone().unwrap_or_default();
                    match get_approver(&state.consent_approvers_ks, &subject.platform, &ctx).await {
                        Ok(Some(b)) if b.approver == auth.did => {}
                        Ok(Some(_)) => {
                            return app_error_to_reject(
                                &doc,
                                AppError::Forbidden(
                                    "consent/decision: issuer is not the bound approver".into(),
                                ),
                            );
                        }
                        Ok(None) => {
                            if let Err(e) = auth.require_admin() {
                                return app_error_to_reject(&doc, e);
                            }
                            if !ctx.is_empty()
                                && let Err(e) = auth.require_context(&ctx)
                            {
                                return app_error_to_reject(&doc, e);
                            }
                        }
                        Err(e) => return app_error_to_reject(&doc, e),
                    }
                }
                let evidence = if is_bridge {
                    "bridge-attested"
                } else {
                    "did-signed"
                };
                (evidence, Some(p.scope), p.context.clone())
            }
            Ok(_) => {
                return app_error_to_reject(
                    &doc,
                    AppError::Validation(
                        "consent/decision: no pending request matches the challenge".into(),
                    ),
                );
            }
            Err(e) => return app_error_to_reject(&doc, e),
        }
    } else {
        // Operator pre-authorization (no challenge): admins only.
        if let Err(e) = auth.require_admin() {
            return app_error_to_reject(&doc, e);
        }
        ("did-signed", None, None)
    };
    let _ = context;

    let scope = match payload.effect {
        ConsentEffect::Allow => Some(
            payload
                .scope
                .or(scope_default)
                .unwrap_or(ConsentScope::Converse),
        ),
        ConsentEffect::Deny => None,
    };
    let grant = ConsentGrant {
        subject,
        effect: payload.effect,
        scope,
        granted_by: auth.did.clone(),
        granted_at: now,
        expires_at: payload.expires_at.as_deref().and_then(rfc3339_to_epoch),
        evidence: evidence.to_string(),
    };
    if let Err(e) = store_consent_grant(&state.consent_ks, &grant).await {
        return app_error_to_reject(&doc, e);
    }
    success_response(
        &doc,
        AckResponse {
            status: "recorded",
            request_id: None,
            grant_id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
        },
    )
}

/// `consent/revoke/1.0` — an operator withdraws a standing grant. Auth: admin.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let payload: RevokePayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let _ = &payload.reason;
    let subject: ConsentSubject = payload.subject.into();
    match get_consent_grant(&state.consent_ks, &subject).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return app_error_to_reject(
                &doc,
                AppError::NotFound("consent/revoke: no grant for subject".into()),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }
    if let Err(e) = delete_consent_grant(&state.consent_ks, &subject).await {
        return app_error_to_reject(&doc, e);
    }
    success_response(
        &doc,
        AckResponse {
            status: "revoked",
            request_id: None,
            grant_id: None,
        },
    )
}

/// `consent/list/1.0` — a bridge syncs the grants it enforces. Auth: read.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_read() {
        return app_error_to_reject(&doc, e);
    }
    let payload: ListPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let subject_filter: Option<ConsentSubject> = payload.subject.map(Into::into);
    let grants = match list_consent_grants(&state.consent_ks).await {
        Ok(g) => g,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let wire: Vec<WireGrant> = grants
        .into_iter()
        .filter(|g| payload.agent.as_ref().is_none_or(|a| &g.subject.agent == a))
        .filter(|g| {
            payload
                .platform
                .as_ref()
                .is_none_or(|p| &g.subject.platform == p)
        })
        .filter(|g| subject_filter.as_ref().is_none_or(|s| &g.subject == s))
        .map(WireGrant::from)
        .collect();
    success_response(&doc, ListResponse { grants: wire })
}

/// `consent/approver-set/1.0` — an admin binds the approver for a
/// (platform, context). Auth: admin of the context.
pub(super) async fn handle_approver_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: ApproverSetPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    if let Err(e) = auth.require_context(&payload.context) {
        return app_error_to_reject(&doc, e);
    }
    let binding = ApproverBinding {
        platform: payload.platform,
        context: payload.context,
        approver: payload.approver,
        route: payload.route,
        route_hint: payload.route_hint,
    };
    if let Err(e) = store_approver(&state.consent_approvers_ks, &binding).await {
        return app_error_to_reject(&doc, e);
    }
    success_response(&doc, ApproverSetResponse { status: "set" })
}

/// `consent/approver-list/1.0` — read the approver bindings. Auth: read.
pub(super) async fn handle_approver_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_read() {
        return app_error_to_reject(&doc, e);
    }
    let payload: ApproverListPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let all = match list_approvers(&state.consent_approvers_ks).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let approvers: Vec<WireApprover> = all
        .into_iter()
        .filter(|b| payload.platform.as_ref().is_none_or(|p| &b.platform == p))
        .filter(|b| payload.context.as_ref().is_none_or(|c| &b.context == c))
        .map(WireApprover::from)
        .collect();
    success_response(&doc, ApproverListResponse { approvers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_subject_parses_camelcase_and_maps() {
        let v = serde_json::json!({
            "platform": "signal",
            "conversationRef": "sig-1a2b3c4d",
            "kind": "group",
            "agent": "did:key:zA",
        });
        let s: ConsentSubject = serde_json::from_value::<WireSubject>(v).unwrap().into();
        assert_eq!(s.conversation_ref, "sig-1a2b3c4d");
        assert_eq!(s.kind, ConsentKind::Group);
    }

    #[test]
    fn request_payload_parses_full_wire() {
        let v = serde_json::json!({
            "subject": {"platform":"signal","conversationRef":"sig-1","kind":"dm","agent":"did:key:zA"},
            "scope": "converse",
            "challenge": "Q29uc2VudENoYWxsZW5nZQ",
            "displayHint": "Signal DM",
            "contextHint": "ctx",
        });
        let p: RequestPayload = serde_json::from_value(v).unwrap();
        assert_eq!(p.scope, ConsentScope::Converse);
        assert_eq!(p.context_hint.as_deref(), Some("ctx"));
    }

    #[test]
    fn wire_grant_serializes_camelcase() {
        let g = ConsentGrant {
            subject: ConsentSubject {
                platform: "signal".into(),
                conversation_ref: "sig-1".into(),
                kind: ConsentKind::Dm,
                agent: "did:key:zA".into(),
            },
            effect: ConsentEffect::Allow,
            scope: Some(ConsentScope::Converse),
            granted_by: "did:web:op".into(),
            granted_at: 1_700_000_000, // 2023-11-14
            expires_at: None,
            evidence: "did-signed".into(),
        };
        let v = serde_json::to_value(WireGrant::from(g)).unwrap();
        assert_eq!(v["subject"]["conversationRef"], "sig-1");
        assert_eq!(v["effect"], "allow");
        assert_eq!(v["scope"], "converse");
        assert_eq!(v["grantedBy"], "did:web:op");
        assert!(v["grantedAt"].as_str().unwrap().starts_with("2023-11"));
        assert!(v.get("expiresAt").is_none());
    }

    #[test]
    fn epoch_rfc3339_round_trips() {
        let s = epoch_to_rfc3339(1_700_000_000);
        assert_eq!(rfc3339_to_epoch(&s), Some(1_700_000_000));
        assert_eq!(rfc3339_to_epoch("not-a-date"), None);
    }

    #[test]
    fn approver_set_payload_parses_wire_route() {
        let v = serde_json::json!({
            "platform": "signal",
            "context": "ctx",
            "approver": "did:web:op",
            "route": "bridge-relay",
            "routeHint": "sig-0a1b",
        });
        let p: ApproverSetPayload = serde_json::from_value(v).unwrap();
        assert_eq!(p.route, Some(ConsentRoute::BridgeRelay));
        assert_eq!(p.route_hint.as_deref(), Some("sig-0a1b"));
    }

    #[test]
    fn wire_approver_serializes_camelcase_and_route() {
        let b = ApproverBinding {
            platform: "signal".into(),
            context: "ctx".into(),
            approver: "did:web:op".into(),
            route: Some(ConsentRoute::Wake),
            route_hint: None,
        };
        let v = serde_json::to_value(WireApprover::from(b)).unwrap();
        assert_eq!(v["route"], "wake");
        assert!(v.get("routeHint").is_none());
        let list = serde_json::to_value(ApproverListResponse { approvers: vec![] }).unwrap();
        assert_eq!(list["approvers"], serde_json::json!([]));
    }
}
