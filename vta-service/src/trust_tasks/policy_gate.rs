//! The pre-dispatch Policy Decision Point gate — the single step-up authority.
//!
//! Every dispatched Trust Task routes through [`policy_gate`] before its handler
//! runs. The gate is now the one place step-up is decided, sourcing it from two
//! places and rejecting-with-`approve-request` if either demands it:
//!
//! 1. **Config floors** — the existing `[auth.step_up]` floors, via
//!    [`super::step_up::require_step_up`]. This subsumes the per-handler
//!    `require_step_up` calls (removed from the slices). Runs for the gated
//!    op-classes regardless of PDP enforcement, so the config-driven behaviour
//!    is unchanged; a no-op when no floor applies or the session is already
//!    `aal2`.
//! 2. **Rego policy** — when `config.policy.enforcement` is on, a policy may
//!    return `requireStepUp` (self-approve), `deny`, `requireConsent`, or
//!    `allow`. The session's assurance (`acr`/`amr`) is fed into
//!    `PolicyInput.consumer`, so a policy can gate on step-up state.
//!
//! ## Ordering note
//!
//! The inline `require_step_up` used to run *after* a handler's role check; the
//! gate runs *before* dispatch, hence before the role check. A caller lacking
//! the role now sees a step-up challenge before the role denial — they still
//! can't complete the op, so this is a UX/ordering change, not a security one.
//! It is inherent to a single pre-dispatch gate.
//!
//! ## Opt-in Rego, fail-safe
//!
//! The Rego arm is inert unless enforcement is enabled; the config-floor arm
//! preserves existing behaviour. Any failure to load the policy set denies.

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, reject_with};
use crate::auth::AuthClaims;
use crate::policy::{self, Disposition, RequireConsent, consent};
use crate::server::AppState;

/// How long a pending consent request stays open for approvals.
const CONSENT_PENDING_TTL_SECS: u64 = 900;

fn gate_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ceremony tasks carry their own authority (an approver's proof, a step-up
/// approve-response) and must NOT themselves be gated — else approving a task
/// could itself require consent/step-up, ad infinitum.
#[allow(deprecated)]
fn is_ceremony_task(type_uri: &str) -> bool {
    use vta_sdk::trust_tasks as t;
    type_uri == t::TASK_TASK_CONSENT_DECISION_0_1
        || type_uri == t::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1
        || type_uri == t::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2
}

/// The ACR a satisfied step-up reaches. Mirrors `step_up::STEP_UP_TARGET_ACR`.
const STEP_UP_TARGET_ACR: &str = "aal2";

/// Map a task's Type URI to its step-up operation-class, for the gated ops that
/// carry a config floor. Only the ops that previously called `require_step_up`
/// inline are mapped, preserving current behaviour (`acl/swap-key` had no inline
/// call and stays unmapped). Returns `None` for ungated tasks.
#[allow(deprecated)]
fn op_class_for(type_uri: &str) -> Option<&'static str> {
    use super::step_up::op;
    use vta_sdk::trust_tasks as t;
    match type_uri {
        t::TASK_ACL_CREATE_1_0 => Some(op::ACL_GRANT),
        t::TASK_ACL_UPDATE_1_0 => Some(op::ACL_CHANGE_ROLE),
        t::TASK_ACL_DELETE_1_0 => Some(op::ACL_REVOKE),
        t::TASK_CONTEXTS_DELETE_1_0 => Some(op::CONTEXT_DELETE),
        t::TASK_KEYS_REVOKE_1_0 => Some(op::KEY_REVOKE),
        t::TASK_VAULT_RELEASE_0_1 => Some(op::VAULT_RELEASE),
        t::TASK_VAULT_PROXY_LOGIN_0_1 => Some(op::VAULT_PROXY_LOGIN),
        t::TASK_VAULT_SIGN_TRUST_TASK_0_1 => Some(op::VAULT_SIGN_TRUST_TASK),
        t::TASK_VTA_CREDENTIALS_ISSUE_0_1 => Some(op::CREDENTIALS_ISSUE),
        t::TASK_VTA_CREDENTIALS_REVOKE_0_1 => Some(op::CREDENTIALS_REVOKE),
        _ => None,
    }
}

/// Evaluate the gate for a task about to be dispatched.
///
/// `None` → proceed to the handler. `Some(outcome)` → reject before dispatch
/// (the caller still audits the rejected task).
pub(super) async fn policy_gate(
    state: &AppState,
    auth: &AuthClaims,
    type_uri: &str,
    doc: &TrustTask<Value>,
) -> Option<TrustTaskOutcome> {
    // Ceremony tasks are the mechanism, not a gated operation — never gate them.
    if is_ceremony_task(type_uri) {
        return None;
    }

    // (1) Config-floor step-up (subsumes the inline require_step_up).
    if let Some(op_class) = op_class_for(type_uri)
        && let Some(reject) = super::step_up::require_step_up(state, auth, op_class, doc).await
    {
        return Some(reject);
    }

    // (2) Rego policy — only when enforcement is enabled.
    if !state.config.read().await.policy.enforcement {
        return None;
    }

    let class = super::class_for(type_uri);
    let input = policy::build_policy_input(
        type_uri,
        &doc.payload,
        &auth.did,
        &auth.acr,
        &auth.amr,
        class,
    );

    let policies = match policy::load_active_for_context(&state.policy_ks, &input.context_id).await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, type_uri, "policy load failed — denying (fail-closed)");
            return Some(reject_with(
                doc,
                RejectReason::PermissionDenied {
                    reason: "policy evaluation unavailable".to_string(),
                },
            ));
        }
    };

    let decision = policy::decide(&policies, &input);
    match decision.decision {
        Disposition::Allow => None,
        Disposition::Deny => Some(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: decision
                    .explanation
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        )),
        Disposition::RequireStepUp => {
            if auth.acr == STEP_UP_TARGET_ACR {
                // Already elevated — the requirement is satisfied.
                None
            } else {
                Some(super::step_up::initiate_self_step_up(state, auth, doc).await)
            }
        }
        Disposition::RequireConsent => {
            consent_gate(state, auth, doc, type_uri, decision.require_consent).await
        }
    }
}

/// Resolve the PDP `requireConsent` disposition.
///
/// Proceeds (`None`) when a valid grant for this exact task already exists — but
/// only after re-asserting, at the moment of execution, that the world the
/// approver was shown is still the world the task will run against. Otherwise it
/// dry-runs the handler, mints a VTA-signed `task-consent/request` carrying the
/// effects, and rejects with it for the requester to relay to the approver set.
///
/// The signed request is what a consent surface renders. It has to come from
/// here — from the executor — because the requester cannot be allowed to author
/// the prose on which a human bases the decision, and because the payload alone
/// does not contain the consequences (a webvh document update silently rotates
/// the DID's update key).
async fn consent_gate(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    type_uri: &str,
    require: Option<RequireConsent>,
) -> Option<TrustTaskOutcome> {
    // A requireConsent naming no approver set can never be satisfied — fail closed.
    let Some(require) = require else {
        return Some(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: "policy requires consent but named no approver set".into(),
            },
        ));
    };

    let digest = match consent::payload_digest(type_uri, &doc.payload) {
        Ok(d) => d,
        Err(e) => return Some(app_error_to_reject(doc, e)),
    };
    let now = gate_now_secs();

    // An existing grant authorizes this payload — but it was minted minutes ago,
    // against a world that may have moved. Policy has already been re-evaluated
    // (this gate runs on every submit, including the re-submit that consumes the
    // grant); what has not been re-checked is the *data*.
    match consent::consume_grant(&state.task_consent_ks, &auth.did, type_uri, &digest, now).await {
        Ok(Some(grant)) => {
            if let Err(why) = super::planner::assert_plan_still_holds(
                state,
                auth,
                type_uri,
                &doc.payload,
                grant.state_pin.as_ref(),
                &grant.guards,
            )
            .await
            {
                // The grant is already consumed — single-use is single-use, even
                // when we refuse. Re-submitting mints a fresh request and the
                // approver sees the effects as they now are.
                return Some(reject_with(
                    doc,
                    RejectReason::TaskFailed {
                        reason: "auth:consent_stale".into(),
                        details: Some(json!({ "explanation": why })),
                    },
                ));
            }
            return None;
        }
        Ok(None) => {}
        Err(e) => return Some(app_error_to_reject(doc, e)),
    }

    // No grant: the approver set must be defined and non-empty.
    let members = state
        .config
        .read()
        .await
        .policy
        .approver_sets
        .get(&require.approver_set)
        .cloned()
        .unwrap_or_default();
    if members.is_empty() {
        return Some(reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "approver set '{}' is unknown or empty",
                    require.approver_set
                ),
            },
        ));
    }

    // Dry-run the handler we are about to gate. `None` means this executor has no
    // dry-run for it — the effects are *unknown*, not absent, and the consent
    // surface is required to say so.
    let plan = match super::planner::plan_task(state, auth, type_uri, &doc.payload).await {
        Ok(p) => p,
        Err(e) => return Some(app_error_to_reject(doc, e)),
    };
    let (effects, state_pin, guards) = match &plan {
        Some(p) => (p.effects.clone(), p.state_pin.clone(), p.guards.clone()),
        None => (vec![], None, Default::default()),
    };

    let min_approvals = require.min_approvals.max(1);

    // Reuse the pending request — and so the challenge, and so the digest the
    // approver is being asked to sign — but only while it still describes the
    // world. If the state moved under it, the effects it was minted with are no
    // longer what would happen, so it is retired and the approver is asked afresh
    // rather than left holding a stale question.
    let existing = match consent::get_pending(&state.task_consent_ks, &digest, now).await {
        Ok(p) => p,
        Err(e) => return Some(app_error_to_reject(doc, e)),
    };
    let pending = match existing {
        Some(p) if p.state_pin == state_pin && p.guards == guards => p,
        Some(stale) => {
            if let Err(e) = consent::delete_pending(&state.task_consent_ks, &stale).await {
                return Some(app_error_to_reject(doc, e));
            }
            match mint_pending(
                state,
                auth,
                doc,
                type_uri,
                &require,
                min_approvals,
                now,
                &state_pin,
                &guards,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => return Some(app_error_to_reject(doc, e)),
            }
        }
        None => {
            match mint_pending(
                state,
                auth,
                doc,
                type_uri,
                &require,
                min_approvals,
                now,
                &state_pin,
                &guards,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => return Some(app_error_to_reject(doc, e)),
            }
        }
    };

    let class = super::class_for(type_uri).unwrap_or_else(crate::policy::TaskClass::floor);
    let subject = crate::policy::input::subject_of(&doc.payload);
    let requests = match super::consent_request::mint_signed_requests(
        state,
        &pending,
        &members,
        class,
        &effects,
        subject.as_deref(),
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Some(app_error_to_reject(doc, e)),
    };

    Some(reject_with(
        doc,
        RejectReason::TaskFailed {
            reason: "auth:consent_required".into(),
            details: Some(json!({
                // The salted digest: what the approver signs, and what the two
                // screens compare. The internal one never leaves this process.
                "payloadDigest": pending.wire_digest,
                "challenge": pending.challenge,
                "approverSet": require.approver_set,
                "minApprovals": min_approvals,
                // The signed requests to relay. Each is VTA-authored, so the
                // approver renders effects it can attribute to the executor
                // rather than to whoever handed it the document.
                "consentRequests": requests,
            })),
        },
    ))
}

#[allow(clippy::too_many_arguments)]
async fn mint_pending(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    type_uri: &str,
    require: &RequireConsent,
    min_approvals: u32,
    now: u64,
    state_pin: &Option<crate::policy::effects::StatePin>,
    guards: &super::planner::Guards,
) -> Result<consent::PendingTaskConsent, vti_common::error::AppError> {
    // 256 bits of entropy. It is both the replay nonce and the digest salt, so
    // guessing it would both replay a decision and unmask the payload.
    let challenge = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let digest = consent::payload_digest(type_uri, &doc.payload)?;
    let wire_digest = consent::wire_digest(type_uri, &doc.payload, &challenge)?;

    let pending = consent::PendingTaskConsent {
        digest,
        wire_digest,
        type_uri: type_uri.to_string(),
        requester_did: auth.did.clone(),
        approver_set: require.approver_set.clone(),
        min_approvals,
        exclude_requester: require.exclude_requester,
        challenge,
        approvals: vec![],
        state_pin: state_pin.clone(),
        guards: guards.clone(),
        created_at: now,
        expires_at: now + CONSENT_PENDING_TTL_SECS,
    };
    consent::store_pending(&state.task_consent_ks, &pending).await?;
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::PolicyModule;

    fn module(id: &str, priority: i32, rego: &str) -> PolicyModule {
        PolicyModule {
            id: id.into(),
            name: id.into(),
            description: None,
            module: rego.into(),
            applies_to: vec![],
            priority,
            enabled: true,
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    const DENY_ALL: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\", \"explanation\": \"blocked\"}";
    const ALLOW_ALL: &str =
        "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"allow\"}";
    // Step-up unless the session is already aal2 — the canonical policy shape
    // the acr feed enables. Explicitly allows at aal2 (an abstaining policy
    // would default-deny).
    const STEPUP_IF_NOT_AAL2: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"requireStepUp\"} if input.consumer.acr != \"aal2\"\ndecision := {\"decision\": \"allow\"} if input.consumer.acr == \"aal2\"";

    fn doc(type_uri: &str) -> TrustTask<Value> {
        serde_json::from_value(serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": type_uri,
            "issuer": "did:key:zTestAdmin",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "contextId": "default" }
        }))
        .expect("valid trust task")
    }

    // An ungated task URI (not in op_class_for) so the config-floor arm is a
    // no-op and only the Rego arm runs.
    const UNGATED_URI: &str = "https://trusttasks.org/spec/vta/memory/list/0.1";

    #[tokio::test]
    async fn gate_inert_when_disabled_enforces_when_enabled() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        // Disabled: proceed even with an empty policy set.
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none());

        // Enabled + empty set → default-deny.
        state.config.write().await.policy.enforcement = true;
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some());

        // Deny policy → reject.
        crate::policy::storage::store_policy(&state.policy_ks, &module("deny", 0, DENY_ALL))
            .await
            .unwrap();
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some());

        // Higher-priority allow overrides → proceed.
        crate::policy::storage::store_policy(&state.policy_ks, &module("allow", 10, ALLOW_ALL))
            .await
            .unwrap();
        assert!(policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none());
    }

    #[tokio::test]
    async fn rego_requires_step_up_when_session_not_elevated() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let mut auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        state.config.write().await.policy.enforcement = true;
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("su", 0, STEPUP_IF_NOT_AAL2),
        )
        .await
        .unwrap();

        // aal1 session → policy demands step-up → rejected (with approve-request).
        auth.acr = "aal1".into();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some(),
            "aal1 session must be sent to step-up"
        );

        // aal2 session → requirement already satisfied → proceed.
        auth.acr = "aal2".into();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none(),
            "aal2 session must pass the step-up gate"
        );
    }

    // A second ungated URI. `doc()` gives both the *same* payload, which is the
    // whole point: without a type binding in the digest they collide.
    const OTHER_UNGATED_URI: &str = "https://trusttasks.org/spec/vta/memory/delete/0.1";

    const REQUIRE_CONSENT: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"requireConsent\", \"requireConsent\": {\"approverSet\": \"ops\"}}";

    /// The reject must carry VTA-**signed** consent requests.
    ///
    /// This is the load-bearing property of the whole flow: a consent surface
    /// renders `effects` as the basis of a human's decision, so if the requester
    /// could author that document, the least-trusted party in the system would be
    /// writing the prose the human reads — while every downstream signature still
    /// verified. The approver must be able to attribute what it renders to the
    /// executor.
    #[tokio::test]
    async fn consent_reject_carries_vta_signed_requests() {
        use crate::policy::consent;
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        {
            let mut cfg = state.config.write().await;
            cfg.policy.enforcement = true;
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec!["did:key:zApprover".into()]);
        }
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("consent", 0, REQUIRE_CONSENT),
        )
        .await
        .unwrap();

        let outcome = policy_gate(&state, &auth, UNGATED_URI, &d)
            .await
            .expect("first submit is rejected pending consent");
        let body: Value = serde_json::from_slice(&outcome.body).expect("reject body");
        let details = body
            .pointer("/payload/details")
            .expect("reject carries details");

        let requests = details["consentRequests"]
            .as_array()
            .expect("consentRequests present");
        assert_eq!(requests.len(), 1, "one request per eligible approver");
        let req = &requests[0];

        assert!(
            req.get("proof").is_some(),
            "the request must be signed — an unsigned one lets anyone author what the human reads"
        );
        let vta_did = state.config.read().await.vta_did.clone().unwrap();
        assert_eq!(req["issuer"], serde_json::json!(vta_did));
        assert_eq!(req["recipient"], serde_json::json!("did:key:zApprover"));
        assert_eq!(
            req["type"],
            serde_json::json!(super::super::consent_request::TASK_CONSENT_REQUEST_0_1)
        );

        // The digest on the wire is the salted one, and both the requester's copy
        // and the approver's agree on it — that is what lets the two screens be
        // compared.
        let wire = req["payload"]["payloadDigest"].as_str().unwrap();
        assert_eq!(details["payloadDigest"].as_str().unwrap(), wire);
        assert_eq!(
            req["payload"]["challenge"].as_str().unwrap(),
            details["challenge"].as_str().unwrap()
        );

        let challenge = details["challenge"].as_str().unwrap();
        assert_eq!(
            wire,
            consent::wire_digest(UNGATED_URI, &d.payload, challenge).unwrap()
        );
        assert_ne!(
            wire,
            consent::payload_digest(UNGATED_URI, &d.payload).unwrap(),
            "the internal digest must never reach the wire"
        );

        // The authoritative class comes from the **compiled dispatch table**, not
        // from the registry. If the registry decided this, it would be a consent
        // kill-switch: publish a version declaring `sideEffects: none` and consent
        // evaporates for anyone resolving by URI.
        let compiled = serde_json::to_value(
            super::super::class_for(UNGATED_URI).expect("this URI is in the dispatch table"),
        )
        .unwrap();
        assert_eq!(req["payload"]["sideEffects"], compiled["sideEffects"]);
        assert_eq!(req["payload"]["exposure"], compiled["exposure"]);

        // No planner for this task, so no effects. That is "unknown", not
        // "harmless" — and the spec obliges the surface to say so.
        assert_eq!(
            req["payload"]["effects"],
            serde_json::json!([]),
            "a handler with no dry-run yields no effects"
        );
        assert_eq!(req["payload"]["taskType"], serde_json::json!(UNGATED_URI));
    }

    /// The approver named by `excludeRequester` is dropped before we ask, rather
    /// than asked a question whose answer we would refuse.
    #[tokio::test]
    async fn the_requester_is_never_asked_to_approve_its_own_task() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        {
            let mut cfg = state.config.write().await;
            cfg.policy.enforcement = true;
            // The approver set contains ONLY the requester.
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec![auth.did.clone()]);
        }
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("consent", 0, REQUIRE_CONSENT_EXCLUDE_REQUESTER),
        )
        .await
        .unwrap();

        let outcome = policy_gate(&state, &auth, UNGATED_URI, &d).await.unwrap();
        let body: Value = serde_json::from_slice(&outcome.body).unwrap();
        let requests = body
            .pointer("/payload/details/consentRequests")
            .and_then(Value::as_array)
            .expect("consentRequests present");
        assert!(
            requests.is_empty(),
            "the only member of the set is the requester, and the policy excludes them — \
             so there is nobody to ask, and we must not pretend otherwise"
        );
    }

    const REQUIRE_CONSENT_EXCLUDE_REQUESTER: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"requireConsent\", \"requireConsent\": {\"approverSet\": \"ops\", \"excludeRequester\": true}}";

    /// A grant approved for one task URI must not authorize a *different* task
    /// URI that happens to carry an identical payload. The approver only ever
    /// sees an opaque digest, so if the digest didn't bind the type URI, consent
    /// for a benign task would silently authorize a destructive one.
    #[tokio::test]
    async fn grant_for_one_task_uri_does_not_authorize_another() {
        use crate::policy::consent;
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();

        let approved = doc(UNGATED_URI);
        let substituted = doc(OTHER_UNGATED_URI);
        assert_eq!(
            approved.payload, substituted.payload,
            "the two tasks must share a payload for this test to mean anything"
        );

        {
            let mut cfg = state.config.write().await;
            cfg.policy.enforcement = true;
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec!["did:key:zApprover".into()]);
        }
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("consent", 0, REQUIRE_CONSENT),
        )
        .await
        .unwrap();

        // Approvers sign off on UNGATED_URI: mint the grant the gate would consume.
        let now = super::gate_now_secs();
        let digest = consent::payload_digest(UNGATED_URI, &approved.payload).unwrap();
        consent::store_grant(
            &state.task_consent_ks,
            &consent::TaskConsentGrant {
                digest: digest.clone(),
                state_pin: None,
                guards: Default::default(),
                requester_did: auth.did.clone(),
                type_uri: UNGATED_URI.into(),
                approvers: vec!["did:key:zApprover".into()],
                granted_at: now,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        // The substituted task must NOT ride that grant through.
        assert!(
            policy_gate(&state, &auth, OTHER_UNGATED_URI, &substituted)
                .await
                .is_some(),
            "a grant for a different task URI must not authorize this one"
        );

        // …while the task actually approved still passes.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &approved)
                .await
                .is_none(),
            "the approved task must still consume its own grant"
        );
    }

    #[tokio::test]
    async fn require_consent_records_pending_then_grant_lets_resubmit_through() {
        use crate::policy::consent;
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        {
            let mut cfg = state.config.write().await;
            cfg.policy.enforcement = true;
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec!["did:key:zApprover".into()]);
        }
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("consent", 0, REQUIRE_CONSENT),
        )
        .await
        .unwrap();

        // First submit → consent required (rejected) + a pending is recorded.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some(),
            "first submit must be rejected pending consent"
        );
        let digest = consent::payload_digest(UNGATED_URI, &d.payload).unwrap();
        let now = super::gate_now_secs();
        assert!(
            consent::get_pending(&state.task_consent_ks, &digest, now)
                .await
                .unwrap()
                .is_some(),
            "a pending consent record must exist"
        );

        // Simulate approvers reaching threshold: store a grant.
        consent::store_grant(
            &state.task_consent_ks,
            &consent::TaskConsentGrant {
                digest: digest.clone(),
                state_pin: None,
                guards: Default::default(),
                requester_did: auth.did.clone(),
                type_uri: UNGATED_URI.into(),
                approvers: vec!["did:key:zApprover".into()],
                granted_at: now,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        // Re-submit → grant consumed → proceed.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_none(),
            "a valid grant must let the re-submit proceed"
        );
        // Grant was single-use → the next submit needs consent again.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d).await.is_some(),
            "grant is single-use; a further submit re-requires consent"
        );
    }
}
