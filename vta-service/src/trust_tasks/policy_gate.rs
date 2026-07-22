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
    // Out: contexts a consumed delegated grant confers on this execution (see
    // `consent_gate`). Only the consent path ever writes it; every other gate
    // outcome leaves it empty.
    delegated_out: &mut Vec<String>,
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
            consent_gate(
                state,
                auth,
                doc,
                type_uri,
                decision.require_consent,
                delegated_out,
            )
            .await
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
    // Out: filled with the contexts a consumed *delegated* grant confers on this
    // one execution, so the caller can widen `auth` for the dispatch. Left empty
    // for an ordinary same-context consent (the requester already held the
    // context). The bodies below never widen authority themselves — they only
    // report what the approvers conferred, keeping the augmentation on one
    // explicit, auditable path.
    delegated_out: &mut Vec<String>,
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

    // The approver set as it stands *now*, not as it stood when the request was
    // raised. This is resolved before the grant is consumed, because a grant
    // cannot be honoured against a set that no longer exists.
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

    // An existing grant authorizes this payload — but it was minted minutes ago,
    // against a world that may have moved. Three things get re-checked here, and
    // all three used to be one:
    //
    //   1. **Policy.** Already covered: this gate runs on every submit, including
    //      the re-submit that consumes the grant, so `require` below is the
    //      *current* decision — a policy tightened during the approval window
    //      applies.
    //   2. **Enrolment.** The approvers who signed must STILL be members of the
    //      set the current policy names, and must still meet its threshold.
    //   3. **Data.** The state the effects were computed against, and the
    //      executor's own preconditions.
    match consent::consume_grant(&state.task_consent_ks, &auth.did, type_uri, &digest, now).await {
        Ok(Some(grant)) => {
            // The grant is consumed by now — single-use is single-use, even when
            // we go on to refuse. Re-submitting mints a fresh request, and the
            // approver is asked again against the world as it now is.
            if let Err(why) = approvals_still_authorize(&require, &members, &grant, &auth.did) {
                crate::audit::record_consent(
                    &state.audit_ks,
                    "consent.consumed",
                    &auth.did,
                    type_uri,
                    "denied:approver_no_longer_authorized",
                    Some(&format!("digest={digest}; {why}")),
                )
                .await;
                return Some(reject_with(
                    doc,
                    RejectReason::PermissionDenied { reason: why },
                ));
            }
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
                tracing::info!(
                    consent_diag = true,
                    type_uri,
                    digest = %digest.chars().take(12).collect::<String>(),
                    grant_state_pin = ?grant.state_pin,
                    grant_guards = ?grant.guards,
                    %why,
                    "consent-diag: grant CONSUMED but the re-planned world no longer matches it \
                     — re-raising consent. If this line repeats, THIS is the loop."
                );
                crate::audit::record_consent(
                    &state.audit_ks,
                    "consent.consumed",
                    &auth.did,
                    type_uri,
                    "denied:plan_changed",
                    Some(&format!("digest={digest}; {why}")),
                )
                .await;
                return Some(reject_with(
                    doc,
                    RejectReason::TaskFailed {
                        reason: "auth:consent_stale".into(),
                        details: Some(json!({ "explanation": why })),
                    },
                ));
            }
            // The grant is authorized and the world still matches. If it carries
            // a delegation (approvers conferred a context the requester lacked),
            // hand it to the caller to widen `auth` for this one dispatch.
            crate::audit::record_consent(
                &state.audit_ks,
                "consent.consumed",
                &auth.did,
                type_uri,
                "success",
                Some(&format!(
                    "digest={digest}; approvers={}",
                    grant.approvers.join(",")
                )),
            )
            .await;
            *delegated_out = grant.delegated_contexts;
            return None;
        }
        Ok(None) => {
            tracing::info!(
                consent_diag = true,
                type_uri,
                requester = %auth.did,
                digest = %digest.chars().take(12).collect::<String>(),
                "consent-diag: no grant found for (requester, digest) — the approval has not landed \
                 for this exact payload; will mint/reuse a pending below"
            );
        }
        Err(e) => return Some(app_error_to_reject(doc, e)),
    }

    // Dry-run the handler we are about to gate. `None` means this executor has no
    // dry-run for it — the effects are *unknown*, not absent, and the consent
    // surface is required to say so.
    let plan = match super::planner::plan_task(state, auth, type_uri, &doc.payload).await {
        Ok(p) => p,
        Err(e) => return Some(app_error_to_reject(doc, e)),
    };
    let (effects, state_pin, guards, subject_context, requester_authorized) = match &plan {
        Some(p) => (
            p.effects.clone(),
            p.state_pin.clone(),
            p.guards.clone(),
            p.subject_context.clone(),
            p.requester_authorized,
        ),
        // No planner ⇒ no delegation concept: treat as self-authorized so the
        // approver-authority path below never engages for an unplanned task.
        None => (vec![], None, Default::default(), None, true),
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
    // Whether this submit *raised* a new question, as opposed to re-asking one
    // already outstanding. Only a new question is pushed — see below.
    let mut newly_raised = true;
    let pending = match existing {
        Some(p) if p.state_pin == state_pin && p.guards == guards => {
            newly_raised = false;
            tracing::info!(
                consent_diag = true,
                type_uri,
                digest = %digest.chars().take(12).collect::<String>(),
                "consent-diag: REUSING the outstanding pending (state_pin + guards unchanged) — \
                 the code should stay the same; waiting on the approver's grant"
            );
            p
        }
        Some(stale) => {
            tracing::info!(
                consent_diag = true,
                type_uri,
                digest = %digest.chars().take(12).collect::<String>(),
                state_pin_changed = stale.state_pin != state_pin,
                guards_changed = stale.guards != guards,
                old_guards = ?stale.guards,
                new_guards = ?guards,
                old_state_pin = ?stale.state_pin,
                new_state_pin = ?state_pin,
                "consent-diag: RE-MINTING — the outstanding pending went stale, so a fresh code is \
                 issued. `guards_changed`/`state_pin_changed` say which drifted. If this repeats, \
                 THIS is why the code changes every time."
            );
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
                &subject_context,
                requester_authorized,
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
                &subject_context,
                requester_authorized,
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
    // The page that proposed this, when one did. Stamped into `payload.ext` by the
    // enrolled device from the origin its browser attested — so the approver is
    // told *which site* is asking, and told it by the only party in the chain with
    // any standing to say.
    let origin = crate::policy::input::origin_of(&doc.payload);
    let requests = match super::consent_request::mint_signed_requests(
        state,
        &pending,
        &members,
        class,
        &effects,
        subject.as_deref(),
        origin.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Some(app_error_to_reject(doc, e)),
    };

    // Wake the approvers — but only for a question we have not already asked.
    //
    // The reject is deliberately idempotent: a requester re-submitting the same
    // payload gets the same challenge back, so it can retry without invalidating
    // an approval already in flight. Pushing on every re-submit would turn that
    // into a weapon: a relying party could ring an approver's phone as fast as it
    // can retry a task it knows will be rejected. Consent designs die to
    // habituation long before they die to cryptography, and an attacker who can
    // make the prompt appear on demand is the one holding the habituation lever.
    //
    // So the push follows the *question*, not the submit.
    if newly_raised {
        super::consent_request::push_signed_requests(state, &requests).await;
    }

    // Durable record that a Destructive task was gated behind consent. Auditing
    // on every re-submit (not just the newly-raised one) is deliberate: a wedged
    // elevation shows up here as a run of `consent.required` rows with a stable
    // digest and no matching `consent.consumed` — the loop, made visible after
    // the fact without needing live logs.
    crate::audit::record_consent(
        &state.audit_ks,
        "consent.required",
        &auth.did,
        type_uri,
        if newly_raised {
            "pending:raised"
        } else {
            "pending:reasked"
        },
        Some(&format!(
            "digest={digest}; approverSet={}; minApprovals={min_approvals}; challenge={}",
            require.approver_set, pending.challenge
        )),
    )
    .await;

    Some(reject_with(
        doc,
        RejectReason::TaskFailed {
            reason: "auth:consent_required".into(),
            details: Some(json!({
                // The machine-readable reason, so a consumer keys on a stable
                // field in `details` rather than the standard top-level `code`
                // (which is `taskFailed` for this rejection) or the free-text
                // `message`. Mirrors the `RejectReason::TaskFailed.reason` above.
                "reason": "auth:consent_required",
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

/// Do the approvals on this grant *still* authorize the task?
///
/// A grant records who approved. It does not record that they are still allowed
/// to. Between an approval and the execution it authorizes there is a human-sized
/// gap — minutes — and `device/disable`, `device/wipe`, or an operator editing the
/// approver set all land inside it.
///
/// Without this, revoking a compromised approver does not stop the approvals
/// already in flight from it: the grant is keyed by payload and requester, both
/// of which are unchanged, so it consumes cleanly and the task runs on the
/// authority of someone who is no longer trusted to give it. Revocation that does
/// not reach in-flight approvals is not revocation.
///
/// Checked against the **current** policy decision and the **current** set —
/// never the ones captured when the request was raised, which is the whole point.
fn approvals_still_authorize(
    require: &RequireConsent,
    members: &[String],
    grant: &consent::TaskConsentGrant,
    requester_did: &str,
) -> Result<(), String> {
    let min_approvals = require.min_approvals.max(1);

    let still_valid: Vec<&String> = grant
        .approvers
        .iter()
        .filter(|a| members.iter().any(|m| m == *a))
        // A policy that has *since* excluded the requester retroactively
        // disqualifies their own approval, exactly as it would a fresh one.
        .filter(|a| !(require.exclude_requester && a.as_str() == requester_did))
        .collect();

    if (still_valid.len() as u32) >= min_approvals {
        return Ok(());
    }

    let revoked: Vec<&str> = grant
        .approvers
        .iter()
        .filter(|a| !still_valid.contains(a))
        .map(String::as_str)
        .collect();

    Err(format!(
        "the approval for this task is no longer valid: {} of the {} required approver(s) are no \
         longer permitted to approve it ({}). Re-submit to ask the current approver set.",
        min_approvals as usize - still_valid.len(),
        min_approvals,
        if revoked.is_empty() {
            "the approver set or its threshold changed".to_string()
        } else {
            revoked.join(", ")
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
    subject_context: &Option<String>,
    requester_authorized: bool,
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
        subject_context: subject_context.clone(),
        requester_authorized,
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
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_none()
        );

        // Enabled + empty set → default-deny.
        state.config.write().await.policy.enforcement = true;
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some()
        );

        // Deny policy → reject.
        crate::policy::storage::store_policy(&state.policy_ks, &module("deny", 0, DENY_ALL))
            .await
            .unwrap();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some()
        );

        // Higher-priority allow overrides → proceed.
        crate::policy::storage::store_policy(&state.policy_ks, &module("allow", 10, ALLOW_ALL))
            .await
            .unwrap();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_none()
        );
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
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some(),
            "aal1 session must be sent to step-up"
        );

        // aal2 session → requirement already satisfied → proceed.
        auth.acr = "aal2".into();
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_none(),
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

        let outcome = policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
            .await
            .expect("first submit is rejected pending consent");
        let body: Value = serde_json::from_slice(&outcome.body).expect("reject body");
        let details = body
            .pointer("/payload/details")
            .expect("reject carries details");

        // The machine-readable reason a consumer keys on lives in `details`,
        // not the top-level `code` (`taskFailed`) — so clients don't string-match
        // the free-text message.
        assert_eq!(
            details["reason"].as_str(),
            Some("auth:consent_required"),
            "consent rejects must carry a machine-readable reason in details"
        );

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

    /// The approver is told which site is asking — and told it by the device,
    /// which is the only party in the chain with any standing to say.
    ///
    /// The origin rides in `payload.ext`, so it is inside the digest the approver
    /// signs: the site shown to the human is bound to the payload that executes
    /// and cannot be swapped after the fact.
    #[tokio::test]
    async fn the_consent_request_names_the_origin_that_proposed_the_task() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();

        let mut d = doc(UNGATED_URI);
        d.payload["ext"] = json!({ "openvtc.origin": "https://control.example.com" });

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

        let outcome = policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&outcome.body).unwrap();
        let req = &body.pointer("/payload/details/consentRequests").unwrap()[0];

        assert_eq!(
            req["payload"]["origin"],
            json!("https://control.example.com"),
            "the approver must be able to see which site asked"
        );
    }

    /// A task nobody proposed from a page carries no origin — and we do not invent
    /// one. An origin the approver cannot rely on is worse than none: it invites
    /// them to weigh a fact that is not a fact.
    #[tokio::test]
    async fn a_task_with_no_page_behind_it_carries_no_origin() {
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

        let outcome = policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&outcome.body).unwrap();
        let req = &body.pointer("/payload/details/consentRequests").unwrap()[0];
        assert!(req["payload"].get("origin").is_none());
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

        let outcome = policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
            .await
            .unwrap();
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

    /// The push must follow the *question*, not the submit.
    ///
    /// The reject is deliberately idempotent — a requester re-submitting the same
    /// payload gets the same challenge back, so a retry cannot invalidate an
    /// approval already in flight. Pushing on every re-submit would turn that into
    /// a weapon: a relying party could ring an approver's phone as fast as it can
    /// retry a task it knows will be rejected. Consent designs die to habituation
    /// long before they die to cryptography, and an attacker who can summon the
    /// prompt at will is the one holding that lever.
    #[cfg(feature = "didcomm")]
    #[tokio::test]
    async fn a_resubmit_re_asks_nobody() {
        use crate::messaging::registry::MediatorBinding;

        const MEDIATOR: &str = "did:example:mediator";
        const APPROVER: &str = "did:key:zApprover";

        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        // A live mediator the approver routes through, so the push actually lands
        // somewhere we can observe.
        state
            .mediator_registry
            .record_activate(MediatorBinding {
                mediator_did: MEDIATOR.into(),
                endpoint: "https://mediator.test".into(),
            })
            .await;
        {
            let mut cfg = state.config.write().await;
            cfg.policy.enforcement = true;
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec![APPROVER.into()]);
            cfg.messaging = Some(vti_common::config::MessagingConfig {
                mediator_url: String::new(),
                mediator_did: MEDIATOR.into(),
                mediator_host: None,
                setup_acl: false,
                drain_inbox_on_start: false,
            });
        }
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("consent", 0, REQUIRE_CONSENT),
        )
        .await
        .unwrap();

        // First submit raises the question — the approver is asked.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some()
        );
        let pushed = state.mediator_registry.take_outbound(MEDIATOR).await;
        assert_eq!(pushed.len(), 1, "the approver is asked exactly once");
        assert_eq!(
            pushed[0].message_type,
            super::super::consent_request::TASK_CONSENT_REQUEST_0_1
        );
        assert_eq!(pushed[0].recipient_did, APPROVER);
        assert!(
            pushed[0].body.get("proof").is_some(),
            "the pushed document is the same signed one the reject carries — one \
             document on two transports, so a device cannot be shown different \
             effects depending on how it arrived"
        );

        // Re-submitting the identical payload re-asks the same question, and must
        // not ring the phone again.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some()
        );
        assert!(
            state
                .mediator_registry
                .take_outbound(MEDIATOR)
                .await
                .is_empty(),
            "a re-submit must not re-push — otherwise a relying party can spam an \
             approver by retrying a task it knows will be rejected"
        );
    }

    /// Revocation must reach approvals already in flight.
    ///
    /// A grant records who approved. It does not record that they are *still*
    /// allowed to — and between the approval and the execution it authorizes
    /// there is a human-sized gap. Without a re-check, disabling a compromised
    /// approver leaves every approval it already signed executable: the grant is
    /// keyed by payload and requester, both unchanged, so it consumes cleanly and
    /// the task runs on the authority of someone no longer trusted to give it.
    ///
    /// Revocation that does not reach in-flight approvals is not revocation.
    #[tokio::test]
    async fn a_revoked_approver_cannot_carry_a_grant_through() {
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

        // The approver signs off: a grant lands.
        let now = super::gate_now_secs();
        let digest = consent::payload_digest(UNGATED_URI, &d.payload).unwrap();
        let grant = consent::TaskConsentGrant {
            digest: digest.clone(),
            requester_did: auth.did.clone(),
            type_uri: UNGATED_URI.into(),
            approvers: vec!["did:key:zApprover".into()],
            state_pin: None,
            guards: Default::default(),
            delegated_contexts: vec![],
            granted_at: now,
            expires_at: now + 600,
        };
        consent::store_grant(&state.task_consent_ks, &grant)
            .await
            .unwrap();

        // …and is then revoked, while the requester is still holding the grant.
        {
            let mut cfg = state.config.write().await;
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec!["did:key:zSomeoneElse".into()]);
        }

        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some(),
            "a grant signed by a now-revoked approver must NOT carry the task through"
        );
    }

    /// The same grant, with the approver still enrolled, still works — the check
    /// must refuse the revoked case without breaking the ordinary one.
    #[tokio::test]
    async fn a_still_enrolled_approver_carries_the_grant_through() {
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

        let now = super::gate_now_secs();
        let digest = consent::payload_digest(UNGATED_URI, &d.payload).unwrap();
        consent::store_grant(
            &state.task_consent_ks,
            &consent::TaskConsentGrant {
                digest,
                requester_did: auth.did.clone(),
                type_uri: UNGATED_URI.into(),
                approvers: vec!["did:key:zApprover".into()],
                state_pin: None,
                guards: Default::default(),
                delegated_contexts: vec![],
                granted_at: now,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_none(),
            "an approver still in the set must carry the task through"
        );
    }

    /// A threshold raised during the approval window applies to the grant already
    /// in flight. One approval no longer authorizes a task that now needs two.
    #[tokio::test]
    async fn a_threshold_raised_mid_flight_invalidates_the_grant() {
        use crate::policy::consent;
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let auth = crate::test_support::super_admin_claims();
        let d = doc(UNGATED_URI);

        {
            let mut cfg = state.config.write().await;
            cfg.policy.enforcement = true;
            cfg.policy
                .approver_sets
                .insert("ops".into(), vec!["did:key:zA".into(), "did:key:zB".into()]);
        }
        // The policy now demands two approvals.
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &module("consent", 0, REQUIRE_CONSENT_MIN_TWO),
        )
        .await
        .unwrap();

        // The grant carries only one.
        let now = super::gate_now_secs();
        let digest = consent::payload_digest(UNGATED_URI, &d.payload).unwrap();
        consent::store_grant(
            &state.task_consent_ks,
            &consent::TaskConsentGrant {
                digest,
                requester_did: auth.did.clone(),
                type_uri: UNGATED_URI.into(),
                approvers: vec!["did:key:zA".into()],
                state_pin: None,
                guards: Default::default(),
                delegated_contexts: vec![],
                granted_at: now,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some(),
            "a single approval must not satisfy a threshold that has since risen to two"
        );
    }

    const REQUIRE_CONSENT_MIN_TWO: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"requireConsent\", \"requireConsent\": {\"approverSet\": \"ops\", \"minApprovals\": 2}}";

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
                delegated_contexts: vec![],
                granted_at: now,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        // The substituted task must NOT ride that grant through.
        assert!(
            policy_gate(
                &state,
                &auth,
                OTHER_UNGATED_URI,
                &substituted,
                &mut Vec::new()
            )
            .await
            .is_some(),
            "a grant for a different task URI must not authorize this one"
        );

        // …while the task actually approved still passes.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &approved, &mut Vec::new())
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
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some(),
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
                delegated_contexts: vec![],
                granted_at: now,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();

        // Re-submit → grant consumed → proceed.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_none(),
            "a valid grant must let the re-submit proceed"
        );
        // Grant was single-use → the next submit needs consent again.
        assert!(
            policy_gate(&state, &auth, UNGATED_URI, &d, &mut Vec::new())
                .await
                .is_some(),
            "grant is single-use; a further submit re-requires consent"
        );
    }
}
