//! Inbound `task-consent/decision/0.1` — an approver signs off on a specific
//! privileged task execution, bound to the payload digest they were shown.
//!
//! This is the decision half of the PDP's `requireConsent` flow (the gate mints
//! the pending request and wakes approvers). The approver's authority is the
//! **proof**, not the bearer token: we verify the Data-Integrity proof, take the
//! proven signer DID, and require it to be a member of the policy-named approver
//! set. At the required threshold the VTA issues a single-use grant the
//! requester's re-submit consumes.

use serde::Deserialize;
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, parse_payload, reject_with, success_response};
use crate::auth::AuthClaims;
use crate::policy::consent;
use crate::server::AppState;

/// How long a completed grant stays valid for the requester's re-submit.
const GRANT_TTL_SECS: u64 = 600;

/// `task-consent/decision/0.1`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionPayload {
    /// Nonce echoed from the request — binds this decision to it.
    challenge: String,
    /// The **salted** digest the approver was shown and signed. This is the only
    /// digest that ever leaves the executor; the internal one it indexes is
    /// resolved from it.
    payload_digest: String,
    /// The human's answer. An explicit enum rather than a bool, so that a missing
    /// or falsy value can never read as assent — silence, timeouts and dismissals
    /// are denials, and a wire form that lets them decode as approval is a bug
    /// waiting for a serializer change.
    decision: Decision,
    /// Optional note, most useful on a denial.
    #[allow(dead_code)]
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Approve,
    Deny,
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(super) async fn handle_decision(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload: DecisionPayload = match parse_payload(&doc) {
        Ok(p) => p,
        Err(o) => return o,
    };

    // Authority is the proof: verify it and take the *proven* signer DID.
    let approver = match crate::auth::di_proof::verify_trust_task_proof(&doc).await {
        Ok(did) => did,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::PermissionDenied {
                    reason: format!("task-consent decision must carry a valid proof: {e}"),
                },
            );
        }
    };

    let now = now_secs();

    let ks = &state.task_consent_ks;
    // An expired pending reads as absent, so a lapsed request can't be approved.
    let pending = match consent::pending_by_wire_digest(ks, &payload.payload_digest, now).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "task-consent/decision:no_pending".into(),
                    details: Some(json!({ "payloadDigest": payload.payload_digest })),
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Bind the decision to this exact request.
    if payload.challenge != pending.challenge {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "challenge does not match the pending request".into(),
            },
        );
    }

    // The proven signer must be a member of the policy-named approver set.
    let members = state
        .config
        .read()
        .await
        .policy
        .approver_sets
        .get(&pending.approver_set)
        .cloned()
        .unwrap_or_default();
    if !members.iter().any(|m| m == &approver) {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "signer is not a member of approver set '{}'",
                    pending.approver_set
                ),
            },
        );
    }
    // A requester can't approve their own task when the policy excludes them.
    if pending.exclude_requester && approver == pending.requester_did {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "the requester may not approve its own task".into(),
            },
        );
    }

    // A denial aborts the request.
    if payload.decision == Decision::Deny {
        let _ = consent::delete_pending(ks, &pending).await;
        return success_response(
            &doc,
            json!({ "status": "denied", "payloadDigest": payload.payload_digest }),
        );
    }

    // Accumulate the approval; at the threshold, issue a single-use grant.
    let updated = match consent::add_approval(ks, &pending.digest, &approver, now).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "task-consent/decision:no_pending".into(),
                    details: None,
                },
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if updated.approvals.len() as u32 >= updated.min_approvals {
        let grant = consent::TaskConsentGrant {
            digest: updated.digest.clone(),
            requester_did: updated.requester_did.clone(),
            type_uri: updated.type_uri.clone(),
            approvers: updated.approvals.clone(),
            // Carry what the approvers were shown through to execution, which
            // re-asserts it before committing. Without this the grant would
            // authorize the payload but say nothing about the state it was
            // approved against — and a human in the loop makes that window
            // minutes wide.
            state_pin: updated.state_pin.clone(),
            guards: updated.guards.clone(),
            granted_at: now,
            expires_at: now + GRANT_TTL_SECS,
        };
        if let Err(e) = consent::store_grant(ks, &grant).await {
            return app_error_to_reject(&doc, e);
        }
        let _ = consent::delete_pending(ks, &updated).await;
        return success_response(
            &doc,
            json!({
                "status": "granted",
                "payloadDigest": payload.payload_digest,
                "approvals": updated.approvals.len(),
            }),
        );
    }

    success_response(
        &doc,
        json!({
            "status": "pending",
            "payloadDigest": payload.payload_digest,
            "approvals": updated.approvals.len(),
            "needed": updated.min_approvals,
        }),
    )
}
