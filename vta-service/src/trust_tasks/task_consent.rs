//! Inbound `task-consent/decision/1.0` — an approver signs off on a specific
//! privileged task execution, bound to its payload digest.
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecisionPayload {
    /// Payload digest of the task being approved (echoes the pending request).
    digest: String,
    /// Nonce echoed from the pending request — binds this decision to it.
    challenge: String,
    /// True to approve, false to deny (a denial aborts the request).
    #[serde(default)]
    approve: bool,
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

    let ks = &state.task_consent_ks;
    let pending = match consent::get_pending(ks, &payload.digest).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "task-consent:no_pending".into(),
                    details: Some(json!({ "digest": payload.digest })),
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

    let now = now_secs();

    // A denial aborts the request.
    if !payload.approve {
        let _ = consent::delete_pending(ks, &payload.digest).await;
        return success_response(
            &doc,
            json!({ "status": "denied", "digest": payload.digest }),
        );
    }

    // Accumulate the approval; at the threshold, issue a single-use grant.
    let updated = match consent::add_approval(ks, &payload.digest, &approver).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: "task-consent:no_pending".into(),
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
            granted_at: now,
            expires_at: now + GRANT_TTL_SECS,
        };
        if let Err(e) = consent::store_grant(ks, &grant).await {
            return app_error_to_reject(&doc, e);
        }
        let _ = consent::delete_pending(ks, &payload.digest).await;
        return success_response(
            &doc,
            json!({
                "status": "granted",
                "digest": payload.digest,
                "approvals": updated.approvals.len(),
            }),
        );
    }

    success_response(
        &doc,
        json!({
            "status": "pending",
            "digest": payload.digest,
            "approvals": updated.approvals.len(),
            "needed": updated.min_approvals,
        }),
    )
}
