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
use crate::acl::{Role, get_acl_entry};
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

/// Contexts these approvals may confer on the single execution that consumes the
/// grant — the per-task delegation.
///
/// Empty unless the task was a cross-context proposal (`requester_authorized ==
/// false`) with a known `subject_context`. When it was, an approver confers that
/// context **only if they hold authority over it**, resolved against live ACL
/// state, by *either* of two paths:
///   1. **Explicit approve authority** — an `approve_scope` covering the context.
///      This is the least-privilege approver: it may confer without any power to
///      act (`role: Reader`, no `allowed_contexts`).
///   2. **Admin of the context** — `Role::Admin` with context access (super-admin,
///      or the context/an ancestor in `allowed_contexts`). The backward-compatible
///      path: an admin confers what it already holds.
///
/// This is attenuation — an approver can never delegate authority it does not
/// hold, and set membership alone is not authority. The context is conferred only
/// if enough such approvers met the same `min_approvals` threshold the task
/// required; otherwise the grant carries nothing and execution still fails the
/// requester's own authorization.
async fn compute_delegated_contexts(
    state: &AppState,
    pending: &consent::PendingTaskConsent,
    now: u64,
) -> Vec<String> {
    if pending.requester_authorized {
        return Vec::new();
    }
    let Some(ctx) = pending.subject_context.as_deref() else {
        return Vec::new();
    };
    let mut conferrers = 0u32;
    for approver in &pending.approvals {
        // A DID absent from the ACL (or expired) confers nothing — a random
        // approver device cannot grant authority.
        let Ok(Some(entry)) = get_acl_entry(&state.acl_ks, approver).await else {
            continue;
        };
        if entry.is_expired(now) {
            continue;
        }
        let confers = entry.approve_scope.covers(ctx) || {
            let claims = AuthClaims {
                did: approver.clone(),
                role: entry.role.clone(),
                allowed_contexts: entry.allowed_contexts.clone(),
                ..Default::default()
            };
            claims.role == Role::Admin && claims.has_context_access(ctx)
        };
        if confers {
            conferrers += 1;
        }
    }
    if conferrers >= pending.min_approvals {
        vec![ctx.to_string()]
    } else {
        Vec::new()
    }
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
            crate::audit::record_consent(
                &state.audit_ks,
                "consent.decision",
                &approver,
                &payload.payload_digest,
                "denied:no_pending",
                Some(
                    "approver decided on a request that no longer exists (expired, \
                      already resolved, or re-minted under a new challenge)",
                ),
            )
            .await;
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
        crate::audit::record_consent(
            &state.audit_ks,
            "consent.decision",
            &approver,
            &pending.type_uri,
            "denied:challenge_mismatch",
            Some(&format!("digest={}", pending.digest)),
        )
        .await;
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
        crate::audit::record_consent(
            &state.audit_ks,
            "consent.decision",
            &approver,
            &pending.type_uri,
            "denied:not_a_member",
            Some(&format!("approverSet={}", pending.approver_set)),
        )
        .await;
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
        crate::audit::record_consent(
            &state.audit_ks,
            "consent.decision",
            &approver,
            &pending.type_uri,
            "denied:requester_excluded",
            None,
        )
        .await;
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
        crate::audit::record_consent(
            &state.audit_ks,
            "consent.decision",
            &approver,
            &pending.type_uri,
            "success:deny",
            Some(&format!("digest={}", pending.digest)),
        )
        .await;
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
        // Per-task delegation. When the requester could not self-authorize the
        // task's context, the approvals confer execution authority for it — but
        // only if the approvers actually hold admin there. Resolved here, at the
        // moment the grant is minted, against live ACL state.
        let delegated_contexts = compute_delegated_contexts(state, &updated, now).await;
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
            delegated_contexts,
            granted_at: now,
            expires_at: now + GRANT_TTL_SECS,
        };
        if let Err(e) = consent::store_grant(ks, &grant).await {
            return app_error_to_reject(&doc, e);
        }
        let _ = consent::delete_pending(ks, &updated).await;
        // The approval that crossed the threshold, then the grant it minted:
        // two rows so the trail shows both the final approver and the single-use
        // grant the requester will consume.
        crate::audit::record_consent(
            &state.audit_ks,
            "consent.decision",
            &approver,
            &updated.type_uri,
            "success:approve",
            Some(&format!(
                "digest={}; approvals={}/{}",
                updated.digest,
                updated.approvals.len(),
                updated.min_approvals
            )),
        )
        .await;
        crate::audit::record_consent(
            &state.audit_ks,
            "consent.granted",
            &updated.requester_did,
            &updated.type_uri,
            "success",
            Some(&format!(
                "digest={}; approvers={}",
                updated.digest,
                updated.approvals.join(",")
            )),
        )
        .await;
        // Nudge the requester that a grant is ready, so it re-submits at once
        // instead of polling. Best-effort — the grant is already durable; a lost
        // notice only costs the requester a poll cycle.
        super::consent_request::push_granted(
            state,
            &updated.requester_did,
            &updated.wire_digest,
            &updated.type_uri,
        )
        .await;
        return success_response(
            &doc,
            json!({
                "status": "granted",
                "payloadDigest": payload.payload_digest,
                "approvals": updated.approvals.len(),
            }),
        );
    }

    crate::audit::record_consent(
        &state.audit_ks,
        "consent.decision",
        &approver,
        &updated.type_uri,
        "success:approve_partial",
        Some(&format!(
            "digest={}; approvals={}/{}",
            updated.digest,
            updated.approvals.len(),
            updated.min_approvals
        )),
    )
    .await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_signing_test_app_state, seed_acl_entry};

    const OPENVTC: &str = "openvtc";
    const ADMIN_A: &str = "did:key:zAdminOpenvtc";
    const ADMIN_OTHER: &str = "did:key:zAdminElsewhere";
    const READER: &str = "did:key:zReaderOpenvtc";
    const STRANGER: &str = "did:key:zNotInAcl";

    /// A cross-context pending awaiting `min` approvals for `OPENVTC`.
    fn cross_context_pending(approvals: Vec<String>, min: u32) -> consent::PendingTaskConsent {
        consent::PendingTaskConsent {
            digest: "d".into(),
            wire_digest: "w".into(),
            type_uri: "https://…/dids/update/1.0".into(),
            requester_did: "did:key:zAgent".into(),
            approver_set: "openvtc-admins".into(),
            min_approvals: min,
            exclude_requester: true,
            challenge: "nonce".into(),
            approvals,
            state_pin: None,
            guards: Default::default(),
            subject_context: Some(OPENVTC.into()),
            requester_authorized: false,
            created_at: 0,
            expires_at: u64::MAX,
        }
    }

    #[tokio::test]
    async fn context_admin_approval_confers_the_context() {
        let (state, _dir) = build_signing_test_app_state().await;
        seed_acl_entry(&state.acl_ks, ADMIN_A, Role::Admin, vec![OPENVTC.into()]).await;

        let pending = cross_context_pending(vec![ADMIN_A.into()], 1);
        assert_eq!(
            compute_delegated_contexts(&state, &pending, 1000).await,
            vec![OPENVTC.to_string()],
            "an admin of the context confers it"
        );
    }

    #[tokio::test]
    async fn approval_from_admin_of_another_context_confers_nothing() {
        let (state, _dir) = build_signing_test_app_state().await;
        seed_acl_entry(
            &state.acl_ks,
            ADMIN_OTHER,
            Role::Admin,
            vec!["some-other-ctx".into()],
        )
        .await;

        let pending = cross_context_pending(vec![ADMIN_OTHER.into()], 1);
        assert!(
            compute_delegated_contexts(&state, &pending, 1000)
                .await
                .is_empty(),
            "an admin of a different context cannot delegate this one"
        );
    }

    #[tokio::test]
    async fn a_reader_of_the_context_confers_nothing() {
        // Attenuation: holding the context as a non-admin is not authority to delegate.
        let (state, _dir) = build_signing_test_app_state().await;
        seed_acl_entry(&state.acl_ks, READER, Role::Reader, vec![OPENVTC.into()]).await;

        let pending = cross_context_pending(vec![READER.into()], 1);
        assert!(
            compute_delegated_contexts(&state, &pending, 1000)
                .await
                .is_empty(),
            "a reader of the context is not an admin of it"
        );
    }

    #[tokio::test]
    async fn an_approver_absent_from_the_acl_confers_nothing() {
        let (state, _dir) = build_signing_test_app_state().await;
        let pending = cross_context_pending(vec![STRANGER.into()], 1);
        assert!(
            compute_delegated_contexts(&state, &pending, 1000)
                .await
                .is_empty(),
            "a signer with no ACL entry has no authority to delegate"
        );
    }

    #[tokio::test]
    async fn delegation_requires_meeting_the_threshold_with_context_admins() {
        // Two approvals required, but only one is a context-admin ⇒ no delegation.
        let (state, _dir) = build_signing_test_app_state().await;
        seed_acl_entry(&state.acl_ks, ADMIN_A, Role::Admin, vec![OPENVTC.into()]).await;
        seed_acl_entry(&state.acl_ks, READER, Role::Reader, vec![OPENVTC.into()]).await;

        let pending = cross_context_pending(vec![ADMIN_A.into(), READER.into()], 2);
        assert!(
            compute_delegated_contexts(&state, &pending, 1000)
                .await
                .is_empty(),
            "one context-admin cannot meet a threshold of two"
        );
    }

    #[tokio::test]
    async fn a_super_admin_approver_can_confer_any_context() {
        let (state, _dir) = build_signing_test_app_state().await;
        // Empty contexts + Admin role = super-admin (unrestricted).
        seed_acl_entry(&state.acl_ks, ADMIN_A, Role::Admin, vec![]).await;

        let pending = cross_context_pending(vec![ADMIN_A.into()], 1);
        assert_eq!(
            compute_delegated_contexts(&state, &pending, 1000).await,
            vec![OPENVTC.to_string()],
        );
    }

    #[tokio::test]
    async fn a_self_authorized_task_never_delegates() {
        let (state, _dir) = build_signing_test_app_state().await;
        seed_acl_entry(&state.acl_ks, ADMIN_A, Role::Admin, vec![OPENVTC.into()]).await;

        let mut pending = cross_context_pending(vec![ADMIN_A.into()], 1);
        pending.requester_authorized = true;
        assert!(
            compute_delegated_contexts(&state, &pending, 1000)
                .await
                .is_empty(),
            "the requester already held the context — nothing to delegate"
        );
    }

    #[tokio::test]
    async fn a_pure_approver_with_approve_scope_confers_without_admin() {
        // Fix 1: a least-privilege approver — a Reader that can act nowhere —
        // still confers the context through explicit `approve_scope`.
        let (state, _dir) = build_signing_test_app_state().await;
        let entry = crate::acl::AclEntry::new(ADMIN_A, Role::Reader, "did:key:zSetup")
            .with_approve_scope(crate::acl::ApproveScope::Contexts(vec![OPENVTC.into()]));
        crate::acl::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();

        let pending = cross_context_pending(vec![ADMIN_A.into()], 1);
        assert_eq!(
            compute_delegated_contexts(&state, &pending, 1000).await,
            vec![OPENVTC.to_string()],
            "a non-admin approver with approve authority still confers the context"
        );
    }

    #[tokio::test]
    async fn an_approve_all_approver_confers_any_context_without_admin() {
        let (state, _dir) = build_signing_test_app_state().await;
        let entry = crate::acl::AclEntry::new(ADMIN_A, Role::Reader, "did:key:zSetup")
            .with_approve_scope(crate::acl::ApproveScope::All);
        crate::acl::store_acl_entry(&state.acl_ks, &entry)
            .await
            .unwrap();

        let pending = cross_context_pending(vec![ADMIN_A.into()], 1);
        assert_eq!(
            compute_delegated_contexts(&state, &pending, 1000).await,
            vec![OPENVTC.to_string()],
        );
    }
}
