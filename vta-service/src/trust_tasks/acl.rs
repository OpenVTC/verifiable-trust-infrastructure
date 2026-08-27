//! ACL slice trust-task handlers.
//!
//! Mirrors the legacy REST `/acl/*` routes one-for-one. Auth: Admin or
//! Initiator for list/create/get/delete; Admin-only for update.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::acl_management::change_role::ChangeRoleBody;
use vta_sdk::protocols::acl_management::create::CreateAclBody;
use vta_sdk::protocols::acl_management::delete::DeleteAclBody;
use vta_sdk::protocols::acl_management::get::GetAclBody;
use vta_sdk::protocols::acl_management::list::ListAclBody;
use vta_sdk::protocols::acl_management::swap::SwapKeyBody;
use vta_sdk::protocols::acl_management::update::UpdateAclBody;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};

/// Handler for `acl/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: ListAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // `list_entries`, not `list_acl`: the canonical `acl/list/0.1` response is
    // the `{entries, truncated, cursor, redactedFields}` wrapper over the
    // shared `AclEntry`, not the legacy bare array of flat rows (#857).
    match operations::acl::list_entries(
        &state.acl_ks,
        auth,
        req.scope.as_deref(),
        req.direction.unwrap_or_default(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `acl/grant/0.1`.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (acl/grant floor) is enforced centrally by the PDP gate.
    let req: CreateAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::grant_from_entry(
        &state.acl_ks,
        &state.audit_sink,
        &state.contexts_ks,
        auth,
        req.entry,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `acl/show/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: GetAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // `show_by_subject`, not `get_acl`: canonical `acl/show/0.1` responds with
    // the `{entry, redactedFields}` wrapper, not the legacy flat row (#857).
    match operations::acl::show_by_subject(&state.acl_ks, auth, &req.subject, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `acl/update/0.1`. Admin-only — matches the
/// legacy REST `PATCH /acl/{did}` policy.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (acl/change-role floor) is enforced centrally by the PDP gate.
    let req: UpdateAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Role transitions live in `acl/change-role`, not here.
    let role = None;
    match operations::acl::update_from_params(
        &state.acl_ks,
        &state.audit_sink,
        &state.contexts_ks,
        auth,
        &req.did,
        operations::acl::UpdateAclParams {
            role,
            label: req.label.clone(),
            allowed_contexts: req.allowed_contexts.clone(),
            step_up_approver: req.step_up_approver(),
            step_up_require: req.step_up_require(),
            approve_scope: req.approve_scope(),
            expires_at: req
                .expires_at
                .map(vta_sdk::protocols::acl_management::entry::to_epoch),
            reason: req.reason.clone(),
            allowed_keys: req
                .allowed_keys
                .clone()
                .map(|r| r.map(|keys| keys.into_iter().collect())),
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `acl/change-role/0.1`. Admin-only.
///
/// Separate task from `acl/update` because the transition is
/// compare-and-swapped against `fromRole` — see
/// [`operations::acl::change_role`].
pub(super) async fn handle_change_role(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: ChangeRoleBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::change_role_by_subject(
        &state.acl_ks,
        &state.audit_sink,
        auth,
        &req.subject,
        &req.from_role,
        &req.to_role,
        req.reason.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        // Canonical `acl/change-role/0.1` responds with the realized entry
        // under `entry`, like the rest of the family (#857).
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `acl/revoke/0.1`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (acl/revoke floor) is enforced centrally by the PDP gate.
    let req: DeleteAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::revoke_by_subject(
        &state.acl_ks,
        &state.audit_sink,
        auth,
        &req.subject,
        req.scopes,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for the canonical `acl/swap-key/0.1` Trust Task — self-service
/// rotation of the caller's own ACL entry onto a new subject DID. Consolidates
/// the bespoke REST `/acl/swap` handler and the DIDComm `handle_swap_acl` onto
/// the shared dispatcher (so it works over REST, DIDComm, and TSP identically).
///
/// No `require_manage()`: the caller only moves their own grant. The
/// transport-authenticated sender (REST bearer / DIDComm authcrypt / TSP VID)
/// is bound to `currentSubject`; the `link_proof` VP-JWT proves control of
/// `newSubject`.
pub(super) async fn handle_swap_key(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: SwapKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // `linkProof` is optional at the framework level and required by this
    // deployment. Refused by name rather than as a parse failure: the document
    // is well-formed, and telling a producer its shape is wrong sends it to
    // re-read the schema, which will agree with the producer.
    let Some(link_proof) = req.link_proof.clone() else {
        return reject_with(
            &doc,
            RejectReason::TaskFailed {
                reason: "acl:link_proof_required — this maintainer requires a `linkProof` \
                         proving the new subject consents to the takeover"
                    .to_string(),
                details: None,
            },
        );
    };

    // The authenticated caller must equal the declared currentSubject — stops a
    // sender from claiming to rotate someone else's entry.
    if req.current_subject != auth.did {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!(
                    "acl/swap-key: currentSubject {} does not equal authenticated caller {}",
                    req.current_subject, auth.did
                ),
            },
        );
    }

    // No inline step-up check. This handler used to resolve the `acl/swap-key`
    // config floor itself, passing the non-escalation carve-out — swap-key
    // being self-service rotation of the caller's own entry — so that a floor
    // with `allow_aal1_if_non_escalating` still admitted an AAL1
    // sender-authenticated transport.
    //
    // The floors are retired, and with them the carve-out: it existed to let a
    // blunt, op-class-keyed floor make an exception a rule can simply not
    // make in the first place. An operator who wants rotation gated writes a
    // rule naming `acl/swap-key/0.1`, and [`super::policy_gate`] enforces it
    // before this handler is reached — on every transport.
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(v) => v,
        None => {
            return app_error_to_reject(&doc, AppError::Internal("VTA DID not configured".into()));
        }
    };

    match operations::acl::swap_acl(
        &state.acl_ks,
        &state.audit_sink,
        auth,
        &link_proof,
        did_resolver,
        &vta_did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(result) => {
            // Cross-check the declared newSubject matches the VP holder the
            // operation actually verified (defence-in-depth over the proof).
            if req.new_subject != result.did {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!(
                            "acl/swap-key: newSubject {} does not match verified VP holder {}",
                            req.new_subject, result.did
                        ),
                    },
                );
            }
            // Canonical `acl/swap-key/0.1` responds with the realized entry
            // plus the swapped-out `previousSubject` (#857).
            success_response(
                &doc,
                vta_sdk::protocols::acl_management::swap::SwapKeyResultBody {
                    entry: vta_sdk::protocols::acl_management::entry::AclEntry::from_result(
                        &result,
                    ),
                    previous_subject: req.current_subject.clone(),
                },
            )
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::protocols::acl_management::entry::{Approve, StepUp};

    use trust_tasks_rs::specs::acl::change_role::v0_1 as canonical_change_role;
    use trust_tasks_rs::specs::acl::update::v0_1 as canonical_update;

    /// Our wire shapes must be the canonical ones, not merely bound to
    /// the canonical URIs. The generated types carry
    /// `deny_unknown_fields` and the spec's required set, so round-
    /// tripping our serialized form through them catches a member we
    /// named differently or one the spec forbids.
    #[test]
    fn change_role_conforms_and_update_carries_no_role() {
        let change = ChangeRoleBody {
            subject: "did:key:z6MkSubject".into(),
            from_role: "reader".into(),
            to_role: "application".into(),
            reason: Some("promoted".into()),
        };
        let json = serde_json::to_value(&change).expect("serialize");
        serde_json::from_value::<canonical_change_role::Payload>(json.clone())
            .unwrap_or_else(|e| panic!("not canonical `acl/change-role/0.1`: {e}\n{json:#}"));

        // What the role split established: `acl/update` carries no role, so
        // the only way to move one is the checked path above.
        let base = serde_json::to_value(update_body()).expect("serialize");
        assert!(
            base.get("role").is_none(),
            "acl/update must not carry a role: {base:#}"
        );
    }

    /// A fully-populated request body, so the round-trip exercises every
    /// member the type can emit — a partially-populated sample would let a
    /// non-canonical spelling of the omitted members through.
    fn update_body() -> UpdateAclBody {
        UpdateAclBody {
            did: "did:key:z6MkSubject".into(),
            label: Some("build agent".into()),
            allowed_contexts: Some(vec!["ctx-a".into(), "ctx-b".into()]),
            expires_at: Some(
                chrono::DateTime::parse_from_rfc3339("2027-01-15T08:00:00Z")
                    .expect("valid ts")
                    .to_utc(),
            ),
            reason: Some("quarterly access review".into()),
            step_up: Some(StepUp {
                approver: Some("did:key:z6MkApprover".into()),
                require: Some("delegated".into()),
            }),
            approve: Some(Approve {
                all: false,
                scopes: vec!["ctx-a".into()],
            }),
            // `allowedKeys` (#818) is published in `acl/update/0.1` as of
            // `trust-tasks-rs` 0.2.51, so the fully-populated sample carries
            // it. `Some(Some(..))` is the arm that emits an array; the
            // clear (`Some(None)` → explicit `null`) and leave-unchanged
            // (`None` → omitted) arms are pinned in `update.rs`'s own tests.
            allowed_keys: Some(Some(vec!["tenant-key-a".into()])),
        }
    }

    /// The #856 fix: `acl/update`'s request body is canonical, and the check
    /// has teeth. #842 repointed the URI onto the published spec — which
    /// switched schema validation on at the dispatch spine — while the body
    /// still emitted `did`/`allowedContexts`, so every conforming document
    /// (and every one we emitted) was rejected with `malformed_request`.
    #[test]
    fn update_body_is_canonical() {
        let json = serde_json::to_value(update_body()).expect("serialize");
        serde_json::from_value::<canonical_update::Payload>(json.clone())
            .unwrap_or_else(|e| panic!("not canonical `acl/update/0.1`: {e}\n{json:#}"));

        // Prove the assertion above can fail (#857's lesson: an assertion
        // that was passing for the wrong reason hid this exact defect for
        // three PRs). Reintroduce the pre-fix spelling and require rejection.
        let mut drifted = json.clone();
        let obj = drifted.as_object_mut().expect("object");
        let subject = obj.remove("subject").expect("subject is emitted");
        obj.insert("did".into(), subject);
        assert!(
            serde_json::from_value::<canonical_update::Payload>(drifted).is_err(),
            "`did` must be rejected by the canonical schema"
        );

        // And the historical flat members must be gone from the wire.
        for legacy in ["did", "allowedContexts", "stepUpApprover", "approveScope"] {
            assert!(
                json.get(legacy).is_none(),
                "legacy member `{legacy}` leaked onto the wire: {json:#}"
            );
        }

        // Round-trip back: what the canonical schema accepts, we parse.
        let ours: UpdateAclBody = serde_json::from_value(json).expect("parse our own wire form");
        assert_eq!(ours.did, "did:key:z6MkSubject");
        assert_eq!(ours.step_up_require().as_deref(), Some("delegated"));
        assert_eq!(
            ours.approve_scope(),
            Some(vta_sdk::acl::ApproveScope::Contexts(vec!["ctx-a".into()]))
        );
    }
}
