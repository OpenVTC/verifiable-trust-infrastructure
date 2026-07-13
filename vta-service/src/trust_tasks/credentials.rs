//! Issued-credential lifecycle trust-task slice
//! (`spec/vta/credentials/{issue,revoke}/0.1`).
//!
//! Mints a VTA-signed, scoped, time-boxed W3C Verifiable Credential to a holder
//! DID and revokes it by id. Distinct from the credential-vault slice
//! ([`super::cred_vault`]), which stores credentials the holder *holds*; here the
//! VTA is the issuer and signs the VC with its own `{vta_did}#key-0` key (see
//! [`crate::operations::credentials`]).
//!
//! Both handlers are:
//! - **Capability-gated** — Admin role required ([`AuthClaims::require_admin`]),
//!   mirroring the role check the sibling ACL/keys handlers run before their
//!   step-up gate. Issuing or revoking a credential is a higher-trust action
//!   than ACL management, so it's Admin-only (not Admin-or-Initiator).
//! - **Step-up-gated** — operator AAL2 via [`super::step_up::require_step_up`]
//!   with the `credentials/issue` / `credentials/revoke` op-classes, the exact
//!   pattern `acl::handle_create` (`op::ACL_GRANT`) uses.
//! - **Audited** — `credentials.issue` / `credentials.revoke` via
//!   [`crate::audit::record`].

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use vta_sdk::protocols::credentials_issuance::{
    IssueCredentialBody, IssueCredentialResponse, RevokeCredentialBody, RevokeCredentialResponse,
};

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::credentials::{self, IssueParams};
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/credentials/issue/0.1`.
pub(super) async fn handle_issue(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    // 1. Capability gate (before the step-up gate, so a caller lacking the role
    //    gets a permission error rather than a step-up prompt — same ordering as
    //    `acl::handle_create`).
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // 2. Operator step-up (credentials/issue floor) — enforced centrally by the PDP gate.
    // 3. Parse the request body.
    let req: IssueCredentialBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // 4. Mint + store the credential.
    let record = match credentials::issue_credential(
        state,
        IssueParams {
            holder: &req.holder,
            claims: &req.claims,
            credential_type: req.credential_type.as_deref(),
            validity_seconds: req.validity_seconds,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // 5. Audit (`detail` carries the operator-supplied purpose, like the vault
    //    slice records its `reason`).
    if let Err(e) = audit::record_with_detail(
        &state.audit_ks,
        "credentials.issue",
        &auth.did,
        Some(&record.id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        req.purpose.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for credentials.issue");
    }

    success_response(
        &doc,
        IssueCredentialResponse {
            credential_id: record.id,
            credential: record.credential,
            expires_at: record.expires_at,
        },
    )
}

/// Handler for `spec/vta/credentials/revoke/0.1`.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (credentials/revoke floor) is enforced centrally by the PDP gate.
    let req: RevokeCredentialBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let revoked_at = match credentials::revoke_credential(
        state,
        &req.credential_id,
        req.reason.as_deref(),
    )
    .await
    {
        Ok(ts) => ts,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(e) = audit::record_with_detail(
        &state.audit_ks,
        "credentials.revoke",
        &auth.did,
        Some(&req.credential_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        req.reason.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for credentials.revoke");
    }

    success_response(
        &doc,
        RevokeCredentialResponse {
            credential_id: req.credential_id,
            revoked_at,
        },
    )
}

#[cfg(any(test, feature = "test-support"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::test_support::{build_signing_test_app_state, super_admin_claims};
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vta_sdk::trust_tasks::{TASK_VTA_CREDENTIALS_ISSUE_0_1, TASK_VTA_CREDENTIALS_REVOKE_0_1};

    /// AAL2 (stepped-up) admin — passes both the capability + step-up gates.
    fn stepped_up_admin() -> AuthClaims {
        AuthClaims {
            acr: "aal2".to_string(),
            ..super_admin_claims()
        }
    }

    /// Build an `issue` trust-task document for the given payload.
    fn issue_doc(payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = TASK_VTA_CREDENTIALS_ISSUE_0_1.parse().expect("issue uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn revoke_doc(payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = TASK_VTA_CREDENTIALS_REVOKE_0_1.parse().expect("revoke uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    /// Extract the `payload` object of a success response document.
    fn response_payload(out: &super::super::helpers::TrustTaskOutcome) -> Value {
        let doc: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        doc.get("payload").cloned().unwrap_or(Value::Null)
    }

    /// Configure a `credentials/issue` step-up floor (self-approve, AAL2) on the
    /// state's policy so an AAL1 session is gated. Without an operator floor the
    /// gate is a no-op (step-up is opt-in, mirroring the ACL/keys handlers).
    async fn require_issue_step_up(state: &AppState) {
        use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
        let mut cfg = state.config.write().await;
        cfg.auth.step_up.enabled = true;
        cfg.auth.step_up.floors.push(StepUpFloor {
            operation: super::super::step_up::op::CREDENTIALS_ISSUE.to_string(),
            mode: StepUpMode::SelfApprove,
            allow_aal1_if_non_escalating: false,
        });
    }

    // Step-up is now enforced by the central PDP gate, not inline in the
    // handler (the inline require_step_up was removed). This exercises the
    // config-floor step-up path through the gate for credentials/issue.
    #[tokio::test]
    #[allow(deprecated)]
    async fn issue_at_aal1_is_rejected_by_the_gate() {
        let (state, _dir) = build_signing_test_app_state().await;
        require_issue_step_up(&state).await;
        // AAL1 admin (acr empty) — capability passes, step-up gate must fire.
        let auth = super_admin_claims();
        let doc = issue_doc(json!({
            "holder": "did:key:zHolder",
            "claims": { "role": "member" },
            "validitySeconds": 3600u64,
        }));
        let out = super::super::policy_gate::policy_gate(
            &state,
            &auth,
            vta_sdk::trust_tasks::TASK_VTA_CREDENTIALS_ISSUE_0_1,
            &doc,
        )
        .await
        .expect("the credentials/issue floor must reject an AAL1 caller at the gate");
        assert!(!out.status.is_success(), "got {}", out.status);
        let body = String::from_utf8_lossy(&out.body);
        assert!(
            body.contains("step_up_required"),
            "rejection should carry the step-up code, got: {body}"
        );
    }

    #[tokio::test]
    async fn issue_non_admin_is_rejected() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = AuthClaims {
            role: Role::Reader,
            acr: "aal2".to_string(),
            ..super_admin_claims()
        };
        let doc = issue_doc(json!({
            "holder": "did:key:zHolder",
            "claims": { "role": "member" },
            "validitySeconds": 3600u64,
        }));
        let out = handle_issue(&state, &auth, doc).await;
        assert!(
            !out.status.is_success(),
            "non-admin issue must be rejected by the capability gate"
        );
    }

    #[tokio::test]
    async fn issue_with_step_up_succeeds_and_binds_holder() {
        let (state, _dir) = build_signing_test_app_state().await;
        let holder = "did:key:zHolderBindMe";
        let doc = issue_doc(json!({
            "holder": holder,
            "claims": { "role": "member", "level": 2 },
            "credentialType": "MembershipCredential",
            "validitySeconds": 3600u64,
            "purpose": "tier-2 access",
        }));
        let out = handle_issue(&state, &stepped_up_admin(), doc).await;
        assert!(out.status.is_success(), "stepped-up issue should succeed");
        let payload = response_payload(&out);
        let cred_id = payload
            .get("credentialId")
            .and_then(Value::as_str)
            .expect("credentialId present");
        assert!(
            cred_id.starts_with("urn:uuid:"),
            "id is a urn:uuid: {cred_id}"
        );
        let credential = payload.get("credential").expect("credential present");
        // The signed VC binds the holder as the subject.
        assert_eq!(
            credential
                .get("credentialSubject")
                .and_then(|s| s.get("id"))
                .and_then(Value::as_str),
            Some(holder),
            "credentialSubject.id must equal the holder DID"
        );
        // And it carries a Data-Integrity proof + the extra type.
        assert!(credential.get("proof").is_some(), "VC has a proof");
        let types: Vec<&str> = credential
            .get("type")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert!(types.contains(&"VerifiableCredential"));
        assert!(types.contains(&"MembershipCredential"));
    }

    #[tokio::test]
    async fn revoke_known_id_succeeds_then_double_revoke_conflicts() {
        let (state, _dir) = build_signing_test_app_state().await;
        // Issue first.
        let issue_out = handle_issue(
            &state,
            &stepped_up_admin(),
            issue_doc(json!({
                "holder": "did:key:zHolder",
                "claims": { "role": "member" },
                "validitySeconds": 3600u64,
            })),
        )
        .await;
        assert!(issue_out.status.is_success());
        let cred_id = response_payload(&issue_out)
            .get("credentialId")
            .and_then(Value::as_str)
            .expect("credentialId")
            .to_string();

        // Revoke it.
        let revoke_out = handle_revoke(
            &state,
            &stepped_up_admin(),
            revoke_doc(json!({ "credentialId": cred_id, "reason": "policy change" })),
        )
        .await;
        assert!(
            revoke_out.status.is_success(),
            "first revoke should succeed"
        );
        assert!(
            response_payload(&revoke_out).get("revokedAt").is_some(),
            "revoke response carries revokedAt"
        );

        // Revoke again → already_revoked (Conflict).
        let again = handle_revoke(
            &state,
            &stepped_up_admin(),
            revoke_doc(json!({ "credentialId": cred_id })),
        )
        .await;
        assert!(!again.status.is_success(), "double revoke must be rejected");
        let body = String::from_utf8_lossy(&again.body);
        assert!(
            body.contains("already revoked"),
            "second revoke should report already-revoked, got: {body}"
        );
    }

    #[tokio::test]
    async fn revoke_unknown_id_is_not_found() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_revoke(
            &state,
            &stepped_up_admin(),
            revoke_doc(json!({ "credentialId": "urn:uuid:does-not-exist" })),
        )
        .await;
        assert!(!out.status.is_success(), "unknown id must be rejected");
        let body = String::from_utf8_lossy(&out.body);
        assert!(
            body.contains("not found"),
            "unknown id should report not-found, got: {body}"
        );
    }
}
