//! Issued-credential lifecycle trust-task slice
//! (`spec/vta/credentials/{issue,revoke,list}`).
//!
//! Mints a VTA-signed, scoped, time-boxed W3C Verifiable Credential to a holder
//! DID and revokes it by id. Distinct from the credential-vault slice
//! ([`super::cred_vault`]), which stores credentials the holder *holds*; here the
//! VTA is the issuer and signs the VC with its own `{vta_did}#key-0` key (see
//! [`crate::operations::credentials`]).
//!
//! Both handlers are:
//! - **Super-admin only**, through
//!   `operations::key_custody::require_instance_authority`, which audits a
//!   refusal. The credential is signed with the VTA's own `#key-0` over
//!   caller-chosen claims, so issuing or revoking one is the VTA speaking as
//!   itself. No context's authority covers that, and a role-only check let a
//!   context-scoped admin do it (see `docs/05-design-notes/key-custody.md`).
//! - **Step-up-gated** — operator AAL2 via [`super::step_up::require_step_up`]
//!   with the `credentials/issue` / `credentials/revoke` op-classes, the exact
//!   pattern `acl::handle_create` (`op::ACL_GRANT`) uses.
//! - **Audited** — `credentials.issue` / `credentials.revoke` via
//!   [`crate::audit::record`].

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use vta_sdk::protocols::credentials_issuance::{
    IssueCredentialBody, IssueCredentialResponse, IssueInContextBody, IssueInContextResponse,
    ListCredentialsBody, RevokeCredentialBody, RevokeCredentialResponse,
};

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::credentials::{self, IssueInContextParams, IssueParams};
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/credentials/issue/0.2`.
pub(super) async fn handle_issue(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    // 1. Authority gate (before the step-up gate, so a caller lacking it gets a
    //    permission error rather than a step-up prompt, the same ordering as
    //    `acl::handle_create`). Super-admin, not admin: the credential is signed
    //    with the VTA's own `#key-0` over caller-chosen claims for any holder, so
    //    it is the VTA vouching as itself, which no context's authority covers.
    //    A role-only check let a context-scoped admin mint VTA-signed VCs (key
    //    custody sweep after FTL-29904). The refusal is audited.
    if let Err(e) = crate::operations::key_custody::require_instance_authority(
        auth,
        "credentials.issue",
        &state.audit_sink,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
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
        &state.audit_sink,
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
            issued_at: Some(record.issued_at),
        },
    )
}

/// Handler for `spec/vta/credentials/issue-in-context/0.1`.
///
/// Deliberately **not** gated by [`require_instance_authority`]: that gate is
/// what makes `credentials/issue` unusable by a delegating agent, and the
/// reason behind it — the VTA vouching as *itself* with its own key — does not
/// apply here. This issues as the context's own DID with the context's own key,
/// so authority over the context is the authority the operation needs, and
/// [`credentials::issue_in_context`] enforces exactly that.
///
/// `credentials/issue` is untouched.
///
/// [`require_instance_authority`]: crate::operations::key_custody::require_instance_authority
pub(super) async fn handle_issue_in_context(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: IssueInContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let issued = match credentials::issue_in_context(
        state,
        auth,
        IssueInContextParams {
            context_id: &req.context_id,
            holder: &req.holder,
            claims: &req.claims,
            credential_type: req.credential_type.as_deref(),
            validity_seconds: req.validity_seconds,
            additional_contexts: &req.additional_contexts,
            expected_verification_method: req.expected_verification_method.as_deref(),
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if let Err(e) = audit::record_with_detail(
        &state.audit_sink,
        "credentials.issue-in-context",
        &auth.did,
        Some(&issued.record.id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        Some(&req.context_id),
        Some(&issued.verification_method),
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for credentials.issue-in-context");
    }

    success_response(
        &doc,
        IssueInContextResponse {
            credential_id: issued.record.id,
            credential: issued.record.credential,
            verification_method: issued.verification_method,
            issued_at: issued.record.issued_at,
            expires_at: issued.record.expires_at,
        },
    )
}

/// Handler for `spec/vta/credentials/revoke/0.1`.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    // Super-admin: revocation takes a VTA-issued credential out of force for
    // every relying party, whichever context asked for it to be issued.
    if let Err(e) = crate::operations::key_custody::require_instance_authority(
        auth,
        "credentials.revoke",
        &state.audit_sink,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
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
        &state.audit_sink,
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

/// Handler for `spec/vta/credentials/list/0.1`.
///
/// ## Why this is gated differently from its siblings
///
/// `issue` and `revoke` are super-admin plus a step-up floor, because each
/// changes what a holder can prove. This is a read, and it is gated on
/// `require_manage` — the same gate `acl::handle_list` uses for the equivalent
/// question about authority.
///
/// Admin-only would have been the easy consistency, and the wrong one: it would
/// mean an operator who may read the ACL and the policy set may not read what
/// their own agent has issued, which is the same category of question. A
/// step-up on a read would be worse still — a gate that fires on every page of
/// a list is a gate people learn to clear without reading.
///
/// What the read does disclose is real and is not a per-credential fact: the
/// response is a map of the issuer's holder set, and the *pattern* of issuance
/// can be sensitive where no single credential is. That is why the gate is here
/// at all rather than the task being open to any authenticated caller.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: ListCredentialsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let page = match credentials::list_issued(state, &req).await {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Audited like the mutating siblings. A read that maps the holder set is
    // worth a trail entry even though it changes nothing — "who enumerated the
    // issuance log, and when" is exactly the question an incident review asks,
    // and it cannot be answered afterwards if nothing recorded it.
    if let Err(e) = audit::record_with_detail(
        &state.audit_sink,
        "credentials.list",
        &auth.did,
        req.holder.as_deref(),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        None,
    )
    .await
    {
        tracing::warn!(error = %e, "audit record failed for credentials.list");
    }

    success_response(&doc, page)
}

#[cfg(any(test, feature = "test-support"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Role;
    use crate::test_support::{build_signing_test_app_state, super_admin_claims};
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vta_sdk::trust_tasks::{TASK_VTA_CREDENTIALS_ISSUE_0_2, TASK_VTA_CREDENTIALS_REVOKE_0_1};

    /// AAL2 (stepped-up) admin — passes both the capability + step-up gates.
    fn stepped_up_admin() -> AuthClaims {
        AuthClaims {
            acr: "aal2".to_string(),
            ..super_admin_claims()
        }
    }

    /// Build an `issue` trust-task document for the given payload.
    fn issue_doc(payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = TASK_VTA_CREDENTIALS_ISSUE_0_2.parse().expect("issue uri");
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

    /// Write a rule demanding step-up for `credentials/issue`, and turn
    /// enforcement on.
    ///
    /// This used to push an `[auth.step_up]` config floor. The floors are gone;
    /// an operator who wants issuance gated says so as a rule, which is what
    /// this now asserts still works. The rule allows at `aal2` explicitly — an
    /// abstaining policy default-denies, which would pass the assertion below
    /// for the wrong reason.
    async fn require_issue_step_up(state: &AppState) {
        const STEPUP_ISSUE: &str = "package vta.policy\nimport rego.v1\n\
            decision := {\"decision\": \"requireStepUp\"} if input.consumer.acr != \"aal2\"\n\
            decision := {\"decision\": \"allow\"} if input.consumer.acr == \"aal2\"";
        state.config.write().await.policy.enforcement = true;
        crate::policy::storage::store_policy(
            &state.policy_ks,
            &crate::policy::types::PolicyModule {
                id: "issue-stepup".into(),
                name: "issue-stepup".into(),
                description: None,
                module: STEPUP_ISSUE.into(),
                applies_to: vec![],
                priority: 0,
                enabled: true,
                version: 1,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                ext: Value::Null,
            },
        )
        .await
        .expect("store the step-up rule");
    }

    // Step-up is enforced by the central PDP gate, never inline in the handler.
    // This exercises the rule-driven step-up path through the gate for
    // credentials/issue.
    #[tokio::test]
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
            vta_sdk::trust_tasks::TASK_VTA_CREDENTIALS_ISSUE_0_2,
            &doc,
            &mut Vec::new(),
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

    // ─── `credentials/issue-in-context/0.1` ───────────────────────────────
    //
    // The property under test throughout: a caller holding *only* a context
    // can issue as that context's DID, and cannot reach anything else.

    const CTX: &str = "ctx1";

    fn issue_in_context_doc(payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = vta_sdk::trust_tasks::TASK_VTA_CREDENTIALS_ISSUE_IN_CONTEXT_0_1
            .parse()
            .expect("issue-in-context uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    /// An admin whose authority is confined to `context` — the caller the whole
    /// task exists for, and the one `super_admin_claims` cannot stand in for.
    fn context_scoped(context: &str) -> AuthClaims {
        crate::test_support::admin_claims_for_context(context)
    }

    /// Create `context` in the store. This state builder seeds no contexts, and
    /// every path under test resolves one.
    async fn seed_context(state: &AppState, context: &str, index: u32) {
        crate::contexts::store_context(
            &state.contexts_ks,
            &crate::contexts::ContextRecord {
                id: context.into(),
                name: context.into(),
                did: None,
                description: None,
                parent: None,
                base_path: format!("m/26'/2'/{index}'"),
                index,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                context_policy: None,
                issuer_key_id: None,
                proof_key_ids: Default::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("seed context {context}: {e:?}"));
    }

    /// Mint an Ed25519 key inside `context` and return `(key_id, public_key)`.
    async fn key_in_context(state: &AppState, context: &str) -> (String, String) {
        let created = crate::operations::keys::create_key(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.seed_store,
            &state.audit_sink,
            &state.acl_ks,
            &super_admin_claims(),
            crate::operations::keys::CreateKeyParams {
                key_type: vta_sdk::keys::KeyType::Ed25519,
                internal: false,
                derivation_path: None,
                key_id: None,
                mnemonic: None,
                label: None,
                context_id: Some(context.to_string()),
            },
            "test",
        )
        .await
        .expect("create a key in the context");
        (created.key_id, created.public_key)
    }

    /// Give `context` a DID and designate `key_id` as its issuer key.
    ///
    /// The DID is `did:key:<public multibase>` so the verification method the
    /// task resolves is one a `did:key` resolver really would resolve to this
    /// key — the test then verifies the proof against that key, which is the
    /// assertion that the credential is actually usable.
    async fn designate_issuer(state: &AppState, context: &str, key_id: &str, public_key: &str) {
        crate::operations::contexts::update_context(
            &state.contexts_ks,
            &super_admin_claims(),
            context,
            crate::operations::contexts::UpdateContextParams {
                name: None,
                did: Some(format!("did:key:{public_key}")),
                description: None,
                context_policy: None,
                issuer_key_id: None,
            },
            "test",
        )
        .await
        .expect("set the context DID");
        crate::operations::contexts::set_context_issuer_key(
            &state.contexts_ks,
            &state.keys_ks,
            &super_admin_claims(),
            context,
            Some(key_id.to_string()),
            None,
            "test",
        )
        .await
        .expect("designate the context issuer key");
    }

    /// A context with a DID and a designated issuer key. Returns the public
    /// multibase of that key.
    async fn context_ready_to_issue(state: &AppState, context: &str) -> String {
        seed_context(state, context, 1).await;
        let (key_id, public_key) = key_in_context(state, context).await;
        designate_issuer(state, context, &key_id, &public_key).await;
        public_key
    }

    fn body_of(out: &super::super::helpers::TrustTaskOutcome) -> String {
        String::from_utf8_lossy(&out.body).to_string()
    }

    #[tokio::test]
    async fn context_scoped_caller_issues_as_the_context_did_and_the_proof_verifies() {
        let (state, _dir) = build_signing_test_app_state().await;
        let public_key = context_ready_to_issue(&state, CTX).await;
        let issuer_did = format!("did:key:{public_key}");

        let out = handle_issue_in_context(
            &state,
            // Deliberately *not* a super-admin and *not* stepped up: the
            // premise of the task is that neither is required.
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "credentialType": "AgentIdentityCredential",
                "validitySeconds": 3600u64,
            })),
        )
        .await;
        assert!(
            out.status.is_success(),
            "a context-scoped caller must be able to issue: {}",
            body_of(&out)
        );

        let payload = response_payload(&out);
        let credential = &payload["credential"];

        assert_eq!(
            credential["issuer"], issuer_did,
            "the issuer must be the context's DID, not the VTA's"
        );
        assert_eq!(
            credential["credentialSubject"]["id"], "did:key:zHolderInContext",
            "the subject must be the requested holder"
        );
        assert_eq!(
            payload["verificationMethod"],
            format!("{issuer_did}#{public_key}"),
            "the response must echo the resolved verification method"
        );
        assert_eq!(
            credential["proof"]["verificationMethod"], payload["verificationMethod"],
            "the echoed verification method must be the one in the proof"
        );
        assert_eq!(credential["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(credential["proof"]["proofPurpose"], "assertionMethod");
        assert!(
            payload["issuedAt"].is_string() && payload["expiresAt"].is_string(),
            "the response must carry the validity window: {payload}"
        );

        // The assertion that matters: the proof verifies against the context's
        // issuer key. Everything above could hold on a credential nobody can
        // use.
        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(credential["proof"].clone()).expect("proof deserialises");
        let mut unsigned = credential.clone();
        unsigned
            .as_object_mut()
            .expect("credential is an object")
            .remove("proof");
        let (_base, public_bytes) =
            multibase::decode(&public_key).expect("public key is multibase");
        proof
            .verify_with_public_key(
                &unsigned,
                // Strip the two-byte Ed25519 multicodec prefix.
                &public_bytes[2..],
                affinidi_data_integrity::VerifyOptions::default(),
            )
            .expect("the proof must verify against the context's issuer key");
    }

    #[tokio::test]
    async fn a_caller_outside_the_context_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_issue(&state, CTX).await;

        let out = handle_issue_in_context(
            &state,
            &context_scoped("some-other-context"),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "validitySeconds": 3600u64,
            })),
        )
        .await;
        assert!(!out.status.is_success(), "a cross-context issue must fail");
        let body = body_of(&out);
        assert!(
            body.contains("not authorized in context"),
            "the refusal should name the context, got: {body}"
        );
    }

    #[tokio::test]
    async fn a_key_outside_the_context_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        // A context that designates a key belonging to a *different* context —
        // the shape a `#key-0` (no context at all) designation also takes.
        seed_context(&state, CTX, 1).await;
        seed_context(&state, "other-ctx", 77).await;
        let (foreign_key_id, foreign_public) = key_in_context(&state, "other-ctx").await;
        // Written straight to the record: `set_context_issuer_key` refuses this
        // designation at the point an operator makes it. Issuance must refuse
        // it too, because the record can also arrive from a restore or an
        // out-of-band edit — which is the check being tested.
        let mut record = crate::contexts::get_context(&state.contexts_ks, CTX)
            .await
            .expect("load the context")
            .expect("the context exists");
        record.did = Some(format!("did:key:{foreign_public}"));
        record.issuer_key_id = Some(foreign_key_id);
        crate::contexts::store_context(&state.contexts_ks, &record)
            .await
            .expect("write the cross-context designation");

        let out = handle_issue_in_context(
            &state,
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "validitySeconds": 3600u64,
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "signing with a key outside the context must fail"
        );
        let body = body_of(&out);
        assert!(
            body.contains("does not belong to context"),
            "the refusal should name the key separation, got: {body}"
        );
    }

    #[tokio::test]
    async fn a_context_with_no_designated_issuer_key_fails_closed() {
        let (state, _dir) = build_signing_test_app_state().await;
        // A DID but no designation: the VTA must not fall back to its own key.
        seed_context(&state, CTX, 1).await;
        crate::operations::contexts::update_context(
            &state.contexts_ks,
            &super_admin_claims(),
            CTX,
            crate::operations::contexts::UpdateContextParams {
                name: None,
                did: Some("did:key:zNoIssuerKeyHere".into()),
                description: None,
                context_policy: None,
                issuer_key_id: None,
            },
            "test",
        )
        .await
        .expect("set the context DID");

        let out = handle_issue_in_context(
            &state,
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "validitySeconds": 3600u64,
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "an undesignated context must fail"
        );
        let body = body_of(&out);
        assert!(
            body.contains("no designated issuer key"),
            "the refusal should be specific about the missing designation, got: {body}"
        );
    }

    #[tokio::test]
    async fn a_mismatched_expected_verification_method_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_issue(&state, CTX).await;

        let out = handle_issue_in_context(
            &state,
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "validitySeconds": 3600u64,
                "expectedVerificationMethod": "did:key:zSomethingElse#zSomethingElse",
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "a mismatched expectation must be refused, not signed with the other key"
        );
        let body = body_of(&out);
        assert!(
            body.contains("expectedVerificationMethod"),
            "the refusal should name the assertion that failed, got: {body}"
        );
    }

    #[tokio::test]
    async fn a_matching_expected_verification_method_issues_normally() {
        let (state, _dir) = build_signing_test_app_state().await;
        let public_key = context_ready_to_issue(&state, CTX).await;
        let expected = format!("did:key:{public_key}#{public_key}");

        let out = handle_issue_in_context(
            &state,
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "validitySeconds": 3600u64,
                "expectedVerificationMethod": expected,
            })),
        )
        .await;
        assert!(
            out.status.is_success(),
            "a matching expectation must issue normally: {}",
            body_of(&out)
        );
        assert_eq!(response_payload(&out)["verificationMethod"], expected);
    }

    #[tokio::test]
    async fn the_payload_accepts_no_key_id() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_issue(&state, CTX).await;

        let out = handle_issue_in_context(
            &state,
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "validitySeconds": 3600u64,
                "keyId": "any-key-at-all",
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "a caller-supplied keyId must be refused rather than ignored"
        );
    }

    /// A credential whose type defines its own terms needs the context that
    /// declares them. The issuer knows which one; the VTA carries it without
    /// resolving or interpreting it.
    #[tokio::test]
    async fn additional_contexts_are_carried_after_the_base_context() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_issue(&state, CTX).await;
        const AGENT_CTX: &str = "https://example.test/AgentIdentityCredentialV1.jsonld";

        let out = handle_issue_in_context(
            &state,
            &context_scoped(CTX),
            issue_in_context_doc(json!({
                "contextId": CTX,
                "holder": "did:key:zHolderInContext",
                "claims": { "role": "agent" },
                "credentialType": "AgentIdentityCredential",
                "validitySeconds": 3600u64,
                // The base context is repeated deliberately: echoing it would
                // make the credential non-conformant rather than more correct.
                "additionalContexts": ["https://www.w3.org/ns/credentials/v2", AGENT_CTX],
            })),
        )
        .await;
        assert!(out.status.is_success(), "{}", body_of(&out));

        let credential = response_payload(&out)["credential"].clone();
        assert_eq!(
            credential["@context"],
            json!(["https://www.w3.org/ns/credentials/v2", AGENT_CTX]),
            "the base context must come first and must not be duplicated"
        );
        assert_eq!(
            credential["type"],
            json!(["VerifiableCredential", "AgentIdentityCredential"])
        );
    }

    /// Designating a key from another context is refused where the operator
    /// makes the mistake, not only at the first issuance.
    #[tokio::test]
    async fn designating_a_foreign_key_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        seed_context(&state, CTX, 1).await;
        seed_context(&state, "foreign-ctx", 78).await;
        let (foreign_key_id, _) = key_in_context(&state, "foreign-ctx").await;

        let err = crate::operations::contexts::set_context_issuer_key(
            &state.contexts_ks,
            &state.keys_ks,
            &super_admin_claims(),
            CTX,
            Some(foreign_key_id.clone()),
            None,
            "test",
        )
        .await
        .err()
        .map(|e| format!("{e:?}"))
        .unwrap_or_else(|| panic!("designating `{foreign_key_id}` into `{CTX}` must be refused"));
        assert!(
            err.contains("does not belong to context"),
            "the refusal should name the residency rule, got: {err}"
        );
    }

    /// `credentials/issue` keeps its instance-authority gate — the new task
    /// must not have relaxed the old one on its way past.
    #[tokio::test]
    async fn credentials_issue_still_requires_instance_authority() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_issue(
            &state,
            &AuthClaims {
                acr: "aal2".to_string(),
                ..context_scoped(CTX)
            },
            issue_doc(json!({
                "holder": "did:key:zHolder",
                "claims": { "role": "member" },
                "validitySeconds": 3600u64,
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "a context-scoped caller must still not be able to issue as the VTA"
        );
    }
}
