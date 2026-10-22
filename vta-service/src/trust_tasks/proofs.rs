//! Trust Task handlers for server-built Data-Integrity proofs
//! (`spec/vta/proofs/attach/0.1`).
//!
//! Authorized **by context**, never by instance authority: the key is a
//! persisted key in the caller's own context, so authority over that context is
//! the authority the operation needs. See
//! [`crate::operations::context_signing`] for why the key is resolved rather
//! than named.

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use vta_sdk::protocols::proofs::{AttachProofBody, AttachProofResponse};

use crate::auth::AuthClaims;
use crate::operations::proofs::{self, AttachProofParams};
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// Handler for `spec/vta/proofs/attach/0.1`.
pub(super) async fn handle_attach(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> super::helpers::TrustTaskOutcome {
    let req: AttachProofBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match proofs::attach_proof(
        state,
        auth,
        AttachProofParams {
            context_id: &req.context_id,
            document: &req.document,
            proof_purpose: &req.proof_purpose,
            challenge: req.challenge.as_deref(),
            domain: req.domain.as_deref(),
            expected_verification_method: req.expected_verification_method.as_deref(),
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(proven) => success_response(
            &doc,
            AttachProofResponse {
                document: proven.document,
                verification_method: proven.verification_method,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_signing_test_app_state, super_admin_claims};
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vta_sdk::trust_tasks::TASK_PROOFS_ATTACH_0_1;

    const CTX: &str = "proof-ctx";

    fn attach_doc(payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = TASK_PROOFS_ATTACH_0_1.parse().expect("attach uri");
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn context_scoped(context: &str) -> AuthClaims {
        crate::test_support::admin_claims_for_context(context)
    }

    fn body_of(out: &super::super::helpers::TrustTaskOutcome) -> String {
        String::from_utf8_lossy(&out.body).to_string()
    }

    fn response_payload(out: &super::super::helpers::TrustTaskOutcome) -> Value {
        let doc: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        doc.get("payload").cloned().unwrap_or(Value::Null)
    }

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

    /// A context with a DID and an `authentication` proof key. Returns the
    /// public multibase of that key.
    ///
    /// The DID is `did:key:<public multibase>` so the verification method the
    /// task resolves really would resolve to this key.
    async fn context_ready_to_prove(state: &AppState, context: &str) -> String {
        seed_context(state, context, 5).await;
        let (key_id, public_key) = key_in_context(state, context).await;
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
            Some(key_id),
            Some("authentication"),
            "test",
        )
        .await
        .expect("designate the authentication proof key");
        public_key
    }

    fn a_presentation() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": "did:key:zHolder",
            "verifiableCredential": [],
        })
    }

    /// Verify `document`'s proof against `public_key` the way a standard DI
    /// verifier would. A proof that merely exists proves nothing.
    fn assert_proof_verifies(document: &Value, public_key: &str) {
        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(document["proof"].clone()).expect("proof deserialises");
        let mut unsigned = document.clone();
        unsigned
            .as_object_mut()
            .expect("document is an object")
            .remove("proof");
        let (_base, public_bytes) = multibase::decode(public_key).expect("multibase public key");
        proof
            .verify_with_public_key(
                &unsigned,
                // Strip the two-byte Ed25519 multicodec prefix.
                &public_bytes[2..],
                affinidi_data_integrity::VerifyOptions::default(),
            )
            .expect("the proof must verify against the context's key");
    }

    #[tokio::test]
    async fn a_context_scoped_caller_gets_a_proof_that_verifies() {
        let (state, _dir) = build_signing_test_app_state().await;
        let public_key = context_ready_to_prove(&state, CTX).await;
        let expected_vm = format!("did:key:{public_key}#{public_key}");

        let out = handle_attach(
            &state,
            // Not a super-admin: the whole point is that context authority is
            // enough.
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
            })),
        )
        .await;
        assert!(
            out.status.is_success(),
            "a context-scoped caller must get a proof: {}",
            body_of(&out)
        );

        let payload = response_payload(&out);
        let document = &payload["document"];
        assert_eq!(payload["verificationMethod"], expected_vm);
        assert_eq!(document["proof"]["verificationMethod"], expected_vm);
        assert_eq!(document["proof"]["proofPurpose"], "authentication");
        assert_eq!(document["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(
            document["holder"], "did:key:zHolder",
            "the document must come back intact"
        );
        assert_proof_verifies(document, &public_key);
    }

    #[tokio::test]
    async fn a_proof_purpose_outside_the_allow_list_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_prove(&state, CTX).await;

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "capabilityDelegation",
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "an unlisted proof purpose must be refused"
        );
        let body = body_of(&out);
        assert!(
            body.contains("is not one of"),
            "the refusal should name the allow-list, got: {body}"
        );
    }

    #[tokio::test]
    async fn a_caller_outside_the_context_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_prove(&state, CTX).await;

        let out = handle_attach(
            &state,
            &context_scoped("somewhere-else"),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
            })),
        )
        .await;
        assert!(!out.status.is_success(), "a cross-context proof must fail");
        assert!(
            body_of(&out).contains("not authorized in context"),
            "the refusal should name the context"
        );
    }

    #[tokio::test]
    async fn a_key_outside_the_context_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_prove(&state, CTX).await;
        seed_context(&state, "elsewhere", 6).await;
        let (foreign_key_id, _) = key_in_context(&state, "elsewhere").await;

        // Written straight to the record: `set_context_issuer_key` refuses this
        // at designation time. Signing must refuse it too, because a record can
        // also arrive from a restore or an out-of-band edit — which is the
        // check under test, and what keeps the VTA's context-less `#key-0` out
        // of reach.
        let mut record = crate::contexts::get_context(&state.contexts_ks, CTX)
            .await
            .expect("load the context")
            .expect("the context exists");
        record
            .proof_key_ids
            .insert("authentication".into(), foreign_key_id);
        crate::contexts::store_context(&state.contexts_ks, &record)
            .await
            .expect("write the cross-context designation");

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "signing with a key outside the context must fail"
        );
        assert!(
            body_of(&out).contains("does not belong to context"),
            "the refusal should name the key separation"
        );
    }

    #[tokio::test]
    async fn a_context_with_no_key_for_that_purpose_fails_closed() {
        let (state, _dir) = build_signing_test_app_state().await;
        // Designated for `authentication` only — `assertionMethod` has neither
        // an explicit proof key nor an issuer key to fall back to.
        context_ready_to_prove(&state, CTX).await;

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "assertionMethod",
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "an undesignated purpose must fail closed rather than reach for another key"
        );
        let body = body_of(&out);
        assert!(
            body.contains("no designated key for proof purpose"),
            "the refusal should be specific about the missing designation, got: {body}"
        );
    }

    /// `assertionMethod` resolves to the context's issuer key when no explicit
    /// proof key is designated — that *is* the context's assertion key, and
    /// naming it twice would let the two disagree.
    #[tokio::test]
    async fn assertion_method_falls_back_to_the_issuer_key() {
        let (state, _dir) = build_signing_test_app_state().await;
        let public_key = context_ready_to_prove(&state, CTX).await;
        let issuer_key_id = crate::contexts::get_context(&state.contexts_ks, CTX)
            .await
            .expect("load the context")
            .expect("the context exists")
            .proof_key_ids
            .get("authentication")
            .expect("authentication key designated")
            .clone();
        crate::operations::contexts::set_context_issuer_key(
            &state.contexts_ks,
            &state.keys_ks,
            &super_admin_claims(),
            CTX,
            Some(issuer_key_id),
            None,
            "test",
        )
        .await
        .expect("designate the issuer key");

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "assertionMethod",
            })),
        )
        .await;
        assert!(
            out.status.is_success(),
            "assertionMethod should fall back to the issuer key: {}",
            body_of(&out)
        );
        assert_eq!(
            response_payload(&out)["verificationMethod"],
            format!("did:key:{public_key}#{public_key}")
        );
    }

    #[tokio::test]
    async fn a_mismatched_expected_verification_method_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_prove(&state, CTX).await;

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
                "expectedVerificationMethod": "did:key:zOther#zOther",
            })),
        )
        .await;
        assert!(
            !out.status.is_success(),
            "a mismatched expectation must be refused, not signed with the other key"
        );
        assert!(
            body_of(&out).contains("expectedVerificationMethod"),
            "the refusal should name the assertion that failed"
        );
    }

    #[tokio::test]
    async fn a_matching_expected_verification_method_signs_normally() {
        let (state, _dir) = build_signing_test_app_state().await;
        let public_key = context_ready_to_prove(&state, CTX).await;
        let expected = format!("did:key:{public_key}#{public_key}");

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
                "expectedVerificationMethod": expected,
            })),
        )
        .await;
        assert!(
            out.status.is_success(),
            "a matching expectation must sign normally: {}",
            body_of(&out)
        );
        assert_eq!(response_payload(&out)["verificationMethod"], expected);
    }

    /// The caller supplies a *document*, never pre-framed bytes, and no key id.
    #[tokio::test]
    async fn the_payload_accepts_neither_a_key_id_nor_raw_bytes() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_prove(&state, CTX).await;

        for (member, value) in [("keyId", json!("any-key")), ("payload", json!("QUJD"))] {
            let mut payload = json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
            });
            payload
                .as_object_mut()
                .expect("object")
                .insert(member.to_string(), value);
            let out = handle_attach(&state, &context_scoped(CTX), attach_doc(payload)).await;
            assert!(
                !out.status.is_success(),
                "`{member}` must be refused rather than ignored"
            );
        }
    }

    /// An inbound `proof` is dropped before the signing input is built. JCS
    /// canonicalization is presence-sensitive, so hashing a document that still
    /// carried one would produce a proof that verifies against nothing.
    #[tokio::test]
    async fn an_inbound_proof_is_replaced_not_nested() {
        let (state, _dir) = build_signing_test_app_state().await;
        let public_key = context_ready_to_prove(&state, CTX).await;

        let mut document = a_presentation();
        document.as_object_mut().expect("object").insert(
            "proof".into(),
            json!({ "type": "DataIntegrityProof", "proofValue": "zSomeoneElses" }),
        );

        let out = handle_attach(
            &state,
            &context_scoped(CTX),
            attach_doc(json!({
                "contextId": CTX,
                "document": document,
                "proofPurpose": "authentication",
            })),
        )
        .await;
        assert!(out.status.is_success(), "{}", body_of(&out));

        let signed = response_payload(&out)["document"].clone();
        assert_eq!(
            signed["proof"]["verificationMethod"],
            format!("did:key:{public_key}#{public_key}"),
            "the inbound proof must be replaced, not kept"
        );
        assert_proof_verifies(&signed, &public_key);
    }

    /// `challenge`/`domain` are refused rather than dropped: the cryptosuite in
    /// use carries neither member, so a proof claiming to be bound to one could
    /// not be, and returning one the caller believes is replay-bound is worse
    /// than refusing.
    #[tokio::test]
    async fn challenge_and_domain_are_refused_not_silently_dropped() {
        let (state, _dir) = build_signing_test_app_state().await;
        context_ready_to_prove(&state, CTX).await;

        for (member, value) in [("challenge", "nonce-1"), ("domain", "https://verifier")] {
            let mut payload = json!({
                "contextId": CTX,
                "document": a_presentation(),
                "proofPurpose": "authentication",
            });
            payload
                .as_object_mut()
                .expect("object")
                .insert(member.to_string(), json!(value));
            let out = handle_attach(&state, &context_scoped(CTX), attach_doc(payload)).await;
            assert!(
                !out.status.is_success(),
                "`{member}` must be refused rather than silently dropped"
            );
            assert!(
                body_of(&out).contains("not supported"),
                "the refusal should say why"
            );
        }
    }
}
