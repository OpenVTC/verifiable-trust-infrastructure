//! Keys slice trust-task handlers.
//!
//! Mirrors the legacy REST `/keys/*` routes. Auth: any authenticated
//! caller for list/get; admin for create/rename/revoke; write
//! (Application or higher) for sign.

use super::helpers::TrustTaskOutcome;

use base64::Engine as _;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::key_management::create::CreateKeyBody;
use vta_sdk::protocols::key_management::derive_and_sign::DeriveAndSignBody;
use vta_sdk::protocols::key_management::derive_and_sign_document::DeriveAndSignDocumentBody;
use vta_sdk::protocols::key_management::get::GetKeyBody;
use vta_sdk::protocols::key_management::import::{ImportKeyBody, ImportKeyResponseBody};
use vta_sdk::protocols::key_management::list::ListKeysBody;
use vta_sdk::protocols::key_management::rename::RenameKeyBody;
use vta_sdk::protocols::key_management::revoke::RevokeKeyBody;
use vta_sdk::protocols::key_management::secret::GetKeySecretBody;
use vta_sdk::protocols::key_management::sign::SignRequestBody;
use vta_sdk::protocols::key_management::sign::SigningDomain;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_declared, reject_with,
    success_response,
};

/// Handler for `keys/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListKeysBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::list_keys(
        &state.keys_ks,
        auth,
        operations::keys::ListKeysParams {
            offset: req.offset,
            limit: req.limit,
            status: req.status,
            context_id: req.context_id,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/create/0.1`. Gated on `KeyMint` in the operation
/// (`operations::keys::ensure_may_mint_key`), not on a role (Keyring VTI-23).
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CreateKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::create_key(
        &state.keys_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_sink,
        &state.acl_ks,
        auth,
        operations::keys::CreateKeyParams {
            internal: req.internal.unwrap_or(false),
            key_type: req.key_type,
            derivation_path: req.derivation_path,
            // Straight from the request. `keys/create/0.1` publishes `keyId` as
            // of `trust-tasks-rs` 0.12.1 (dtgwg-trust-tasks-tf#275), so the
            // binding no longer has to mint one for an internal key — which it
            // did between #1118 and this change, because an internal key has no
            // derivation path to be named after and the operation layer refuses
            // one without an id.
            //
            // `None` stays right for a derived key: the operation layer names
            // it after the derivation path.
            key_id: req.key_id,
            mnemonic: req.mnemonic,
            label: req.label,
            context_id: req.context_id,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        // Canonical `keys/create/0.1` answers the realized record under `key`,
        // like `keys/show` and `keys/import` — one record shape across the
        // family, so a consumer cannot end up holding two spellings of it.
        Ok(body) => success_response(
            &doc,
            vta_sdk::protocols::key_management::create::CreateKeyResponseBody { key: body },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/show/0.1`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::get_key(&state.keys_ks, auth, &req.key_id, TRANSPORT_TRUST_TASK).await {
        Ok(record) => success_response(
            &doc,
            vta_sdk::protocols::key_management::get::GetKeyResponseBody { key: Some(record) },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/rename/0.1`. Admin only.
pub(super) async fn handle_rename(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: RenameKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::rename_key(
        &state.keys_ks,
        &state.audit_sink,
        auth,
        &req.key_id,
        &req.new_key_id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/revoke/0.1`. Admin only.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (key/revoke floor) is enforced centrally by the PDP gate.
    let req: RevokeKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::revoke_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_sink,
        auth,
        &req.key_id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/set-exportability/0.1`.
///
/// Admin of the key's context to impose the restriction; strictly more than
/// that to lift it. The asymmetry lives in the operation rather than here,
/// because it depends on the key's *current* state — a handler-level gate would
/// have to demand the stronger authority for both directions, which would make
/// locking a key down as hard as unlocking it and so discourage the safe move.
pub(super) async fn handle_set_exportability(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: vta_sdk::protocols::key_management::set_exportability::SetKeyExportabilityBody =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
    match operations::keys::set_key_exportability(
        &state.keys_ks,
        &state.sessions_ks,
        &state.audit_sink,
        auth,
        &req.key_id,
        req.exportable,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(key) => success_response(
            &doc,
            vta_sdk::protocols::key_management::set_exportability::SetKeyExportabilityResultBody {
                key,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/export-secret/0.1`.
///
/// `KeyExport` **in the key's own scope** — both checked, with the internal-key
/// and non-exportable refusals and the durable audit row, inside
/// `operations::keys::get_key_secret`. The URI this replaces
/// (`vta/seeds/export-mnemonic/1.0`) demanded global Admin for the same act,
/// which handed a caller wanting one key authority over everything else.
///
/// Nothing is checked here. `GET /keys/{id}/secret` and DIDComm
/// `get-key-secret` reach the same operation, and the capability gate used to
/// live in this handler alone — so the other two transports released keys to
/// an admin narrowed without `key-export`. A check that lives in one handler is
/// a check the next transport forgets.
pub(super) async fn handle_export_secret(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetKeySecretBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::export_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        &req.key_id,
        export_channel(),
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        // The two refusals about the key carry the codes the task declares.
        // Only reachable once key-export, the channel and scope have all
        // passed, so they are said only to a caller entitled to the key.
        Err(operations::keys::KeyExportError::Refused(refusal, message)) => {
            match trust_tasks_rs::TrustTaskCode::new_extended("keys/export-secret", refusal.code())
            {
                Ok(code) => super::helpers::reject_with_code(&doc, code, message, None),
                Err(_) => app_error_to_reject(&doc, crate::error::AppError::Forbidden(message)),
            }
        }
        Err(operations::keys::KeyExportError::Other(e)) => app_error_to_reject(&doc, e),
    }
}

/// The [`operations::keys::ExportChannel`] for a key leaving over the Trust-Task
/// spine: end-to-end over DIDComm and TSP, hop-by-hop (and so refused) over
/// HTTPS. The channel names the binding, so each `key.secret_export` row says
/// which transport the key left over.
pub(super) fn export_channel() -> operations::keys::ExportChannel<'static> {
    let channel = super::transport::audit_channel();
    match super::transport::current() {
        super::transport::TransportConfidentiality::EndToEnd => {
            operations::keys::ExportChannel::EndToEnd(channel)
        }
        super::transport::TransportConfidentiality::HopByHop => {
            operations::keys::ExportChannel::HopByHop(channel)
        }
    }
}

/// Handler for `keys/sign/0.1`. Application-or-higher (write).
///
/// Decodes the base64url payload before invoking the signing oracle —
/// matches the legacy REST handler's behaviour. The signature in the
/// response is also base64url-encoded.
pub(super) async fn handle_sign(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let req: SignRequestBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&req.payload))
    {
        Ok(b) => b,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid base64url payload: {e}"),
                },
            );
        }
    };
    match operations::keys::sign_payload(
        &state.keys_ks,
        &state.imported_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        &req.key_id,
        &payload_bytes,
        &req.algorithm,
        // A payload from a task caller: the VTA cannot parse it.
        SigningDomain::Opaque,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/sign-sshsig/0.1` — git's SSH commit-signing format, signed
/// by a key that never leaves the VTA.
///
/// Parsed into the generated payload, answered with the generated response.
/// The two refusals the specification declares a code for are rendered with
/// it; every other refusal is the usual mapping.
pub(super) async fn handle_sign_sshsig(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use operations::keys::SshsigRefusal;
    use vta_sdk::protocols::key_management::sign::SignAlgorithm;
    use vta_sdk::protocols::key_management::sign_sshsig::{
        SignSshsigAlgorithm, SignSshsigPayload, SignSshsigResponse, SignSshsigResponseAlgorithm,
        digest_len, error_codes, hash_algorithm_name,
    };

    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let req: SignSshsigPayload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let invalid = |reason: String| reject_declared(&doc, error_codes::INVALID_ARGUMENT, reason);

    let (algorithm, response_algorithm) = match req.algorithm {
        SignSshsigAlgorithm::EdDsa => (SignAlgorithm::EdDSA, SignSshsigResponseAlgorithm::EdDsa),
        SignSshsigAlgorithm::Es256 => (SignAlgorithm::ES256, SignSshsigResponseAlgorithm::Es256),
        other => return invalid(format!("unsupported algorithm {other}")),
    };
    let (Some(hash_name), Some(hash_len)) = (
        hash_algorithm_name(&req.hash_algorithm),
        digest_len(&req.hash_algorithm),
    ) else {
        return invalid(format!("unsupported hashAlgorithm {}", req.hash_algorithm));
    };
    let message_hash =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(req.message_hash.as_str()) {
            Ok(b) => b,
            Err(e) => return invalid(format!("messageHash is not base64url: {e}")),
        };

    match operations::keys::sign_sshsig(
        &state.keys_ks,
        &state.imported_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        req.key_id.as_str(),
        &algorithm,
        req.namespace.as_str(),
        hash_name,
        hash_len,
        &message_hash,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => {
            let response = SignSshsigResponse::builder()
                .key_id(body.key_id)
                .algorithm(response_algorithm)
                .signature(body.signature);
            match SignSshsigResponse::try_from(response) {
                Ok(r) => success_response(&doc, r),
                Err(e) => reject_with(
                    &doc,
                    RejectReason::InternalError {
                        reason: format!("keys/sign-sshsig response: {e}"),
                    },
                ),
            }
        }
        Err(SshsigRefusal::KeyNotActive(m)) => {
            reject_declared(&doc, error_codes::FAILED_PRECONDITION, m)
        }
        Err(SshsigRefusal::InvalidArgument(m)) => invalid(m),
        Err(SshsigRefusal::App(e)) => app_error_to_reject(&doc, e),
    }
}

/// Render a [`operations::keys::ProtocolSignRefusal`] with the codes `slug`'s
/// specification declares. A missing key is `keys:notFound` — said only to a
/// super-admin, since for anyone else an absent key and one outside their
/// scope are the same refusal.
fn protocol_sign_refusal(
    doc: &TrustTask<Value>,
    refusal: operations::keys::ProtocolSignRefusal,
    codes: ProtocolSignCodes,
) -> TrustTaskOutcome {
    use operations::keys::ProtocolSignRefusal as R;
    use operations::sign_formats::FormatRefusal as F;
    match refusal {
        R::KeyNotActive(m) => reject_declared(doc, codes.failed_precondition, m),
        R::KeyTypeUnsupported(key_type) => super::helpers::reject_with_code(
            doc,
            declared_code(codes.key_type_unsupported),
            format!("a {key_type} key signs nothing this task produces"),
            Some(serde_json::json!({ "keyType": key_type.to_string() })),
        ),
        R::Format(F::HeaderMemberForbidden(member)) => super::helpers::reject_with_code(
            doc,
            declared_code(
                codes
                    .header_member_forbidden
                    .unwrap_or(codes.invalid_argument),
            ),
            format!("the custodian sets or refuses header member `{member}`"),
            Some(serde_json::json!({ "member": member })),
        ),
        R::Format(F::InvalidArgument(m)) => reject_declared(doc, codes.invalid_argument, m),
        R::Format(F::PayloadInvalid(m)) => reject_declared(
            doc,
            codes.payload_invalid.unwrap_or(codes.invalid_argument),
            m,
        ),
        R::Format(F::SubjectInvalid {
            member,
            index,
            reason,
        }) => {
            let mut details = serde_json::json!({ "member": member, "reason": reason });
            if let Some(i) = index {
                details["index"] = i.into();
            }
            super::helpers::reject_with_code(
                doc,
                declared_code(codes.subject_invalid.unwrap_or(codes.invalid_argument)),
                reason,
                Some(details),
            )
        }
        R::Format(F::ProofPresent) => reject_declared(
            doc,
            codes
                .document
                .map_or(codes.invalid_argument, |d| d.proof_present),
            "the document already carries a proof; this task makes a document's only proof"
                .to_string(),
        ),
        R::Format(F::DocumentInvalid(reason)) => super::helpers::reject_with_code(
            doc,
            declared_code(
                codes
                    .document
                    .map_or(codes.invalid_argument, |d| d.document_invalid),
            ),
            match reason {
                "noSigner" => "the document names its signer in neither issuer nor controller",
                "signerMalformed" => "the document names its signer in a form that is not a DID",
                _ => "the document holds a value RFC 8785 cannot serialise exactly",
            }
            .to_string(),
            Some(serde_json::json!({ "reason": reason })),
        ),
        R::Format(F::IssuerMismatch(member)) => super::helpers::reject_with_code(
            doc,
            declared_code(
                codes
                    .document
                    .map_or(codes.invalid_argument, |d| d.issuer_mismatch),
            ),
            format!(
                "the key is not a verification method of the DID the document's {member} names"
            ),
            Some(serde_json::json!({ "member": member })),
        ),
        R::Format(F::PurposeNotAuthorized(purpose)) => super::helpers::reject_with_code(
            doc,
            declared_code(
                codes
                    .document
                    .map_or(codes.invalid_argument, |d| d.purpose_not_authorized),
            ),
            format!("the signer DID does not list the key under {purpose}"),
            Some(serde_json::json!({ "proofPurpose": purpose })),
        ),
        R::App(crate::error::AppError::NotFound(m)) => reject_declared(doc, codes.not_found, m),
        R::App(e) => app_error_to_reject(doc, e),
    }
}

/// The codes only `keys/sign-document` declares.
#[derive(Clone, Copy)]
struct DocumentSignCodes {
    proof_present: trust_tasks_rs::DeclaredErrorCode,
    document_invalid: trust_tasks_rs::DeclaredErrorCode,
    issuer_mismatch: trust_tasks_rs::DeclaredErrorCode,
    purpose_not_authorized: trust_tasks_rs::DeclaredErrorCode,
}

/// The declared codes one protocol signing task renders its refusals with.
struct ProtocolSignCodes {
    not_found: trust_tasks_rs::DeclaredErrorCode,
    invalid_argument: trust_tasks_rs::DeclaredErrorCode,
    failed_precondition: trust_tasks_rs::DeclaredErrorCode,
    key_type_unsupported: trust_tasks_rs::DeclaredErrorCode,
    header_member_forbidden: Option<trust_tasks_rs::DeclaredErrorCode>,
    payload_invalid: Option<trust_tasks_rs::DeclaredErrorCode>,
    subject_invalid: Option<trust_tasks_rs::DeclaredErrorCode>,
    document: Option<DocumentSignCodes>,
}

fn declared_code(code: trust_tasks_rs::DeclaredErrorCode) -> trust_tasks_rs::TrustTaskCode {
    trust_tasks_rs::TrustTaskCode::Extended {
        slug: code.namespace().to_string(),
        local: code.local().to_string(),
    }
}

/// Handler for `keys/sign-jws/0.1` — a compact JWS from a key that never leaves
/// the VTA. Parsed into the generated payload, answered with the generated
/// response; every declared refusal is rendered with its code.
pub(super) async fn handle_sign_jws(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use operations::sign_formats::JwsPayload;
    use vta_sdk::protocols::key_management::sign_jws::{
        SignJwsAlg, SignJwsPayload, SignJwsResponse, error_codes,
    };

    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let req: SignJwsPayload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (key_id, header, payload) = match &req {
        SignJwsPayload::Variant0 {
            key_id,
            header,
            payload,
            ..
        } => (key_id.as_str(), header, JwsPayload::Json(payload)),
        SignJwsPayload::Variant1 {
            key_id,
            header,
            payload_base64_url,
            ..
        } => (
            key_id.as_str(),
            header,
            JwsPayload::Base64Url(payload_base64_url.as_str()),
        ),
        _ => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: "keys/sign-jws: unrecognised payload shape".into(),
                },
            );
        }
    };

    let signed = operations::keys::sign_jws(
        &state.keys_ks,
        &state.imported_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        key_id,
        header,
        payload,
        TRANSPORT_TRUST_TASK,
    )
    .await;
    match signed {
        Ok((jws, alg)) => {
            let response = (|| {
                SignJwsResponse::try_from(
                    SignJwsResponse::builder()
                        .key_id(key_id)
                        .alg(alg.parse::<SignJwsAlg>()?)
                        .jws(jws),
                )
            })();
            match response {
                Ok(r) => success_response(&doc, r),
                Err(e) => reject_with(
                    &doc,
                    RejectReason::InternalError {
                        reason: format!("keys/sign-jws response: {e}"),
                    },
                ),
            }
        }
        Err(refusal) => protocol_sign_refusal(
            &doc,
            refusal,
            ProtocolSignCodes {
                not_found: error_codes::NOT_FOUND,
                invalid_argument: error_codes::INVALID_ARGUMENT,
                failed_precondition: error_codes::FAILED_PRECONDITION,
                key_type_unsupported: error_codes::KEY_TYPE_UNSUPPORTED,
                header_member_forbidden: Some(error_codes::HEADER_MEMBER_FORBIDDEN),
                payload_invalid: Some(error_codes::PAYLOAD_INVALID),
                subject_invalid: None,
                document: None,
            },
        ),
    }
}

/// Handler for `keys/sign-csr/0.1` — a PKCS#10 certificate signing request for
/// a key that never leaves the VTA, built by the VTA from the structured
/// subject.
pub(super) async fn handle_sign_csr(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use vta_sdk::protocols::key_management::sign_csr::{
        SignCsrPayload, SignCsrResponse, error_codes,
    };

    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let req: SignCsrPayload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let signed = operations::keys::sign_csr(
        &state.keys_ks,
        &state.imported_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        req.key_id.as_str(),
        &req.subject,
        req.subject_alt_names.as_ref(),
        TRANSPORT_TRUST_TASK,
    )
    .await;
    // No `keys:invalidArgument` is declared for this task; a format refusal it
    // could reach would be a subject one.
    match signed {
        Ok((csr, public_key)) => {
            let response = SignCsrResponse::try_from(
                SignCsrResponse::builder()
                    .key_id(req.key_id.as_str())
                    .csr(csr)
                    .public_key(public_key),
            );
            match response {
                Ok(r) => success_response(&doc, r),
                Err(e) => reject_with(
                    &doc,
                    RejectReason::InternalError {
                        reason: format!("keys/sign-csr response: {e}"),
                    },
                ),
            }
        }
        Err(refusal) => protocol_sign_refusal(
            &doc,
            refusal,
            ProtocolSignCodes {
                not_found: error_codes::NOT_FOUND,
                invalid_argument: error_codes::SUBJECT_INVALID,
                failed_precondition: error_codes::FAILED_PRECONDITION,
                key_type_unsupported: error_codes::KEY_TYPE_UNSUPPORTED,
                header_member_forbidden: None,
                payload_invalid: None,
                subject_invalid: Some(error_codes::SUBJECT_INVALID),
                document: None,
            },
        ),
    }
}

/// Handler for `keys/sign-document/0.1` — an `eddsa-jcs-2022` proof over a
/// document that names its signer, from a key that never leaves the VTA. The
/// document is read as received: every member of it is signed as given.
pub(super) async fn handle_sign_document(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use vta_sdk::protocols::key_management::sign_document::{
        SignDocumentPayload, SignDocumentResponse, error_codes,
    };

    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let req: SignDocumentPayload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(document) = doc.payload.get("document").cloned() else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "keys/sign-document: no document".into(),
            },
        );
    };
    let text = |k: &str| doc.payload.get(k).and_then(Value::as_str);
    let signed = operations::keys::sign_document(
        &state.keys_ks,
        &state.imported_ks,
        &state.internal_ks,
        &state.contexts_ks,
        &state.acl_ks,
        &state.seed_store,
        &state.audit_sink,
        operations::persona::PersonaStores::from_state(state),
        state.did_resolver.as_ref(),
        auth,
        req.key_id.as_str(),
        &document,
        text("proofPurpose"),
        text("created"),
        text("challenge"),
        text("domain"),
        TRANSPORT_TRUST_TASK,
    )
    .await;
    match signed {
        Ok(s) => {
            let body = serde_json::json!({
                "keyId": req.key_id.as_str(),
                "signerDid": s.signer_did,
                "document": s.document,
                "proof": s.proof,
            });
            // Through the generated response, so an answer its schema refuses
            // is never sent — but sent as built: the document is the bytes the
            // proof covers.
            match serde_json::from_value::<SignDocumentResponse>(body.clone()) {
                Ok(_) => success_response(&doc, body),
                Err(e) => reject_with(
                    &doc,
                    RejectReason::InternalError {
                        reason: format!("keys/sign-document response: {e}"),
                    },
                ),
            }
        }
        Err(refusal) => protocol_sign_refusal(
            &doc,
            refusal,
            ProtocolSignCodes {
                not_found: error_codes::NOT_FOUND,
                invalid_argument: error_codes::INVALID_ARGUMENT,
                failed_precondition: error_codes::FAILED_PRECONDITION,
                key_type_unsupported: error_codes::KEY_TYPE_UNSUPPORTED,
                header_member_forbidden: None,
                payload_invalid: None,
                subject_invalid: None,
                document: Some(DocumentSignCodes {
                    proof_present: error_codes::PROOF_PRESENT,
                    document_invalid: error_codes::DOCUMENT_INVALID,
                    issuer_mismatch: error_codes::ISSUER_MISMATCH,
                    purpose_not_authorized: error_codes::PURPOSE_NOT_AUTHORIZED,
                }),
            },
        ),
    }
}

/// Handler for `keys/derive-and-sign/0.1`. Super-admin, path inside `m/26'/9'`: both
/// enforced, and the signature audited, in the operation (`vta_keys::custody`).
///
/// Ephemeral: derives at the requested BIP-32 path, signs, and returns the
/// signature + derived public key without persisting a key record.
pub(super) async fn handle_derive_and_sign(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeriveAndSignBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&req.payload))
    {
        Ok(b) => b,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid base64url payload: {e}"),
                },
            );
        }
    };
    match operations::keys::derive_and_sign(
        &state.keys_ks,
        &state.acl_ks,
        &state.seed_store,
        auth,
        &state.audit_sink,
        &req.key_type,
        &req.derivation_path,
        &payload_bytes,
        &req.algorithm,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/derive-and-sign-document/0.1`. Super-admin, path inside
/// `m/26'/9'`: enforced, and audited, in the operation.
///
/// Attaches an `eddsa-jcs-2022` Data-Integrity proof to the document, signed as
/// the key derived at the requested path — without persisting a key record.
pub(super) async fn handle_derive_and_sign_document(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeriveAndSignDocumentBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::derive_and_sign_document(
        &state.keys_ks,
        &state.acl_ks,
        &state.seed_store,
        auth,
        &state.audit_sink,
        &req.key_type,
        &req.derivation_path,
        req.document,
        req.proof_purpose.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `keys/import-wrapping-key/0.1`. Admin only — the authority
/// `keys/import` needs, since a wrapping key is useful for nothing else and
/// each one costs this agent memory until it expires.
///
/// Mints a fresh Ed25519 key pair per request and keeps only its X25519
/// counterpart, in memory, single-use, for 60 seconds
/// ([`vta_keys::wrapping::WrappingKeyCache`]). The public half goes back as a
/// `did:key` in this agent's signed response, which a producer must verify
/// before sealing to it: the transports that need a wrapping key are the ones
/// with an intermediary that could substitute its own. Replaces
/// `GET /keys/import/wrapping-key`, which returned an X25519 JWK unsigned, and
/// is reachable over every transport — over HTTPS it is what makes a key import
/// possible at all, since the cleartext carrier is refused there.
pub(super) async fn handle_import_wrapping_key(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::keys::import_wrapping_key::v0_1 as spec;
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    if let Err(resp) = parse_payload::<spec::Payload>(&doc) {
        return resp;
    }
    let key = state.wrapping_cache.generate().await;
    let body = serde_json::json!({
        "wrappingKey": key.public_did,
        "keyId": key.kid,
        "expiresAt": key.expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    // Through the generated type, so the `did:key:z6Mk…` pattern is checked on
    // the way out.
    match serde_json::from_value::<spec::Response>(body) {
        Ok(r) => success_response(&doc, r),
        Err(e) => reject_with(
            &doc,
            RejectReason::InternalError {
                reason: format!("wrapping key does not match its schema: {e}"),
            },
        ),
    }
}

/// Handler for `keys/import/0.1`. Admin only.
///
/// **The cleartext `privateKeyMultibase` carrier is admitted only where the
/// transport established confidentiality end-to-end** — DIDComm authcrypt and
/// TSP, which seal to this VTA's own key. Over REST it is refused: TLS
/// terminates wherever the operator terminates it, and the plaintext exists
/// there.
///
/// This is the specification's own rule ("only where the transport is
/// end-to-end confidential") rather than the blanket refusal that stood in for
/// it while the spine discarded the transport before handlers ran. See
/// [`crate::trust_tasks::transport`].
pub(super) async fn handle_import(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: ImportKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if req.private_key_multibase.is_some()
        && crate::trust_tasks::transport::current()
            != crate::trust_tasks::transport::TransportConfidentiality::EndToEnd
    {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "keys/import: the cleartext `privateKeyMultibase` carrier needs a \
                         transport that is confidential end to end, and this request did not \
                         arrive on one — TLS terminates wherever the operator terminates it, so \
                         the key would exist in plaintext there. Seal the key to this VTA and \
                         send `privateKeySealed`, or send it over DIDComm or TSP."
                    .to_string(),
            },
        );
    }

    let private_key_bytes = if let Some(sealed) = req.private_key_sealed.as_deref() {
        match state.wrapping_cache.unwrap_sealed(sealed).await {
            Ok((sealed_type, bytes)) => {
                if sealed_type != req.key_type.to_string() {
                    return reject_with(
                        &doc,
                        RejectReason::MalformedRequest {
                            reason: format!(
                                "sealed keyType `{sealed_type}` does not match the request's                                  `{}`",
                                req.key_type
                            ),
                        },
                    );
                }
                bytes
            }
            Err(e) => return app_error_to_reject(&doc, e),
        }
    } else if let Some(jwe) = req.private_key_jwe.as_deref() {
        tracing::warn!("key import via legacy JWE carrier — prefer privateKeySealed");
        match state.wrapping_cache.unwrap_jwe(jwe).await {
            Ok(bytes) => bytes,
            Err(e) => return app_error_to_reject(&doc, e),
        }
    } else if let Some(mb) = req.private_key_multibase.as_deref() {
        // Only reachable on an end-to-end-confidential transport — the gate
        // above refused it otherwise. The key arrives multicodec-prefixed
        // (ed25519-priv `0x8026`); strip the prefix so the operation receives
        // the raw private key, exactly as the sealed and JWE carriers deliver.
        match multibase::decode(mb) {
            Ok((_, decoded)) => match decoded.len() {
                34 => decoded[2..].to_vec(),
                32 => decoded,
                other => {
                    return reject_with(
                        &doc,
                        RejectReason::MalformedRequest {
                            reason: format!(
                                "keys/import: `privateKeyMultibase` decoded to {other} bytes; \
                                 expected 32 raw or 34 multicodec-prefixed"
                            ),
                        },
                    );
                }
            },
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("keys/import: `privateKeyMultibase` is not multibase: {e}"),
                    },
                );
            }
        }
    } else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "keys/import: one of `privateKeySealed`, `privateKeyJwe` or \
                         `privateKeyMultibase` is required"
                    .to_string(),
            },
        );
    };

    match operations::keys::import_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        operations::keys::ImportKeyParams {
            key_type: req.key_type,
            private_key_bytes,
            label: req.label,
            context_id: req.context_id,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, ImportKeyResponseBody { key: body }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

#[cfg(test)]
mod key_export_tests {
    use super::*;
    use crate::acl::Role;
    use crate::test_support::build_signing_test_app_state;
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vti_common::acl::{AclEntry, Capability, store_acl_entry};

    fn claims(did: &str, role: Role) -> AuthClaims {
        AuthClaims {
            did: did.into(),
            role,
            allowed_contexts: vec!["acme".to_string()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    /// A key id that exists nowhere. The capability gate runs before the key
    /// is looked up, so a caller refused by the gate is told "denied", while a
    /// caller that passes it reaches the lookup and is told the key is absent.
    /// That difference is what these tests read.
    fn export_doc() -> TrustTask<Value> {
        let uri: TypeUri = vta_sdk::trust_tasks::TASK_KEYS_EXPORT_SECRET_0_1
            .parse()
            .expect("export-secret uri");
        TrustTask::new(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            uri,
            json!({ "keyId": "did:key:zNoSuchKey#key-0" }),
        )
    }

    fn refused_by_the_gate(out: &super::super::helpers::TrustTaskOutcome) -> bool {
        let doc: Value = serde_json::from_slice(&out.body).expect("response is JSON");
        doc.pointer("/payload/code").and_then(Value::as_str) == Some("permissionDenied")
    }

    /// Keyring VTI-23 / VTI-VTA-003: an initiator holds `Sign` and must not
    /// thereby export. It acts as a key through the signing oracle instead.
    #[tokio::test]
    async fn an_initiator_cannot_export_a_secret() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_export_secret(
            &state,
            &claims("did:key:zManager", Role::Initiator),
            export_doc(),
        )
        .await;
        assert!(
            refused_by_the_gate(&out),
            "an initiator must be refused at the KeyExport gate"
        );
    }

    /// An admin passes the gate — it derives `KeyExport` — and, over an
    /// end-to-end transport, reaches the lookup, which is what proves the
    /// refusal above was the capability and not some other check.
    #[tokio::test]
    async fn an_admin_passes_the_key_export_gate() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = super::super::transport::with_confidentiality(
            super::super::transport::TransportConfidentiality::EndToEnd,
            handle_export_secret(
                &state,
                &claims("did:key:zOperator", Role::Admin),
                export_doc(),
            ),
        )
        .await;
        // The key does not exist, so the lookup refuses it — as out of scope,
        // since an absent key and another context's key look alike to a
        // scoped caller. What matters is that the refusal is not the gate's.
        let body = String::from_utf8_lossy(&out.body);
        assert!(
            !body.contains("key-export capability"),
            "an admin derives KeyExport and must reach the key lookup: {body}"
        );
        assert!(body.contains("not within the caller's scope"), "{body}");
    }

    /// The two refusals about the key answer with the codes
    /// `keys/export-secret/0.1` declares, to a caller entitled to the key.
    #[tokio::test]
    async fn refusals_about_the_key_carry_the_declared_codes() {
        use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
        let (state, _dir) = build_signing_test_app_state().await;
        for (id, origin, exportable, code) in [
            (
                "k-locked",
                KeyOrigin::Derived,
                Some(false),
                "keys/export-secret:notExportable",
            ),
            (
                "k-inside",
                KeyOrigin::Internal,
                None,
                "keys/export-secret:neverExportable",
            ),
        ] {
            let now = chrono::Utc::now();
            state
                .keys_ks
                .insert(
                    crate::keys::store_key(id),
                    &KeyRecord {
                        key_id: id.into(),
                        derivation_path: "m/26'/0'/0'/0'".into(),
                        key_type: KeyType::Ed25519,
                        status: KeyStatus::Active,
                        public_key: "z6MkUnused".into(),
                        label: None,
                        context_id: None,
                        seed_id: None,
                        exportable,
                        origin,
                        created_at: now,
                        updated_at: now,
                    },
                )
                .await
                .unwrap();
            let uri: TypeUri = vta_sdk::trust_tasks::TASK_KEYS_EXPORT_SECRET_0_1
                .parse()
                .unwrap();
            let doc = TrustTask::new(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                uri,
                json!({ "keyId": id }),
            );
            let mut super_admin = claims("did:key:zRootAdmin", Role::Admin);
            super_admin.allowed_contexts.clear();
            let out = super::super::transport::with_confidentiality(
                super::super::transport::TransportConfidentiality::EndToEnd,
                handle_export_secret(&state, &super_admin, doc),
            )
            .await;
            let body: Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                body.pointer("/payload/code").and_then(Value::as_str),
                Some(code),
                "{body}"
            );
        }
    }

    /// `keys/export-secret/0.1` over the HTTPS binding is refused even for an
    /// entitled caller: TLS terminates wherever the operator terminates it, so
    /// the key would exist in plaintext there. The refusal names the fix.
    #[tokio::test]
    async fn an_export_over_https_is_refused_and_says_which_transports_work() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = super::super::transport::with_binding(
            "https",
            super::super::transport::with_confidentiality(
                super::super::transport::TransportConfidentiality::HopByHop,
                handle_export_secret(
                    &state,
                    &claims("did:key:zOperator", Role::Admin),
                    export_doc(),
                ),
            ),
        )
        .await;
        assert!(refused_by_the_gate(&out));
        let body = String::from_utf8_lossy(&out.body);
        assert!(body.contains("DIDComm or TSP"), "{body}");
    }

    /// What the role floor could not express: export narrowed away from one
    /// admin, who keeps everything else.
    #[tokio::test]
    async fn an_admin_narrowed_without_key_export_is_refused() {
        let (state, _dir) = build_signing_test_app_state().await;
        let auth = claims("did:key:zNarrowed", Role::Admin);
        let narrowed = AclEntry::new(&auth.did, Role::Admin, "did:key:zRoot")
            .with_contexts(vec!["acme".to_string()])
            .with_capabilities(vec![Capability::Sign, Capability::KeyMint]);
        store_acl_entry(&state.acl_ks, &narrowed)
            .await
            .expect("store the narrowed entry");

        let out = handle_export_secret(&state, &auth, export_doc()).await;
        assert!(
            refused_by_the_gate(&out),
            "a narrowing without key-export removes it, even from an admin"
        );
    }
}

#[cfg(test)]
mod import_wrapping_key_tests {
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use crate::test_support::build_signing_test_app_state;
    use serde_json::{Value, json};

    async fn ask(state: &crate::server::AppState, seed: u8, role: Role) -> Value {
        let vta_did = state.config.read().await.vta_did.clone().expect("vta_did");
        let (did, _) = crate::test_support::did_for_seed(seed);
        let mut doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": vta_sdk::trust_tasks::TASK_KEYS_IMPORT_WRAPPING_KEY_0_1,
            "issuer": did,
            "recipient": vta_did,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .unwrap();
        crate::test_support::sign_as(seed, &mut doc);
        let claims = AuthClaims {
            did,
            role,
            allowed_contexts: vec![],
            ..Default::default()
        };
        let out = super::super::dispatch_trust_task_core(
            state,
            &claims,
            &serde_json::to_vec(&doc).unwrap(),
            super::super::transport::TransportConfidentiality::HopByHop,
        )
        .await;
        serde_json::from_slice(&out.body).expect("a JSON document")
    }

    /// keys/import-wrapping-key/0.1: an admin gets a fresh Ed25519 `did:key`
    /// in the agent's signed answer, a new one every time; the key opens a
    /// bundle sealed to its X25519 counterpart exactly once.
    #[tokio::test]
    async fn an_admin_gets_a_fresh_signed_did_key_that_opens_one_sealed_bundle() {
        let (state, _dir) = build_signing_test_app_state().await;
        let first = ask(&state, 0x68, Role::Admin).await;
        let second = ask(&state, 0x68, Role::Admin).await;
        let key = first["payload"]["wrappingKey"].as_str().expect("{first}");
        assert!(key.starts_with("did:key:z6Mk"), "{first}");
        assert!(first["payload"]["keyId"].is_string(), "{first}");
        assert!(first["payload"]["expiresAt"].is_string(), "{first}");
        assert!(first["proof"].is_object(), "the answer is signed: {first}");
        assert_ne!(
            first["payload"]["wrappingKey"],
            second["payload"]["wrappingKey"]
        );

        // Seal to the did:key's X25519 counterpart; the cache opens it once.
        use base64::Engine as _;
        use vta_sdk::sealed_transfer::{
            AssertionProof, InMemoryNonceStore, ProducerAssertion, RawPrivateKey, SealedPayloadV1,
            armor, generate_ed25519_keypair, seal_payload,
        };
        let x = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(
            &affinidi_crypto::did_key::did_key_to_ed25519_pub(key).unwrap(),
        )
        .unwrap();
        let (_s, prod) = generate_ed25519_keypair();
        let bundle = seal_payload(
            &x,
            [9u8; 16],
            ProducerAssertion {
                producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod),
                proof: AssertionProof::PinnedOnly,
            },
            &SealedPayloadV1::RawPrivateKey(RawPrivateKey {
                key_type: "ed25519".into(),
                key_bytes_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode([0x33u8; 32]),
            }),
            &InMemoryNonceStore::new(),
        )
        .await
        .unwrap();
        let armored = armor::encode(&bundle);
        let (kind, bytes) = state.wrapping_cache.unwrap_sealed(&armored).await.unwrap();
        assert_eq!(
            (kind.as_str(), bytes.as_slice()),
            ("ed25519", &[0x33u8; 32][..])
        );
        assert!(
            state.wrapping_cache.unwrap_sealed(&armored).await.is_err(),
            "single use"
        );
    }

    /// The authority `keys/import` needs: anyone else is refused.
    #[tokio::test]
    async fn a_non_admin_is_refused_a_wrapping_key() {
        let (state, _dir) = build_signing_test_app_state().await;
        let resp = ask(&state, 0x69, Role::Reader).await;
        assert_eq!(resp["payload"]["code"], "permissionDenied", "{resp}");
    }
}

#[cfg(test)]
#[path = "sign_document_tests.rs"]
mod sign_document_tests;
