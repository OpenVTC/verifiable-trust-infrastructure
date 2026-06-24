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
use vta_sdk::protocols::key_management::list::ListKeysBody;
use vta_sdk::protocols::key_management::rename::RenameKeyBody;
use vta_sdk::protocols::key_management::revoke::RevokeKeyBody;
use vta_sdk::protocols::key_management::sign::SignRequestBody;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};

/// Handler for `spec/vta/keys/list/1.0`.
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

/// Handler for `spec/vta/keys/create/1.0`. Admin only.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: CreateKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::create_key(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_ks,
        auth,
        operations::keys::CreateKeyParams {
            key_type: req.key_type,
            derivation_path: Some(req.derivation_path),
            // Trust-task envelope auto-generates key_id from derivation
            // path; explicit-key_id specification stays on the legacy
            // REST path until Phase 3 hardening extends CreateKeyBody.
            key_id: None,
            mnemonic: req.mnemonic,
            label: req.label,
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

/// Handler for `spec/vta/keys/get/1.0`.
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
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/keys/rename/1.0`. Admin only.
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
        &state.audit_ks,
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

/// Handler for `spec/vta/keys/revoke/1.0`. Admin only.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Revoking (deleting) a key is gated per the `key/revoke` step-up floor.
    if let Some(resp) =
        super::step_up::require_step_up(state, auth, super::step_up::op::KEY_REVOKE, &doc).await
    {
        return resp;
    }
    let req: RevokeKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::revoke_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
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

/// Handler for `spec/vta/keys/sign/1.0`. Application-or-higher (write).
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
        &state.contexts_ks,
        &state.seed_store,
        auth,
        &req.key_id,
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

/// Handler for `spec/vta/keys/derive-and-sign/1.0`. Admin only.
///
/// Ephemeral: derives at the requested BIP-32 path, signs, and returns the
/// signature + derived public key without persisting a key record.
pub(super) async fn handle_derive_and_sign(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
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
        &state.seed_store,
        auth,
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

/// Handler for `spec/vta/keys/derive-and-sign-document/1.0`. Admin only.
///
/// Attaches an `eddsa-jcs-2022` Data-Integrity proof to the document, signed as
/// the key derived at the requested path — without persisting a key record.
pub(super) async fn handle_derive_and_sign_document(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: DeriveAndSignDocumentBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::derive_and_sign_document(
        &state.keys_ks,
        &state.seed_store,
        auth,
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
