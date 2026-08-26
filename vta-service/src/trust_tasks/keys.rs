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
use vta_sdk::protocols::key_management::sign::SignRequestBody;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
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

/// Handler for `keys/create/0.1`. Admin only.
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
        &state.internal_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        operations::keys::CreateKeyParams {
            internal: req.internal.unwrap_or(false),
            key_type: req.key_type,
            derivation_path: req.derivation_path,
            // A derived key takes its id from the derivation path, so `None`
            // is right for it. An **internal** key has no derivation path to
            // be named after and the operation layer refuses one without an
            // id — so over this binding, where the request carries no `keyId`
            // member to supply, the binding mints one.
            //
            // `keyId` is published in `keys/create/0.1` as of `trust-tasks-rs`
            // 0.12.1 (dtgwg-trust-tasks-tf#275), and this workspace cannot
            // move to 0.12 yet: `affinidi-messaging-sdk` 0.19.12 pins
            // `trust-tasks-rs ^0.11` and `vta_sdk::acl_setup` hands it a
            // generated `MediatorAcl`, so two nodes in one graph fail to
            // compile. **When that bump lands, take `key_id` from the request
            // and delete this branch** — the specification says a maintainer
            // that offers internal keys and receives no `keyId` SHOULD reject,
            // and minting one is a deliberate deviation taken because the
            // alternative is a security feature that cannot be used at all.
            //
            // The consumer is not left guessing: the id is returned on the
            // response record, the CLI prints it, and `keys/rename/0.1` can
            // change it.
            key_id: if req.internal.unwrap_or(false) {
                Some(format!("internal-{}", uuid::Uuid::new_v4()))
            } else {
                None
            },
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

/// Handler for `keys/derive-and-sign/0.1`. Admin only.
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

/// Handler for `keys/derive-and-sign-document/0.1`. Admin only.
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
