//! Keys slice trust-task handlers.
//!
//! Mirrors the legacy REST `/keys/*` routes. Auth: any authenticated
//! caller for list/get; admin for create/rename/revoke; write
//! (Application or higher) for sign.

use super::helpers::TrustTaskOutcome;
use crate::audit;
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
/// `KeyExport` **in the key's own scope**: the capability is the gate and
/// `get_key_secret`'s own `require_context` is the scope, so a holder in one
/// context reaches no other context's keys. The URI this replaces
/// (`vta/seeds/export-mnemonic/1.0`) demanded global Admin for the same act,
/// which handed a caller wanting one key authority over everything else.
///
/// The two refusals the spec makes consumer requirements — an internal key is
/// never released, and a non-exportable key is refused about the key rather
/// than the asker — are both enforced inside `get_key_secret`, which is the one
/// place a private key leaves. Re-checking them here would be a second set of
/// rules to keep in step.
pub(super) async fn handle_export_secret(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // `KeyExport`, not the admin role — VTI-VTA-003: an export "MUST be gated
    // by a capability distinct from the capability to use the key". Only
    // `admin` derives it, so no current admin loses anything; what changes is
    // that an operator can now narrow it away from a particular admin, which a
    // role floor could not express. Scope is still enforced inside
    // `get_key_secret`, and the export is still audited there.
    if let Err(reject) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        vti_common::acl::Capability::KeyExport,
        "keys/export-secret",
    )
    .await
    {
        return reject;
    }
    let req: GetKeySecretBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
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
        Ok(body) => {
            // A signature is the most consequential thing this agent does with a key,
            // and these two are the only signing paths that persist no key record — so
            // without a line here, a derived-key signature leaves the agent with no
            // evidence it ever happened. The derivation path is the resource: it is
            // what identifies *which* key signed, and it is not itself secret.
            if let Err(e) = audit::record_with_detail(
                &state.audit_sink,
                "keys.derive-and-sign",
                &auth.did,
                Some(&req.derivation_path),
                "success",
                Some(TRANSPORT_TRUST_TASK),
                None,
                Some(&format!("keyType={} alg={}", req.key_type, req.algorithm)),
            )
            .await
            {
                tracing::warn!(error = %e, "audit record failed for keys.derive-and-sign");
            }
            success_response(&doc, body)
        }
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
    let audit_path = req.derivation_path.clone();
    let audit_detail = format!(
        "keyType={} proofPurpose={}",
        req.key_type,
        req.proof_purpose.as_deref().unwrap_or("assertionMethod")
    );
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
        Ok(body) => {
            // Sibling of `derive-and-sign` above, and the same reasoning. The
            // document itself is deliberately not recorded — it is the caller's
            // content, may carry anything, and the trail answers "which key
            // signed, under what purpose", not "what did it say".
            if let Err(e) = audit::record_with_detail(
                &state.audit_sink,
                "keys.derive-and-sign-document",
                &auth.did,
                Some(&audit_path),
                "success",
                Some(TRANSPORT_TRUST_TASK),
                None,
                Some(&audit_detail),
            )
            .await
            {
                tracing::warn!(
                    error = %e,
                    "audit record failed for keys.derive-and-sign-document"
                );
            }
            success_response(&doc, body)
        }
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

    /// An admin passes the gate — it derives `KeyExport` — and reaches the
    /// lookup, which is what proves the refusal above was the capability and
    /// not some other check.
    #[tokio::test]
    async fn an_admin_passes_the_key_export_gate() {
        let (state, _dir) = build_signing_test_app_state().await;
        let out = handle_export_secret(
            &state,
            &claims("did:key:zOperator", Role::Admin),
            export_doc(),
        )
        .await;
        assert!(
            !refused_by_the_gate(&out),
            "an admin derives KeyExport and must reach the key lookup"
        );
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
