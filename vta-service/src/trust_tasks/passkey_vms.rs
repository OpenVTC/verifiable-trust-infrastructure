//! Passkey-VM slice trust-task handlers.
//!
//! **Feature-gated** — requires both `webvh` (DID-doc mutation + log
//! entries) AND `didcomm` (mediator push for the updated DID). The
//! whole module is `#![cfg(all(feature = "webvh", feature = "didcomm"))]`
//! at the top; mod.rs's `mod passkey_vms;` declaration carries the
//! same gate. URIs are still declared in vta-sdk unconditionally — the
//! parity harness uses `KNOWN_FEATURE_GATED_URIS` to recognise them
//! when this module isn't compiled.
//!
//! See `docs/05-design-notes/trust-task-feature-gating.md` for the
//! convention. This module is the worked example.
//!
//! Auth: Admin role on the DID's context for every handler. Enforced
//! inside the operations layer (`operations::passkey_vms::*` calls
//! `auth.require_admin` or equivalent).

#![cfg(all(feature = "webvh", feature = "didcomm"))]

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::{ErrorPayload, StandardCode, TrustTask, TrustTaskCode};
use vta_sdk::protocols::did_management::passkey_vms::{
    EnrollPasskeyChallengeBody, EnrollPasskeySubmitBody, ListPasskeyVmsBody, RevokePasskeyVmBody,
    RevokePasskeyVmResponse,
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::operations::passkey_vms::PasskeyVmError;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, error_response, parse_payload, success_response,
};

// ── Error mapping (#308) ────────────────────────────────────────────
//
// Map `PasskeyVmError` onto the published 0.1 error taxonomy: framework
// **standard** codes for auth / availability / internal failures, and
// **extended** `<task-slug>:<local>` codes (camelCase, framework 0.2)
// for the task-specific failures — with `details.reason` on the
// `invalidAttestation` family. The slug is sourced from the incoming
// document's type URI, so the same variant (e.g. DidNotFound) is
// namespaced to whichever task raised it, and 0.1/1.0 share one mapping.

/// Pure error→code mapping (tested in isolation). Returns the trust-task
/// code plus an optional `details.reason` value.
fn passkey_vm_code(slug: &str, err: &PasskeyVmError) -> (TrustTaskCode, Option<&'static str>) {
    let ext = |local: &str| {
        TrustTaskCode::new_extended(slug, local)
            .expect("passkey-vms extended code is grammar-valid")
    };
    match err {
        // Standard framework codes.
        PasskeyVmError::PermissionDenied(_) => (StandardCode::PermissionDenied.into(), None),
        PasskeyVmError::NotAvailable(_) => (StandardCode::Unavailable.into(), None),
        PasskeyVmError::Persistence(_)
        | PasskeyVmError::Internal(_)
        | PasskeyVmError::Update(_) => (StandardCode::InternalError.into(), None),
        // Extended, task-namespaced codes.
        PasskeyVmError::UnknownCeremony => (ext("unknownCeremony"), None),
        PasskeyVmError::CeremonyDidMismatch => (ext("ceremonyDidMismatch"), None),
        PasskeyVmError::InvalidAttestation(_) => (ext("invalidAttestation"), Some("unparseable")),
        PasskeyVmError::WebauthnFinishFailed(_) => (
            ext("invalidAttestation"),
            Some("webauthnVerificationFailed"),
        ),
        PasskeyVmError::Multikey(_) => (ext("invalidAttestation"), Some("unsupportedAlgorithm")),
        PasskeyVmError::PublicKeyMismatch => (ext("publicKeyMismatch"), None),
        PasskeyVmError::AlreadyEnrolled | PasskeyVmError::FragmentCollision(_) => {
            (ext("alreadyEnrolled"), None)
        }
        PasskeyVmError::DidNotFound => (ext("didNotFound"), None),
        PasskeyVmError::FragmentNotFound => (ext("fragmentNotFound"), None),
    }
}

/// Task slug (`vta/passkey-vms/<op>`) from the incoming document's type
/// URI, for namespacing extended codes. Falls back to the family slug
/// if the shape is unexpected (the document arrived via dispatch, so a
/// known URI is the norm).
fn slug_from_doc(doc: &TrustTask<Value>) -> String {
    let uri = doc.type_uri.to_string();
    uri.strip_prefix("https://trusttasks.org/spec/")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(slug, _ver)| slug.to_string())
        .unwrap_or_else(|| "vta/passkey-vms".to_string())
}

/// Render a `PasskeyVmError` as a spec-taxonomy trust-task error response,
/// namespaced to the task that raised it.
fn passkey_vm_reject(doc: &TrustTask<Value>, err: PasskeyVmError) -> TrustTaskOutcome {
    let slug = slug_from_doc(doc);
    let (code, reason) = passkey_vm_code(&slug, &err);
    let mut payload = ErrorPayload::new(code).with_message(err.to_string());
    if let Some(r) = reason {
        payload = payload.with_details(serde_json::json!({ "reason": r }));
    }
    error_response(doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

/// Handler for `spec/vta/passkey-vms/enroll-challenge/0.1`. Admin only
/// (enforced by the operation function).
pub(super) async fn handle_enroll_challenge(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: EnrollPasskeyChallengeBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let config = state.config.read().await;
    match operations::passkey_vms::start_enrollment(
        &state.webvh_ks,
        &state.passkey_vms_ks,
        &config,
        auth,
        &req.did,
        req.label,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => passkey_vm_reject(&doc, e),
    }
}

/// Handler for `spec/vta/passkey-vms/enroll-submit/0.1`. Admin only
/// (enforced by the operation function). Appends the new VM to the
/// DID document via a WebVH LogEntry; pushes the update to the
/// configured mediator.
pub(super) async fn handle_enroll_submit(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: EnrollPasskeySubmitBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = state.config.read().await.vta_did.clone();
    let config = state.config.read().await.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    match operations::passkey_vms::finish_enrollment(
        &deps,
        &state.passkey_vms_ks,
        auth,
        req,
        vta_did.as_deref(),
        &config,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => passkey_vm_reject(&doc, e),
    }
}

/// Handler for `spec/vta/passkey-vms/list/0.1`. Admin only (enforced
/// by the operation function).
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListPasskeyVmsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::passkey_vms::list_passkeys(&state.webvh_ks, auth, &req.did).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => passkey_vm_reject(&doc, e),
    }
}

/// Handler for `spec/vta/passkey-vms/revoke/0.1`. Admin only (enforced
/// by the operation function). Removes the VM via a WebVH LogEntry
/// and pushes the update to the mediator.
pub(super) async fn handle_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: RevokePasskeyVmBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    match operations::passkey_vms::revoke_passkey(
        &deps,
        auth,
        &req.did,
        &req.fragment,
        vta_did.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(()) => success_response(&doc, RevokePasskeyVmResponse::default()),
        Err(e) => passkey_vm_reject(&doc, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TypeUri;

    #[test]
    fn standard_codes_map_to_framework_codes() {
        let s = "vta/passkey-vms/enroll-submit";
        assert!(matches!(
            passkey_vm_code(s, &PasskeyVmError::PermissionDenied("x".into())).0,
            TrustTaskCode::Standard(StandardCode::PermissionDenied)
        ));
        assert!(matches!(
            passkey_vm_code(s, &PasskeyVmError::NotAvailable("x".into())).0,
            TrustTaskCode::Standard(StandardCode::Unavailable)
        ));
        assert!(matches!(
            passkey_vm_code(s, &PasskeyVmError::Internal("x".into())).0,
            TrustTaskCode::Standard(StandardCode::InternalError)
        ));
    }

    #[test]
    fn extended_codes_are_task_namespaced() {
        let submit = "vta/passkey-vms/enroll-submit";
        assert_eq!(
            passkey_vm_code(submit, &PasskeyVmError::UnknownCeremony)
                .0
                .to_string(),
            "vta/passkey-vms/enroll-submit:unknownCeremony"
        );
        assert_eq!(
            passkey_vm_code(submit, &PasskeyVmError::CeremonyDidMismatch)
                .0
                .to_string(),
            "vta/passkey-vms/enroll-submit:ceremonyDidMismatch"
        );
        assert_eq!(
            passkey_vm_code(submit, &PasskeyVmError::PublicKeyMismatch)
                .0
                .to_string(),
            "vta/passkey-vms/enroll-submit:publicKeyMismatch"
        );
        assert_eq!(
            passkey_vm_code(submit, &PasskeyVmError::AlreadyEnrolled)
                .0
                .to_string(),
            "vta/passkey-vms/enroll-submit:alreadyEnrolled"
        );
        // DidNotFound takes the emitting task's slug.
        assert_eq!(
            passkey_vm_code("vta/passkey-vms/list", &PasskeyVmError::DidNotFound)
                .0
                .to_string(),
            "vta/passkey-vms/list:didNotFound"
        );
        // fragmentNotFound is revoke-only and distinct from didNotFound.
        assert_eq!(
            passkey_vm_code("vta/passkey-vms/revoke", &PasskeyVmError::FragmentNotFound)
                .0
                .to_string(),
            "vta/passkey-vms/revoke:fragmentNotFound"
        );
    }

    #[test]
    fn invalid_attestation_family_carries_details_reason() {
        let s = "vta/passkey-vms/enroll-submit";
        let (code, reason) = passkey_vm_code(s, &PasskeyVmError::InvalidAttestation("x".into()));
        assert_eq!(
            code.to_string(),
            "vta/passkey-vms/enroll-submit:invalidAttestation"
        );
        assert_eq!(reason, Some("unparseable"));
        assert_eq!(
            passkey_vm_code(s, &PasskeyVmError::WebauthnFinishFailed("x".into())).1,
            Some("webauthnVerificationFailed")
        );
    }

    #[test]
    fn slug_is_derived_from_type_uri_for_both_versions() {
        for (uri, want) in [
            (
                "https://trusttasks.org/spec/vta/passkey-vms/revoke/0.1",
                "vta/passkey-vms/revoke",
            ),
            (
                "https://trusttasks.org/spec/vta/passkey-vms/enroll-submit/0.1",
                "vta/passkey-vms/enroll-submit",
            ),
        ] {
            let type_uri: TypeUri = uri.parse().unwrap();
            let doc = TrustTask::new("urn:uuid:1", type_uri, serde_json::json!({}));
            assert_eq!(slug_from_doc(&doc), want);
        }
    }
}
