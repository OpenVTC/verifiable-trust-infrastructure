//! Provision-integration slice trust-task handler.
//!
//! **Feature-gated** — requires `webvh` (DID-doc mutation + log
//! entries). The whole module is `#![cfg(feature = "webvh")]` at the
//! top; mod.rs's `mod provision_integration;` declaration carries
//! the same gate.
//!
//! Auth: Admin role on the target context (enforced inside
//! [`crate::operations::provision_integration::provision_integration`]).
//! `create_context: true` additionally requires super-admin on the
//! VTA (enforced by
//! `crate::operations::provision_integration::ensure_target_context_or_create`).
//!
//! Mirrors the legacy REST `POST /bootstrap/provision-integration`
//! handler byte-for-byte (the sealed armored bundle is the payload
//! of the response, per the URI-registry's "sealed armor is
//! payload-of" decision).

#![cfg(feature = "webvh")]

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::provision_integration::http::{
    AssertionMode, ProvisionIntegrationRequest, ProvisionIntegrationResponse,
};

use crate::auth::AuthClaims;
use crate::operations::provision_integration::{
    AmbiguousContext, ProvisionIntegrationDeps, ProvisionIntegrationParams,
    ensure_target_context_or_create, infer_target_context,
    provision_integration as provision_integration_op,
};
use crate::server::AppState;

use super::helpers::{app_error_to_reject, parse_payload, reject_with, success_response};

/// Handler for `spec/vta/provision-integration/request/1.0`. Admin
/// role on the target context required; super-admin required if the
/// request asks to create the context inline.
pub(super) async fn handle_request(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ProvisionIntegrationRequest = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Verify the inbound BootstrapRequest's VP before doing any
    // state changes.
    let verified = match req.request.verify() {
        Ok(v) => v,
        Err(e) => {
            return reject_with(
                &doc,
                trust_tasks_rs::RejectReason::MalformedRequest {
                    reason: format!("verify BootstrapRequest: {e}"),
                },
            );
        }
    };

    let assertion_mode = req.assertion.unwrap_or_default();
    let vc_validity = req.vc_validity_seconds.map(chrono::Duration::seconds);
    let deps = ProvisionIntegrationDeps::from(state);

    // Resolve the target context. When the caller sent one, use it
    // verbatim; otherwise run the spec's inference rules. Ambiguous
    // → MalformedRequest with the candidates inline (trust-task
    // envelopes don't carry the canonical `provision/integration:
    // context_required` code yet — REST surfaces what we have here).
    let context = match req.context {
        Some(c) => c,
        None => match infer_target_context(auth, &deps.contexts_ks).await {
            Ok(Ok(c)) => c,
            Ok(Err(AmbiguousContext {
                candidates,
                message,
            })) => {
                return reject_with(
                    &doc,
                    trust_tasks_rs::RejectReason::MalformedRequest {
                        reason: format!("{message} (candidates: {})", candidates.join(", ")),
                    },
                );
            }
            Err(e) => return app_error_to_reject(&doc, e),
        },
    };

    // `create_context: true` — create the target context inline if it
    // doesn't exist. Hits the super-admin gate inside
    // operations::contexts::create_context; context-admin callers
    // surface as Forbidden. Idempotent when the context already exists.
    let context_created = match ensure_target_context_or_create(
        &deps.contexts_ks,
        auth,
        &context,
        req.create_context,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let output = match provision_integration_op(
        &deps,
        auth,
        ProvisionIntegrationParams {
            request: verified,
            context,
            assertion_mode: AssertionModeOpAdapter(assertion_mode).into(),
            vc_validity,
        },
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let body = ProvisionIntegrationResponse {
        bundle: output.armored,
        digest: output.digest,
        summary: vta_sdk::provision_integration::http::ProvisionSummary {
            client_did: output.summary.client_did,
            admin_did: output.summary.admin_did,
            admin_rolled_over: output.summary.admin_rolled_over,
            integration_did: output.summary.integration_did,
            template_name: output.summary.template_name,
            template_kind: output.summary.template_kind,
            admin_template_name: output.summary.admin_template_name,
            bundle_id_hex: output.summary.bundle_id_hex,
            secret_count: output.summary.secret_count,
            output_count: output.summary.output_count,
            webvh_server_id: output.summary.webvh_server_id,
            context_created,
        },
    };
    success_response(&doc, body)
}

/// Adapter to convert the SDK wire enum `AssertionMode` into the op
/// layer's `crate::operations::provision_integration::AssertionMode`.
/// The two enums are kept structurally identical but distinct types
/// so the wire format can evolve independently of the op layer.
struct AssertionModeOpAdapter(AssertionMode);

impl From<AssertionModeOpAdapter> for crate::operations::provision_integration::AssertionMode {
    fn from(a: AssertionModeOpAdapter) -> Self {
        match a.0 {
            AssertionMode::DidSigned => {
                crate::operations::provision_integration::AssertionMode::DidSigned
            }
            AssertionMode::PinnedOnly => {
                crate::operations::provision_integration::AssertionMode::PinnedOnly
            }
        }
    }
}
