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

use super::helpers::{
    app_error_to_reject, parse_payload, reject_with, reject_with_code, success_response,
};

/// Handler for canonical `provision/integration/0.2`. Admin
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

    // Verify the inbound BootstrapRequest's VP before doing any state changes,
    // over the JSON **as received** — the same thing the DIDComm handler does.
    //
    // `req.request.verify()` re-serialises the typed struct first, which
    // re-imposes this crate's serde casing on the very bytes the holder signed.
    // That only worked while both sides happened to agree: the moment either
    // one's casing moves, the proof breaks over a document nobody tampered
    // with. `verify_value` takes the wire bytes, so the signed form survives
    // JCS canonicalisation and the typed view is built from it separately.
    let request_raw = match doc.payload.get("request") {
        Some(v) => v.clone(),
        None => {
            return reject_with(
                &doc,
                trust_tasks_rs::RejectReason::MalformedRequest {
                    reason: "provision-integration request missing 'request' field".into(),
                },
            );
        }
    };
    let verified = match vta_sdk::provision_integration::BootstrapRequest::verify_value(request_raw)
    {
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

    // Resolve the target context. When the caller sent one, use it verbatim;
    // otherwise run the spec's inference rules.
    //
    // Ambiguous → the canonical `provision/integration:contextRequired` code
    // with `details.candidates`, which is the shape
    // `ProvisionIntegrationRequest::context` documents and the shape a wallet
    // branches on to show the operator a context picker. It used to be a
    // `MalformedRequest` with the candidates joined into the human message,
    // on the grounds that "trust-task envelopes don't carry the canonical code
    // yet" — they do; `reject_with_code` is the seam that was missing, not the
    // capability. Recovering a list from a rendered sentence is precisely the
    // string-matching a machine-readable code exists to avoid.
    //
    // This is also the one refusal that had three different shapes across the
    // three transports: DIDComm a problem-report with `args`, REST a bare 400
    // with the message inline, and the spine this stringified reason — none of
    // them the documented one. The spine is the path all three converge on, so
    // fixing it here is what makes the refusal transport-agnostic rather than
    // one more rendering.
    let context = match req.context {
        Some(c) => c,
        None => match infer_target_context(auth, &deps.contexts_ks).await {
            Ok(Ok(c)) => c,
            Ok(Err(AmbiguousContext {
                candidates,
                message,
            })) => {
                return context_required(&doc, &message, &candidates);
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
        digest_multibase: Some(output.digest_multibase),
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

/// Refuse an under-specified provisioning request with the code its own
/// specification declares.
///
/// The code string is parsed from `vta_sdk`'s single constant rather than
/// rebuilt from a slug/local pair here, so the spine and the DIDComm
/// problem-report cannot drift into two spellings of the same refusal — that
/// drift is exactly what SPEC §4.10 rule 4 was written about.
///
/// A parse failure would mean the constant itself stopped being a legal
/// extended code, which is a bug in this workspace rather than anything the
/// producer did. It falls back to `taskFailed` carrying the same `details`:
/// the candidates still reach the caller, and the alternative — dropping the
/// refusal or panicking a request thread — serves nobody.
fn context_required(
    doc: &TrustTask<Value>,
    message: &str,
    candidates: &[String],
) -> TrustTaskOutcome {
    let details = serde_json::json!({ "candidates": candidates });
    match vta_sdk::protocols::problem_report_codes::PROVISION_CONTEXT_REQUIRED
        .parse::<trust_tasks_rs::TrustTaskCode>()
    {
        Ok(code) => reject_with_code(doc, code, message, Some(details)),
        Err(e) => {
            tracing::error!(
                error = %e,
                code = vta_sdk::protocols::problem_report_codes::PROVISION_CONTEXT_REQUIRED,
                "provision-integration contextRequired code is not a legal extended code; \
                 falling back to taskFailed"
            );
            reject_with(
                doc,
                trust_tasks_rs::RejectReason::TaskFailed {
                    reason: message.to_string(),
                    details: Some(details),
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    /// The constant this slice refuses with must be a legal extended code.
    ///
    /// `context_required` parses it at runtime and falls back to `taskFailed`
    /// when it does not parse. That fallback exists so a malformed constant
    /// cannot panic a request thread — but it would also silently downgrade
    /// the refusal to a code no wallet branches on, and nothing at runtime
    /// would say so. This test is what makes the fallback unreachable rather
    /// than merely unlikely.
    #[test]
    fn the_context_required_constant_is_a_legal_extended_code() {
        let raw = vta_sdk::protocols::problem_report_codes::PROVISION_CONTEXT_REQUIRED;
        let code: trust_tasks_rs::TrustTaskCode = raw
            .parse()
            .expect("PROVISION_CONTEXT_REQUIRED must parse as an extended code");
        assert_eq!(
            code.to_string(),
            raw,
            "the parsed code must round-trip to the constant the DIDComm \
             problem-report also sends, or the two transports refuse in two \
             different spellings"
        );
    }
}
