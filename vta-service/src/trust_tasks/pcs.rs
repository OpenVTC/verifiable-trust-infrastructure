//! Hidden-vetting PCS engine (`vta/pcs/*/0.1`, trust-tasks-tf #756) — the VTA holds its
//! principal's PCS keys and runs every member-side hidden-vetting operation, so the client that
//! carries the messages (a wallet with no PCS implementation) never holds one.
//!
//! The engine is [`crate::operations::pcs`]; this slice is the dispatch surface over it:
//!
//! - **Capability-gated**, before anything is read: `pcs-vetter` for the vetter tasks,
//!   `pcs-applicant` for the applicant tasks (registered upstream as `pcsVetter` /
//!   `pcsApplicant`). Neither is `sign`, and neither confers it (VTI-VTA-007).
//! - **Context-gated**: a vetter task, and `applications/create`, name the context; the caller
//!   must be able to act in it. An application handle in a context the caller cannot act in
//!   reads as `notFound`, so a refusal does not confirm that it exists.
//! - **Audited** without pairing a vetter with an applicant (the family's conventions §6): the
//!   action, the caller, the context, the community or the application — never an applicant
//!   identifier, a tag or statement metadata.
//!
//! Payloads are validated by parsing into the generated `vti_specs::vta::pcs`
//! types, and responses are rendered through the generated response type, so a response that
//! drifted from its schema fails here rather than at a consumer.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::{DeclaredErrorCode, RejectReason, TrustTask};
use vti_specs::vta::pcs as spec;

use vti_common::acl::Capability;

use crate::auth::AuthClaims;
use crate::operations::pcs::{self as engine, Caller, PcsError};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, require_capability, success_response,
};

// ─── Shared plumbing ─────────────────────────────────────────────────────────

/// Answer with `value` rendered through the task's generated response type `R`.
fn respond<R: DeserializeOwned + Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

/// Refuse with the code the task declares for `e`, or as an internal error when it declares
/// none (which is a defect: every engine refusal a task can reach has a declared code).
fn refuse(
    doc: &TrustTask<Value>,
    e: PcsError,
    code: impl Fn(&PcsError) -> Option<DeclaredErrorCode>,
) -> TrustTaskOutcome {
    match e {
        PcsError::App(a) => app_error_to_reject(doc, a),
        other => match code(&other) {
            Some(c) => reject_declared(doc, c, other.to_string()),
            None => reject_with(
                doc,
                RejectReason::InternalError {
                    reason: other.to_string(),
                },
            ),
        },
    }
}

fn str_of<'a>(doc: &'a TrustTask<Value>, key: &str) -> &'a str {
    doc.payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn value_of(doc: &TrustTask<Value>, key: &str) -> Value {
    doc.payload.get(key).cloned().unwrap_or(Value::Null)
}

/// The caller may act in `context`, or the request is refused `permissionDenied`.
fn require_context(
    doc: &TrustTask<Value>,
    auth: &AuthClaims,
    context: &str,
) -> Result<(), TrustTaskOutcome> {
    auth.require_context(context)
        .map_err(|e| app_error_to_reject(doc, e))
}

async fn audit(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    resource: &str,
    context: &str,
    detail: Option<&str>,
) {
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        action,
        &auth.did,
        Some(resource),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        Some(context),
        detail,
    )
    .await
    {
        tracing::warn!(error = %e, action, "audit record failed for a PCS engine task");
    }
}

fn caller(auth: &AuthClaims) -> Caller<'_> {
    Caller {
        did: &auth.did,
        channel: TRANSPORT_TRUST_TASK,
    }
}

/// The application named by `applicationId`, if the caller may see it.
async fn application(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    not_found: DeclaredErrorCode,
) -> Result<engine::ApplicationRecord, TrustTaskOutcome> {
    let id = str_of(doc, "applicationId");
    engine::application_record(state, id, |ctx| auth.has_context_access(ctx))
        .await
        .map_err(|e| {
            refuse(doc, e, |e| {
                matches!(e, PcsError::NotFound).then_some(not_found)
            })
        })
}

// ─── Applicant ───────────────────────────────────────────────────────────────

/// `vta/pcs/applications/create/0.1`.
pub(super) async fn handle_applications_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::applications::create::v0_1 as t;
    if let Err(r) =
        require_capability(state, auth, &doc, Capability::PcsApplicant, "pcs applicant").await
    {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let context = str_of(&doc, "contextId").to_string();
    if let Err(r) = require_context(&doc, auth, &context) {
        return r;
    }
    let community = str_of(&doc, "community").to_string();
    match engine::create_application(
        state,
        &caller(auth),
        &context,
        &community,
        str_of(&doc, "joinDid"),
        &value_of(&doc, "parameters"),
    )
    .await
    {
        Ok(app) => {
            let id = app["applicationId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            audit(
                state,
                "pcs.application.create",
                auth,
                &id,
                &context,
                Some(&community),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "application": app }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/applications/show/0.1`.
pub(super) async fn handle_applications_show(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::applications::show::v0_1 as t;
    if let Err(r) =
        require_capability(state, auth, &doc, Capability::PcsApplicant, "pcs applicant").await
    {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let record = match application(state, auth, &doc, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    match engine::show_application(state, &record).await {
        Ok(app) => respond::<t::Response>(&doc, json!({ "application": app })),
        Err(e) => refuse(&doc, e, |_| None),
    }
}

/// `vta/pcs/applications/delete/0.1`.
pub(super) async fn handle_applications_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::applications::delete::v0_1 as t;
    if let Err(r) =
        require_capability(state, auth, &doc, Capability::PcsApplicant, "pcs applicant").await
    {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let record = match application(state, auth, &doc, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    match engine::delete_application(state, &record).await {
        Ok(()) => {
            audit(
                state,
                "pcs.application.delete",
                auth,
                &record.application_id,
                &record.context_id,
                None,
            )
            .await;
            respond::<t::Response>(
                &doc,
                json!({ "applicationId": record.application_id, "deleted": true }),
            )
        }
        Err(e) => refuse(&doc, e, |_| None),
    }
}

/// `vta/pcs/verify-attestation/0.1`.
pub(super) async fn handle_verify_attestation(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::verify_attestation::v0_1 as t;
    if let Err(r) =
        require_capability(state, auth, &doc, Capability::PcsApplicant, "pcs applicant").await
    {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let record = match application(state, auth, &doc, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    match engine::verify_attestation(
        state,
        &caller(auth),
        &record,
        &value_of(&doc, "parameters"),
        &value_of(&doc, "attestation"),
    )
    .await
    {
        Ok((app, accepted)) => {
            audit(
                state,
                "pcs.attestation.receive",
                auth,
                &record.application_id,
                &record.context_id,
                None,
            )
            .await;
            respond::<t::Response>(&doc, json!({ "application": app, "accepted": accepted }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            PcsError::AttestationInvalid(_) => Some(t::error_codes::ATTESTATION_INVALID),
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            _ => None,
        }),
    }
}

/// `vta/pcs/prove/0.1`.
pub(super) async fn handle_prove(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::prove::v0_1 as t;
    if let Err(r) =
        require_capability(state, auth, &doc, Capability::PcsApplicant, "pcs applicant").await
    {
        return r;
    }
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let record = match application(state, auth, &doc, t::error_codes::NOT_FOUND).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    match engine::prove(
        state,
        &caller(auth),
        &record,
        &value_of(&doc, "parameters"),
        str_of(&doc, "requirementsDigest"),
        str_of(&doc, "challenge"),
    )
    .await
    {
        Ok(proof) => {
            audit(
                state,
                "pcs.prove",
                auth,
                &record.application_id,
                &record.context_id,
                None,
            )
            .await;
            respond::<t::Response>(&doc, json!({ "hiddenVetting": proof }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            PcsError::NoUsableAttestation => Some(t::error_codes::NO_USABLE_ATTESTATION),
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            _ => None,
        }),
    }
}

// ─── Vetter ──────────────────────────────────────────────────────────────────

/// The vetter-task preamble: the capability, the payload against its schema, the context.
/// Returns the context and community.
async fn vetter_preamble<P: DeserializeOwned>(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(String, String), TrustTaskOutcome> {
    require_capability(state, auth, doc, Capability::PcsVetter, "pcs vetter").await?;
    parse_payload::<P>(doc)?;
    let context = str_of(doc, "contextId").to_string();
    require_context(doc, auth, &context)?;
    Ok((context, str_of(doc, "community").to_string()))
}

/// `vta/pcs/root-request/0.1`.
pub(super) async fn handle_root_request(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::root_request::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let label = str_of(&doc, "label").to_string();
    match engine::root_request(
        state,
        &caller(auth),
        &context,
        &community,
        str_of(&doc, "memberDid"),
        &value_of(&doc, "parameters"),
        &label,
    )
    .await
    {
        Ok(request) => {
            audit(
                state,
                "pcs.vetter.root_request",
                auth,
                &community,
                &context,
                Some(&label),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "request": request }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            PcsError::MemberMismatch => Some(t::error_codes::MEMBER_MISMATCH),
            PcsError::LabelNotLive(_) => Some(t::error_codes::LABEL_NOT_LIVE),
            _ => None,
        }),
    }
}

/// `vta/pcs/root-accept/0.1`.
pub(super) async fn handle_root_accept(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::root_accept::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let answer = value_of(&doc, "response");
    let label = answer["label"].as_str().unwrap_or_default().to_string();
    match engine::root_accept(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        &label,
        answer["preCredential"].as_str().unwrap_or_default(),
    )
    .await
    {
        Ok(vetter) => {
            audit(
                state,
                "pcs.vetter.root_accept",
                auth,
                &community,
                &context,
                Some(&label),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "vetter": vetter }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::NoRequestInFlight => Some(t::error_codes::NO_REQUEST_IN_FLIGHT),
            PcsError::CredentialInvalid(_) => Some(t::error_codes::CREDENTIAL_INVALID),
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/tokens/request/0.1`.
pub(super) async fn handle_tokens_request(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::tokens::request::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let label = str_of(&doc, "label").to_string();
    let tick = doc.payload["tick"].as_u64().unwrap_or_default();
    let Ok(tick) = u32::try_from(tick) else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "tick is out of range".into(),
            },
        );
    };
    let count = doc.payload["count"].as_u64().unwrap_or_default() as usize;
    match engine::tokens_request(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        &label,
        tick,
        count,
    )
    .await
    {
        Ok(request) => {
            let detail = format!("{label} tick {tick}");
            audit(
                state,
                "pcs.vetter.tokens_request",
                auth,
                &community,
                &context,
                Some(&detail),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "request": request }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::LabelNotLive(_) => Some(t::error_codes::LABEL_NOT_LIVE),
            PcsError::CountExceedsDrip { .. } => Some(t::error_codes::COUNT_EXCEEDS_DRIP),
            PcsError::AlreadyInFlight => Some(t::error_codes::ALREADY_IN_FLIGHT),
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/tokens/accept/0.1`.
pub(super) async fn handle_tokens_accept(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::tokens::accept::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let answer: vti_vetting_pcs::issuer::TokenBatchWire =
        match serde_json::from_value(value_of(&doc, "response")) {
            Ok(a) => a,
            Err(e) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("response: {e}"),
                    },
                );
            }
        };
    let detail = format!("{} tick {}", answer.label, answer.tick);
    match engine::tokens_accept(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        answer,
    )
    .await
    {
        Ok((received, vetter)) => {
            audit(
                state,
                "pcs.vetter.tokens_accept",
                auth,
                &community,
                &context,
                Some(&detail),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "received": received, "vetter": vetter }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::NoDrawInFlight => Some(t::error_codes::NO_DRAW_IN_FLIGHT),
            PcsError::TokensInvalid(_) => Some(t::error_codes::TOKENS_INVALID),
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/tokens/abandon/0.1`.
pub(super) async fn handle_tokens_abandon(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::tokens::abandon::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let label = doc.payload["draw"]["label"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let Ok(tick) = u32::try_from(doc.payload["draw"]["tick"].as_u64().unwrap_or_default()) else {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "tick is out of range".into(),
            },
        );
    };
    match engine::tokens_abandon(state, &context, &community, &label, tick).await {
        Ok(vetter) => {
            let detail = format!("{label} tick {tick}");
            audit(
                state,
                "pcs.vetter.tokens_abandon",
                auth,
                &community,
                &context,
                Some(&detail),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "vetter": vetter }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::NoDrawInFlight => Some(t::error_codes::NO_DRAW_IN_FLIGHT),
            _ => None,
        }),
    }
}

/// `vta/pcs/attest/0.1`.
pub(super) async fn handle_attest(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::attest::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // The engine fills the token members from the token it spends.
    let mut meta = value_of(&doc, "meta");
    if let Some(m) = meta.as_object_mut() {
        m.insert("tokenLabel".into(), Value::String(String::new()));
        m.insert("tokenSerial".into(), Value::String(String::new()));
    }
    let meta = match serde_json::from_value(meta) {
        Ok(m) => m,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("meta: {e}"),
                },
            );
        }
    };
    let prefer = doc.payload.get("preferLabel").and_then(Value::as_str);
    match engine::attest(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        str_of(&doc, "applicantId"),
        meta,
        prefer,
    )
    .await
    {
        Ok(attestation) => {
            // The token label, and nothing that names the applicant (conventions §6).
            let label = attestation["token"]["label"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            audit(
                state,
                "pcs.vetter.attest",
                auth,
                &community,
                &context,
                Some(&label),
            )
            .await;
            respond::<t::Response>(&doc, json!({ "attestation": attestation }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::NotEnrolled => Some(t::error_codes::NOT_ENROLLED),
            PcsError::NoToken => Some(t::error_codes::NO_TOKEN),
            PcsError::ApplicantInvalid => Some(t::error_codes::APPLICANT_INVALID),
            PcsError::CommunityMismatch => Some(t::error_codes::COMMUNITY_MISMATCH),
            PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
            PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/vetter/show/0.1`.
pub(super) async fn handle_vetter_show(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::vetter::show::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match engine::vetter_show(state, &context, &community).await {
        Ok(vetter) => respond::<t::Response>(&doc, json!({ "vetter": vetter })),
        Err(e) => refuse(&doc, e, |e| {
            matches!(e, PcsError::NotFound).then_some(t::error_codes::NOT_FOUND)
        }),
    }
}

/// `vta/pcs/vetter/recover/0.1`: restore the key the community bound the member to.
///
/// Audited as `pcs.vetter.recover` with the community and whether the key changed — never the
/// identifier, the key, the seed or the path (rule 8). The search itself is audited once by key
/// custody (`key.pcs_search`).
pub(super) async fn handle_vetter_recover(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::vetter::recover::v0_1 as t;
    let (context, community) = match vetter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match engine::vetter_recover(
        state,
        &caller(auth),
        &context,
        &community,
        str_of(&doc, "memberDid"),
        str_of(&doc, "boundId"),
        |ctx| auth.has_context_access(ctx),
    )
    .await
    {
        Ok((recovered, vetter)) => {
            if recovered {
                audit(
                    state,
                    "pcs.vetter.recover",
                    auth,
                    &community,
                    &context,
                    Some("key restored"),
                )
                .await;
            }
            respond::<t::Response>(&doc, json!({ "recovered": recovered, "vetter": vetter }))
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::BoundKeyNotFound(_) => Some(t::error_codes::NOT_FOUND),
            PcsError::HeldInAnotherContext(_) => Some(t::error_codes::HELD_IN_ANOTHER_CONTEXT),
            PcsError::MemberMismatch => Some(t::error_codes::MEMBER_MISMATCH),
            PcsError::EngineEnrolled => Some(t::error_codes::ENGINE_ENROLLED),
            _ => None,
        }),
    }
}

// ─── Voter ───────────────────────────────────────────────────────────────────
//
// `vta/pcs/voter/*` and `vta/pcs/vote` (trust-tasks-tf #834, VTI-VOT-020 – 053). Audit names the
// election and never a tag, a cast, a ballot or a receipt (VTI-VOT-100): the record pairs the
// caller with an election they took part in, which their community already knows, and nothing
// that could link them to what they voted.

/// The voter-task preamble: the capability, the payload against its schema, the context.
async fn voter_preamble<P: DeserializeOwned>(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(String, String), TrustTaskOutcome> {
    require_capability(state, auth, doc, Capability::PcsVoter, "pcs voter").await?;
    parse_payload::<P>(doc)?;
    let context = str_of(doc, "contextId").to_string();
    require_context(doc, auth, &context)?;
    Ok((context, str_of(doc, "community").to_string()))
}

/// `vta/pcs/voter/read/0.6`: `vtc/elections/list/0.5` or `vtc/elections/show/0.6`, signed as
/// the member (items 3 – 8), the `show` carrying the member's presentation of
/// `membershipCredential` where the request names one, issued by `memberOf` where it names
/// that (VTI-VOT-016); 0.3, which signs `list/0.3` or `show/0.3`; and 0.2, which signs
/// `list/0.3` or `show/0.2`. The version the request names picks the reads signed.
#[allow(deprecated)] // vta/pcs/voter/read/0.2 – 0.3 and the reads they sign: still served
pub(super) async fn handle_voter_read(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::voter::read::v0_6 as t;
    use trust_tasks_rs::validate::ValidatedPayload as _;
    use vti_specs::vtc::elections::{
        list::v0_3 as list_0_3, list::v0_5 as list, show::v0_2 as show_0_2, show::v0_3 as show_0_3,
        show::v0_6 as show,
    };
    let (_context, community) = match voter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let named = doc.type_uri.to_string();
    let is = |uri: &str| named.starts_with(uri);
    // 0 = 0.6, 3 = 0.3, 2 = 0.2.
    let version = if is(<spec::voter::read::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI) {
        2
    } else if is(<spec::voter::read::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI) {
        3
    } else {
        0
    };
    let read = doc.payload["read"].as_str().unwrap_or_default();
    let payload = value_of(&doc, "payload");
    // Item 3: only the engine builds a presentation, bound to the document it signs.
    if payload.get("presentation").is_some() {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "payload carries a presentation; name membershipCredential and the \
                         engine presents it"
                    .into(),
            },
        );
    }
    // Item 3: the read's own payload, against its own schema.
    let (type_uri, checked) = match (read, version) {
        ("list", 0) => (
            <list::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            list::Payload::validate_value(&payload).map_err(|e| e.to_string()),
        ),
        ("list", _) => (
            <list_0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            list_0_3::Payload::validate_value(&payload).map_err(|e| e.to_string()),
        ),
        ("show", 2) => (
            <show_0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            show_0_2::Payload::validate_value(&payload).map_err(|e| e.to_string()),
        ),
        ("show", 3) => (
            <show_0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            show_0_3::Payload::validate_value(&payload).map_err(|e| e.to_string()),
        ),
        ("show", _) => (
            <show::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            show::Payload::validate_value(&payload).map_err(|e| e.to_string()),
        ),
        (other, _) => ("", Err(format!("`{other}` is not a read this task signs"))),
    };
    if let Err(reason) = checked {
        return reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {reason}"),
            },
        );
    }
    let member = doc.payload["member"].as_str().unwrap_or_default();
    let codes = |e: &PcsError| match e {
        PcsError::MemberNotHeld(_) => Some(t::error_codes::MEMBER_NOT_HELD),
        PcsError::MembershipCredentialUnusable => {
            Some(t::error_codes::MEMBERSHIP_CREDENTIAL_UNUSABLE)
        }
        PcsError::MembershipCredentialMismatch => {
            Some(t::error_codes::MEMBERSHIP_CREDENTIAL_MISMATCH)
        }
        _ => None,
    };
    // Item 4 before items 5 – 6: an unheld member is refused before its vault is read.
    if let Err(e) =
        crate::operations::pcs_voter::PersonaTicketSigner::for_member(state, auth, member).await
    {
        return refuse(&doc, e, codes);
    }
    // Items 5 – 6 (VTI-VOT-016): the schema admits both only under 0.6, and only with `show`.
    let presenter = match doc
        .payload
        .get("membershipCredential")
        .and_then(Value::as_str)
    {
        None => None,
        Some(id) => match crate::operations::pcs_voter::MembershipPresenter::check(
            state,
            auth,
            id,
            member,
            doc.payload.get("memberOf").and_then(Value::as_str),
            PcsError::MembershipCredentialMismatch,
        )
        .await
        {
            Ok(p) => Some(p),
            Err(e) => return refuse(&doc, e, codes),
        },
    };
    match crate::operations::pcs_voter::sign_read(
        state,
        auth,
        member,
        &community,
        type_uri,
        payload,
        presenter.as_ref(),
    )
    .await
    {
        // Each version answers through its own response type, naming the reads it signs.
        Ok(document) if version == 2 => {
            respond::<spec::voter::read::v0_2::Response>(&doc, json!({ "document": document }))
        }
        Ok(document) if version == 3 => {
            respond::<spec::voter::read::v0_3::Response>(&doc, json!({ "document": document }))
        }
        Ok(document) => respond::<t::Response>(&doc, json!({ "document": document })),
        Err(e) => refuse(&doc, e, codes),
    }
}

/// `vta/pcs/voter/register/0.5`, whose `ticketDocument` is a `vtc/elections/tickets/issue/0.3`
/// request carrying, under a credential roll, the member's presentation of
/// `membershipCredential` (item 9, VTI-VOT-025); and 0.3 and 0.2, whose manifest has no
/// credential roll and whose `ticketDocument` is a `tickets/issue/0.1` request. The spine holds
/// each to its own version's schema; each answers through its own response type.
#[allow(deprecated)] // vta/pcs/voter/register/0.2 – 0.3: still served
pub(super) async fn handle_voter_register(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::operations::pcs_voter::{MembershipPresenter, TicketVersion};
    use spec::voter::register::v0_5 as t;
    let (context, community) = match voter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let manifest = value_of(&doc, "manifest");
    let current =
        !doc.type_uri.to_string().starts_with(
            <spec::voter::register::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ) && !doc.type_uri.to_string().starts_with(
            <spec::voter::register::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        );
    let version = if current {
        TicketVersion::V0_3
    } else {
        TicketVersion::V0_1
    };
    let codes = |e: &PcsError| match e {
        PcsError::ElectionChanged => Some(t::error_codes::ELECTION_CHANGED),
        PcsError::UnsupportedSuite(_) => Some(t::error_codes::UNSUPPORTED_SUITE),
        PcsError::ParametersInvalid(_) => Some(t::error_codes::PARAMETERS_INVALID),
        PcsError::UnsupportedSecrecy(_) => Some(t::error_codes::UNSUPPORTED_SECRECY),
        PcsError::TicketHeld => Some(t::error_codes::TICKET_HELD),
        PcsError::MemberNotHeld(_) => Some(t::error_codes::MEMBER_NOT_HELD),
        PcsError::MembershipCredentialRequired => {
            Some(t::error_codes::MEMBERSHIP_CREDENTIAL_REQUIRED)
        }
        PcsError::MembershipCredentialUnusable => {
            Some(t::error_codes::MEMBERSHIP_CREDENTIAL_UNUSABLE)
        }
        _ => None,
    };
    // Item 9: the member's key is found, and the caller's standing to act as it checked, before
    // anything is allocated.
    let member_did = doc.payload.get("member").and_then(Value::as_str);
    let member = match member_did {
        None => None,
        Some(did) => {
            match crate::operations::pcs_voter::PersonaTicketSigner::for_member(state, auth, did)
                .await
            {
                Ok(s) => Some(s),
                Err(e) => return refuse(&doc, e, codes),
            }
        }
    };
    // Item 9 (VTI-VOT-025): under a credential roll the member presents the membership
    // credential for `roll.memberOf` that they chose; under any other rule, and without
    // `member`, none is presented. Checked before anything is allocated.
    let credential = doc
        .payload
        .get("membershipCredential")
        .and_then(Value::as_str);
    let member_of = manifest["roll"]["memberOf"].as_str();
    let credential_roll = manifest["roll"]["rule"].as_str() == Some("credential");
    let presenter = match (credential_roll, member_did, credential) {
        (true, Some(m), Some(id)) => match MembershipPresenter::check(
            state,
            auth,
            id,
            m,
            member_of,
            PcsError::MembershipCredentialUnusable,
        )
        .await
        {
            Ok(p) => Some(p),
            Err(e) => return refuse(&doc, e, codes),
        },
        (true, Some(_), None) | (_, None, Some(_)) | (false, _, Some(_)) => {
            return refuse(&doc, PcsError::MembershipCredentialRequired, codes);
        }
        _ => None,
    };
    match crate::operations::pcs_voter::register(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        &manifest,
        member
            .as_ref()
            .map(|s| s as &dyn crate::operations::pcs_voter::TicketSigner),
        version,
        presenter.as_ref(),
    )
    .await
    {
        Ok(answer) => {
            let election = manifest["electionId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            audit(
                state,
                "pcs.voter.register",
                auth,
                &community,
                &context,
                Some(&election),
            )
            .await;
            // Each version answers through its own response type: 0.3's and 0.2's
            // `ticketDocument` is a tickets/issue/0.1 request.
            if current {
                respond::<t::Response>(&doc, answer)
            } else {
                respond::<spec::voter::register::v0_3::Response>(&doc, answer)
            }
        }
        Err(e) => refuse(&doc, e, codes),
    }
}

/// `vta/pcs/voter/accept/0.1`.
pub(super) async fn handle_voter_accept(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::voter::accept::v0_1 as t;
    let (context, community) = match voter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let election = str_of(&doc, "electionId").to_string();
    match crate::operations::pcs_voter::accept(
        state,
        &caller(auth),
        &context,
        &community,
        &election,
        &value_of(&doc, "parameters"),
        &value_of(&doc, "response"),
    )
    .await
    {
        Ok(answer) => {
            audit(
                state,
                "pcs.voter.accept",
                auth,
                &community,
                &context,
                Some(&election),
            )
            .await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::NoRequestInFlight => Some(t::error_codes::NO_REQUEST_IN_FLIGHT),
            PcsError::CredentialInvalid(_) => Some(t::error_codes::CREDENTIAL_INVALID),
            PcsError::ParametersInvalid(_) | PcsError::UnsupportedSuite(_) => {
                Some(t::error_codes::PARAMETERS_INVALID)
            }
            _ => None,
        }),
    }
}

/// `vta/pcs/vote/0.4`, and 0.3 and 0.2 (a manifest without the credential roll; under 0.2 a
/// threshold of at least 10), read and answered as 0.4's types once the spine has held the
/// payload to its own version's schema.
pub(super) async fn handle_vote(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::vote::v0_4 as t;
    let (context, community) = match voter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let manifest = value_of(&doc, "manifest");
    match crate::operations::pcs_voter::vote(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        &manifest,
        &value_of(&doc, "ballot"),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(answer) => {
            // The election, and nothing that names the cast (VTI-VOT-100).
            let election = manifest["electionId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            audit(
                state,
                "pcs.vote",
                auth,
                &community,
                &context,
                Some(&election),
            )
            .await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::ManifestMismatch => Some(t::error_codes::MANIFEST_MISMATCH),
            PcsError::BallotInvalid(_) => Some(t::error_codes::BALLOT_INVALID),
            PcsError::NotOpen => Some(t::error_codes::NOT_OPEN),
            PcsError::ParametersInvalid(_) | PcsError::UnsupportedSuite(_) => {
                Some(t::error_codes::PARAMETERS_INVALID)
            }
            _ => None,
        }),
    }
}

/// `vta/pcs/voter/receipt/0.1`.
pub(super) async fn handle_voter_receipt(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::voter::receipt::v0_1 as t;
    let (context, community) = match voter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let election = str_of(&doc, "electionId").to_string();
    match crate::operations::pcs_voter::receipt(
        state,
        &context,
        &community,
        &election,
        &value_of(&doc, "receipt"),
        doc.payload.get("checkpoint"),
        doc.payload.get("inclusion"),
    )
    .await
    {
        Ok(answer) => {
            audit(
                state,
                "pcs.voter.receipt",
                auth,
                &community,
                &context,
                Some(&election),
            )
            .await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::ReceiptInvalid(_) => Some(t::error_codes::RECEIPT_INVALID),
            PcsError::EvidenceInvalid(_) => Some(t::error_codes::EVIDENCE_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/vote-encrypted/0.5`, and 0.4 and 0.3 (a manifest without the credential roll;
/// under 0.3 a threshold of at least 10): the key formed here from the trustees' signed steps.
/// Each is read and answered as 0.5's types.
pub(super) async fn handle_vote_encrypted(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::vote_encrypted::v0_5 as t;
    let (context, community) = match voter_preamble::<t::Payload>(state, auth, &doc).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let manifest = value_of(&doc, "manifest");
    match crate::operations::pcs_voter::vote_encrypted(
        state,
        &caller(auth),
        &context,
        &community,
        &value_of(&doc, "parameters"),
        &manifest,
        &value_of(&doc, "ceremony"),
        &value_of(&doc, "ballot"),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(answer) => {
            // The election, and nothing that names the cast (VTI-VOT-100).
            let election = manifest["electionId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            audit(
                state,
                "pcs.vote",
                auth,
                &community,
                &context,
                Some(&election),
            )
            .await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::NotFound => Some(t::error_codes::NOT_FOUND),
            PcsError::WrongLevel => Some(t::error_codes::WRONG_LEVEL),
            PcsError::ElectionKeyInvalid(_) => Some(t::error_codes::ELECTION_KEY_INVALID),
            PcsError::BallotInvalid(_) | PcsError::ManifestMismatch => {
                Some(t::error_codes::BALLOT_INVALID)
            }
            PcsError::NotOpen => Some(t::error_codes::NOT_OPEN),
            _ => None,
        }),
    }
}

/// The trustee tasks' common preamble: the capability, the payload against its schema, and
/// standing over the context (`vta/pcs/trustee/*` items 1 – 2).
async fn trustee_preamble<P: DeserializeOwned>(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(String, String, String), TrustTaskOutcome> {
    require_capability(state, auth, doc, Capability::PcsTrustee, "pcs trustee").await?;
    parse_payload::<P>(doc)?;
    let context = str_of(doc, "contextId").to_string();
    require_context(doc, auth, &context)?;
    Ok((
        context,
        str_of(doc, "community").to_string(),
        str_of(doc, "trustee").to_string(),
    ))
}

async fn trustee_audit(
    state: &AppState,
    action: &str,
    auth: &AuthClaims,
    community: &str,
    context: &str,
    doc: &TrustTask<Value>,
) {
    let election = str_of(doc, "electionId").to_string();
    audit(state, action, auth, community, context, Some(&election)).await;
}

/// `vta/pcs/trustee/enrol/0.4`, and 0.3 and 0.2 (a manifest without the credential roll), read
/// and answered as 0.4's types.
pub(super) async fn handle_trustee_enrol(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::trustee::enrol::v0_4 as t;
    let (context, community, trustee) =
        match trustee_preamble::<t::Payload>(state, auth, &doc).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    match crate::operations::pcs_trustee::enrol(
        state,
        &caller(auth),
        auth,
        &context,
        &community,
        &trustee,
        &value_of(&doc, "manifest"),
    )
    .await
    {
        Ok(answer) => {
            trustee_audit(state, "pcs.trustee.enrol", auth, &community, &context, &doc).await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::TrusteeNotHeld(_) => Some(t::error_codes::TRUSTEE_NOT_HELD),
            PcsError::NotTrustee => Some(t::error_codes::NOT_TRUSTEE),
            _ => None,
        }),
    }
}

/// `vta/pcs/trustee/deal/0.5`, and 0.4 and 0.3 (a manifest without the credential roll),
/// read and answered as 0.5's types.
pub(super) async fn handle_trustee_deal(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::trustee::deal::v0_5 as t;
    let (context, community, trustee) =
        match trustee_preamble::<t::Payload>(state, auth, &doc).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    match crate::operations::pcs_trustee::deal_task(
        state,
        &caller(auth),
        auth,
        &context,
        &community,
        &trustee,
        &value_of(&doc, "manifest"),
        &value_of(&doc, "ceremony"),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(answer) => {
            trustee_audit(state, "pcs.trustee.deal", auth, &community, &context, &doc).await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::TrusteeNotHeld(_) => Some(t::error_codes::TRUSTEE_NOT_HELD),
            PcsError::NotEnrolled | PcsError::ElectionChanged => Some(t::error_codes::NOT_ENROLLED),
            PcsError::CeremonyInvalid(_) => Some(t::error_codes::CEREMONY_INVALID),
            PcsError::CeremonyChanged => Some(t::error_codes::CEREMONY_CHANGED),
            _ => None,
        }),
    }
}

/// `vta/pcs/trustee/keys/0.5`, and 0.4 and 0.3 (a manifest without the credential roll),
/// read and answered as 0.5's types.
pub(super) async fn handle_trustee_keys(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::trustee::keys::v0_5 as t;
    let (context, community, trustee) =
        match trustee_preamble::<t::Payload>(state, auth, &doc).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    match crate::operations::pcs_trustee::keys(
        state,
        &caller(auth),
        auth,
        &context,
        &community,
        &trustee,
        &value_of(&doc, "manifest"),
        &value_of(&doc, "ceremony"),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(answer) => {
            trustee_audit(state, "pcs.trustee.keys", auth, &community, &context, &doc).await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::TrusteeNotHeld(_) => Some(t::error_codes::TRUSTEE_NOT_HELD),
            PcsError::NotEnrolled | PcsError::ElectionChanged => Some(t::error_codes::NOT_ENROLLED),
            PcsError::KeyMismatch => Some(t::error_codes::KEY_MISMATCH),
            PcsError::CeremonyInvalid(_) => Some(t::error_codes::CEREMONY_INVALID),
            _ => None,
        }),
    }
}

/// `vta/pcs/trustee/justify/0.5`, and 0.4 and 0.3 (a manifest without the credential roll),
/// read and answered as 0.5's types.
pub(super) async fn handle_trustee_justify(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::trustee::justify::v0_5 as t;
    let (context, community, trustee) =
        match trustee_preamble::<t::Payload>(state, auth, &doc).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    let recipient = doc.payload["recipient"].as_u64().unwrap_or_default() as u32;
    match crate::operations::pcs_trustee::justify(
        state,
        &caller(auth),
        auth,
        &context,
        &community,
        &trustee,
        &value_of(&doc, "manifest"),
        &value_of(&doc, "ceremony"),
        recipient,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(answer) => {
            trustee_audit(
                state,
                "pcs.trustee.justify",
                auth,
                &community,
                &context,
                &doc,
            )
            .await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::TrusteeNotHeld(_) => Some(t::error_codes::TRUSTEE_NOT_HELD),
            PcsError::NoDealing | PcsError::NotEnrolled => Some(t::error_codes::NO_DEALING),
            PcsError::CeremonyInvalid(_) => Some(t::error_codes::CEREMONY_INVALID),
            PcsError::NoComplaint => Some(t::error_codes::NO_COMPLAINT),
            _ => None,
        }),
    }
}

/// `vta/pcs/trustee/read/0.4`: `voting/trustees/status/0.1` or `voting/election/show/0.4`,
/// signed as the trustee (items 3 – 5); 0.3, which signs `voting/election/show/0.3`; and 0.2,
/// which signs `voting/election/show/0.2` — the one difference between them. Keeps nothing, so
/// it is not audited, as `voter/read` is not.
#[allow(deprecated)] // vta/pcs/trustee/read/0.2 – 0.3 and the voting/election/show they sign: still served
pub(super) async fn handle_trustee_read(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::trustee::read::v0_4 as t;
    use vti_specs::voting::election::show::{v0_2 as show_0_2, v0_3 as show_0_3, v0_4 as show};
    let (_context, community, trustee) =
        match trustee_preamble::<t::Payload>(state, auth, &doc).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    let named = doc.type_uri.to_string();
    let signs_show_0_2 = named
        .starts_with(<spec::trustee::read::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI);
    let signs_show_0_3 = named
        .starts_with(<spec::trustee::read::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI);
    let election_show = if signs_show_0_2 {
        <show_0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI
    } else if signs_show_0_3 {
        <show_0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI
    } else {
        <show::Payload as trust_tasks_rs::Payload>::TYPE_URI
    };
    match crate::operations::pcs_trustee::sign_read(
        state,
        auth,
        &trustee,
        &community,
        str_of(&doc, "electionId"),
        str_of(&doc, "ballotBox"),
        str_of(&doc, "read"),
        election_show,
    )
    .await
    {
        // Each version answers through its own response type, naming the show it signs.
        Ok(document) if signs_show_0_2 => {
            respond::<spec::trustee::read::v0_2::Response>(&doc, json!({ "document": document }))
        }
        Ok(document) if signs_show_0_3 => {
            respond::<spec::trustee::read::v0_3::Response>(&doc, json!({ "document": document }))
        }
        Ok(document) => respond::<t::Response>(&doc, json!({ "document": document })),
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::TrusteeNotHeld(_) => Some(t::error_codes::TRUSTEE_NOT_HELD),
            _ => None,
        }),
    }
}

/// `vta/pcs/trustee/decrypt/0.2`: only the targets the community authorized, once.
pub(super) async fn handle_trustee_decrypt(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::trustee::decrypt::v0_2 as t;
    let (context, community, trustee) =
        match trustee_preamble::<t::Payload>(state, auth, &doc).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    match crate::operations::pcs_trustee::decrypt(
        state,
        auth,
        &context,
        &community,
        str_of(&doc, "electionId"),
        &trustee,
        &value_of(&doc, "targets"),
        &value_of(&doc, "authorization"),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(answer) => {
            trustee_audit(
                state,
                "pcs.trustee.decrypt",
                auth,
                &community,
                &context,
                &doc,
            )
            .await;
            respond::<t::Response>(&doc, answer)
        }
        Err(e) => refuse(&doc, e, |e| match e {
            PcsError::TrusteeNotHeld(_) => Some(t::error_codes::TRUSTEE_NOT_HELD),
            PcsError::KeyNotHeld => Some(t::error_codes::KEY_NOT_HELD),
            PcsError::AuthorizationInvalid(_) => Some(t::error_codes::AUTHORIZATION_INVALID),
            PcsError::AlreadyDecrypted => Some(t::error_codes::ALREADY_DECRYPTED),
            _ => None,
        }),
    }
}

#[cfg(test)]
#[path = "pcs_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pcs_voter_tests.rs"]
mod voter_tests;

#[cfg(test)]
#[path = "pcs_trustee_tests.rs"]
mod trustee_tests;
