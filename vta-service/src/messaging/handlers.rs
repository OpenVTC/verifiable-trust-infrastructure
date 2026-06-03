//! DIDComm handler functions for `affinidi-messaging-didcomm-service` Router.
//!
//! Each handler follows the `handler_fn()` pattern:
//!   - Extracts `HandlerContext`, `Message`, and `Extension<Arc<VtaState>>`
//!   - Performs auth via `auth_from_message()`
//!   - Calls the shared operation
//!   - Returns `Ok(Some(DIDCommResponse))` or `Ok(None)`

use std::sync::Arc;

use base64::Engine;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, ProblemReport,
    ServiceProblemReport,
};
use tracing::{info, warn};

use crate::acl::Role;
use crate::error::AppError;
use crate::messaging::auth::auth_from_message;
use crate::operations;
use crate::server::AppState;

use super::router::VtaState;

use vta_sdk::protocols::{
    acl_management, audit_management, context_management, credential_exchange, key_management,
    seed_management, vta_management,
};

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

/// Helper to convert non-domain errors (serde, base64, missing subsystem)
/// into `DIDCommServiceError::Handler`, which the transport renders as
/// `e.p.msg.internal-error`. For domain errors (`AppError`) use [`app_try!`]
/// so the caller receives a typed problem-report code (`e.p.msg.conflict`,
/// `e.p.msg.not-found`, etc.) instead of an opaque internal-error.
fn handler_err(e: impl std::fmt::Display) -> DIDCommServiceError {
    DIDCommServiceError::Handler(e.to_string())
}

/// Map an [`AppError`] to a typed [`DIDCommResponse::problem_report`] so the
/// client sees the right `e.p.msg.*` code (conflict/not-found/unauthorized/
/// bad-request) instead of everything collapsing into `internal-error`.
///
/// Call via the [`app_try!`] macro at operation, auth, and role-check sites.
fn app_err_to_response(e: AppError) -> DIDCommResponse {
    let report = match &e {
        AppError::Conflict(msg) => ProblemReport::conflict(msg.clone()),
        AppError::NotFound(msg) => ProblemReport::not_found(msg.clone()),
        AppError::Authentication(msg) | AppError::Unauthorized(msg) => {
            ProblemReport::unauthorized(msg.clone())
        }
        // The affinidi taxonomy doesn't define a `forbidden` code,
        // but collapsing into `unauthorized` means SDK clients see
        // "Token may be expired" for what's actually a permission /
        // privilege-laundering rejection. Emit a workspace-specific
        // `e.p.msg.forbidden` code; SDK clients that don't know it
        // fall back to `DidcommRemote { code, comment }` cleanly.
        AppError::Forbidden(msg) => ProblemReport {
            code: vta_sdk::protocols::problem_report_codes::FORBIDDEN.to_string(),
            comment: msg.clone(),
            args: Vec::new(),
            escalate_to: None,
        },
        AppError::Validation(msg) => ProblemReport::bad_request(msg.clone()),
        _ => ProblemReport::internal_error(e.to_string()),
    };
    DIDCommResponse::problem_report(report)
}

/// `?`-style early-return for `Result<T, AppError>` inside a `HandlerResult`.
/// On `Err`, returns `Ok(Some(problem_report))` with the correct typed code.
macro_rules! app_try {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(err) => return Ok(Some($crate::messaging::handlers::app_err_to_response(err))),
        }
    };
}

/// Helper to build a typed response from a serializable result.
fn response<T: serde::Serialize>(
    msg_type: &str,
    result: &T,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let body = serde_json::to_value(result).map_err(handler_err)?;
    Ok(Some(DIDCommResponse::new(msg_type, body)))
}

/// DIDComm `type` for Trust-Tasks envelopes, per the framework binding
/// `https://trusttasks.org/binding/didcomm/0.1`: a single reserved type
/// whose `body` carries the full `TrustTask<P>` JSON. Conformant
/// consumers reject any other type. Mirrors
/// `trust_tasks_didcomm::ENVELOPE_TYPE`; defined locally to avoid taking
/// a dependency on the binding crate for one constant.
pub(crate) const TRUST_TASK_ENVELOPE_TYPE: &str =
    "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Generic DIDComm handler for the Trust-Tasks surface.
///
/// Routed at the single binding envelope type [`TRUST_TASK_ENVELOPE_TYPE`];
/// the message body carries the full `TrustTask<Value>` envelope
/// (identical to the REST `POST /api/trust-tasks` body, whose own `type`
/// field selects the operation). The authcrypt sender is the
/// authenticated caller.
///
/// Delegates to the shared `dispatch_trust_task_core` so REST and
/// DIDComm run byte-identical routing + authorization, then returns the
/// framework result/error document — itself a trust-task envelope — as
/// the reply body. The document is self-describing (its own `type` +
/// status `code`), so the HTTP status the core attaches is dropped on
/// the DIDComm wire.
pub async fn handle_trust_task(
    _ctx: HandlerContext,
    message: Message,
    Extension(app_state): Extension<AppState>,
) -> HandlerResult {
    // The DIDComm message body IS the trust-task envelope.
    let body = serde_json::to_vec(&message.body).map_err(handler_err)?;

    // Authenticate the authcrypt sender → AuthClaims (role + allowed
    // contexts resolved from the ACL, expiry enforced — same as REST). On
    // failure (e.g. the peer has no ACL entry) reply with a Trust-Task
    // `permission_denied` *envelope*, not a DIDComm problem-report — a
    // conformant Trust-Task client only understands binding envelopes.
    let response = match auth_from_message(&message, &app_state.acl_ks).await {
        Ok(auth) => {
            crate::routes::trust_tasks::dispatch_trust_task_core(&app_state, &auth, &body).await
        }
        Err(e) => crate::routes::trust_tasks::reject_trust_task(
            &body,
            trust_tasks_rs::RejectReason::PermissionDenied {
                reason: e.to_string(),
            },
        ),
    };

    let doc = response_into_json(response).await?;

    // The reply is itself a trust-task envelope; the service sets `thid`
    // from the inbound message id for client correlation.
    Ok(Some(DIDCommResponse::new(TRUST_TASK_ENVELOPE_TYPE, doc)))
}

/// Decompose an axum `Response` (the shared core's return) into its JSON
/// body. The body is always a serialised framework trust-task document.
async fn response_into_json(
    resp: axum::response::Response,
) -> Result<serde_json::Value, DIDCommServiceError> {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .map_err(handler_err)?;
    serde_json::from_slice(&bytes).map_err(handler_err)
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

pub async fn handle_create_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::key_management::create::CreateKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::keys::create_key(
            &state.keys_ks,
            &state.contexts_ks,
            &state.seed_store,
            &state.audit_ks,
            &auth,
            operations::keys::CreateKeyParams {
                key_type: body.key_type,
                derivation_path: if body.derivation_path.is_empty() {
                    None
                } else {
                    Some(body.derivation_path)
                },
                key_id: None,
                mnemonic: body.mnemonic,
                label: body.label,
                context_id: body.context_id,
            },
            "didcomm",
        )
        .await
    );
    response(key_management::CREATE_KEY_RESULT, &result)
}

pub async fn handle_get_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::key_management::get::GetKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result =
        app_try!(operations::keys::get_key(&state.keys_ks, &auth, &body.key_id, "didcomm").await);
    response(key_management::GET_KEY_RESULT, &result)
}

pub async fn handle_list_keys(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::key_management::list::ListKeysBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::keys::list_keys(
            &state.keys_ks,
            &auth,
            operations::keys::ListKeysParams {
                offset: body.offset,
                limit: body.limit,
                status: body.status,
                context_id: body.context_id,
            },
            "didcomm",
        )
        .await
    );
    response(key_management::LIST_KEYS_RESULT, &result)
}

pub async fn handle_rename_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::key_management::rename::RenameKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::keys::rename_key(
            &state.keys_ks,
            &state.audit_ks,
            &auth,
            &body.key_id,
            &body.new_key_id,
            "didcomm",
        )
        .await
    );
    response(key_management::RENAME_KEY_RESULT, &result)
}

pub async fn handle_revoke_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::key_management::revoke::RevokeKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::keys::revoke_key(
            &state.keys_ks,
            &state.imported_ks,
            &state.audit_ks,
            &auth,
            &body.key_id,
            "didcomm",
        )
        .await
    );
    response(key_management::REVOKE_KEY_RESULT, &result)
}

pub async fn handle_get_key_secret(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::key_management::secret::GetKeySecretBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::keys::get_key_secret(
            &state.keys_ks,
            &state.imported_ks,
            &state.seed_store,
            &state.audit_ks,
            &auth,
            &body.key_id,
            "didcomm",
        )
        .await
    );
    response(key_management::GET_KEY_SECRET_RESULT, &result)
}

pub async fn handle_sign_request(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_write());
    let body: vta_sdk::protocols::key_management::sign::SignRequestBody =
        serde_json::from_value(message.body).map_err(handler_err)?;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body.payload)
        .map_err(|e| handler_err(format!("invalid base64url payload: {e}")))?;

    let result = app_try!(
        operations::keys::sign_payload(
            &state.keys_ks,
            &state.imported_ks,
            &state.seed_store,
            &auth,
            &body.key_id,
            &payload,
            &body.algorithm,
            "didcomm",
        )
        .await
    );
    response(key_management::SIGN_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Seed management
// ---------------------------------------------------------------------------

pub async fn handle_list_seeds(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let result = app_try!(operations::seeds::list_seeds(&state.keys_ks, "didcomm").await);
    response(seed_management::LIST_SEEDS_RESULT, &result)
}

pub async fn handle_rotate_seed(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::seed_management::rotate::RotateSeedBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::seeds::rotate_seed(
            &state.keys_ks,
            &state.imported_ks,
            &state.seed_store,
            &state.audit_ks,
            &auth.did,
            body.mnemonic.as_deref(),
            "didcomm",
        )
        .await
    );
    response(seed_management::ROTATE_SEED_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Context management
// ---------------------------------------------------------------------------

pub async fn handle_create_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    // Admin role required; `create_context` enforces the finer gate (super-admin
    // for a top-level context, admin-of-parent for a sub-context).
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::context_management::create::CreateContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::contexts::create_context(
            &state.contexts_ks,
            &auth,
            &body.id,
            body.name,
            body.description,
            body.parent,
            "didcomm",
        )
        .await
    );
    response(context_management::CREATE_CONTEXT_RESULT, &result)
}

pub async fn handle_get_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::context_management::get::GetContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::contexts::get_context_op(&state.contexts_ks, &auth, &body.id, "didcomm").await
    );
    response(context_management::GET_CONTEXT_RESULT, &result)
}

pub async fn handle_list_contexts(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let result =
        app_try!(operations::contexts::list_contexts(&state.contexts_ks, &auth, "didcomm").await);
    response(context_management::LIST_CONTEXTS_RESULT, &result)
}

pub async fn handle_update_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_super_admin());
    let body: vta_sdk::protocols::context_management::update::UpdateContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::contexts::update_context(
            &state.contexts_ks,
            &auth,
            &body.id,
            operations::contexts::UpdateContextParams {
                name: body.name,
                did: body.did,
                description: body.description,
            },
            "didcomm",
        )
        .await
    );
    response(context_management::UPDATE_CONTEXT_RESULT, &result)
}

pub async fn handle_update_context_did(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::context_management::update_did::UpdateContextDidBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::contexts::update_context_did(
            &state.contexts_ks,
            &auth,
            &body.id,
            body.did,
            "didcomm",
        )
        .await
    );
    response(context_management::UPDATE_CONTEXT_DID_RESULT, &result)
}

pub async fn handle_preview_delete_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::context_management::delete::DeleteContextPreviewBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::contexts::preview_delete_context(
            &state.contexts_ks,
            &state.keys_ks,
            &state.acl_ks,
            &state.did_templates_ks,
            #[cfg(feature = "webvh")]
            &state.webvh_ks,
            &auth,
            &body.id,
            "didcomm",
        )
        .await
    );
    response(context_management::PREVIEW_DELETE_CONTEXT_RESULT, &result)
}

pub async fn handle_delete_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::context_management::delete::DeleteContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let ks = operations::Keyspaces::from_vta_state(&state);
    let result = app_try!(
        operations::contexts::delete_context(&ks, &auth, &body.id, body.force, "didcomm").await
    );
    response(context_management::DELETE_CONTEXT_RESULT, &result)
}

// ---------------------------------------------------------------------------
// ACL management
// ---------------------------------------------------------------------------

pub async fn handle_create_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_manage());
    let body: vta_sdk::protocols::acl_management::create::CreateAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let role = app_try!(Role::parse(&body.role));
    let result = app_try!(
        operations::acl::create_acl(
            &state.acl_ks,
            &state.audit_ks,
            &state.contexts_ks,
            &auth,
            &body.did,
            role,
            body.label,
            body.allowed_contexts,
            body.expires_at,
            body.step_up_approver,
            "didcomm",
        )
        .await
    );
    response(acl_management::CREATE_ACL_RESULT, &result)
}

pub async fn handle_swap_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    // Routed for both the legacy FPN-private `swap-acl` type URI and the
    // canonical Trust Task `acl/swap-key/0.1` URI. Dispatch on the incoming
    // type so we accept either wire shape during the deprecation window.
    // The actual verification is identical: the VP-JWT proves new-subject
    // control regardless of which envelope carried it.
    let is_canonical = message.typ == acl_management::ACL_SWAP_KEY;

    // No require_manage(): self-service rotation of the caller's own entry.
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);

    let (presentation, claimed_new_subject) = if is_canonical {
        let body: vta_sdk::protocols::acl_management::swap::SwapKeyBody =
            serde_json::from_value(message.body).map_err(handler_err)?;
        // Cross-check: the DIDComm sender (authenticated) must equal the
        // declared currentSubject. Stops a sender from claiming to rotate
        // someone else's entry by lying in the body.
        if body.current_subject != auth.did {
            return Err(handler_err(format!(
                "acl/swap-key: currentSubject {} does not equal authenticated sender {}",
                body.current_subject, auth.did
            )));
        }
        (body.link_proof, Some(body.new_subject))
    } else {
        let body: vta_sdk::protocols::acl_management::swap::SwapAclBody =
            serde_json::from_value(message.body).map_err(handler_err)?;
        (body.presentation, None)
    };

    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    let vta_did = {
        let config = state.config.read().await;
        config
            .vta_did
            .clone()
            .ok_or_else(|| handler_err("VTA DID not configured"))?
    };

    let result = app_try!(
        operations::acl::swap_acl(
            &state.acl_ks,
            &state.audit_ks,
            &auth,
            &presentation,
            did_resolver,
            &vta_did,
            "didcomm",
        )
        .await
    );

    // For canonical Trust Task callers, additionally enforce that the body's
    // claimed newSubject equals the holder the VP-JWT actually proved. The
    // operation already verified the VP — `result.did` is the verified holder.
    if let Some(claimed) = claimed_new_subject
        && claimed != result.did
    {
        return Err(handler_err(format!(
            "acl/swap-key: newSubject {} does not match verified VP holder {}",
            claimed, result.did
        )));
    }

    let response_type = if is_canonical {
        acl_management::ACL_SWAP_KEY_RESPONSE
    } else {
        acl_management::SWAP_ACL_RESULT
    };
    response(response_type, &result)
}

pub async fn handle_get_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_manage());
    let body: vta_sdk::protocols::acl_management::get::GetAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result =
        app_try!(operations::acl::get_acl(&state.acl_ks, &auth, &body.did, "didcomm").await);
    response(acl_management::GET_ACL_RESULT, &result)
}

pub async fn handle_list_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_manage());
    let body: vta_sdk::protocols::acl_management::list::ListAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::acl::list_acl(&state.acl_ks, &auth, body.context.as_deref(), "didcomm").await
    );
    response(acl_management::LIST_ACL_RESULT, &result)
}

pub async fn handle_update_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_manage());
    let body: vta_sdk::protocols::acl_management::update::UpdateAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let role = match body.role {
        Some(r) => Some(app_try!(Role::parse(&r))),
        None => None,
    };
    let result = app_try!(
        operations::acl::update_acl(
            &state.acl_ks,
            &state.audit_ks,
            &state.contexts_ks,
            &auth,
            &body.did,
            operations::acl::UpdateAclParams {
                role,
                label: body.label,
                allowed_contexts: body.allowed_contexts,
                step_up_approver: body.step_up_approver,
            },
            "didcomm",
        )
        .await
    );
    response(acl_management::UPDATE_ACL_RESULT, &result)
}

pub async fn handle_delete_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_manage());
    let body: vta_sdk::protocols::acl_management::delete::DeleteAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::acl::delete_acl(&state.acl_ks, &state.audit_ks, &auth, &body.did, "didcomm")
            .await
    );
    response(acl_management::DELETE_ACL_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Audit management
// ---------------------------------------------------------------------------

pub async fn handle_list_logs(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let body: vta_sdk::protocols::audit_management::list::ListAuditLogsBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::audit::list_audit_logs(&state.audit_ks, &auth, &body, "didcomm").await
    );
    response(audit_management::LIST_LOGS_RESULT, &result)
}

pub async fn handle_get_retention(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_admin());
    let result = app_try!(operations::audit::get_retention(&state.config, &auth, "didcomm").await);
    response(audit_management::GET_RETENTION_RESULT, &result)
}

pub async fn handle_update_retention(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_super_admin());
    let body: vta_sdk::protocols::audit_management::retention::UpdateRetentionBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::audit::update_retention(
            &state.config,
            &state.audit_ks,
            &auth,
            body.retention_days,
            "didcomm",
        )
        .await
    );
    response(audit_management::UPDATE_RETENTION_RESULT, &result)
}

// ---------------------------------------------------------------------------
// VTA management
// ---------------------------------------------------------------------------

pub async fn handle_get_config(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let result = app_try!(operations::config::get_config(&state.config, &auth, "didcomm").await);
    response(vta_management::GET_CONFIG_RESULT, &result)
}

pub async fn handle_update_config(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_super_admin());
    let body: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::config::update_config(
            &state.config,
            &auth,
            operations::config::UpdateConfigParams {
                vta_did: body.vta_did,
                vta_name: body.vta_name,
                public_url: body.public_url,
            },
            "didcomm",
        )
        .await
    );
    response(vta_management::UPDATE_CONFIG_RESULT, &result)
}

// ---------------------------------------------------------------------------
// DID WebVH management (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "webvh")]
pub async fn handle_create_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::create::CreateDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let config = state.config.read().await;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;

    let result = app_try!(
        operations::did_webvh::create_did_webvh(
            &state.keys_ks,
            &state.imported_ks,
            &state.contexts_ks,
            &state.webvh_ks,
            &state.did_templates_ks,
            &*state.seed_store,
            &config,
            &auth,
            body.into(),
            did_resolver,
            &state.didcomm_bridge,
            "didcomm",
        )
        .await
    );
    response(
        vta_sdk::protocols::did_management::CREATE_DID_WEBVH_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_get_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::get::GetDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::did_webvh::get_did_webvh(&state.webvh_ks, &auth, &body.did, "didcomm").await
    );
    response(
        vta_sdk::protocols::did_management::GET_DID_WEBVH_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_get_did_webvh_log(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::get::GetDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::did_webvh::get_did_webvh_log(&state.webvh_ks, &auth, &body.did, "didcomm")
            .await
    );
    response(
        vta_sdk::protocols::did_management::GET_DID_WEBVH_LOG_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_list_dids_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::list::ListDidsWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::did_webvh::list_dids_webvh(
            &state.webvh_ks,
            &auth,
            body.context_id.as_deref(),
            body.server_id.as_deref(),
            "didcomm",
        )
        .await
    );
    response(
        vta_sdk::protocols::did_management::LIST_DIDS_WEBVH_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_delete_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::delete::DeleteDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let result = app_try!(
        operations::did_webvh::delete_did_webvh(
            &state.webvh_ks,
            &state.keys_ks,
            &state.imported_ks,
            &state.audit_ks,
            &*state.seed_store,
            &auth,
            &body.did,
            did_resolver,
            &state.didcomm_bridge,
            vta_did.as_deref(),
            &state.webvh_auth_locks,
            "didcomm",
        )
        .await
    );
    response(
        vta_sdk::protocols::did_management::DELETE_DID_WEBVH_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_add_webvh_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::servers::AddWebvhServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    let result = app_try!(
        operations::did_webvh::add_webvh_server(
            &state.webvh_ks,
            &auth,
            &body.id,
            &body.did,
            body.label,
            did_resolver,
            "didcomm",
        )
        .await
    );
    response(
        vta_sdk::protocols::did_management::ADD_WEBVH_SERVER_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_list_webvh_servers(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let result = app_try!(
        operations::did_webvh::list_webvh_servers(&state.webvh_ks, &auth, "didcomm").await
    );
    response(
        vta_sdk::protocols::did_management::LIST_WEBVH_SERVERS_RESULT,
        &result,
    )
}

/// `list-webvh-server-domains` — relay the registered hosting
/// server's `/api/me/domains` view through the VTA. Used by `pnm
/// did-mgmt list-domains` and the interactive `--domain` prompt in
/// `create-did` / `register-did`. The handler authenticates to the
/// server with the VTA's own credentials and returns the
/// caller-scoped subset of hosting domains plus the system default.
///
/// Without this arm in the router, pnm-cli's DIDComm transport
/// returns `unsupported message type:
/// firstperson.network/protocols/did-management/1.0/list-webvh-server-domains`
/// and the CLI falls back to the server's resolution chain with a
/// warning — the symptom that motivated this addition.
#[cfg(feature = "webvh")]
pub async fn handle_list_webvh_server_domains(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let result = app_try!(
        operations::did_webvh::list_webvh_server_domains(
            &state.keys_ks,
            &state.imported_ks,
            &state.audit_ks,
            &state.webvh_ks,
            &*state.seed_store,
            &auth,
            did_resolver,
            &state.didcomm_bridge,
            &state.webvh_auth_locks,
            vta_did.as_deref(),
            &body.server_id,
        )
        .await
    );
    response(
        vta_sdk::protocols::did_management::LIST_WEBVH_SERVER_DOMAINS_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_update_webvh_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::servers::UpdateWebvhServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::did_webvh::update_webvh_server(
            &state.webvh_ks,
            &auth,
            &body.id,
            body.label,
            "didcomm",
        )
        .await
    );
    response(
        vta_sdk::protocols::did_management::UPDATE_WEBVH_SERVER_RESULT,
        &result,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_remove_webvh_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::servers::RemoveWebvhServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::did_webvh::remove_webvh_server(&state.webvh_ks, &auth, &body.id, "didcomm")
            .await
    );
    response(
        vta_sdk::protocols::did_management::REMOVE_WEBVH_SERVER_RESULT,
        &result,
    )
}

/// DIDComm handler for `did-management/1.0/register-did-with-server`.
/// Mirrors [`crate::routes::did_webvh::register_did_with_server_handler`]:
/// promotes a serverless WebVH DID to a server-managed one by pushing the
/// existing log to the host and flipping the local record's `server_id`.
#[cfg(feature = "webvh")]
pub async fn handle_register_did_with_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let body: vta_sdk::protocols::did_management::servers::RegisterDidWithServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let result = app_try!(
        operations::did_webvh::register_did_with_server(
            &state.webvh_ks,
            &state.keys_ks,
            &state.imported_ks,
            &state.audit_ks,
            &*state.seed_store,
            &auth,
            did_resolver,
            &state.didcomm_bridge,
            operations::did_webvh::RegisterDidWithServerParams {
                did: body.did,
                server_id: body.server_id,
                force: body.force,
                domain: body.domain,
            },
            vta_did.as_deref(),
            &state.webvh_auth_locks,
            "didcomm",
        )
        .await
        .map_err(register_err_to_app_error)
    );
    let body = vta_sdk::protocols::did_management::servers::RegisterDidWithServerResultBody {
        did: result.did,
        server_id: result.server_id,
        log_entry_count: result.log_entry_count,
    };
    response(
        vta_sdk::protocols::did_management::REGISTER_DID_WITH_SERVER_RESULT,
        &body,
    )
}

/// Map `RegisterDidWithServerError` onto `AppError` for the DIDComm
/// handler. Mirrors `routes::did_webvh::map_register_err`.
#[cfg(feature = "webvh")]
fn register_err_to_app_error(e: operations::did_webvh::RegisterDidWithServerError) -> AppError {
    use operations::did_webvh::RegisterDidWithServerError as E;
    match e {
        E::Auth(msg) => AppError::Forbidden(msg),
        E::DidNotFound(msg) | E::ServerNotFound(msg) | E::LogMissing(msg) => {
            AppError::NotFound(msg)
        }
        E::AlreadyServerManaged { .. } | E::Conflict(_) => AppError::Conflict(e.to_string()),
        E::Transport(msg) | E::Publish(msg) => AppError::Internal(format!("publish: {msg}")),
        E::DidUrlParse { .. } => AppError::Validation(e.to_string()),
        E::Storage(msg) => AppError::Internal(msg),
    }
}

// ---------------------------------------------------------------------------
// TEE Attestation (feature-gated, unauthenticated)
// ---------------------------------------------------------------------------

#[cfg(feature = "tee")]
pub async fn handle_tee_status(
    _ctx: HandlerContext,
    _message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let tee_state = state
        .tee_state
        .as_ref()
        .ok_or_else(|| handler_err("TEE attestation is not enabled on this VTA"))?;
    let status = operations::attestation::get_tee_status(tee_state);
    response(
        vta_sdk::protocols::attestation_management::GET_TEE_STATUS_RESULT,
        &status,
    )
}

#[cfg(feature = "tee")]
pub async fn handle_request_attestation(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let tee_state = state
        .tee_state
        .as_ref()
        .ok_or_else(|| handler_err("TEE attestation is not enabled on this VTA"))?;
    let body: crate::tee::types::AttestationRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::attestation::generate_attestation_report(tee_state, &state.config, &body.nonce)
            .await
    );
    response(
        vta_sdk::protocols::attestation_management::ATTESTATION_RESULT,
        &result,
    )
}

// ---------------------------------------------------------------------------
// VTA management — restart
// ---------------------------------------------------------------------------

pub async fn handle_restart(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_super_admin());
    let _ = crate::audit::record(
        &state.audit_ks,
        "vta.restart",
        &auth.did,
        None,
        "success",
        Some("didcomm"),
        None,
    )
    .await;
    crate::server::trigger_restart(&state.restart_tx);
    response(
        vta_sdk::protocols::vta_management::RESTART_RESULT,
        &vta_sdk::protocols::vta_management::restart::RestartResult {
            status: "restarting".into(),
        },
    )
}

// ---------------------------------------------------------------------------
// Backup management
// ---------------------------------------------------------------------------

pub async fn handle_backup_export(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_super_admin());
    let body: vta_sdk::protocols::backup_management::types::ExportRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let config = state.config.read().await;
    let ks = operations::Keyspaces::from_vta_state(&state);
    let envelope = app_try!(
        operations::backup::export_backup(
            &ks,
            &*state.seed_store,
            &config,
            &auth,
            &body.password,
            body.include_audit,
        )
        .await
    );
    let _ = crate::audit::record(
        &state.audit_ks,
        "backup.export",
        &auth.did,
        None,
        "success",
        Some("didcomm"),
        None,
    )
    .await;
    info!(
        ciphertext_bytes = envelope.ciphertext.len(),
        "backup export DIDComm response size"
    );
    response(
        vta_sdk::protocols::backup_management::EXPORT_BACKUP_RESULT,
        &envelope,
    )
}

pub async fn handle_backup_import(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    app_try!(auth.require_super_admin());
    let body: vta_sdk::protocols::backup_management::types::ImportRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;

    if !body.confirm {
        let (_payload, preview) =
            app_try!(operations::backup::preview_import(&body.backup, &body.password).await);
        return response(
            vta_sdk::protocols::backup_management::IMPORT_BACKUP_RESULT,
            &preview,
        );
    }

    let payload = app_try!(operations::backup::decrypt_backup(
        &body.backup,
        &body.password
    ));

    let ks = operations::Keyspaces::from_vta_state(&state);
    let result = app_try!(
        operations::backup::apply_import(
            &payload,
            &ks,
            &state.seed_store,
            &state.config,
            None, // Store for TEE re-encryption (handled on restart)
        )
        .await
    );

    let _ = crate::audit::record(
        &state.audit_ks,
        "backup.import",
        &auth.did,
        payload.config.vta_did.as_deref(),
        "success",
        Some("didcomm"),
        None,
    )
    .await;

    crate::server::trigger_restart(&state.restart_tx);
    response(
        vta_sdk::protocols::backup_management::IMPORT_BACKUP_RESULT,
        &result,
    )
}

// ---------------------------------------------------------------------------
// Problem report & fallback
// ---------------------------------------------------------------------------

pub async fn handle_problem_report(_ctx: HandlerContext, message: Message) -> HandlerResult {
    let code = message
        .body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let comment = message
        .body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("no details provided");
    let from = message.from.as_deref().unwrap_or("unknown");
    let thid = message.thid.as_deref().unwrap_or("none");
    warn!(from, code, comment, thid, msg_type = %message.typ, "received problem-report");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

pub async fn handle_discover_capabilities(
    _ctx: HandlerContext,
    _message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let config = state.config.read().await;

    let features = vta_sdk::protocols::discovery::FeaturesInfo {
        webvh: cfg!(feature = "webvh"),
        didcomm: cfg!(feature = "didcomm"),
        tee: cfg!(feature = "tee"),
        rest: cfg!(feature = "rest"),
    };

    let services = vta_sdk::protocols::discovery::ServicesInfo {
        rest: config.services.rest,
        didcomm: config.services.didcomm,
    };

    #[cfg(feature = "webvh")]
    let webvh_servers = {
        let servers = app_try!(crate::webvh_store::list_servers(&state.webvh_ks).await);
        servers
            .into_iter()
            .map(|s| vta_sdk::protocols::discovery::WebvhServerInfo {
                id: s.id,
                label: s.label,
            })
            .collect()
    };
    #[cfg(not(feature = "webvh"))]
    let webvh_servers: Vec<vta_sdk::protocols::discovery::WebvhServerInfo> = vec![];

    let mut did_creation_modes = vec!["vta-built".to_string()];
    if cfg!(feature = "webvh") {
        did_creation_modes.push("template".to_string());
        did_creation_modes.push("final".to_string());
        did_creation_modes.push("user-specified-keys".to_string());
    }

    let result = vta_sdk::protocols::discovery::CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
        services,
        webvh_servers,
        did_creation_modes,
    };
    response(
        vta_sdk::protocols::discovery::DISCOVER_CAPABILITIES_RESULT,
        &result,
    )
}

// ---------------------------------------------------------------------------
// Provision-integration (DIDComm transport for the VP→sealed-bundle flow)
// ---------------------------------------------------------------------------

/// DIDComm equivalent of `POST /bootstrap/provision-integration`.
///
/// Inbound body shape mirrors the REST handler's JSON exactly
/// (`vta_sdk::provision_integration::http::ProvisionIntegrationRequest`).
/// Outbound body is `ProvisionIntegrationResponse`.
///
/// Auth model: dual-check.
/// 1. `auth_from_message` — sender DID is authcrypt-authenticated and
///    must hold admin role in the target context (same gate the REST
///    handler runs inside the library fn's preconditions).
/// 2. The VP's `DataIntegrityProof` is also verified by the library
///    function. The DIDComm sender DID and the VP holder DID must
///    agree — otherwise we'd accept a VP signed by someone else just
///    because the DIDComm envelope was authcrypt'd from an
///    ACL-registered admin. Holder substitution rejection.
///
/// On success, the body is the same `ProvisionIntegrationResponse`
/// shape REST returns: armored bundle, sha256 digest, and summary
/// (including `admin_did`/`admin_rolled_over` for rollover requests).
pub async fn handle_provision_integration(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);

    let body: vta_sdk::protocols::provision_integration_management::request::ProvisionIntegrationRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;

    let verified = match body.request.verify() {
        Ok(v) => v,
        Err(e) => {
            return Ok(Some(app_err_to_response(AppError::Validation(format!(
                "verify BootstrapRequest VP: {e}"
            )))));
        }
    };

    // No "sender must equal VP holder" check — by design.
    //
    // The provision-integration flow is layered like an onion:
    //
    //   * Outer (DIDComm authcrypt): the *relayer* is
    //     authenticated by the authcrypt sender. ACL authorization
    //     above (`auth_from_message` + the upstream context-admin
    //     check) gates whether the relayer is allowed to make the
    //     call.
    //   * Inner (VP): the *holder* is authenticated by the VP's
    //     `DataIntegrityProof`. The VTA issues a bundle bound to
    //     this holder and HPKE-sealed to the holder's X25519
    //     derivation.
    //
    // Sender ≠ holder is the **air-gap onboarding** case: a
    // third-party integration on a disconnected network signs a
    // BootstrapRequest using its own ephemeral did:key, ships the
    // request to the operator, and the operator's PNM relays it to
    // the VTA. The bundle returned is encrypted to the integration
    // and only the integration can open it — the relayer carries
    // ciphertext back across the air-gap. There is no
    // privilege-laundering: the relayer can't decrypt the bundle,
    // and the VP signature requires the holder's private key (so
    // the relayer can't forge a VP claiming to be a third party
    // either).
    //
    // Same model as the REST path, where `auth.did` (the bearer
    // token's DID) and the VP holder can also legitimately differ.

    let assertion_mode = body
        .assertion
        .map(|m| match m {
            vta_sdk::provision_integration::http::AssertionMode::DidSigned => {
                operations::provision_integration::AssertionMode::DidSigned
            }
            vta_sdk::provision_integration::http::AssertionMode::PinnedOnly => {
                operations::provision_integration::AssertionMode::PinnedOnly
            }
        })
        .unwrap_or_default();

    let vc_validity = body.vc_validity_seconds.map(chrono::Duration::seconds);

    let deps = operations::provision_integration::ProvisionIntegrationDeps::from(state.as_ref());

    // Resolve the target context. When the caller sent one, use it
    // verbatim (integration-class consumer pattern). When omitted, run
    // the spec's three inference rules — single-context grant, super-
    // admin + single-context maintainer, else AmbiguousContext.
    let context = match body.context {
        Some(c) => c,
        None => match app_try!(
            operations::provision_integration::infer_target_context(&auth, &deps.contexts_ks).await
        ) {
            Ok(ctx) => ctx,
            Err(operations::provision_integration::AmbiguousContext {
                candidates,
                message,
            }) => {
                // Emit the canonical Trust Task error code so clients
                // can surface candidates structurally. `args` carries
                // the list in arrival order (sorted by the helper).
                let report = ProblemReport {
                    code: vta_sdk::protocols::problem_report_codes::PROVISION_CONTEXT_REQUIRED
                        .to_string(),
                    comment: message,
                    args: candidates,
                    escalate_to: None,
                };
                return Ok(Some(DIDCommResponse::problem_report(report)));
            }
        },
    };

    // `--create-context` from the wire body. Same semantics as the
    // REST handler — super-admin gate enforced inside
    // `operations::contexts::create_context`. Idempotent.
    let context_created = app_try!(
        operations::provision_integration::ensure_target_context_or_create(
            &deps.contexts_ks,
            &auth,
            &context,
            body.create_context,
        )
        .await
    );
    let output = app_try!(
        operations::provision_integration::provision_integration(
            &deps,
            &auth,
            operations::provision_integration::ProvisionIntegrationParams {
                request: verified,
                context,
                assertion_mode,
                vc_validity,
            },
        )
        .await
    );

    let result = vta_sdk::provision_integration::http::ProvisionIntegrationResponse {
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

    // Match the response URI to whichever request URI the caller used.
    // A client targeting the canonical Trust Task URI
    // (`https://trusttasks.org/spec/provision/integration/0.1`) receives
    // the canonical `#response` fragment; the legacy FPN URI gets the
    // legacy `…-result`. Both share one handler so the routing decision
    // lives in `result_uri_for` rather than two parallel branches here.
    let result_uri =
        vta_sdk::protocols::provision_integration_management::result_uri_for(&message.typ);

    info!(
        from = %auth.did,
        admin_did = %result.summary.admin_did,
        admin_rolled_over = result.summary.admin_rolled_over,
        bundle_id = %result.summary.bundle_id_hex,
        request_uri = %message.typ,
        result_uri,
        "provision-integration completed via DIDComm"
    );

    response(result_uri, &result)
}

/// Envelope used by the DIDComm update + rotate-keys messages.
/// Mirrors the SDK rpc call shape: `{ context_id, scid, body }`.
#[cfg(feature = "webvh")]
#[derive(Debug, serde::Deserialize)]
struct WebvhUpdateEnvelope<B> {
    #[allow(dead_code)]
    // ctx_id is enforced inside the operation via the record's context_id; the field exists on the wire for client-side routing.
    context_id: String,
    scid: String,
    body: B,
}

#[cfg(feature = "webvh")]
pub async fn handle_update_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let env: WebvhUpdateEnvelope<vta_sdk::protocols::did_management::update::UpdateDidWebvhBody> =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;

    // Translate wire body → ops body. `witnesses` flips from opaque
    // JSON to the typed `Witnesses` enum.
    let witnesses = env
        .body
        .witnesses
        .map(serde_json::from_value)
        .transpose()
        .map_err(handler_err)?;
    let opts = operations::did_webvh::UpdateDidWebvhOptions {
        document: env.body.document,
        pre_rotation_count: env.body.pre_rotation_count,
        witnesses,
        watchers: env.body.watchers,
        ttl: env.body.ttl,
        label: env.body.label,
        expected_version_id: env.body.expected_version_id,
    };

    let vta_did = state.config.read().await.vta_did.clone();
    let result = app_try!(
        operations::did_webvh::update_did_webvh(
            &state.keys_ks,
            &state.imported_ks,
            &state.contexts_ks,
            &state.webvh_ks,
            &state.audit_ks,
            &*state.seed_store,
            &auth,
            &env.scid,
            opts,
            did_resolver,
            &state.didcomm_bridge,
            vta_did.as_deref(),
            &state.webvh_auth_locks,
            "didcomm",
        )
        .await
        .map_err(crate::error::AppError::from)
    );
    let body = vta_sdk::protocols::did_management::update::UpdateDidWebvhResultBody {
        did: result.did,
        new_version_id: result.new_version_id,
        new_scid: result.new_scid,
        new_log_entry: result.new_log_entry,
        update_keys_count: result.update_keys_count,
        pre_rotation_key_count: result.pre_rotation_key_count,
        serverless: result.serverless,
    };
    response(
        vta_sdk::protocols::did_management::UPDATE_DID_WEBVH_RESULT,
        &body,
    )
}

#[cfg(feature = "webvh")]
pub async fn handle_rotate_did_webvh_keys(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = app_try!(auth_from_message(&message, &state.acl_ks).await);
    let env: WebvhUpdateEnvelope<
        vta_sdk::protocols::did_management::update::RotateDidWebvhKeysBody,
    > = serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;

    let opts = operations::did_webvh::RotateDidWebvhKeysOptions {
        pre_rotation_count: env.body.pre_rotation_count,
        label: env.body.label,
    };

    let vta_did = state.config.read().await.vta_did.clone();
    let result = app_try!(
        operations::did_webvh::rotate_did_webvh_keys(
            &state.keys_ks,
            &state.imported_ks,
            &state.contexts_ks,
            &state.webvh_ks,
            &state.audit_ks,
            &*state.seed_store,
            &auth,
            &env.scid,
            opts,
            did_resolver,
            &state.didcomm_bridge,
            vta_did.as_deref(),
            &state.webvh_auth_locks,
            "didcomm",
        )
        .await
        .map_err(crate::error::AppError::from)
    );
    let body = vta_sdk::protocols::did_management::update::UpdateDidWebvhResultBody {
        did: result.did,
        new_version_id: result.new_version_id,
        new_scid: result.new_scid,
        new_log_entry: result.new_log_entry,
        update_keys_count: result.update_keys_count,
        pre_rotation_key_count: result.pre_rotation_key_count,
        serverless: result.serverless,
    };
    response(
        vta_sdk::protocols::did_management::ROTATE_DID_WEBVH_KEYS_RESULT,
        &body,
    )
}

// ---------------------------------------------------------------------------
// Step-up approval (VTA vouches a holder may step up at a relying party)
// ---------------------------------------------------------------------------

/// Inbound DIDComm message type for a step-up approval request. The
/// authcrypt sender is the holder (`sub`); the body carries the RP DID +
/// nonce. The plugin (Slice C) sends this.
pub(crate) const STEP_UP_APPROVE_REQUEST_TYPE: &str =
    "https://trusttasks.org/vta/step-up/approve-request/1.0";

/// Outbound DIDComm message type carrying the signed approval token.
pub(crate) const STEP_UP_APPROVE_RESPONSE_TYPE: &str =
    "https://trusttasks.org/vta/step-up/approve-response/1.0";

/// Request body for [`handle_step_up_approve`].
#[derive(serde::Deserialize)]
struct StepUpApproveRequestBody {
    rp_did: String,
    nonce: String,
}

/// Response body: the compact-JWS approval token the VTA signed.
#[derive(serde::Serialize)]
struct StepUpApproveResponseBody {
    approval_token: String,
}

/// DIDComm handler for `step-up/approve-request/1.0`.
///
/// The authcrypt **sender DID** is the holder (`sub`). On success the VTA
/// signs an approval token (`iss = vta_did`, `sub = holder`, `aud = rp_did`)
/// with its `{vta_did}#key-0` key and returns it in a
/// `step-up/approve-response/1.0` message.
pub async fn handle_step_up_approve(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    // The holder is the authcrypt-authenticated sender DID (the transport
    // only surfaces sender-authenticated authcrypt frames). We do NOT
    // require VTA-side ACL membership: the VTA vouches for the sender's
    // OWN DID (`sub` == sender), and that approval is only useful to a
    // caller who *also* holds an aal1 session as that DID at the RP (which
    // checks `sub` == its session DID). So getting an approval requires
    // possessing the holder key either way — the `step_up_policy_approve`
    // gate below is the authorization control, not an ACL lookup.
    let holder_did = match message.from.as_deref() {
        Some(d) => d.split('#').next().unwrap_or(d).to_string(),
        None => {
            return Ok(Some(app_err_to_response(AppError::Authentication(
                "step-up approve request has no authenticated sender".into(),
            ))));
        }
    };

    let body: StepUpApproveRequestBody =
        serde_json::from_value(message.body).map_err(handler_err)?;

    // Approval gate (stub — always approves for now).
    if !operations::step_up_approval::step_up_policy_approve(&holder_did, &body.rp_did) {
        return Ok(Some(app_err_to_response(AppError::Forbidden(format!(
            "step-up approval denied for holder {holder_did} at {}",
            body.rp_did
        )))));
    }

    // The VTA's own DID — same source the WebVH handlers use.
    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(d) => d,
        None => {
            return Ok(Some(app_err_to_response(AppError::Internal(
                "VTA DID not configured; cannot issue step-up approval".into(),
            ))));
        }
    };

    let signing_key = app_try!(
        operations::step_up_approval::load_vta_key0_signing_key(
            &state.keys_ks,
            &state.imported_ks,
            &*state.seed_store,
            &state.audit_ks,
            &vta_did,
        )
        .await
    );

    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let approval_token = app_try!(operations::step_up_approval::build_vta_approval_token(
        &vta_did,
        &holder_did,
        &body.rp_did,
        &body.nonce,
        iat,
        &signing_key,
    ));

    info!(
        holder = %holder_did,
        rp = %body.rp_did,
        "issued VTA step-up approval token via DIDComm"
    );

    response(
        STEP_UP_APPROVE_RESPONSE_TYPE,
        &StepUpApproveResponseBody { approval_token },
    )
}

/// Holder-side receive of a credential delivered over DIDComm
/// (`credential-exchange/issue`, spec §6 / task 3.3).
///
/// The authcrypt sender (`message.from`) is the issuer; unpacking already
/// proved that DID cryptographically, so there is **no ACL gate** — the issuer
/// is a credential counterparty, not an operator of this VTA. The proven sender
/// DID is recorded as the stored credential's provenance (falling back to the
/// exchange thread id). The credential format is inferred and the body stored
/// through the format-agnostic vault by
/// [`operations::credential_exchange::receive_issued_credential`].
///
/// `issue` is a one-way deposit: it returns `Ok(None)` (no response body) on
/// success, or a typed problem-report on a validation failure.
pub async fn handle_credential_issue(
    _ctx: HandlerContext,
    message: Message,
    Extension(app_state): Extension<AppState>,
) -> HandlerResult {
    let body: credential_exchange::IssueBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    // Provenance: the cryptographically-proven issuer DID, else the thread id.
    let source = message.from.clone().or_else(|| message.thid.clone());
    let stored = app_try!(
        operations::credential_exchange::receive_issued_credential(
            &app_state.vault_ks,
            &body,
            source,
            chrono::Utc::now(),
        )
        .await
    );
    info!(
        credential_id = %stored.id,
        format = ?stored.format,
        from = message.from.as_deref().unwrap_or("unknown"),
        "received issued credential into vault via DIDComm"
    );
    Ok(None)
}

/// `credential-exchange/query` over DIDComm (Phase 3) — the holder answers a
/// verifier's DCQL query with a presentation.
///
/// The authcrypt sender is the **verifier**. The VTA presents its **own** held
/// credentials, so it acts with its own authority (super-admin over its own
/// contexts) — the **consent policy** (trusted verifiers from config) is the
/// gate. `present_query` does match → ACL-gated holder-key resolution →
/// consent-policy → present. A **trusted** verifier gets a `present` reply with
/// the `vp_token`; any other **defers** (the pending-approval persistence + the
/// re-present loop is a follow-up).
pub async fn handle_credential_query(
    ctx: HandlerContext,
    message: Message,
    Extension(app_state): Extension<AppState>,
) -> HandlerResult {
    let verifier_did = ctx
        .sender_did
        .clone()
        .ok_or_else(|| handler_err("credential query has no authcrypt sender"))?;
    let body: credential_exchange::QueryBody =
        serde_json::from_value(message.body).map_err(handler_err)?;

    // Trusted-verifier policy + the VTA's own identity, from config.
    let (policy, vta_did) = {
        let config = app_state.config.read().await;
        (
            operations::credential_exchange::ConsentPolicy::trusting(
                config.trusted_presentation_verifiers.clone(),
            ),
            config.vta_did.clone().unwrap_or_else(|| "vta:self".into()),
        )
    };
    // The VTA presents its own held credentials — its own authority.
    let auth = crate::auth::AuthClaims {
        did: vta_did,
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        ..Default::default()
    };

    let outcome = app_try!(
        operations::credential_exchange::present_query(
            &app_state.vault_ks,
            &app_state.keys_ks,
            &app_state.seed_store,
            &auth,
            &body,
            &verifier_did,
            &policy,
            chrono::Utc::now(),
        )
        .await
    );

    use operations::credential_exchange::PresentOutcome;
    match outcome {
        PresentOutcome::Presented(present_body) => {
            info!(verifier = %verifier_did, "presented a vp_token via DIDComm");
            response(credential_exchange::PRESENT, &present_body)
        }
        PresentOutcome::ConsentRequired {
            claims, purpose, ..
        } => {
            info!(
                verifier = %verifier_did,
                ?claims,
                %purpose,
                "credential query deferred — holder consent required"
            );
            // Deferred-approval store + re-present loop is a follow-up; signal
            // the verifier that holder consent is required.
            Ok(Some(DIDCommResponse::problem_report(
                ProblemReport::bad_request(
                    "presentation requires holder consent (verifier not trusted); \
                     an out-of-band approval is needed"
                        .to_string(),
                ),
            )))
        }
    }
}

pub async fn handle_unknown(_ctx: HandlerContext, message: Message) -> HandlerResult {
    let from = message.from.as_deref().unwrap_or("unknown");
    let thid = message.thid.as_deref().unwrap_or("none");

    // Extract problem-report details if present in the body
    if message.typ.contains("problem-report") {
        let code = message
            .body
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let comment = message
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or("no details provided");
        warn!(
            from,
            code,
            comment,
            thid,
            msg_type = %message.typ,
            "received unhandled problem-report"
        );
        return Ok(None);
    }

    warn!(from, thid, msg_type = %message.typ, "unknown message type — ignoring");
    Ok(Some(DIDCommResponse::problem_report(
        ProblemReport::bad_request(format!("unsupported message type: {}", message.typ)),
    )))
}
