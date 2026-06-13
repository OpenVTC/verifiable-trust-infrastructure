//! WebVH-DID-lifecycle slice trust-task handlers.
//!
//! **Feature-gated** — requires `webvh` (the entire op layer for
//! WebVH DID-doc creation, update, deletion, and host registration
//! lives under `cfg(feature = "webvh")`). The whole module is
//! `#![cfg(feature = "webvh")]` at the top; mod.rs's `mod webvh;`
//! declaration carries the same gate. URIs are declared in vta-sdk
//! unconditionally — the parity harness uses
//! `KNOWN_FEATURE_GATED_URIS` to recognise them when this module
//! isn't compiled.
//!
//! Auth requirements per URI (enforced by the operation function or
//! by the typed `AdminAuth` / `SuperAdminAuth` extractors used in the
//! REST handlers — replicated here at the slice boundary since
//! trust-task handlers take `AuthClaims` directly):
//!
//! | URI                                 | Auth        |
//! |-------------------------------------|-------------|
//! | `webvh/servers/list/1.0`            | any authed  |
//! | `webvh/servers/add/1.0`             | super-admin |
//! | `webvh/servers/update/1.0`          | super-admin |
//! | `webvh/servers/remove/1.0`          | super-admin |
//! | `webvh/dids/list/1.0`               | any authed  |
//! | `webvh/dids/create/1.0`             | admin       |
//! | `webvh/dids/get/1.0`                | any authed  |
//! | `webvh/dids/get-log/1.0`            | any authed  |
//! | `webvh/dids/delete/1.0`             | admin       |
//! | `webvh/dids/update/1.0`             | admin       |
//! | `webvh/dids/rotate-keys/1.0`        | admin       |
//! | `webvh/dids/register-with-server/1.0` | super-admin |

#![cfg(feature = "webvh")]

use super::helpers::TrustTaskOutcome;
use didwebvh_rs::witness::Witnesses;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};

use vta_sdk::protocols::did_management::{
    create::CreateDidWebvhBody,
    delete::DeleteDidWebvhBody,
    get::GetDidWebvhBody,
    lifecycle::GetDidWebvhLogBody,
    list::ListDidsWebvhBody,
    servers::{
        AddWebvhServerBody, ListWebvhServersBody, RegisterDidWithServerBody,
        RegisterDidWithServerResultBody, RemoveWebvhServerBody, UpdateWebvhServerBody,
    },
    update::{RotateDidWebvhKeysBody, UpdateDidWebvhBody},
};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::operations::did_webvh::{
    RegisterDidWithServerError, RegisterDidWithServerParams, RotateDidWebvhKeysOptions,
    UpdateDidWebvhOptions, register_did_with_server,
};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};

// ─── Server CRUD ────────────────────────────────────────────────────────

/// `webvh/servers/list/1.0` — list registered webvh hosts.
pub(super) async fn handle_servers_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _: ListWebvhServersBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_webvh::list_webvh_servers(&state.webvh_ks, auth, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/servers/add/1.0` — register a new webvh host. Super-admin.
pub(super) async fn handle_servers_add(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: AddWebvhServerBody = match parse_payload(&doc) {
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
    match operations::did_webvh::add_webvh_server(
        &state.webvh_ks,
        auth,
        &req.id,
        &req.did,
        req.label,
        did_resolver,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/servers/update/1.0` — patch a webvh host's label. Super-admin.
pub(super) async fn handle_servers_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateWebvhServerBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_webvh::update_webvh_server(
        &state.webvh_ks,
        auth,
        &req.id,
        req.label,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/servers/remove/1.0` — deregister a webvh host. Super-admin.
pub(super) async fn handle_servers_remove(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: RemoveWebvhServerBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_webvh::remove_webvh_server(
        &state.webvh_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── DID lifecycle ──────────────────────────────────────────────────────

/// `webvh/dids/list/1.0` — list known DIDs, optionally filtered.
pub(super) async fn handle_dids_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListDidsWebvhBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_webvh::list_dids_webvh(
        &state.webvh_ks,
        auth,
        req.context_id.as_deref(),
        req.server_id.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/dids/create/1.0` — mint a new DID. Admin role on target context.
pub(super) async fn handle_dids_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let body: CreateDidWebvhBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let config = state.config.read().await;
    let did_resolver = match state.did_resolver.as_ref() {
        Some(r) => r,
        None => {
            return app_error_to_reject(
                &doc,
                AppError::Internal("DID resolver not available".into()),
            );
        }
    };
    let params = body.into();
    match operations::did_webvh::create_did_webvh(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.did_templates_ks,
        &*state.seed_store,
        &config,
        auth,
        params,
        did_resolver,
        &state.didcomm_bridge,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/dids/get/1.0` — fetch a DID record.
pub(super) async fn handle_dids_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetDidWebvhBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_webvh::get_did_webvh(
        &state.webvh_ks,
        auth,
        &req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/dids/get-log/1.0` — fetch the raw `did.jsonl` log (authed).
/// The unauthenticated public mirror (`GET /did/{did}/log`) is
/// deliberately NOT trust-task-wrapped — it stays plain REST as the
/// DID-resolver failover path.
pub(super) async fn handle_dids_get_log(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetDidWebvhLogBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_webvh::get_did_webvh_log(
        &state.webvh_ks,
        auth,
        &req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/dids/delete/1.0` — delete a DID locally (+ remote cleanup
/// when hosted). Admin role on the DID's context.
pub(super) async fn handle_dids_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeleteDidWebvhBody = match parse_payload(&doc) {
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
    match operations::did_webvh::delete_did_webvh(
        &state.webvh_ks,
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        &*state.seed_store,
        auth,
        &req.did,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `webvh/dids/update/1.0` — apply a generic DID-doc patch. Admin
/// role on the DID's context.
///
/// The SDK wire body
/// (`vta_sdk::protocols::did_management::update::UpdateDidWebvhBody`)
/// carries `witnesses` as opaque JSON (no `didwebvh-rs` dependency
/// for SDK consumers). Convert to the op-layer's typed
/// `UpdateDidWebvhOptions` at the slice boundary by deserialising
/// the JSON into `Witnesses` (the enum is `#[serde(untagged)]`, so
/// the wire shapes are identical).
///
/// The trust-task envelope has no URL path, so the caller carries
/// the target `did` at the payload top level via the
/// [`UpdateDidWithDid`] wrapper.
pub(super) async fn handle_dids_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpdateDidWithDid = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let UpdateDidWithDid { did, body } = req;
    let options = match update_body_to_options(body) {
        Ok(o) => o,
        Err(resp) => return reject_with(&doc, resp),
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
    match operations::did_webvh::update_did_webvh(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &*state.seed_store,
        auth,
        &did,
        options,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// `webvh/dids/rotate-keys/1.0` — rotate every VM's key bytes on a
/// DID and apply the resulting document change as one update. Admin
/// role on the DID's context.
pub(super) async fn handle_dids_rotate_keys(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: RotateKeysWithDid = match parse_payload(&doc) {
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
    let options = RotateDidWebvhKeysOptions {
        pre_rotation_count: req.body.pre_rotation_count,
        label: req.body.label,
    };
    match operations::did_webvh::rotate_did_webvh_keys(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &*state.seed_store,
        auth,
        &req.did,
        options,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// `webvh/dids/register-with-server/1.0` — promote a serverless DID
/// to a server-managed one. Super-admin.
pub(super) async fn handle_dids_register_with_server(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: RegisterDidWithServerBody = match parse_payload(&doc) {
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
    match register_did_with_server(
        &state.webvh_ks,
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        &*state.seed_store,
        auth,
        did_resolver,
        &state.didcomm_bridge,
        RegisterDidWithServerParams {
            did: req.did,
            server_id: req.server_id,
            force: req.force,
            domain: req.domain.clone(),
        },
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(result) => success_response(
            &doc,
            RegisterDidWithServerResultBody {
                did: result.did,
                server_id: result.server_id,
                log_entry_count: result.log_entry_count,
            },
        ),
        Err(e) => app_error_to_reject(&doc, map_register_err(e)),
    }
}

/// Map `RegisterDidWithServerError` onto `AppError`. Mirrors the
/// `map_register_err` helper in `routes::did_webvh` so REST and
/// trust-task transports return the same statuses for the same
/// failure modes. Kept private to the slice — sharing the helper
/// with `routes::did_webvh` would mean making it `pub(crate)`,
/// which we don't yet need.
fn map_register_err(e: RegisterDidWithServerError) -> AppError {
    use RegisterDidWithServerError as E;
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

// ─── Helpers internal to this slice ─────────────────────────────────────

fn update_body_to_options(body: UpdateDidWebvhBody) -> Result<UpdateDidWebvhOptions, RejectReason> {
    let witnesses = match body.witnesses {
        Some(v) => match serde_json::from_value::<Witnesses>(v) {
            Ok(w) => Some(w),
            Err(e) => {
                return Err(RejectReason::MalformedRequest {
                    reason: format!("witnesses: {e}"),
                });
            }
        },
        None => None,
    };
    Ok(UpdateDidWebvhOptions {
        document: body.document,
        pre_rotation_count: body.pre_rotation_count,
        witnesses,
        watchers: body.watchers,
        ttl: body.ttl,
        label: body.label,
        expected_version_id: body.expected_version_id,
    })
}

/// Wrapper carrying `RotateDidWebvhKeysBody` plus the target `did`.
/// The trust-task envelope has no URL path; the caller must include
/// the DID at the payload top level.
#[derive(Debug, serde::Deserialize)]
struct RotateKeysWithDid {
    did: String,
    #[serde(flatten)]
    body: RotateDidWebvhKeysBody,
}

/// Wrapper carrying `UpdateDidWebvhBody` plus the target `did`. Same
/// rationale as [`RotateKeysWithDid`].
#[derive(Debug, serde::Deserialize)]
struct UpdateDidWithDid {
    did: String,
    #[serde(flatten)]
    body: UpdateDidWebvhBody,
}
