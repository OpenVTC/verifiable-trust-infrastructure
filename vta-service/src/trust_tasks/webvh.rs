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
    agent_name::{
        AgentNameBody, AgentNameCheckBody, AgentNameCheckResultBody, AgentNameEntry,
        AgentNameListBody, AgentNameListResultBody, AgentNameResultBody,
    },
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
    AgentNameVerb, RegisterDidWithServerError, RegisterDidWithServerParams,
    RotateDidWebvhKeysOptions, UpdateDidWebvhOptions, register_did_with_server,
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
    let deps =
        operations::did_webvh::CreateDidWebvhDeps::from_app_state(state, &config, did_resolver);
    match operations::did_webvh::create_did_webvh(&deps, auth, params, TRANSPORT_TRUST_TASK).await {
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
    let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    match operations::did_webvh::delete_did_webvh(
        &deps,
        auth,
        &req.did,
        vta_did.as_deref(),
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
    let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    match operations::did_webvh::update_did_webvh(
        &deps,
        auth,
        &did,
        options,
        vta_did.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => {
            // A Destructive update that passed the consent gate and then failed
            // in execute previously vanished into a bare 422 — no line named the
            // cause, so a consent-approved-but-still-looping DID was undiagnosable
            // from the log. The error's Display distinguishes the sub-causes
            // (`reconcile publish_did: …`, `webvh server … missing`,
            // `get_published_version: …`, a signing/library failure), so log it.
            tracing::warn!(
                did = %did,
                error = %e,
                "webvh dids/update execute failed after the consent gate passed — \
                 returning task error to requester"
            );
            app_error_to_reject(&doc, AppError::from(e))
        }
    }
}

/// `spec/vta/webvh/agent-name/list/1.0` — read the DID's agent-name registry
/// from the hosting control plane, parked names included. Read-only.
pub(super) async fn handle_agent_name_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: AgentNameListBody = match parse_payload(&doc) {
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
    match operations::did_webvh::list_agent_names(&deps, auth, &req.did, vta_did.as_deref()).await {
        Ok((did, names)) => success_response(
            &doc,
            AgentNameListResultBody {
                did,
                names: names
                    .into_iter()
                    .map(|e| AgentNameEntry {
                        name: e.name,
                        enabled: e.enabled,
                        created_at: e.created_at,
                    })
                    .collect(),
            },
        ),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// `spec/vta/webvh/agent-name/check/1.0` — is this name free on the DID's
/// host? Read-only; lets a client report a collision before signing anything.
pub(super) async fn handle_agent_name_check(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: AgentNameCheckBody = match parse_payload(&doc) {
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
    match operations::did_webvh::check_agent_name(
        &deps,
        auth,
        &req.did,
        &req.name,
        vta_did.as_deref(),
    )
    .await
    {
        Ok(a) => success_response(
            &doc,
            AgentNameCheckResultBody {
                name: a.name,
                domain: a.domain,
                available: a.available,
                reserved: a.reserved,
            },
        ),
        Err(e) => app_error_to_reject(&doc, AppError::from(e)),
    }
}

/// `spec/vta/webvh/agent-name/set/1.0` — bind an agent name: publish a new
/// signed version claiming it in `alsoKnownAs` and register the binding with
/// the host, which refuses a reserved name or one another DID already holds.
/// Destructive.
pub(super) async fn handle_agent_name_set(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    handle_agent_name(state, auth, doc, AgentNameVerb::Set).await
}

/// `spec/vta/webvh/agent-name/remove/1.0` — release an agent name: publish a
/// new signed version dropping it from `alsoKnownAs` and tell the host to drop
/// the reservation, so anyone may reclaim it. Destructive — and unlike
/// `disable`, not recoverable by this DID alone.
pub(super) async fn handle_agent_name_remove(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    handle_agent_name(state, auth, doc, AgentNameVerb::Remove).await
}

/// `spec/vta/webvh/agent-name/disable/1.0` — park an agent name: publish a new
/// signed version dropping it from `alsoKnownAs` and tell the host to keep it
/// reserved. Destructive.
pub(super) async fn handle_agent_name_disable(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    handle_agent_name(state, auth, doc, AgentNameVerb::Disable).await
}

/// `spec/vta/webvh/agent-name/enable/1.0` — resume serving a parked name:
/// publish a new signed version that claims it again.
pub(super) async fn handle_agent_name_enable(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    handle_agent_name(state, auth, doc, AgentNameVerb::Enable).await
}

async fn handle_agent_name(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    verb: AgentNameVerb,
) -> TrustTaskOutcome {
    let req: AgentNameBody = match parse_payload(&doc) {
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
    match operations::did_webvh::agent_name_op(
        &deps,
        auth,
        &req.did,
        &req.name,
        verb,
        vta_did.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(_) => success_response(
            &doc,
            AgentNameResultBody {
                did: req.did,
                name: req.name,
                // Whether the name resolves now — `remove` reports `false`
                // like `disable`; the caller knows which verb it sent.
                enabled: verb.claims_name(),
            },
        ),
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
    let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    match operations::did_webvh::rotate_did_webvh_keys(
        &deps,
        auth,
        &req.did,
        options,
        vta_did.as_deref(),
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
    let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
    match register_did_with_server(
        &deps,
        auth,
        RegisterDidWithServerParams {
            did: req.did,
            server_id: req.server_id,
            force: req.force,
            domain: req.domain.clone(),
        },
        vta_did.as_deref(),
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
        E::Transport(msg) => AppError::Internal(format!("publish: {msg}")),
        // Pass the host's typed rejection through untouched — see
        // `RegisterDidWithServerError::Publish`.
        E::Publish(e) => e,
        E::DidUrlParse { .. } => AppError::Validation(e.to_string()),
        E::Storage(msg) => AppError::Internal(msg),
    }
}

// ─── Helpers internal to this slice ─────────────────────────────────────

pub(super) fn update_body_to_options(
    body: UpdateDidWebvhBody,
) -> Result<UpdateDidWebvhOptions, RejectReason> {
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
pub(super) struct UpdateDidWithDid {
    pub(super) did: String,
    #[serde(flatten)]
    pub(super) body: UpdateDidWebvhBody,
}
