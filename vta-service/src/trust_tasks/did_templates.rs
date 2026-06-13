//! DID-templates slice trust-task handlers (global + context scope).
//!
//! Twelve handlers — six per scope, mirroring the legacy REST surface.
//! Auth contracts:
//!
//! | URI                                                       | Auth                              |
//! |-----------------------------------------------------------|-----------------------------------|
//! | `did-templates/{list,get,render}/1.0`                     | any authed                        |
//! | `did-templates/{create,update,delete}/1.0`                | super-admin                       |
//! | `contexts/did-templates/{list,get,render}/1.0`            | any authed with context access    |
//! | `contexts/did-templates/{create,update,delete}/1.0`       | super-admin OR admin-with-context |
//!
//! Auth enforcement lives in the operation functions (`require_super_admin`
//! for global writes, `require_context_write` / `require_context_read`
//! for context ops). The slice handlers don't gate themselves — they
//! deserialize the payload, call the op, and serialize back.

use std::collections::HashMap;

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::did_templates::TemplateVars;
use vta_sdk::protocols::did_template_management::{
    create::{CreateContextDidTemplateBody, CreateDidTemplateBody},
    delete::{DeleteContextDidTemplateBody, DeleteDidTemplateBody, DeleteDidTemplateResultBody},
    get::{GetContextDidTemplateBody, GetDidTemplateBody},
    list::{ListContextDidTemplatesBody, ListDidTemplatesBody, ListDidTemplatesResultBody},
    render::{RenderContextDidTemplateBody, RenderDidTemplateBody, RenderDidTemplateResultBody},
    update::{UpdateContextDidTemplateBody, UpdateDidTemplateBody},
};

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

// ─── Global scope ──────────────────────────────────────────────────────

/// `did-templates/list/1.0` — list all global templates. Any authed.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _: ListDidTemplatesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::list_global(
        &state.did_templates_ks,
        auth,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(templates) => success_response(&doc, ListDidTemplatesResultBody { templates }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/create/1.0` — create a global template. Super-admin.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CreateDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::create_global(
        &state.did_templates_ks,
        &state.audit_ks,
        auth,
        req.template,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/get/1.0` — fetch one global template. Any authed.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::get_global(
        &state.did_templates_ks,
        auth,
        &req.name,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/update/1.0` — replace a global template. Super-admin.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpdateDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::update_global(
        &state.did_templates_ks,
        &state.audit_ks,
        auth,
        &req.name,
        req.template,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/delete/1.0` — delete a global template. Super-admin.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeleteDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::delete_global(
        &state.did_templates_ks,
        &state.audit_ks,
        auth,
        &req.name,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(()) => success_response(
            &doc,
            DeleteDidTemplateResultBody {
                name: req.name,
                deleted: true,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/render/1.0` — render a global template with caller
/// vars. Any authed.
pub(super) async fn handle_render(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: RenderDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let caller_vars = vars_from_hashmap(req.vars);
    let config_guard = state.config.read().await;
    match operations::did_templates::render_global(
        &state.did_templates_ks,
        &config_guard,
        auth,
        &req.name,
        caller_vars,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(document) => success_response(&doc, RenderDidTemplateResultBody { document }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── Context scope ─────────────────────────────────────────────────────

/// `contexts/did-templates/list/1.0` — list templates in a context.
pub(super) async fn handle_context_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListContextDidTemplatesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::list_context(
        &state.did_templates_ks,
        auth,
        &req.context_id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(templates) => success_response(&doc, ListDidTemplatesResultBody { templates }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `contexts/did-templates/create/1.0` — create a context-scoped
/// template. Super-admin OR admin-with-context.
pub(super) async fn handle_context_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CreateContextDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::create_context(
        &state.did_templates_ks,
        &state.contexts_ks,
        &state.audit_ks,
        auth,
        &req.context_id,
        req.template,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `contexts/did-templates/get/1.0` — fetch one context-scoped
/// template.
pub(super) async fn handle_context_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetContextDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::get_context(
        &state.did_templates_ks,
        auth,
        &req.context_id,
        &req.name,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `contexts/did-templates/update/1.0` — replace a context-scoped
/// template. Super-admin OR admin-with-context.
pub(super) async fn handle_context_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpdateContextDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::update_context(
        &state.did_templates_ks,
        &state.audit_ks,
        auth,
        &req.context_id,
        &req.name,
        req.template,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `contexts/did-templates/delete/1.0` — delete a context-scoped
/// template. Super-admin OR admin-with-context.
pub(super) async fn handle_context_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeleteContextDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::did_templates::delete_context(
        &state.did_templates_ks,
        &state.audit_ks,
        auth,
        &req.context_id,
        &req.name,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(()) => success_response(
            &doc,
            DeleteDidTemplateResultBody {
                name: req.name,
                deleted: true,
            },
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `contexts/did-templates/render/1.0` — render a context-scoped
/// template with caller vars. Any authed with context access.
pub(super) async fn handle_context_render(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: RenderContextDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let caller_vars = vars_from_hashmap(req.vars);
    let config_guard = state.config.read().await;
    match operations::did_templates::render_context(
        &state.did_templates_ks,
        &state.contexts_ks,
        &config_guard,
        auth,
        &req.context_id,
        &req.name,
        caller_vars,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(document) => success_response(&doc, RenderDidTemplateResultBody { document }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn vars_from_hashmap(map: HashMap<String, Value>) -> TemplateVars {
    let mut vars = TemplateVars::new();
    for (k, v) in map {
        vars.insert(k, v);
    }
    vars
}
