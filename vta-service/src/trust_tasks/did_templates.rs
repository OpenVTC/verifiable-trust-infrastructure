//! DID-templates slice trust-task handlers.
//!
//! Six handlers — one per operation, serving the merged
//! `spec/vta/did-templates/*/2.0` family. Scope is selected by the
//! payload's optional `contextId` (absent = global, present = that
//! context); each handler branches to the matching global/context
//! operation function. Auth contracts:
//!
//! | URI                                     | `contextId` absent | `contextId` present               |
//! |------------------------------------------|--------------------|-----------------------------------|
//! | `did-templates/{list,get,render}/2.0`    | any authed         | any authed with context access    |
//! | `did-templates/{create,update,delete}/2.0` | super-admin      | super-admin OR admin-with-context |
//!
//! Auth enforcement lives in the operation functions (`require_super_admin`
//! for global writes, `require_context_write` / `require_context_read`
//! for context ops). The slice handlers don't gate themselves — they
//! deserialize the payload, branch on scope, call the op, and serialize
//! back.

use std::collections::HashMap;

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::did_templates::TemplateVars;
use vta_sdk::protocols::did_template_management::{
    create::CreateDidTemplateBody,
    delete::{DeleteDidTemplateBody, DeleteDidTemplateResultBody},
    get::GetDidTemplateBody,
    list::{ListDidTemplatesBody, ListDidTemplatesResultBody},
    render::{RenderDidTemplateBody, RenderDidTemplateResultBody},
    update::UpdateDidTemplateBody,
};

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, success_response};

/// `did-templates/list/2.0` — list the templates in one scope.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: ListDidTemplatesBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let result = match req.context_id {
        Some(context_id) => {
            operations::did_templates::list_context(
                &state.did_templates_ks,
                auth,
                &context_id,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
        None => {
            operations::did_templates::list_global(
                &state.did_templates_ks,
                auth,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
    };
    match result {
        Ok(templates) => success_response(&doc, ListDidTemplatesResultBody { templates }),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/create/2.0` — create a template in one scope.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: CreateDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let result = match req.context_id {
        Some(context_id) => {
            operations::did_templates::create_context(
                &state.did_templates_ks,
                &state.contexts_ks,
                &state.audit_sink,
                auth,
                &context_id,
                req.template,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
        None => {
            operations::did_templates::create_global(
                &state.did_templates_ks,
                &state.audit_sink,
                auth,
                req.template,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
    };
    match result {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/get/2.0` — fetch one template from one scope.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let result = match req.context_id {
        Some(context_id) => {
            operations::did_templates::get_context(
                &state.did_templates_ks,
                auth,
                &context_id,
                &req.name,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
        None => {
            operations::did_templates::get_global(
                &state.did_templates_ks,
                auth,
                &req.name,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
    };
    match result {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/update/2.0` — replace a template in one scope.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: UpdateDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let result = match req.context_id {
        Some(context_id) => {
            operations::did_templates::update_context(
                &state.did_templates_ks,
                &state.audit_sink,
                auth,
                &context_id,
                &req.name,
                req.template,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
        None => {
            operations::did_templates::update_global(
                &state.did_templates_ks,
                &state.audit_sink,
                auth,
                &req.name,
                req.template,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
    };
    match result {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// `did-templates/delete/2.0` — delete a template from one scope.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: DeleteDidTemplateBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let result = match &req.context_id {
        Some(context_id) => {
            operations::did_templates::delete_context(
                &state.did_templates_ks,
                &state.audit_sink,
                auth,
                context_id,
                &req.name,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
        None => {
            operations::did_templates::delete_global(
                &state.did_templates_ks,
                &state.audit_sink,
                auth,
                &req.name,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
    };
    match result {
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

/// `did-templates/render/2.0` — render a template from one scope with
/// caller vars. Context scope additionally injects ambient
/// `CONTEXT_ID` / `CONTEXT_DID`.
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
    let result = match req.context_id {
        Some(context_id) => {
            operations::did_templates::render_context(
                &state.did_templates_ks,
                &state.contexts_ks,
                &config_guard,
                auth,
                &context_id,
                &req.name,
                caller_vars,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
        None => {
            operations::did_templates::render_global(
                &state.did_templates_ks,
                &config_guard,
                auth,
                &req.name,
                caller_vars,
                TRANSPORT_TRUST_TASK,
            )
            .await
        }
    };
    match result {
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
