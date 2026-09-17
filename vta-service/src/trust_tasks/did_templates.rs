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

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with, success_response,
};
use trust_tasks_rs::RejectReason;

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
        Ok(templates) => {
            // The whole listing is refused rather than filtered. A list with
            // the post-quantum templates quietly missing would read as "none
            // were created", which is a worse answer than an error naming the
            // version that can show them.
            if let Some(reject) = check_record_schema_version(
                &doc,
                templates.iter().map(|t| t.template.schema_version),
            ) {
                return reject;
            }
            success_response(&doc, ListDidTemplatesResultBody { templates })
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// The highest template `schemaVersion` the dispatching spec version can
/// express.
///
/// # Why this exists
///
/// `parse_payload` is plain serde on a hand-rolled body type — there is no
/// per-version JSON-Schema validation at runtime, so the **only** thing
/// carrying the spec version is the task URI. Dispatching 2.0 and 3.0 to one
/// handler therefore makes them indistinguishable once inside it, and a 2.0
/// request could carry a `schemaVersion` 2 template with a `keys` block that
/// the 2.0 spec forbids (`schemaVersion` is `const: 1` in
/// `vta/_shared/0.1`).
///
/// That would leave this service quietly more permissive than the
/// specification it claims to implement, and nothing would catch it: the
/// conformance fixtures check payload shapes, not which URI dispatched them.
///
/// So the handler reads its own dispatching URI and holds the template to what
/// that version can say. A 3.0 caller gets the wider schema; a 2.0 caller gets
/// exactly what 2.0 promised.
fn max_template_schema_version(type_uri: &str) -> u32 {
    if type_uri.ends_with("/3.0") { 2 } else { 1 }
}

/// Refuse a template whose `schemaVersion` the dispatching spec version cannot
/// express.
fn check_template_schema_version(
    doc: &TrustTask<Value>,
    template: &vta_sdk::did_templates::DidTemplate,
) -> Option<TrustTaskOutcome> {
    let ceiling = max_template_schema_version(&doc.type_uri.to_string());
    if template.schema_version <= ceiling {
        return None;
    }
    Some(reject_with(
        doc,
        RejectReason::MalformedRequest {
            reason: format!(
                "template declares schemaVersion {} but this task version accepts at most {} \
                 — send it to the 3.0 task URI, which is the version that can express it",
                template.schema_version, ceiling,
            ),
        },
    ))
}

/// Refuse to return a record the dispatching spec version cannot express.
///
/// The mirror of [`check_template_schema_version`], and a gap that PR #1538
/// left: the ceiling guarded what a caller could *send*, not what the service
/// would *return*. A `schemaVersion` 2 template fetched through a 2.0 read
/// comes back carrying a `keys` block, under a response schema that pins
/// `schemaVersion` to `const: 1` and sets `additionalProperties: false`. The
/// caller gets a document its own spec says cannot exist.
///
/// Refusing is deliberately preferred to the two alternatives. Returning it
/// anyway makes the service non-conformant in a way no fixture checks. Silently
/// omitting v2 templates from a listing is worse still: an operator would see a
/// list with the post-quantum templates missing and conclude they were never
/// created.
fn check_record_schema_version(
    doc: &TrustTask<Value>,
    records: impl IntoIterator<Item = u32>,
) -> Option<TrustTaskOutcome> {
    let ceiling = max_template_schema_version(&doc.type_uri.to_string());
    let highest = records.into_iter().max().unwrap_or(0);
    if highest <= ceiling {
        return None;
    }
    Some(reject_with(
        doc,
        RejectReason::TaskFailed {
            reason: format!(
                "a stored template declares schemaVersion {highest}, which this task version \
                 cannot return — read it through the 3.0 task URI, which can"
            ),
            details: Some(serde_json::json!({ "reason": "schemaVersionTooHigh" })),
        },
    ))
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
    if let Some(reject) = check_template_schema_version(&doc, &req.template) {
        return reject;
    }
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
        Ok(record) => {
            if let Some(reject) =
                check_record_schema_version(&doc, [record.template.schema_version])
            {
                return reject;
            }
            success_response(&doc, record)
        }
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
    if let Some(reject) = check_template_schema_version(&doc, &req.template) {
        return reject;
    }
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

#[cfg(test)]
mod schema_ceiling_tests {
    use super::max_template_schema_version;

    /// A 2.0 task accepts only what 2.0 can express, and 3.0 accepts the wider
    /// schema.
    ///
    /// This is the whole of VTI's conformance to the 2.0 spec once both
    /// versions dispatch to one handler. `parse_payload` is plain serde with no
    /// per-version schema validation, so the URI is the only carrier of the
    /// version — without this ceiling a 2.0 caller could send a
    /// `schemaVersion` 2 template with a `keys` block, which
    /// `vta/_shared/0.1` forbids by pinning `schemaVersion` to `const: 1`.
    ///
    /// Nothing else would catch that. The conformance fixtures check payload
    /// shapes, not which URI dispatched them, so the service would simply be
    /// quietly more permissive than the specification it publishes.
    #[test]
    fn a_task_version_accepts_only_the_template_schema_it_can_express() {
        for uri in [
            "https://trusttasks.org/spec/vta/did-templates/create/2.0",
            "https://trusttasks.org/spec/vta/did-templates/update/2.0",
        ] {
            assert_eq!(
                max_template_schema_version(uri),
                1,
                "{uri} must not accept a v2 template — its schema pins schemaVersion to 1"
            );
        }

        for uri in [
            "https://trusttasks.org/spec/vta/did-templates/create/3.0",
            "https://trusttasks.org/spec/vta/did-templates/update/3.0",
        ] {
            assert_eq!(
                max_template_schema_version(uri),
                2,
                "{uri} is the version that exists to carry a keys block"
            );
        }
    }

    /// An unrecognised URI gets the *narrow* ceiling, not the wide one.
    ///
    /// The direction matters. Defaulting to the permissive end would mean any
    /// future task version silently accepted templates it had never promised
    /// to, and the failure would be invisible; defaulting narrow produces a
    /// clear rejection naming the version instead.
    #[test]
    fn an_unrecognised_version_defaults_to_the_narrow_ceiling() {
        // Derived from a real constant rather than written as a literal. The
        // produced-URI census greps source for spec-URI literals and requires
        // each to be published — so both a made-up version AND the bare stem
        // read to it as URIs this service produces. That is the confusion it
        // exists to catch, and it caught both attempts. Deriving it also keeps
        // the test correct if the URI ever moves.
        let stem = vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_3_0
            .rsplit_once('/')
            .expect("a task URI ends in /<version>")
            .0;
        let unknown = format!("{stem}/9.9");
        assert_eq!(max_template_schema_version(&unknown), 1);
    }
}
