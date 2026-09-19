//! Contexts slice trust-task handlers.
//!
//! Mirrors the legacy REST `/contexts/*` routes. Auth: any
//! authenticated caller for list/get; admin for update-did;
//! super-admin for create/update/preview-delete/delete.

use super::helpers::TrustTaskOutcome;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::context_management::create::CreateContextBody;
use vta_sdk::protocols::context_management::delete::{DeleteContextBody, DeleteContextPreviewBody};
use vta_sdk::protocols::context_management::get::GetContextBody;
use vta_sdk::protocols::context_management::list::ListContextsBody;
use vta_sdk::protocols::context_management::update::UpdateContextBody;
use vta_sdk::protocols::context_management::update_did::UpdateContextDidBody;

use crate::auth::AuthClaims;
use crate::operations;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, app_error_to_reject, parse_payload, reject_with_code, success_response,
};

/// The task's own slug, read off the document rather than written down, so an
/// extended code can only ever name the task that emitted it.
fn slug_from_doc(doc: &TrustTask<Value>) -> String {
    doc.type_uri
        .to_string()
        .strip_prefix("https://trusttasks.org/spec/")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(slug, _ver)| slug.to_string())
        .unwrap_or_else(|| "vta/contexts/delete".to_string())
}

fn ext(slug: &str, local: &str) -> trust_tasks_rs::TrustTaskCode {
    trust_tasks_rs::TrustTaskCode::new_extended(slug, local)
        .expect("contexts extended code is grammar-valid")
}

/// Reject a context operation with the error code its own specification
/// declares.
///
/// One function for the whole family, because the slug is read off the
/// document: the same match answers `vta/contexts/get:notFound`,
/// `vta/contexts/update:notFound`, `vta/contexts/create:parentNotFound` and
/// `vta/contexts/delete:notEmpty` depending only on which task is being
/// served. A per-handler mapping would be six copies of this, and the sixth
/// would be the one that drifts.
fn reject_context_error(
    doc: &TrustTask<Value>,
    e: operations::contexts::ContextError,
) -> TrustTaskOutcome {
    use operations::contexts::ContextError;
    let slug = slug_from_doc(doc);
    match e {
        // Deliberately says nothing about whether the id exists. That is the
        // point of the code: `vta/contexts/get` states that it "does not
        // distinguish 'does not exist' from 'exists but not yours'", and a
        // message that distinguished them would put back exactly what the
        // conflation removes.
        ContextError::Unreachable => reject_with_code(
            doc,
            ext(&slug, "notFound"),
            "no context with that id is reachable by this caller",
            None,
        ),
        ContextError::ParentUnreachable => reject_with_code(
            doc,
            ext(&slug, "parentNotFound"),
            "no context with that parent id is reachable by this caller",
            None,
        ),
        ContextError::NotEmpty(holds) => reject_with_code(
            doc,
            ext(&slug, "notEmpty"),
            format!(
                "context holds {}; retry with force to delete the whole subtree, or preview it \
                 first",
                holds.summary()
            ),
            // The counts machine-readably, so a consumer can decide without
            // parsing the sentence above. `subContexts` is the one that
            // changes what the operator is agreeing to.
            Some(serde_json::json!({
                "subContexts": holds.sub_contexts,
                "keys": holds.keys,
                "webvhDids": holds.webvh_dids,
                "aclEntries": holds.acl_entries,
                "didTemplates": holds.did_templates,
            })),
        ),
        ContextError::Other(e) => app_error_to_reject(doc, e),
    }
}

/// Handler for `spec/vta/contexts/list/1.0`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let _req: ListContextsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::list_contexts(&state.contexts_ks, auth, TRANSPORT_TRUST_TASK).await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/create/1.0`. Super-admin only.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Admin role required; `create_context` enforces the finer gate (super-admin
    // for a top-level context, admin-of-parent for a sub-context).
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: CreateContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let audit_id = req.id.clone();
    match operations::contexts::create_context(
        &state.contexts_ks,
        auth,
        &req.id,
        req.name,
        req.description,
        req.parent,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => {
            // A context is the isolation boundary every key, DID and app-state
            // record hangs off. Creating one is creating a new compartment, and
            // "when did this appear, and who made it" is a question the trail
            // has to answer.
            if let Err(e) = crate::audit::record_with_detail(
                &state.audit_sink,
                "contexts.create",
                &auth.did,
                Some(&audit_id),
                "success",
                Some(TRANSPORT_TRUST_TASK),
                Some(&audit_id),
                None,
            )
            .await
            {
                tracing::warn!(error = %e, "audit record failed for contexts.create");
            }
            success_response(&doc, body)
        }
        Err(e) => reject_context_error(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/get/1.0`.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: GetContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::get_context_op(
        &state.contexts_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => reject_context_error(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/secrets/1.0` — the private keys of a context's own DID.
///
/// **Application or higher, and only for a context the caller may act in.** Deliberately not
/// Admin: reading the keys of the DID you already operate is not an administrative act, and
/// requiring Admin meant a service had to be granted authority over everything else in the
/// VTA in order to be itself.
///
/// Both checks live in [`operations::keys::get_context_secrets`] rather than here, so a
/// second entry point cannot acquire a different set of them.
pub(super) async fn handle_secrets(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: vta_sdk::protocols::context_management::secrets::GetContextSecretsBody =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
    let deps = operations::export::ExportDeps {
        keys_ks: &state.keys_ks,
        contexts_ks: &state.contexts_ks,
        imported_ks: &state.imported_ks,
        audit: &state.audit_sink,
        acl_ks: &state.acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks: &state.webvh_ks,
        seed_store: &state.seed_store,
    };
    match operations::export::get_context_secrets(&deps, auth, &req.id, TRANSPORT_TRUST_TASK).await
    {
        // The spec's response is lowerCamelCase (SPEC §4.10); `DidSecretsBundle` is the
        // internal snake_case form, shared with the on-disk export. The conversion is the
        // boundary between them.
        Ok(bundle) => success_response(
            &doc,
            vta_sdk::protocols::context_management::secrets::ContextSecretsResultBody::from(bundle),
        ),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/update/1.0`. Super-admin only.
pub(super) async fn handle_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::update_context(
        &state.contexts_ks,
        auth,
        &req.id,
        operations::contexts::UpdateContextParams {
            name: req.name,
            did: req.did,
            description: req.description,
            context_policy: req.context_policy,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => reject_context_error(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/update-did/1.0`. Admin only.
pub(super) async fn handle_update_did(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateContextDidBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::update_context_did(
        &state.contexts_ks,
        auth,
        &req.id,
        req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => reject_context_error(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/preview-delete/1.0`. Super-admin only.
pub(super) async fn handle_preview_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Admin role; the operation enforces access to the context or an ancestor.
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: DeleteContextPreviewBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::preview_delete_context(
        &state.contexts_ks,
        &state.keys_ks,
        &state.acl_ks,
        &state.did_templates_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => reject_context_error(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/delete/1.0`. Admin role; the operation
/// enforces access to the context or an ancestor (folder authority) and
/// cascades the subtree with `force`.
pub(super) async fn handle_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    // Step-up (context/delete floor) is enforced centrally by the PDP gate.
    let req: DeleteContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ks = operations::keyspaces_from_app_state(state);
    // A context's DIDs are deleted through the full webvh path, which needs a
    // resolver to reach their hosting servers. Without one the deletion is
    // *refused* for a context that holds DIDs rather than dropping their local
    // records — see `ContextDidCleanup`.
    #[cfg(feature = "webvh")]
    let outcome = {
        let vta_did = state.config.read().await.vta_did.clone();
        match state.did_resolver.as_ref() {
            Some(did_resolver) => {
                let deps = operations::did_webvh::WebvhDeps::from_app_state(state, did_resolver);
                let cleanup = operations::contexts::ContextDidCleanup {
                    deps: &deps,
                    vta_did: vta_did.as_deref(),
                };
                operations::contexts::delete_context(
                    &ks,
                    auth,
                    &req.id,
                    req.force,
                    TRANSPORT_TRUST_TASK,
                    Some(&cleanup),
                )
                .await
            }
            None => {
                operations::contexts::delete_context(
                    &ks,
                    auth,
                    &req.id,
                    req.force,
                    TRANSPORT_TRUST_TASK,
                    None,
                )
                .await
            }
        }
    };
    #[cfg(not(feature = "webvh"))]
    let outcome =
        operations::contexts::delete_context(&ks, auth, &req.id, req.force, TRANSPORT_TRUST_TASK)
            .await;

    match outcome {
        Ok(body) => success_response(&doc, body),
        Err(e) => reject_context_error(&doc, e),
    }
}
