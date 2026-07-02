//! DID template resolution for the provision-integration flow.
//!
//! Templates can live in three scopes, resolved in order:
//!   1. Context-scoped (`tpl:ctx:{ctx}:{name}`)
//!   2. Global (`tpl:global:{name}`)
//!   3. Built-in (embedded in the SDK via `include_str!`)
//!
//! The helpers here encode that lookup order so callers don't have to
//! duplicate the "three-level fallback" pattern each time they need a
//! template.

use crate::error::AppError;

use super::ProvisionIntegrationDeps;

/// Resolve the admin template the request asked for (by name), surfacing
/// a Validation error with admin-specific remediation when not found.
///
/// Differs from [`resolve_template_by_name`]: this path wraps NotFound
/// into Validation with a message tailored to the admin-template role
/// (suggests the built-in `vta-admin`), since an admin-template missing
/// is an operator-input error rather than an internal lookup failure.
/// Returns the parsed [`DidTemplate`] instead of just a registration
/// boolean — we need to render it during the mint.
pub(super) async fn resolve_admin_template(
    state: &ProvisionIntegrationDeps,
    context: &str,
    name: &str,
) -> Result<vta_sdk::did_templates::DidTemplate, AppError> {
    resolve_template_by_name(state, context, name)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::Validation(format!(
                "admin template '{name}' is not registered on this VTA. Register it via \
                 'pnm did-templates create {name} --file <path>' then retry, or use \
                 the built-in 'vta-admin' template."
            )),
            other => other,
        })
}

/// Resolve a DID template by name (context → global → builtin). Returns
/// `NotFound` if no scope matches — caller re-wraps as a role-specific
/// Validation error (see [`resolve_admin_template`]).
pub(super) async fn resolve_template_by_name(
    state: &ProvisionIntegrationDeps,
    context: &str,
    name: &str,
) -> Result<vta_sdk::did_templates::DidTemplate, AppError> {
    if let Some(rec) =
        crate::did_templates::get_context_template(&state.did_templates_ks, context, name).await?
    {
        return Ok(rec.template);
    }
    if let Some(rec) =
        crate::did_templates::get_global_template(&state.did_templates_ks, name).await?
    {
        return Ok(rec.template);
    }
    if let Ok(tpl) = vta_sdk::did_templates::load_embedded(name) {
        return Ok(tpl);
    }
    Err(AppError::NotFound(format!("template '{name}' not found")))
}

/// Returns `true` when the template declares `methods` containing only
/// `"key"` — i.e. the operator intends a did:key integration (ephemeral
/// / headless / signing-only), not a webvh-hosted one. An empty
/// `methods` list keeps the did:webvh path (back-compat default, since
/// `methods` is advisory).
pub(super) fn template_targets_did_key_only(
    template: &vta_sdk::did_templates::DidTemplate,
) -> bool {
    !template.methods.is_empty() && template.methods.iter().all(|m| m == "key")
}

/// Returns `true` when the template declares `methods` containing `"peer"`
/// — i.e. the operator intends a self-contained `did:peer` integration (no
/// WebVH hosting, no did.jsonl, no publish). Selected before the did:key /
/// did:webvh dispatch. An empty `methods` list is not peer (back-compat
/// default stays on the did:webvh path).
pub(super) fn template_targets_did_peer(template: &vta_sdk::did_templates::DidTemplate) -> bool {
    template.methods.iter().any(|m| m == "peer")
}

/// Resolve only the `kind` field of a template (context → global →
/// builtin). Used for the VC's `credentialSubject.integrationKind`
/// without the cost of parsing the full template body.
pub(super) async fn resolve_template_kind(
    templates_ks: &crate::store::KeyspaceHandle,
    name: &str,
    context: &str,
) -> Result<String, AppError> {
    if let Some(rec) =
        crate::did_templates::get_context_template(templates_ks, context, name).await?
    {
        return Ok(rec.template.kind);
    }
    if let Some(rec) = crate::did_templates::get_global_template(templates_ks, name).await? {
        return Ok(rec.template.kind);
    }
    if let Ok(tpl) = vta_sdk::did_templates::load_embedded(name) {
        return Ok(tpl.kind);
    }
    Err(AppError::NotFound(format!("template '{name}' not found")))
}
