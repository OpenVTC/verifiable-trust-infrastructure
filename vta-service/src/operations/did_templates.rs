//! DID template CRUD + render operations.
//!
//! Two scopes:
//!
//! - **Global**: writes gated on super admin, reads open to any
//!   authenticated caller.
//! - **Context**: writes gated on context admin (Admin role with the
//!   target context in `allowed_contexts`) or super admin. Reads gated
//!   on context access (any role that has the context on their ACL).
//!
//! Templates are advisory shapes, not secrets — reads are intentionally
//! permissive so managers and initiators can preview what a create flow
//! will produce.

use chrono::Utc;
use serde_json::Value;
use tracing::info;

use vta_sdk::did_templates::{DidTemplate, DidTemplateRecord, Scope, TemplateVars};
use vti_common::identifier::validate_identifier;

use crate::audit;
use crate::auth::AuthClaims;
use crate::did_templates as store;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Create a new global template. Super admin only.
///
/// Rejects duplicates — updates must go through [`update_global`].
pub async fn create_global(
    templates_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    template: DidTemplate,
    channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    auth.require_super_admin()?;

    // The SDK validator already ran in `DidTemplate::from_json` if the
    // caller built it through the parse path; re-run it here to defend
    // against programmatic construction with invalid shapes.
    template
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    // Defence against store-keyspace injection: a template name
    // containing ':' or other separator characters could collide with
    // adjacent keyspace prefixes (see vti_common::identifier).
    validate_identifier("template name", &template.name)?;

    if store::get_global_template(templates_ks, &template.name)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "template already exists: {}",
            template.name
        )));
    }

    let now = unix_secs();
    let record = DidTemplateRecord {
        template,
        scope: Scope::Global,
        created_at: now,
        updated_at: now,
        created_by: auth.did.clone(),
    };

    store::store_global_template(templates_ks, &record).await?;
    let _ = audit::record(
        audit,
        "did_template.created",
        &auth.did,
        Some(&record.template.name),
        "success",
        Some(channel),
        None,
    )
    .await;

    info!(channel, name = %record.template.name, "did template created");
    Ok(record)
}

/// Update an existing global template. Super admin only.
///
/// `created_at` and `created_by` are preserved from the stored record;
/// `updated_at` advances to now. The entire [`DidTemplate`] body is
/// replaced — partial updates go through delete + create.
pub async fn update_global(
    templates_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    name: &str,
    template: DidTemplate,
    channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    auth.require_super_admin()?;
    validate_identifier("template name", name)?;

    if template.name != name {
        return Err(AppError::Validation(format!(
            "template name in body ('{}') does not match path ('{name}')",
            template.name
        )));
    }

    template
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let existing = store::get_global_template(templates_ks, name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("template not found: {name}")))?;

    let record = DidTemplateRecord {
        template,
        scope: Scope::Global,
        created_at: existing.created_at,
        updated_at: unix_secs(),
        created_by: existing.created_by,
    };

    store::store_global_template(templates_ks, &record).await?;
    let _ = audit::record(
        audit,
        "did_template.updated",
        &auth.did,
        Some(&record.template.name),
        "success",
        Some(channel),
        None,
    )
    .await;

    info!(channel, name = %record.template.name, "did template updated");
    Ok(record)
}

/// Fetch a single global template by name.
///
/// Open to any authenticated caller — templates don't carry secrets and
/// any admin or manager may want to preview one.
pub async fn get_global(
    templates_ks: &KeyspaceHandle,
    _auth: &AuthClaims,
    name: &str,
    _channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    store::get_global_template(templates_ks, name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("template not found: {name}")))
}

/// List every stored global template.
///
/// Open to any authenticated caller. Return is sorted by name.
pub async fn list_global(
    templates_ks: &KeyspaceHandle,
    _auth: &AuthClaims,
    _channel: &str,
) -> Result<Vec<DidTemplateRecord>, AppError> {
    store::list_global_templates(templates_ks).await
}

/// Delete a global template. Super admin only.
pub async fn delete_global(
    templates_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    name: &str,
    channel: &str,
) -> Result<(), AppError> {
    auth.require_super_admin()?;

    if store::get_global_template(templates_ks, name)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!("template not found: {name}")));
    }

    store::delete_global_template(templates_ks, name).await?;
    let _ = audit::record(
        audit,
        "did_template.deleted",
        &auth.did,
        Some(name),
        "success",
        Some(channel),
        None,
    )
    .await;

    info!(channel, name, "did template deleted");
    Ok(())
}

/// Render a stored global template with caller-supplied variables.
///
/// Renders never audit — they're read-only and frequent. Ambient variables
/// the server knows about are injected automatically (`VTA_DID`, `VTA_URL`,
/// `NOW`). The caller supplies everything else.
pub async fn render_global(
    templates_ks: &KeyspaceHandle,
    config: &crate::config::AppConfig,
    _auth: &AuthClaims,
    name: &str,
    caller_vars: TemplateVars,
    _channel: &str,
) -> Result<Value, AppError> {
    let record = store::get_global_template(templates_ks, name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("template not found: {name}")))?;

    let mut vars = ambient_vars(config);
    vars.extend(caller_vars);

    record
        .template
        .render(&vars)
        .map_err(|e| AppError::Validation(e.to_string()))
}

/// Build the ambient variable set the server can fill in without caller input.
///
/// Phase 4 extends this with DID-creation-flow vars (DID, SIGNING_KEY_MB,
/// KA_KEY_MB). Phase 3 adds `CONTEXT_ID` / `CONTEXT_DID` when a render
/// happens in context scope — see [`ambient_vars_with_context`].
fn ambient_vars(config: &crate::config::AppConfig) -> TemplateVars {
    let mut vars = TemplateVars::new();
    if let Some(vta_did) = config.vta_did.as_deref() {
        vars.insert_string("VTA_DID", vta_did);
    }
    if let Some(vta_url) = config.public_url.as_deref() {
        vars.insert_string("VTA_URL", vta_url);
    }
    vars.insert_string("NOW", Utc::now().to_rfc3339());
    vars
}

/// Like [`ambient_vars`], but also injects `CONTEXT_ID` and (if the context
/// has a DID set) `CONTEXT_DID`. Used by context-scope render.
async fn ambient_vars_with_context(
    config: &crate::config::AppConfig,
    contexts_ks: &KeyspaceHandle,
    context_id: &str,
) -> TemplateVars {
    let mut vars = ambient_vars(config);
    vars.insert_string("CONTEXT_ID", context_id);
    if let Ok(Some(ctx)) = crate::contexts::get_context(contexts_ks, context_id).await
        && let Some(ref did) = ctx.did
    {
        vars.insert_string("CONTEXT_DID", did.clone());
    }
    vars
}

// ── Context scope ────────────────────────────────────────────────────

/// Write-side authz for context-scoped templates: super admin, or admin
/// with the target context in `allowed_contexts`.
fn require_context_write(auth: &AuthClaims, context_id: &str) -> Result<(), AppError> {
    if auth.is_super_admin() {
        return Ok(());
    }
    auth.require_admin()?;
    auth.require_context(context_id)?;
    Ok(())
}

/// Read-side authz for context-scoped templates: any authenticated caller
/// with access to the context (super admin or context in `allowed_contexts`).
fn require_context_read(auth: &AuthClaims, context_id: &str) -> Result<(), AppError> {
    auth.require_context(context_id)
}

/// Create a new context-scoped template. Context-admin-or-super.
///
/// Rejects if the context does not exist — templates attached to a missing
/// parent would orphan on creation.
pub async fn create_context(
    templates_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    context_id: &str,
    template: DidTemplate,
    channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    require_context_write(auth, context_id)?;
    validate_identifier("context id", context_id)?;
    validate_identifier("template name", &template.name)?;

    if crate::contexts::get_context(contexts_ks, context_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "context not found: {context_id}"
        )));
    }

    template
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    if store::get_context_template(templates_ks, context_id, &template.name)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "template already exists in context '{context_id}': {}",
            template.name
        )));
    }

    let now = unix_secs();
    let record = DidTemplateRecord {
        template,
        scope: Scope::Context {
            context_id: context_id.to_string(),
        },
        created_at: now,
        updated_at: now,
        created_by: auth.did.clone(),
    };

    store::store_context_template(templates_ks, context_id, &record).await?;
    let _ = audit::record(
        audit,
        "did_template.created",
        &auth.did,
        Some(&record.template.name),
        "success",
        Some(channel),
        Some(context_id),
    )
    .await;

    info!(
        channel,
        context_id,
        name = %record.template.name,
        "did template created (context scope)"
    );
    Ok(record)
}

/// Replace an existing context-scoped template. Context-admin-or-super.
pub async fn update_context(
    templates_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    context_id: &str,
    name: &str,
    template: DidTemplate,
    channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    require_context_write(auth, context_id)?;
    validate_identifier("context id", context_id)?;
    validate_identifier("template name", name)?;

    if template.name != name {
        return Err(AppError::Validation(format!(
            "template name in body ('{}') does not match path ('{name}')",
            template.name
        )));
    }

    template
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let existing = store::get_context_template(templates_ks, context_id, name)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "template not found in context '{context_id}': {name}"
            ))
        })?;

    let record = DidTemplateRecord {
        template,
        scope: Scope::Context {
            context_id: context_id.to_string(),
        },
        created_at: existing.created_at,
        updated_at: unix_secs(),
        created_by: existing.created_by,
    };

    store::store_context_template(templates_ks, context_id, &record).await?;
    let _ = audit::record(
        audit,
        "did_template.updated",
        &auth.did,
        Some(&record.template.name),
        "success",
        Some(channel),
        Some(context_id),
    )
    .await;

    info!(
        channel,
        context_id,
        name = %record.template.name,
        "did template updated (context scope)"
    );
    Ok(record)
}

/// Fetch a single context-scoped template by name.
pub async fn get_context(
    templates_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: &str,
    name: &str,
    _channel: &str,
) -> Result<DidTemplateRecord, AppError> {
    require_context_read(auth, context_id)?;
    store::get_context_template(templates_ks, context_id, name)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "template not found in context '{context_id}': {name}"
            ))
        })
}

/// List context-scoped templates for one context.
pub async fn list_context(
    templates_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: &str,
    _channel: &str,
) -> Result<Vec<DidTemplateRecord>, AppError> {
    require_context_read(auth, context_id)?;
    store::list_context_templates(templates_ks, context_id).await
}

/// Delete a context-scoped template. Context-admin-or-super.
pub async fn delete_context(
    templates_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    context_id: &str,
    name: &str,
    channel: &str,
) -> Result<(), AppError> {
    require_context_write(auth, context_id)?;

    if store::get_context_template(templates_ks, context_id, name)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "template not found in context '{context_id}': {name}"
        )));
    }

    store::delete_context_template(templates_ks, context_id, name).await?;
    let _ = audit::record(
        audit,
        "did_template.deleted",
        &auth.did,
        Some(name),
        "success",
        Some(channel),
        Some(context_id),
    )
    .await;

    info!(
        channel,
        context_id, name, "did template deleted (context scope)"
    );
    Ok(())
}

/// Render a context-scoped template with caller-supplied variables. Any
/// caller with read access to the context. Ambient vars include
/// `CONTEXT_ID` (always) and `CONTEXT_DID` (if set on the context record).
#[allow(clippy::too_many_arguments)]
pub async fn render_context(
    templates_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    config: &crate::config::AppConfig,
    auth: &AuthClaims,
    context_id: &str,
    name: &str,
    caller_vars: TemplateVars,
    _channel: &str,
) -> Result<Value, AppError> {
    require_context_read(auth, context_id)?;
    let record = store::get_context_template(templates_ks, context_id, name)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "template not found in context '{context_id}': {name}"
            ))
        })?;

    let mut vars = ambient_vars_with_context(config, contexts_ks, context_id).await;
    vars.extend(caller_vars);

    record
        .template
        .render(&vars)
        .map_err(|e| AppError::Validation(e.to_string()))
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
