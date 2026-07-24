//! Server-side storage for DID templates.
//!
//! Two scopes:
//!
//! - **Global** — keyed `tpl:global:<name>`, super-admin-managed, visible
//!   across every context.
//! - **Context** — keyed `tpl:ctx:<context_id>:<name>`, context-admin-
//!   managed (or super admin), visible only within that context. May
//!   shadow a global template of the same name — resolution order is
//!   context → global → builtin.
//!
//! The on-wire record shape is [`vta_sdk::did_templates::DidTemplateRecord`]
//! reused verbatim — no server-side wrapper struct.

pub use vta_sdk::did_templates::DidTemplateRecord;

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

const GLOBAL_PREFIX: &str = "tpl:global:";
const CONTEXT_PREFIX: &str = "tpl:ctx:";

fn global_key(name: &str) -> String {
    format!("{GLOBAL_PREFIX}{name}")
}

fn context_prefix(context_id: &str) -> String {
    format!("{CONTEXT_PREFIX}{context_id}:")
}

fn context_key(context_id: &str, name: &str) -> String {
    format!("{CONTEXT_PREFIX}{context_id}:{name}")
}

// ── Global scope ─────────────────────────────────────────────────────

/// Fetch a global template by name.
pub async fn get_global_template(
    ks: &KeyspaceHandle,
    name: &str,
) -> Result<Option<DidTemplateRecord>, AppError> {
    ks.get(global_key(name)).await
}

/// Store (create or overwrite) a global template record.
pub async fn store_global_template(
    ks: &KeyspaceHandle,
    record: &DidTemplateRecord,
) -> Result<(), AppError> {
    ks.insert(global_key(&record.template.name), record).await
}

/// Delete a global template by name.
pub async fn delete_global_template(ks: &KeyspaceHandle, name: &str) -> Result<(), AppError> {
    ks.remove(global_key(name)).await
}

/// List every stored global template, sorted by name.
pub async fn list_global_templates(
    ks: &KeyspaceHandle,
) -> Result<Vec<DidTemplateRecord>, AppError> {
    let raw = ks.prefix_iter_raw(GLOBAL_PREFIX).await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidTemplateRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    records.sort_by(|a, b| a.template.name.cmp(&b.template.name));
    Ok(records)
}

// ── Context scope ────────────────────────────────────────────────────

/// Fetch a context-scoped template by name.
pub async fn get_context_template(
    ks: &KeyspaceHandle,
    context_id: &str,
    name: &str,
) -> Result<Option<DidTemplateRecord>, AppError> {
    ks.get(context_key(context_id, name)).await
}

/// Store (create or overwrite) a context-scoped template record.
pub async fn store_context_template(
    ks: &KeyspaceHandle,
    context_id: &str,
    record: &DidTemplateRecord,
) -> Result<(), AppError> {
    ks.insert(context_key(context_id, &record.template.name), record)
        .await
}

/// Delete a context-scoped template by name.
pub async fn delete_context_template(
    ks: &KeyspaceHandle,
    context_id: &str,
    name: &str,
) -> Result<(), AppError> {
    ks.remove(context_key(context_id, name)).await
}

/// List every stored context-scoped template for one context, sorted by name.
pub async fn list_context_templates(
    ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<Vec<DidTemplateRecord>, AppError> {
    let raw = ks.prefix_iter_raw(context_prefix(context_id)).await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidTemplateRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    records.sort_by(|a, b| a.template.name.cmp(&b.template.name));
    Ok(records)
}

/// Delete every template attached to a context. Used by context deletion
/// so orphaned records don't linger after their parent context is gone.
///
/// Returns the number of records removed.
pub async fn delete_all_context_templates(
    ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<usize, AppError> {
    let records = list_context_templates(ks, context_id).await?;
    let count = records.len();
    for r in records {
        ks.remove(context_key(context_id, &r.template.name)).await?;
    }
    Ok(count)
}
