pub use vta_sdk::contexts::ContextRecord;

use chrono::Utc;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn ctx_key(id: &str) -> String {
    format!("ctx:{id}")
}

/// Retrieve a context by ID.
pub async fn get_context(ks: &KeyspaceHandle, id: &str) -> Result<Option<ContextRecord>, AppError> {
    ks.get(ctx_key(id)).await
}

/// Store (create or overwrite) a context record.
pub async fn store_context(ks: &KeyspaceHandle, record: &ContextRecord) -> Result<(), AppError> {
    ks.insert(ctx_key(&record.id), record).await
}

/// Delete a context by ID.
pub async fn delete_context(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(ctx_key(id)).await
}

/// List all context records.
pub async fn list_contexts(ks: &KeyspaceHandle) -> Result<Vec<ContextRecord>, AppError> {
    let raw = ks.prefix_iter_raw("ctx:").await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: ContextRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    Ok(records)
}

/// Allocate the next context index and return `(index, base_path)`.
///
/// Allocate the next BIP-32 base path under `base_prefix`, bumping the counter
/// at `counter_key`.
///
/// Top-level contexts use [`CONTEXT_KEY_BASE`] + the legacy `ctx_counter` key
/// (so existing indices are preserved). A sub-context passes its **parent's**
/// `base_path` as the prefix and a **per-parent** counter key, so each parent
/// allocates its children independently and the derivation path nests:
/// `{parent.base_path}/<child>'`.
pub async fn allocate_context_index(
    ks: &KeyspaceHandle,
    base_prefix: &str,
    counter_key: &str,
) -> Result<(u32, String), AppError> {
    let current: u32 = match ks.get_raw(counter_key).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| AppError::Internal("corrupt context counter".into()))?;
            u32::from_le_bytes(arr)
        }
        None => 0,
    };
    let base_path = format!("{base_prefix}/{current}'");
    ks.insert_raw(counter_key, (current + 1).to_le_bytes().to_vec())
        .await?;
    Ok((current, base_path))
}

/// Create a new top-level application context and store it.
pub async fn create_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    let (index, base_path) = allocate_context_index(contexts_ks, CONTEXT_KEY_BASE, "ctx_counter")
        .await
        .map_err(|e| format!("{e}"))?;
    let now = Utc::now();
    let record = ContextRecord {
        id: id.to_string(),
        name: name.to_string(),
        did: None,
        description: None,
        parent: None,
        base_path,
        index,
        created_at: now,
        updated_at: now,
    };
    store_context(contexts_ks, &record)
        .await
        .map_err(|e| format!("{e}"))?;
    Ok(record)
}

/// Base path for application context keys.
pub const CONTEXT_KEY_BASE: &str = "m/26'/2'";
