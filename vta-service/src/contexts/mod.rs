pub use vta_sdk::contexts::ContextRecord;

use chrono::Utc;
use vta_sdk::context_path::parent_path;
use vta_sdk::context_policy::ContextPolicy;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn ctx_key(id: &str) -> String {
    format!("ctx:{id}")
}

/// Retrieve a context by ID.
pub async fn get_context(ks: &KeyspaceHandle, id: &str) -> Result<Option<ContextRecord>, AppError> {
    ks.get(ctx_key(id)).await
}

/// Resolve the *effective* [`ContextPolicy`] for `context_id` by intersecting
/// the policies of every context on the path root→leaf (field-wise, additive
/// narrowing — see [`ContextPolicy`] docs). Contexts with no policy (or a
/// missing record) contribute nothing; a chain that constrains nothing resolves
/// to [`ContextPolicy::unrestricted`], i.e. today's behaviour.
///
/// Because enforcement always resolves the whole chain, a permissive policy
/// written at a child level can never widen what an ancestor allows.
pub async fn effective_context_policy(
    ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<ContextPolicy, AppError> {
    // Collect ids leaf→root, then resolve root→leaf.
    let mut ids: Vec<String> = Vec::new();
    let mut cur: Option<String> = Some(context_id.to_string());
    while let Some(id) = cur {
        cur = parent_path(&id).map(str::to_string);
        ids.push(id);
    }
    ids.reverse();

    let mut policies: Vec<ContextPolicy> = Vec::new();
    for id in &ids {
        if let Some(rec) = get_context(ks, id).await? {
            if let Some(policy) = rec.context_policy {
                policies.push(policy);
            }
        }
    }
    Ok(ContextPolicy::resolve(policies.iter()))
}

/// Enforce a per-day operation quota for a context (the `quotas` arm of
/// [`ContextPolicy`]). Atomically counts this operation in the current UTC day
/// and returns `Forbidden` once the ceiling is reached. Counters are keyed by
/// day (`quota:{context}:{op}:{YYYY-MM-DD}`) in the contexts keyspace, so they
/// roll over automatically and stale days are inert (a future sweep can prune
/// them). `allocate_u32` is 0-indexed, so the call that returns `limit` is the
/// `(limit+1)`-th — rejecting it allows exactly `limit` operations per day.
pub async fn enforce_daily_quota(
    ks: &KeyspaceHandle,
    context_id: &str,
    op_class: &str,
    limit: u64,
) -> Result<(), AppError> {
    let day = Utc::now().format("%Y-%m-%d");
    let key = format!("quota:{context_id}:{op_class}:{day}");
    let slot = vti_common::store::counter::allocate_u32(ks, &key).await?;
    if u64::from(slot) >= limit {
        return Err(AppError::Forbidden(format!(
            "daily quota exceeded for {op_class} in context {context_id} ({limit}/day)"
        )));
    }
    Ok(())
}

/// Store (create or overwrite) a context record.
pub async fn store_context(ks: &KeyspaceHandle, record: &ContextRecord) -> Result<(), AppError> {
    ks.insert(ctx_key(&record.id), record).await
}

/// Store a NEW context record, claiming the id atomically. Returns
/// `false` (storing nothing) when the id is already taken — creation
/// paths must treat that as a Conflict, never overwrite: last-writer-
/// wins on a context record silently re-points its BIP-32 base path.
pub async fn store_new_context(
    ks: &KeyspaceHandle,
    record: &ContextRecord,
) -> Result<bool, AppError> {
    ks.insert_if_absent(ctx_key(&record.id), record).await
}

/// Delete a context by ID.
pub async fn delete_context(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(ctx_key(id)).await
}

/// List all context records.
///
/// A row that fails to deserialize is skipped with a warning rather than
/// aborting the whole listing — one corrupt context must not break
/// context management for every other context.
pub async fn list_contexts(ks: &KeyspaceHandle) -> Result<Vec<ContextRecord>, AppError> {
    let raw = ks.prefix_iter_raw("ctx:").await?;
    let mut records = Vec::with_capacity(raw.len());
    let mut skipped = 0usize;
    for (key, value) in raw {
        match serde_json::from_slice::<ContextRecord>(&value) {
            Ok(record) => records.push(record),
            Err(e) => {
                skipped += 1;
                tracing::warn!(
                    key = %String::from_utf8_lossy(&key),
                    error = %e,
                    "skipping undeserializable context row in list_contexts"
                );
            }
        }
    }
    if skipped > 0 {
        tracing::warn!(skipped, "list_contexts skipped corrupt rows");
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
    // Serialised via the shared counter allocator: two concurrent
    // context creations handed the same index would share an entire
    // BIP-32 subtree — identical private keys across trust boundaries.
    let current = vti_common::store::counter::allocate_u32(ks, counter_key).await?;
    let base_path = format!("{base_prefix}/{current}'");
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
        context_policy: None,
    };
    if !store_new_context(contexts_ks, &record)
        .await
        .map_err(|e| format!("{e}"))?
    {
        // The allocated counter slot is intentionally left as a gap —
        // counters skip forward on a lost race, they never reuse.
        return Err(format!("context already exists: {id}").into());
    }
    Ok(record)
}

/// Base path for application context keys.
pub const CONTEXT_KEY_BASE: &str = "m/26'/2'";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        (
            store
                .keyspace(crate::keyspaces::CONTEXTS)
                .expect("keyspace"),
            dir,
        )
    }

    #[tokio::test]
    async fn daily_quota_allows_up_to_limit_then_forbids() {
        let (ks, _dir) = temp_ks();
        // Limit 2: the first two operations pass, the third is refused.
        enforce_daily_quota(&ks, "sales", "sign", 2).await.unwrap();
        enforce_daily_quota(&ks, "sales", "sign", 2).await.unwrap();
        let err = enforce_daily_quota(&ks, "sales", "sign", 2).await;
        assert!(matches!(err, Err(AppError::Forbidden(_))), "{err:?}");

        // A different op-class (and a different context) has an independent
        // counter.
        enforce_daily_quota(&ks, "sales", "vault/release", 1)
            .await
            .unwrap();
        let err2 = enforce_daily_quota(&ks, "sales", "vault/release", 1).await;
        assert!(matches!(err2, Err(AppError::Forbidden(_))), "{err2:?}");
        enforce_daily_quota(&ks, "eng", "sign", 2).await.unwrap();
    }

    /// Regression test for the context-index race: N concurrent
    /// allocations must yield N distinct base paths. Two contexts
    /// handed the same index would share an entire BIP-32 subtree —
    /// identical private keys across trust boundaries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn allocate_context_index_is_collision_free_under_concurrency() {
        let (ks, _dir) = temp_ks();

        let n = 64usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                allocate_context_index(&ks, CONTEXT_KEY_BASE, "ctx_counter")
                    .await
                    .expect("alloc")
            }));
        }
        let mut paths = std::collections::HashSet::with_capacity(n);
        for h in handles {
            let (_, base_path) = h.await.expect("join");
            assert!(
                paths.insert(base_path.clone()),
                "duplicate context base path {base_path}"
            );
        }
        assert_eq!(paths.len(), n);
    }

    /// Concurrent creates with the same id: exactly one may win; the
    /// losers must not overwrite the winner's record (last-writer-wins
    /// would silently re-point the context's BIP-32 base path).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_id_creates_admit_exactly_one() {
        let (ks, _dir) = temp_ks();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let ks = ks.clone();
            handles.push(tokio::spawn(async move {
                create_context(&ks, "contested", "Contested").await.ok()
            }));
        }
        let mut winners = Vec::new();
        for h in handles {
            if let Some(rec) = h.await.expect("join") {
                winners.push(rec);
            }
        }
        assert_eq!(winners.len(), 1, "exactly one same-id create may win");

        let stored = get_context(&ks, "contested")
            .await
            .expect("get")
            .expect("record exists");
        assert_eq!(
            stored.base_path, winners[0].base_path,
            "stored record must be the winner's — no overwrite by losers"
        );
    }
}
