//! Persistence for the PDP's Rego policy set, in the `policy` keyspace.
//!
//! One [`PolicyModule`] per id under `policy:<id>`. Unlike vtc-service (one
//! active policy per purpose, via a second pointer keyspace), our active set is
//! simply *every enabled row*, evaluated priority-ordered — so a single
//! keyspace suffices and there is no pointer to flip.
//!
//! [`load_active_for_context`] is the bridge to [`super::decide`]: it filters
//! the stored modules to those enabled and applicable to a context, compiles
//! each, and returns the `(priority, CompiledPolicy)` pairs the orchestrator
//! consumes. The PDP reaches it through [`PolicyCache`], which keeps the compiled
//! set until the keyspace is written again.

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::engine::{self, CompiledPolicy};
use super::types::PolicyModule;

const POLICY_PREFIX: &[u8] = b"policy:";

fn policy_key(id: &str) -> Vec<u8> {
    let mut k = POLICY_PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<PolicyModule, AppError> {
    serde_json::from_slice(bytes).map_err(|e| AppError::Internal(format!("policy decode: {e}")))
}

/// Retrieve a policy by id. `Ok(None)` if absent.
pub async fn get_policy(ks: &KeyspaceHandle, id: &str) -> Result<Option<PolicyModule>, AppError> {
    match ks.get_raw(policy_key(id)).await? {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Persist a policy row (create or overwrite by id). Callers set `version` /
/// `updated_at` before calling; this helper never edits them.
pub async fn store_policy(ks: &KeyspaceHandle, policy: &PolicyModule) -> Result<(), AppError> {
    let key = String::from_utf8(policy_key(&policy.id))
        .map_err(|e| AppError::Internal(format!("policy key not utf-8: {e}")))?;
    ks.insert(key, policy).await
}

/// Delete a policy row. Idempotent.
pub async fn delete_policy(ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    ks.remove(policy_key(id)).await
}

/// Every stored policy row (whole-keyspace walk). Unparseable rows are skipped
/// with a warning rather than failing the whole load.
pub async fn list_policies(ks: &KeyspaceHandle) -> Result<Vec<PolicyModule>, AppError> {
    let raw = ks.prefix_iter_raw(POLICY_PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match decode(&v) {
            Ok(p) => out.push(p),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable policy row"),
        }
    }
    Ok(out)
}

/// Load, filter, and compile the active policy set for a context.
///
/// Active = `enabled` and (`appliesTo` empty ⇒ all contexts, or contains
/// `context_id`). A stored policy that fails to compile is **skipped with a
/// loud error**, not fatal: the requests it would have governed fall through to
/// the orchestrator's default-deny rather than the whole PDP failing. (A broken
/// *allow* policy denying is fail-safe; a broken *deny* policy is logged so an
/// operator notices enforcement dropped.)
pub async fn load_active_for_context(
    ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<Vec<(i32, CompiledPolicy)>, AppError> {
    let modules = list_policies(ks).await?;
    let mut active = Vec::new();
    for m in modules {
        if !m.enabled {
            continue;
        }
        if !m.applies_to.is_empty() && !m.applies_to.iter().any(|c| c == context_id) {
            continue;
        }
        match engine::compile(&m.module, &m.id) {
            Ok(compiled) => active.push((m.priority, compiled)),
            Err(err) => tracing::error!(
                policy = %m.id,
                error = %err,
                "active policy failed to compile — skipped; requests it would govern default-deny"
            ),
        }
    }
    Ok(active)
}

/// One stored policy, compiled, with what decides where it applies.
#[derive(Clone)]
struct CompiledEntry {
    priority: i32,
    applies_to: Vec<String>,
    compiled: CompiledPolicy,
}

/// Every enabled policy in the keyspace, compiled, kept until the keyspace is
/// written again (#2623).
///
/// [`load_active_for_context`] lists the keyspace and parses and compiles every
/// active Rego module, which the PDP did once per gated Trust Task. The set
/// changes only when a policy row is written — upsert, delete, enable, the
/// declarative approvals row — so this keeps the compiled set under the
/// keyspace's [`KeyspaceHandle::cache_ticket`]: a cached set is served only
/// while no write has begun, landed or been abandoned since it was read, and a
/// fresh read is cached only if no write raced it. Any write through any path
/// (including a restore, which reaches the store before any request) moves the
/// ticket, so nothing is invalidated by hand.
#[derive(Default)]
pub struct PolicyCache {
    cached: std::sync::Mutex<Option<(u64, std::sync::Arc<Vec<CompiledEntry>>)>>,
}

impl std::fmt::Debug for PolicyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyCache").finish_non_exhaustive()
    }
}

impl PolicyCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// [`load_active_for_context`], compiling only when the keyspace changed
    /// since the set was last compiled. Compilation runs on the blocking pool:
    /// it is a full Rego parse per module, CPU work that must not hold an
    /// executor thread.
    pub async fn active_for_context(
        &self,
        ks: &KeyspaceHandle,
        context_id: &str,
    ) -> Result<Vec<(i32, CompiledPolicy)>, AppError> {
        let ticket = ks.cache_ticket();
        let hit = ticket.and_then(|t| {
            self.lock()
                .as_ref()
                .filter(|(at, _)| *at == t)
                .map(|(_, set)| set.clone())
        });
        let set = match hit {
            Some(set) => set,
            None => {
                let modules = list_policies(ks).await?;
                let compiled = tokio::task::spawn_blocking(move || compile_enabled(modules))
                    .await
                    .map_err(|e| AppError::Internal(format!("policy compile panicked: {e}")))?;
                let set = std::sync::Arc::new(compiled);
                if let Some(t) = ticket
                    && ks.ticket_is_current(t)
                {
                    *self.lock() = Some((t, set.clone()));
                }
                set
            }
        };
        Ok(set
            .iter()
            .filter(|e| e.applies_to.is_empty() || e.applies_to.iter().any(|c| c == context_id))
            .map(|e| (e.priority, e.compiled.clone()))
            .collect())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<(u64, std::sync::Arc<Vec<CompiledEntry>>)>> {
        self.cached.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Compile every enabled module, skipping (loudly) one that fails, as
/// [`load_active_for_context`] does.
fn compile_enabled(modules: Vec<PolicyModule>) -> Vec<CompiledEntry> {
    modules
        .into_iter()
        .filter(|m| m.enabled)
        .filter_map(|m| match engine::compile(&m.module, &m.id) {
            Ok(compiled) => Some(CompiledEntry {
                priority: m.priority,
                applies_to: m.applies_to,
                compiled,
            }),
            Err(err) => {
                tracing::error!(
                    policy = %m.id,
                    error = %err,
                    "active policy failed to compile — skipped; requests it would govern default-deny"
                );
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_policy_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace(vta_keyspaces::POLICY).expect("policy ks");
        // `dir` owns the backing; return it so it outlives the handle.
        (ks, dir)
    }

    fn module(
        id: &str,
        priority: i32,
        enabled: bool,
        applies_to: Vec<String>,
        rego: &str,
    ) -> PolicyModule {
        PolicyModule {
            id: id.into(),
            name: id.into(),
            description: None,
            module: rego.into(),
            applies_to,
            priority,
            enabled,
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            ext: serde_json::Value::Null,
        }
    }

    const ALLOW: &str = "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"allow\"}";

    #[tokio::test]
    async fn crud_round_trip() {
        let (ks, _dir) = temp_policy_ks().await;
        let m = module("p1", 0, true, vec![], ALLOW);
        store_policy(&ks, &m).await.unwrap();
        let got = get_policy(&ks, "p1").await.unwrap().expect("present");
        assert_eq!(got.name, "p1");
        assert_eq!(list_policies(&ks).await.unwrap().len(), 1);
        delete_policy(&ks, "p1").await.unwrap();
        assert!(get_policy(&ks, "p1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn load_active_filters_disabled_and_context() {
        let (ks, _dir) = temp_policy_ks().await;
        store_policy(&ks, &module("global", 0, true, vec![], ALLOW))
            .await
            .unwrap();
        store_policy(&ks, &module("disabled", 0, false, vec![], ALLOW))
            .await
            .unwrap();
        store_policy(&ks, &module("ctxA", 5, true, vec!["ctxA".into()], ALLOW))
            .await
            .unwrap();
        store_policy(&ks, &module("ctxB", 5, true, vec!["ctxB".into()], ALLOW))
            .await
            .unwrap();

        let active = load_active_for_context(&ks, "ctxA").await.unwrap();
        // global (all contexts) + ctxA — not disabled, not ctxB.
        assert_eq!(active.len(), 2, "expected global + ctxA only");
    }

    /// #2623: the cache answers as `load_active_for_context` does, compiles
    /// once while the keyspace is unchanged, and sees every write.
    #[tokio::test]
    async fn the_cache_compiles_once_and_follows_every_write() {
        let (ks, _dir) = temp_policy_ks().await;
        let cache = PolicyCache::new();
        store_policy(&ks, &module("global", 0, true, vec![], ALLOW))
            .await
            .unwrap();
        store_policy(&ks, &module("ctxB", 5, true, vec!["ctxB".into()], ALLOW))
            .await
            .unwrap();

        let first = cache.active_for_context(&ks, "ctxA").await.unwrap();
        assert_eq!(first.len(), 1);
        let cached = cache.lock().as_ref().map(|(_, set)| set.clone()).unwrap();
        cache.active_for_context(&ks, "ctxB").await.unwrap();
        let again = cache.lock().as_ref().map(|(_, set)| set.clone()).unwrap();
        assert!(
            std::sync::Arc::ptr_eq(&cached, &again),
            "an unchanged keyspace is not recompiled"
        );
        assert_eq!(
            cache.active_for_context(&ks, "ctxB").await.unwrap().len(),
            2
        );

        // A write (here, disabling) is seen on the next decision.
        store_policy(&ks, &module("global", 0, false, vec![], ALLOW))
            .await
            .unwrap();
        assert!(
            cache
                .active_for_context(&ks, "ctxA")
                .await
                .unwrap()
                .is_empty()
        );
        delete_policy(&ks, "ctxB").await.unwrap();
        assert!(
            cache
                .active_for_context(&ks, "ctxB")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn load_active_skips_uncompilable_policy() {
        let (ks, _dir) = temp_policy_ks().await;
        store_policy(&ks, &module("good", 0, true, vec![], ALLOW))
            .await
            .unwrap();
        store_policy(
            &ks,
            &module(
                "broken",
                0,
                true,
                vec![],
                "package vta.policy\ndecision := {",
            ),
        )
        .await
        .unwrap();
        // The broken row is skipped (logged), not fatal.
        let active = load_active_for_context(&ks, "any").await.unwrap();
        assert_eq!(active.len(), 1, "only the compilable policy loads");
    }
}
