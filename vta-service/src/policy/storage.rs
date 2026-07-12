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
//! consumes. Compilation is per-request (matching vtc); a compiled-policy cache
//! is a later optimisation.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    async fn temp_policy_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store.keyspace(crate::keyspaces::POLICY).expect("policy ks");
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
