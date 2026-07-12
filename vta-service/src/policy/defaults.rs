//! Boot-installed default policy.
//!
//! Mirrors vtc-service's `install_defaults`: seed a baseline only when the
//! operator hasn't already provided one, so uploads are never clobbered. Here
//! "already provided" is simply "the policy keyspace is non-empty".

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::storage;
use super::types::PolicyModule;

/// Stable id of the boot-installed baseline.
pub const DEFAULT_POLICY_ID: &str = "default";

/// The baseline Rego, embedded at compile time. Validated by a test below so a
/// broken default can never ship.
pub const DEFAULT_POLICY_REGO: &str = include_str!("../../policies/default.rego");

/// Install the baseline policy iff the policy keyspace is empty.
///
/// Called once at boot after the store is opened. Idempotent: a second call is
/// a no-op because the keyspace is no longer empty. Never overwrites an
/// operator's policy set (if any row exists, this does nothing).
pub async fn install_default_policy(
    policy_ks: &KeyspaceHandle,
    now_rfc3339: &str,
) -> Result<(), AppError> {
    if !storage::list_policies(policy_ks).await?.is_empty() {
        return Ok(());
    }
    // Compile-check before storing so a malformed embedded default fails loudly
    // at boot rather than silently seeding an unparseable policy.
    super::engine::compile(DEFAULT_POLICY_REGO, DEFAULT_POLICY_ID)?;

    let baseline = PolicyModule {
        id: DEFAULT_POLICY_ID.to_string(),
        name: "Default baseline".to_string(),
        description: Some(
            "Boot-installed permissive baseline; operators layer higher-priority \
             policies to tighten. See policies/default.rego."
                .to_string(),
        ),
        module: DEFAULT_POLICY_REGO.to_string(),
        applies_to: Vec::new(), // all contexts
        priority: 0,
        enabled: true,
        version: 1,
        created_at: now_rfc3339.to_string(),
        updated_at: now_rfc3339.to_string(),
    };
    storage::store_policy(policy_ks, &baseline).await?;
    tracing::info!(
        policy = DEFAULT_POLICY_ID,
        "installed default PDP baseline policy"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        (store.keyspace(crate::keyspaces::POLICY).unwrap(), dir)
    }

    #[test]
    fn embedded_default_compiles() {
        // The shipped baseline must always be valid Rego.
        super::super::engine::compile(DEFAULT_POLICY_REGO, "default")
            .expect("default.rego compiles");
    }

    #[tokio::test]
    async fn installs_when_empty_and_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        install_default_policy(&ks, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        let after_first = storage::list_policies(&ks).await.unwrap();
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].id, DEFAULT_POLICY_ID);

        // Second call is a no-op.
        install_default_policy(&ks, "2026-02-02T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(storage::list_policies(&ks).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn does_not_clobber_an_operator_policy() {
        let (ks, _dir) = temp_ks().await;
        let op = PolicyModule {
            id: "operator".into(),
            name: "op".into(),
            description: None,
            module: "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\"}"
                .into(),
            applies_to: vec![],
            priority: 100,
            enabled: true,
            version: 1,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        storage::store_policy(&ks, &op).await.unwrap();
        install_default_policy(&ks, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        // Non-empty keyspace ⇒ baseline NOT installed.
        let all = storage::list_policies(&ks).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "operator");
    }
}
