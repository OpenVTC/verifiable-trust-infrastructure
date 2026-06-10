use std::sync::Arc;

use tracing::info;

use crate::audit::{self, audit};
use vta_sdk::keys::KeyOrigin;
use vta_sdk::protocols::seed_management::{
    list::{ListSeedsResultBody, SeedInfo},
    rotate::RotateSeedResultBody,
};

use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::imported;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{self as seeds, get_active_seed_id, load_seed_bytes};
use crate::store::KeyspaceHandle;

pub async fn list_seeds(
    keys_ks: &KeyspaceHandle,
    channel: &str,
) -> Result<ListSeedsResultBody, AppError> {
    let active_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let records = seeds::list_seed_records(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let seeds_info: Vec<SeedInfo> = records
        .into_iter()
        .map(|r| SeedInfo {
            id: r.id,
            status: if r.retired_at.is_some() {
                "retired".into()
            } else {
                "active".into()
            },
            created_at: r.created_at,
            retired_at: r.retired_at,
        })
        .collect();

    info!(channel, count = seeds_info.len(), active_id, "seeds listed");

    Ok(ListSeedsResultBody {
        seeds: seeds_info,
        active_seed_id: active_id,
    })
}

/// Serialises seed rotation process-wide. Two concurrent rotations
/// would both read active generation N and both write N+1 — corrupting
/// the generation chain and racing `reencrypt_all` with mismatched
/// old/new seed pairs.
static ROTATE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

pub async fn rotate_seed(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
    actor: &str,
    mnemonic: Option<&str>,
    channel: &str,
) -> Result<RotateSeedResultBody, AppError> {
    // Held across read-generation → archive → write-new → re-encrypt.
    let _rotation_guard = ROTATE_LOCK.lock().await;

    // Refuse rotation on a seed store whose `set` does not survive a
    // restart (the TEE KMS store). Rotating would bump `active_seed_id`
    // to a generation whose bytes live only in enclave memory; the next
    // boot would restore the original seed and every key minted after
    // rotation would be permanently unrecoverable. Typed Conflict so the
    // CLI can render operator guidance rather than a generic 500.
    if !seed_store.set_persists_across_restart() {
        return Err(AppError::Conflict(
            "seed rotation is unavailable on this VTA: the active seed store does \
             not persist a rotated seed across a restart, so every key minted after \
             rotation would become unrecoverable on the next boot. TEE/KMS \
             deployments re-seed via a fresh enclave bootstrap, not in-place rotation."
                .into(),
        ));
    }

    let previous_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Load old seed for re-encryption of imported secrets
    let old_seed = load_seed_bytes(keys_ks, &**seed_store, Some(previous_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let new_id = seeds::rotate_seed(keys_ks, &**seed_store, mnemonic)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Re-encrypt imported secrets with the new seed
    let new_seed = load_seed_bytes(keys_ks, &**seed_store, Some(new_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Collect imported key records for AAD
    let raw = keys_ks.prefix_iter_raw("key:").await?;
    let imported_keys: Vec<(String, String)> = raw
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<KeyRecord>(&v).ok())
        .filter(|r| r.origin == KeyOrigin::Imported && r.status == vta_sdk::keys::KeyStatus::Active)
        .map(|r| (r.key_id, r.key_type.to_string()))
        .collect();

    if !imported_keys.is_empty() {
        let count =
            imported::reencrypt_all(imported_ks, keys_ks, &old_seed, &new_seed, &imported_keys)
                .await?;
        info!(
            channel,
            count, "re-encrypted imported secrets after seed rotation"
        );
    }

    info!(channel, previous_id, new_id, "seed rotated");
    audit!(
        "seed.rotate",
        actor = actor,
        resource = "seed",
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "seed.rotate",
        actor,
        Some("seed"),
        "success",
        Some(channel),
        None,
    )
    .await;

    Ok(RotateSeedResultBody {
        previous_seed_id: previous_id,
        new_seed_id: new_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    use crate::keys::seed_store::SeedStore;
    use crate::keys::seeds::{SeedRecord, get_seed_record, save_seed_record};
    use crate::store::KeyspaceHandle;

    /// A mock seed store backed by a Mutex so `set` persists across calls.
    struct MockSeedStore(Mutex<Option<Vec<u8>>>);

    impl SeedStore for MockSeedStore {
        fn get(
            &self,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<Vec<u8>>, crate::error::AppError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(self.0.lock().await.clone()) })
        }
        fn set(
            &self,
            seed: &[u8],
        ) -> Pin<
            Box<dyn std::future::Future<Output = Result<(), crate::error::AppError>> + Send + '_>,
        > {
            let seed = seed.to_vec();
            Box::pin(async move {
                *self.0.lock().await = Some(seed);
                Ok(())
            })
        }
    }

    struct TestHarness {
        keys_ks: KeyspaceHandle,
        imported_ks: KeyspaceHandle,
        audit_ks: KeyspaceHandle,
        seed_store: Arc<dyn SeedStore>,
        _dir: tempfile::TempDir,
    }

    impl TestHarness {
        async fn new() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let store_config = StoreConfig {
                data_dir: dir.path().to_path_buf(),
            };
            let store = Store::open(&store_config).expect("open store");

            let keys_ks = store.keyspace("keys").unwrap();
            let imported_ks = store.keyspace("imported_secrets").unwrap();
            let audit_ks = store.keyspace("audit").unwrap();

            let initial_seed = vec![0xABu8; 32];
            let seed_store: Arc<dyn SeedStore> =
                Arc::new(MockSeedStore(Mutex::new(Some(initial_seed))));

            // Bootstrap: create a seed record for generation 0 so rotation works
            let now = chrono::Utc::now();
            save_seed_record(
                &keys_ks,
                &SeedRecord {
                    id: 0,
                    seed_hex: None,
                    created_at: now,
                    retired_at: None,
                },
            )
            .await
            .expect("save initial seed record");

            Self {
                keys_ks,
                imported_ks,
                audit_ks,
                seed_store,
                _dir: dir,
            }
        }
    }

    /// P0.6: rotation must refuse on a seed store whose `set` does not
    /// survive a restart (the TEE KMS store), and must mutate nothing —
    /// otherwise a TEE operator who runs `keys rotate-seed` silently
    /// loses every key minted afterwards on the next enclave boot.
    #[cfg(feature = "tee")]
    #[tokio::test]
    async fn rotate_seed_refused_on_non_durable_store_and_leaves_state_intact() {
        use crate::keys::seed_store::KmsTeeSeedStore;

        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let keys_ks = store.keyspace("keys").unwrap();
        let imported_ks = store.keyspace("imported_secrets").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();

        // Bootstrap generation 0 as the active seed.
        save_seed_record(
            &keys_ks,
            &SeedRecord {
                id: 0,
                seed_hex: None,
                created_at: chrono::Utc::now(),
                retired_at: None,
            },
        )
        .await
        .expect("save gen-0 record");

        let seed_store: Arc<dyn SeedStore> = Arc::new(KmsTeeSeedStore::new(
            vec![0xABu8; 32],
            "arn:aws:kms:test".into(),
            "us-east-1".into(),
        ));

        let err = rotate_seed(
            &keys_ks,
            &imported_ks,
            &seed_store,
            &audit_ks,
            "did:key:z6MkTestAdmin",
            None,
            "test",
        )
        .await
        .expect_err("TEE rotation must be refused");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");

        // Nothing mutated: active id unchanged, gen-0 still active (not
        // archived/retired), no gen-1 record created.
        assert_eq!(get_active_seed_id(&keys_ks).await.unwrap(), 0);
        let gen0 = get_seed_record(&keys_ks, 0).await.unwrap().unwrap();
        assert!(gen0.retired_at.is_none(), "gen-0 must not be retired");
        assert!(gen0.seed_hex.is_none(), "gen-0 must stay active");
        assert!(
            get_seed_record(&keys_ks, 1).await.unwrap().is_none(),
            "no gen-1 record may be created by a refused rotation"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_rotations_produce_distinct_generations() {
        // Without ROTATE_LOCK both rotations read active generation 0
        // and both write generation 1, corrupting the chain.
        let h = TestHarness::new().await;

        let mut handles = Vec::new();
        for _ in 0..2 {
            let keys_ks = h.keys_ks.clone();
            let imported_ks = h.imported_ks.clone();
            let audit_ks = h.audit_ks.clone();
            let seed_store = h.seed_store.clone();
            handles.push(tokio::spawn(async move {
                rotate_seed(
                    &keys_ks,
                    &imported_ks,
                    &seed_store,
                    &audit_ks,
                    "did:key:z6MkTestAdmin",
                    None,
                    "test",
                )
                .await
                .expect("rotate")
            }));
        }
        let mut new_ids = Vec::new();
        for hd in handles {
            new_ids.push(hd.await.expect("join").new_seed_id);
        }
        new_ids.sort_unstable();
        assert_eq!(
            new_ids,
            vec![1, 2],
            "two concurrent rotations must produce generations 1 and 2"
        );
        let active = get_active_seed_id(&h.keys_ks).await.expect("active id");
        assert_eq!(active, 2);
    }

    #[tokio::test]
    async fn test_rotate_seed() {
        let h = TestHarness::new().await;

        // Verify initial state: active_seed_id == 0
        let initial_id = get_active_seed_id(&h.keys_ks)
            .await
            .expect("get active seed id");
        assert_eq!(initial_id, 0);

        // Rotate the seed
        let result = rotate_seed(
            &h.keys_ks,
            &h.imported_ks,
            &h.seed_store,
            &h.audit_ks,
            "did:key:z6MkTestAdmin",
            None,
            "test",
        )
        .await
        .expect("rotate_seed should succeed");

        assert_eq!(result.previous_seed_id, 0);
        assert_eq!(result.new_seed_id, 1);

        // The old seed (generation 0) should now be retired (archived with seed_hex)
        let old_record = get_seed_record(&h.keys_ks, 0)
            .await
            .expect("get seed record")
            .expect("old seed record should exist");
        assert!(
            old_record.seed_hex.is_some(),
            "retired seed should have archived hex"
        );
        assert!(
            old_record.retired_at.is_some(),
            "retired seed should have retired_at timestamp"
        );

        // The new seed (generation 1) should be active (no seed_hex)
        let new_record = get_seed_record(&h.keys_ks, 1)
            .await
            .expect("get seed record")
            .expect("new seed record should exist");
        assert!(
            new_record.seed_hex.is_none(),
            "active seed should not have archived hex"
        );
        assert!(
            new_record.retired_at.is_none(),
            "active seed should not have retired_at"
        );

        // Active seed ID should now be 1
        let new_active_id = get_active_seed_id(&h.keys_ks)
            .await
            .expect("get active seed id");
        assert_eq!(new_active_id, 1);
    }
}
