//! End-to-end restore tests: export from one store, stage into another, boot
//! (load + apply + finish), and check what the target holds — across every
//! pairing of plain, hardened and enclave deployments.
//!
//! The storage key a hardened VTA or an enclave derives from its seed is
//! modelled by [`storage_key_for`]; what matters to a restore is only that it
//! is a function of the seed, which both real derivations are.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use sha2::{Digest, Sha256};

use vta_sdk::protocols::backup_management::types::{BackupEnvironment, BackupPayload};
use vta_support::restore_stage::AnchorBinding;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::ops::{StageRequest, decrypt_backup, export_backup, stage_import};
use crate::restore::{self, PendingRestore};
use crate::test_support::{
    MemSeedStore, TestStore, open_test_store, super_admin_claims, test_app_config,
};
use crate::{BackupTarget, PreparedCommit, RestoreCommitter, RestoredSecrets, SeedStoreCommitter};

const PASSWORD: &str = "restore-test-password";
const SOURCE_SEED: [u8; 32] = [0x51; 32];
const TARGET_SEED: [u8; 32] = [0x7a; 32];

/// The storage key a seed-keyed deployment derives. Stands in for the real
/// HKDF derivations, which differ only in salt and info.
fn storage_key_for(env: BackupEnvironment, seed: &[u8]) -> Option<[u8; 32]> {
    match env {
        BackupEnvironment::Plain => None,
        BackupEnvironment::Hardened | BackupEnvironment::Tee => {
            Some(Sha256::digest([seed, &[env as u8]].concat()).into())
        }
    }
}

fn target_for<'a>(ts: &'a TestStore, env: BackupEnvironment, seed: &[u8]) -> BackupTarget<'a> {
    BackupTarget {
        store: &ts.store,
        storage_key: storage_key_for(env, seed),
        environment: env,
    }
}

/// An enclave's committer, minus KMS: records the restored seed where the
/// "enclave" will find it at boot, and reports a KMS row and an anchor
/// reservation the stage must bind to.
struct FakeTeeCommitter<'a> {
    seed_store: &'a MemSeedStore,
    anchor: Option<AnchorBinding>,
}

#[async_trait::async_trait]
impl RestoreCommitter for FakeTeeCommitter<'_> {
    async fn prepare(&self, _: &RestoredSecrets<'_>) -> Result<PreparedCommit, AppError> {
        Ok(PreparedCommit {
            tee_secrets_row: Some(b"kms-sealed".to_vec()),
            anchor: self.anchor.clone(),
        })
    }
    async fn commit(
        &self,
        secrets: &RestoredSecrets<'_>,
        _: PreparedCommit,
    ) -> Result<(), AppError> {
        use vta_keys::seed_store::SeedStore;
        self.seed_store.set(secrets.seed).await
    }
}

/// A committer whose commit never happens — the import dies at the point of
/// no return.
struct FailingCommitter;

#[async_trait::async_trait]
impl RestoreCommitter for FailingCommitter {
    async fn prepare(&self, _: &RestoredSecrets<'_>) -> Result<PreparedCommit, AppError> {
        Ok(PreparedCommit::default())
    }
    async fn commit(&self, _: &RestoredSecrets<'_>, _: PreparedCommit) -> Result<(), AppError> {
        Err(AppError::Internal("the process died here".into()))
    }
}

/// `BackupPayload` zeroizes on drop and so is not `Clone`; a test that restores
/// one payload twice round-trips it through JSON.
fn clone_payload(payload: &BackupPayload) -> BackupPayload {
    serde_json::from_value(serde_json::to_value(payload).unwrap()).unwrap()
}

async fn put(ks: &KeyspaceHandle, key: &str, value: &[u8]) {
    ks.insert_raw(key, value.to_vec()).await.unwrap();
}

async fn get(ks: &KeyspaceHandle, key: &str) -> Option<Vec<u8>> {
    ks.get_raw(key).await.unwrap()
}

/// Export `source` (a `source_env` deployment on `SOURCE_SEED`) and decrypt it.
async fn export_from(
    source: &TestStore,
    source_env: BackupEnvironment,
    config: &vta_config::AppConfig,
) -> BackupPayload {
    let seed_store = MemSeedStore::new(&SOURCE_SEED);
    let env = export_backup(
        &target_for(source, source_env, &SOURCE_SEED),
        &seed_store,
        config,
        &super_admin_claims(),
        PASSWORD,
        true,
    )
    .await
    .expect("export");
    decrypt_backup(&env, PASSWORD).expect("decrypt")
}

/// Stage `payload` into `target` (a `target_env` deployment currently on
/// `TARGET_SEED`), then "reboot": derive the storage key from whatever seed the
/// target now has, and apply. Returns the post-restore target description and
/// config.
async fn restore_into<'a>(
    target: &'a TestStore,
    target_env: BackupEnvironment,
    payload: BackupPayload,
    running_did: Option<&str>,
    replace_identity: bool,
) -> (
    BackupTarget<'a>,
    vta_config::AppConfig,
    restore::AppliedRestore,
) {
    let seed_store = MemSeedStore::new(&TARGET_SEED);
    let mut config = test_app_config(target.data_dir.clone());
    config.vta_did = running_did.map(str::to_owned);
    let config_lock = tokio::sync::RwLock::new(config);
    let before = target_for(target, target_env, &TARGET_SEED);

    let seed_committer = SeedStoreCommitter {
        seed_store: &seed_store,
    };
    let tee_committer = FakeTeeCommitter {
        seed_store: &seed_store,
        anchor: Some(AnchorBinding {
            did: payload.config.vta_did.clone().unwrap_or_default(),
            version: 4,
        }),
    };
    let committer: &dyn RestoreCommitter = if target_env == BackupEnvironment::Tee {
        &tee_committer
    } else {
        &seed_committer
    };
    stage_import(
        payload,
        StageRequest {
            target: &before,
            config: &config_lock,
            committer,
            auth: &super_admin_claims(),
            replace_identity,
        },
    )
    .await
    .expect("stage");

    // Reboot.
    let seed = seed_store.current();
    let after = target_for(target, target_env, &seed);
    let mut config = config_lock.into_inner();
    let PendingRestore::Ready(ready) = restore::load_pending(&after, &seed).await.unwrap() else {
        panic!("a committed restore must be pending after the reboot");
    };
    let applied = ready.apply(&after, &mut config).await.expect("apply");
    ready.finish(&after).await.unwrap();
    (after, config, applied)
}

/// A value unique to one keyspace, so a row landing in the wrong one shows.
fn census_value(name: &str) -> Vec<u8> {
    format!("census-of-{name}").into_bytes()
}

/// Plant one row in every keyspace — backed up or not — plus the
/// deployment-bound rows a backup must leave behind.
async fn plant_census(ts: &TestStore, target: &BackupTarget<'_>) {
    for name in vta_keyspaces::ALL {
        if *name == vta_keyspaces::BOOTSTRAP {
            continue;
        }
        put(
            &target.keyspace(name).unwrap(),
            "census:row",
            &census_value(name),
        )
        .await;
    }
    let keys = target.keyspace(vta_keyspaces::KEYS).unwrap();
    put(&keys, "tee:vta_did", b"did:example:source-enclave").await;
    put(&keys, "hardened:jwt_key", &[9u8; 32]).await;
    put(
        &target.keyspace(vta_keyspaces::PERSONA).unwrap(),
        "pxi:blinded",
        b"[]",
    )
    .await;
    let _ = ts;
}

/// **The fidelity census.** Every keyspace in `BACKED_UP` comes back, row for
/// row; nothing from `EXCLUDED_FROM_BACKUP` or the deployment-bound rows
/// travels; and the target's own state from before the restore is gone.
///
/// This is the test that fails if a keyspace is ever listed as backed up and
/// silently not exported — which is what happened to ten of them while export
/// was a set of per-keyspace collectors.
#[tokio::test]
async fn every_backed_up_keyspace_survives_a_round_trip() {
    for (source_env, target_env) in [
        (BackupEnvironment::Plain, BackupEnvironment::Plain),
        (BackupEnvironment::Plain, BackupEnvironment::Hardened),
        (BackupEnvironment::Hardened, BackupEnvironment::Plain),
        (BackupEnvironment::Plain, BackupEnvironment::Tee),
        (BackupEnvironment::Tee, BackupEnvironment::Plain),
        (BackupEnvironment::Tee, BackupEnvironment::Tee),
        (BackupEnvironment::Hardened, BackupEnvironment::Tee),
        (BackupEnvironment::Tee, BackupEnvironment::Hardened),
    ] {
        let source = open_test_store().await;
        let source_target = target_for(&source, source_env, &SOURCE_SEED);
        plant_census(&source, &source_target).await;
        let mut config = test_app_config(source.data_dir.clone());
        config.vta_did = Some("did:example:restored".into());
        let payload = export_from(&source, source_env, &config).await;

        // The target has a life of its own before the restore.
        let target = open_test_store().await;
        let before = target_for(&target, target_env, &TARGET_SEED);
        put(
            &before.keyspace(vta_keyspaces::SESSIONS).unwrap(),
            "stale",
            b"x",
        )
        .await;
        put(
            &before.keyspace(vta_keyspaces::MEMORY).unwrap(),
            "stale",
            b"x",
        )
        .await;

        let (after, _config, _) = restore_into(&target, target_env, payload, None, false).await;

        for name in vta_keyspaces::BACKED_UP {
            let ks = after.keyspace(name).unwrap();
            assert_eq!(
                get(&ks, "census:row").await,
                Some(census_value(name)),
                "{source_env} → {target_env}: `{name}` did not survive the round trip"
            );
        }
        for name in vta_keyspaces::EXCLUDED_FROM_BACKUP {
            if *name == vta_keyspaces::BOOTSTRAP {
                continue;
            }
            let ks = target.store.keyspace(name).unwrap();
            assert!(
                ks.get_raw("census:row").await.unwrap().is_none(),
                "{source_env} → {target_env}: excluded `{name}` travelled"
            );
        }
        assert!(
            target
                .store
                .keyspace(vta_keyspaces::SESSIONS)
                .unwrap()
                .prefix_keys(Vec::<u8>::new())
                .await
                .unwrap()
                .is_empty(),
            "{source_env} → {target_env}: the target's pre-restore sessions survived"
        );
        assert_eq!(
            get(&after.keyspace(vta_keyspaces::MEMORY).unwrap(), "stale").await,
            None,
            "{source_env} → {target_env}: a pre-restore row survived in a restored keyspace"
        );
        assert_eq!(
            get(
                &after.keyspace(vta_keyspaces::PERSONA).unwrap(),
                "pxi:blinded"
            )
            .await,
            None,
            "blinded persona indexes are rebuilt, never carried"
        );
    }
}

/// Plain → hardened: the restore lands under the storage key the *restored*
/// seed yields, and the JWT key goes where a hardened VTA looks for it.
#[tokio::test]
async fn a_restore_into_a_hardened_vta_is_sealed_under_the_restored_seed() {
    let source = open_test_store().await;
    let mut config = test_app_config(source.data_dir.clone());
    config.vta_did = Some("did:example:restored".into());
    config.auth.jwt_signing_key = Some(BASE64.encode([0x33u8; 32]));
    put(
        &target_for(&source, BackupEnvironment::Plain, &SOURCE_SEED)
            .keyspace(vta_keyspaces::ACL)
            .unwrap(),
        "acl:did:example:admin",
        b"{}",
    )
    .await;
    let payload = export_from(&source, BackupEnvironment::Plain, &config).await;

    let target = open_test_store().await;
    let (after, config, applied) =
        restore_into(&target, BackupEnvironment::Hardened, payload, None, false).await;

    assert_eq!(
        after.storage_key,
        storage_key_for(BackupEnvironment::Hardened, &SOURCE_SEED),
        "the next boot derives its storage key from the restored seed"
    );
    let keys = after.keyspace(vta_keyspaces::KEYS).unwrap();
    assert_eq!(
        get(&keys, restore::HARDENED_JWT_KEY).await,
        Some(vec![0x33u8; 32])
    );
    assert!(
        get(
            &after.keyspace(vta_keyspaces::ACL).unwrap(),
            "acl:did:example:admin"
        )
        .await
        .is_some()
    );
    // Under the *old* key, the restored rows are unreadable — the proof that
    // they were written for the new one.
    let stale = target_for(&target, BackupEnvironment::Hardened, &TARGET_SEED);
    assert!(
        stale
            .keyspace(vta_keyspaces::ACL)
            .unwrap()
            .get_raw("acl:did:example:admin")
            .await
            .is_err()
    );
    assert_eq!(config.vta_did.as_deref(), Some("did:example:restored"));
    assert_eq!(
        config.auth.jwt_signing_key, None,
        "a hardened VTA never keeps its JWT key in config"
    );
    assert_eq!(
        applied.provenance.target_environment,
        BackupEnvironment::Hardened
    );
    assert_eq!(
        applied.provenance.source_environment,
        Some(BackupEnvironment::Plain)
    );
}

/// Anything → enclave: the identity is written where an enclave's boot reads
/// it (the store, not the parent-delivered config), the Mode-B carve-out is
/// closed, and the manifest re-baseline carries the anchor reservation.
#[tokio::test]
async fn a_restore_into_an_enclave_writes_what_its_boot_reads() {
    let source = open_test_store().await;
    let mut config = test_app_config(source.data_dir.clone());
    config.vta_did = Some("did:webvh:scid:example.com".into());
    put(
        &target_for(&source, BackupEnvironment::Hardened, &SOURCE_SEED)
            .keyspace(vta_keyspaces::WEBVH)
            .unwrap(),
        "log:did:webvh:scid:example.com",
        b"{\"versionId\":\"1-abc\"}",
    )
    .await;
    let payload = export_from(&source, BackupEnvironment::Hardened, &config).await;

    let target = open_test_store().await;
    let (after, config, _) =
        restore_into(&target, BackupEnvironment::Tee, payload, None, false).await;

    let keys = after.keyspace(vta_keyspaces::KEYS).unwrap();
    assert_eq!(
        get(&keys, restore::TEE_VTA_DID_KEY).await.as_deref(),
        Some(&b"did:webvh:scid:example.com"[..])
    );
    assert_eq!(
        get(&keys, restore::TEE_DID_LOG_KEY).await.as_deref(),
        Some(&b"{\"versionId\":\"1-abc\"}"[..])
    );
    assert_eq!(
        get(&after.bootstrap().unwrap(), restore::TEE_DID_LOG_KEY)
            .await
            .as_deref(),
        Some(&b"{\"versionId\":\"1-abc\"}"[..]),
        "the parent-side proxy serves the log from the bootstrap copy"
    );
    assert!(
        get(&keys, restore::TEE_CARVEOUT_CLOSED_KEY).await.is_some(),
        "a restored enclave must not leave the single-use admin carve-out open"
    );
    let marker = restore::read_rebaseline_marker(&after)
        .await
        .unwrap()
        .expect("an enclave restore must ask its boot to re-baseline the manifest");
    assert_eq!(
        marker.anchor,
        Some(AnchorBinding {
            did: "did:webvh:scid:example.com".into(),
            version: 4
        })
    );
    assert_eq!(
        config.vta_did.as_deref(),
        Some("did:webvh:scid:example.com")
    );
}

/// Enclave → plain: the enclave's own rows stay behind, and the identity and
/// JWT key land in config.
#[tokio::test]
async fn a_restore_out_of_an_enclave_lands_in_config() {
    let source = open_test_store().await;
    let source_target = target_for(&source, BackupEnvironment::Tee, &SOURCE_SEED);
    let keys = source_target.keyspace(vta_keyspaces::KEYS).unwrap();
    put(&keys, "tee:vta_did", b"did:example:enclave").await;
    put(&keys, "tee:bootstrap-carveout-closed", b"did:example:admin").await;
    let mut config = test_app_config(source.data_dir.clone());
    config.vta_did = Some("did:example:enclave".into());
    config.auth.jwt_signing_key = Some(BASE64.encode([0x44u8; 32]));
    let payload = export_from(&source, BackupEnvironment::Tee, &config).await;

    let target = open_test_store().await;
    let (after, config, _) =
        restore_into(&target, BackupEnvironment::Plain, payload, None, false).await;

    assert_eq!(config.vta_did.as_deref(), Some("did:example:enclave"));
    assert_eq!(
        config.auth.jwt_signing_key.as_deref(),
        Some(BASE64.encode([0x44u8; 32]).as_str())
    );
    let keys = after.keyspace(vta_keyspaces::KEYS).unwrap();
    assert!(get(&keys, "tee:vta_did").await.is_none());
    assert!(get(&keys, "tee:bootstrap-carveout-closed").await.is_none());
    assert!(
        restore::read_rebaseline_marker(&after)
            .await
            .unwrap()
            .is_none()
    );
}

/// An import that dies before its commit leaves a stage nothing can open. The
/// next boot drops it, and the VTA is exactly what it was.
#[tokio::test]
async fn an_uncommitted_restore_is_discarded_and_changes_nothing() {
    let source = open_test_store().await;
    let config = test_app_config(source.data_dir.clone());
    let payload = export_from(&source, BackupEnvironment::Plain, &config).await;

    let target = open_test_store().await;
    let before = target_for(&target, BackupEnvironment::Hardened, &TARGET_SEED);
    put(
        &before.keyspace(vta_keyspaces::ACL).unwrap(),
        "acl:mine",
        b"{}",
    )
    .await;
    let config_lock = tokio::sync::RwLock::new(test_app_config(target.data_dir.clone()));
    stage_import(
        payload,
        StageRequest {
            target: &before,
            config: &config_lock,
            committer: &FailingCommitter,
            auth: &super_admin_claims(),
            replace_identity: false,
        },
    )
    .await
    .expect_err("the commit failed");

    assert!(matches!(
        restore::load_pending(&before, &TARGET_SEED).await.unwrap(),
        PendingRestore::Discarded { .. }
    ));
    assert!(matches!(
        restore::load_pending(&before, &TARGET_SEED).await.unwrap(),
        PendingRestore::None
    ));
    assert!(
        get(&before.keyspace(vta_keyspaces::ACL).unwrap(), "acl:mine")
            .await
            .is_some()
    );
}

/// A boot interrupted while applying applies again, to the same result.
#[tokio::test]
async fn applying_a_restore_twice_is_the_same_as_once() {
    let source = open_test_store().await;
    let mut config = test_app_config(source.data_dir.clone());
    config.vta_did = Some("did:example:restored".into());
    put(
        &target_for(&source, BackupEnvironment::Plain, &SOURCE_SEED)
            .keyspace(vta_keyspaces::VAULT)
            .unwrap(),
        "entry:1",
        b"secret",
    )
    .await;
    let payload = export_from(&source, BackupEnvironment::Plain, &config).await;

    let target = open_test_store().await;
    let seed_store = MemSeedStore::new(&TARGET_SEED);
    let before = target_for(&target, BackupEnvironment::Hardened, &TARGET_SEED);
    let config_lock = tokio::sync::RwLock::new(test_app_config(target.data_dir.clone()));
    stage_import(
        payload,
        StageRequest {
            target: &before,
            config: &config_lock,
            committer: &SeedStoreCommitter {
                seed_store: &seed_store,
            },
            auth: &super_admin_claims(),
            replace_identity: false,
        },
    )
    .await
    .unwrap();

    let seed = seed_store.current();
    let after = target_for(&target, BackupEnvironment::Hardened, &seed);
    let mut config = config_lock.into_inner();
    let PendingRestore::Ready(first) = restore::load_pending(&after, &seed).await.unwrap() else {
        panic!("pending")
    };
    first.apply(&after, &mut config).await.unwrap();
    // "Crash" before finish: the stage is still there, and applies again.
    let PendingRestore::Ready(second) = restore::load_pending(&after, &seed).await.unwrap() else {
        panic!("an unfinished restore must still be pending")
    };
    second.apply(&after, &mut config).await.unwrap();
    second.finish(&after).await.unwrap();

    assert_eq!(
        get(&after.keyspace(vta_keyspaces::VAULT).unwrap(), "entry:1").await,
        Some(b"secret".to_vec())
    );
    assert!(matches!(
        restore::load_pending(&after, &seed).await.unwrap(),
        PendingRestore::None
    ));
}

/// A stage committed for one kind of deployment is not applied by another:
/// the identity and JWT key would land where that deployment does not look.
#[tokio::test]
async fn a_restore_is_applied_only_by_the_deployment_it_was_staged_for() {
    let source = open_test_store().await;
    let config = test_app_config(source.data_dir.clone());
    let payload = export_from(&source, BackupEnvironment::Plain, &config).await;

    let target = open_test_store().await;
    let seed_store = MemSeedStore::new(&TARGET_SEED);
    let before = target_for(&target, BackupEnvironment::Hardened, &TARGET_SEED);
    let config_lock = tokio::sync::RwLock::new(test_app_config(target.data_dir.clone()));
    stage_import(
        payload,
        StageRequest {
            target: &before,
            config: &config_lock,
            committer: &SeedStoreCommitter {
                seed_store: &seed_store,
            },
            auth: &super_admin_claims(),
            replace_identity: false,
        },
    )
    .await
    .unwrap();

    let seed = seed_store.current();
    let as_plain = target_for(&target, BackupEnvironment::Plain, &seed);
    let PendingRestore::Ready(ready) = restore::load_pending(&as_plain, &seed).await.unwrap()
    else {
        panic!("pending")
    };
    let mut config = config_lock.into_inner();
    let Err(err) = ready.apply(&as_plain, &mut config).await else {
        panic!("a hardened stage must not apply on a plain boot");
    };
    assert!(
        format!("{err}").contains("staged for a hardened deployment"),
        "{err}"
    );
}

/// Restoring onto the VTA that took the backup keeps its internal keys;
/// restoring anywhere else cannot, and says which keys were lost.
#[tokio::test]
async fn internal_keys_survive_only_a_restore_onto_their_own_vta() {
    use vta_sdk::keys::{KeyOrigin, KeyType};

    let source = open_test_store().await;
    let source_target = target_for(&source, BackupEnvironment::Hardened, &SOURCE_SEED);
    let mut record = crate::ops::tests::mk_key_record("ik1", "");
    record.origin = KeyOrigin::Internal;
    source_target
        .keyspace(vta_keyspaces::KEYS)
        .unwrap()
        .insert(vta_keys::store_key("ik1"), &record)
        .await
        .unwrap();
    vta_keys::internal::generate(
        &source_target
            .keyspace(vta_keyspaces::INTERNAL_KEYS)
            .unwrap(),
        "ik1",
        KeyType::Ed25519,
    )
    .await
    .unwrap();
    let config = test_app_config(source.data_dir.clone());
    let payload = export_from(&source, BackupEnvironment::Hardened, &config).await;
    assert_eq!(payload.internal_keys_not_carried, vec!["ik1".to_string()]);

    // Elsewhere: the record comes back, the material cannot.
    let elsewhere = open_test_store().await;
    let (after, _, applied) = restore_into(
        &elsewhere,
        BackupEnvironment::Hardened,
        clone_payload(&payload),
        None,
        false,
    )
    .await;
    assert_eq!(
        applied.provenance.internal_keys_lost,
        vec!["ik1".to_string()]
    );
    assert!(
        !vta_keys::internal::exists(
            &after.keyspace(vta_keyspaces::INTERNAL_KEYS).unwrap(),
            "ik1"
        )
        .await
        .unwrap()
    );

    // Onto the source itself (same seed, same storage key): kept.
    let seed_store = MemSeedStore::new(&SOURCE_SEED);
    let config_lock = tokio::sync::RwLock::new(test_app_config(source.data_dir.clone()));
    stage_import(
        payload,
        StageRequest {
            target: &source_target,
            config: &config_lock,
            committer: &SeedStoreCommitter {
                seed_store: &seed_store,
            },
            auth: &super_admin_claims(),
            replace_identity: false,
        },
    )
    .await
    .unwrap();
    let PendingRestore::Ready(ready) = restore::load_pending(&source_target, &SOURCE_SEED)
        .await
        .unwrap()
    else {
        panic!("pending")
    };
    let mut config = config_lock.into_inner();
    let applied = ready.apply(&source_target, &mut config).await.unwrap();
    assert!(applied.provenance.internal_keys_lost.is_empty());
    assert!(
        vta_keys::internal::exists(
            &source_target
                .keyspace(vta_keyspaces::INTERNAL_KEYS)
                .unwrap(),
            "ik1"
        )
        .await
        .unwrap()
    );
}

/// A pre-v2 backup still restores — including the P0.5 fidelity it already
/// had: path counters carried forward, ACL entries restored losslessly.
#[tokio::test]
async fn a_v1_backup_restores_with_its_fidelity() {
    use vti_common::acl::{AclEntry, Role};

    let base = "m/26'/2'/0'";
    let mut entry = AclEntry::new("did:key:zAcl", Role::Admin, "did:key:zSetup");
    entry.expires_at = Some(1_900_000_000);
    let payload = BackupPayload {
        active_seed_hex: hex::encode(SOURCE_SEED),
        active_seed_id: 0,
        seed_records: vec![],
        jwt_signing_key: None,
        key_records: vec![
            crate::ops::tests::mk_key_record("k0", &format!("{base}/0'")),
            crate::ops::tests::mk_key_record("k1", &format!("{base}/1'")),
        ],
        context_records: vec![],
        context_counter: 0,
        path_counters: vec![],
        subcontext_counters: vec![],
        acl_entries: vec![],
        acl_entries_full: vec![serde_json::to_value(&entry).unwrap()],
        seal: None,
        webvh_servers: vec![],
        webvh_dids: vec![],
        webvh_logs: vec![],
        config: vta_sdk::protocols::backup_management::types::BackupConfig {
            vta_did: Some("did:example:v1".into()),
            vta_name: None,
            public_url: None,
            mediator_url: None,
            mediator_did: None,
        },
        audit_logs: vec![],
        imported_secrets: vec![],
        imported_kek_salt: None,
        keyspaces: vec![],
        source_environment: None,
        internal_keys_not_carried: vec![],
    };

    let target = open_test_store().await;
    let (after, config, _) =
        restore_into(&target, BackupEnvironment::Tee, payload, None, false).await;

    let keys = after.keyspace(vta_keyspaces::KEYS).unwrap();
    assert_eq!(
        vta_keys::paths::allocate_path(&keys, base).await.unwrap(),
        format!("{base}/2'"),
        "the recomputed counter must skip both in-use indices"
    );
    let restored: AclEntry = after
        .keyspace(vta_keyspaces::ACL)
        .unwrap()
        .get("acl:did:key:zAcl")
        .await
        .unwrap()
        .expect("acl entry restored");
    assert_eq!(restored.expires_at, Some(1_900_000_000));
    assert_eq!(config.vta_did.as_deref(), Some("did:example:v1"));
}

/// Replacing a different identity detaches hosted-DID registrations: they were
/// made by the source, and re-publishing from here would clobber its slot.
#[tokio::test]
async fn replacing_an_identity_detaches_hosted_dids() {
    let source = open_test_store().await;
    let now = chrono::Utc::now();
    let record = vta_sdk::webvh::WebvhDidRecord {
        did: "did:webvh:scid:host.example".into(),
        server_id: "prod".into(),
        mnemonic: "hosted/path".into(),
        scid: "scid".into(),
        context_id: "ctx".into(),
        portable: true,
        log_entry_count: 1,
        pre_rotation_count: 0,
        next_fragment_id: 1,
        created_at: now,
        updated_at: now,
    };
    target_for(&source, BackupEnvironment::Plain, &SOURCE_SEED)
        .keyspace(vta_keyspaces::WEBVH)
        .unwrap()
        .insert(format!("did:{}", record.did), &record)
        .await
        .unwrap();
    let mut config = test_app_config(source.data_dir.clone());
    config.vta_did = Some("did:example:lost".into());
    let payload = export_from(&source, BackupEnvironment::Plain, &config).await;

    // Refused without the flag…
    let target = open_test_store().await;
    let before = target_for(&target, BackupEnvironment::Plain, &TARGET_SEED);
    let mut running = test_app_config(target.data_dir.clone());
    running.vta_did = Some("did:example:fresh".into());
    let seed_store = MemSeedStore::new(&TARGET_SEED);
    let err = stage_import(
        clone_payload(&payload),
        StageRequest {
            target: &before,
            config: &tokio::sync::RwLock::new(running),
            committer: &SeedStoreCommitter {
                seed_store: &seed_store,
            },
            auth: &super_admin_claims(),
            replace_identity: false,
        },
    )
    .await
    .unwrap_err();
    assert!(format!("{err}").contains("--replace-identity"));

    // …and detaches with it.
    let (after, config, applied) = restore_into(
        &target,
        BackupEnvironment::Plain,
        payload,
        Some("did:example:fresh"),
        true,
    )
    .await;
    assert_eq!(config.vta_did.as_deref(), Some("did:example:lost"));
    assert_eq!(
        applied.provenance.hosted_dids_detached,
        vec!["did:webvh:scid:host.example".to_string()]
    );
    let restored: vta_sdk::webvh::WebvhDidRecord = after
        .keyspace(vta_keyspaces::WEBVH)
        .unwrap()
        .get("did:did:webvh:scid:host.example")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.server_id, "serverless");
    assert!(restored.mnemonic.is_empty());
}
