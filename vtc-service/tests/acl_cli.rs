//! Offline `vtc acl` CLI integration tests.
//!
//! Drives the `acl_cli` handlers against a temp store + minimal config
//! file, exactly as the `vtc acl {list,add,remove}` subcommands do, and
//! verifies the resulting `acl` keyspace state.

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use vti_common::config::StoreConfig;

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry};
use vtc_service::acl_cli::{AclAddArgs, run_acl_add, run_acl_list, run_acl_remove};
use vtc_service::store::Store;

const DID: &str = "did:key:z6MkAclCliTestAdmin";

/// A temp dir + a minimal `config.toml` pointing the store at it.
/// Returns `(dir, config_path, data_dir)`; keep `dir` alive for the test.
fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!("[store]\ndata_dir = \"{}\"\n", data_dir.display()),
    )
    .expect("write config");
    (dir, cfg_path, data_dir)
}

/// Re-open the store and read back an entry — the CLI handler drops its
/// own store (releasing the fjall lock) before this runs.
async fn read_entry(data_dir: &Path, did: &str) -> Option<VtcAclEntry> {
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })
    .expect("open store");
    let ks = store.keyspace("acl").expect("acl ks");
    get_acl_entry(&ks, did).await.expect("get_acl_entry")
}

#[tokio::test]
async fn add_list_remove_round_trip() {
    let (_dir, cfg, data_dir) = fixture();

    run_acl_add(AclAddArgs {
        config_path: Some(cfg.clone()),
        did: DID.into(),
        role: "admin".into(),
        label: Some("ops".into()),
        contexts: vec!["ctx-1".into(), "ctx-2".into()],
        expires: Some(3600),
    })
    .await
    .expect("add");

    let e = read_entry(&data_dir, DID).await.expect("entry stored");
    assert_eq!(e.role, VtcRole::Admin);
    assert_eq!(e.label.as_deref(), Some("ops"));
    assert_eq!(e.allowed_contexts, vec!["ctx-1", "ctx-2"]);
    assert!(e.expires_at.is_some(), "expiry should be set");

    // `list` runs cleanly against a populated store.
    run_acl_list(Some(cfg.clone())).await.expect("list");

    run_acl_remove(Some(cfg.clone()), DID.into())
        .await
        .expect("remove");
    assert!(read_entry(&data_dir, DID).await.is_none(), "entry removed");
}

#[tokio::test]
async fn add_is_upsert_and_preserves_created_at() {
    let (_dir, cfg, data_dir) = fixture();

    run_acl_add(AclAddArgs {
        config_path: Some(cfg.clone()),
        did: DID.into(),
        role: "member".into(),
        label: None,
        contexts: vec![],
        expires: None,
    })
    .await
    .expect("add member");
    let first = read_entry(&data_dir, DID).await.expect("first");
    assert_eq!(first.role, VtcRole::Member);

    // Re-add the same DID with a new role — upsert, not duplicate.
    run_acl_add(AclAddArgs {
        config_path: Some(cfg.clone()),
        did: DID.into(),
        role: "moderator".into(),
        label: Some("mod".into()),
        contexts: vec![],
        expires: None,
    })
    .await
    .expect("upsert moderator");
    let second = read_entry(&data_dir, DID).await.expect("second");
    assert_eq!(second.role, VtcRole::Moderator);
    assert_eq!(second.label.as_deref(), Some("mod"));
    assert_eq!(
        second.created_at, first.created_at,
        "created_at preserved across update"
    );
}

#[tokio::test]
async fn add_rejects_unknown_role() {
    let (_dir, cfg, data_dir) = fixture();
    let result = run_acl_add(AclAddArgs {
        config_path: Some(cfg),
        did: DID.into(),
        role: "wizard".into(),
        label: None,
        contexts: vec![],
        expires: None,
    })
    .await;
    assert!(result.is_err(), "unknown role must be rejected");
    // Nothing was written.
    assert!(read_entry(&data_dir, DID).await.is_none());
}

#[tokio::test]
async fn remove_missing_did_is_ok() {
    let (_dir, cfg, _data_dir) = fixture();
    // Removing a DID that was never added is a clean no-op (the store is
    // created on open), not an error.
    run_acl_remove(Some(cfg), "did:key:zNeverAdded".into())
        .await
        .expect("remove missing is ok");
}
