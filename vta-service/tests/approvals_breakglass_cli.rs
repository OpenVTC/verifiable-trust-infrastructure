//! End-to-end: the offline approvals break-glass, driven as an operator drives
//! it — the real `vta` binary, a real config file, a real fjall store.
//!
//! The unit tests beside `approvals_cli.rs` cover the model manipulation. This
//! covers the part they cannot: that the clap wiring reaches those functions at
//! all, that a populated row renders, and that the whole thing works from a
//! config file rather than a hand-built `KeyspaceHandle`.
//!
//! That distinction earns its keep here specifically. This is a recovery path —
//! it runs only when every other way in has already failed — so "the function is
//! correct but the subcommand was never wired up" is a failure mode that would
//! otherwise be discovered by an operator, mid-incident, with no way in.

use std::path::Path;
use std::process::Command;

use vta_policy::approvals::{DeclarativeModel, declarative_row};
use vta_policy::storage;
use vta_sdk::approvals::ApprovalRule;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.1";
const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";

/// Write the config file the `vta` binary will read.
fn write_config(dir: &Path) -> std::path::PathBuf {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"vta_did = "did:key:z6MkTestVTA"

[server]
port = 8080

[store]
data_dir = "{}"

[auth]
jwt_signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
            data_dir.display()
        ),
    )
    .expect("write config");
    config_path
}

/// Seat the row that wedges the VTA: consent for `policy/upsert` from a set
/// whose only member has rotated away. The rule gates the very task that would
/// remove it, so nothing on the wire can recover — which is the whole reason
/// this surface exists.
async fn seed_lockout(data_dir: &Path) {
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })
    .expect("open store");
    let ks = store.keyspace(vta_keyspaces::POLICY).expect("policy ks");

    let model = DeclarativeModel {
        rules: vec![
            ApprovalRule::consent(POLICY_UPSERT, "ops"),
            ApprovalRule::reauth(ACL_GRANT),
        ],
        approver_sets: [("ops".to_string(), vec!["did:key:zGoneForever".to_string()])]
            .into_iter()
            .collect(),
    };
    let row = declarative_row(&model, 1, "2026-08-10T00:00:00Z", "2026-08-10T00:00:00Z");
    storage::store_policy(&ks, &row).await.expect("seed row");
    // Drop the store so the binary can take fjall's per-data-dir lock.
    drop(store);
}

/// Run the built `vta` binary and return (success, stdout+stderr).
fn vta(config: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_vta"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run vta");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

#[tokio::test]
async fn an_operator_can_diagnose_and_clear_a_lockout_offline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());
    seed_lockout(&dir.path().join("data")).await;

    // 1. Diagnose. The command that answers "why am I being asked for consent
    //    I cannot satisfy" — the question this whole convergence started from.
    let (ok, out) = vta(&config, &["approvals", "list"]);
    assert!(ok, "approvals list failed: {out}");
    assert!(
        out.contains(POLICY_UPSERT),
        "the wedging rule must be named: {out}"
    );
    assert!(
        out.contains("consent") && out.contains("ops"),
        "the operator needs to see WHAT it requires and from WHICH set: {out}"
    );
    assert!(
        out.contains("did:key:zGoneForever"),
        "and who is in that set — which is how they learn it is unsatisfiable: {out}"
    );

    // 2. Recover, surgically.
    let (ok, out) = vta(&config, &["approvals", "remove", POLICY_UPSERT]);
    assert!(ok, "approvals remove failed: {out}");

    // 3. The gate is gone and every other control still stands.
    let (ok, out) = vta(&config, &["approvals", "list"]);
    assert!(ok, "approvals list failed after remove: {out}");
    assert!(
        !out.contains(POLICY_UPSERT),
        "the removed rule must be gone: {out}"
    );
    assert!(
        out.contains(ACL_GRANT),
        "the unrelated rule must survive: {out}"
    );
}

#[tokio::test]
async fn disable_clears_everything_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());
    seed_lockout(&dir.path().join("data")).await;

    let (ok, out) = vta(&config, &["approvals", "disable"]);
    assert!(ok, "approvals disable failed: {out}");
    assert!(
        out.contains("2 rule(s)") && out.contains("1 approver set(s)"),
        "the operator should leave knowing exactly what they switched off: {out}"
    );
    assert!(
        out.contains("caller's own authority"),
        "and that it is a real reduction in control: {out}"
    );

    let (ok, out) = vta(&config, &["approvals", "list"]);
    assert!(ok);
    assert!(out.contains("No approval rules"), "{out}");
}

/// `vta policy delete` refuses the declarative row, and the refusal names the
/// two commands that do the job — an operator reaching for the wrong one under
/// pressure should be redirected, not stopped.
#[tokio::test]
async fn policy_delete_redirects_away_from_the_declarative_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());
    seed_lockout(&dir.path().join("data")).await;

    let (ok, out) = vta(&config, &["policy", "delete", "approvals"]);
    assert!(
        !ok,
        "deleting the declarative row this way must fail: {out}"
    );
    assert!(out.contains("vta approvals remove"), "{out}");
    assert!(out.contains("vta approvals disable"), "{out}");

    // …and the row is untouched.
    let (ok, out) = vta(&config, &["approvals", "list"]);
    assert!(ok);
    assert!(out.contains(POLICY_UPSERT), "{out}");
}

/// An empty rule list does not mean nothing is gating you. A hand-authored
/// module denies just as effectively and is invisible to the declarative view,
/// so `approvals list` has to point at it or the operator stops looking.
#[tokio::test]
async fn a_hand_authored_module_is_surfaced_and_removable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    {
        let store = Store::open(&StoreConfig {
            data_dir: data_dir.clone(),
        })
        .expect("open store");
        let ks = store.keyspace(vta_keyspaces::POLICY).expect("policy ks");
        storage::store_policy(
            &ks,
            &vta_policy::types::PolicyModule {
                id: "operator-deny-all".into(),
                name: "deny all".into(),
                description: Some("hand-authored".into()),
                module: "package vta.policy\nimport rego.v1\ndecision := {\"decision\": \"deny\"}"
                    .into(),
                applies_to: vec![],
                priority: 500,
                enabled: true,
                version: 1,
                created_at: "2026-08-10T00:00:00Z".into(),
                updated_at: "2026-08-10T00:00:00Z".into(),
                ext: serde_json::Value::Null,
            },
        )
        .await
        .expect("seed module");
    }

    // No rules at all — but something IS denying, and the listing must say so.
    let (ok, out) = vta(&config, &["approvals", "list"]);
    assert!(ok, "{out}");
    assert!(out.contains("No approval rules"), "{out}");
    assert!(
        out.contains("operator-deny-all"),
        "a hand-authored module must be surfaced, or an empty rule list reads as \
         'nothing is gating me' when something is: {out}"
    );

    let (ok, out) = vta(&config, &["policy", "delete", "operator-deny-all"]);
    assert!(ok, "policy delete failed: {out}");

    let (ok, out) = vta(&config, &["policy", "list"]);
    assert!(ok);
    assert!(out.contains("No policy modules stored"), "{out}");
}
