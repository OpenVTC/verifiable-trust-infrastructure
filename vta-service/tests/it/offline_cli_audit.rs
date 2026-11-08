//! The offline CLI writes authority without an authenticated caller, so what it
//! writes must be visible in the audit log (VTI-AUD-001, and the offline-writer
//! note after VTI-ACL-058). Driven as an operator drives it: the real `vta`
//! binary, a real config file, a real fjall store.

use std::path::Path;
use std::process::Command;

use vti_common::config::StoreConfig;
use vti_common::store::Store;

const GATEWAY: &str = "did:key:z6MkgAnvkP45uNxwCKeNdt6wrYkEjpYX4f7Nrd8MQqFL8Fbn";

fn write_config(dir: &Path) -> std::path::PathBuf {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"vta_did = "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD"

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

/// Every audit row as `(action, actor, resource, outcome, channel)`.
async fn audit_rows(dir: &Path) -> Vec<(String, String, String, String, String)> {
    let store = Store::open(&StoreConfig {
        data_dir: dir.join("data"),
    })
    .expect("open store");
    let ks = store.keyspace(vta_keyspaces::AUDIT).expect("audit ks");
    let mut rows = Vec::new();
    for (key, value) in ks.prefix_iter_raw("log:").await.expect("scan") {
        if String::from_utf8_lossy(&key).contains("chain") {
            continue;
        }
        let Ok(row) = serde_json::from_slice::<serde_json::Value>(&value) else {
            continue;
        };
        let text = |name: &str| row[name].as_str().unwrap_or_default().to_string();
        rows.push((
            text("action"),
            text("actor"),
            text("resource"),
            text("outcome"),
            text("channel"),
        ));
    }
    rows
}

#[tokio::test]
async fn offline_context_and_acl_writes_leave_audit_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    let (ok, out) = vta(&config, &["contexts", "create", "--id", "gateway"]);
    assert!(ok, "contexts create failed: {out}");
    let (ok, out) = vta(
        &config,
        &[
            "acl",
            "create",
            "--did",
            GATEWAY,
            "--role",
            "initiator",
            "--contexts",
            "gateway",
            "--capabilities",
            "context-create,key-mint,sign-jws,sign-document",
        ],
    );
    assert!(ok, "acl create failed: {out}");

    let rows = audit_rows(dir.path()).await;
    let find = |action: &str, resource: &str| {
        rows.iter()
            .find(|r| r.0 == action && r.2 == resource)
            .unwrap_or_else(|| panic!("no `{action}` row for {resource}: {rows:?}"))
    };
    let created = find("acl.create", GATEWAY);
    assert_eq!(
        created.1, "vta-cli (break-glass)",
        "the actor names the surface"
    );
    assert_eq!(created.3, "success");
    assert_eq!(created.4, "vta-cli");
    find("context.create", "gateway");
}

#[tokio::test]
async fn offline_acl_update_and_delete_leave_audit_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    let (ok, out) = vta(&config, &["contexts", "create", "--id", "gateway"]);
    assert!(ok, "contexts create failed: {out}");
    let (ok, out) = vta(
        &config,
        &[
            "acl",
            "create",
            "--did",
            GATEWAY,
            "--role",
            "initiator",
            "--contexts",
            "gateway",
        ],
    );
    assert!(ok, "acl create failed: {out}");
    let (ok, out) = vta(&config, &["acl", "update", GATEWAY, "--label", "renamed"]);
    assert!(ok, "acl update failed: {out}");
    let (ok, out) = vta(&config, &["acl", "delete", GATEWAY, "--yes"]);
    assert!(ok, "acl delete failed: {out}");

    let actions: Vec<String> = audit_rows(dir.path())
        .await
        .into_iter()
        .map(|r| r.0)
        .collect();
    for expected in ["acl.create", "acl.update", "acl.delete"] {
        assert!(
            actions.iter().any(|a| a == expected),
            "missing {expected}: {actions:?}"
        );
    }
}

#[tokio::test]
async fn a_refused_offline_write_leaves_no_audit_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    let (ok, _) = vta(
        &config,
        &[
            "acl",
            "create",
            "--did",
            GATEWAY,
            "--role",
            "initiator",
            "--capabilities",
            "no-such-capability",
        ],
    );
    assert!(!ok, "an unknown capability must be refused");
    assert!(
        audit_rows(dir.path()).await.is_empty(),
        "nothing was written, so nothing is audited"
    );
}
