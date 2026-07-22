//! Census: `trust-tasks/index.json` must agree with what the router
//! actually enforces (#537 follow-up).
//!
//! The manifest is the publication source of truth for trusttasks.org.
//! Nothing previously checked it against the code, so it drifted in both
//! directions: entries for tasks no route binds, and live routes the
//! manifest never published.
//!
//! Task bindings are attached as tower layers (`tt` / `ttl` in
//! `routes/mod.rs`), so a built `Router` cannot be enumerated for them.
//! This census therefore reads the wiring sites as source text. That is
//! blunt, but the wiring is confined to a small number of files and a
//! false positive here is a compile-visible string, not a silent pass.
//!
//! Both directions allow explicit, reasoned exceptions — see
//! [`UNBOUND_OK`] and [`UNPUBLISHED_OK`]. Anything not listed there is a
//! failure. Adding an entry to those tables is a deliberate act with a
//! stated reason; letting the manifest drift is not.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const PREFIX: &str = "https://trusttasks.org/openvtc/vtc/";

/// Manifest entries that legitimately bind no route.
///
/// Overwhelmingly the Phase-0 shared-mount workaround: `TrustTaskRouter`
/// has no per-method task selector, so two verbs sharing one mount
/// collapse onto a single task. The unselected task still ships on disk
/// and in the manifest so the soft-gate surface stays complete.
const UNBOUND_OK: &[(&str, &str)] = &[
    // -- shared mount, awaiting per-method Trust-Task selectors --
    (
        "credentials/endorsements/list/1.0",
        "shares the endorsements show mount",
    ),
    (
        "credentials/endorsements/revoke/1.0",
        "shares the endorsements show mount",
    ),
    (
        "endorsement-types/list/1.0",
        "GET shares the register/1.0 mount",
    ),
    (
        "join-requests/list/1.0",
        "admin GET collapses onto submit/1.0",
    ),
    ("members/admin-remove/1.0", "shares the members/{did} mount"),
    (
        "members/personhood/revoke/1.0",
        "DELETE shares the personhood mount",
    ),
    ("members/update/1.0", "PATCH shares the members/{did} mount"),
    (
        "website/files/delete/1.0",
        "shares the website files show mount",
    ),
    (
        "website/files/write/1.0",
        "shares the website files show mount",
    ),
];

/// Task URIs the code binds that the manifest does not publish.
///
/// These are a real backlog, not a design choice: whole feature families
/// shipped after the manifest was last reconciled. Publishing them needs
/// a `spec.md` + `schema.json` per task, so it is tracked separately
/// rather than fixed here. This table exists to stop the backlog growing.
const UNPUBLISHED_OK: &[(&str, &str)] = &[
    ("admin/invites/manage/1.0", "unpublished backlog"),
    ("admin/invites/revoke/1.0", "unpublished backlog"),
    ("auth/admin-session/1.0", "unpublished backlog"),
    ("auth/recognise/challenge/1.0", "unpublished backlog"),
    ("backup/export/1.0", "unpublished backlog"),
    ("backup/import/1.0", "unpublished backlog"),
    ("ceremonies/list/1.0", "unpublished backlog"),
    ("directory/query/1.0", "unpublished backlog"),
    ("invitations/issue/1.0", "unpublished backlog"),
    ("invitations/revoke/1.0", "unpublished backlog"),
    ("members/purge/1.0", "unpublished backlog"),
    ("members/removed/1.0", "unpublished backlog"),
    ("members/request-vmc/1.0", "unpublished backlog"),
    ("members/self-remove-receipt/1.0", "unpublished backlog"),
    ("recognition/check/1.0", "unpublished backlog"),
    ("relationships/graph/1.0", "unpublished backlog"),
    (
        "spec/join-requests/submit-receipt/1.0",
        "unpublished backlog",
    ),
    ("spec/members/request-vmc/1.0", "unpublished backlog"),
    ("spec/members/vmc/1.0", "unpublished backlog"),
    // Phase-0 mount collapse: the admin GET list reuses this slug, while
    // the real wire task is `spec/join-requests/submit/1.0`.
    (
        "join-requests/submit/1.0",
        "mount-collapse alias of spec/join-requests/submit/1.0",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vtc-service has a parent")
        .to_path_buf()
}

struct Task {
    status: String,
    path: String,
}

fn manifest() -> BTreeMap<String, Task> {
    let raw = std::fs::read_to_string(workspace_root().join("trust-tasks/index.json"))
        .expect("read trust-tasks/index.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse index.json");
    doc["tasks"]
        .as_array()
        .expect("tasks array")
        .iter()
        .map(|t| {
            (
                t["id"].as_str().expect("task id").to_owned(),
                Task {
                    status: t["status"].as_str().expect("task status").to_owned(),
                    path: t["path"].as_str().expect("task path").to_owned(),
                },
            )
        })
        .collect()
}

/// Every `https://trusttasks.org/openvtc/vtc/...` literal in the crates
/// that wire or dispatch tasks. Response types (`#response` suffix) are
/// not separately published, so the fragment is trimmed off.
fn bound_task_uris() -> BTreeSet<String> {
    let root = workspace_root();
    let mut found = BTreeSet::new();
    for crate_src in ["vtc-service/src", "vta-sdk/src"] {
        collect_from_dir(&root.join(crate_src), &mut found);
    }
    found
}

fn collect_from_dir(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_from_dir(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("read source file");
            for (idx, _) in text.match_indices(PREFIX) {
                // Only string literals count. Doc comments carry `{verb}`-style
                // URI templates that are documentation, not bindings.
                if idx == 0 || !text[..idx].ends_with('"') {
                    continue;
                }
                let rest = &text[idx..];
                let Some(end) = rest.find('"') else { continue };
                let uri = &rest[..end];
                // `.../foo/1.0#response` publishes under `.../foo/1.0`.
                let uri = uri.split('#').next().expect("split yields a head");
                out.insert(uri.to_owned());
            }
        }
    }
}

fn exceptions(table: &[(&str, &str)]) -> BTreeSet<String> {
    table
        .iter()
        .map(|(slug, _)| format!("{PREFIX}{slug}"))
        .collect()
}

/// A live manifest entry with no route behind it is either drift or a
/// documented exception. Nothing in between.
#[test]
fn every_published_task_is_bound_or_excepted() {
    let bound = bound_task_uris();
    let allowed = exceptions(UNBOUND_OK);

    let orphans: Vec<_> = manifest()
        .iter()
        .filter(|(_, t)| t.status != "retired")
        .map(|(id, _)| id.clone())
        .filter(|id| !bound.contains(id) && !allowed.contains(id))
        .collect();

    assert!(
        orphans.is_empty(),
        "manifest publishes tasks no route binds:\n  {}\n\n\
         Either wire them, retire them (status + supersededBy, SPEC \u{a7}5.3), \
         or add them to UNBOUND_OK with a reason.",
        orphans.join("\n  ")
    );
}

/// A task the code enforces but the manifest never published is
/// invisible to consumers building against trusttasks.org.
#[test]
fn every_bound_task_is_published_or_excepted() {
    let published: BTreeSet<String> = manifest().into_keys().collect();
    let allowed = exceptions(UNPUBLISHED_OK);

    let missing: Vec<_> = bound_task_uris()
        .into_iter()
        .filter(|id| !published.contains(id) && !allowed.contains(id))
        .collect();

    assert!(
        missing.is_empty(),
        "routes enforce tasks the manifest does not publish:\n  {}\n\n\
         Add a manifest entry (plus spec.md + schema.json on disk), \
         or add them to UNPUBLISHED_OK with a reason.",
        missing.join("\n  ")
    );
}

/// Retirement is only meaningful if nothing still enforces the task.
/// This is the assertion that makes the #537 sign-out/whoami class of
/// drift impossible to reintroduce silently.
#[test]
fn retired_tasks_are_not_bound() {
    let bound = bound_task_uris();
    let still_wired: Vec<_> = manifest()
        .iter()
        .filter(|(id, t)| t.status == "retired" && bound.contains(*id))
        .map(|(id, _)| id.clone())
        .collect();

    assert!(
        still_wired.is_empty(),
        "retired tasks are still enforced by a route:\n  {}",
        still_wired.join("\n  ")
    );
}

/// SPEC \u{a7}5.3 vocabulary is lowercase, and `retired` is the only status
/// permitted to carry `supersededBy` (\u{a7}7.3 item 11).
#[test]
fn manifest_status_vocabulary_matches_spec() {
    let raw = std::fs::read_to_string(workspace_root().join("trust-tasks/index.json"))
        .expect("read index.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse index.json");

    for task in doc["tasks"].as_array().expect("tasks array") {
        let id = task["id"].as_str().expect("task id");
        let status = task["status"].as_str().expect("task status");
        assert!(
            matches!(status, "draft" | "candidate" | "standard" | "retired"),
            "{id}: status {status:?} is not SPEC \u{a7}5.3 vocabulary"
        );
        let superseded = task.get("supersededBy").is_some();
        assert_eq!(
            superseded,
            status == "retired",
            "{id}: supersededBy is required on retired specs and forbidden otherwise"
        );
    }
}

/// Every manifest entry must have its spec + schema on disk, or the
/// published registry links to nothing.
#[test]
fn every_manifest_entry_has_files_on_disk() {
    let root = workspace_root().join("trust-tasks");
    let missing: Vec<_> = manifest()
        .into_iter()
        .flat_map(|(id, t)| {
            ["spec.md", "schema.json"]
                .into_iter()
                .filter(|f| !root.join(&t.path).join(f).exists())
                .map(|f| format!("{id} -> {}/{f}", t.path))
                .collect::<Vec<_>>()
        })
        .collect();

    assert!(
        missing.is_empty(),
        "manifest entries missing files:\n  {}",
        missing.join("\n  ")
    );
}
