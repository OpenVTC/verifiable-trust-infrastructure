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
    for crate_src in BINDING_SITES {
        collect_from_dir(&root.join(crate_src), &mut found);
    }
    found
}

/// Every place a Trust-Task URI is bound, dispatched, or sent as a header.
///
/// **All four, not just the router.** A router-only scan is what produced the
/// wrong residual count in #799: four tasks are `vta-sdk` DIDComm constants
/// with no REST mount, so nothing in `routes/mod.rs` mentions them. The admin
/// SPA is worse — it sends `Trust-Task` headers as TypeScript string literals
/// with no type-system backstop, so a missed one fails at runtime in the UI
/// and nothing in the Rust build notices. It is compiled into the binary by
/// `build.rs`, so it cannot lag the daemon by even one release.
const BINDING_SITES: &[&str] = &[
    "vtc-service/src",
    "vta-sdk/src",
    "cnm-cli/src",
    "vtc-service/admin-ui/src",
];

fn collect_from_dir(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_from_dir(&path, out);
        } else if path
            .extension()
            .is_some_and(|e| e == "rs" || e == "ts" || e == "tsx")
        {
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

// ---------------------------------------------------------------------------
// Migration guards (#710)
// ---------------------------------------------------------------------------

/// The `openvtc/vtc/*` URIs still awaiting a canonical disposition.
///
/// This list only ever shrinks. Each entry is a task the #710 design note
/// folds onto a canonical spec rather than republishing under `spec/vtc/*`,
/// so it cannot simply be repointed — three of them additionally need an
/// upstream registry spec that does not exist yet.
///
/// A new `openvtc/vtc/` URI appearing anywhere fails the test below, which is
/// the point: the authority is retired, and nothing should be added to it.
const AWAITING_CANONICAL_FOLD: &[(&str, &str)] = &[
    (
        "admin/config/export/1.0",
        "canonical config/export — blocked on communityProfile moving to ext",
    ),
    (
        "admin/config/import/1.0",
        "canonical config/import — blocked; communityProfileDiff is structural",
    ),
    // The three `admin/passkeys/*` entries are GONE, folded onto the
    // canonical `auth/passkey/{list,enroll/*,revoke/*}` tasks authored in
    // trust-tasks-tf#145.
    //
    // Their recorded blocker was wrong, which is why they sat here so long.
    // The note said each needed a `confirm/1.0` gate; `confirm/request` is an
    // ASYNCHRONOUS delegation whose response returns out of band on the
    // approver's own transport. This surface never needed that — it verifies
    // the user in-band, in the same request, via WebAuthn. The canonical specs
    // were written from this implementation rather than the other way round,
    // so the fold changed URIs and nothing else.
    (
        "auth/admin-login/1.0",
        "canonical auth/authenticate; the cookie side-effect moves to a binding/ext",
    ),
    (
        "config/legacy/manage/1.0",
        "delete — strict duplicate of admin/config/manage, which shipped",
    ),
    // `members/promote-to-admin/1.0` is GONE — folded onto the canonical
    // `spec/vtc/members/update/0.1` (`PATCH /v1/members/{did}` with
    // `role: admin`), gated on a live step-up elevation.
    //
    // Its recorded blocker named `acl/change-role` as the target, which does
    // not hold: that task is bound to `PATCH /v1/acl/{did}`, a bare ACL write
    // that never runs `role_change.rego` and serves non-member ACL rows.
    // Routing admin promotion through it would have reintroduced the P0.14
    // policy bypass. `members/update` already ran the role-change ceremony.
    // The three raw-byte website entries are GONE — de-listed, not folded.
    // `deploy`, `files/show` and `files/write` moved file bytes, and a Trust
    // Task payload is a JSON document, so no canonical spec could ever
    // supersede them. Their routes lost the header gate (never the auth gate)
    // and their specs left the tree. `files/delete` carries a path rather than
    // a payload, so it took the canonical task it should always have had.
];

/// No `openvtc/vtc/` URI may appear outside the shrinking fold list.
///
/// The authority is retired. This is what stops the migration regressing one
/// literal at a time — a new binding on the old authority fails here rather
/// than being discovered by a downstream consumer.
#[test]
fn no_new_bindings_on_the_retired_authority() {
    let bound = bound_task_uris();
    let allowed = exceptions(AWAITING_CANONICAL_FOLD);
    let unexpected: BTreeSet<_> = bound.difference(&allowed).cloned().collect();
    assert!(
        unexpected.is_empty(),
        "these bind the retired `openvtc/vtc/` authority and are not in \
         AWAITING_CANONICAL_FOLD:\n  {}\n\nRepoint them to \
         https://trusttasks.org/spec/vtc/<slug>/<ver>, or — if the task is \
         genuinely awaiting a canonical fold — add it to the list with a reason.",
        unexpected.iter().cloned().collect::<Vec<_>>().join("\n  ")
    );
}

/// Every `spec/vtc/` URI the code binds must be one the registry actually
/// publishes.
///
/// Cross-checked against the generated `trust_tasks_rs` schema index rather
/// than a hand-maintained list, so it tracks the published registry: a typo, a
/// stale slug, or a task repointed to a spec that was never authored all fail
/// here instead of at runtime. `schema_for` returning `None` means this build
/// of the registry crate knows no such task.
#[test]
fn every_bound_vtc_task_exists_in_the_registry() {
    const SPEC_PREFIX: &str = "https://trusttasks.org/spec/vtc/";
    let root = workspace_root();
    let mut bound = BTreeSet::new();
    for crate_src in BINDING_SITES {
        collect_prefixed(&root.join(crate_src), SPEC_PREFIX, &mut bound);
    }
    assert!(
        !bound.is_empty(),
        "found no spec/vtc/ bindings at all — the scan is broken, not the code"
    );

    let unknown: Vec<_> = bound
        .iter()
        .filter(|uri| trust_tasks_rs::schema_index::schema_for(uri).is_none())
        .cloned()
        .collect();
    assert!(
        unknown.is_empty(),
        "these spec/vtc/ URIs are bound but the registry (trust-tasks-rs \
         {}) publishes no such task:\n  {}\n\nEither the slug is wrong or the \
         spec was never authored upstream.",
        env!("CARGO_PKG_VERSION"),
        unknown.join("\n  ")
    );
}

/// As [`collect_from_dir`], for an arbitrary URI prefix.
fn collect_prefixed(dir: &Path, prefix: &str, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_prefixed(&path, prefix, out);
        } else if path
            .extension()
            .is_some_and(|e| e == "rs" || e == "ts" || e == "tsx")
        {
            let text = std::fs::read_to_string(&path).expect("read source file");
            for (idx, _) in text.match_indices(prefix) {
                if idx == 0 || !text[..idx].ends_with('"') {
                    continue;
                }
                let rest = &text[idx..];
                let Some(end) = rest.find('"') else { continue };
                let uri = rest[..end].split('#').next().expect("head").to_owned();
                out.insert(uri);
            }
        }
    }
}
