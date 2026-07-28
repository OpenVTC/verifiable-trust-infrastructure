//! Census: `trust-tasks/index.json` must agree with what the router
//! actually enforces (#537 follow-up).
//!
//! The manifest describes the **retired** `openvtc/vtc` authority. Nothing
//! previously checked it against the code, so it drifted in both directions:
//! entries for tasks no route binds, and live routes the manifest never
//! published. Publication now happens upstream, against canonical
//! `spec/vtc/*` slugs — see [`every_bound_canonical_task_exists_in_the_registry`],
//! which is the assertion that matters for anything shipping today.
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
/// **Empty, and that is the finished state (#710).** It once held seven
/// entries, all the same Phase-0 shared-mount workaround: two verbs sharing a
/// mount collapse onto one task, so the unselected sibling shipped on disk and
/// in the manifest while binding nothing.
///
/// None of them needed an exception in the end. Five were retired as their
/// families moved to `spec/vtc/*`, and the assertion below skips retired
/// entries. The last two — `endorsement-types/list/1.0` and
/// `members/personhood/revoke/1.0` — were still `draft` while the routes they
/// described had *already* moved: `GET /v1/endorsement-types` enforces
/// `spec/vtc/endorsement-types/register/0.1` and
/// `DELETE /v1/members/{did}/personhood` enforces
/// `spec/vtc/members/personhood/assert/0.1`. Two live drafts on a retired
/// authority describing nothing. Both are retired now, pointing at the
/// canonical `list/0.1` and `revoke/0.1` the upstream registry publishes.
///
/// Note what this does *not* fix: those two mounts still collapse a second
/// verb onto a sibling's canonical task. The fan-out is unblocked — Phase 2c
/// established that `task_routes` layers the method router and axum merges
/// same-path method routers per method, pinned by
/// `vti_common::trust_task::openapi::per_method_tasks_on_one_path_are_enforced_independently`
/// — but it is a canonical-side split, not an authority migration, so it is
/// left for its own change.
///
/// The table stays (empty) because the assertion is still load-bearing: a
/// manifest row that goes back to `draft` with no route behind it fails here.
const UNBOUND_OK: &[(&str, &str)] = &[];

/// Task URIs the code binds that the manifest does not publish.
///
/// **Empty, and that is the finished state (#709).** This table once carried
/// twenty entries — whole feature families that shipped after the manifest was
/// last reconciled and were never published. None of them were resolved by
/// authoring twenty specs into this manifest. They were resolved by the #710
/// migration: every one of those tasks now binds a canonical
/// `https://trusttasks.org/spec/vtc/<slug>` URI published by the upstream
/// registry, which [`every_bound_canonical_task_exists_in_the_registry`] verifies
/// against `trust_tasks_rs` rather than against anything local.
///
/// So the backlog did not get published here; the surface it described moved
/// off this authority entirely. What is left on `openvtc/vtc/` is the two
/// entries in [`AWAITING_CANONICAL_FOLD`], and both *are* in the manifest.
///
/// The table stays (empty) because the assertion below is still load-bearing:
/// a new `openvtc/vtc/` binding with no manifest row fails rather than
/// silently reopening the backlog. Adding a row again is a deliberate act.
const UNPUBLISHED_OK: &[(&str, &str)] = &[];

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
/// **Empty — the migration is done (#710).** Nothing in this workspace binds
/// the `https://trusttasks.org/openvtc/vtc/` authority any more. The list only
/// ever shrank: every entry was either folded onto a canonical spec, deleted
/// outright, or — for the last two — repointed once the canonical spec it
/// needed was authored upstream.
///
/// Worth keeping the shape of what was learned emptying it: of the ten
/// dispositions recorded here over the migration, **most of the recorded
/// blockers were wrong**, and each was wrong in a way that had kept real work
/// parked. Three assumed a `confirm/1.0` gate that could not apply, one named
/// a target task that would have reintroduced a policy bypass, one assumed an
/// endpoint had to survive when nothing called it, and one cited a duplicate
/// relationship that did not exist. Only `admin/config/{export,import}` had a
/// blocker that held up — and even there, the *fix* it proposed was wrong.
/// Verify a blocker before planning work on it.
///
/// The table stays because the assertion below is still load-bearing: a new
/// `openvtc/vtc/` URI appearing anywhere fails, which is the point — the
/// authority is retired, and nothing should be added to it.
const AWAITING_CANONICAL_FOLD: &[(&str, &str)] = &[
    // `admin/config/{export,import}/1.0` are GONE — repointed to the canonical
    // `spec/vtc/config/{export,import}/0.1` authored in trust-tasks-tf#147.
    //
    // These were the last two, and the only ones whose recorded blocker was
    // *real*: no canonical counterpart existed. `specs/config/` published
    // `show`, `patch`, `reload` and `restart` and nothing to migrate to.
    //
    // The blocker's proposed fix — promote them into the generic `config/*`
    // family with `communityProfile` pushed into `ext` — was dropped. The
    // profile and its diff are roughly half the import's payload, so the
    // "generic" task would have been a hollow shell in its only real use.
    // They are `vtc/`-slugged instead, following `vtc/backup/{export,import}`.
    //
    // The repoint was not a rename: `confirm` moved from a query string into
    // the payload (a Trust Task is one interface over REST, DIDComm and TSP,
    // and only REST has a query string), the `*Applied` lists folded into the
    // change arrays behind a `status` discriminant, and `pendingRestart` is
    // now reported on the preview as well as the apply.
    //
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
    // `auth/admin-login/1.0` is GONE — the route was deleted, not repointed.
    //
    // Its recorded blocker ("the cookie side-effect moves to a binding/ext")
    // assumed the endpoint had to survive. It did not: it ran the same
    // `authenticate_and_mint` as `POST /v1/auth/` and only appended the
    // `Set-Cookie` pair, which `spec/vtc/auth/admin-session/0.1` already mints
    // from an access token the caller holds. Login is
    // `spec/auth/authenticate/0.1` then `spec/vtc/auth/admin-session/0.1` —
    // the path the admin SPA already used. Nothing called `admin-login`.
    //
    // `config/legacy/manage/1.0` is GONE — `GET, PATCH /v1/config` deleted.
    //
    // Its recorded blocker ("strict duplicate of admin/config/manage") was
    // wrong twice: that task was itself retired, and the two surfaces shared
    // no field. The real disposition came from a field-by-field audit —
    // `vtc_did` / `vtc_name` / `vtc_description` are owned by
    // `spec/vtc/community/profile/{show,update}/0.1` (show is any-session,
    // matching the legacy GET), `public_url` by `spec/config/{show,patch}/0.1`
    // over the same db-overlay the legacy PATCH wrote. Identity immutability
    // survives structurally, pinned by `tests/config_identity.rs`.
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

/// Families binding the canonical authority that the registry does not publish,
/// with the **exact** number of unpublished URIs each currently has.
///
/// Binding `https://trusttasks.org/spec/<slug>` asserts the registry serves
/// that slug. An entry here is an admission that it does not — kept visible and
/// counted rather than silently tolerated.
///
/// **The count is asserted, which is what makes a family-level exception safe.**
/// Listing 68 URIs individually would be unreadable; excluding a whole family
/// without a count would let the next unpublished task in it pass unnoticed,
/// which is the failure mode this assertion exists to prevent. Pinning the
/// number means the debt can only shrink: publish some upstream and the count
/// drops (update it here); add a new unpublished one and the count rises and
/// this test fails.
///
/// Widening the assertion below from `spec/vtc/` to the whole `spec/` authority
/// (#821) is what produced this list. **None of it was previously checked by
/// anything.**
const UNPUBLISHED_CANONICAL_OK: &[(&str, usize, &str)] = &[
    // Not a dispatchable task: the framework's error envelope is a *response*
    // type, deliberately absent from the task index, so `schema_for` will never
    // resolve it. This entry is permanent — the others are debt.
    (
        "https://trusttasks.org/spec/trust-task-error/",
        1,
        "framework error envelope — a response type, not a task; absent from the task index by design",
    ),
    // The vault + credential-store archival lifecycle (PR #540): archive,
    // unarchive, restore, purge over both stores. Authored as local
    // "openvtc 0.1 extensions" and never taken upstream, so each claims a
    // `trusttasks.org/spec/vault/` ID the registry does not serve. The registry
    // publishes vault {delete,get,list,proxy-login,release,sign-trust-task,
    // sync,upsert,usage} — and none of these.
    (
        "https://trusttasks.org/spec/vault/",
        12,
        "vault + credential-store archival lifecycle (#540) — never authored upstream",
    ),
    // The bulk of the VTA's own Trust Task surface at 1.0 — keys, contexts,
    // backup, seeds, acl, audit, attestation, config, discovery, management,
    // provision-integration, and the webvh dids / servers / agent-name
    // families. The registry publishes 22 `vta/*` tasks (did-templates,
    // credentials, memory, passkey-vms, webvh/dids/update); the workspace binds
    // 77.
    (
        "https://trusttasks.org/spec/vta/",
        47,
        "VTA Trust Task surface at 1.0 — predates the registry and was never reconciled with it. \
         Down from 55 via #840 phase A: config/{get,update} onto config/{show,patch}, \
         provision-integration/request onto provision/integration/0.2, and acl/* onto the \
         canonical acl/{grant,show,list,update,revoke} family",
    ),
];

/// Every `trusttasks.org/spec/` URI the code binds must be one the registry
/// actually publishes.
///
/// Cross-checked against the generated `trust_tasks_rs` schema index rather
/// than a hand-maintained list, so it tracks the published registry: a typo, a
/// stale slug, or a task repointed to a spec that was never authored all fail
/// here instead of at runtime. `schema_for` returning `None` means this build
/// of the registry crate knows no such task.
///
/// **Scoped to the whole `spec/` authority, not one family (#821).** This
/// checked only the `spec/vtc/` prefix until the `credential-exchange` family
/// showed what that costs: five of its specs existed solely as files in this
/// repo while claiming a `trusttasks.org` ID no consumer could resolve, and
/// three more bound URIs had no spec anywhere at all. Every one of them passed
/// this test, because none of them started with `spec/vtc/`.
///
/// A per-family prefix is the wrong shape for the assertion — it defends the
/// family someone remembered to name, and silently exempts the next one. The
/// claim being tested is about the *authority*: if we bind a
/// `trusttasks.org/spec/` URI, we are asserting the registry serves it.
#[test]
fn every_bound_canonical_task_exists_in_the_registry() {
    const SPEC_PREFIX: &str = "https://trusttasks.org/spec/";
    let root = workspace_root();
    let mut bound = BTreeSet::new();
    for crate_src in BINDING_SITES {
        collect_prefixed(&root.join(crate_src), SPEC_PREFIX, &mut bound);
    }
    // Narrowing to the whole `spec/` authority catches strings that are not
    // task URIs at all, so filter on the shape the registry actually defines:
    // a Type URI ends in a `MAJOR.MINOR` segment (SPEC §6.1). One rule, two
    // classes excluded — family *prefixes* used to build or assert URIs
    // (`https://trusttasks.org/spec/vault/`, from `vta-sdk`'s
    // `ALLOWED_PREFIXES`), and shared schema `$id`s, which are components
    // rather than tasks and are deliberately absent from the task index
    // (`vault/_shared/0.1/vault-secret`).
    bound.retain(|uri| {
        uri.rsplit('/')
            .next()
            .is_some_and(|last| match last.split_once('.') {
                Some((major, minor)) => {
                    !major.is_empty()
                        && !minor.is_empty()
                        && major.bytes().all(|b| b.is_ascii_digit())
                        && minor.bytes().all(|b| b.is_ascii_digit())
                }
                None => false,
            })
    });
    assert!(
        !bound.is_empty(),
        "found no spec/ task bindings at all — the scan is broken, not the code"
    );

    let missing: Vec<_> = bound
        .iter()
        .filter(|uri| trust_tasks_rs::schema_index::schema_for(uri).is_none())
        .cloned()
        .collect();

    // Excepted families: the count must match exactly, so the debt can shrink
    // but never grow unnoticed.
    for (family, expected, reason) in UNPUBLISHED_CANONICAL_OK {
        let actual = missing.iter().filter(|u| u.starts_with(family)).count();
        assert_eq!(
            actual, *expected,
            "{family} has {actual} unpublished URIs, expected {expected} ({reason}).\n\n\
             If it went DOWN, some were published upstream — lower the count here.\n\
             If it went UP, a new URI was bound on an authority the registry does \
             not serve. Author the spec upstream, or bind an authority we control; \
             raising this number is the wrong fix."
        );
    }

    let unknown: Vec<_> = missing
        .into_iter()
        .filter(|uri| {
            !UNPUBLISHED_CANONICAL_OK
                .iter()
                .any(|(family, _, _)| uri.starts_with(family))
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "these trusttasks.org/spec/ URIs are bound but the registry \
         (trust-tasks-rs {}) publishes no such task:\n  {}\n\nEither the slug \
         is wrong or the spec was never authored upstream. Binding a \
         `trusttasks.org/spec/` URI asserts the registry serves it — author \
         the spec upstream, or bind an authority we control.",
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
