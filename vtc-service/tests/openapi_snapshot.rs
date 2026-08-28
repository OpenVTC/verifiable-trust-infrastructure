//! The checked-in OpenAPI document must match the one this build serves.
//!
//! `admin-ui/openapi.json` is not documentation. It is the input to
//! `npm run wire:generate`, which produces `admin-ui/src/lib/wire.ts` — the
//! types every console fetch is checked against. That makes it a build
//! artefact with a consumer, and a stale one silently un-checks the console:
//! `tsc` keeps passing, because generated types are self-consistent whether or
//! not they describe the daemon.
//!
//! So it is checked in and asserted rather than generated on demand. Three
//! links, each with its own gate, and the chain only holds if all three do:
//!
//! 1. **this test** — `openapi.json` matches `routes::openapi_spec()`
//! 2. **`npm run wire:check`** — `wire.ts` matches `openapi.json`
//! 3. **`tsc`** — the console matches `wire.ts`
//!
//! Link 1 is also why the document is worth trusting at all: see
//! `openapi_response_census.rs`, which asserts each route's `body =` names the
//! type its handler returns. Without that census this snapshot would faithfully
//! record whatever the annotations claimed, and generate a console built on it.

use std::path::{Path, PathBuf};

fn snapshot_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("admin-ui/openapi.json")
}

/// The document as it should be on disk: pretty-printed, newline-terminated,
/// so a diff of a real change is readable rather than one enormous line.
fn rendered() -> String {
    let spec = vtc_service::routes::openapi_spec();
    let mut out = serde_json::to_string_pretty(&spec).expect("the document serialises");
    out.push('\n');
    out
}

#[test]
fn the_checked_in_openapi_document_matches_this_build() {
    let want = rendered();
    let path = snapshot_path();

    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        std::fs::write(&path, &want).expect("snapshot is writable");
        eprintln!("wrote {}", path.display());
        return;
    }

    let got = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing or unreadable ({e}). Regenerate it with:\n\n    \
             UPDATE_OPENAPI=1 cargo test -p vtc-service --test openapi_snapshot\n",
            path.display()
        )
    });

    assert!(
        got == want,
        "admin-ui/openapi.json is out of date — this build serves a different API \
         document than the one checked in.\n\n\
         That file generates admin-ui/src/lib/wire.ts, so leaving it stale means the \
         console is typed against an API the daemon no longer has, and nothing will \
         say so: the generated types typecheck against themselves either way.\n\n\
         Regenerate both, and commit both:\n\n    \
         UPDATE_OPENAPI=1 cargo test -p vtc-service --test openapi_snapshot\n    \
         cd vtc-service/admin-ui && npm run wire:generate\n"
    );
}

/// The document must be stable across two builds of the same code.
///
/// A snapshot that reorders between runs is worse than none: it fails on
/// unrelated PRs, gets regenerated to make the failure go away, and the habit
/// of regenerating-without-reading is exactly what lets a real change through.
#[test]
fn the_document_is_deterministic() {
    assert_eq!(
        rendered(),
        rendered(),
        "openapi_spec() serialised differently on two calls in one process. \
         A non-deterministic document cannot be snapshotted; find the unordered \
         collection behind it before relying on this gate."
    );
}

/// `operationId` must be unique across the document, as OpenAPI requires.
///
/// utoipa defaults it to the handler's function name, and this service names
/// handlers for what they do *within* their module: seven `list`s, four
/// `revoke`s, three `challenge`s. Across one document those collapse into one
/// identifier each, and a generator that keys its output on `operationId` —
/// `openapi-typescript` does — emits duplicate members and produces a
/// `wire.ts` that will not compile.
///
/// Six ids covered twenty-one operations when this was written. The failure
/// mode is worth noting: nothing was wrong with the *service*, and nothing was
/// wrong with any one annotation read on its own. The defect only exists at
/// the document level, which is the level nothing was looking at.
#[test]
fn operation_ids_are_unique() {
    let doc: serde_json::Value =
        serde_json::from_str(&rendered()).expect("the document is valid JSON");

    let mut seen: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (path, item) in doc["paths"].as_object().expect("paths is an object") {
        for (method, op) in item.as_object().expect("a path item is an object") {
            if !matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                continue;
            }
            if let Some(id) = op.get("operationId").and_then(|v| v.as_str()) {
                seen.entry(id.to_string())
                    .or_default()
                    .push(format!("{} {path}", method.to_uppercase()));
            }
        }
    }

    let dupes: Vec<String> = seen
        .into_iter()
        .filter(|(_, ops)| ops.len() > 1)
        .map(|(id, ops)| format!("  {id}: {}", ops.join(", ")))
        .collect();

    assert!(
        dupes.is_empty(),
        "{} operationId(s) are used by more than one operation:\n\n{}\n\n\
         Two handlers in different modules can share a name; two operations in one \
         document cannot share an id. Give the colliding ones an explicit \
         `operation_id = \"…\"` in their `#[utoipa::path]` — area first, verb last \
         (`endorsementList`, `invitationRevoke`) — then regenerate the snapshot.",
        dupes.len(),
        dupes.join("\n")
    );
}

/// Every `$ref` in the document must resolve to a registered component.
///
/// A dangling `$ref` is not a cosmetic flaw: `openapi-typescript` refuses to
/// generate anything at all from a document containing one, so the whole wire-
/// type chain stops at the first unregistered schema — and the failure arrives
/// as a stack trace from a bundler, nowhere near the annotation that caused it.
///
/// The way to produce one is not obvious, which is why this test exists rather
/// than a comment: utoipa collects schemas transitively from `request_body` and
/// `body =`, but **not** through an `IntoParams` field. A type used only as a
/// query parameter is referenced and never registered. `PolicyStatusFilter` on
/// `GET /v1/policies` was exactly that, and derived `ToSchema` the whole time —
/// the derive is what makes the reference; registration is separate.
#[test]
fn no_dangling_refs() {
    let doc: serde_json::Value =
        serde_json::from_str(&rendered()).expect("the document is valid JSON");

    let registered: std::collections::BTreeSet<String> = doc
        .pointer("/components/schemas")
        .and_then(|s| s.as_object())
        .map(|m| {
            m.keys()
                .map(|k| format!("#/components/schemas/{k}"))
                .collect()
        })
        .unwrap_or_default();

    let mut refs = std::collections::BTreeSet::new();
    collect_refs(&doc, &mut refs);

    let dangling: Vec<_> = refs.difference(&registered).cloned().collect();
    assert!(
        dangling.is_empty(),
        "the OpenAPI document references schema(s) it does not define: {dangling:?}.\n\n\
         A type reached only through a `params(...)` query struct is referenced but not \
         registered, however it derives. Add it to `components(schemas(...))` on `ApiDoc` \
         in routes/mod.rs, then regenerate the snapshot."
    );
}

/// Every `$ref` string anywhere in the document.
fn collect_refs(node: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
    match node {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                match (key.as_str(), value.as_str()) {
                    ("$ref", Some(r)) => {
                        out.insert(r.to_string());
                    }
                    _ => collect_refs(value, out),
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| collect_refs(i, out)),
        _ => {}
    }
}
