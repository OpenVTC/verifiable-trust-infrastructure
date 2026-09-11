//! Census: no workspace crate hand-writes a serde payload or response type for
//! a Trust Task whose wire types `trust-tasks-rs` generates.
//!
//! ## Why
//!
//! The Trust Task specifications in dtgwg-trust-tasks-tf are normative, and
//! `trust-tasks-codegen` turns each one into Rust types published under
//! `trust_tasks_rs::specs`. A hand-written copy of one of those types is a
//! second definition of the wire that nothing keeps in step with the first.
//!
//! The peer-vetting work showed what that costs. Its copies drifted from the
//! published schemas within one stack of pull requests: a documented shape the
//! schema refused, and an admin console calling a Trust Task URI no route bound.
//! Those copies were replaced with the generated types; this census stops the
//! next one being written.
//!
//! ## What it treats as a payload or response type
//!
//! A wire type in this workspace names the task it carries in the summary of
//! its doc comment — "`vetting/request/0.1` payload.", "`acl/list/0.1`
//! response.", "the shape `vtc/backup/export/0.1` publishes". The census reads
//! every `Serialize` or `Deserialize` struct and enum in every workspace member's
//! production source. Where the summary names a Trust Task **and** calls the
//! type a payload, request, response or body, or says the task publishes it, the
//! census asks `trust_tasks_rs::schema_index` whether that task has a generated
//! module. If it does, the type duplicates the generated one.
//!
//! So name the task in a wire type's summary. A type that carries a task's
//! payload without saying so is invisible to this census — and to every reader.
//!
//! Parsed with `syn`, not grepped, for the reason `payload_ext_census.rs` gives:
//! attributes span lines, and a line-oriented scan misreads them in the
//! direction that lets a violation through.
//!
//! ## The baseline
//!
//! [`PREDATES_GENERATED`] lists the hand-written types that were written before
//! their task had a generated module. **It only shrinks.** Migrating one to its
//! generated type removes it from the source, and the census then fails until
//! its entry goes too. A new type is never added: use the generated one.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Attribute, Item, Meta};

const SPEC_AUTHORITY: &str = "https://trusttasks.org/spec/";

/// Hand-written types for tasks that now have generated modules, written before
/// those modules existed. `(file, type)`, file relative to the workspace root;
/// the task each restates follows it.
///
/// This is migration debt, recorded so it is visible and cannot grow — not a
/// list of exceptions. The peer-vetting family was the first to be paid off.
const PREDATES_GENERATED: &[(&str, &str)] = &[
    ("vta-sdk/src/client/types.rs", "CreateDidWebvhRequest"), // vta/webvh/dids/create/1.0
    ("vta-sdk/src/client/types.rs", "UpdateContextRequest"),  // vta/contexts/update/1.0
    (
        "vta-sdk/src/protocols/acl_management/change_role.rs",
        "ChangeRoleBody",
    ), // acl/change-role/0.1
    (
        "vta-sdk/src/protocols/acl_management/create.rs",
        "CreateAclBody",
    ), // acl/grant/0.1
    (
        "vta-sdk/src/protocols/acl_management/create.rs",
        "CreateAclResponseBody",
    ), // acl/grant/0.1
    (
        "vta-sdk/src/protocols/acl_management/delete.rs",
        "DeleteAclBody",
    ), // acl/revoke/0.1
    (
        "vta-sdk/src/protocols/acl_management/delete.rs",
        "DeleteAclResultBody",
    ), // acl/revoke/0.1
    ("vta-sdk/src/protocols/acl_management/get.rs", "GetAclBody"), // acl/show/0.1
    (
        "vta-sdk/src/protocols/acl_management/get.rs",
        "GetAclResultBody",
    ), // acl/show/0.1
    (
        "vta-sdk/src/protocols/acl_management/list.rs",
        "ListAclBody",
    ), // acl/list/0.1
    (
        "vta-sdk/src/protocols/acl_management/list.rs",
        "ListAclResultBody",
    ), // acl/list/0.1
    (
        "vta-sdk/src/protocols/acl_management/swap.rs",
        "SwapKeyBody",
    ), // acl/swap-key/0.1
    (
        "vta-sdk/src/protocols/acl_management/swap.rs",
        "SwapKeyResultBody",
    ), // acl/swap-key/0.1
    (
        "vta-sdk/src/protocols/acl_management/update.rs",
        "UpdateAclBody",
    ), // acl/update/0.1
    (
        "vta-sdk/src/protocols/audit_management/list.rs",
        "ListAuditLogsBody",
    ), // audit/list/0.1
    (
        "vta-sdk/src/protocols/audit_management/list.rs",
        "ListAuditLogsResultBody",
    ), // audit/list/0.1
    (
        "vta-sdk/src/protocols/audit_management/verify.rs",
        "VerifyChainBody",
    ), // audit/verify/0.1
    (
        "vta-sdk/src/protocols/did_management/servers.rs",
        "ReconcileWebvhServerDidsBody",
    ), // vta/webvh/servers/reconcile/0.1
    (
        "vta-sdk/src/protocols/discovery.rs",
        "SupportedTasksResponse",
    ), // trust-task-discovery/0.1
    (
        "vta-sdk/src/protocols/key_management/create.rs",
        "CreateKeyResponseBody",
    ), // keys/create/0.1
    (
        "vta-sdk/src/protocols/key_management/get.rs",
        "GetKeyResponseBody",
    ), // keys/show/0.1
    (
        "vta-sdk/src/protocols/key_management/import.rs",
        "ImportKeyBody",
    ), // keys/import/0.1
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "DeletePolicyBody",
    ), // policy/delete/0.1
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "DeletePolicyResultBody",
    ), // policy/delete/0.1
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "GetPolicyBody",
    ), // policy/get/0.1
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "GetPolicyResultBody",
    ), // policy/get/0.1
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "ListPoliciesBody",
    ), // policy/list/0.2
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "ListPoliciesResultBody",
    ), // policy/list/0.2
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "UpsertPolicyBody",
    ), // policy/upsert/0.2
    (
        "vta-sdk/src/protocols/policy_management.rs",
        "UpsertPolicyResultBody",
    ), // policy/upsert/0.2
    (
        "vta-sdk/src/protocols/vta_management/get_config.rs",
        "GetConfigBody",
    ), // config/show/0.1
    (
        "vta-sdk/src/protocols/vta_management/get_config.rs",
        "GetConfigResultBody",
    ), // config/show/0.1
    (
        "vta-sdk/src/protocols/vta_management/update_config.rs",
        "UpdateConfigBody",
    ), // config/patch/0.1
    (
        "vta-sdk/src/protocols/vta_management/update_config.rs",
        "UpdateConfigResultBody",
    ), // config/patch/0.1
    ("vta-service/src/routes/acl.rs", "SwapAclRequest"),      // acl/swap-key/0.1
    (
        "vta-service/src/trust_tasks/vault.rs",
        "VaultListResponseBody",
    ), // vault/list/0.1
    (
        "vta-service/src/trust_tasks/vault.rs",
        "VaultListStatusFilter",
    ), // vault/list/0.1
    (
        "vta-service/src/trust_tasks/vault.rs",
        "VaultProxyLoginBody",
    ), // vault/proxy-login/0.1
    (
        "vta-service/src/trust_tasks/vault.rs",
        "VaultProxyLoginResponseBody",
    ), // vault/proxy-login/0.1
    ("vta-service/src/trust_tasks/vault.rs", "VaultReleaseBody"), // vault/release/0.1
    (
        "vta-service/src/trust_tasks/vault.rs",
        "VaultSignTrustTaskBody",
    ), // vault/sign-trust-task/0.1
    (
        "vta-service/src/trust_tasks/vault.rs",
        "VaultSignTrustTaskResponseBody",
    ), // vault/sign-trust-task/0.1
    ("vta-service/src/trust_tasks/vault.rs", "VaultUpsertBody"), // vault/upsert/0.1
    ("vtc-service/src/routes/admin/config.rs", "ExportResponse"), // vtc/config/export/0.1#response
    ("vtc-service/src/routes/admin/config.rs", "ImportRequest"), // vtc/config/import/0.1
    ("vtc-service/src/routes/admin/config.rs", "ImportResponse"), // vtc/config/import/0.1#response
    (
        "vtc-service/src/routes/admin/passkeys.rs",
        "RegisteredCredential",
    ), // auth/passkey/list/0.1
    ("vtc-service/src/routes/backup.rs", "ExportResponse"),   // vtc/backup/export/0.1
    (
        "vtc-service/src/routes/ceremonies.rs",
        "CeremonyListResponse",
    ), // vtc/ceremonies/list/0.1
    (
        "vtc-service/src/routes/endorsement_types.rs",
        "RegisterResponse",
    ), // vtc/endorsement-types/register/0.1
    (
        "vtc-service/src/routes/endorsements.rs",
        "EndorsementEnvelope",
    ), // vtc/endorsements/show/0.1
    ("vtc-service/src/routes/join_requests/decide.rs", "Decision"), // vtc/join-requests/decide/0.1
    (
        "vtc-service/src/routes/join_requests/read.rs",
        "JoinRequestEnvelope",
    ), // vtc/join-requests/show/0.1
    ("vtc-service/src/routes/members/read.rs", "MemberEnvelope"), // vtc/members/show/0.1
    (
        "vtc-service/src/routes/members/read.rs",
        "RemovedMembersResponse",
    ), // vtc/members/removed/0.1
    ("vtc-service/src/routes/website/files.rs", "DeleteResponse"), // vtc/website/files/delete/0.1
    (
        "vtc-service/src/routes/website/generations.rs",
        "GenerationsResponse",
    ), // vtc/website/generations/list/0.1
    (
        "vtc-service/src/routes/website/generations.rs",
        "RollbackResponse",
    ), // vtc/website/rollback/0.1
    ("vti-rooms/src/wire.rs", "ChainBody"),                   // rooms/epoch/chain/0.1
    ("vti-rooms/src/wire.rs", "ClaimOwnerBody"),              // rooms/owner/claim/0.1
    ("vti-rooms/src/wire.rs", "CommitsBody"),                 // rooms/epoch/commits/0.1
    ("vti-rooms/src/wire.rs", "CreateRoomBody"),              // rooms/create/0.1
    ("vti-rooms/src/wire.rs", "CurateRecordBody"),            // rooms/records/curate/0.1
    ("vti-rooms/src/wire.rs", "GetRecordBody"),               // rooms/records/get/0.1
    ("vti-rooms/src/wire.rs", "ListRecordsBody"),             // rooms/records/list/0.1
    ("vti-rooms/src/wire.rs", "MintEpochBody"),               // rooms/epoch/mint/0.1
    ("vti-rooms/src/wire.rs", "PruneBody"),                   // rooms/epoch/prune/0.1
    ("vti-rooms/src/wire.rs", "PutRecordBody"),               // rooms/records/put/0.1
    ("vti-rooms/src/wire.rs", "TransferOwnerBody"),           // rooms/owner/transfer/0.1
];

/// The size of [`PREDATES_GENERATED`], asserted so the list cannot grow quietly.
const PREDATES_GENERATED_COUNT: usize = 69;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vta-sdk sits inside the workspace")
        .to_path_buf()
}

/// The `[workspace] members` of the root manifest.
fn workspace_members(root: &Path) -> Vec<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    let start = manifest
        .find("members = [")
        .expect("the workspace manifest lists its members");
    let rest = &manifest[start + "members = [".len()..];
    let list = &rest[..rest.find(']').expect("the members list closes")];
    list.lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(|line| line.split(','))
        .map(|m| m.trim().trim_matches('"').to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory is readable") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn attr_tokens(attr: &Attribute, name: &str) -> Option<String> {
    if !attr.path().is_ident(name) {
        return None;
    }
    match &attr.meta {
        Meta::List(list) => Some(list.tokens.to_string()),
        _ => None,
    }
}

fn derives_serde(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr_tokens(attr, "derive")
            .is_some_and(|t| t.contains("Serialize") || t.contains("Deserialize"))
    })
}

/// `#[cfg(test)]` items are not wire types.
fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr_tokens(attr, "cfg").is_some_and(|t| t.contains("test")))
}

/// The summary paragraph of a doc comment: its lines up to the first blank.
fn summary(attrs: &[Attribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) = &nv.value
        else {
            continue;
        };
        let line = text.value();
        if line.trim().is_empty() {
            if lines.is_empty() {
                continue;
            }
            break;
        }
        lines.push(line.trim().to_string());
    }
    lines.join(" ")
}

/// `slug/path/M.m`, optionally `#response`: the shape of a Trust Task reference
/// relative to the spec authority.
fn as_task_reference(candidate: &str) -> Option<String> {
    let candidate = candidate.strip_prefix(SPEC_AUTHORITY).unwrap_or(candidate);
    let (path, fragment) = match candidate.split_once('#') {
        Some((path, "response")) => (path, "#response"),
        Some(_) => return None,
        None => (candidate, ""),
    };
    let (slug, version) = path.rsplit_once('/')?;
    let (major, minor) = version.split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let slug_ok = !slug.is_empty()
        && slug.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    (slug_ok && digits(major) && digits(minor)).then(|| format!("{path}{fragment}"))
}

/// The Trust Task references in `text`, and `text` with them — and every other
/// backticked span — removed, so a member name in backticks is not read as prose.
fn task_references(text: &str) -> (Vec<String>, String) {
    let mut references = Vec::new();
    let mut prose = String::new();
    for (i, part) in text.split('`').enumerate() {
        if i % 2 == 1 {
            references.extend(as_task_reference(part.trim()));
            continue;
        }
        for word in part.split_whitespace() {
            if word.starts_with(SPEC_AUTHORITY) {
                let uri = word.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
                references.extend(as_task_reference(uri));
            } else {
                prose.push_str(word);
                prose.push(' ');
            }
        }
    }
    (references, prose)
}

/// Does the prose call the type a task's payload, request, response or body, or
/// say a task publishes it?
fn claims_to_carry(prose: &str) -> bool {
    prose
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .any(|w| {
            matches!(
                w.as_str(),
                "payload" | "request" | "response" | "body" | "publishes"
            )
        })
}

/// The generated task a type's summary claims it carries, if any.
fn claimed_generated_task(attrs: &[Attribute]) -> Option<String> {
    let (references, prose) = task_references(&summary(attrs));
    if !claims_to_carry(&prose) {
        return None;
    }
    references.into_iter().find(|r| {
        trust_tasks_rs::schema_index::schema_for(&format!("{SPEC_AUTHORITY}{r}")).is_some()
    })
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Found {
    file: String,
    ty: String,
    task: String,
}

fn walk(items: &[Item], file: &str, inspected: &mut usize, out: &mut Vec<Found>) {
    for item in items {
        let (attrs, ident) = match item {
            Item::Struct(s) => (&s.attrs, &s.ident),
            Item::Enum(e) => (&e.attrs, &e.ident),
            Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    walk(inner, file, inspected, out);
                }
                continue;
            }
            _ => continue,
        };
        if is_cfg_test(attrs) || !derives_serde(attrs) {
            continue;
        }
        *inspected += 1;
        if let Some(task) = claimed_generated_task(attrs) {
            out.push(Found {
                file: file.to_string(),
                ty: ident.to_string(),
                task,
            });
        }
    }
}

fn census() -> (usize, Vec<Found>) {
    let root = workspace_root();
    let mut inspected = 0;
    let mut found = Vec::new();
    for member in workspace_members(&root) {
        let src = root.join(&member).join("src");
        if !src.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_sources(&src, &mut files);
        for path in files {
            let text = fs::read_to_string(&path).expect("source file is readable");
            let parsed = syn::parse_file(&text)
                .unwrap_or_else(|e| panic!("{}: does not parse: {e}", path.display()));
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            walk(&parsed.items, &rel, &mut inspected, &mut found);
        }
    }
    found.sort();
    (inspected, found)
}

#[test]
fn no_workspace_crate_hand_writes_a_generated_trust_task_type() {
    let (inspected, found) = census();
    assert!(
        inspected > 300,
        "inspected only {inspected} serde types — the walk is broken, and a census that \
         inspects nothing passes vacuously"
    );

    let duplicates: Vec<&Found> = found
        .iter()
        .filter(|f| !PREDATES_GENERATED.contains(&(f.file.as_str(), f.ty.as_str())))
        .collect();
    assert!(
        duplicates.is_empty(),
        "{} hand-written type(s) restate a Trust Task that trust-tasks-rs generates:\n{}\n\n\
         Use the generated type from `trust_tasks_rs::specs` (the vetting family re-exports \
         its own from `vta_sdk::protocols::vetting`). A rule the schema cannot state belongs \
         in a check over the generated type, not in a copy of it. If the specification is \
         wrong, change it in dtgwg-trust-tasks-tf and take the trust-tasks-rs release that \
         carries it.",
        duplicates.len(),
        duplicates
            .iter()
            .map(|f| format!("  (\"{}\", \"{}\"),  // {}", f.file, f.ty, f.task))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let stale: Vec<&(&str, &str)> = PREDATES_GENERATED
        .iter()
        .filter(|(file, ty)| !found.iter().any(|f| f.file == *file && f.ty == *ty))
        .collect();
    assert!(
        stale.is_empty(),
        "PREDATES_GENERATED lists type(s) that no longer restate a generated task — they were \
         migrated or removed. Delete their entries and lower PREDATES_GENERATED_COUNT:\n{stale:#?}"
    );
}

/// The baseline can only shrink: an entry is removed when its type is migrated,
/// never added.
#[test]
fn the_baseline_only_shrinks() {
    assert_eq!(
        PREDATES_GENERATED.len(),
        PREDATES_GENERATED_COUNT,
        "PREDATES_GENERATED changed size. Removing a migrated type? Lower the count with it. \
         Adding one? Don't — use the generated type."
    );
}

#[test]
fn the_detector_reads_a_summary_the_way_a_reader_does() {
    let parse = |src: &str| -> Option<String> {
        let file = syn::parse_file(src).unwrap();
        let Item::Struct(s) = &file.items[0] else {
            panic!("a struct");
        };
        claimed_generated_task(&s.attrs)
    };
    assert_eq!(
        parse("/// `vetting/request/0.1` payload.\n#[derive(Serialize)]\nstruct A;"),
        Some("vetting/request/0.1".into())
    );
    assert_eq!(
        parse(
            "/// `vtc/vetting/vetters/list/0.1#response` payload.\n#[derive(Serialize)]\nstruct A;"
        ),
        Some("vtc/vetting/vetters/list/0.1#response".into())
    );
    assert_eq!(
        parse(
            "/// The shape https://trusttasks.org/spec/vtc/members/show/0.1 publishes.\n\
             #[derive(Serialize)]\nstruct A;"
        ),
        Some("vtc/members/show/0.1".into())
    );
    // Named, but not claimed as the type's own payload.
    assert_eq!(
        parse(
            "/// The ticket an applicant presents in `vetting/request/0.1`.\n\
             #[derive(Serialize)]\nstruct A;"
        ),
        None
    );
    // A member called `payload` in backticks is not prose.
    assert_eq!(
        parse("/// Holds the `payload` of `vetting/request/0.1`.\n#[derive(Serialize)]\nstruct A;"),
        None
    );
    // Only the summary counts.
    assert_eq!(
        parse(
            "/// A record.\n///\n/// Mentions the `vetting/request/0.1` payload.\n\
             #[derive(Serialize)]\nstruct A;"
        ),
        None
    );
    // A task no generated module serves is not this census's business.
    assert_eq!(
        parse("/// `example/unpublished/9.9` payload.\n#[derive(Serialize)]\nstruct A;"),
        None
    );
    assert_eq!(
        as_task_reference("vetting/_shared/0.1/identity-vetting"),
        None
    );
}
