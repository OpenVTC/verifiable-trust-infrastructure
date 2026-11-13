//! Census: every payload a Trust Task handler parses under
//! `src/trust_tasks/` is a generated `vti_specs` type, or baselined (#2567).
//!
//! The root CLAUDE.md forbids a hand-written payload type for a task that has a
//! generated module. `vta-sdk/tests/generated_wire_types_census.rs` enforces
//! that for types whose doc summary names the task they carry — and so cannot
//! see a type nobody documented, which is how the six `consent/*` payloads
//! went unnoticed. This census reads the parse sites instead: every `T` in
//! `parse_payload::<T>(..)` or `let _: T = parse_payload(..)` /
//! `let _: T = match parse_payload(..)`, resolved through the file's `use`
//! items, must be a path into `vti_specs` (or `vta_sdk::specs`, which
//! re-exports it). Anything else must be listed in [`BASELINE`], which only
//! shrinks: a new handler reads the generated type, and a type migrated off
//! the list is deleted from it.
//!
//! A baselined type that is security-relevant should refuse unknown members
//! (`deny_unknown_fields`, R3) — `trust_tasks::helpers::
//! assert_reads_exactly_the_schema_members` checks that against the pinned
//! schema.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;
use syn::{Expr, GenericArgument, Item, Local, Pat, PathArguments, Type, UseTree};

/// Hand-written payload types still parsed under `src/trust_tasks/`, as
/// `(file, type)` with `file` relative to `src/trust_tasks/`. Only shrinks.
///
/// Why the larger groups are here: the `vault/*` bodies are read after the
/// `wire_v0_2` edge transform rewrites a 0.2+ document into the 0.1 casing,
/// which the generated (spec-cased) types would refuse; they refuse unknown
/// members and are held to their pinned schemas by
/// `vault::issue_2621_tests`. The rest predate their generated modules or
/// serve tasks no `vti-specs-*` crate pins.
const BASELINE: &[(&str, &str)] = &[
    ("acl.rs", "ChangeRoleBody"),
    ("acl.rs", "SwapKeyBody"),
    ("app_state.rs", "AppStateDeleteBody"),
    ("app_state.rs", "AppStateGetBody"),
    ("app_state.rs", "AppStateGetManyBody"),
    ("app_state.rs", "AppStateListBody"),
    ("app_state.rs", "AppStatePutBody"),
    ("app_state.rs", "AppStatePutManyBody"),
    ("audit.rs", "GetRetentionBody"),
    ("audit.rs", "ListAuditLogsBody"),
    ("audit.rs", "UpdateRetentionBody"),
    ("backup.rs", "AbortBundleBody"),
    ("backup.rs", "CompleteExportBody"),
    ("backup.rs", "FinalizeImportBody"),
    ("backup.rs", "InitiateExportBody"),
    ("backup.rs", "InitiateImportBody"),
    ("config.rs", "GetConfigBody"),
    ("config.rs", "UpdateConfigBody"),
    ("contexts.rs", "CreateContextBody"),
    ("contexts.rs", "DeleteContextPreviewBody"),
    ("contexts.rs", "GetContextBody"),
    ("contexts.rs", "ListContextsBody"),
    ("contexts.rs", "UpdateContextBody"),
    (
        "contexts.rs",
        "vta_sdk::protocols::context_management::secrets::GetContextSecretsBody",
    ),
    ("cred_vault.rs", "CredDeleteBody"),
    ("cred_vault.rs", "CredLifecycleBody"),
    ("cred_vault.rs", "CredentialQuery"),
    ("cred_vault.rs", "ReceiveBody"),
    ("credential_exchange.rs", "IssueBody"),
    ("credential_exchange.rs", "OfferBody"),
    ("credential_exchange.rs", "PendingApproveBody"),
    ("credential_exchange.rs", "PendingDenyBody"),
    ("credential_exchange.rs", "QueryBody"),
    ("credentials.rs", "IssueCredentialBody"),
    ("credentials.rs", "ListCredentialsBody"),
    ("credentials.rs", "RevokeCredentialBody"),
    ("did_templates.rs", "CreateDidTemplateBody"),
    ("did_templates.rs", "DeleteDidTemplateBody"),
    ("did_templates.rs", "GetDidTemplateBody"),
    ("did_templates.rs", "ListDidTemplatesBody"),
    ("did_templates.rs", "RenderDidTemplateBody"),
    ("did_templates.rs", "UpdateDidTemplateBody"),
    ("keys.rs", "CreateKeyBody"),
    ("keys.rs", "DeriveAndSignBody"),
    ("keys.rs", "DeriveAndSignDocumentBody"),
    ("keys.rs", "GetKeyBody"),
    ("keys.rs", "GetKeySecretBody"),
    ("keys.rs", "ImportKeyBody"),
    ("keys.rs", "ListKeysBody"),
    ("keys.rs", "RenameKeyBody"),
    ("keys.rs", "RevokeKeyBody"),
    ("keys.rs", "SignCsrPayload"),
    ("keys.rs", "SignDocumentPayload"),
    ("keys.rs", "SignJwsPayload"),
    ("keys.rs", "SignRequestBody"),
    ("keys.rs", "SignSshsigPayload"),
    (
        "keys.rs",
        "vta_sdk::protocols::key_management::set_exportability::SetKeyExportabilityBody",
    ),
    ("management.rs", "ReloadServicesBody"),
    ("memory.rs", "MemoryDeleteBody"),
    ("memory.rs", "MemoryListBody"),
    ("memory.rs", "MemoryPutBody"),
    ("passkey_vms.rs", "EnrollPasskeyChallengeBody"),
    ("passkey_vms.rs", "EnrollPasskeySubmitBody"),
    ("passkey_vms.rs", "ListPasskeyVmsBody"),
    ("passkey_vms.rs", "RevokePasskeyVmBody"),
    ("pcs.rs", "P"),
    ("policy.rs", "DeletePolicyBody"),
    ("policy.rs", "GetPolicyBody"),
    ("policy.rs", "ListPoliciesBody"),
    ("policy.rs", "UpsertPolicyBody"),
    ("provision_integration.rs", "ProvisionIntegrationRequest"),
    ("seeds.rs", "ListSeedsBody"),
    ("seeds.rs", "RotateSeedBody"),
    ("vault.rs", "VaultDeleteBody"),
    ("vault.rs", "VaultGetBody"),
    ("vault.rs", "VaultLifecycleBody"),
    ("vault.rs", "VaultListBody"),
    ("vault.rs", "VaultProxyLoginBody"),
    ("vault.rs", "VaultReleaseBody"),
    ("vault.rs", "VaultSignTrustTaskBody"),
    ("vault.rs", "VaultUpsertBody"),
    ("webvh.rs", "AgentNameBody"),
    ("webvh.rs", "AgentNameCheckBody"),
    ("webvh.rs", "CreateDidWebvhBody"),
    ("webvh.rs", "DeleteDidWebvhBody"),
    ("webvh.rs", "GetDidWebvhBody"),
    ("webvh.rs", "ListDidsWebvhBody"),
    ("webvh.rs", "ListWebvhServerDomainsBody"),
    ("webvh.rs", "ListWebvhServersBody"),
    ("webvh.rs", "RealignDidKeysBody"),
    ("webvh.rs", "ReconcileWebvhServerDidsBody"),
    ("webvh.rs", "RegisterDidWithServerBody"),
    ("webvh.rs", "RegisterWebvhServerBody"),
    ("webvh.rs", "RemoveWebvhServerBody"),
    ("webvh.rs", "RetireOrphanSlotBody"),
    ("webvh.rs", "RotateKeysWithDid"),
    ("webvh.rs", "UpdateDidWithDid"),
];

/// The size of [`BASELINE`], asserted so the list cannot grow quietly.
const BASELINE_COUNT: usize = 97;

fn trust_tasks_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust_tasks")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `use` aliases in a file: the last segment (or `as` rename) → its full path.
fn collect_uses(tree: &UseTree, prefix: &mut Vec<String>, out: &mut BTreeMap<String, String>) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            collect_uses(&p.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(n) => {
            let mut full = prefix.clone();
            full.push(n.ident.to_string());
            out.insert(n.ident.to_string(), full.join("::"));
        }
        UseTree::Rename(r) => {
            let mut full = prefix.clone();
            full.push(r.ident.to_string());
            out.insert(r.rename.to_string(), full.join("::"));
        }
        UseTree::Group(g) => {
            for t in &g.items {
                collect_uses(t, prefix, out);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn type_path(ty: &Type) -> Option<Vec<String>> {
    match ty {
        Type::Path(p) => Some(
            p.path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
        ),
        _ => None,
    }
}

/// Is `call` a call of `parse_payload`?
fn is_parse_payload(call: &Expr) -> Option<Option<Type>> {
    let Expr::Call(c) = call else { return None };
    let Expr::Path(p) = &*c.func else { return None };
    let last = p.path.segments.last()?;
    if last.ident != "parse_payload" {
        return None;
    }
    // The turbofish, if any.
    if let PathArguments::AngleBracketed(args) = &last.arguments
        && let Some(GenericArgument::Type(t)) = args.args.first()
    {
        return Some(Some(t.clone()));
    }
    Some(None)
}

/// The `parse_payload` call an initializer makes: itself, or the scrutinee of
/// a `match`, possibly behind `?`.
fn parse_call(expr: &Expr) -> Option<Option<Type>> {
    match expr {
        Expr::Match(m) => parse_call(&m.expr),
        Expr::Try(t) => parse_call(&t.expr),
        other => is_parse_payload(other),
    }
}

/// The parse sites of one file, each type resolved through the `use` items in
/// scope where it is written: the file's and its modules', then those of every
/// enclosing block (handlers often `use vti_specs::…::v0_1 as t;` locally).
#[derive(Default)]
struct Sites {
    scopes: Vec<BTreeMap<String, String>>,
    /// Each parsed type as `(written, resolved)`; `None` for a site whose type
    /// the census could not read (a `parse_payload` with neither a turbofish
    /// nor a typed `let`), which fails the census.
    types: Vec<Option<(String, String)>>,
}

impl Sites {
    fn resolve(&self, segments: &[String]) -> String {
        let mut path: Vec<String> = segments.to_vec();
        // Follow aliases (`use spec::claim::v0_1 as t;` after
        // `use vti_specs::vta::collection as spec;`), innermost scope first.
        for _ in 0..8 {
            let Some(full) = self
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&path[0]))
            else {
                break;
            };
            let mut next: Vec<String> = full.split("::").map(str::to_string).collect();
            if next == path[..1] {
                break;
            }
            next.extend(path[1..].iter().cloned());
            path = next;
        }
        path.join("::")
    }

    fn record(&mut self, ty: Option<Vec<String>>) {
        let entry = ty.map(|segments| (segments.join("::"), self.resolve(&segments)));
        self.types.push(entry);
    }
}

fn uses_in(items: &[&Item]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for item in items {
        if let Item::Use(u) = item {
            collect_uses(&u.tree, &mut Vec::new(), &mut out);
        }
    }
    out
}

impl<'ast> Visit<'ast> for Sites {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.scopes
            .push(uses_in(&file.items.iter().collect::<Vec<_>>()));
        syn::visit::visit_file(self, file);
        self.scopes.pop();
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        // Test modules parse fixtures, not requests.
        if m.attrs.iter().any(|a| {
            a.path().is_ident("cfg")
                && matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string().contains("test"))
        }) {
            return;
        }
        let items: Vec<&Item> = m
            .content
            .as_ref()
            .map(|(_, items)| items.iter().collect())
            .unwrap_or_default();
        self.scopes.push(uses_in(&items));
        syn::visit::visit_item_mod(self, m);
        self.scopes.pop();
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let items: Vec<&Item> = block
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                syn::Stmt::Item(item) => Some(item),
                _ => None,
            })
            .collect();
        self.scopes.push(uses_in(&items));
        syn::visit::visit_block(self, block);
        self.scopes.pop();
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let Some(init) = &local.init
            && let Some(turbofish) = parse_call(&init.expr)
        {
            let declared = match &local.pat {
                Pat::Type(pt) => type_path(&pt.ty),
                _ => None,
            };
            self.record(turbofish.as_ref().and_then(type_path).or(declared));
            // Don't count the inner call again.
            return;
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // A call no typed `let` holds: its type is the turbofish, or one the
        // census cannot read (inferred from use), which fails it.
        if let Some(turbofish) = is_parse_payload(&Expr::Call(call.clone())) {
            self.record(turbofish.as_ref().and_then(type_path));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Every `(file, type)` parsed, with the type resolved through the file's
/// `use` items to the path it names.
fn census() -> (usize, Vec<(String, String, String)>) {
    let root = trust_tasks_dir();
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    let mut sites = 0;
    let mut found = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).expect("readable source file");
        let parsed = syn::parse_file(&text)
            .unwrap_or_else(|e| panic!("{}: does not parse: {e}", path.display()));
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        // The definition of `parse_payload`, and the test-only files.
        if rel == "helpers.rs" || rel.ends_with("_tests.rs") {
            continue;
        }
        let mut v = Sites::default();
        v.visit_file(&parsed);
        for ty in v.types {
            sites += 1;
            match ty {
                Some((written, resolved)) => found.push((rel.clone(), written, resolved)),
                None => found.push((rel.clone(), "<unreadable>".into(), String::new())),
            }
        }
    }
    (sites, found)
}

/// Modules outside `vti_specs` that only re-export its generated types.
const REEXPORTS_OF_GENERATED: &[&str] = &[
    "vta_sdk::specs::",
    "vta_sdk::protocols::backup_management::chunked::",
    // The framework's own specifications are generated in `trust_tasks_rs`
    // and are never pinned (root CLAUDE.md).
    "trust_tasks_rs::specs::trust_task_",
];

fn is_generated(resolved: &str) -> bool {
    resolved.starts_with("vti_specs::")
        || REEXPORTS_OF_GENERATED
            .iter()
            .any(|prefix| resolved.starts_with(prefix))
}

#[test]
fn every_parsed_payload_is_a_generated_type_or_baselined() {
    let (sites, found) = census();
    assert!(
        sites > 100,
        "the census found only {sites} parse sites — the walk has stopped finding \
         them, so a pass here would prove nothing"
    );
    let hand_written: BTreeSet<(String, String)> = found
        .iter()
        .filter(|(_, _, resolved)| !is_generated(resolved))
        .map(|(file, written, _)| (file.clone(), written.clone()))
        .collect();
    let baselined: BTreeSet<(String, String)> = BASELINE
        .iter()
        .map(|(f, t)| (f.to_string(), t.to_string()))
        .collect();
    let offenders: Vec<_> = hand_written.difference(&baselined).collect();
    assert!(
        offenders.is_empty(),
        "{} hand-written payload type(s) parsed by a Trust Task handler:\n{}\n\n\
         Read the generated `vti_specs` type for the task instead (root CLAUDE.md: \
         never hand-write a payload type for a task with a generated module). A task \
         no `vti-specs-*` crate pins is pinned first (`trust-tasks -C <crate> add`).",
        offenders.len(),
        offenders
            .iter()
            .map(|(f, t)| format!("  {f} :: {t}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let stale: Vec<_> = baselined.difference(&hand_written).collect();
    assert!(
        stale.is_empty(),
        "BASELINE names type(s) no handler parses any more: {stale:?}. Delete them and \
         lower BASELINE_COUNT."
    );
}

#[test]
fn the_baseline_only_shrinks() {
    assert_eq!(
        BASELINE.len(),
        BASELINE_COUNT,
        "BASELINE changed. Removed a migrated type? Lower BASELINE_COUNT with it. \
         Adding one is not the fix: parse the generated type."
    );
}
