//! Census: every Trust-Task call site whose decode type is **private to the
//! client** must be covered by `trust_task_decode.rs`.
//!
//! ## The invariant
//!
//! `rpc_tt` sends a Trust Task and deserializes the agent's reply. When the type
//! it deserializes into is the *same* type the agent serializes, the two ends
//! cannot disagree: any change moves both at once. When it is a **separate**
//! struct describing the same wire, either end can move alone — and then the
//! command fails in the field, not in CI.
//!
//! So: a client-private decode type is allowed, but only if the seam test
//! actually drives the agent's body into it.
//!
//! ## Why a census rather than more cases
//!
//! #1033 was this defect. #1000 folded the agent's payloads to lowerCamelCase
//! and excluded `client/types.rs` as "REST bodies"; the exclusion was drawn by
//! file path and the path was stale, so the agent moved to `basePath` while
//! `ContextResponse` went on demanding `base_path`. Every `pnm contexts`
//! command, four `pnm keys` commands, seed rotate/list and the MCP surface
//! failed against any current agent.
//!
//! The audit that followed found the split is total: of 61 call sites, the 50
//! that decode a shared `protocols::**` type were all fine, and all 11 with a
//! private type in `client/types.rs` were broken. The correlation is the point.
//!
//! `trust_task_decode.rs` fixed the eleven. It cannot stop the twelfth, because
//! it is a list someone has to remember to extend — and the whole failure mode
//! here is a change that looks unrelated to a list. This file makes forgetting a
//! compile-time-adjacent failure instead of a production one.
//!
//! The real repair is to collapse each pair onto one type (#1035), after which
//! [`COVERED_BY_SEAM_TEST`] empties and this census keeps it empty.
//!
//! ## Scope and method
//!
//! Every `rpc_tt` call under `vta-sdk/src/client/`. `rpc_tt_void` is excluded —
//! it decodes nothing, so it has no seam to drift.
//!
//! Parsed with `syn`, not grepped, for the same reason as
//! [`payload_null_census`](../payload_null_census.rs): return types wrap across
//! lines, and a line-oriented regex misreads that in the direction that lets a
//! violation through.

#![cfg(feature = "client")]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use syn::{ImplItem, Item, ReturnType, Type};

/// Decode types that are private to the client, each covered by a case in
/// `trust_task_decode.rs`.
///
/// An entry here is a statement that this type is a **second struct for a wire
/// the agent already has a type for** — a known hazard held safe by a test, not
/// a design. Adding one is allowed; adding one without the matching seam case is
/// what this census refuses.
///
/// Every name here should disappear as #1035 collapses the pairs.
const COVERED_BY_SEAM_TEST: &[&str] = &[
    // The ACL pair is the one place two types is the right answer:
    // `AclEntryResponse` renames `subject`→`did` and `scopes`→`allowed_contexts`
    // and converts RFC 3339 to epoch seconds, so it cannot simply re-export the
    // agent's `AclEntry`. An adapter carrying real logic can be wrong in ways a
    // mirror cannot, which is why it is checked rather than reasoned about.
    "AclListResponse",
];

// The eight names that used to sit above — ContextResponse, ContextListResponse,
// SignResponse, RenameKeyResponse, InvalidateKeyResponse, GetKeySecretResponse,
// RotateSeedResponse, ListSeedsResponse — are gone because the types are gone.
// #1035 replaced each with a `pub use` of the agent's own body, so they are no
// longer defined under `src/client/` and this census no longer classifies them
// as private. That is the intended end state: the list shrinks as the duplicates
// are removed, rather than growing as they are papered over.

/// Client-private types that are nonetheless safe, each with the reason.
///
/// "Defined in `client/`" is the census's proxy for "the agent does not
/// serialize this type", and these are the places the proxy over-reports. Each
/// entry is a claim that drift is *impossible*, not merely unobserved — the
/// weaker claim is what [`COVERED_BY_SEAM_TEST`] is for.
const CLIENT_PRIVATE_BUT_SAFE: &[(&str, &str)] = &[
    (
        "ConfigResponse",
        "`#[serde(flatten)]` over the agent's own GetConfigResultBody; declares \
         no fields of its own, so there is nothing to spell differently",
    ),
    (
        "GetDidLogResponse",
        "only single-word members (`did`, `log`) — no casing difference is \
         expressible",
    ),
    (
        "ListKeysResponse",
        "`keys` + `total` are single-word; the nested KeyRecord is shared with \
         the agent and camelCase on both sides",
    ),
    (
        "AclEntryEnvelope",
        "`pub(crate)` `{ entry }` wrapper — its one member is single-word, so \
         the envelope itself cannot drift. What it wraps is covered by \
         trust_task_decode.rs::acl_entry_decodes",
    ),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn client_dir() -> PathBuf {
    src_dir().join("client")
}

/// Names of types **defined under `src/client/`**.
///
/// This is the census's operative question. A decode type defined here is the
/// client's own struct for a wire the agent describes with a different one, so
/// the two can move independently. A decode type defined anywhere else in the
/// crate is a type the agent serializes directly — `protocols::**` bodies,
/// `webvh::WebvhDidRecord`, and so on — and cannot drift against itself.
///
/// Derived rather than listed, so a type that *moves* into or out of `client/`
/// is reclassified automatically. Hand-listing the shared side was the first
/// attempt and would have meant ~40 names to maintain, which is its own way of
/// going stale.
fn client_private_types() -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_sources(&client_dir(), &mut files);

    let mut names = BTreeSet::new();
    for path in files {
        let src = fs::read_to_string(&path).expect("client source is readable");
        let ast = syn::parse_file(&src).expect("client source parses");
        for item in ast.items {
            match item {
                Item::Struct(s) => {
                    names.insert(s.ident.to_string());
                }
                Item::Enum(e) => {
                    names.insert(e.ident.to_string());
                }
                _ => {}
            }
        }
    }
    names
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("client/ is readable") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The `T` of a `Result<T, VtaError>` return, rendered as its final path
/// segment.
///
/// The last segment is what matters: `context_management::create::Foo` and a
/// bare `Foo` are the same type to this census, and comparing full paths would
/// make the allow-lists depend on how each call site happened to import.
fn ok_type_name(sig: &syn::Signature) -> Option<String> {
    let ReturnType::Type(_, ty) = &sig.output else {
        return None;
    };
    let Type::Path(tp) = &**ty else { return None };
    let last = tp.path.segments.last()?;
    if last.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    let syn::GenericArgument::Type(ok) = args.args.first()? else {
        return None;
    };
    match ok {
        // `rpc_tt_void` — nothing decoded, nothing to drift.
        Type::Tuple(t) if t.elems.is_empty() => None,
        Type::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
        _ => None,
    }
}

/// Finds a real `self.rpc_tt(..)` call anywhere inside a method body.
///
/// A visitor rather than a search over the body's tokens: the call sits inside
/// `match` arms and behind `?`, and a token search would also match the name
/// where it appears in a comment or a doc link — of which this client has
/// several, since `rpc_tt` is the thing its docs keep explaining.
///
/// `rpc_tt_void` decodes nothing, so it has no seam and is deliberately not
/// matched.
#[derive(Default)]
struct FindRpcTt {
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for FindRpcTt {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "rpc_tt" {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn expr_calls_rpc_tt(expr: &syn::Expr) -> bool {
    let mut v = FindRpcTt::default();
    syn::visit::Visit::visit_expr(&mut v, expr);
    v.found
}

fn calls_rpc_tt(item: &ImplItem) -> bool {
    let ImplItem::Fn(f) = item else { return false };
    let mut v = FindRpcTt::default();
    syn::visit::Visit::visit_block(&mut v, &f.block);
    v.found
}

/// The types a method *deserializes into*, taken from annotated `let` bindings
/// whose initializer contains the `rpc_tt` call.
///
/// This is the distinction the first draft of this census got wrong. Several
/// methods decode the **agent's** body into a local and then map it field by
/// field into a friendlier client-side shape:
///
/// ```ignore
/// let wrapped: protocols::key_management::create::CreateKeyResponseBody =
///     self.rpc_tt(..).await?;
/// Ok(CreateKeyResponse { key_id: wrapped.key.key_id, .. })
/// ```
///
/// Reading the *return* type there reports `CreateKeyResponse` and asks for a
/// seam case that would prove nothing: the decode is against the shared type,
/// and the mapping is checked by the compiler — change the agent's struct and
/// this stops building. The hazard is only where the client's own type is what
/// `serde` is handed.
struct DecodeTypes {
    found: Vec<String>,
}

impl<'ast> syn::visit::Visit<'ast> for DecodeTypes {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init
            && expr_calls_rpc_tt(&init.expr)
            && let syn::Pat::Type(pt) = &node.pat
            && let Type::Path(p) = &*pt.ty
            && let Some(last) = p.path.segments.last()
        {
            self.found.push(last.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }
}

/// Collect `(method, decode type)` for every `rpc_tt` call site in the client.
fn decode_targets() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_sources(&client_dir(), &mut files);
    files.sort();

    let mut found = Vec::new();
    for path in files {
        let src = fs::read_to_string(&path).expect("client source is readable");
        let ast = syn::parse_file(&src).expect("client source parses");
        for item in ast.items {
            let Item::Impl(imp) = item else { continue };
            for sub in &imp.items {
                if !calls_rpc_tt(sub) {
                    continue;
                }
                let ImplItem::Fn(f) = sub else { continue };
                let method = f.sig.ident.to_string();

                // An annotated `let` is the authoritative answer: it is literally
                // the type handed to serde. Only when there is none does the
                // reply flow straight out of the method, making the return type
                // the decode type.
                let mut annotated = DecodeTypes { found: Vec::new() };
                syn::visit::Visit::visit_block(&mut annotated, &f.block);

                if annotated.found.is_empty() {
                    if let Some(ty) = ok_type_name(&f.sig) {
                        found.push((method, ty));
                    }
                } else {
                    for ty in annotated.found {
                        found.push((method.clone(), ty));
                    }
                }
            }
        }
    }
    found
}

/// Every client-private decode type is exercised by the seam test.
///
/// The failure text names the specific repair, because the instinct on seeing
/// this red is to add the type to the allow-list — which is exactly the move
/// that reopens #1033.
#[test]
fn every_client_private_decode_type_has_a_seam_case() {
    let private = client_private_types();
    let accounted: BTreeSet<&str> = COVERED_BY_SEAM_TEST
        .iter()
        .copied()
        .chain(CLIENT_PRIVATE_BUT_SAFE.iter().map(|(ty, _)| *ty))
        .collect();

    let mut unclassified: Vec<String> = decode_targets()
        .into_iter()
        // Only types the client defines itself can drift against the agent.
        .filter(|(_, ty)| private.contains(ty.as_str()))
        .filter(|(_, ty)| !accounted.contains(ty.as_str()))
        .map(|(m, ty)| format!("  {m} -> {ty}"))
        .collect();
    unclassified.sort();
    unclassified.dedup();

    assert!(
        unclassified.is_empty(),
        "these Trust-Task call sites decode a type the client defines itself, with \
         nothing checking it against what the agent sends:\n{}\n\n\
         A client-private decode type is a SECOND struct for a wire the agent already \
         types, so the two ends can move apart. Do one of:\n\
         \n\
         - Decode the agent's own type instead (best — see #1035). Nothing to list.\n\
         - Add a case to tests/trust_task_decode.rs that serializes the AGENT's body \
           into this type, then name it in COVERED_BY_SEAM_TEST.\n\
         - If drift is genuinely impossible — only single-word members, or a flatten \
           wrapper over the agent's body — add it to CLIENT_PRIVATE_BUT_SAFE with that \
           reason.\n\
         \n\
         Reach for the last one only if it is actually true. \"These are just the REST \
         bodies, nothing pins their casing\" was said about client/types.rs in #1000, \
         and it broke every `pnm contexts` command in the field.",
        unclassified.join("\n")
    );
}

/// Each name in [`COVERED_BY_SEAM_TEST`] really appears in the seam test.
///
/// Without this the allow-list is only a promise: a type could be listed as
/// covered while its case was deleted, renamed, or never written, and the census
/// above would still pass. Cheap to check, and it is the half that makes the
/// other half mean anything.
#[test]
fn the_seam_test_covers_what_the_allow_list_claims() {
    let seam = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("trust_task_decode.rs"),
    )
    .expect("trust_task_decode.rs is readable");

    let missing: Vec<&str> = COVERED_BY_SEAM_TEST
        .iter()
        .copied()
        .filter(|ty| !seam.contains(ty))
        .collect();

    assert!(
        missing.is_empty(),
        "COVERED_BY_SEAM_TEST claims these are covered, but they do not appear in \
         tests/trust_task_decode.rs:\n  {}\n\n\
         Either write the case, or — if the pair was collapsed onto one type \
         (#1035) — drop the name from the list and move it to SHARED_WITH_AGENT.",
        missing.join("\n  ")
    );
}

/// The census sees a realistic number of call sites.
///
/// A refactor that renamed `rpc_tt`, moved the client, or changed the return
/// shape would leave both tests above passing over an empty set — green because
/// nothing was examined. #1033's own root cause was a check that had quietly
/// stopped covering its subject, so this file states its floor out loud.
#[test]
fn the_census_is_not_scanning_an_empty_set() {
    let found = decode_targets();
    assert!(
        found.len() >= 40,
        "only {} rpc_tt call sites found; the audit for #1033 counted 55. \
         Something moved and this census is now looking at almost nothing — \
         fix the walk, do not lower this floor.",
        found.len()
    );
}
