//! Census: no workspace type derives `Debug` over a field holding secret
//! material.
//!
//! ## Why
//!
//! A derived `Debug` prints every field. On a type that holds a private key, a
//! seed or mnemonic, a bearer or refresh token, or a password, that puts the
//! secret into anything that formats the value — a `tracing` field, an
//! `unwrap` or `expect` on an enclosing type, a test failure, a panic message.
//! A credential that reaches a log has left, and nothing about `#[derive(Debug)]`
//! says so at the call site that formats it.
//!
//! When this census was written about 55 types across a dozen crates did
//! exactly that, found while `vtc-client` began holding an operator's key in a
//! `HolderKey` whose derived `Debug` printed it. The fix for each is a
//! hand-written `Debug` that reports the field as `<redacted>`, the idiom the
//! workspace already used where someone had thought of it
//! (`vta_sdk::protocols::backup_management::ExportRequest`). `Zeroizing<T>` is
//! **not** a redaction: its `Debug` prints the inner value.
//!
//! ## What counts
//!
//! A `#[derive(Debug)]` struct or enum with a field whose **name** says secret
//! and whose **type** holds raw material — `String`, `str`, bytes,
//! `Zeroizing<_>`, optionally in an `Option` or behind a reference. A field
//! whose type is another workspace type (`Vec<SecretEntry>`, `VaultSecret`) is
//! not flagged: its `Debug` is that type's, which this census checks where it
//! is defined.
//!
//! Names are matched loosely on purpose (`*_key`, `*token*`, `*secret*`,
//! `seed*`, `password`, `mnemonic`, …) and the usual non-secret shapes are
//! excluded (`public*`, `*_id`, `*_name`, `*_kid`, …). What is left and still
//! not a secret — a record's `key`, a webvh path called `mnemonic` — is listed
//! in [`NOT_SECRET`] with the reason, and that list only shrinks.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Attribute, Fields, GenericArgument, Item, Meta, PathArguments, Type};

/// Flagged fields that do not hold secret material, each with the reason.
///
/// `(file, type, field, reason)`. An entry is a claim about what the field
/// *holds*; "it is awkward to redact" is never one.
const NOT_SECRET: &[(&str, &str, &str, &str)] = &[
    (
        "vta-persona/src/claim_types.rs",
        "Entry",
        "token",
        "a claim-type vocabulary token, a public identifier",
    ),
    (
        "vta-persona/src/claim_types.rs",
        "ExtensionEntry",
        "token",
        "a claim-type vocabulary token, a public identifier",
    ),
    (
        "vta-persona/src/claim_types.rs",
        "ExtensionError",
        "token",
        "a claim-type vocabulary token, a public identifier",
    ),
    (
        "vta-persona/src/claim_types.rs",
        "RejectedEntry",
        "token",
        "a claim-type vocabulary token, a public identifier",
    ),
    (
        "vta-sdk/src/webvh.rs",
        "WebvhDidRecord",
        "mnemonic",
        "a webvh host's path label for the DID, not a BIP-39 phrase",
    ),
    (
        "vta-webvh/src/webvh_client.rs",
        "RequestUriResponse",
        "mnemonic",
        "a webvh host's path label for the DID, not a BIP-39 phrase",
    ),
    (
        "vta-webvh/src/webvh_client.rs",
        "HostedDidEntry",
        "mnemonic",
        "a webvh host's path label for the DID, not a BIP-39 phrase",
    ),
    (
        "vti-common/src/setup/secrets_prompt.rs",
        "SecretsBackendChoice",
        "secret_key",
        "the name of the entry in the secret store, not its value",
    ),
];

/// The size of [`NOT_SECRET`], asserted so the list cannot grow quietly.
const NOT_SECRET_COUNT: usize = 8;

/// Field names that are exactly one of these are record or index keys, not
/// key material.
const NOT_SECRET_EXACT: &[&str] = &[
    "key",
    "key_package",
    "key_agreement",
    "idempotency_key",
    "last_key",
    "record_key",
];

/// Words that, anywhere in a name, make it public material.
const NOT_SECRET_ANYWHERE: &[&str] = &["public", "pubkey"];

/// Suffixes that make a secret-sounding name something other than the secret.
const NOT_SECRET_SUFFIXES: &[&str] = &[
    "_id",
    "_ids",
    "_name",
    "_path",
    "_kind",
    "_count",
    "_field",
    "_at",
    "_url",
    "_did",
    "_type",
    "_ref",
    "_len",
    "_hash",
    "_hashes",
    "_fingerprint",
    "_label",
    "_algorithm",
    "_format",
    "_uri",
    "_kid",
    "_arn",
    "_salt",
    "_jti",
    "_origin",
    "_sha256",
    "_fp",
    "_digest",
];

const SECRET_WORDS: &[&str] = &[
    "private_key",
    "privkey",
    "secret",
    "secrets",
    "seed",
    "password",
    "passphrase",
    "mnemonic",
    "token",
    "jwt",
    "key",
];

/// Names that end like an identifier but are credentials: a Vault AppRole
/// `secret_id` is the password half of the login, and `*_id` would otherwise
/// excuse it.
const SECRET_DESPITE_SUFFIX: &[&str] = &["secret_id"];

fn names_a_secret(field: &str) -> bool {
    let f = field.to_ascii_lowercase();
    if NOT_SECRET_EXACT.contains(&f.as_str()) {
        return false;
    }
    if SECRET_DESPITE_SUFFIX.iter().any(|s| f.ends_with(s)) {
        return true;
    }
    if NOT_SECRET_ANYWHERE.iter().any(|w| f.contains(w))
        || NOT_SECRET_SUFFIXES.iter().any(|s| f.ends_with(s))
    {
        return false;
    }
    f.split('_').any(|part| SECRET_WORDS.contains(&part))
        || SECRET_WORDS
            .iter()
            .filter(|w| w.contains('_'))
            .any(|w| f.contains(w))
}

/// Does the type hold raw material, as opposed to another type with a
/// `Debug` of its own?
fn holds_raw(ty: &Type) -> bool {
    match ty {
        Type::Reference(r) => holds_raw(&r.elem),
        Type::Array(a) => holds_raw(&a.elem),
        Type::Slice(s) => holds_raw(&s.elem),
        Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return false;
            };
            let name = last.ident.to_string();
            match name.as_str() {
                "String" | "str" | "u8" => true,
                // Wrappers whose `Debug` shows what they wrap.
                "Option" | "Vec" | "Box" | "Zeroizing" | "Arc" | "Rc" => match &last.arguments {
                    PathArguments::AngleBracketed(args) => args.args.iter().any(|a| match a {
                        GenericArgument::Type(t) => holds_raw(t),
                        _ => false,
                    }),
                    _ => false,
                },
                _ => false,
            }
        }
        _ => false,
    }
}

fn derives_debug(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let tokens = match &attr.meta {
            Meta::List(list) if attr.path().is_ident("derive") => list.tokens.to_string(),
            Meta::List(list) if attr.path().is_ident("cfg_attr") => list.tokens.to_string(),
            _ => return false,
        };
        tokens
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|w| w == "Debug")
            && (attr.path().is_ident("derive") || tokens.contains("derive"))
    })
}

fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("test"))
    })
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Found {
    file: String,
    ty: String,
    field: String,
}

fn check_fields(fields: &Fields, file: &str, ty: &str, out: &mut Vec<Found>) {
    for field in fields.iter() {
        let Some(name) = field.ident.as_ref().map(|i| i.to_string()) else {
            continue;
        };
        if names_a_secret(&name) && holds_raw(&field.ty) {
            out.push(Found {
                file: file.to_string(),
                ty: ty.to_string(),
                field: name,
            });
        }
    }
}

fn walk(items: &[Item], file: &str, inspected: &mut usize, out: &mut Vec<Found>) {
    for item in items {
        match item {
            Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    walk(inner, file, inspected, out);
                }
            }
            Item::Struct(s) if !is_cfg_test(&s.attrs) && derives_debug(&s.attrs) => {
                *inspected += 1;
                check_fields(&s.fields, file, &s.ident.to_string(), out);
            }
            Item::Enum(e) if !is_cfg_test(&e.attrs) && derives_debug(&e.attrs) => {
                *inspected += 1;
                for variant in &e.variants {
                    check_fields(&variant.fields, file, &e.ident.to_string(), out);
                }
            }
            _ => {}
        }
    }
}

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
fn no_workspace_type_derives_debug_over_secret_material() {
    let (inspected, found) = census();
    assert!(
        inspected > 500,
        "the census inspected only {inspected} Debug-deriving types — the walk has \
         stopped finding them, so a pass here would prove nothing"
    );

    let mut matched_exceptions = Vec::new();
    let offenders: Vec<String> = found
        .iter()
        .filter(|f| {
            let excused = NOT_SECRET
                .iter()
                .any(|(file, ty, field, _)| *file == f.file && *ty == f.ty && *field == f.field);
            if excused {
                matched_exceptions.push((f.file.clone(), f.ty.clone(), f.field.clone()));
            }
            !excused
        })
        .map(|f| format!("  {} :: {}.{}", f.file, f.ty, f.field))
        .collect();

    assert!(
        offenders.is_empty(),
        "{} field(s) holding secret material sit in a type that derives `Debug`:\n\n{}\n\n\
         A derived `Debug` prints them into any log line, panic or test failure that \
         formats the value. Write the `Debug` by hand and report the field as \
         `<redacted>` — `Zeroizing` does not redact. If the field genuinely holds no \
         secret, add it to NOT_SECRET with what it holds.",
        offenders.len(),
        offenders.join("\n")
    );

    let stale: Vec<_> = NOT_SECRET
        .iter()
        .filter(|(file, ty, field, _)| {
            !matched_exceptions
                .iter()
                .any(|(f, t, fl)| f == file && t == ty && fl == field)
        })
        .map(|(file, ty, field, _)| format!("{file} :: {ty}.{field}"))
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_SECRET names field(s) the census no longer flags: {stale:?}. Delete them \
         and lower NOT_SECRET_COUNT."
    );
}

#[test]
fn the_not_secret_list_only_shrinks() {
    assert_eq!(
        NOT_SECRET.len(),
        NOT_SECRET_COUNT,
        "NOT_SECRET changed. Removing an entry? Lower NOT_SECRET_COUNT with it. Adding \
         one? It must say what the field holds, and a field holding a secret belongs \
         behind a hand-written Debug, not on this list."
    );
}

/// The name test, held on the cases that decided its shape.
#[test]
fn the_name_test_reads_names_the_way_a_reviewer_would() {
    for secret in [
        "private_key_multibase",
        "private_key",
        "access_token",
        "refresh_token",
        "token",
        "seed",
        "seed_hex",
        "mnemonic",
        "password",
        "agent_key",
        "signer_key_multibase",
        "jwt_signing_key",
        "ephemeral_signing_key",
        "claim_secret",
        "key_bundle_hex",
        "transport_token",
        "approle_secret_id",
        "vault_approle_secret_id",
        "agent_secrets",
        "jwt",
    ] {
        assert!(names_a_secret(secret), "{secret} names a secret");
    }
    for not in [
        "public_key_multibase",
        "key",
        "key_id",
        "signing_key_id",
        "secret_kind",
        "secret_count",
        "seed_id",
        "key_arn",
        "storage_key_salt",
        "key_agreement_kid",
        "install_token_jti",
        "idempotency_key",
        "password_field",
        "hpke_public_key",
        "key_agreement_public_x25519",
        "new_next_key_hashes",
        "token_origin",
    ] {
        assert!(!names_a_secret(not), "{not} does not name a secret");
    }
}
