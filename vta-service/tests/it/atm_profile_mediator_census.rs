//! Every `ATMProfile` this service builds must name a mediator.
//!
//! # What this is guarding
//!
//! `server::init_auth` used to build `ATMProfile::new(atm, "VTA", vta_did,
//! None)` and park it in `AppState`, on the reasoning that unsealing a TSP
//! envelope reads the decryption key from the ATM's secrets resolver and so
//! needs no route. The reasoning is wrong, and the profile could do nothing at
//! all: every TSP entry point in the messaging SDK resolves the mediator off the
//! profile handed to it. `TspOps::pack` and `unpack_bytes` call
//! `ATMProfile::dids()`; `send_raw` calls it alongside
//! `get_mediator_rest_endpoint()`. All three answer
//! `ConfigError("No Mediator is configured for this Profile")` without one.
//!
//! It sat there unnoticed because a mediator-less profile is *selectable*: it
//! has the right type, it registers on an ATM without complaint, and it fails
//! only when something asks it to do work. When the outbound seam gained the
//! ability to initiate over TSP it reached for the nearest profile-shaped thing
//! in `AppState`, and every TSP send this VTA attempted died inside the SDK
//! before a byte left the process — surfacing to an operator as
//! `trust task failed [internalError]`.
//!
//! # Why a census and not a type
//!
//! `messaging::tsp_transport::TspTransport` already refuses to exist around a
//! mediator-less profile, so nothing can *use* one through the supported path.
//! This catches the step before: constructing one at all, which is what puts a
//! plausible-looking dud somewhere a later reader can find it. The constructor
//! is foreign, so there is no place to put the check except here.
//!
//! A failure is not necessarily a bug — a genuinely mediator-less profile may
//! one day have a use. It is a claim that needs writing down, which is what the
//! allowlist below is for, and what the old comment never had to do.

use std::path::{Path, PathBuf};

/// Call sites permitted to pass `None`. Empty, and it should stay that way:
/// adding an entry is asserting that this particular profile is never handed to
/// `pack`, `unpack`, `unpack_bytes`, `send`, `send_raw` or any `send_*` variant,
/// which between them are most of what a profile is for.
const ALLOWED_MEDIATORLESS: &[&str] = &[];

#[test]
fn every_atm_profile_names_a_mediator() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();

    for file in rust_files(&src) {
        let text = std::fs::read_to_string(&file).expect("read source file");
        let rel = file
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap_or(&file)
            .display()
            .to_string();

        for (offset, args) in atm_profile_new_calls(&text) {
            // `ATMProfile::new(atm, alias, did, mediator)` — the mediator is the
            // fourth. A call with a different arity is a signature change, and
            // should fail loudly here rather than be silently skipped.
            assert_eq!(
                args.len(),
                4,
                "{rel}: ATMProfile::new took {} arguments, not 4 — this census reads the \
                 mediator as the fourth and needs updating alongside the signature",
                args.len(),
            );
            if args[3].trim() != "None" {
                continue;
            }
            let line = text[..offset].lines().count();
            let site = format!("{rel}:{line}");
            if ALLOWED_MEDIATORLESS.contains(&site.as_str()) {
                continue;
            }
            offenders.push(site);
        }
    }

    assert!(
        offenders.is_empty(),
        "these profiles are built with no mediator, and a profile with no mediator can neither \
         send nor unseal — the messaging SDK refuses every TSP operation on one with \
         `ConfigError(\"No Mediator is configured for this Profile\")`, before any I/O:\n  {}\n\
         Pass the mediator DID, or add the site to ALLOWED_MEDIATORLESS with a note saying what \
         the profile is for.",
        offenders.join("\n  "),
    );
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// Byte offset and top-level arguments of each `ATMProfile::new(...)` call.
///
/// A paren-matching scan rather than a regex: the calls are written across
/// several lines and the arguments nest (`Some(mediator_did.to_string())`), so
/// splitting on commas without tracking depth reads the wrong argument — which
/// for this census would mean reporting green while the defect is present.
fn atm_profile_new_calls(text: &str) -> Vec<(usize, Vec<String>)> {
    const NEEDLE: &str = "ATMProfile::new(";
    let bytes = text.as_bytes();
    let mut calls = Vec::new();
    let mut from = 0;

    while let Some(found) = text[from..].find(NEEDLE) {
        let open = from + found + NEEDLE.len();
        from = open;

        // Skip a doc-comment or `//` mention rather than parsing prose.
        let line_start = text[..open].rfind('\n').map_or(0, |i| i + 1);
        let prefix = text[line_start..open].trim_start();
        if prefix.starts_with("//") || prefix.starts_with("*") {
            continue;
        }

        let mut depth = 1usize;
        let mut args = Vec::new();
        let mut arg_start = open;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        args.push(text[arg_start..i].trim().to_string());
                        break;
                    }
                }
                b',' if depth == 1 => {
                    args.push(text[arg_start..i].trim().to_string());
                    arg_start = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        // A trailing comma leaves an empty final argument.
        if args.last().is_some_and(|a| a.is_empty()) {
            args.pop();
        }
        calls.push((open, args));
        from = i;
    }
    calls
}
