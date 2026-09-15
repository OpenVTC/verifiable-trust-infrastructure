//! Every TSP send in this crate puts the binding envelope on the wire.
//!
//! ## Why a census rather than a behavioural test
//!
//! The defect this guards against is an *omission*, and an omission has no
//! behaviour to assert on. When `send_document` sealed the bare document, every
//! test in the workspace still passed: `tsp_round_trip` and `tsp_dual_leg` send
//! and receive through this crate, so a private dialect round-trips against
//! itself perfectly. Only a peer — the VTA — could tell, and it told us in a
//! deployment log rather than in CI.
//!
//! `tests/e2e/tests/tsp_binding_pair.rs` closes that for the paths it drives.
//! This closes it for the ones nobody has driven yet: a *new* send site, added
//! later, that forgets the wrapper. It is deliberately dumb — it counts calls in
//! source text — because the thing it is protecting is a one-line habit, and a
//! clever check would be one more thing to keep working.
//!
//! Source-text census, so it is feature-independent: gating this on `tsp` would
//! make it dead in exactly the default build CI runs (see CLAUDE.md, "the CI
//! Test job feature set").

use std::fs;
use std::path::{Path, PathBuf};

/// Files allowed to send a TSP frame without the binding envelope, and why.
///
/// Exactly one peer on the TSP wire does not speak the binding: the
/// **mediator's own management surface**. Its TSP arm parses the bare document
/// and claims it only when the type is one it serves
/// (`affinidi-messaging-mediator`'s `trust_tasks::parse_if_served`), so it has
/// no envelope to open and would file a wrapped frame as ordinary mail — the
/// account ACL silently not applied.
///
/// This list is not a place to put a send that is merely inconvenient to wrap.
/// It records peers that cannot read the binding. Adding a line means naming
/// such a peer.
const BARE_DOCUMENT_PEERS: &[(&str, &str)] = &[(
    "acl_setup.rs",
    "addressed to the mediator's management surface, which parses the bare \
     document (affinidi-messaging-mediator `trust_tasks::parse_if_served`)",
)];

/// The upstream calls that put bytes on the TSP wire.
///
/// `.tsp().send(` is spelled out rather than matched as a bare `.send(`, which
/// every HTTP and DIDComm path in this crate would also hit. The cost of that
/// precision is that a *new* send method on the TSP transport is invisible
/// here — which is why `finds_every_tsp_transport_call` exists below: it fails
/// when a file touches `atm.tsp()` in a way this list does not account for,
/// rather than letting the census quietly stop covering it.
const TSP_SEND_CALLS: &[&str] = &[".send_routed(", ".send_anycast(", ".tsp().send("];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Count occurrences of `needle`, ignoring lines that are comments or doc
/// comments — a call named in prose is not a call.
fn count_code(source: &str, needle: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter(|line| line.contains(needle))
        .count()
}

/// The census is only as good as its list of send calls, and that list is the
/// part most likely to go stale — the transport gains a method, a call site is
/// rephrased, and `every_tsp_send_…` keeps passing over a file it no longer
/// reads. So: every file that reaches the TSP transport at all must be one the
/// send census accounted for.
#[test]
fn finds_every_tsp_transport_call() {
    let mut sources = Vec::new();
    rust_sources(Path::new("src"), &mut sources);

    let mut unaccounted = Vec::new();
    for path in sources {
        let source = fs::read_to_string(&path).expect("read source");
        // `.tsp()` on its own is also how a *receive* path reaches the
        // transport (`unpack`, `unpack_bytes`), which the send census rightly
        // ignores. Only a file with neither a known send nor a known receive is
        // unaccounted for.
        let touches = count_code(&source, ".tsp()");
        if touches == 0 {
            continue;
        }
        let accounted: usize = TSP_SEND_CALLS
            .iter()
            .chain([".unpack(", ".unpack_bytes(", ".is_tsp("].iter())
            .map(|call| count_code(&source, call))
            .sum();
        if accounted == 0 {
            unaccounted.push(path.display().to_string());
        }
    }

    assert!(
        unaccounted.is_empty(),
        "these files reach the TSP transport in a way the binding census does \
         not recognise, so it is not checking them. Add the call to \
         TSP_SEND_CALLS (if it sends) and make sure the file wraps:\n  {}",
        unaccounted.join("\n  ")
    );
}

#[test]
fn every_tsp_send_wraps_the_document_in_the_binding_envelope() {
    let mut sources = Vec::new();
    rust_sources(Path::new("src"), &mut sources);

    let mut failures = Vec::new();
    let mut sends_seen = 0usize;

    for path in sources {
        let source = fs::read_to_string(&path).expect("read source");
        let sends: usize = TSP_SEND_CALLS
            .iter()
            .map(|call| count_code(&source, call))
            .sum();
        if sends == 0 {
            continue;
        }
        sends_seen += sends;

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if let Some((_, reason)) = BARE_DOCUMENT_PEERS.iter().find(|(f, _)| *f == name) {
            assert!(
                count_code(&source, "wrap_envelope") == 0,
                "{name} is listed as a bare-document peer ({reason}) but wraps its \
                 sends — if that peer now speaks the binding, remove it from \
                 BARE_DOCUMENT_PEERS instead of leaving the list lying"
            );
            continue;
        }

        let wraps = count_code(&source, "wrap_envelope");
        if wraps < sends {
            failures.push(format!(
                "  {}: {sends} TSP send(s), {wraps} wrap_envelope call(s)",
                path.display()
            ));
        }
    }

    assert!(
        sends_seen > 0,
        "this census found no TSP sends at all — the call names in TSP_SEND_CALLS \
         have drifted and the guard is now vacuous"
    );
    assert!(
        failures.is_empty(),
        "a TSP send is putting a bare Trust-Task document on the wire. A \
         conformant peer refuses it as `not a binding envelope` and the symptom \
         is a request that never gets a reply — nothing looks broken here. Wrap \
         the document with `crate::tsp_binding::wrap_envelope` before \
         `send_routed`, or (only if the recipient cannot read the binding) add \
         the file to BARE_DOCUMENT_PEERS with the reason:\n{}",
        failures.join("\n")
    );
}
