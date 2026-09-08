//! Every Trust Task URI this service *names* is published, served, or listed
//! here as debt.
//!
//! ## The gap this closes
//!
//! Three harnesses already police the task surface, and a document can slip
//! between all three:
//!
//! - `UNSPECCED_DISPATCHED_URIS` (`trust_tasks/mod.rs`) is per-URI and
//!   shrink-only, but it tracks what this dispatcher **serves**.
//! - `producer_payload_conformance` drives client methods that build payloads
//!   by hand, but only ones reached through a `VtaClient` method.
//! - `vtc-service`'s manifest census scans source for URI literals, but its
//!   prefix is `https://trusttasks.org/openvtc/vtc/` — the VTC's private
//!   namespace — so a public `spec/` URI never matches it wherever it runs.
//!
//! `consent/approve-request/0.1` fell through all three. It is constructed
//! inline in `trust_tasks/consent.rs` and pushed to an approver's phone; it is
//! produced, never served, reached through no client method, and lives in the
//! public namespace. It shipped for as long as it did because **serving** an
//! unspecced URI fails the build while **producing** one was invisible.
//!
//! ## What this asserts
//!
//! A source scan, in the spirit of the VTC's census and for the same stated
//! reason: a string literal has no type-system backstop, so the only thing
//! that catches a new one is something that reads the source.
//!
//! Every `https://trusttasks.org/spec/...` literal under `vta-service/src`
//! must be one of:
//!
//! 1. **published** — `schema_index` resolves a schema for it, so the payload
//!    and response are validatable and a peer can implement against it;
//! 2. **served** — it appears in the dispatch table, where
//!    `UNSPECCED_DISPATCHED_URIS` already owns the debt and enforces its own
//!    monotonicity; or
//! 3. **listed in [`PRODUCED_UNPUBLISHED`]** below, with a reason.
//!
//! Anything else fails. The list is shrink-only in both directions, matching
//! the served-side harness: a new entry is a build failure rather than a line
//! someone adds, and a stale entry — one whose spec has since been published —
//! fails too, so publishing a spec cannot silently leave debt recorded.

#![cfg(test)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Produced URIs with no published spec, and why each is still here.
///
/// Not a waiver for the risk — an entry means a document goes out over the
/// wire with no schema on either side and no registry page a peer could
/// implement from. It means the gap is *known* rather than invisible, which is
/// the only thing this file can buy.
const PRODUCED_UNPUBLISHED: &[(&str, &str)] = &[
    (
        "https://trusttasks.org/spec/vta/attestation/status/1.0",
        "Found by this census on the day it was written, which is the case \
         for having it: REST-routed rather than dispatched, so the served-URI \
         harness never saw it. Unauthenticated and internet-reachable — the \
         thing a verifier checks *before* deciding to trust this VTA — and \
         the one surface here whose counterparty is not the operator. \
         Tracked in #1177.",
    ),
    (
        "https://trusttasks.org/spec/vta/attestation/report/1.0",
        "Same family and same route as `attestation/status/1.0`; publishing \
         one without the other leaves a verifier able to ask the question but \
         not read the answer. Tracked in #1177.",
    ),
];

/// URIs that appear as literals but are not documents this service produces.
///
/// Kept as an explicit list rather than a clever heuristic. A scan that tried
/// to infer "is this inside a test module" from source text would be wrong
/// occasionally and silently, and this census only works if a failure means
/// something.
const NOT_PRODUCED: &[(&str, &str)] = &[(
    "https://trusttasks.org/spec/does-not-exist/9.9",
    "Negative fixture: `class_for` must return `None` for an unknown URI, and \
         `method_not_found` must reject an unknown *family* as `unsupportedType` \
         rather than as a version skew. Deliberately names nothing.",
)];

/// Repo root, from this test binary's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vta-service has a parent directory")
        .to_path_buf()
}

/// Every `https://trusttasks.org/spec/...` **string literal** under `dir`.
///
/// Literals only: doc comments carry `{verb}`-style URI templates and prose
/// references, which are documentation rather than something that goes on the
/// wire. The same distinction the VTC census draws, and for the same reason —
/// counting prose produces false failures that train people to edit the
/// allowlist instead of reading it.
fn spec_uri_literals(dir: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source file");
                for (idx, _) in text.match_indices(PREFIX) {
                    if idx == 0 || !text[..idx].ends_with('"') {
                        continue;
                    }
                    let rest = &text[idx..];
                    let Some(end) = rest.find('"') else { continue };
                    // `.../foo/1.0#response` publishes under `.../foo/1.0`.
                    let uri = rest[..end].split('#').next().expect("split has a head");
                    // A trailing slash means this is a *prefix* constant built
                    // on at runtime (`TRUST_TASK_ERROR_PREFIX`), not a URI; a
                    // `{` means a `format!` template with the version
                    // interpolated. Neither is a URI that goes on a wire.
                    if uri.ends_with('/') || uri.contains('{') {
                        continue;
                    }
                    out.insert(uri.to_owned());
                }
            }
        }
    }
    let mut found = BTreeSet::new();
    walk(dir, &mut found);
    found
}

const PREFIX: &str = "https://trusttasks.org/spec/";

#[test]
fn every_produced_uri_is_published_or_tracked() {
    let root = workspace_root();
    let named = spec_uri_literals(&root.join("vta-service/src"));

    // Served URIs are the other harness's problem, and it is stricter than
    // this one. Derived from the dispatch table rather than re-listed, so the
    // two cannot disagree.
    let served: BTreeSet<String> = super::dispatched_uris()
        .into_iter()
        .map(str::to_owned)
        .collect();

    let tracked: BTreeSet<&str> = PRODUCED_UNPUBLISHED.iter().map(|(u, _)| *u).collect();

    let not_produced: BTreeSet<&str> = NOT_PRODUCED.iter().map(|(u, _)| *u).collect();

    let untracked: Vec<&String> = named
        .iter()
        .filter(|u| trust_tasks_rs::schema_index::schema_for(u).is_none())
        // The framework's own error envelope, not a task. It *is* in the
        // registry (`trust-task-error/0.1` … `/0.5`), but `schema_index`
        // carries payload schemas for tasks, so `schema_for` answers `None`
        // for it — using that as the published-check would report a published
        // document as debt.
        .filter(|u| !u.starts_with("https://trusttasks.org/spec/trust-task-error/"))
        .filter(|u| !served.contains(*u))
        .filter(|u| !tracked.contains(u.as_str()))
        .filter(|u| !not_produced.contains(u.as_str()))
        .collect();

    assert!(
        untracked.is_empty(),
        "these Trust Task URIs are produced by vta-service with no published \
         schema, and nothing tracks them:\n{}\n\nA produced document with no \
         spec has no validation on either side and no page a peer could \
         implement from. Publish the spec upstream, or — if it genuinely \
         cannot be published yet — add it to PRODUCED_UNPUBLISHED with the \
         reason and a tracking issue.",
        untracked
            .iter()
            .map(|u| format!("  {u}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The debt list shrinks. An entry whose spec has landed must go.
///
/// Without this the list is write-only: publishing a spec upstream leaves a
/// stale line claiming debt that no longer exists, and the next reader trusts
/// it. The served-side list carries the same guard for the same reason.
#[test]
fn no_tracked_entry_outlives_its_spec() {
    let published: Vec<&str> = PRODUCED_UNPUBLISHED
        .iter()
        .map(|(u, _)| *u)
        .filter(|u| trust_tasks_rs::schema_index::schema_for(u).is_some())
        .collect();

    assert!(
        published.is_empty(),
        "these have a published spec now and must be removed from \
         PRODUCED_UNPUBLISHED:\n{}",
        published
            .iter()
            .map(|u| format!("  {u}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every entry states a reason. A bare URI records that someone hit the
/// failure, not why the gap is acceptable.
#[test]
fn every_tracked_entry_states_why() {
    for (uri, reason) in PRODUCED_UNPUBLISHED.iter().chain(NOT_PRODUCED) {
        assert!(
            reason.len() > 40,
            "{uri}: the reason must say why this cannot be published yet and \
             where it is tracked"
        );
    }
}
/// Documents this service produces that a **person** is shown and asked to act
/// on, with the file that builds each.
///
/// The census above answers "is this URI published?". That is the half of
/// #1177 a schema can answer, and it is not the half that mattered: the
/// finding was a prompt reaching a human's phone *authenticated by nothing the
/// device could check*. A published schema would not have helped. A signature
/// is what lets the receiving device refuse a prompt that did not come from an
/// enrolled issuer, which is precisely the check
/// `vta-mobile-core::task::parse_step_up_request` already performs on the
/// comparable path.
///
/// So this is a second, narrower table, and membership is a judgement rather
/// than a fact a scan can derive: *does a human read this and tap something?*
/// Adding a produced URI here is a deliberate act. The cost of getting the
/// judgement wrong is asymmetric — a machine-to-machine document listed here
/// is over-protected, a human-facing one omitted is #1177 again — so when in
/// doubt, list it.
const RENDERED_TO_A_HUMAN: &[(&str, &str)] = &[(
    "https://trusttasks.org/spec/consent/approve-request/0.1",
    "vta-service/src/trust_tasks/consent.rs",
)];

/// What a signed prompt's construction site must contain.
///
/// `issuer` and `recipient` are not decoration: SPEC §7.2 item 5b makes
/// `recipient` REQUIRED and item 6 requires the in-band issuer to match the
/// transport identity, so a proof over a document naming neither party can be
/// lifted and replayed at a different approver. A signature over an unaddressed
/// document is a weaker thing than it looks.
const SIGNING_MARKERS: &[&str] = &["DataIntegrityProof::sign", "\"issuer\"", "\"recipient\""];

/// A prompt a person is asked to approve must be signed, and addressed.
///
/// **This is a source scan and it proves less than it looks like it proves.**
/// It cannot show that the signature covers the right bytes, that the key
/// belongs to the agent, or that the failure arm does not send the document
/// anyway. What it does is make the *absence* of signing visible at the place
/// it would be missing, which is the whole of what went wrong in #1177: nothing
/// anywhere objected to a prompt with no proof on it.
///
/// It would have failed before that fix — `consent.rs` built four members and
/// signed nothing — and it fails again the day someone adds a second prompt the
/// same way. That is the property worth having; the stronger checks belong to
/// the device that receives the document, which is the one party that can
/// actually refuse it.
#[test]
fn a_prompt_a_person_answers_is_signed_and_addressed() {
    let root = workspace_root();
    for (uri, file) in RENDERED_TO_A_HUMAN {
        let path = root.join(file);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("`{file}` is named by RENDERED_TO_A_HUMAN but cannot be read: {e}")
        });
        for marker in SIGNING_MARKERS {
            assert!(
                text.contains(marker),
                "`{uri}` is shown to a person and answered by them, but `{file}` \
                 does not contain `{marker}`. A prompt that reaches a phone \
                 authenticated by nothing the device can check is #1177; if this \
                 document moved, move its entry in RENDERED_TO_A_HUMAN with it."
            );
        }
    }
}

/// The table names URIs this service actually produces, and keeps naming them.
///
/// Shrink-only in the same sense as the lists above: an entry whose URI has
/// left the source is a line nobody is maintaining, and one that stays behind
/// after the document it describes was deleted reads as coverage that is not
/// there.
#[test]
fn every_human_facing_entry_still_names_a_produced_uri() {
    let root = workspace_root();
    let named = spec_uri_literals(&root.join("vta-service/src"));
    for (uri, file) in RENDERED_TO_A_HUMAN {
        assert!(
            named.contains(*uri),
            "RENDERED_TO_A_HUMAN lists `{uri}` (in `{file}`), but no source \
             literal under `vta-service/src` names it any more. Remove the \
             entry, or restore the document it was guarding."
        );
    }
}
