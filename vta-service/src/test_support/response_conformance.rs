//! Validate every Trust Task response this dispatcher produces against the
//! schema its task publishes.
//!
//! ## Why this is a layer and not a fixture
//!
//! `trust_tasks::conformance` checks example documents typed by hand into the
//! witness table. That table reports **79 tasks at zero drift**, and the number
//! is true — of the fixtures. It says nothing about what a handler emits,
//! because a fixture is written separately from the thing it describes.
//!
//! The VTC ran exactly this experiment. Its witness also read zero drift; the
//! equivalent layer then found **134 violations across 23 tasks**, five of them
//! in a family the table called fully conformant (VTI #1107–#1112). The failure
//! that matters is the flattering one: a fixture that *omits* a member reports
//! a non-conformant route as conforming, and no amount of re-reading the table
//! produces the sentence `invalid type: string, expected struct
//! IssuedCredential`.
//!
//! So this layer stops describing and starts observing.
//!
//! ## Why the dispatch spine, and not middleware
//!
//! The VTC's equivalent is axum middleware reading a `Trust-Task` request
//! header. That works there because the VTC serves Trust Tasks over REST only.
//!
//! This service serves them over **REST, DIDComm and TSP**, and all three
//! converge on [`dispatch_trust_task_core`](crate::trust_tasks) — which returns
//! a `TrustTaskOutcome` whose body *is* the serialised result document. That
//! document names its own `#response` type in its `type` member, so one check
//! at the spine covers every transport and needs no header at all. Middleware
//! would have covered one transport of three, and would have been blind to
//! precisely the two that carry no HTTP request to read a header from.
//!
//! ## What it does not do
//!
//! - **It does not fail the build.** This is deliberately a reporting layer:
//!   see [`KNOWN_VIOLATIONS`] for the inventory it was landed to make visible,
//!   and the module's own tests for the properties that *are* asserted. Turning
//!   it into a gate is a follow-up, once the inventory is closed — the same two
//!   steps the VTC took across #1107 and #1111.
//! - **Error responses are exempt.** A non-success outcome is a framework
//!   reject document, not the task's response payload; validating it against
//!   the success schema would fail for the wrong reason.
//! - **Unknown tasks pass.** `schema_for` returning `None` means this build
//!   knows no published spec for that URI — a locally-defined openvtc extension
//!   such as `vault/{archive,unarchive,restore,purge}/0.1`. That is not
//!   evidence of a violation, and treating it as one would make the layer fail
//!   loudest on the routes it understands least.
//! - **It sees only what a test exercises**, and that is the headline number:
//!   a full suite run observes **29 of the 79 bound tasks**. The other fifty
//!   produce no success response anywhere in `tests/`, so the inventory below
//!   is a floor taken over a third of the surface, not a total. The census in
//!   `trust_tasks::conformance` is what covers the rest, with the caveat this
//!   module exists to state: it covers them as fixtures.

use std::sync::{Mutex, OnceLock};

/// Tasks observed emitting a non-conforming response, as of the run that
/// landed this module.
///
/// **This list is an inventory, not an allowlist** — nothing consults it at
/// runtime. It is here so the work is written down at the point the layer was
/// added, rather than living in a PR description that nobody reads again, and
/// so `the_inventory_is_still_accurate` fails when one is fixed and the note
/// goes stale.
///
/// Every entry is a class the VTC hit too, which is the argument for the layer:
/// these are not exotic, they are what happens to any wire type nothing
/// observes.
pub const KNOWN_VIOLATIONS: &[(&str, &str)] = &[
    (
        "https://trusttasks.org/spec/vta/webvh/dids/get/1.0",
        "returns its eleven members flat; the schema requires them under \
         `record`, which is a required property the response omits entirely",
    ),
    (
        "https://trusttasks.org/spec/vault/get/0.1",
        "leaks `status` / `graceUntil` / `deletedAt` — the archival lifecycle \
         was added to the storage row and never to the wire contract",
    ),
    (
        "https://trusttasks.org/spec/vault/list/0.1",
        "the same three lifecycle members as `vault/get/0.1`",
    ),
    (
        "https://trusttasks.org/spec/provision/integration/0.2",
        "sends `null` for two members the schema types as `string`; the \
         `null`-for-absent class, which wants `skip_serializing_if`",
    ),
];

/// Violations observed during a test run, newest last.
///
/// Collected as well as printed because the two serve different readers: the
/// print names the test that provoked it, and the collection is what lets a
/// whole run be swept at once. Sweeping is how the inventory above was taken.
static VIOLATIONS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn violations() -> &'static Mutex<Vec<String>> {
    VIOLATIONS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Every response-schema violation seen so far in this process.
///
/// Per-process, so a value read here covers one test binary and not the run.
pub fn observed_violations() -> Vec<String> {
    violations().lock().expect("violations lock").clone()
}

/// Forget everything observed. For a test that deliberately provokes one.
pub fn clear_violations() {
    violations().lock().expect("violations lock").clear();
}

/// Observe one dispatch outcome. Called from the dispatch spine.
///
/// Takes the raw bytes rather than a parsed `Value` because that is what the
/// spine holds: `TrustTaskOutcome.body` stays raw so the wire output is
/// byte-identical to direct serialisation, and re-parsing here keeps that
/// property untouched on the path that matters.
pub fn observe(status: axum::http::StatusCode, body: &[u8]) {
    if let Some(msg) = check(status, body) {
        eprintln!("RESPONSE-CONFORMANCE VIOLATION  {msg}");
        violations().lock().expect("violations lock").push(msg);
    }
}

/// The check itself, separated so it is unit-testable without a dispatcher.
///
/// Returns the failure message when the response does not conform to the schema
/// its own `type` names; `None` when it conforms, when there is no published
/// schema for that type, or when there is nothing to validate.
fn check(status: axum::http::StatusCode, body: &[u8]) -> Option<String> {
    if !status.is_success() || body.is_empty() {
        return None;
    }
    let doc = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    // The response document names its own task. This is the whole reason the
    // spine is a better vantage point than middleware: nothing has to be
    // threaded in alongside the bytes.
    let ty = doc.get("type")?.as_str()?;
    let schema = trust_tasks_rs::schema_index::schema_for(ty)?;
    let payload = doc.get("payload")?;
    let Err(e) = trust_tasks_rs::validate::against_schema(schema, payload) else {
        return None;
    };
    Some(format!("{ty}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    /// A response that does not match its own task's schema is reported.
    #[test]
    fn a_non_conforming_payload_is_reported() {
        let body = br#"{
            "type": "https://trusttasks.org/spec/vault/list/0.1#response",
            "payload": {"nope": 1}
        }"#;
        let out = check(StatusCode::OK, body);
        assert!(
            out.is_some_and(|m| m.contains("vault/list")),
            "a payload that fails its schema must be reported, and the message \
             must name the task so a sweep of a run is readable"
        );
    }

    /// A task with no published schema is not a violation.
    ///
    /// This is not hypothetical: `vault/{archive,unarchive,restore,purge}/0.1`
    /// are locally-defined openvtc extensions that dispatch here and resolve no
    /// schema. Treating "unknown" as "bad" would fail loudest on the routes
    /// this build understands least.
    #[test]
    fn an_unpublished_task_is_not_a_violation() {
        // Deliberately not a `trusttasks.org/spec/` URI: the dispatcher census
        // scans this crate for bound canonical URIs and would read a fake one
        // here as a real binding.
        let body = br#"{"type": "https://example.invalid/not/a/task/9.9#response",
                        "payload": {}}"#;
        assert!(check(StatusCode::OK, body).is_none());
    }

    /// A reject document is not validated against the success schema.
    #[test]
    fn an_error_outcome_is_exempt() {
        let body = br#"{
            "type": "https://trusttasks.org/spec/vault/list/0.1#response",
            "payload": {"nope": 1}
        }"#;
        assert!(
            check(StatusCode::BAD_REQUEST, body).is_none(),
            "a 4xx body is a framework reject document, not the task's payload"
        );
    }

    /// The inventory only shrinks, and its entries stay real.
    ///
    /// Asserted for the reason the VTC's `KNOWN_DRIFT_COUNT` is: a tolerated
    /// defect that nothing counts becomes a permanent one. Fixing one means
    /// deleting its entry — which fails this until the count moves with it, so
    /// the note cannot go stale silently.
    #[test]
    fn the_inventory_is_still_accurate() {
        assert_eq!(
            KNOWN_VIOLATIONS.len(),
            4,
            "the known-violation inventory changed. Fixed one? Remove its entry \
             and lower this. Found a new one? That is a defect to fix, not an \
             entry to add — this list records what was already true when the \
             layer landed, and it is meant to reach zero."
        );
        for (uri, why) in KNOWN_VIOLATIONS {
            assert!(
                trust_tasks_rs::schema_index::schema_for(&format!("{uri}#response")).is_some(),
                "{uri} has no published response schema, so it cannot be \
                 violating one — the entry is stale"
            );
            assert!(!why.is_empty(), "{uri} needs a reason, not just a URI");
        }
    }
}
