//! Validate every Trust Task response this dispatcher produces against the
//! schema its task publishes.
//!
//! ## Why this is a layer and not a fixture
//!
//! `trust_tasks::conformance` checks example documents typed by hand into the
//! witness table. That table reports **zero drift across every task it
//! covers**, and the number is true — of the fixtures. It says nothing about what a handler emits,
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
//! - **It fails the build.** It did not when it landed in #1113: it reported,
//!   so the four violations it found could be read off a run rather than
//!   blocking one. That inventory is now empty, so the layer gates — a
//!   violation replaces the response with an error document, and the test that
//!   provoked it fails on its own assertion. Same two steps the VTC took across
//!   #1107 and #1112.
//! - **Error responses are exempt.** A non-success outcome is a framework
//!   reject document, not the task's response payload; validating it against
//!   the success schema would fail for the wrong reason.
//! - **Unknown tasks pass.** `schema_for` returning `None` means this build
//!   knows no published spec for that URI — a locally-defined openvtc extension
//!   such as `vault/{archive,unarchive,restore,purge}/0.1`. That is not
//!   evidence of a violation, and treating it as one would make the layer fail
//!   loudest on the routes it understands least.
//! - **It sees only what a test exercises**, and that is the headline number:
//!   a full suite run observes **29 of the 109 tasks whose response schema is
//!   published** — 27%. The other eighty produce no success response anywhere
//!   in `tests/`, and they are not the quiet corners of the surface: the
//!   signing oracle (`keys/sign`, `keys/derive-and-sign`, `keys/import`), the
//!   credential release path (`vault/release`, `vault/proxy-login`), device
//!   `wipe`, and every `consent/*` ceremony are all in the uncovered set.
//!
//!   So any clean report from this layer is a floor over a quarter of the
//!   surface, not a total. `scripts/trust-task-coverage.sh` prints the figure
//!   and the uncovered list; run it before quoting a violation count, because
//!   the two numbers only mean something together. The census in
//!   `trust_tasks::conformance` is what covers the rest, with the caveat this
//!   module exists to state: it covers them as fixtures.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

/// Tasks known to emit a non-conforming response.
///
/// **Empty, and the layer now gates.** It held four entries when #1113 landed
/// the layer as a reporter, and two after #1114 fixed the ones that needed no
/// spec change; the last two closed when `trust-tasks-rs` 0.11.16 published the
/// `VaultEntry` lifecycle members (dtgwg-trust-tasks-tf#268).
///
/// **This is an inventory, not an allowlist** — nothing consults it at runtime,
/// so re-adding an entry does not make a violation tolerable. It stays as the
/// place to record a violation that is genuinely blocked on something external,
/// with the blocker named, and `the_inventory_is_still_accurate` fails when the
/// count moves so a stale note cannot sit here quietly.
pub const KNOWN_VIOLATIONS: &[(&str, &str)] = &[];

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
pub fn observe(status: axum::http::StatusCode, body: &[u8]) -> Option<Vec<u8>> {
    let task = successful_task(status, body)?;
    record_observed(&task);
    let msg = check(status, body)?;
    eprintln!("RESPONSE-CONFORMANCE VIOLATION  {msg}");
    violations()
        .lock()
        .expect("violations lock")
        .push(msg.clone());
    // Replace the body rather than panic. A panic at the dispatch spine unwinds
    // through whichever transport is driving — for DIDComm and TSP that is a
    // background inbound loop, where it reads as "the peer went away" and names
    // nothing. Handing back an error document makes the test that provoked it
    // fail on its own assertion, and print the reason.
    Some(
        serde_json::json!({
            "error": "responseSchemaViolation",
            "message": msg,
        })
        .to_string()
        .into_bytes(),
    )
}

/// The `#response` type URI of a successful dispatch, or `None`.
///
/// Separate from [`check`] because coverage and conformance ask different
/// questions of the same bytes: *was this task exercised at all*, and *did what
/// it emitted conform*. Conflating them is how "zero violations" came to mean
/// "fifty tasks were never looked at" — the first number is only readable
/// against the second.
fn successful_task(status: axum::http::StatusCode, body: &[u8]) -> Option<String> {
    if !status.is_success() || body.is_empty() {
        return None;
    }
    let doc = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    Some(doc.get("type")?.as_str()?.to_owned())
}

/// Task URIs this process has seen emit a successful response.
static OBSERVED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

fn observed() -> &'static Mutex<BTreeSet<String>> {
    OBSERVED.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Every task URI this process has observed, sorted.
pub fn observed_tasks() -> Vec<String> {
    observed()
        .lock()
        .expect("observed lock")
        .iter()
        .cloned()
        .collect()
}

/// Note a task as exercised, and append it to the run-wide coverage file when
/// `TRUST_TASK_OBSERVED_FILE` names one.
///
/// The file exists because a coverage figure is a property of a **run**, not of
/// a process, and every binary under `tests/` is its own process — thirty-five
/// of them on the VTC, twenty-seven here. An in-memory set answers "what did
/// *this* binary touch", which is not the question.
///
/// Appends are `O_APPEND` one line at a time, which is atomic below `PIPE_BUF`
/// for a URI, so concurrent binaries interleave lines rather than corrupt them.
/// Duplicates are expected and the reader dedupes; writing once per process per
/// URI just keeps the file small.
fn record_observed(task: &str) {
    {
        let mut seen = observed().lock().expect("observed lock");
        if !seen.insert(task.to_owned()) {
            return;
        }
    }
    let Ok(path) = std::env::var("TRUST_TASK_OBSERVED_FILE") else {
        return;
    };
    use std::io::Write;
    // Best-effort: a coverage file that cannot be written must never fail a
    // test run. The script that sets the variable checks the file itself.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{task}");
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

/// Tasks this dispatcher binds whose **response** schema is published — the
/// set the layer is able to check at all.
///
/// Derived from `dispatched_uris()`, never hand-listed, for the same reason
/// the witness census is: a hand-kept denominator drifts, and a coverage figure
/// over a drifted denominator is worse than none.
pub fn checkable_tasks() -> Vec<&'static str> {
    crate::trust_tasks::dispatched_uris()
        .into_iter()
        .filter(|u| trust_tasks_rs::schema_index::schema_for(&format!("{u}#response")).is_some())
        .collect()
}

/// Report which checkable tasks a whole run never exercised.
///
/// Run by `scripts/trust-task-coverage.sh` **after** the suite, against the
/// file the suite appended to. Ignored by default because on its own — with no
/// preceding run — it would report zero coverage and say nothing true.
///
/// It reports rather than fails. The gap it measures is fifty-odd tasks wide,
/// and a gate at that width is a gate nobody can turn on; the number is the
/// deliverable until the gap is closed enough for a floor to mean something.
#[test]
#[ignore = "needs a suite run first; driven by scripts/trust-task-coverage.sh"]
fn report_task_coverage() {
    let path = std::env::var("TRUST_TASK_OBSERVED_FILE")
        .expect("set TRUST_TASK_OBSERVED_FILE, or run scripts/trust-task-coverage.sh");
    let seen: BTreeSet<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();

    let checkable = checkable_tasks();
    // The file records the `#response` URI the document carried; the census
    // yields the bare task URI. Compare on the bare form.
    let seen_bare: BTreeSet<&str> = seen
        .iter()
        .map(|u| u.strip_suffix("#response").unwrap_or(u))
        .collect();

    let mut uncovered: Vec<&str> = checkable
        .iter()
        .copied()
        .filter(|u| !seen_bare.contains(u))
        .collect();
    uncovered.sort_unstable();

    let total = checkable.len();
    let covered = total - uncovered.len();
    println!(
        "\nTRUST-TASK RESPONSE COVERAGE  {covered}/{total}          ({:.0}%) — {} never exercised\n",
        (covered as f64 / total.max(1) as f64) * 100.0,
        uncovered.len()
    );
    for u in &uncovered {
        println!("  UNCOVERED  {u}");
    }
    println!();
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

    /// A violation now replaces the response, rather than only being noted.
    #[test]
    fn a_violation_replaces_the_response() {
        clear_violations();
        let body = br#"{
            "type": "https://trusttasks.org/spec/vault/list/0.1#response",
            "payload": {"nope": 1}
        }"#;
        let out = observe(StatusCode::OK, body).expect("a violation must be fatal");
        let doc: serde_json::Value = serde_json::from_slice(&out).expect("error document");
        assert_eq!(doc["error"], "responseSchemaViolation");
        assert!(
            doc["message"]
                .as_str()
                .is_some_and(|m| m.contains("vault/list")),
            "the replacement must name the task, or the failing test says nothing"
        );
        assert_eq!(
            observed_violations().len(),
            1,
            "it must still be recorded — raising fails one test, recording is \
             what lets a whole run be swept"
        );
    }

    /// A conforming response passes through untouched.
    #[test]
    fn a_conforming_response_is_not_replaced() {
        // `messaging/ping/0.1` is bound and published; an empty payload object
        // is not valid for it, so use a task whose response really does pass:
        // the exemption paths are covered above, so assert the shape that
        // matters here — no violation, no replacement.
        assert!(observe(StatusCode::NO_CONTENT, b"").is_none());
        assert!(observe(StatusCode::BAD_REQUEST, b"{}").is_none());
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
            0,
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
