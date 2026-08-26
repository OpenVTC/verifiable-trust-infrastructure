//! Validate every response an integration test provokes against the schema
//! its Trust Task publishes.
//!
//! ## Why this is a layer and not a fixture
//!
//! `trust_tasks::conformance` checks example documents that are typed by hand
//! into the witness table. That is a *proxy* for what a handler emits, and the
//! proxy drifted three separate ways in one week:
//!
//! - **stale** — `endorsements/revoke` described a `{id}` response six PRs
//!   after the handler had stopped sending one;
//! - **inventing** — a wrapper fixture carried a `totalEstimate` no producer
//!   in the workspace ever sets;
//! - **omitting** — the community-profile fixture left out `personhood`, and
//!   that one reported *two non-conformant routes as conforming*.
//!
//! The last is the failure that matters. A fixture can only be wrong in the
//! flattering direction if it is written separately from the thing it
//! describes, so the fix is to stop describing and start observing: this layer
//! reads the `Trust-Task` header the test already sends, looks up that task's
//! `#response` schema, and validates the bytes the handler actually produced.
//!
//! It sits in `test_support` rather than in each test file because every
//! binary under `tests/` is its own crate with its own `send` helper — thirty-
//! five of them. One layer at the single point where those routers are built
//! covers all of them, and cannot be forgotten by the next test that is added.
//!
//! ## What it does not do
//!
//! - **Error responses are exempt.** A 4xx/5xx body is a framework error
//!   document, not the task's response payload; validating it against the
//!   success schema would fail for the wrong reason.
//! - **Unknown tasks pass.** `schema_for` returning `None` means this build
//!   knows no spec for that URI — an unpublished or locally-served route. It
//!   is not evidence of a violation, and treating it as one would make the
//!   layer fail loudest on the routes it understands least.
//! - **It sees only what a test exercises.** A route with no integration test
//!   gets no coverage here, which is exactly how `endorsements/show` and
//!   `ceremonies/list` drifted. The census in
//!   `trust_tasks::conformance` is what covers the rest.

use std::sync::{Mutex, OnceLock};

use axum::body::{Body, Bytes};
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;

/// Tasks whose responses are known not to conform, and may not fail the build
/// yet.
///
/// **This list may only shrink.** It is the same discipline as
/// `KNOWN_DRIFT_COUNT` in `trust_tasks::conformance`, for the same reason: a
/// tolerated defect that nothing counts becomes a permanent one. Every entry
/// names a task and why it is still here, and
/// `the_allowlist_only_shrinks` fails if the count goes up.
///
/// **The list is empty.** Every route this suite exercises now conforms to the
/// schema its task publishes, so the layer is an unconditional gate rather than
/// a report with exceptions. The machinery stays because the discipline is the
/// point: a task that starts failing must be *fixed*, and if it genuinely
/// cannot be, adding it back here is a visible decision that shows up in a
/// diff — not a silent one.
const ALLOWED: &[&str] = &[];

/// The number of allowlisted tasks, asserted so the list cannot grow quietly.
pub const ALLOWED_COUNT: usize = 0;

/// Violations observed during a test run, for the harness to assert on.
///
/// Collected rather than panicked on inside the layer: a panic in middleware
/// surfaces as a transport error at the call site, which reads as "the request
/// failed" and hides what actually went wrong. The failure is raised at the
/// end of the request instead, as a `500` carrying the reason, so the test
/// that provoked it is the test that fails.
static VIOLATIONS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn violations() -> &'static Mutex<Vec<String>> {
    VIOLATIONS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Every response-schema violation seen so far, newest last.
pub fn observed_violations() -> Vec<String> {
    violations().lock().expect("violations lock").clone()
}

/// Forget everything observed. For a test that deliberately provokes a
/// violation and wants a clean slate afterwards.
pub fn clear_violations() {
    violations().lock().expect("violations lock").clear();
}

/// Axum middleware: validate a success response against its task's published
/// `#response` schema.
pub async fn validate_response(req: Request<Body>, next: Next) -> Response<Body> {
    let task = req
        .headers()
        .get("trust-task")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let res = next.run(req).await;

    let Some(task) = task else { return res };
    if !res.status().is_success() {
        return res;
    }

    let (parts, body) = res.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };

    match check(&task, parts.status, &bytes) {
        None => Response::from_parts(parts, Body::from(bytes)),
        // Replace the response rather than panic. A panic in middleware
        // surfaces at the call site as a transport error — "the request
        // failed" — which says nothing about why. A 500 carrying the schema
        // error makes the test that provoked it fail on its own status
        // assertion, and print the reason.
        Some(msg) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "responseSchemaViolation",
                    "message": msg,
                })
                .to_string(),
            ))
            .expect("static response builds"),
    }
}

/// The check itself, separated so it is unit-testable without a router.
///
/// Returns the failure message when the response does not conform **and** the
/// task is not allowlisted; `None` otherwise.
fn check(task: &str, status: StatusCode, bytes: &Bytes) -> Option<String> {
    // 204 and an empty body carry no payload to validate.
    if status == StatusCode::NO_CONTENT || bytes.is_empty() {
        return None;
    }
    let schema = trust_tasks_rs::schema_index::schema_for(&format!("{task}#response"))?;
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    // A Trust Task *document* carries its payload under `payload`; a bare REST
    // response is the payload itself. Validate whichever this is, so the layer
    // works across both bindings without the test having to say which.
    let payload = value.get("payload").unwrap_or(&value);
    let Err(e) = trust_tasks_rs::validate::against_schema(schema, payload) else {
        return None;
    };
    let msg = format!("{task}: {e}");
    eprintln!("RESPONSE-CONFORMANCE VIOLATION  {msg}");
    violations()
        .lock()
        .expect("violations lock")
        .push(msg.clone());
    if ALLOWED.contains(&task) {
        return None;
    }
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allowlist may only shrink.
    ///
    /// Asserted for the same reason `KNOWN_DRIFT_COUNT` is: a tolerated defect
    /// that nothing counts becomes a permanent one, and the cheapest way to
    /// make a failing check pass is to add a line to a list nobody is
    /// watching. Closing an entry means deleting it *and* lowering this.
    #[test]
    fn the_allowlist_only_shrinks() {
        assert_eq!(
            ALLOWED.len(),
            ALLOWED_COUNT,
            "the response-conformance allowlist changed. Removing a task? \
             Lower ALLOWED_COUNT with it. Adding one? That needs a reason in \
             review, not a quiet edit — a route whose response does not match \
             its published schema is a defect, and this list exists to record \
             the ones already known, not to absorb new ones."
        );
    }

    /// A violation is *recorded* as well as raised.
    ///
    /// The two are separate on purpose. Raising fails the one test that
    /// provoked it; recording is what lets a run be swept for every violation
    /// at once, which is how the original inventory of 134 was taken. If the
    /// allowlist ever gains an entry again, that entry is reported and not
    /// raised — recording is the half that keeps it visible.
    #[test]
    fn a_violation_is_recorded_as_well_as_raised() {
        clear_violations();
        let out = check(
            "https://trusttasks.org/spec/auth/whoami/0.1",
            StatusCode::OK,
            &Bytes::from_static(b"{\"nope\":1}"),
        );
        assert!(
            out.is_some(),
            "a non-allowlisted violation must fail the build"
        );
        assert_eq!(
            observed_violations().len(),
            1,
            "it must also be recorded, or a run cannot be swept for all of them"
        );
    }

    /// A task with no published schema is not a violation. Treating "unknown"
    /// as "bad" would fail loudest on the routes this build understands least.
    #[test]
    fn an_unknown_task_is_not_a_violation() {
        assert!(
            check(
                // Deliberately not a `trusttasks.org/spec/` URI:
                // `every_bound_canonical_task_exists_in_the_registry` scans
                // this crate for bound canonical URIs and would read a fake
                // one here as a real binding — which it did, on the first
                // run of this test.
                "https://example.invalid/not/a/task/9.9",
                StatusCode::OK,
                &Bytes::from_static(b"{}"),
            )
            .is_none()
        );
    }
}
