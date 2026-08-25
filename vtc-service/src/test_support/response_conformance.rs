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

/// Violations observed during a test run, for the harness to assert on.
///
/// Collected rather than panicked on inside the layer: a panic in middleware
/// surfaces as a transport error at the call site, which reads as "the request
/// failed" and hides what actually went wrong.
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

    check(&task, parts.status, &bytes);
    Response::from_parts(parts, Body::from(bytes))
}

/// The check itself, separated so it is unit-testable without a router.
fn check(task: &str, status: StatusCode, bytes: &Bytes) {
    // 204 and an empty body carry no payload to validate.
    if status == StatusCode::NO_CONTENT || bytes.is_empty() {
        return;
    }
    let Some(schema) = trust_tasks_rs::schema_index::schema_for(&format!("{task}#response")) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return;
    };
    // A Trust Task *document* carries its payload under `payload`; a bare REST
    // response is the payload itself. Validate whichever this is, so the layer
    // works across both bindings without the test having to say which.
    let payload = value.get("payload").unwrap_or(&value);
    if let Err(e) = trust_tasks_rs::validate::against_schema(schema, payload) {
        let msg = format!("{task}: {e}");
        // Printed as well as collected. A violation that only accumulates in a
        // static is invisible to `cargo test`, which is how a conformance
        // signal quietly stops being one.
        eprintln!("RESPONSE-CONFORMANCE VIOLATION  {msg}");
        violations().lock().expect("violations lock").push(msg);
    }
}
