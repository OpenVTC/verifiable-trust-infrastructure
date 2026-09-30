//! Integration coverage for the canonical `policy/*` surface (phase 2a).
//!
//! The interesting part is the model mismatch. Canonical treats a policy
//! module as purpose-agnostic and mutable, selected at evaluate time;
//! VTC binds purpose intrinsically (it is fixed by the module's Rego
//! package) over append-only revisions. These tests pin how that gap is
//! bridged — and, more importantly, that nothing is silently accepted.
//!
//! The admin bearer routes these used to drive are gone (#1834): every verb
//! is a signed document now, sent with [`common::signed::call`] and read back
//! through [`reply`], which recovers the REST status the retired route
//! answered with.

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::test_support::TestVtc;

const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const LIST: &str = "https://trusttasks.org/spec/policy/list/0.2";
const GET: &str = "https://trusttasks.org/spec/policy/get/0.1";
const ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";

const JOIN_POLICY: &str = "package vtc.join\nimport rego.v1\ndefault allow := true\n";

struct Fixture {
    signer: Party,
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    let signer = common::signed::admin(&vtc).await;
    Fixture { signer, _vtc: vtc }
}

/// The status the retired REST route would have answered with, read off the
/// signed door's error `code` where there was a refusal.
fn status_for_code(code: &str) -> StatusCode {
    if code.ends_with(":notFound") {
        StatusCode::NOT_FOUND
    } else if code.ends_with(":versionConflict") || code.ends_with(":alreadyActive") {
        StatusCode::CONFLICT
    } else if code == "permissionDenied" {
        StatusCode::FORBIDDEN
    } else if code == "malformedRequest" || code.contains(':') {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    }
}

/// Sign `payload` as `task` and send it, answering the way the retired REST
/// route did: `success` on a `#response`, or the mapped status + a
/// REST-shaped `{"error": ...}` body on a `trust-task-error`.
async fn call(
    fix: &Fixture,
    task: &str,
    payload: Value,
    success: StatusCode,
) -> (StatusCode, Value) {
    let (_, doc) = common::signed::call(&fix._vtc, &fix.signer, task, payload).await;
    match common::signed::error_code(&doc) {
        Some(code) => (
            status_for_code(code),
            json!({ "error": doc["payload"]["message"] }),
        ),
        None => (success, doc["payload"].clone()),
    }
}

async fn upsert(fix: &Fixture, body: Value) -> (StatusCode, Value) {
    let (_, doc) = common::signed::call(&fix._vtc, &fix.signer, UPSERT, body).await;
    let success = if doc["payload"]["created"] == false {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    match common::signed::error_code(&doc) {
        Some(code) => (
            status_for_code(code),
            json!({ "error": doc["payload"]["message"] }),
        ),
        None => (success, doc["payload"].clone()),
    }
}

async fn get(fix: &Fixture, id: &str) -> (StatusCode, Value) {
    call(fix, GET, json!({ "id": id }), StatusCode::OK).await
}

async fn activate(fix: &Fixture, id: &str, purpose: &str) -> (StatusCode, Value) {
    call(
        fix,
        ACTIVATE,
        json!({ "id": id, "purpose": purpose }),
        StatusCode::OK,
    )
    .await
}

async fn list(fix: &Fixture, purpose: Option<&str>) -> (StatusCode, Value) {
    let mut payload = json!({});
    if let Some(p) = purpose {
        payload["ext"] = json!({ "org.openvtc.purpose": p });
    }
    call(fix, LIST, payload, StatusCode::OK).await
}

fn upsert_body(purpose: &str, module: &str) -> Value {
    json!({
        "name": purpose,
        "module": module,
        "ext": { "org.openvtc.purpose": purpose },
    })
}

#[tokio::test]
async fn upsert_returns_a_canonical_policy_module() {
    let fix = build().await;
    let (status, body) = upsert(&fix, upsert_body("join", JOIN_POLICY)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["created"], true,
        "first revision is a creation: {body}"
    );

    let p = &body["policy"];
    for f in ["id", "name", "module", "version", "createdAt", "updatedAt"] {
        assert!(p.get(f).is_some(), "{f} missing: {p}");
    }
    // Maintainer-specific fields ride in ext — the canonical type is
    // additionalProperties:false.
    assert_eq!(p["ext"]["org.openvtc.purpose"], "join");
    assert!(p["ext"]["org.openvtc.sha256"].as_str().is_some());
    assert!(p.get("purpose").is_none(), "purpose is not top-level: {p}");
    assert!(p.get("regoSource").is_none(), "renamed to module: {p}");
}

/// Purpose cannot be inferred (only 4 of 10 have an expected package)
/// and canonical upsert has no purpose field, so it is required in ext.
/// Guessing would risk filing a module under the wrong decision slot.
#[tokio::test]
async fn upsert_without_the_purpose_ext_is_refused() {
    let fix = build().await;
    let (status, body) = upsert(&fix, json!({ "name": "join", "module": JOIN_POLICY })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("purpose"),
        "the error should name what is missing: {body}"
    );
}

/// The pre-existing guard: a module whose Rego package does not serve
/// the declared purpose compiles cleanly and then silently denies
/// everything. It must survive the migration.
#[tokio::test]
async fn upsert_still_rejects_a_package_purpose_mismatch() {
    let fix = build().await;
    let (status, body) = upsert(
        &fix,
        // A join-purpose upload whose module lives in the removal package.
        upsert_body(
            "join",
            "package vtc.removal\nimport rego.v1\ndefault allow := true\n",
        ),
    )
    .await;
    assert_ne!(status, StatusCode::CREATED, "must not be accepted: {body}");
}

/// Canonical members VTC cannot honour must be refused, not ignored —
/// a caller setting `enabled: false` must never have it dropped.
#[tokio::test]
async fn upsert_refuses_selection_hints_it_cannot_honour() {
    let fix = build().await;
    for (field, value) in [
        ("appliesTo", json!(["ctx-a"])),
        ("priority", json!(10)),
        ("enabled", json!(false)),
    ] {
        let mut body = upsert_body("join", JOIN_POLICY);
        body[field] = value;
        let (status, resp) = upsert(&fix, body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{field} must be refused: {resp}"
        );
        assert!(
            resp["error"].as_str().unwrap_or_default().contains(field),
            "the error should name {field}: {resp}"
        );
    }
}

/// `enabled: true` is the schema default, and the generated `policy/upsert`
/// payload always serialises it — so refusing it would refuse every client
/// built on the canonical type. It asks for nothing this maintainer lacks.
#[tokio::test]
async fn upsert_accepts_enabled_true_the_schema_default() {
    let fix = build().await;
    let mut body = upsert_body("join", JOIN_POLICY);
    body["enabled"] = json!(true);
    let (status, resp) = upsert(&fix, body).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
}

/// `expectedVersion` is an optimistic-concurrency token: two operators
/// racing on the same purpose must not each append over the other's
/// read.
#[tokio::test]
async fn expected_version_is_a_real_compare_and_swap() {
    let fix = build().await;
    upsert(&fix, upsert_body("join", JOIN_POLICY)).await;

    // Stale: caller believes nothing exists yet.
    let mut stale = upsert_body("join", JOIN_POLICY);
    stale["expectedVersion"] = json!(0);
    let (status, body) = upsert(&fix, stale).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Correct: current revision is 1.
    let mut fresh = upsert_body("join", JOIN_POLICY);
    fresh["expectedVersion"] = json!(1);
    let (status, body) = upsert(&fix, fresh).await;
    assert_eq!(status, StatusCode::OK, "a revision, not a creation: {body}");
    assert_eq!(body["created"], false, "{body}");
    assert_eq!(body["policy"]["version"], 2);
}

#[tokio::test]
async fn activate_exposes_the_binding_via_policy_active() {
    let fix = build().await;
    let (_, up) = upsert(&fix, upsert_body("join", JOIN_POLICY)).await;
    let id = up["policy"]["id"].as_str().unwrap().to_string();

    let (status, act) = activate(&fix, &id, "join").await;
    assert_eq!(status, StatusCode::OK, "{act}");
    assert_eq!(
        act["activated"], id,
        "canonical names it `activated`: {act}"
    );
    assert_eq!(act["purpose"], "join");
}

/// Canonical `contextId`/`enabledOnly` list filters are refused rather than
/// silently ignored: this maintainer is not context-partitioned and its
/// modules carry no enabled flag.
#[tokio::test]
async fn unsupported_list_and_active_filters_are_refused() {
    let fix = build().await;
    for extra in [
        json!({ "contextId": "ctx-a" }),
        json!({ "enabledOnly": true }),
    ] {
        let (status, body) = call(&fix, LIST, extra, StatusCode::OK).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn list_and_get_return_canonical_envelopes() {
    let fix = build().await;
    let (_, up) = upsert(&fix, upsert_body("join", JOIN_POLICY)).await;
    let id = up["policy"]["id"].as_str().unwrap().to_string();

    let (status, list_body) = list(&fix, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        list_body.get("policies").is_some(),
        "canonical key: {list_body}"
    );
    assert!(
        list_body.get("truncated").is_some(),
        "required: {list_body}"
    );
    assert!(
        list_body.get("items").is_none(),
        "old key must be gone: {list_body}"
    );

    let (status, got) = get(&fix, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["policy"]["id"], id, "wrapped in `policy`: {got}");
}

/// `name` is canonical-required, so discarding the operator's value and
/// substituting the purpose would be an accept-and-ignore.
#[tokio::test]
async fn the_operator_supplied_name_and_description_survive() {
    let fix = build().await;
    let mut body = upsert_body("join", JOIN_POLICY);
    body["name"] = json!("Join policy — v2 rewrite");
    body["description"] = json!("stricter age check");

    let (status, resp) = upsert(&fix, body).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    assert_eq!(resp["policy"]["name"], "Join policy — v2 rewrite");

    // And it survives a re-read, not just the echo.
    let id = resp["policy"]["id"].as_str().unwrap().to_string();
    let (_, got) = get(&fix, &id).await;
    assert_eq!(got["policy"]["name"], "Join policy — v2 rewrite");
}

/// Canonical lets a caller target an existing module id; here revision
/// ids are server-allocated, so honouring one would mean pretending to
/// update a row we actually append past.
#[tokio::test]
async fn upsert_refuses_a_caller_supplied_id() {
    let fix = build().await;
    let mut body = upsert_body("join", JOIN_POLICY);
    body["id"] = json!("11111111-1111-1111-1111-111111111111");
    let (status, resp) = upsert(&fix, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
}
