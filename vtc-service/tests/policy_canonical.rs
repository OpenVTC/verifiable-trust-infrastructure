//! Integration coverage for the canonical `policy/*` surface (phase 2a).
//!
//! The interesting part is the model mismatch. Canonical treats a policy
//! module as purpose-agnostic and mutable, selected at evaluate time;
//! VTC binds purpose intrinsically (it is fixed by the module's Rego
//! package) over append-only revisions. These tests pin how that gap is
//! bridged — and, more importantly, that nothing is silently accepted.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vtc_service::test_support::TestVtc;

const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const LIST: &str = "https://trusttasks.org/spec/policy/list/0.2";
const GET: &str = "https://trusttasks.org/spec/policy/get/0.1";
const ACTIVE: &str = "https://trusttasks.org/spec/policy/active/0.1";
const ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";

const JOIN_POLICY: &str = "package vtc.join\nimport rego.v1\ndefault allow := true\n";

struct Fixture {
    router: axum::Router,
    token: String,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    let token = vtc.token("did:key:z6MkAdmin", "admin", vec![]).await;
    Fixture {
        router: vtc.router.clone(),
        token,
    }
}

async fn call(
    fix: &Fixture,
    method: &str,
    uri: &str,
    task: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {}", fix.token));
    if body.is_some() {
        b = b.header("Content-Type", "application/json");
    }
    let req = b
        .body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
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
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/policies",
        UPSERT,
        Some(upsert_body("join", JOIN_POLICY)),
    )
    .await;
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
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/policies",
        UPSERT,
        Some(json!({ "name": "join", "module": JOIN_POLICY })),
    )
    .await;
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
    let (status, body) = call(
        &fix,
        "POST",
        "/v1/policies",
        UPSERT,
        // A join-purpose upload whose module lives in the removal package.
        Some(upsert_body(
            "join",
            "package vtc.removal\nimport rego.v1\ndefault allow := true\n",
        )),
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
        let (status, resp) = call(&fix, "POST", "/v1/policies", UPSERT, Some(body)).await;
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

/// `expectedVersion` is an optimistic-concurrency token: two operators
/// racing on the same purpose must not each append over the other's
/// read.
#[tokio::test]
async fn expected_version_is_a_real_compare_and_swap() {
    let fix = build().await;
    call(
        &fix,
        "POST",
        "/v1/policies",
        UPSERT,
        Some(upsert_body("join", JOIN_POLICY)),
    )
    .await;

    // Stale: caller believes nothing exists yet.
    let mut stale = upsert_body("join", JOIN_POLICY);
    stale["expectedVersion"] = json!(0);
    let (status, body) = call(&fix, "POST", "/v1/policies", UPSERT, Some(stale)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Correct: current revision is 1.
    let mut fresh = upsert_body("join", JOIN_POLICY);
    fresh["expectedVersion"] = json!(1);
    let (status, body) = call(&fix, "POST", "/v1/policies", UPSERT, Some(fresh)).await;
    assert_eq!(status, StatusCode::OK, "a revision, not a creation: {body}");
    assert_eq!(body["created"], false, "{body}");
    assert_eq!(body["policy"]["version"], 2);
}

#[tokio::test]
async fn activate_exposes_the_binding_via_policy_active() {
    let fix = build().await;
    let (_, up) = call(
        &fix,
        "POST",
        "/v1/policies",
        UPSERT,
        Some(upsert_body("join", JOIN_POLICY)),
    )
    .await;
    let id = up["policy"]["id"].as_str().unwrap().to_string();

    let (status, act) = call(
        &fix,
        "POST",
        &format!("/v1/policies/{id}/activate"),
        ACTIVATE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{act}");
    assert_eq!(
        act["activated"], id,
        "canonical names it `activated`: {act}"
    );
    assert_eq!(act["purpose"], "join");

    // The binding is now readable as a canonical ActiveBinding.
    let (status, body) = call(&fix, "GET", "/v1/policies/active", ACTIVE, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let b = body["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["purpose"] == "join")
        .expect("join binding");
    assert_eq!(b["policy"]["id"], id);
}

#[tokio::test]
async fn unsupported_list_and_active_filters_are_refused() {
    let fix = build().await;
    for (uri, task) in [
        ("/v1/policies?contextId=ctx-a", LIST),
        ("/v1/policies?enabledOnly=true", LIST),
        ("/v1/policies/active?contextId=ctx-a", ACTIVE),
    ] {
        let (status, body) = call(&fix, "GET", uri, task, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
    }
}

#[tokio::test]
async fn list_and_get_return_canonical_envelopes() {
    let fix = build().await;
    let (_, up) = call(
        &fix,
        "POST",
        "/v1/policies",
        UPSERT,
        Some(upsert_body("join", JOIN_POLICY)),
    )
    .await;
    let id = up["policy"]["id"].as_str().unwrap().to_string();

    let (status, list) = call(&fix, "GET", "/v1/policies", LIST, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.get("policies").is_some(), "canonical key: {list}");
    assert!(list.get("truncated").is_some(), "required: {list}");
    assert!(list.get("items").is_none(), "old key must be gone: {list}");

    let (status, got) = call(&fix, "GET", &format!("/v1/policies/{id}"), GET, None).await;
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

    let (status, resp) = call(&fix, "POST", "/v1/policies", UPSERT, Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    assert_eq!(resp["policy"]["name"], "Join policy — v2 rewrite");

    // And it survives a re-read, not just the echo.
    let id = resp["policy"]["id"].as_str().unwrap().to_string();
    let (_, got) = call(&fix, "GET", &format!("/v1/policies/{id}"), GET, None).await;
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
    let (status, resp) = call(&fix, "POST", "/v1/policies", UPSERT, Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
}

#[tokio::test]
async fn each_verb_rejects_a_siblings_task() {
    let fix = build().await;
    let (status, _) = call(&fix, "GET", "/v1/policies", UPSERT, None).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
