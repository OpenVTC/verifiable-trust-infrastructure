//! Integration coverage for `/v1/policies/*` (Phase 2 M2.3).
//!
//! Acceptance bullets from `phase-2-todo.md` M2.3.1:
//! - Happy upload + bad-Rego rejection.
//! - Activate-after-upload swaps the active pointer.
//! - Test-without-activate doesn't mutate state.
//!
//! Plus auxiliary coverage: re-activate-same-id 409, activate
//! unknown id 404, and audit envelope emission on the two
//! state-changing endpoints.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::store::KeyspaceHandle;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::policy::{PolicyPurpose, get_active_policy_id, get_policy};
use vtc_service::test_support::TestVtc;

const UPLOAD_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/upload/1.0";
const ACTIVATE_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/activate/1.0";
const TEST_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/test/1.0";
/// `/v1/policies` (list) + `/v1/policies/{id}` (show) share their
/// HTTP mounts with the upload + activate POSTs respectively —
/// TrustTaskRouter doesn't yet support per-method selectors, so
/// the GET requests carry the upload task header. See
/// `vtc-service/src/routes/mod.rs` comment block.
const LIST_TASK: &str = UPLOAD_TASK;
const SHOW_TASK: &str = UPLOAD_TASK;

const ADMIN_DID: &str = "did:key:zPolicyAdmin";

// Test fixtures must live in the package their declared purpose expects
// (P1.5: a join policy in `vtc.test` is now rejected at upload as a
// silent-deny footgun). These exercise generic upload/activate/list
// mechanics, so they just need a valid `allow` rule in the right package.
const JOIN_ALLOW_POLICY: &str = "\
package vtc.join

import rego.v1

default allow := false

allow if input.role == \"admin\"
";

const JOIN_ALT_POLICY: &str = "\
package vtc.join

import rego.v1

default allow := true
";

const REMOVAL_POLICY: &str = "\
package vtc.removal

import rego.v1

default allow := true
";

struct Fixture {
    router: axum::Router,
    admin_token: String,
    policies_ks: KeyspaceHandle,
    active_policies_ks: KeyspaceHandle,
    audit_ks: KeyspaceHandle,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;

    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("test admin".into()),
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let admin_token = vtc.token(ADMIN_DID, "admin", vec![]).await;

    let policies_ks = vtc.state.policies_ks.clone();
    let active_policies_ks = vtc.state.active_policies_ks.clone();
    let audit_ks = vtc.state.audit_ks.clone();
    let router = vtc.router.clone();

    Fixture {
        router,
        admin_token,
        policies_ks,
        active_policies_ks,
        audit_ks,
        _vtc: vtc,
    }
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        let raw = String::from_utf8_lossy(&bytes);
        panic!("response body was not JSON ({e}): {raw}")
    })
}

fn auth_request(method: &str, uri: &str, task: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("trust-task", task)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn upload_policy(fix: &Fixture, purpose: &str, source: &str) -> Value {
    let req = auth_request(
        "POST",
        "/v1/policies",
        UPLOAD_TASK,
        &fix.admin_token,
        json!({ "purpose": purpose, "regoSource": source }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "expected 201 from upload"
    );
    body_json(resp.into_body()).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Acceptance bullet 1a: happy upload. The 201 response carries
/// id/sha256/purpose/version and the policy row is persisted to
/// fjall.
#[tokio::test]
async fn upload_happy_path_persists_policy() {
    let fix = build_fixture().await;
    let body = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

    assert_eq!(body["purpose"], "join");
    assert_eq!(body["version"], 1);
    let sha = body["sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    assert!(
        sha.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );

    // Row persisted with same id + matching SHA.
    let stored = get_policy(&fix.policies_ks, id).await.unwrap().unwrap();
    assert_eq!(stored.id, id);
    assert_eq!(stored.purpose, PolicyPurpose::Join);
    assert_eq!(hex::encode(stored.sha256), sha);
    assert_eq!(stored.version, 1);
    assert!(
        stored.activated_at.is_none(),
        "upload must not activate the row"
    );

    // No active pointer was flipped.
    assert!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap()
            .is_none(),
        "upload must not mutate the active pointer"
    );
}

/// Acceptance bullet 1b: bad-Rego rejection. A malformed source
/// surfaces from the harness as 400 (AppError::Validation) and the
/// id from the error message is meaningful for the operator.
#[tokio::test]
async fn upload_bad_rego_returns_400() {
    let fix = build_fixture().await;
    let req = auth_request(
        "POST",
        "/v1/policies",
        UPLOAD_TASK,
        &fix.admin_token,
        json!({ "purpose": "join", "regoSource": "@@@ not rego @@@" }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_json(resp.into_body()).await;
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("rego compile failed"),
        "error body should explain the compile failure: {body}"
    );
}

/// P1.5: a policy whose Rego package doesn't match its declared
/// purpose is rejected at upload — it would compile + activate cleanly
/// then evaluate to `undefined` (silent host default-deny) for the
/// whole ceremony.
#[tokio::test]
async fn upload_rejects_purpose_package_mismatch() {
    let fix = build_fixture().await;
    // purpose=join, but the module lives in vtc.removal.
    let mismatched = "package vtc.removal\nimport rego.v1\ndefault allow := false\n";
    let req = auth_request(
        "POST",
        "/v1/policies",
        UPLOAD_TASK,
        &fix.admin_token,
        json!({ "purpose": "join", "regoSource": mismatched }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp.into_body()).await;
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("vtc.join"),
        "error must name the expected package: {body}"
    );
}

/// Acceptance bullet 2: activate-after-upload swaps the active
/// pointer and stamps `activated_at` on the row.
#[tokio::test]
async fn activate_swaps_active_pointer() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = uploaded["id"].as_str().unwrap().parse().unwrap();

    let req = auth_request(
        "POST",
        &format!("/v1/policies/{id}/activate"),
        ACTIVATE_TASK,
        &fix.admin_token,
        json!({}),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    assert_eq!(body["id"], id.to_string());
    assert_eq!(body["purpose"], "join");
    assert!(
        body["previousPolicyId"].is_null(),
        "first activation must have null predecessor: {body}"
    );

    // Active pointer + activated_at populated.
    assert_eq!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap(),
        Some(id)
    );
    let stored = get_policy(&fix.policies_ks, id).await.unwrap().unwrap();
    assert!(
        stored.activated_at.is_some(),
        "activate must stamp activated_at"
    );
}

/// Second activation of the same id for the same purpose returns
/// 409. Re-activating a *different* id later swaps cleanly (covered
/// in `activate_replaces_predecessor`).
#[tokio::test]
async fn activate_same_id_twice_returns_409() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = uploaded["id"].as_str().unwrap().parse().unwrap();

    for expected in [StatusCode::OK, StatusCode::CONFLICT] {
        let req = auth_request(
            "POST",
            &format!("/v1/policies/{id}/activate"),
            ACTIVATE_TASK,
            &fix.admin_token,
            json!({}),
        );
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), expected);
    }
}

/// Activating a different revision after a prior one records the
/// predecessor on the response + audit envelope.
#[tokio::test]
async fn activate_replaces_predecessor() {
    let fix = build_fixture().await;
    let first = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let first_id: Uuid = first["id"].as_str().unwrap().parse().unwrap();
    let second = upload_policy(&fix, "join", JOIN_ALT_POLICY).await;
    let second_id: Uuid = second["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(second["version"], 2, "second upload bumps version");

    // Activate first, then second.
    for id in [first_id, second_id] {
        let req = auth_request(
            "POST",
            &format!("/v1/policies/{id}/activate"),
            ACTIVATE_TASK,
            &fix.admin_token,
            json!({}),
        );
        let resp = fix.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "activating {id}");
    }

    // Active pointer is now second; predecessor returned by the
    // activate-second response is first.
    assert_eq!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap(),
        Some(second_id)
    );
}

/// Activating an unknown id returns 404.
#[tokio::test]
async fn activate_unknown_id_returns_404() {
    let fix = build_fixture().await;
    let ghost = Uuid::new_v4();
    let req = auth_request(
        "POST",
        &format!("/v1/policies/{ghost}/activate"),
        ACTIVATE_TASK,
        &fix.admin_token,
        json!({}),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Acceptance bullet 3: test-without-activate runs the policy and
/// does not mutate the active pointer or the policy row's
/// `activated_at`.
#[tokio::test]
async fn test_does_not_mutate_state() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = uploaded["id"].as_str().unwrap().parse().unwrap();

    let req = auth_request(
        "POST",
        &format!("/v1/policies/{id}/test"),
        TEST_TASK,
        &fix.admin_token,
        json!({
            "query": "data.vtc.join.allow",
            "input": { "role": "admin" }
        }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    assert_eq!(body["id"], id.to_string());
    let allow = body
        .pointer("/result/result/0/expressions/0/value")
        .expect("regorus QueryResults shape");
    assert_eq!(allow, &json!(true));

    // No active pointer was flipped, no activated_at was stamped.
    assert!(
        get_active_policy_id(&fix.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap()
            .is_none(),
        "test must not activate the policy"
    );
    let stored = get_policy(&fix.policies_ks, id).await.unwrap().unwrap();
    assert!(
        stored.activated_at.is_none(),
        "test must not stamp activated_at"
    );
}

/// The shipped decision-shaped default policy, evaluated through the
/// real `/test` endpoint with the query + facts the simulator sends,
/// produces a four-valued decision object — proving the backend +
/// default + wire shape are sound end-to-end (the simulator's
/// "no decision" error is a non-decision-shaped *active* policy, not a
/// backend bug).
#[tokio::test]
async fn shipped_directory_default_yields_a_decision_via_test() {
    const DIRECTORY_DEFAULT: &str = include_str!("../policies/default/directory.rego");
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "directory", DIRECTORY_DEFAULT).await;
    let id: Uuid = uploaded["id"].as_str().unwrap().parse().unwrap();

    let req = auth_request(
        "POST",
        &format!("/v1/policies/{id}/test"),
        TEST_TASK,
        &fix.admin_token,
        json!({
            "query": "data.vtc.directory.decision",
            "input": { "actor": { "role": "admin", "authenticated": true } }
        }),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    let decision = body
        .pointer("/result/result/0/expressions/0/value")
        .expect("decision query must yield a value");
    assert_eq!(
        decision["effect"], "allow",
        "admin viewer → allow, got {decision}"
    );
    assert!(decision["with"]["fields"].is_array());
}

/// Upload + activate each emit one audit envelope. The audit
/// keyspace gains exactly two rows (plus the boot-time
/// `AuditKeyRotated::Initial` row from `ensure_initial`).
#[tokio::test]
async fn upload_and_activate_emit_audit_envelopes() {
    let fix = build_fixture().await;
    let baseline = fix
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .len();

    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id: Uuid = uploaded["id"].as_str().unwrap().parse().unwrap();
    let after_upload = fix
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .len();
    assert_eq!(
        after_upload - baseline,
        1,
        "upload must emit exactly one audit envelope"
    );

    let req = auth_request(
        "POST",
        &format!("/v1/policies/{id}/activate"),
        ACTIVATE_TASK,
        &fix.admin_token,
        json!({}),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let after_activate = fix
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .len();
    assert_eq!(
        after_activate - after_upload,
        1,
        "activate must emit exactly one audit envelope"
    );
}

// ---------------------------------------------------------------------------
// Read endpoints (M2.4)
// ---------------------------------------------------------------------------

fn auth_get(uri: &str, task: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("trust-task", task)
        .body(Body::empty())
        .unwrap()
}

/// `GET /v1/policies` returns every uploaded policy. Each item
/// carries the full row + an `isActive` flag.
#[tokio::test]
async fn list_returns_all_policies() {
    let fix = build_fixture().await;
    let a = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let _b = upload_policy(&fix, "removal", REMOVAL_POLICY).await;
    let a_id = a["id"].as_str().unwrap();

    // Activate one of them so the isActive flag has signal.
    let req = auth_request(
        "POST",
        &format!("/v1/policies/{a_id}/activate"),
        ACTIVATE_TASK,
        &fix.admin_token,
        json!({}),
    );
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = fix
        .router
        .clone()
        .oneshot(auth_get("/v1/policies", LIST_TASK, &fix.admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    let active: Vec<&Value> = items.iter().filter(|i| i["isActive"] == true).collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0]["id"], a_id);
    // Full row visibility — Rego source is in the response.
    assert!(items.iter().all(|i| i["regoSource"].is_string()));
}

/// `?purpose=removal` filters list to that purpose only.
#[tokio::test]
async fn list_filters_by_purpose() {
    let fix = build_fixture().await;
    upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    upload_policy(&fix, "removal", REMOVAL_POLICY).await;

    let resp = fix
        .router
        .clone()
        .oneshot(auth_get(
            "/v1/policies?purpose=removal",
            LIST_TASK,
            &fix.admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["purpose"], "removal");
}

/// `?status=active` returns only rows pointed at by their
/// per-purpose active pointer. `?status=archived` returns the
/// complement.
#[tokio::test]
async fn list_filters_by_status() {
    let fix = build_fixture().await;
    let join = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let removal = upload_policy(&fix, "removal", REMOVAL_POLICY).await;
    let join_id = join["id"].as_str().unwrap();
    let _removal_id = removal["id"].as_str().unwrap();

    // Activate only the join row.
    let req = auth_request(
        "POST",
        &format!("/v1/policies/{join_id}/activate"),
        ACTIVATE_TASK,
        &fix.admin_token,
        json!({}),
    );
    fix.router.clone().oneshot(req).await.unwrap();

    // status=active → just the join row.
    let resp = fix
        .router
        .clone()
        .oneshot(auth_get(
            "/v1/policies?status=active",
            LIST_TASK,
            &fix.admin_token,
        ))
        .await
        .unwrap();
    let body = body_json(resp.into_body()).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], join_id);
    assert_eq!(items[0]["isActive"], true);

    // status=archived → just the removal row.
    let resp = fix
        .router
        .clone()
        .oneshot(auth_get(
            "/v1/policies?status=archived",
            LIST_TASK,
            &fix.admin_token,
        ))
        .await
        .unwrap();
    let body = body_json(resp.into_body()).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["purpose"], "removal");
    assert_eq!(items[0]["isActive"], false);
}

/// Regression: the simulator's active-policy lookup
/// (`?purpose=X&status=active&limit=1`) must return X's active row even
/// when several purposes have active policies. The purpose/status
/// filters run *after* pagination, so `limit=1` used to fetch one
/// arbitrary keyspace row and filter it — surfacing the active policy
/// for a single purpose only (whichever sorted first). status=active is
/// now resolved from the per-purpose active pointers directly.
#[tokio::test]
async fn list_active_by_purpose_is_exact_under_limit_one() {
    let fix = build_fixture().await;
    let join = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let removal = upload_policy(&fix, "removal", REMOVAL_POLICY).await;
    let join_id = join["id"].as_str().unwrap();
    let removal_id = removal["id"].as_str().unwrap();

    // Activate a policy for both purposes.
    for id in [join_id, removal_id] {
        let req = auth_request(
            "POST",
            &format!("/v1/policies/{id}/activate"),
            ACTIVATE_TASK,
            &fix.admin_token,
            json!({}),
        );
        fix.router.clone().oneshot(req).await.unwrap();
    }

    // Each purpose's active lookup returns ITS row, despite limit=1.
    for (purpose, id) in [("join", join_id), ("removal", removal_id)] {
        let resp = fix
            .router
            .clone()
            .oneshot(auth_get(
                &format!("/v1/policies?purpose={purpose}&status=active&limit=1"),
                LIST_TASK,
                &fix.admin_token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{purpose}: active lookup returns one row");
        assert_eq!(items[0]["id"], id, "{purpose}: active id");
        assert_eq!(items[0]["isActive"], true);
    }
}

/// `GET /v1/policies/{id}` returns the full row + isActive flag.
#[tokio::test]
async fn show_returns_full_row() {
    let fix = build_fixture().await;
    let uploaded = upload_policy(&fix, "join", JOIN_ALLOW_POLICY).await;
    let id = uploaded["id"].as_str().unwrap();

    let resp = fix
        .router
        .clone()
        .oneshot(auth_get(
            &format!("/v1/policies/{id}"),
            SHOW_TASK,
            &fix.admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    assert_eq!(body["id"], id);
    assert_eq!(body["purpose"], "join");
    assert_eq!(body["version"], 1);
    assert_eq!(body["isActive"], false);
    assert!(
        body["regoSource"]
            .as_str()
            .unwrap()
            .contains("default allow")
    );
}

/// `GET /v1/policies/{id}` returns 404 for unknown ids.
#[tokio::test]
async fn show_unknown_id_returns_404() {
    let fix = build_fixture().await;
    let ghost = Uuid::new_v4();
    let resp = fix
        .router
        .clone()
        .oneshot(auth_get(
            &format!("/v1/policies/{ghost}"),
            SHOW_TASK,
            &fix.admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Auth gate: an unauthenticated upload returns 401. Confirms the
/// `AdminAuth` extractor is wired through the route.
#[tokio::test]
async fn upload_without_token_returns_401() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/policies")
        .header("trust-task", UPLOAD_TASK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "purpose": "join", "regoSource": JOIN_ALLOW_POLICY }).to_string(),
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
