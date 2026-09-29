//! The policy log and the community's DID log as signed Trust Tasks
//! (`trust_tasks::policy_tasks`), driven through `POST /v1/trust-tasks` the way
//! the console sends them.
//!
//! Each verb is answered for an administrator (its reply matching the
//! published `#response` schema), refused unsigned, refused for a signer below
//! the role its bearer route took, and — where the route is gone — not served
//! over bearer REST.

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};

use common::signed::{
    admin, bearer_route_served_as, call, error_code, party_with_role, payload, post, unsigned,
};
use vtc_service::acl::VtcRole;
use vtc_service::policy::{PolicyPurpose, get_active_policy_id, get_policy};
use vtc_service::test_support::TestVtc;

const LIST: &str = "https://trusttasks.org/spec/policy/list/0.2";
const GET: &str = "https://trusttasks.org/spec/policy/get/0.1";
const ACTIVE: &str = "https://trusttasks.org/spec/policy/active/0.1";
const UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";
const TEST: &str = "https://trusttasks.org/spec/vtc/policies/test/0.1";
const DID_REGISTER: &str = "https://trusttasks.org/spec/did-management/did/register/0.1";

const TEST_ERR_NOT_FOUND: &str =
    trust_tasks_rs::specs::vtc::policies::test::v0_1::error_codes::NOT_FOUND.code;
const TEST_ERR_EVALUATION_FAILED: &str =
    trust_tasks_rs::specs::vtc::policies::test::v0_1::error_codes::EVALUATION_FAILED.code;

/// A refusal's declared code.
fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

const JOIN_POLICY: &str = "package vtc.join\n\nimport rego.v1\n\ndefault allow := false\n\nallow if input.role == \"admin\"\n";

async fn vtc() -> TestVtc {
    TestVtc::builder().with_audit(true).build().await
}

fn upsert(purpose: &str, module: &str) -> Value {
    json!({ "name": purpose, "module": module, "ext": { "org.openvtc.purpose": purpose } })
}

/// Upload `module` for `purpose` as `by`, returning the revision id.
async fn uploaded(vtc: &TestVtc, by: &vti_rooms_dtg::test_support::Party, purpose: &str) -> String {
    let (status, doc) = call(vtc, by, UPSERT, upsert(purpose, JOIN_POLICY)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    payload(&doc)["policy"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn an_administrator_runs_every_policy_verb_over_the_spine() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let id = uploaded(&vtc, &admin, "join").await;

    let (status, doc) = call(&vtc, &admin, GET, json!({ "id": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["policy"]["id"], id);

    // `ext` narrows the listing to one purpose.
    let (_, list) = call(
        &vtc,
        &admin,
        LIST,
        json!({ "ext": { "org.openvtc.purpose": "removal" } }),
    )
    .await;
    assert_eq!(payload(&list)["policies"], json!([]), "{list}");
    let (_, list) = call(
        &vtc,
        &admin,
        LIST,
        json!({ "ext": { "org.openvtc.purpose": "join" } }),
    )
    .await;
    assert_eq!(payload(&list)["policies"][0]["id"], id, "{list}");

    // A test evaluates without activating.
    let (status, doc) = call(
        &vtc,
        &admin,
        TEST,
        json!({ "id": id, "query": "data.vtc.join.allow", "input": { "role": "admin" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        payload(&doc).pointer("/result/result/0/expressions/0/value"),
        Some(&json!(true))
    );
    assert!(
        get_active_policy_id(&vtc.state.active_policies_ks, PolicyPurpose::Join)
            .await
            .unwrap()
            .is_none(),
        "a test activates nothing"
    );
    let uuid = id.parse().unwrap();
    assert!(
        get_policy(&vtc.state.policies_ks, uuid)
            .await
            .unwrap()
            .unwrap()
            .activated_at
            .is_none()
    );

    // A purpose the revision does not decide is refused; its own is bound.
    let (status, doc) = call(
        &vtc,
        &admin,
        ACTIVATE,
        json!({ "id": id, "purpose": "removal" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{doc}");
    let (status, doc) = call(
        &vtc,
        &admin,
        ACTIVATE,
        json!({ "id": id, "purpose": "join" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["activated"], id);
    let (_, doc) = call(
        &vtc,
        &admin,
        ACTIVATE,
        json!({ "id": id, "purpose": "join" }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("policy/activate:alreadyActive"),
        "{doc}"
    );

    let (status, doc) = call(&vtc, &admin, ACTIVE, json!({ "purpose": "join" })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["bindings"][0]["policy"]["id"], id, "{doc}");
    let (status, _) = call(&vtc, &admin, ACTIVE, json!({ "contextId": "ctx-a" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_codes_the_specifications_declare_are_answered() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    let ghost = uuid::Uuid::new_v4().to_string();
    let (_, doc) = call(&vtc, &admin, GET, json!({ "id": ghost })).await;
    assert_eq!(error_code(&doc), Some("policy/get:notFound"), "{doc}");
    let (_, doc) = call(
        &vtc,
        &admin,
        TEST,
        json!({ "id": ghost, "query": "data.vtc.join.allow", "input": {} }),
    )
    .await;
    assert_eq!(tt_error_code(&doc), Some(TEST_ERR_NOT_FOUND), "{doc}");

    let id = uploaded(&vtc, &admin, "join").await;
    let (_, doc) = call(
        &vtc,
        &admin,
        TEST,
        json!({ "id": id, "query": "data.vtc.join[", "input": {} }),
    )
    .await;
    assert_eq!(
        tt_error_code(&doc),
        Some(TEST_ERR_EVALUATION_FAILED),
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        UPSERT,
        json!({
            "name": "join",
            "module": JOIN_POLICY,
            "expectedVersion": 7,
            "ext": { "org.openvtc.purpose": "join" },
        }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("policy/upsert:versionConflict"),
        "{doc}"
    );
}

/// The bearer routes took `AdminAuth`; a moderator and an unsigned document
/// are refused, and the community's DID log is for an unrestricted
/// administrator only (`SuperAdminAuth`).
#[tokio::test]
async fn below_an_administrator_and_unsigned_are_refused() {
    let vtc = vtc().await;
    let moderator = party_with_role(&vtc, VtcRole::Moderator, &[]).await;
    for (task, body) in [
        (LIST, json!({})),
        (ACTIVE, json!({})),
        (UPSERT, upsert("join", JOIN_POLICY)),
    ] {
        let (status, doc) = call(&vtc, &moderator, task, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{task}: {doc}");
        let (status, doc) = post(&vtc, &unsigned(&moderator, task, body)).await;
        assert!(
            status.is_client_error() && error_code(&doc).is_some(),
            "{task} unsigned: {status} {doc}"
        );
    }

    let scoped = party_with_role(&vtc, VtcRole::Admin, &["ctx-a"]).await;
    let (status, doc) = call(
        &vtc,
        &scoped,
        DID_REGISTER,
        json!({ "path": ".well-known", "method": "webvh", "didData": "{}" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{doc}");
}

/// A Rego module of the full 64 KiB source limit escapes past the 64 KiB
/// document default. An administrator's is admitted at `policy/upsert`'s
/// raised limit; a stranger's the same size is refused for its size before it
/// is verified.
#[tokio::test]
async fn a_large_module_is_admitted_from_an_administrator_only() {
    let vtc = vtc().await;
    let admin = admin(&vtc).await;
    // Quotes and newlines escape to two bytes each, so a comment of them
    // nearly doubles on the wire: ~61 KiB of source, ~117 KiB of document.
    let filler = "#\"\"\"\"\"\"\"\"\"\"\"\n".repeat(4800);
    let module = format!("{JOIN_POLICY}{filler}");
    assert!(module.len() < 64 * 1024);
    let body = upsert("join", &module);
    assert!(serde_json::to_vec(&body).unwrap().len() > 100 * 1024);

    let (status, doc) = call(&vtc, &admin, UPSERT, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    let stranger = vti_rooms_dtg::test_support::Party::new();
    let (status, doc) = call(&vtc, &stranger, UPSERT, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{doc}");
    assert_eq!(payload(&doc)["details"]["maxBytes"], 64 * 1024, "{doc}");
}

#[tokio::test]
async fn the_moved_bearer_routes_are_gone_and_the_client_routes_stay() {
    let vtc = vtc().await;
    assert!(!bearer_route_served_as(&vtc, "GET", "/v1/policies/active", ACTIVE).await);
    let id = uuid::Uuid::new_v4();
    assert!(!bearer_route_served_as(&vtc, "POST", &format!("/v1/policies/{id}/test"), TEST).await);
    // `vtc-client` still calls these.
    assert!(bearer_route_served_as(&vtc, "GET", "/v1/policies", LIST).await);
}
