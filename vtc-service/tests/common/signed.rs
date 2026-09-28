//! The signed-document door, as an administrator's client uses it: a Trust
//! Task built with the SDK's own builder, signed by a `did:key` party, and
//! posted to `POST /v1/trust-tasks`.
//!
//! The admin verbs have no REST route, so the integration suites that used to
//! drive their bearer routes drive this instead. The reply is the whole
//! document — a `#response`, or a `trust-task-error` — with its HTTP status.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

/// A signer holding an ACL row of `role`, scoped to `contexts` (empty for an
/// unrestricted one).
pub async fn party_with_role(vtc: &TestVtc, role: VtcRole, contexts: &[&str]) -> Party {
    let party = Party::new();
    seed_role(vtc, &party.did, role, contexts).await;
    party
}

/// An unrestricted administrator.
pub async fn admin(vtc: &TestVtc) -> Party {
    party_with_role(vtc, VtcRole::Admin, &[]).await
}

/// Write `did`'s ACL row.
pub async fn seed_role(vtc: &TestVtc, did: &str, role: VtcRole, contexts: &[&str]) {
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: contexts.iter().map(|c| c.to_string()).collect(),
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed ACL row");
}

/// The unsigned document `from` would send.
pub fn unsigned(from: &Party, type_uri: &str, payload: Value) -> Value {
    let doc = vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, TEST_VTC_DID)
        .expect("build the document");
    serde_json::to_value(doc).expect("a document serialises")
}

/// The document `from` would send, signed by its key.
pub async fn signed(from: &Party, type_uri: &str, payload: Value) -> Value {
    let mut doc =
        vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &from.did, TEST_VTC_DID)
            .expect("build the document");
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .expect("a did:key names its own verification method");
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .expect("sign the document");
    serde_json::to_value(doc).expect("a document serialises")
}

/// Post `doc` to `POST /v1/trust-tasks`.
///
/// Each call comes from an address of its own. The document endpoint sits
/// behind the per-address governor (a burst of ten), and these suites send
/// many more documents than that on purpose; what they test is the verb, not
/// the governor, which `rate_limit_source.rs` covers.
pub async fn post(vtc: &TestVtc, doc: &Value) -> (StatusCode, Value) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let peer = std::net::SocketAddr::from(([10, (n >> 16) as u8, (n >> 8) as u8, n as u8], 40_000));
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Sign `payload` as `from` and send it: the reply's status and document.
///
/// A success reply is held to its task's published `#response` schema — the
/// check the router's response-conformance layer makes on the bearer routes,
/// which keys on the `Trust-Task` header this door does not carry.
pub async fn call(
    vtc: &TestVtc,
    from: &Party,
    type_uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let (status, doc) = post(vtc, &signed(from, type_uri, payload).await).await;
    if doc["type"].as_str() == Some(format!("{type_uri}#response").as_str()) {
        assert_conforms(type_uri, &doc);
    }
    (status, doc)
}

/// `doc`'s payload validates against `type_uri`'s published `#response` schema.
pub fn assert_conforms(type_uri: &str, doc: &Value) {
    let schema = trust_tasks_rs::schema_index::schema_for(&format!("{type_uri}#response"))
        .unwrap_or_else(|| panic!("{type_uri} publishes no #response schema"));
    trust_tasks_rs::validate::against_schema(schema, &doc["payload"]).unwrap_or_else(|e| {
        panic!("{type_uri}: the response does not match its published schema: {e}\n{doc}")
    });
}

/// The reply's `payload`.
pub fn payload(doc: &Value) -> &Value {
    &doc["payload"]
}

/// A `trust-task-error` reply's `code`, or `None` for a success.
pub fn error_code(doc: &Value) -> Option<&str> {
    if doc["type"].as_str()?.contains("trust-task-error") {
        doc["payload"]["code"].as_str()
    } else {
        None
    }
}

/// Whether `method path`, sent with an administrator's bearer token, reaches
/// an API handler. A path no route serves is `404` or `405`, or — for a `GET`
/// — falls through to the website's static handler, which answers HTML; an API
/// handler answers JSON.
pub async fn bearer_route_served(vtc: &TestVtc, method: &str, path: &str) -> bool {
    let token = vtc.admin_token().await;
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    if status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED {
        return false;
    }
    res.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"))
}
