//! Suites written against the administrator's retired bearer routes, driven
//! through the signed door instead.
//!
//! The community verbs (`trust_tasks::community_tasks`, and the join queue's
//! query and vetting reads in `trust_tasks::surface_tasks`) have no REST route;
//! they are signed documents at `POST /v1/trust-tasks`. The suites below keep
//! their assertions — the operations' behaviour did not change — by handing
//! each request they used to send to [`send`], which turns it into the signed
//! document the console sends now: the same verb, its payload read off the
//! request's path, query and body, signed by the party the request's bearer
//! token stood for. The reply is rendered back the way those suites read a
//! REST answer: the `#response` payload with the route's success status, or a
//! refusal's code under the status the route used for it.
//!
//! Only verbs whose bearer route is gone are translated; anything else is sent
//! to the router unchanged.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tower::ServiceExt;
use vti_rooms_dtg::test_support::Party;

use vtc_service::test_support::TestVtc;

const SPEC: &str = "https://trusttasks.org/spec/vtc/";
const POLICY_GET: &str = "https://trusttasks.org/spec/policy/get/0.1";
const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const VETTER_GRANT: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
const VETTER_SHOW: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/show/0.1";

/// Which signed document a request to a retired route is, and the success
/// status the route answered with.
fn translate(
    method: &str,
    path: &str,
    query: &Map<String, Value>,
    body: &Value,
) -> Option<(String, Value, StatusCode)> {
    let seg: Vec<&str> = path.trim_start_matches("/v1/").split('/').collect();
    let decode = |s: &str| percent_decode(s);
    let q = |k: &str| query.get(k).cloned();
    let obj = |pairs: Vec<(&str, Option<Value>)>| {
        let mut m = Map::new();
        for (k, v) in pairs {
            if let Some(v) = v {
                m.insert(k.to_string(), v);
            }
        }
        Value::Object(m)
    };
    let ok = StatusCode::OK;
    let t = |slug: &str| format!("{SPEC}{slug}");
    let with = |mut v: Value, k: &str, x: Value| {
        if !v.is_object() {
            v = json!({});
        }
        v[k] = x;
        v
    };
    let page = || {
        obj(vec![
            ("cursor", q("cursor")),
            ("limit", q("limit").map(number)),
        ])
    };
    Some(match (method, seg.as_slice()) {
        ("GET", ["members"]) => (
            t("members/list/0.1"),
            with(page(), "role", q("role").unwrap_or(Value::Null)),
            ok,
        ),
        ("GET", ["members", did, "credentials"]) => (
            t("members/credentials/0.1"),
            json!({ "did": decode(did) }),
            ok,
        ),
        ("PATCH", ["members", did]) => (
            t("members/update/0.1"),
            with(body.clone(), "did", json!(decode(did))),
            ok,
        ),
        ("DELETE", ["members", did]) => (
            t("members/admin-remove/0.1"),
            with(body.clone(), "did", json!(decode(did))),
            ok,
        ),
        ("GET", ["join-requests"]) => (
            t("join-requests/list/0.1"),
            with(page(), "status", q("status").unwrap_or(Value::Null)),
            ok,
        ),
        ("POST", ["join-requests", id, "decide"]) => (
            t("join-requests/decide/0.1"),
            with(body.clone(), "id", json!(decode(id))),
            ok,
        ),
        ("GET", ["policies"]) => (
            "https://trusttasks.org/spec/policy/list/0.2".into(),
            page(),
            ok,
        ),
        ("POST", ["policies"]) => (POLICY_UPSERT.into(), body.clone(), StatusCode::CREATED),
        ("GET", ["policies", id]) => (POLICY_GET.into(), json!({ "id": decode(id) }), ok),
        ("POST", ["policies", id, "activate"]) => (
            "https://trusttasks.org/spec/policy/activate/0.1".into(),
            with(body.clone(), "id", json!(decode(id))),
            ok,
        ),
        ("GET", ["audit", "verify"]) => (
            "https://trusttasks.org/spec/audit/verify/0.1".into(),
            json!({}),
            ok,
        ),
        ("POST", ["admin", "did", "register"]) => (
            "https://trusttasks.org/spec/did-management/did/register/0.1".into(),
            body.clone(),
            ok,
        ),
        ("POST", ["vetting", "vetters"]) => {
            (VETTER_GRANT.into(), body.clone(), StatusCode::CREATED)
        }
        ("POST", ["vetting", "vetters", "show"]) => (VETTER_SHOW.into(), body.clone(), ok),
        ("GET", ["community", "profile"]) => (t("community/profile/show/0.1"), json!({}), ok),
        ("GET", ["ceremonies"]) => (t("ceremonies/list/0.1"), json!({}), ok),
        ("GET", ["directory", did]) => (
            t("directory/query/0.1"),
            obj(vec![
                ("subject", Some(json!(decode(did)))),
                ("fields", q("fields")),
            ]),
            ok,
        ),
        ("GET", ["endorsement-types"]) => (
            t("endorsement-types/list/0.1"),
            obj(vec![
                ("cursor", q("cursor")),
                ("limit", q("limit").map(number)),
            ]),
            ok,
        ),
        ("GET", ["recognition", "check"]) => {
            (t("recognition/check/0.1"), obj(vec![("did", q("did"))]), ok)
        }
        ("GET", ["members", "removed"]) => (t("members/removed/0.1"), json!({}), ok),
        ("GET", ["members", did]) => (t("members/show/0.1"), json!({ "did": decode(did) }), ok),
        ("POST", ["members", did, "request-vmc"]) => (
            t("members/solicit-vmc/0.1"),
            obj(vec![
                ("memberDid", Some(json!(decode(did)))),
                ("reason", body.get("reason").cloned()),
            ]),
            StatusCode::ACCEPTED,
        ),
        ("GET", ["join-requests", id]) => {
            (t("join-requests/show/0.1"), json!({ "id": decode(id) }), ok)
        }
        ("GET", ["relationships", "graph"]) => (t("relationships/graph/0.2"), json!({}), ok),
        ("POST", ["invitations"]) => (
            t("invitations/issue/0.1"),
            body.clone(),
            StatusCode::CREATED,
        ),
        ("GET", ["invitations"]) => (t("invitations/list/0.1"), json!({}), ok),
        ("POST", ["invitations", "deliver"]) => (t("invitations/deliver/0.1"), body.clone(), ok),
        ("DELETE", ["invitations", id]) => {
            (t("invitations/revoke/0.1"), json!({ "id": decode(id) }), ok)
        }
        ("POST", ["join-requests", "query"]) => (t("join-requests/query/0.1"), body.clone(), ok),
        ("GET", ["join-requests", id, "vetting"]) => (
            t("join-requests/vetting/show/0.1"),
            json!({ "id": decode(id) }),
            ok,
        ),
        ("DELETE", ["relationships", id]) => (
            "https://trusttasks.org/spec/vtc/relationships/revoke/0.2".into(),
            with(body.clone(), "id", json!(decode(id))),
            ok,
        ),
        ("GET", ["credentials", "endorsements"]) => (t("endorsements/list/0.1"), page(), ok),
        ("GET", ["credentials", "endorsements", id]) => (
            t("endorsements/show/0.1"),
            json!({ "endorsementId": decode(id) }),
            ok,
        ),
        ("DELETE", ["credentials", "endorsements", id]) => (
            t("endorsements/revoke/0.1"),
            json!({ "endorsementId": decode(id) }),
            ok,
        ),
        ("POST", ["vetting", "vetters", member_did, "resend"]) => (
            "https://trusttasks.org/spec/vtc/vetting/vetters/resend/0.2".into(),
            json!({ "memberDid": decode(member_did) }),
            ok,
        ),
        _ => return None,
    })
}

/// A query-string number as JSON.
fn number(v: Value) -> Value {
    v.as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(v, |n| json!(n))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

fn parse_query(q: Option<&str>) -> Map<String, Value> {
    let mut m = Map::new();
    for pair in q.unwrap_or_default().split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.insert(k.to_string(), json!(percent_decode(v)));
    }
    m
}

/// The status a retired route answered a refusal with.
pub fn legacy_status(payload: &Value) -> StatusCode {
    let code = payload["code"].as_str().unwrap_or_default();
    match (code, payload["details"]["reason"].as_str()) {
        ("permissionDenied", _) => StatusCode::FORBIDDEN,
        ("proofRequired", _) => StatusCode::UNAUTHORIZED,
        ("malformedRequest", _) => StatusCode::BAD_REQUEST,
        ("expired", _) | (_, Some("gone")) => StatusCode::GONE,
        (_, Some("not_found")) => StatusCode::NOT_FOUND,
        (_, Some("conflict")) => StatusCode::CONFLICT,
        ("internalError", _) => StatusCode::INTERNAL_SERVER_ERROR,
        (c, _) if c.ends_with(":notFound") => StatusCode::NOT_FOUND,
        (c, _) if c.ends_with(":revoked") => StatusCode::CONFLICT,
        (c, _) if c.ends_with(":noRoute") => StatusCode::UNPROCESSABLE_ENTITY,
        (c, _) if c.contains(':') => StatusCode::BAD_REQUEST,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

/// Send `req` as `parties` identify its bearer token: a retired route's
/// request becomes its signed document (see the module docs); anything else
/// goes to the router as it is.
pub async fn send(
    vtc: &TestVtc,
    parties: &[(&str, &Party)],
    req: Request<Body>,
) -> axum::response::Response {
    let (status, body) = send_json(vtc, parties, req).await;
    axum::response::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// As [`send`], answering the status and the JSON body.
pub async fn send_json(
    vtc: &TestVtc,
    parties: &[(&str, &Party)],
    req: Request<Body>,
) -> (StatusCode, Value) {
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json_body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query = parse_query(parts.uri.query());

    let Some((task, mut payload, mut success)) = translate(&method, &path, &query, &json_body)
    else {
        let req = Request::from_parts(parts, Body::from(bytes));
        let res = vtc.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
        return (status, v);
    };

    let token = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(party) = token.and_then(|t| parties.iter().find(|(k, _)| *k == t).map(|(_, p)| *p))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            json!({ "error": "no signer for this request" }),
        );
    };
    if let Some(map) = payload.as_object_mut() {
        map.retain(|_, v| !v.is_null());
    }
    // `policy/activate` names the purpose the revision is bound to, which the
    // route read from the stored revision.
    if task.ends_with("/policy/activate/0.1") && payload.get("purpose").is_none() {
        let (_, got) =
            super::signed::call(vtc, party, POLICY_GET, json!({ "id": payload["id"] })).await;
        if let Some(purpose) = got["payload"]["policy"]["ext"]["org.openvtc.purpose"].as_str() {
            payload["purpose"] = json!(purpose);
        }
    }
    // The grant route answered `201` for a new grant and `200` for one that
    // stood; the task's response does not say which, so ask first.
    if task == VETTER_GRANT {
        let (_, shown) = super::signed::call(
            vtc,
            party,
            VETTER_SHOW,
            json!({ "vetterDid": payload["memberDid"] }),
        )
        .await;
        if shown["payload"]["status"] == "live" {
            success = StatusCode::OK;
        }
    }
    let (_, doc) = super::signed::call(vtc, party, &task, payload).await;
    let payload = doc["payload"].clone();
    if super::signed::error_code(&doc).is_none() {
        if task == POLICY_UPSERT && payload["created"] == false {
            return (StatusCode::OK, payload);
        }
        return (success, payload);
    }
    let status = legacy_status(&payload);
    let code = payload["code"].as_str().unwrap_or_default();
    let mut body = json!({ "error": payload["message"] });
    if code.contains(':') || code == "expired" {
        body["code"] = json!(code);
    }
    (status, body)
}
