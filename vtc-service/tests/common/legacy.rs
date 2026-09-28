//! Suites written against the administrator's retired bearer routes, driven
//! through the signed door instead.
//!
//! The community verbs (`trust_tasks::community_tasks`) have no REST route;
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
    Some(match (method, seg.as_slice()) {
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
fn legacy_status(payload: &Value) -> StatusCode {
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

    let Some((task, payload, success)) = translate(&method, &path, &query, &json_body) else {
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
    let (_, doc) = super::signed::call(vtc, party, &task, payload).await;
    let payload = doc["payload"].clone();
    if super::signed::error_code(&doc).is_none() {
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
