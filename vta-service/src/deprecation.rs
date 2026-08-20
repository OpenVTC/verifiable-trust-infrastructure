//! Deprecation signalling for legacy REST routes that a canonical
//! `/api/trust-tasks` Trust-Task now supersedes.
//!
//! These routes keep working — the deprecation is advisory. We add response
//! headers so clients can detect the deprecation and migrate, and increment a
//! hit counter (`deprecated_route_requests_total`, labelled by route) so that
//! removal can be gated on **observed usage dropping to zero** rather than a
//! guessed calendar date. (No `Sunset` date is emitted for that reason.)
//!
//! The canonical replacement for every route marked here is the same operation
//! dispatched as a Trust-Task via `POST /api/trust-tasks` (reachable over REST,
//! DIDComm, and TSP through the shared `dispatch_trust_task_core` spine).

use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use metrics::counter;
use vta_sdk::trust_tasks;

/// Build the deprecation response headers for a legacy `route`, pointing at the
/// successor Trust-Task URI, and record a hit for that route.
///
/// Emits `Deprecation: true` and `Link: <successor>; rel="successor-version"`
/// (RFC 8288). Attach the returned [`HeaderMap`] to the handler's response.
pub fn superseded(route: &'static str, successor: &'static str) -> HeaderMap {
    counter!("deprecated_route_requests_total", "route" => route).increment(1);

    let mut headers = HeaderMap::new();
    headers.insert("deprecation", HeaderValue::from_static("true"));
    if let Ok(link) = HeaderValue::from_str(&format!("<{successor}>; rel=\"successor-version\"")) {
        headers.insert("link", link);
    }
    headers
}

// ─── The superseded-route table ────────────────────────────────────────────
//
// `(method, matched-path, metric label, successor Trust-Task URI)`.
//
// Recovered from the `build_rest` closures the SDK carried before #1000
// deleted them: each paired a Trust-Task constant with the exact REST route it
// fell back to, so this mapping is what the client itself used rather than a
// guess from matching names. Two entries look wrong at a glance and are not —
// `GET /webvh/dids/{scid}/log` points at `dids/get`, because the dedicated
// get-log task folded into it behind `includeLog`; and
// `PATCH /webvh/servers/{id}` points at `servers/register`, because #850
// folded add and update into that one task.
//
// A route absent from this table is absent on purpose: `/auth`, `/bootstrap`,
// `/backup` blob streaming, `/keys/import/wrapping-key`, `/metrics` and
// `/.well-known` are genuinely REST and are not going anywhere. `/services/*`
// used to be listed here too, as the one block with no twin at all; it has one
// now, and its entries are at the end of this table.
/// The table, for tests that need to assert on its contents.
pub fn superseded_table() -> &'static [(&'static str, &'static str, &'static str, &'static str)] {
    SUPERSEDED
}

const SUPERSEDED: &[(&str, &str, &str, &str)] = &[
    ("GET", "/acl", "GET /acl", trust_tasks::TASK_ACL_LIST_0_1),
    ("POST", "/acl", "POST /acl", trust_tasks::TASK_ACL_GRANT_0_1),
    (
        "DELETE",
        "/acl/{did}",
        "DELETE /acl/{did}",
        trust_tasks::TASK_ACL_REVOKE_0_1,
    ),
    (
        "GET",
        "/acl/{did}",
        "GET /acl/{did}",
        trust_tasks::TASK_ACL_SHOW_0_1,
    ),
    (
        "PATCH",
        "/acl/{did}",
        "PATCH /acl/{did}",
        trust_tasks::TASK_ACL_UPDATE_0_1,
    ),
    (
        "POST",
        "/acl/{did}/change-role",
        "POST /acl/{did}/change-role",
        trust_tasks::TASK_ACL_CHANGE_ROLE_0_1,
    ),
    (
        "GET",
        "/audit/logs",
        "GET /audit/logs",
        trust_tasks::TASK_AUDIT_LIST_0_1,
    ),
    (
        "GET",
        "/audit/retention",
        "GET /audit/retention",
        trust_tasks::TASK_AUDIT_GET_RETENTION_1_0,
    ),
    (
        "PATCH",
        "/audit/retention",
        "PATCH /audit/retention",
        trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0,
    ),
    (
        "GET",
        "/capabilities",
        "GET /capabilities",
        trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0,
    ),
    (
        "GET",
        "/config",
        "GET /config",
        trust_tasks::TASK_CONFIG_SHOW_0_1,
    ),
    (
        "PATCH",
        "/config",
        "PATCH /config",
        trust_tasks::TASK_CONFIG_PATCH_0_1,
    ),
    (
        "GET",
        "/contexts",
        "GET /contexts",
        trust_tasks::TASK_CONTEXTS_LIST_1_0,
    ),
    (
        "POST",
        "/contexts",
        "POST /contexts",
        trust_tasks::TASK_CONTEXTS_CREATE_1_0,
    ),
    (
        "DELETE",
        "/contexts/{id}",
        "DELETE /contexts/{id}",
        trust_tasks::TASK_CONTEXTS_DELETE_1_0,
    ),
    (
        "GET",
        "/contexts/{id}",
        "GET /contexts/{id}",
        trust_tasks::TASK_CONTEXTS_GET_1_0,
    ),
    (
        "PATCH",
        "/contexts/{id}",
        "PATCH /contexts/{id}",
        trust_tasks::TASK_CONTEXTS_UPDATE_1_0,
    ),
    (
        "GET",
        "/contexts/{id}/delete-preview",
        "GET /contexts/{id}/delete-preview",
        trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0,
    ),
    (
        "PUT",
        "/contexts/{id}/did",
        "PUT /contexts/{id}/did",
        trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
    ),
    (
        "GET",
        "/contexts/{id}/did-templates",
        "GET /contexts/{id}/did-templates",
        trust_tasks::TASK_DID_TEMPLATES_LIST_2_0,
    ),
    (
        "POST",
        "/contexts/{id}/did-templates",
        "POST /contexts/{id}/did-templates",
        trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
    ),
    (
        "DELETE",
        "/contexts/{id}/did-templates/{name}",
        "DELETE /contexts/{id}/did-templates/{name}",
        trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0,
    ),
    (
        "GET",
        "/contexts/{id}/did-templates/{name}",
        "GET /contexts/{id}/did-templates/{name}",
        trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
    ),
    (
        "PUT",
        "/contexts/{id}/did-templates/{name}",
        "PUT /contexts/{id}/did-templates/{name}",
        trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0,
    ),
    (
        "POST",
        "/contexts/{id}/did-templates/{name}/render",
        "POST /contexts/{id}/did-templates/{name}/render",
        trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0,
    ),
    (
        "GET",
        "/did-templates",
        "GET /did-templates",
        trust_tasks::TASK_DID_TEMPLATES_LIST_2_0,
    ),
    (
        "POST",
        "/did-templates",
        "POST /did-templates",
        trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
    ),
    (
        "DELETE",
        "/did-templates/{name}",
        "DELETE /did-templates/{name}",
        trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0,
    ),
    (
        "GET",
        "/did-templates/{name}",
        "GET /did-templates/{name}",
        trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
    ),
    (
        "PUT",
        "/did-templates/{name}",
        "PUT /did-templates/{name}",
        trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0,
    ),
    (
        "POST",
        "/did-templates/{name}/render",
        "POST /did-templates/{name}/render",
        trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0,
    ),
    ("GET", "/keys", "GET /keys", trust_tasks::TASK_KEYS_LIST_0_1),
    (
        "POST",
        "/keys",
        "POST /keys",
        trust_tasks::TASK_KEYS_CREATE_0_1,
    ),
    (
        "POST",
        "/keys/derive-and-sign",
        "POST /keys/derive-and-sign",
        trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_0_1,
    ),
    (
        "POST",
        "/keys/derive-and-sign-document",
        "POST /keys/derive-and-sign-document",
        trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_DOCUMENT_0_1,
    ),
    (
        "POST",
        "/keys/import",
        "POST /keys/import",
        trust_tasks::TASK_KEYS_IMPORT_0_1,
    ),
    (
        "GET",
        "/keys/seeds",
        "GET /keys/seeds",
        trust_tasks::TASK_SEEDS_LIST_1_0,
    ),
    (
        "POST",
        "/keys/seeds/rotate",
        "POST /keys/seeds/rotate",
        trust_tasks::TASK_SEEDS_ROTATE_1_0,
    ),
    (
        "DELETE",
        "/keys/{key_id}",
        "DELETE /keys/{key_id}",
        trust_tasks::TASK_KEYS_REVOKE_0_1,
    ),
    (
        "GET",
        "/keys/{key_id}",
        "GET /keys/{key_id}",
        trust_tasks::TASK_KEYS_SHOW_0_1,
    ),
    (
        "PATCH",
        "/keys/{key_id}",
        "PATCH /keys/{key_id}",
        trust_tasks::TASK_KEYS_RENAME_0_1,
    ),
    (
        "GET",
        "/keys/{key_id}/secret",
        "GET /keys/{key_id}/secret",
        trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0,
    ),
    (
        "POST",
        "/keys/{key_id}/sign",
        "POST /keys/{key_id}/sign",
        trust_tasks::TASK_KEYS_SIGN_0_1,
    ),
    (
        "POST",
        "/vta/restart",
        "POST /vta/restart",
        trust_tasks::TASK_MANAGEMENT_RELOAD_SERVICES_1_0,
    ),
    (
        "GET",
        "/webvh/dids",
        "GET /webvh/dids",
        trust_tasks::TASK_WEBVH_DIDS_LIST_1_0,
    ),
    (
        "POST",
        "/webvh/dids",
        "POST /webvh/dids",
        trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
    ),
    (
        "DELETE",
        "/webvh/dids/{did}",
        "DELETE /webvh/dids/{did}",
        trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0,
    ),
    (
        "GET",
        "/webvh/dids/{did}",
        "GET /webvh/dids/{did}",
        trust_tasks::TASK_WEBVH_DIDS_GET_1_0,
    ),
    (
        "GET",
        "/webvh/dids/{did}/log",
        "GET /webvh/dids/{did}/log",
        trust_tasks::TASK_WEBVH_DIDS_GET_1_0,
    ),
    (
        "POST",
        "/webvh/dids/{did}/register-server",
        "POST /webvh/dids/{did}/register-server",
        trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
    ),
    (
        "GET",
        "/webvh/servers",
        "GET /webvh/servers",
        trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0,
    ),
    (
        "POST",
        "/webvh/servers",
        "POST /webvh/servers",
        trust_tasks::TASK_WEBVH_SERVERS_REGISTER_1_0,
    ),
    (
        "DELETE",
        "/webvh/servers/{id}",
        "DELETE /webvh/servers/{id}",
        trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0,
    ),
    (
        "PATCH",
        "/webvh/servers/{id}",
        "PATCH /webvh/servers/{id}",
        trust_tasks::TASK_WEBVH_SERVERS_REGISTER_1_0,
    ),
    (
        "GET",
        "/webvh/servers/{id}/domains",
        "GET /webvh/servers/{id}/domains",
        trust_tasks::TASK_WEBVH_SERVERS_DOMAINS_0_1,
    ),
    (
        "GET",
        "/webvh/servers/{id}/reconcile",
        "GET /webvh/servers/{id}/reconcile",
        trust_tasks::TASK_WEBVH_SERVERS_RECONCILE_0_1,
    ),
    // ─── /services/* ────────────────────────────────────────────────────
    //
    // These twenty were the last block with no twin at all, which is why the
    // note above used to exclude them. trust-tasks #243 specified the family
    // and the handlers landed alongside this, so they are superseded like
    // everything else — and the metric now covers the whole retirement
    // candidate set rather than most of it.
    //
    // Four verbs collapse across four transports because the task is
    // parameterised by `service`: sixteen routes point at four tasks. The two
    // drain routes share a path and split on method — GET lists what is
    // draining, POST cancels a drain — which is why they map to different
    // successors despite the identical path.
    (
        "GET",
        "/services",
        "GET /services",
        trust_tasks::TASK_SERVICES_LIST_1_0,
    ),
    (
        "GET",
        "/services/didcomm",
        "GET /services/didcomm",
        trust_tasks::TASK_SERVICES_GET_1_0,
    ),
    (
        "GET",
        "/services/didcomm/drain",
        "GET /services/didcomm/drain",
        trust_tasks::TASK_SERVICES_DRAIN_LIST_1_0,
    ),
    (
        "POST",
        "/services/didcomm/disable",
        "POST /services/didcomm/disable",
        trust_tasks::TASK_SERVICES_DISABLE_1_0,
    ),
    (
        "POST",
        "/services/didcomm/drain",
        "POST /services/didcomm/drain",
        trust_tasks::TASK_SERVICES_DRAIN_CANCEL_1_0,
    ),
    (
        "POST",
        "/services/didcomm/enable",
        "POST /services/didcomm/enable",
        trust_tasks::TASK_SERVICES_ENABLE_1_0,
    ),
    (
        "POST",
        "/services/didcomm/rollback",
        "POST /services/didcomm/rollback",
        trust_tasks::TASK_SERVICES_ROLLBACK_1_0,
    ),
    (
        "POST",
        "/services/didcomm/update",
        "POST /services/didcomm/update",
        trust_tasks::TASK_SERVICES_UPDATE_1_0,
    ),
    (
        "POST",
        "/services/rest/disable",
        "POST /services/rest/disable",
        trust_tasks::TASK_SERVICES_DISABLE_1_0,
    ),
    (
        "POST",
        "/services/rest/enable",
        "POST /services/rest/enable",
        trust_tasks::TASK_SERVICES_ENABLE_1_0,
    ),
    (
        "POST",
        "/services/rest/rollback",
        "POST /services/rest/rollback",
        trust_tasks::TASK_SERVICES_ROLLBACK_1_0,
    ),
    (
        "POST",
        "/services/rest/update",
        "POST /services/rest/update",
        trust_tasks::TASK_SERVICES_UPDATE_1_0,
    ),
    (
        "POST",
        "/services/tsp/disable",
        "POST /services/tsp/disable",
        trust_tasks::TASK_SERVICES_DISABLE_1_0,
    ),
    (
        "POST",
        "/services/tsp/enable",
        "POST /services/tsp/enable",
        trust_tasks::TASK_SERVICES_ENABLE_1_0,
    ),
    (
        "POST",
        "/services/tsp/rollback",
        "POST /services/tsp/rollback",
        trust_tasks::TASK_SERVICES_ROLLBACK_1_0,
    ),
    (
        "POST",
        "/services/tsp/update",
        "POST /services/tsp/update",
        trust_tasks::TASK_SERVICES_UPDATE_1_0,
    ),
    (
        "POST",
        "/services/webauthn/disable",
        "POST /services/webauthn/disable",
        trust_tasks::TASK_SERVICES_DISABLE_1_0,
    ),
    (
        "POST",
        "/services/webauthn/enable",
        "POST /services/webauthn/enable",
        trust_tasks::TASK_SERVICES_ENABLE_1_0,
    ),
    (
        "POST",
        "/services/webauthn/rollback",
        "POST /services/webauthn/rollback",
        trust_tasks::TASK_SERVICES_ROLLBACK_1_0,
    ),
    (
        "POST",
        "/services/webauthn/update",
        "POST /services/webauthn/update",
        trust_tasks::TASK_SERVICES_UPDATE_1_0,
    ),
];

/// Middleware: tag any response served by a superseded REST route.
///
/// A layer rather than a call inside each of the 56 handlers, because the
/// per-handler form has to thread a `HeaderMap` back through the return type —
/// and a handler with several `Ok(...)` arms only has to miss one for its route
/// to go quiet and read as "nobody calls this any more". Since the whole point
/// is to delete routes on the strength of a zero reading, a signal that can be
/// half-applied is worse than none. Matching on [`MatchedPath`] cannot be.
pub async fn mark_superseded(req: Request, next: Next) -> Response {
    let hit = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .and_then(|path| {
            let method = req.method().as_str();
            SUPERSEDED
                .iter()
                .find(|(m, p, _, _)| *m == method && *p == path)
        })
        .copied();

    let mut resp = next.run(req).await;

    if let Some((_, _, label, successor)) = hit {
        // Only a response the route actually produced counts as usage. A 404,
        // or a request rejected before it reached the handler, says nothing
        // about a client depending on this route — counting those would hold
        // the metric off zero forever and the route could never be retired.
        if resp.status().is_success() {
            resp.headers_mut().extend(superseded(label, successor));
        }
    }
    resp
}
