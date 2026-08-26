//! How this service retires things, in two halves.
//!
//! **Legacy REST routes** that a canonical `/api/trust-tasks` Trust-Task now
//! supersedes. These routes keep working — the deprecation is advisory. We add
//! response headers so clients can detect the deprecation and migrate, and
//! increment a hit counter (`deprecated_route_requests_total`, labelled by
//! route) so that removal can be gated on **observed usage dropping to zero**
//! rather than a guessed calendar date. (No `Sunset` date is emitted for that
//! reason.) The canonical replacement for every route marked here is the same
//! operation dispatched as a Trust-Task via `POST /api/trust-tasks` (reachable
//! over REST, DIDComm, and TSP through the shared `dispatch_trust_task_core`
//! spine).
//!
//! **Superseded Trust Task URIs**, further down. Same rule, same evidence:
//! `deprecated_trust_task_requests_total` labelled by URI, a successor named
//! in the response so a client can act rather than guess, and removal on an
//! observed zero. Added in #1045, because until then a task could be retired
//! only by deleting it and the only evidence available was a source audit —
//! grep the repos we can see and reason about the rest.
//!
//! Both tables are pinned to the thing they describe by a test, because a row
//! that outlives its route or its handler reads zero forever and **that is the
//! same reading as "safe to delete"**. See
//! `every_superseded_row_names_a_live_route` (`tests/api_integration.rs`) and
//! `superseded_tasks_are_dispatched` (`crate::trust_tasks`).
//!
//! One consequence worth naming: a URI can now leave
//! `UNSPECCED_DISPATCHED_URIS` (or `vtc-service`'s `UNPUBLISHED_CANONICAL_OK`)
//! by *ceasing to exist* rather than by gaining a spec. Both censuses shrink
//! monotonically by test, so that departure looks identical to progress in the
//! count alone. A row here, and its removal, is the explicit record of which
//! one happened.

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
    // ─── the Trust-Task endpoint itself ─────────────────────────────────
    //
    // `/api/trust-tasks` is not superseded by a *task* — it IS the task
    // endpoint. What supersedes it is the conformant spelling served beside
    // it, `POST /trust-tasks`, which is what the published HTTPS binding asks
    // for. The successor URI below is the envelope type rather than an
    // operation, because there is no operation: the successor is the same
    // dispatcher at the path the binding actually uses.
    //
    // The successor is a PATH, not a task URI — every other row here names the
    // task that replaced an operation, and this one names the endpoint that
    // replaced a spelling. `Link: rel="successor-version"` takes a URI either
    // way, so the header stays meaningful; the row is simply the one place in
    // this table where the successor is not a `trusttasks.org` URI.
    //
    // Marked so the existing metric governs its retirement like everything
    // else. It cannot go until deployed clients stop asking for it, and those
    // clients are our own SDK until it takes the change beside this one.
    (
        "POST",
        "/api/trust-tasks",
        "POST /api/trust-tasks",
        "/trust-tasks",
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

// ─── The superseded-task table ─────────────────────────────────────────────
//
// The Trust-Task half of everything above. A REST route gets `Deprecation:
// true`, a `Link: rel="successor-version"`, and a per-route hit counter, so it
// can be removed on evidence. A Trust Task URI had none of that: it could be
// retired only by deleting it, and the only available evidence was a source
// audit — grep this repo and the ones we can see, and reason about the rest.
// That was defensible for `vta/discovery/capabilities/1.0` (#1044: zero
// consumers anywhere, plus a member whose vocabulary corresponded to nothing)
// and it does not generalise. The next retirement may be one somebody is
// calling, and we would find out from a support ticket.
//
// ## Invention, not adoption — the framework has no signal to adopt
//
// Checked first, per #1045. The *registry* has the concept: a spec's front
// matter can say `status: retired` with `supersededBy`, which is how twelve
// `messaging/*` tasks were retired upstream. `trust-tasks-rs` (0.11) exposes
// none of it — `schema_index` maps URI → payload schema and nothing else,
// `Payload` carries `IS_BEARER` / `IS_PROOF_REQUIRED` and no lifecycle
// constant, and `trust-task-discovery/0.1`'s expanded `supportedTypes` entry is
// `additionalProperties: false` over `{type, requiredExt}`. So a consumer
// cannot read a task's retirement status at runtime and a producer has nowhere
// framework-defined to announce one. This stays local machinery until that
// changes; the vocabulary deliberately matches the registry's (`supersededBy`)
// so adopting a published signal later is a rename, not a redesign.

/// One Trust Task the VTA still dispatches and intends to stop dispatching.
///
/// Rows are added when a task is superseded and removed when the task itself
/// is — retirement is gated on `deprecated_trust_task_requests_total` reaching
/// zero for the URI, exactly as route removal is gated on
/// `deprecated_route_requests_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersededTask {
    /// The Type URI clients still send. MUST be one the dispatch spine
    /// actually routes — pinned by `superseded_tasks_are_dispatched` in
    /// `crate::trust_tasks`. A row for a URI nothing dispatches reads zero
    /// forever, which is the "safe to delete" signal produced about something
    /// already deleted.
    pub uri: &'static str,
    /// The Type URI to send instead. Named on the wire so a client can act
    /// rather than guess.
    pub successor: &'static str,
    /// Why, in one line, rendered to the caller alongside the successor.
    pub reason: &'static str,
}

/// The table.
///
/// Seeded from what this workspace had already declared deprecated in prose:
/// the eleven dispatched URIs carrying `#[deprecated]` in
/// `vta_sdk::trust_tasks`, each naming its 0.2 successor. Those attributes
/// told a Rust caller to migrate and told a wire caller nothing at all, and no
/// instrument anywhere said whether anyone was still sending them.
///
/// `auth/passkey/login/{start,finish}/0.1` are deprecated too and are
/// deliberately **absent**: they are `REST_ROUTED_URIS`, served by dedicated
/// unauthenticated routes the dispatcher never sees, so a row here would count
/// nothing and read a permanent zero.
///
/// Naming the gap rather than hiding it: those two are covered by *neither*
/// instrument. The route table above excludes `/auth/*` on purpose (genuinely
/// REST, and the pre-login bootstrap that has to work before a Trust Task can
/// be authenticated at all), and a per-route counter could not separate 0.1
/// from 0.2 anyway — one path serves both and the only difference is the
/// casing of a `purpose` value inside the body. Distinguishing them needs a
/// counter inside those two handlers, which is its own change.
#[allow(deprecated)] // names the deprecated 0.1 URIs on purpose — that is the point
const SUPERSEDED_TASKS: &[SupersededTask] = &[
    // ── auth ────────────────────────────────────────────────────────────
    SupersededTask {
        uri: trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1,
        successor: trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2,
        reason: "0.2 spells the evidence enum `didSigned` in camelCase; the payload is \
                 signed, so the two versions have separate typed handlers rather than \
                 an edge transform",
    },
    // ── device ──────────────────────────────────────────────────────────
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_REGISTER_0_1,
        successor: trust_tasks::TASK_DEVICE_REGISTER_0_2,
        reason: "0.2 spells the enum values in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_HEARTBEAT_0_1,
        successor: trust_tasks::TASK_DEVICE_HEARTBEAT_0_2,
        reason: "0.2 spells the enum values in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_LIST_0_1,
        successor: trust_tasks::TASK_DEVICE_LIST_0_2,
        reason: "0.2 spells the enum values in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_DEVICE_SET_WAKE_0_1,
        successor: trust_tasks::TASK_DEVICE_SET_WAKE_0_2,
        reason: "no enum values changed; the bump is canonical-version alignment, so \
                 the whole device slice sits on one version",
    },
    // ── vault ───────────────────────────────────────────────────────────
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_LIST_0_1,
        successor: trust_tasks::TASK_VAULT_LIST_0_2,
        reason: "0.2 spells secretKind and the related enums in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_GET_0_1,
        successor: trust_tasks::TASK_VAULT_GET_0_2,
        reason: "0.2 spells the response enums in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_UPSERT_0_1,
        successor: trust_tasks::TASK_VAULT_UPSERT_0_2,
        reason: "0.2 spells the secretKind / sealed-envelope / target enums in camelCase",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_RELEASE_0_1,
        successor: trust_tasks::TASK_VAULT_RELEASE_0_2,
        reason: "0.2 spells the secretKind / sealed-envelope / step-up-proof enums in \
                 camelCase, inside the sealed cleartext as well as around it",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1,
        successor: trust_tasks::TASK_VAULT_PROXY_LOGIN_0_2,
        reason: "0.2 spells the site-target / step-up-proof enums in camelCase, inside \
                 the sealed cleartext as well as around it",
    },
    SupersededTask {
        uri: trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1,
        successor: trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_2,
        reason: "0.2 spells the step-up-proof enums in camelCase",
    },
];

/// The table, for the dispatch spine and for tests that assert on its contents.
pub fn superseded_tasks_table() -> &'static [SupersededTask] {
    SUPERSEDED_TASKS
}

/// The row for `type_uri`, or `None` when the task is not superseded.
pub fn superseded_task(type_uri: &str) -> Option<&'static SupersededTask> {
    SUPERSEDED_TASKS.iter().find(|t| t.uri == type_uri)
}

/// Top-level document member carrying the deprecation notice.
///
/// A reverse-DNS name, matching SPEC §4.5.1's `ext` namespace convention and
/// the `org.openvtc.*` names this workspace already uses (`vault-session`,
/// `authorization-context`, `purpose`).
///
/// **Document level, not `payload.ext`.** The framework's envelope keeps
/// unrecognized top-level members in `TrustTask::extra`, and SPEC §7.1/§7.2
/// tells consumers to preserve rather than reject them, so a member here
/// cannot break a client that has never heard of it. `payload` can make no
/// such promise: every published payload schema is `additionalProperties:
/// false`, the generated `Response` types are `deny_unknown_fields`, and the
/// conformance sweep validates response payloads against those schemas — so a
/// member there would have to go in per-spec, and only for specs whose schema
/// happens to define `ext`. This is the Trust-Task analogue of putting the
/// REST signal in a header: beside the answer rather than inside it.
pub const DEPRECATION_MEMBER: &str = "org.openvtc.deprecation";

/// Record a dispatch of a superseded task.
///
/// Unlike [`mark_superseded`], this counts the request whatever the outcome.
/// The route middleware filters non-success responses because an unauthorised
/// request there says nothing about a client depending on the route — those
/// routes are reachable without credentials. The dispatch spine is behind
/// authentication on all three transports (bearer on REST, authcrypt sender on
/// DIDComm, VID on TSP), so there is no unauthenticated-prober class to filter
/// out: an authenticated party emitting this URI *is* the usage being
/// measured, whether or not its payload turned out to be well-formed.
pub fn note_superseded_task(task: &SupersededTask) {
    counter!("deprecated_trust_task_requests_total", "task" => task.uri).increment(1);
}

/// Stamp the deprecation notice onto a serialized response document.
///
/// Refuses to touch a document carrying a `proof`: adding a member after
/// signing voids the signature, and a silently-invalid proof is worse than an
/// absent notice. Also a no-op on a body that is not a JSON object, or that
/// already carries the member.
pub fn annotate_superseded(body: &mut Vec<u8>, task: &SupersededTask) {
    let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(body) else {
        return;
    };
    let Some(obj) = doc.as_object_mut() else {
        return;
    };
    if obj.contains_key("proof") || obj.contains_key(DEPRECATION_MEMBER) {
        return;
    }
    obj.insert(
        DEPRECATION_MEMBER.to_string(),
        serde_json::json!({
            "supersededBy": task.successor,
            "reason": task.reason,
        }),
    );
    if let Ok(bytes) = serde_json::to_vec(&doc) {
        *body = bytes;
    }
}

#[cfg(test)]
mod superseded_task_tests {
    use super::*;

    #[test]
    fn a_notice_rides_the_document_top_level_not_the_payload() {
        let task = &SUPERSEDED_TASKS[0];
        let mut body = serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/device/list/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "devices": [] },
        }))
        .unwrap();

        annotate_superseded(&mut body, task);

        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc[DEPRECATION_MEMBER]["supersededBy"], task.successor);
        assert_eq!(doc[DEPRECATION_MEMBER]["reason"], task.reason);
        // The payload is what a published schema validates and what a generated
        // `Response` type deserialises with `deny_unknown_fields`. It must come
        // back unchanged.
        assert_eq!(doc["payload"], serde_json::json!({ "devices": [] }));
    }

    #[test]
    fn a_signed_document_is_left_alone() {
        // Stamping a member into a signed document voids the proof over it. A
        // notice is worth less than a verifiable signature, so the notice loses.
        let task = &SUPERSEDED_TASKS[0];
        let original = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/device/list/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
            "proof": { "type": "DataIntegrityProof" },
        });
        let mut body = serde_json::to_vec(&original).unwrap();

        annotate_superseded(&mut body, task);

        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc, original,
            "a proofed document must be returned untouched"
        );
    }

    #[test]
    fn annotating_twice_does_not_nest_or_duplicate() {
        // The spine annotates exactly once today — the idempotency store
        // records the un-annotated outcome and the replay is annotated on its
        // way out like any other. This pins the helper against a future caller
        // that does not preserve that ordering: a second stamp must be a no-op,
        // not a nested or duplicated notice.
        let task = &SUPERSEDED_TASKS[0];
        let mut body = serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:1",
            "type": "x",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .unwrap();

        annotate_superseded(&mut body, task);
        let once = body.clone();
        annotate_superseded(&mut body, task);

        assert_eq!(body, once);
    }

    #[test]
    fn a_body_that_is_not_a_document_is_left_alone() {
        // `error_response` falls back to an empty body when serialisation
        // fails. Annotation must not turn that into a panic or a fake document.
        let task = &SUPERSEDED_TASKS[0];
        let mut empty: Vec<u8> = Vec::new();
        annotate_superseded(&mut empty, task);
        assert!(empty.is_empty());

        let mut array = b"[1,2,3]".to_vec();
        annotate_superseded(&mut array, task);
        assert_eq!(array, b"[1,2,3]");
    }

    #[test]
    fn every_row_names_a_different_successor() {
        // A row whose successor is itself would advertise "migrate to where you
        // already are" and could never be retired.
        for t in SUPERSEDED_TASKS {
            assert_ne!(
                t.uri, t.successor,
                "{} is listed as its own successor",
                t.uri
            );
            assert!(!t.reason.is_empty(), "{} has no reason", t.uri);
        }
    }

    #[test]
    fn no_uri_is_listed_twice() {
        // `superseded_task` returns the first match, so a duplicate would make
        // one of the two rows unreachable — and unreachable is exactly what a
        // zero reading means.
        let mut seen: Vec<&str> = SUPERSEDED_TASKS.iter().map(|t| t.uri).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "a URI is listed more than once");
    }
}
