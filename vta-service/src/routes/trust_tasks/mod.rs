//! `POST /api/trust-tasks` — the VTA-side trust-task dispatcher.
//!
//! Mirrors `affinidi-webvh-service`'s `did-hosting-control` dispatcher
//! (`routes/trust_tasks.rs`) — body shape, error envelope, and routing
//! semantics are byte-equivalent.
//!
//! ## Module layout
//!
//! - [`helpers`]: shared wire-shape helpers (`parse_payload`,
//!   `reject_with`, `success_response`, `app_error_to_reject`, etc.)
//!   used by every slice's handler module. `pub(super)` only.
//! - One module per Phase 3 slice (`auth`, `acl`, `contexts`, `keys`,
//!   `seeds`, `audit`, `discovery`, …). Each module's handler
//!   functions are `pub(super) async fn handle_<op>(state, auth, doc)
//!   -> Response`. The dispatcher's match arms call them.
//! - The cross-crate URI parity harness lives in the test module
//!   below; it asserts every URI declared in `vta-sdk::trust_tasks`
//!   is either dispatched or on the `REST_ROUTED` allowlist.
//!
//! ## Adding a new URI
//!
//! 1. Add the `TASK_*` const to `vta-sdk::trust_tasks` and extend its
//!    `ALL_URIS` array.
//! 2. Add a `handle_*` function in the appropriate slice module
//!    (create a new one if no slice fits).
//! 3. Add a match arm in `dispatch_typed` that calls the handler.
//! 4. Add the URI to the `dispatched` array in
//!    `tests::dispatcher_handles_every_vta_sdk_uri`.
//!
//! ## Body-parse failures emit framework-conformant errors
//!
//! Like the webvh-service dispatcher, we accept the body as
//! `axum::body::Bytes` and parse to `TrustTask<Value>` by hand so a
//! malformed body produces a `trust-task-error/0.1` document (per
//! framework SPEC §8.5) instead of axum's plain-text 400 default.

use axum::extract::State;
use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

mod acl;
mod audit;
mod auth;
mod backup;
mod config;
mod contexts;
mod device;
mod did_templates;
mod discovery;
mod helpers;
mod keys;
mod management;
#[cfg(all(feature = "webvh", feature = "didcomm"))]
mod passkey_vms;
#[cfg(feature = "webvh")]
mod provision_integration;
mod seeds;
// `pub(crate)` so the DIDComm message handlers can reach `resolve_step_up`
// to honour step-up floors on that transport too (P0.13). The step-up engine
// living under `routes/` is a known layering wrinkle that P2.4 relocates to
// `operations/`.
pub(crate) mod step_up;
mod step_up_policy;
pub(crate) use step_up::{
    AclChangeRoleOp, AclGrantOp, AclRevokeOp, AclSwapKeyOp, ContextDeleteOp, RequireStepUp,
};
mod vault;
#[cfg(feature = "webvh")]
mod webvh;
mod wire_v0_2;

use helpers::{body_parse_error_response, method_not_found, reject_with};
#[cfg(feature = "didcomm")]
use trust_tasks_rs::RejectReason;

/// URIs that the VTA exposes through dedicated unauth REST routes
/// rather than the authenticated `/api/trust-tasks` dispatcher.
///
/// Per the feature-gating convention in
/// `docs/05-design-notes/trust-task-feature-gating.md`: the parity
/// harness accepts these as "tracked" without requiring a dispatcher
/// arm. The corresponding handlers live in `routes::auth` (passkey
/// login, legacy challenge/authenticate/refresh) and
/// `routes::attestation` (TEE status / report).
// `#[allow(deprecated)]`: this intentionally names the deprecated passkey-login
// 0.1 URIs — they remain REST-routed and dual-accepted during the migration.
#[allow(dead_code, deprecated)] // consumed by the dispatcher's test-only parity harness
const REST_ROUTED: &[&str] = &[
    // Auth (pre-login — no session, can't pass AuthClaims)
    vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1,
    vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1,
    vta_sdk::trust_tasks::TASK_AUTH_REFRESH_0_1,
    vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_1,
    vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1,
    // Passkey-login 0.2: the only 0.1→0.2 delta in the spec is the `purpose`
    // enum value (`step-up`→`stepUp`), and the VTA's flat-JSON request/response
    // types (`PasskeyLoginStart/FinishRequest`, `…StartResponse`) don't carry
    // `purpose` at all — so a 0.2 client sends structurally identical JSON to
    // the same `/auth/passkey-login/*` handlers. Dual-accept is purely
    // declarative here; no edge transform needed.
    vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_2,
    vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_2,
    // Attestation (unauth — TEE proofs are publicly verifiable by design)
    vta_sdk::trust_tasks::TASK_ATTESTATION_STATUS_1_0,
    vta_sdk::trust_tasks::TASK_ATTESTATION_REPORT_1_0,
];

/// URIs that vta-sdk declares but the dispatcher may not wire in
/// every build because they depend on `vta-service` feature flags
/// (e.g. `webvh`, `didcomm`, `tee`).
///
/// When their feature is **on**, the slice module's `DISPATCHED_URIS`
/// const also lists them, so they're tracked by
/// `aggregate_dispatched_uris()`. When the feature is **off**, the
/// slice module isn't compiled — its const isn't aggregated — so only
/// this allowlist keeps the parity harness from failing on them.
///
/// Adding a URI here is a deliberate act: it says "this URI's
/// dispatch lives behind a feature flag and may be unreachable in
/// some builds, but the URI is canonically declared in vta-sdk."
///
/// All entries are unconditional (don't change per cfg). They're
/// just statements that the dispatcher knows about them.
#[allow(dead_code)] // consumed by the dispatcher's test-only parity harness
const KNOWN_FEATURE_GATED_URIS: &[&str] = &[
    // Passkey-VMs slice — requires `webvh` + `didcomm` features. The
    // slice module's `DISPATCHED_URIS` lists the same URIs and is
    // aggregated by the parity harness when both features are on; this
    // allowlist covers builds where either feature is off.
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1,
    vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1,
    // Provision-integration — requires `webvh`.
    vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_REQUEST_1_0,
    // WebVH-DID-lifecycle slice — requires `webvh`. The slice
    // module's `DISPATCHED_URIS` lists the same URIs and is
    // aggregated by the parity harness when `webvh` is on; this
    // allowlist covers builds where `webvh` is off.
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_ADD_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_UPDATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_LOG_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0,
    vta_sdk::trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
    // did-management Trust-Task spec URIs — declared in vta-sdk by
    // PR #139 ("PR 1 of N") as the shared vocabulary for the
    // cross-repo did-management migration (vta-sdk + vta-service +
    // affinidi-webvh-service all reference these). They are
    // **outbound producer URIs** — VTA's `webvh_didcomm.rs` sends
    // requests with these URIs to did-hosting, then matches
    // `<uri>#response` on the way back. They are not consumed by any
    // vta-service inbound dispatcher arm, so the parity harness
    // treats them like the feature-gated URIs above (declared
    // canonically, intentionally not in `DISPATCHED_URIS`). Removing
    // an entry here without a corresponding dispatcher addition will
    // surface as a parity-harness failure pointing back at this list.
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_PUBLISH_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_DELETE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_ENABLE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_DISABLE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_LIST_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_INFO_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_CHECK_NAME_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_CHANGE_OWNER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_ROLLBACK_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DID_PROBLEM_REPORT_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_CREATE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_UPDATE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_DISABLE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_PURGE_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_SET_DEFAULT_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_ASSIGN_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_UNASSIGN_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_SERVER_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_SERVER_HEALTH_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_SERVER_STATS_SYNC_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_REGISTRY_ADMIN_REGISTER_0_1,
    vta_sdk::trust_tasks::TASK_DID_MANAGEMENT_REGISTRY_DEREGISTER_0_1,
];

/// Aggregate `DISPATCHED_URIS` from every slice module. Feature-gated
/// slices contribute only when their cfg is satisfied — this is the
/// load-bearing detail that lets `KNOWN_FEATURE_GATED_URIS` work as a
/// shrunk-build allowlist.
#[cfg(test)]
fn aggregate_dispatched_uris() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    v.extend(acl::DISPATCHED_URIS);
    v.extend(audit::DISPATCHED_URIS);
    v.extend(auth::DISPATCHED_URIS);
    v.extend(backup::DISPATCHED_URIS);
    v.extend(config::DISPATCHED_URIS);
    v.extend(contexts::DISPATCHED_URIS);
    v.extend(device::DISPATCHED_URIS);
    v.extend(did_templates::DISPATCHED_URIS);
    v.extend(discovery::DISPATCHED_URIS);
    v.extend(keys::DISPATCHED_URIS);
    v.extend(management::DISPATCHED_URIS);
    v.extend(seeds::DISPATCHED_URIS);
    v.extend(step_up::DISPATCHED_URIS);
    v.extend(step_up_policy::DISPATCHED_URIS);
    v.extend(vault::DISPATCHED_URIS);
    // Feature-gated slices add their `v.extend(slice::DISPATCHED_URIS)`
    // here under `#[cfg(feature = "...")]`. The corresponding URIs
    // must also appear in `KNOWN_FEATURE_GATED_URIS` so the parity
    // harness passes in builds where the feature is off.
    #[cfg(all(feature = "webvh", feature = "didcomm"))]
    v.extend(passkey_vms::DISPATCHED_URIS);
    #[cfg(feature = "webvh")]
    v.extend(provision_integration::DISPATCHED_URIS);
    #[cfg(feature = "webvh")]
    v.extend(webvh::DISPATCHED_URIS);
    v
}

/// `POST /api/trust-tasks` handler.
///
/// Bearer-auth'd via [`AuthClaims`]; the caller's DID is the
/// transport-authenticated peer for SPEC.md §4.8.1 precedence inside
/// each typed handler.
///
/// Body is accepted as raw bytes so a parse failure surfaces as a
/// `trust-task-error/0.1` document with `code: malformed_request`
/// rather than axum's text/plain default. The route mount caps body
/// size separately (the workspace-wide 1 MB cap applies).
pub async fn dispatch_trust_task(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    Ok(dispatch_trust_task_core(&state, &auth, &body).await)
}

/// Transport-agnostic trust-task dispatch core.
///
/// Parses the envelope bytes and dispatches by `type` URI, returning
/// the framework result/error document wrapped in a `Response` (the
/// status code comes from the framework's status table). Shared by:
/// - the REST route [`dispatch_trust_task`] (returns the `Response` as-is), and
/// - the DIDComm trust-task handler
///   (`crate::messaging::handlers::handle_trust_task`), which decomposes
///   the `Response` body into a DIDComm reply.
///
/// `body` is the full `TrustTask<Value>` envelope JSON — the HTTP POST
/// body on REST, the DIDComm message body on DIDComm.
pub(crate) async fn dispatch_trust_task_core(
    state: &AppState,
    auth: &AuthClaims,
    body: &[u8],
) -> Response {
    // 1. Parse the envelope.
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => return body_parse_error_response(&e.to_string()),
    };

    // 2. Framework §7.2 items 4 + 5 — expiry + recipient
    //    enforcement. Closes L5 from the May 2026 security
    //    review: the hand-rolled dispatcher previously skipped
    //    these, so a Trust-Task envelope addressed at a
    //    different recipient would be silently accepted and an
    //    expired envelope would be honoured.
    //
    //    Audience binding (proof + recipient required for non-
    //    bearer specs, framework §7.2 item 8) is typed —
    //    `enforce_audience_binding` needs `P: Payload`, so each
    //    slice's typed handler runs it after `parse_payload`.
    {
        let vta_did = state.config.read().await.vta_did.clone();
        if let Some(my_vid) = vta_did.as_deref()
            && let Err(reason) = doc.validate_basic(chrono::Utc::now(), my_vid)
        {
            return reject_with(&doc, reason);
        }
        // No vta_did configured → service is in setup; skip
        // the recipient check (no identity to bind against).
        // Production VTAs always have vta_did set by `vta setup`.
    }

    // 3. Session-pubkey binding pre-check.
    //
    // Once `AuthClaims` carries `session_pubkey_b58btc` (Phase 3 work,
    // mirrors `webvh-service`'s pattern) the dispatcher will enforce
    // that the proof's `verificationMethod` matches the JWT-bound
    // pubkey before any handler runs. Phase 2 scaffold elides this —
    // no passkey-bound sessions exist yet on the VTA side.
    let _ = auth;

    // 4. Dispatch by type URI.
    //
    // 0.2 dual-accept: bearer-authed specs whose only 0.1→0.2 delta is
    // enum-value casing are down-converted to their canonical 0.1 form,
    // dispatched through the existing 0.1 handler, and the response
    // up-converted back to 0.2 (see `wire_v0_2`). Signed-payload specs are NOT
    // routed here — they have typed 0.2 arms in `dispatch_typed`.
    let type_uri = doc.type_uri.to_string();
    if let Some(spec) = wire_v0_2::lookup_0_2(&type_uri) {
        let mut doc = doc;
        wire_v0_2::downconvert_request(&mut doc.payload, spec);
        if let Ok(uri_0_1) = spec.uri_0_1.parse() {
            doc.type_uri = uri_0_1;
        }
        let resp = dispatch_typed(state, auth, doc).await;
        return wire_v0_2::upconvert_response(resp, spec).await;
    }
    dispatch_typed(state, auth, doc).await
}

/// Build a Trust-Task rejection `Response` for a request whose envelope
/// bytes are in `body`, WITHOUT dispatching it.
///
/// The DIDComm trust-task handler uses this when it can't authorize the
/// transport peer (no ACL entry), so the reply is still a proper
/// Trust-Task error document — not a DIDComm problem-report, which a
/// conformant Trust-Task client can't read. (On REST the JWT extractor
/// rejects unauthenticated callers before dispatch, so this gap is
/// DIDComm-only — hence the feature gate.)
#[cfg(feature = "didcomm")]
pub(crate) fn reject_trust_task(body: &[u8], reason: RejectReason) -> Response {
    match serde_json::from_slice::<TrustTask<Value>>(body) {
        Ok(doc) => reject_with(&doc, reason),
        Err(e) => body_parse_error_response(&e.to_string()),
    }
}

/// Type-dispatch over the inbound document's `type` URI.
///
/// Each match arm delegates to the slice's `handle_*` function. Phase
/// 3 slices land in their own modules — new slices add a `mod foo;`
/// declaration at the top and a match arm here.
///
/// Unknown URIs fall through to `method_not_found` which returns
/// `unsupported_type` per the framework's status table.
///
/// `#[allow(deprecated)]`: the device / vault / step-up / passkey arms match on
/// the deprecated `*_0_1` URI constants on purpose — the VTA keeps serving 0.1
/// during the migration. The 0.2 counterparts arrive pre-down-converted (see
/// `wire_v0_2`) so they match the same arms.
#[allow(deprecated)]
async fn dispatch_typed(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    let type_uri = doc.type_uri.to_string();

    // Note: `passkey-login-{start,finish}/1.0`, `challenge/1.0`,
    // `authenticate/1.0`, and `refresh/1.0` are NOT handled here.
    // They are UNAUTHENTICATED operations served as dedicated REST
    // routes (`/auth/*`) — the user has no session JWT, so they
    // can't pass `AuthClaims` through the dispatcher's extractor.
    // The parity harness's `REST_ROUTED` allowlist tracks them.
    match type_uri.as_str() {
        // ─── Auth slice (authenticated operations) ───────────────────
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_1 => {
            auth::handle_revoke_session(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_AUTH_WHOAMI_0_1 => auth::handle_whoami(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_AUTH_SESSIONS_LIST_0_1 => {
            auth::handle_sessions_list(state, auth, doc).await
        }
        // Dual-accept: both versions route to the same typed handler, which
        // normalises the `evidence.kind` discriminator on a copy (the signed
        // document is never mutated). Not edge-transformed in `wire_v0_2`
        // because the payload carries the approver's signature.
        vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1
        | vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2 => {
            step_up::handle_approve_response(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_AUTH_STEP_UP_POLICY_0_2 => {
            step_up_policy::handle_set_step_up_policy(state, auth, doc).await
        }
        // ─── ACL slice ────────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_ACL_LIST_1_0 => acl::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_CREATE_1_0 => acl::handle_create(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_GET_1_0 => acl::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_UPDATE_1_0 => acl::handle_update(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_DELETE_1_0 => acl::handle_delete(state, auth, doc).await,
        // ─── Device slice ─────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_DEVICE_REGISTER_0_1 => {
            device::handle_register(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DEVICE_HEARTBEAT_0_1 => {
            device::handle_heartbeat(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DEVICE_LIST_0_1 => device::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_DEVICE_DISABLE_0_1 => {
            device::handle_disable(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DEVICE_SET_WAKE_0_1 => {
            device::handle_set_wake(state, auth, doc).await
        }
        // ─── Contexts slice ──────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0 => {
            contexts::handle_list(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0 => {
            contexts::handle_create(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0 => contexts::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0 => {
            contexts::handle_update(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0 => {
            contexts::handle_update_did(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0 => {
            contexts::handle_preview_delete(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0 => {
            contexts::handle_delete(state, auth, doc).await
        }
        // ─── Keys slice ──────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_KEYS_LIST_1_0 => keys::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_CREATE_1_0 => keys::handle_create(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_GET_1_0 => keys::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_RENAME_1_0 => keys::handle_rename(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_REVOKE_1_0 => keys::handle_revoke(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_SIGN_1_0 => keys::handle_sign(state, auth, doc).await,
        // ─── Seeds slice ─────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0 => seeds::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0 => seeds::handle_rotate(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0 => {
            seeds::handle_export_mnemonic(state, auth, doc).await
        }
        // ─── Audit slice ─────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_AUDIT_LIST_LOGS_1_0 => {
            audit::handle_list_logs(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0 => {
            audit::handle_get_retention(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0 => {
            audit::handle_update_retention(state, auth, doc).await
        }
        // ─── Discovery ───────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0 => {
            discovery::handle_capabilities(state, auth, doc).await
        }
        // ─── Vault slice (public 0.1 spec) ──────────────────────────
        vta_sdk::trust_tasks::TASK_VAULT_LIST_0_1 => vault::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_VAULT_GET_0_1 => vault::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_VAULT_UPSERT_0_1 => vault::handle_upsert(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_VAULT_DELETE_0_1 => vault::handle_delete(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_VAULT_RELEASE_0_1 => {
            vault::handle_release(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1 => {
            vault::handle_proxy_login(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1 => {
            vault::handle_sign_trust_task(state, auth, doc).await
        }
        // ─── Config slice ────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_CONFIG_GET_1_0 => config::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_CONFIG_UPDATE_1_0 => {
            config::handle_update(state, auth, doc).await
        }
        // ─── Management slice ────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_MANAGEMENT_RELOAD_SERVICES_1_0 => {
            management::handle_reload_services(state, auth, doc).await
        }
        // ─── Backup slice (descriptor pattern) ───────────────────────
        vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_0 => {
            backup::handle_initiate_export(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_BACKUP_COMPLETE_EXPORT_1_0 => {
            backup::handle_complete_export(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_BACKUP_INITIATE_IMPORT_1_0 => {
            backup::handle_initiate_import(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_BACKUP_FINALIZE_IMPORT_1_0 => {
            backup::handle_finalize_import(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_BACKUP_ABORT_1_0 => backup::handle_abort(state, auth, doc).await,
        // ─── DID-templates slice (global) ────────────────────────────
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_LIST_1_0 => {
            did_templates::handle_list(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_1_0 => {
            did_templates::handle_create(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_1_0 => {
            did_templates::handle_get(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_UPDATE_1_0 => {
            did_templates::handle_update(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_DELETE_1_0 => {
            did_templates::handle_delete(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_RENDER_1_0 => {
            did_templates::handle_render(state, auth, doc).await
        }
        // ─── DID-templates slice (context-scoped) ────────────────────
        vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_LIST_1_0 => {
            did_templates::handle_context_list(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_CREATE_1_0 => {
            did_templates::handle_context_create(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_GET_1_0 => {
            did_templates::handle_context_get(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_UPDATE_1_0 => {
            did_templates::handle_context_update(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_DELETE_1_0 => {
            did_templates::handle_context_delete(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DID_TEMPLATES_RENDER_1_0 => {
            did_templates::handle_context_render(state, auth, doc).await
        }
        // ─── Passkey-VMs slice (feature-gated: webvh + didcomm) ─────
        //
        // Canonical 0.1 only — the pre-spec 1.0 aliases were removed (the
        // browser plugin migrated to 0.1; a 1.0 doc now gets UnsupportedType).
        #[cfg(all(feature = "webvh", feature = "didcomm"))]
        vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1 => {
            passkey_vms::handle_enroll_challenge(state, auth, doc).await
        }
        #[cfg(all(feature = "webvh", feature = "didcomm"))]
        vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1 => {
            passkey_vms::handle_enroll_submit(state, auth, doc).await
        }
        #[cfg(all(feature = "webvh", feature = "didcomm"))]
        vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1 => {
            passkey_vms::handle_list(state, auth, doc).await
        }
        #[cfg(all(feature = "webvh", feature = "didcomm"))]
        vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1 => {
            passkey_vms::handle_revoke(state, auth, doc).await
        }
        // ─── Provision-integration (feature-gated: webvh) ────────────
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_REQUEST_1_0 => {
            provision_integration::handle_request(state, auth, doc).await
        }
        // ─── WebVH-DID-lifecycle slice (feature-gated: webvh) ────────
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0 => {
            webvh::handle_servers_list(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_ADD_1_0 => {
            webvh::handle_servers_add(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_UPDATE_1_0 => {
            webvh::handle_servers_update(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0 => {
            webvh::handle_servers_remove(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0 => {
            webvh::handle_dids_list(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0 => {
            webvh::handle_dids_create(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_1_0 => {
            webvh::handle_dids_get(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_GET_LOG_1_0 => {
            webvh::handle_dids_get_log(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0 => {
            webvh::handle_dids_delete(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0 => {
            webvh::handle_dids_update(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0 => {
            webvh::handle_dids_rotate_keys(state, auth, doc).await
        }
        #[cfg(feature = "webvh")]
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0 => {
            webvh::handle_dids_register_with_server(state, auth, doc).await
        }
        // ─── Unknown / REST-routed ───────────────────────────────────
        //
        // A client mistakenly sending a REST-routed URI through the
        // envelope path gets `unsupported_type` here — correct from
        // the dispatcher's POV; the operation lives elsewhere.
        _ => method_not_found(doc, &type_uri),
    }
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the dispatcher's wire-shape contracts + the
    //! cross-crate URI parity harness. Each arm's actual handler
    //! logic is tested in its owning operations module (or by the
    //! Phase 5 integration suite once full AppState scaffolding is
    //! in place).

    use trust_tasks_rs::TrustTask;

    use super::*;

    #[test]
    fn body_parse_error_wire_shape() {
        let resp = body_parse_error_response("expected `,`");
        // Function returns; full HTTP-shape assertions live in the
        // Phase 5 integration tests once the route is reachable
        // through a real router setup.
        let _ = resp;
    }

    /// Pins the framework's current `TypeUri::from_str` constraint:
    /// the wire-format `type` field MUST use the canonical
    /// `/spec/<slug>/<major.minor>` shape. Flat URIs are rejected.
    ///
    /// If the framework parser relaxes (accepts both), the test fails
    /// on the flat-rejection assert and we know Phase 3 can simplify.
    #[test]
    fn framework_requires_canonical_uri_in_wire_type_field() {
        // Canonical form parses — with HIERARCHICAL slug
        // (`vta/auth/revoke-session`) per SPEC.md slug grammar.
        let canonical = serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/spec/auth/revoke-session/0.1",
            "issuer": "did:example:alice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "session_id": "sess-1" }
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let parsed: Result<TrustTask<Value>, _> = serde_json::from_slice(&bytes);
        assert!(
            parsed.is_ok(),
            "canonical URI must parse: {:?}",
            parsed.err()
        );

        // Flat form is rejected.
        let flat = serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/vta/auth/revoke-session/1.0",
            "issuer": "did:example:alice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "session_id": "sess-1" }
        });
        let bytes = serde_json::to_vec(&flat).unwrap();
        let parsed: Result<TrustTask<Value>, _> = serde_json::from_slice(&bytes);
        assert!(
            parsed.is_err(),
            "flat URI must NOT parse — if this changes, the framework \
             relaxed its parser and Phase 3 design can simplify"
        );
    }

    #[test]
    #[allow(deprecated)] // names the dual-accepted passkey-login 0.1 URIs on purpose
    fn phase_2_uri_registry_present() {
        // Compile-time check: every URI we route in `dispatch_typed`
        // is declared in `vta-sdk::trust_tasks`. If a URI gets renamed
        // or removed in vta-sdk, this stops compiling.
        let _ = vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_REFRESH_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_WHOAMI_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_SESSIONS_LIST_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_1;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1;
    }

    /// Cross-crate URI parity harness (mirrors webvh-service's T9
    /// invariant). Every URI declared in `vta-sdk::trust_tasks` must
    /// either:
    ///
    /// 1. Be tracked by a slice module's `DISPATCHED_URIS` const
    ///    (the slice's handler IS wired into `dispatch_typed`), OR
    /// 2. Be on the `REST_ROUTED` allowlist (served by dedicated
    ///    unauth REST handlers — passkey login, legacy challenge/
    ///    authenticate/refresh, TEE attestation), OR
    /// 3. Be on the `KNOWN_FEATURE_GATED_URIS` allowlist (feature-
    ///    flagged in vta-service and not compiled in this build).
    ///
    /// See `docs/05-design-notes/trust-task-feature-gating.md` for
    /// the full convention.
    ///
    /// Adding a new URI to `vta-sdk::trust_tasks::ALL_URIS` without
    /// doing one of these three fails this test loudly with the
    /// offending URI in the message.
    #[test]
    fn dispatcher_handles_every_vta_sdk_uri() {
        let dispatched = aggregate_dispatched_uris();

        for declared in vta_sdk::trust_tasks::ALL_URIS {
            let in_dispatched = dispatched.contains(declared);
            let in_rest_routed = REST_ROUTED.contains(declared);
            let in_feature_gated = KNOWN_FEATURE_GATED_URIS.contains(declared);
            // 0.2 dual-accept URIs are served via the `wire_v0_2` edge
            // transform (down-convert → 0.1 handler → up-convert), not a
            // dedicated `dispatch_typed` arm, so they're tracked here.
            let in_wire_v0_2 = wire_v0_2::WIRE_V0_2_URIS.contains(declared);

            assert!(
                in_dispatched || in_rest_routed || in_feature_gated || in_wire_v0_2,
                "vta-sdk declares URI `{declared}` but it is not tracked in this dispatcher — \
                 either (a) add it to a slice's `DISPATCHED_URIS` const and wire a match arm, \
                 (b) add it to `REST_ROUTED` if it lives on a dedicated REST route, \
                 (c) add it to `KNOWN_FEATURE_GATED_URIS` with a comment explaining the gating, or \
                 (d) register it in `wire_v0_2::WIRE_V0_2_URIS` if it's an edge-transformed 0.2 URI"
            );
        }
    }

    /// Passkey-VMs: the canonical `…/0.1` URIs are dispatched. The pre-spec
    /// `…/1.0` aliases were removed (the browser plugin migrated to 0.1), so a
    /// 1.0 document now falls through to `UnsupportedType`.
    #[test]
    fn passkey_vms_0_1_dispatched() {
        let dispatched = aggregate_dispatched_uris();
        let tracked = |u: &&str| dispatched.contains(u) || KNOWN_FEATURE_GATED_URIS.contains(u);
        for v0_1 in [
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1,
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1,
        ] {
            assert!(tracked(&v0_1), "canonical 0.1 URI not dispatched: {v0_1}");
            assert!(v0_1.ends_with("/0.1"), "version-label mismatch for {v0_1}");
        }
    }

    /// Defensive guard against double-tracking. A URI should appear in
    /// exactly one of (DISPATCHED_URIS for some slice, REST_ROUTED,
    /// KNOWN_FEATURE_GATED_URIS) — except that
    /// `KNOWN_FEATURE_GATED_URIS` redundantly mirrors a feature-gated
    /// slice's URIs when the feature is on. That redundancy is allowed
    /// (the harness tolerates it); other overlaps would indicate
    /// confusion about which transport a URI uses.
    ///
    /// Specifically: a URI MUST NOT be in BOTH `aggregate_dispatched_uris()`
    /// AND `REST_ROUTED`. That'd mean two handlers compete for it.
    #[test]
    fn no_uri_is_both_dispatched_and_rest_routed() {
        let dispatched = aggregate_dispatched_uris();
        for uri in REST_ROUTED {
            assert!(
                !dispatched.contains(uri),
                "URI `{uri}` is in REST_ROUTED but also in a slice's DISPATCHED_URIS — \
                 a URI must live on exactly one transport"
            );
        }
    }
}
