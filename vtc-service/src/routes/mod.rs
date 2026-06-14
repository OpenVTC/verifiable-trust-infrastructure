mod acl;
mod admin;
#[cfg(feature = "admin-ui")]
mod admin_ui;
mod audit;
mod auth;
mod ceremonies;
mod community;
mod config;
pub(crate) mod did_log;
mod directory;
mod endorsement_types;
mod endorsements;
mod health;
pub(crate) mod install;
pub mod join_requests;
pub(crate) mod members;
pub(crate) mod policies;
pub mod recognise;
mod relationships;
mod schemas;
pub(crate) mod status_lists;
#[cfg(feature = "website")]
mod website;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use vti_common::trust_task::{TrustTask, task_layer, task_routes};

use crate::config::RoutingConfig;
use crate::server::AppState;

/// OpenAPI document root for the VTC REST surface.
///
/// As in the VTA, the router is the single source of truth for *paths*: each
/// handler annotated with `#[utoipa::path]` and registered via
/// `routes!()` — wrapped in [`task_routes`] so the per-route Trust-Task header
/// validation is preserved — contributes its operation to the served
/// `/openapi.json`. This struct only seeds document metadata + the security
/// scheme.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Verifiable Trust Community (VTC) API",
        description = "Community lifecycle, ACL, audit, policy, credentials, \
                       endorsements, and cross-community recognition REST surface \
                       of a Verifiable Trust Community.",
        version = env!("CARGO_PKG_VERSION"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// Registers the `bearer_jwt` HTTP-bearer security scheme referenced by
/// authenticated operations' `security(("bearer_jwt" = []))`.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_jwt",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

/// Serve the assembled OpenAPI document as JSON at `GET /openapi.json`.
/// Unauthenticated by design — it describes the API shape, not any secret.
async fn serve_openapi(api: utoipa::openapi::OpenApi) -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(api)
}

/// The assembled OpenAPI document describing the VTC REST surface.
///
/// Built from the same [`build_api_chain`] assembly that wires the live
/// routes — every handler registered via [`task_routes`]`(routes!(...))`
/// contributes its operation — so the document cannot drift from what the
/// service serves. The API surface is nested under the `/v1` mount exactly as
/// [`assemble`] mounts the live router; `OpenApiRouter::nest` composes the
/// documented paths the same way. Served at `GET /openapi.json`.
///
/// Handlers still registered via [`task_layer`] (not yet `#[utoipa::path]`-
/// annotated) are served but absent from the document until annotated.
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .nest("/v1", build_api_chain(&RoutingConfig::default(), false))
        .split_for_parts()
        .1
}

/// Global API surface body cap (Phase 5 M5.1.4 — §14.4 runtime
/// guard). Matches the VTA's `MAX_BODY_SIZE`. Website management
/// routes (M5.5) override per-route with larger caps via
/// `DefaultBodyLimit::disable() + RequestBodyLimitLayer::new(...)`.
pub const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Tighter body cap for unauthenticated routes. Aligned with
/// `vta-service`'s `UNAUTH_BODY_SIZE` — generous enough for a
/// JWE / sealed-transfer envelope but small enough to reject 1 MB
/// blob floods that the rate limiter alone cannot starve out.
pub const UNAUTH_BODY_SIZE: usize = 64 * 1024;

/// Build the public router with default routing (path mode, `/v1`
/// API mount, `/admin` UX placeholder, `/` website fallback).
///
/// Convenience wrapper around [`router_with`] for integration-test
/// fixtures and any caller that doesn't carry a [`RoutingConfig`].
/// Production startup goes through [`router_with`] from `server.rs`
/// so operator-supplied mount overrides take effect.
pub fn router() -> Router<AppState> {
    #[cfg(feature = "website")]
    {
        router_with(&RoutingConfig::default(), None)
    }
    #[cfg(not(feature = "website"))]
    {
        router_with(&RoutingConfig::default())
    }
}

/// Build the public router with operator-supplied routing config
/// (Phase 5 M5.1.1). Three logical surfaces under one
/// [`axum::Router`]:
///
/// - **API** (`routing.api.mount`, default `/v1`): the existing
///   [`TrustTaskRouter`]-built handler set. Every mutating + read
///   handler the daemon ships lives here. Phase 5 keeps handler
///   attach order identical to Phase 0–4; only the prefix moves
///   from inline `/v1/...` literals to a single `nest` boundary.
/// - **Admin UX** (`routing.admin_ui.mount`, default `/admin`):
///   placeholder router that returns 503 until M5.7 lands the
///   baked SPA. The mount is reserved so cookie-scope isolation
///   (§9.3) doesn't have to wait for the SPA to exist.
/// - **Website** (`routing.website.mount`, default `/`):
///   placeholder fallback that returns 503 until M5.4 lands the
///   filesystem-backed static handler. When the website mount is
///   `/`, attached as a catch-all fallback; otherwise nested.
///
/// `/health` is the **single** Trust-Task-exempt endpoint — kept
/// at the parent-router root (above every nest boundary) so
/// monitoring integration stays trivial regardless of routing
/// mode.
#[cfg(feature = "website")]
pub fn router_with(
    routing: &RoutingConfig,
    website_state: Option<crate::website::WebsiteState>,
) -> Router<AppState> {
    router_with_inner(routing, website_state, false)
}

/// Build the router with explicit `trust_xff`. Use this from
/// `server.rs` where the config is available; the no-args
/// `router_with` defaults to `trust_xff=false` (peer-IP rate
/// limiting), which is the safe default for tests and direct-
/// binding deployments.
#[cfg(feature = "website")]
pub fn router_with_xff(
    routing: &RoutingConfig,
    website_state: Option<crate::website::WebsiteState>,
    trust_xff: bool,
) -> Router<AppState> {
    router_with_inner(routing, website_state, trust_xff)
}

#[cfg(not(feature = "website"))]
pub fn router_with(routing: &RoutingConfig) -> Router<AppState> {
    router_with_inner(routing, false)
}

#[cfg(not(feature = "website"))]
pub fn router_with_xff(routing: &RoutingConfig, trust_xff: bool) -> Router<AppState> {
    router_with_inner(routing, trust_xff)
}

#[cfg(not(feature = "website"))]
fn router_with_inner(routing: &RoutingConfig, trust_xff: bool) -> Router<AppState> {
    // `build_api_chain` returns an `OpenApiRouter` (the single source of truth
    // for both routes and `/openapi.json`); split off the served axum `Router`
    // for `assemble` to nest. The OpenAPI document is rebuilt from the same
    // assembly by [`openapi_spec`] (which `assemble` serves), so the two cannot
    // drift.
    let api_chain = build_api_chain(routing, trust_xff).split_for_parts().0;
    assemble(routing, api_chain)
}

#[cfg(feature = "website")]
fn router_with_inner(
    routing: &RoutingConfig,
    website_state: Option<crate::website::WebsiteState>,
    trust_xff: bool,
) -> Router<AppState> {
    let api_chain = build_api_chain(routing, trust_xff).split_for_parts().0;
    assemble_with_website(routing, api_chain, website_state)
}

/// Build the merged API+unauth surface. Identical shape regardless
/// of the `website` feature; `routing` is currently unused inside
/// the chain (the API mount prefix is applied by [`assemble`] /
/// [`assemble_with_website`]) but threaded through so a future
/// per-mount override can land without changing this function's
/// signature.
fn build_api_chain(_routing: &RoutingConfig, trust_xff: bool) -> OpenApiRouter<AppState> {
    // Canonical cross-cutting auth tasks from trusttasks-tf. The legacy
    // openvtc/vtc/auth/legacy/* slugs were VTC-specific reimplementations
    // of primitives that VTA + did-hosting also have; consolidating here
    // so a multi-service deployment can use one client library.
    let auth_sessions_manage = TrustTask::new("https://trusttasks.org/spec/auth/sessions/list/0.1")
        .expect("static Trust-Task URL");
    let auth_sessions_revoke =
        TrustTask::new("https://trusttasks.org/spec/auth/revoke-session/0.1")
            .expect("static Trust-Task URL");
    // Browser-SPA convenience surface: `whoami` + `sign-out`. Both
    // are bound to the access-token session (cookie or bearer);
    // sign-out revokes the server-side session and clears the
    // browser cookies in one trip.
    let auth_whoami = TrustTask::new("https://trusttasks.org/spec/auth/whoami/0.1")
        .expect("static Trust-Task URL");
    let auth_sign_out = TrustTask::new("https://trusttasks.org/spec/auth/revoke-session/0.1")
        .expect("static Trust-Task URL");
    // Audit log list — super-admin only since envelopes carry
    // plaintext DIDs.
    let audit_list = TrustTask::new("https://trusttasks.org/openvtc/vtc/audit/list/1.0")
        .expect("static Trust-Task URL");
    let config_manage =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/config/legacy/manage/1.0")
            .expect("static Trust-Task URL");
    let acl_manage = TrustTask::new("https://trusttasks.org/openvtc/vtc/acl/legacy/manage/1.0")
        .expect("static Trust-Task URL");
    let acl_entry = TrustTask::new("https://trusttasks.org/openvtc/vtc/acl/legacy/entry/1.0")
        .expect("static Trust-Task URL");
    let community_profile =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0")
            .expect("static Trust-Task URL");
    let admin_config = TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0")
        .expect("static Trust-Task URL");
    let admin_config_reload =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/reload/1.0")
            .expect("static Trust-Task URL");
    let admin_config_restart =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/restart/1.0")
            .expect("static Trust-Task URL");
    let admin_config_export =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/export/1.0")
            .expect("static Trust-Task URL");
    let admin_config_import =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/import/1.0")
            .expect("static Trust-Task URL");
    let admin_bootstrap = TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/bootstrap/1.0")
        .expect("static Trust-Task URL");
    let admin_passkeys_list =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0")
            .expect("static Trust-Task URL");
    let admin_passkeys_register =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/passkeys/register/1.0")
            .expect("static Trust-Task URL");
    let admin_passkeys_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/passkeys/revoke/1.0")
            .expect("static Trust-Task URL");
    // Admin invites — REST surface for `vtc admin invite`. Single
    // Trust Task covers GET + POST on `/admin/invites` (same Phase-0
    // workaround community/profile + admin/config use); DELETE on
    // `/admin/invites/{jti}` has its own Trust Task since it's on a
    // distinct mount.
    let admin_invites_manage =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/invites/manage/1.0")
            .expect("static Trust-Task URL");
    let admin_invites_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/invites/revoke/1.0")
            .expect("static Trust-Task URL");
    let members_list = TrustTask::new("https://trusttasks.org/openvtc/vtc/members/list/1.0")
        .expect("static Trust-Task URL");
    let members_show = TrustTask::new("https://trusttasks.org/openvtc/vtc/members/show/1.0")
        .expect("static Trust-Task URL");
    let directory_query = TrustTask::new("https://trusttasks.org/openvtc/vtc/directory/query/1.0")
        .expect("static Trust-Task URL");
    let ceremonies_list = TrustTask::new("https://trusttasks.org/openvtc/vtc/ceremonies/list/1.0")
        .expect("static Trust-Task URL");
    // `members_update` (`members/update/1.0`) shares the
    // `members/{did}` mount with `show` for now — TrustTaskRouter
    // doesn't support per-method Trust-Task selectors yet
    // (same Phase-0 workaround `admin/config` + `community/profile`
    // use). When that lands, split show + update.
    let members_promote =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0")
            .expect("static Trust-Task URL");
    let members_self_remove =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/self-remove/1.0")
            .expect("static Trust-Task URL");
    // `members_admin_remove` (`members/admin-remove/1.0`) shares
    // the `members/{did}` mount with show + update for now —
    // TrustTaskRouter doesn't support per-method Trust-Task
    // selectors yet. The standalone task exists on disk +
    // index.json so the soft-gate surface stays complete.
    // POST + GET share `/v1/join-requests`. The `join-requests/list/1.0`
    // Trust Task exists in index.json + on-disk spec/schema so the
    // soft-gate surface stays complete; the wire enforcement here
    // collapses to `join-requests/submit/1.0` until TrustTaskRouter
    // gains per-method selectors (same workaround community/profile,
    // admin/config, members/{did} use).
    // The unauthenticated `/join-requests` POST submit, `/accept`, and
    // `/status` move to `build_unauth_routes` (P0.5) so the governor + 64 KiB
    // cap apply; their Trust Tasks are declared there. The admin GET list keeps
    // the `/join-requests` mount here under the *same* `join-requests/submit/1.0`
    // task it has always required (axum merges this GET with the governed POST;
    // the task descriptor collapse to `submit/1.0` for the list is unchanged —
    // a per-method `list/1.0` split is future work, tracked separately).
    let join_submit = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0")
        .expect("static Trust-Task URL");
    let join_show = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/show/1.0")
        .expect("static Trust-Task URL");
    let join_approve =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/approve/1.0")
            .expect("static Trust-Task URL");
    let join_reject = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/reject/1.0")
        .expect("static Trust-Task URL");
    let join_manifest =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/manifest/1.0")
            .expect("static Trust-Task URL");
    // Policies (Phase 2 M2.3). Three distinct Trust Tasks for the
    // three POST endpoints — upload, activate, test — so SIEM
    // filters + soft-gate consumers can target each precisely.
    let policies_upload = TrustTask::new("https://trusttasks.org/openvtc/vtc/policies/upload/1.0")
        .expect("static Trust-Task URL");
    let policies_activate =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/policies/activate/1.0")
            .expect("static Trust-Task URL");
    let policies_test = TrustTask::new("https://trusttasks.org/openvtc/vtc/policies/test/1.0")
        .expect("static Trust-Task URL");
    let members_renew = TrustTask::new("https://trusttasks.org/openvtc/vtc/members/renew/1.0")
        .expect("static Trust-Task URL");
    let members_rotate_challenge =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/rotate-challenge/1.0")
            .expect("static Trust-Task URL");
    let members_rotate = TrustTask::new("https://trusttasks.org/openvtc/vtc/members/rotate/1.0")
        .expect("static Trust-Task URL");
    // Phase 4 M4.3 + M4.4 — personhood lifecycle.
    let members_personhood_challenge =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/personhood/challenge/1.0")
            .expect("static Trust-Task URL");
    let members_personhood_assert =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/personhood/assert/1.0")
            .expect("static Trust-Task URL");
    // `members_personhood_revoke` (`members/personhood/revoke/1.0`)
    // exists on disk + in index.json so the soft-gate surface
    // stays complete, but the DELETE method shares the
    // `members/personhood/assert/1.0` mount at the router
    // layer pending per-method selectors. Same workaround as
    // `members/{did}` show + update + admin-remove.
    let _members_personhood_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/personhood/revoke/1.0")
            .expect("static Trust-Task URL");
    // Phase 4 M4.6 — VRC trust-graph endpoints.
    let relationships_publish =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/relationships/publish/1.0")
            .expect("static Trust-Task URL");
    let relationships_list =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/relationships/list/1.0")
            .expect("static Trust-Task URL");
    let relationships_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/relationships/revoke/1.0")
            .expect("static Trust-Task URL");
    // Phase 4 M4.8 — endorsement type registry + custom
    // endorsement CRUD. Seven Trust Tasks total — list / show
    // / delete share their mount where TrustTaskRouter
    // doesn't yet support per-method selectors (standalone
    // tasks ship on disk + in index.json).
    let endorsement_types_register =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/endorsement-types/register/1.0")
            .expect("static Trust-Task URL");
    let _endorsement_types_list =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/endorsement-types/list/1.0")
            .expect("static Trust-Task URL");
    let endorsement_types_delete =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/endorsement-types/delete/1.0")
            .expect("static Trust-Task URL");
    let endorsements_issue =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/credentials/endorsements/issue/1.0")
            .expect("static Trust-Task URL");
    let _endorsements_list =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/credentials/endorsements/list/1.0")
            .expect("static Trust-Task URL");
    // `endorsements_show` + `endorsements_revoke` share the
    // `endorsements/{id}` mount with the Trust Task header
    // pinned to the `show` variant. Standalone tasks ship on
    // disk + in index.json so the soft-gate surface stays
    // complete (same workaround as members/{did}, etc.).
    let _endorsements_show =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/credentials/endorsements/show/1.0")
            .expect("static Trust-Task URL");
    let _endorsements_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/credentials/endorsements/revoke/1.0")
            .expect("static Trust-Task URL");
    let endorsements_show_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/credentials/endorsements/show/1.0")
            .expect("static Trust-Task URL");
    // Phase 3 M3.8 — trust-registry reconciler diagnostics.
    // Admin-gated (not super-admin) so on-call ops can read
    // queue depth + RTBF-batched + failed counts without the
    // super-admin role.
    let health_diagnostics =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/health/diagnostics/1.0")
            .expect("static Trust-Task URL");
    // Phase 3 M3.10 — cross-community session mint. The Trust
    // Task declaration moved to `build_unauth_routes` so the
    // handler sits behind the tower-governor + the 64 KB body
    // cap — it's an unauthenticated endpoint that does DID
    // resolution + outbound HTTP fetch + Rego policy eval +
    // session-JWT mint, all driven by attacker-controlled VEC/VMC
    // JSON, and it was previously exposed on the 1 MB / no-rate-
    // limit main chain.
    // Read endpoints (M2.4). GET /v1/policies and
    // GET /v1/policies/{id} share their mounts with the POST
    // /v1/policies upload and POST /v1/policies/{id}/activate
    // endpoints respectively — TrustTaskRouter doesn't yet support
    // per-method selectors (same workaround community/profile,
    // admin/config, members/{did}, join-requests use). The
    // standalone `policies/list/1.0` + `policies/show/1.0` Trust
    // Tasks exist on disk + in index.json so the soft-gate
    // surface stays complete; the wire enforcement collapses to
    // the POST task on the shared mount.

    let api = OpenApiRouter::<AppState>::new()
        .routes(task_routes(
            routes!(health::diagnostics),
            health_diagnostics,
        ))
        // BitstringStatusList publication (M2.11). Trust-Task-
        // exempt — external verifiers don't carry our extension
        // header (same rationale as `did.jsonl`).
        .routes(routes!(status_lists::show))
        // Auth routes. `POST /v1/auth/{challenge,authenticate,refresh}`
        // are unauthenticated and live in `build_unauth_routes` so the
        // tower-governor + tighter body cap apply. The two
        // session-management endpoints below are authenticated and
        // stay on the main chain.
        .routes(task_routes(
            routes!(auth::session_list, auth::revoke_sessions_by_did),
            auth_sessions_manage,
        ))
        .routes(task_routes(
            routes!(auth::revoke_session),
            auth_sessions_revoke,
        ))
        .routes(task_routes(routes!(auth::whoami), auth_whoami))
        .routes(task_routes(routes!(auth::sign_out), auth_sign_out))
        // Audit log read (super-admin only).
        .routes(task_routes(routes!(audit::list_audit), audit_list))
        // Config
        .routes(task_routes(
            routes!(config::get_config, config::update_config),
            config_manage,
        ))
        // ACL
        .routes(task_routes(
            routes!(acl::list_acl, acl::create_acl),
            acl_manage,
        ))
        .routes(task_routes(
            routes!(acl::get_acl, acl::update_acl, acl::delete_acl),
            acl_entry,
        ))
        // Community profile (GET + PUT share one Trust Task today;
        // a spec-aligned split into community/profile/show/1.0 +
        // community/profile/update/1.0 lands when TrustTaskRouter
        // gains per-method task selectors in Phase 1+).
        .routes(task_routes(
            routes!(
                community::profile::get_profile,
                community::profile::put_profile
            ),
            community_profile,
        ))
        // Public read of the community profile. Trust-Task-exempt and
        // unauthenticated — visitors landing on the default public
        // website need the community's name + description + DIDs to
        // render before any session exists. Curated subset only (no
        // extensions, no registry status).
        .routes(routes!(community::profile::get_public_profile))
        // Admin config (M0.8 — GET + PATCH share one task; will
        // split into admin/config/show/1.0 + patch/1.0 when
        // TrustTaskRouter gains per-method selectors).
        .routes(task_routes(
            routes!(admin::config::get_config, admin::config::patch_config),
            admin_config,
        ))
        // Reload + restart (M0.8.3). Reload applies hot-reloadable
        // settings in-place; restart requires a supervisor (412
        // `SupervisorRequired` otherwise).
        .routes(task_routes(
            routes!(admin::config::reload_config),
            admin_config_reload,
        ))
        .routes(task_routes(
            routes!(admin::config::restart_config),
            admin_config_restart,
        ))
        // Export / import (M0.8.4). Export returns the portable
        // (db-layer overrides + community profile) JSON; import runs
        // diff-and-confirm via `?confirm=true|false`.
        .routes(task_routes(
            routes!(admin::config::export_config),
            admin_config_export,
        ))
        .routes(task_routes(
            routes!(admin::config::import_config),
            admin_config_import,
        ))
        // Install claim endpoints (`/install/claim/start` and
        // `/install/claim/finish`) are unauthenticated and live in
        // `build_unauth_routes` so the tower-governor + tighter
        // body cap apply.
        // Admin bootstrap (M0.6.2) — closes the install carve-out
        // and writes the first admin ACL entry. Unauthenticated
        // because the setup-session JWT IS the auth credential.
        .routes(task_routes(
            routes!(admin::bootstrap::bootstrap),
            admin_bootstrap,
        ))
        // Admin passkey management (M0.6.3). Step-up UV is enforced
        // via the two-phase ceremony: `register/start` and
        // `revoke/start` issue a UV challenge bound to an existing
        // passkey; `register/finish` and `revoke/finish` reject if
        // the UV assertion doesn't verify.
        .routes(task_routes(
            routes!(admin::passkeys::list),
            admin_passkeys_list,
        ))
        .routes(task_routes(
            routes!(admin::passkeys::register_start),
            admin_passkeys_register.clone(),
        ))
        .routes(task_routes(
            routes!(admin::passkeys::register_finish),
            admin_passkeys_register,
        ))
        .routes(task_routes(
            routes!(admin::passkeys::revoke_start),
            admin_passkeys_revoke.clone(),
        ))
        .routes(task_routes(
            routes!(admin::passkeys::revoke_finish),
            admin_passkeys_revoke,
        ))
        // Admin invites — REST mirror of `vtc admin invite`. GET +
        // POST share the same mount; DELETE on `/admin/invites/{jti}`
        // revokes outstanding (Issued) invites. Consumed rows are
        // immutable (audit history) — DELETE on those returns 409.
        .routes(task_routes(
            routes!(admin::invites::list_invites, admin::invites::create_invite),
            admin_invites_manage,
        ))
        .routes(task_routes(
            routes!(admin::invites::revoke_invite),
            admin_invites_revoke,
        ))
        // Directory ceremony (read-only field projection via the
        // ceremony decision pipeline).
        .routes(task_routes(routes!(directory::query), directory_query))
        // Ceremony registry — the admin-UI renders its flow + simulator
        // from these manifests (purpose / fields / facts template).
        .routes(task_routes(routes!(ceremonies::list), ceremonies_list))
        // Members (Phase 1 M1.4–M1.6).
        .routes(task_routes(
            routes!(members::read::list_members),
            members_list,
        ))
        // `/v1/members/me` for self-remove (M1.11.1). Must be
        // declared BEFORE the `/v1/members/{did}` mount otherwise
        // axum's path-trie picks the parameterised route first
        // and routes "me" as a literal DID.
        .routes(task_routes(
            routes!(members::remove::self_remove),
            members_self_remove,
        ))
        // Renewal (M2.13). POST on its own mount so the
        // Trust Task header check + per-method selectors are
        // unambiguous.
        .routes(task_routes(routes!(members::renew::renew), members_renew))
        // DID rotation (M2.15.1). Two-step ceremony — challenge
        // mints a single-use rotation_id, the finish endpoint
        // applies the co-signed swap atomically.
        .routes(task_routes(
            routes!(members::rotate::challenge),
            members_rotate_challenge,
        ))
        .routes(task_routes(
            routes!(members::rotate::rotate),
            members_rotate,
        ))
        // Phase 4 M4.3 + M4.4 — personhood lifecycle. Three
        // mounts on the same path prefix; declared BEFORE
        // `/v1/members/{did}` so axum's path-trie matches the
        // literal segment first. Personhood is a per-member
        // resource; `{did}` is the subject.
        .routes(task_routes(
            routes!(members::personhood::challenge),
            members_personhood_challenge,
        ))
        .routes(task_routes(
            routes!(members::personhood::assert, members::personhood::revoke), // POST + DELETE share `personhood/assert/1.0` at
            // the router layer pending per-method selectors;
            // the standalone `personhood/revoke/1.0` Trust Task
            // exists on disk + in index.json so the soft-gate
            // surface stays complete. (Same workaround as
            // members/{did}'s show + update + admin-remove.)
            members_personhood_assert,
        ))
        // Phase 4 M4.6 — VRC trust-graph endpoints. The
        // per-member list mounts under /v1/members/{did}/
        // and must precede the catchall `/v1/members/{did}`
        // (same path-trie precedence as personhood).
        .routes(task_routes(
            routes!(members::relationships::list),
            relationships_list,
        ))
        .routes(task_routes(
            routes!(relationships::publish),
            relationships_publish,
        ))
        .routes(task_routes(
            routes!(relationships::revoke),
            relationships_revoke,
        ))
        // Phase 4 M4.8.1 — operator-uploaded endorsement type
        // registry. Admin-gated CRUD.
        .routes(task_routes(
            routes!(endorsement_types::register, endorsement_types::list), // POST + GET share `register/1.0` at the router
            // layer pending per-method selectors; standalone
            // `list/1.0` exists on disk + in index.json.
            endorsement_types_register,
        ))
        .routes(task_routes(
            routes!(endorsement_types::delete),
            endorsement_types_delete,
        ))
        // Phase 2 §8 — community schema store (Issues + Accepts
        // registry). Plain admin-gated CRUD (AdminAuth extractor),
        // exempt from the Trust-Task soft-gate. (`accepts` static
        // segments bind before the `{type_uri}` param via matchit.)
        .routes(routes!(
            schemas::register_accepts,
            schemas::list_accepts_route
        ))
        .routes(routes!(
            schemas::get_accepts_route,
            schemas::delete_accepts_route
        ))
        .routes(routes!(schemas::register, schemas::list))
        .routes(routes!(schemas::get_one, schemas::delete_one))
        // Phase 4 M4.8.2-4 — custom endorsement issuance +
        // retrieval + revocation. Admin OR Issuer-role member.
        .routes(task_routes(
            routes!(endorsements::issue, endorsements::list), // POST + GET share `issue/1.0` at the router
            // layer pending per-method selectors; standalone
            // `list/1.0` exists on disk + in index.json.
            endorsements_issue,
        ))
        .routes(task_routes(
            routes!(endorsements::show, endorsements::revoke), // GET + DELETE share `show/1.0` at the router
            // layer pending per-method selectors; standalone
            // `revoke/1.0` exists on disk + in index.json.
            endorsements_show_revoke,
        ))
        .routes(task_routes(
            routes!(
                members::read::show_member,
                members::update::update_member,
                members::remove::admin_remove
            ), // GET + PATCH + DELETE share `members/show/1.0` at the
            // router layer pending per-method selectors; the
            // standalone `members/update/1.0` and
            // `members/admin-remove/1.0` Trust Tasks exist on
            // disk + in index.json so the soft-gate surface stays
            // complete.
            members_show,
        ))
        .routes(task_routes(
            routes!(members::promote::promote_start),
            members_promote.clone(),
        ))
        .routes(task_routes(
            routes!(members::promote::promote_finish),
            members_promote,
        ))
        // Join requests (Phase 1 M1.7–M1.10). The unauth POST submit /
        // accept / status live on the governed branch (`build_unauth_routes`,
        // P0.5); the admin GET list keeps this `/join-requests` mount (axum
        // merges this GET with the governed-branch POST submit).
        .routes(task_routes(
            routes!(join_requests::read::list_join_requests),
            join_submit,
        ))
        .routes(task_routes(
            routes!(join_requests::read::show_join_request),
            join_show,
        ))
        .routes(task_routes(
            routes!(join_requests::decide::approve),
            join_approve,
        ))
        .routes(task_routes(
            routes!(join_requests::decide::reject),
            join_reject,
        ))
        // Manifest (unauth public discovery): the community's join
        // evidence requirements. Static `manifest` segment takes
        // precedence over the `{id}` show route.
        .routes(task_routes(
            routes!(join_requests::manifest::manifest),
            join_manifest,
        ))
        // Credential-exchange query send (admin): prepare a DCQL query + issue a
        // single-use presentation challenge for a holder. Plain admin route (no
        // Trust-Task descriptor) — the holder answers over the credential-exchange
        // DIDComm `present` surface.
        .routes(routes!(join_requests::present::send_query))
        // Policies (Phase 2 M2.3). Three POST endpoints, three
        // Trust Tasks. `upload` mints + persists; `activate` flips
        // the per-purpose active pointer; `test` evaluates a stored
        // policy without mutating state.
        .routes(task_routes(
            routes!(policies::read::list_policies, policies::admin::upload),
            policies_upload.clone(),
        ))
        .routes(task_routes(
            routes!(policies::read::show_policy), // Reuses the upload task on the shared mount; the
            // `policies/show/1.0` Trust Task lives in index.json
            // + on disk for the soft-gate surface (see above).
            policies_upload.clone(),
        ))
        .routes(task_routes(
            routes!(policies::admin::activate),
            policies_activate,
        ))
        .routes(task_routes(routes!(policies::admin::test), policies_test));

    // Phase 5 M5.5 — public-website management routes. The
    // `route_with_task` helper accepts a pre-layered `MethodRouter`
    // so per-route body caps override the 1 MiB global. We attach
    // these BEFORE the global `DefaultBodyLimit` layer so the
    // route-specific cap wins.
    #[cfg(feature = "website")]
    let api = {
        use axum::extract::DefaultBodyLimit;

        let website_files_list =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/files/list/1.0")
                .expect("static Trust-Task URL");
        let website_files_show =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/files/show/1.0")
                .expect("static Trust-Task URL");
        // write + delete tasks share the show mount; standalone
        // tasks ship on disk + in index.json for the soft-gate
        // surface (same workaround the rest of the router uses).
        let _website_files_write =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/files/write/1.0")
                .expect("static Trust-Task URL");
        let _website_files_delete =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/files/delete/1.0")
                .expect("static Trust-Task URL");
        let website_deploy =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/deploy/1.0")
                .expect("static Trust-Task URL");
        let website_gens_list =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/generations/list/1.0")
                .expect("static Trust-Task URL");
        let website_rollback =
            TrustTask::new("https://trusttasks.org/openvtc/vtc/website/rollback/1.0")
                .expect("static Trust-Task URL");

        // 64 MiB upper bound on the per-route body cap covers
        // both `max_bundle_size_mb` (default 50) and
        // `max_file_size_mb` (default 10). Handler then enforces
        // the operator-configured value at runtime.
        const WEBSITE_ROUTE_CAP: usize = 64 * 1024 * 1024;

        api.route(
            "/website/files",
            task_layer(get(website::files::list), website_files_list),
        )
        .route(
            "/website/files/{*path}",
            task_layer(
                get(website::files::show)
                    .put(website::files::write)
                    .delete(website::files::delete)
                    .layer(DefaultBodyLimit::max(WEBSITE_ROUTE_CAP)), // Three methods on the same mount share the show
                // task per the TrustTaskRouter limitation already
                // documented elsewhere. The `write` and `delete`
                // tasks are still registered on disk + in index.json
                // for the soft-gate surface.
                website_files_show,
            ),
        )
        .route(
            "/website/deploy",
            task_layer(
                post(website::deploy::deploy).layer(DefaultBodyLimit::max(WEBSITE_ROUTE_CAP)),
                website_deploy,
            ),
        )
        .route(
            "/website/generations",
            task_layer(get(website::generations::list), website_gens_list),
        )
        .route(
            "/website/rollback/{gen_num}",
            task_layer(post(website::generations::rollback), website_rollback),
        )
    };

    let api = api
        // §14.4 — every authenticated API route inherits the 1 MiB
        // global body cap. The per-route overrides above for
        // `/v1/website/*` apply first; this layer is the default
        // for everything else.
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

    // Unauthenticated routes — tighter body cap + per-IP governor.
    let unauth = build_unauth_routes(trust_xff);
    api.merge(unauth)
}

/// Build the unauthenticated sub-router: 5 POST routes that drive
/// expensive crypto against attacker-controlled bytes.
///
/// - `POST /auth/challenge`
/// - `POST /auth/` (authenticate)
/// - `POST /auth/refresh`
/// - `POST /install/claim/start`
/// - `POST /install/claim/finish`
///
/// Layers:
/// - [`UNAUTH_BODY_SIZE`] body cap (tighter than the 1 MiB main
///   API cap — generous enough for a JWE / sealed-transfer
///   envelope, small enough to reject blob floods).
/// - Per-IP `tower-governor` (5 rps + 10 burst) via
///   [`SmartIpKeyExtractor`].
fn build_unauth_routes(trust_xff: bool) -> OpenApiRouter<AppState> {
    // Canonical cross-cutting auth tasks from trusttasks-tf.
    let auth_challenge = TrustTask::new("https://trusttasks.org/spec/auth/challenge/0.1")
        .expect("static Trust-Task URL");
    let auth_authenticate = TrustTask::new("https://trusttasks.org/spec/auth/authenticate/0.1")
        .expect("static Trust-Task URL");
    let auth_refresh = TrustTask::new("https://trusttasks.org/spec/auth/refresh/0.1")
        .expect("static Trust-Task URL");
    // Phase 5 M5.2.3 — admin SPA cookie-session mint endpoint. VTC-
    // specific because the response includes Set-Cookie semantics
    // (vtc_admin_session + csrf) that the canonical authenticate
    // doesn't define. Stays under openvtc/vtc/ until the cookie
    // semantics are absorbed into a binding spec.
    let auth_admin_login =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/admin-login/1.0")
            .expect("static Trust-Task URL");
    // Bearer→cookie bridge for the VTA-wallet login: the SPA posts the
    // wallet-issued access token, the daemon mirrors it into the
    // `vtc_admin_session` + `csrf` cookies (same shape as admin-login).
    let auth_admin_session =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/admin-session/1.0")
            .expect("static Trust-Task URL");
    // Browser-friendly passkey login — same canonical spec serves
    // initial login and AAL step-up via the payload's `purpose` field.
    let auth_passkey_login_start =
        TrustTask::new("https://trusttasks.org/spec/auth/passkey/login/start/0.1")
            .expect("static Trust-Task URL");
    let auth_passkey_login_finish =
        TrustTask::new("https://trusttasks.org/spec/auth/passkey/login/finish/0.1")
            .expect("static Trust-Task URL");
    let install_claim_start =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/start/1.0")
            .expect("static Trust-Task URL");
    let install_claim_finish =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0")
            .expect("static Trust-Task URL");
    // Phase 3 M3.10 — cross-community session mint. Sits in the
    // unauth chain (not the main API chain) so the tower-governor
    // + 64 KB body cap apply: the handler runs DID resolution,
    // outbound HTTP fetch of the foreign `statusListCredential`
    // URL, Rego policy eval, and a session JWT mint, all driven by
    // attacker-supplied JSON. Behind the rate limit, a sustained
    // SSRF / CPU-amplification probe is throttled to 5 rps per
    // source IP.
    let auth_recognise = TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/recognise/1.0")
        .expect("static Trust-Task URL");
    // Step 1 of the recognise flow — issues the single-use challenge nonce the
    // holder binds into the VP presented to `/auth/recognise`. Same unauth
    // chain (governor + body cap) as the other challenge endpoints.
    let auth_recognise_challenge =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/recognise/challenge/1.0")
            .expect("static Trust-Task URL");
    // P0.5 — the unauthenticated join-request POSTs (submit / accept / status)
    // do the same attacker-driven crypto as recognise (Ed25519 holder-binding
    // verify, reciprocal-VC counter-sign verify, Rego eval) but were left on
    // the 1 MiB / no-limiter main chain. Move them here so the governor + 64
    // KiB cap apply. The admin GET list + show + approve / reject and the
    // public GET manifest stay on the `api` chain.
    let join_submit = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0")
        .expect("static Trust-Task URL");
    let join_accept = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/accept/1.0")
        .expect("static Trust-Task URL");
    let join_status = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/status/1.0")
        .expect("static Trust-Task URL");

    // L2: rate-limiter key extractor honours `trust_xff`. The
    // governor is applied in the routing chain below via a
    // branched `apply_governor` helper so the two key extractors'
    // distinct generic types don't pollute the variable's signature.
    let _ = trust_xff;

    // `SmartIpKeyExtractor` reads `X-Forwarded-For` / `X-Real-IP` /
    // `Forwarded` headers first and only falls back to `ConnectInfo`
    // when none are set. In production the `axum::serve` call in
    // `server.rs` wires `into_make_service_with_connect_info` so the
    // peer-IP fallback works; in integration tests built on
    // `Router::oneshot`, neither headers nor `ConnectInfo` are present
    // and the extractor errors with 500. This synthetic-`ConnectInfo`
    // middleware inserts a `127.0.0.1` placeholder **only when missing**
    // so test calls take the peer-IP fallback path — production traffic
    // (which already carries `ConnectInfo` from the service factory)
    // is untouched.
    let synth_connect_info = axum::middleware::from_fn(insert_default_connect_info_if_missing);

    let unauth_router = OpenApiRouter::<AppState>::new()
        .routes(task_routes(routes!(auth::challenge), auth_challenge))
        .routes(task_routes(routes!(auth::authenticate), auth_authenticate))
        // VTA-wallet login surface. The browser wallet extension drives
        // the SIOPv2 round-trip itself and posts to `<base>/auth/challenge`
        // + `<base>/auth/` with **no** `Trust-Task` header (the op `type`
        // rides in the body). These header-exempt aliases reuse the same
        // `challenge` / `authenticate` handlers — the latter's SIOP branch
        // handles the wallet's `id_token` envelope. The admin-UI points the
        // wallet at `<origin>/v1/wallet` so it lands here, leaving the
        // Trust-Task-gated `/auth/*` routes above untouched for DIDComm and
        // CLI clients. Mirrors did-hosting-control's header-less auth.
        .route("/wallet/auth/challenge", post(auth::challenge))
        .route("/wallet/auth/", post(auth::authenticate))
        .routes(task_routes(routes!(auth::refresh), auth_refresh))
        .routes(task_routes(routes!(auth::admin_login), auth_admin_login))
        .routes(task_routes(
            routes!(auth::admin_session),
            auth_admin_session,
        ))
        .routes(task_routes(
            routes!(auth::passkey_login_start),
            auth_passkey_login_start,
        ))
        .routes(task_routes(
            routes!(auth::passkey_login_finish),
            auth_passkey_login_finish,
        ))
        .routes(task_routes(
            routes!(install::claim_start),
            install_claim_start,
        ))
        .routes(task_routes(
            routes!(install::claim_finish),
            install_claim_finish,
        ))
        .routes(task_routes(
            routes!(recognise::recognise_challenge),
            auth_recognise_challenge,
        ))
        .routes(task_routes(routes!(recognise::recognise), auth_recognise))
        // Join-request POSTs (P0.5). Submit shares the `/join-requests` mount
        // with the admin GET list on the `api` chain — axum merges the GET +
        // POST method routers; the unauth POST lands here (governed), the admin
        // GET stays there (JWT-gated).
        .routes(task_routes(
            routes!(join_requests::submit::submit),
            join_submit,
        ))
        .routes(task_routes(
            routes!(join_requests::accept::accept),
            join_accept,
        ))
        .routes(task_routes(
            routes!(join_requests::status::status),
            join_status,
        ))
        .layer(DefaultBodyLimit::max(UNAUTH_BODY_SIZE));

    // Apply the per-IP rate limiter in a branch so the two
    // key-extractor generic types don't leak into the variable's
    // type. The layered router is type-erased on the axum side
    // once we hand it back.
    let unauth_router = if trust_xff {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(5)
                .burst_size(10)
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .expect("governor config values are static and non-zero"),
        );
        unauth_router.layer(GovernorLayer::new(cfg))
    } else {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(5)
                .burst_size(10)
                .key_extractor(tower_governor::key_extractor::PeerIpKeyExtractor)
                .finish()
                .expect("governor config values are static and non-zero"),
        );
        unauth_router.layer(GovernorLayer::new(cfg))
    };
    unauth_router.layer(synth_connect_info)
}

/// Middleware that inserts a `ConnectInfo<SocketAddr>(127.0.0.1)`
/// extension if the request doesn't already carry one. See the
/// rationale comment in [`build_unauth_routes`].
async fn insert_default_connect_info_if_missing(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::extract::ConnectInfo;

    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_none()
    {
        let synthetic =
            ConnectInfo::<SocketAddr>(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        request.extensions_mut().insert(synthetic);
    }
    next.run(request).await
}

/// Build the public router from the API sub-router + placeholder
/// admin/website surfaces. Extracted so unit tests can exercise
/// nest behaviour without rebuilding the full TrustTaskRouter.
///
/// Only used by the no-`website`-feature build path; the
/// feature build always flows through [`assemble_with_website`].
#[cfg_attr(feature = "website", allow(dead_code))]
fn assemble(routing: &RoutingConfig, api: Router<AppState>) -> Router<AppState> {
    use axum::middleware::from_fn;

    use crate::routing::security_headers::security_headers;

    // Admin UX + website sub-routers serve HTML/JS to a browser;
    // both get the default CSP + `X-Content-Type-Options: nosniff`
    // layer (Phase 5 M5.3.2). The API sub-router is a JSON wire
    // surface and is intentionally excluded — CSP is browser-only.
    let admin_placeholder: Router<AppState> = Router::new()
        .fallback(any(placeholder_503))
        .layer(from_fn(security_headers));
    let website_placeholder: Router<AppState> = Router::new()
        .fallback(any(placeholder_503))
        .layer(from_fn(security_headers));

    let spec = openapi_spec();
    let mut app: Router<AppState> = Router::new()
        // `/health` is the single Trust-Task-exempt endpoint;
        // attached at the parent-router root so monitoring works
        // identically across path mode and subdomain mode (the
        // operator just curls `/health` on whichever host the
        // daemon is reachable on).
        .route("/health", get(health::health))
        // Machine-readable API description for black-box conformance / fuzz
        // tooling. Unauthenticated (API shape, not secrets); served at the
        // parent root like `/health`.
        .route("/openapi.json", get(move || serve_openapi(spec.clone())))
        // `did:webvh` log publication. Mounted at the parent root
        // (above the `/v1` nest) because a serverless VTC's DID,
        // `did:webvh:<scid>:<host>`, resolves to
        // `https://<host>/.well-known/did.jsonl` by the did:webvh
        // convention — the log has to live at that exact URL for the
        // VTC's own DID to be resolvable. The VTC hosts exactly one
        // DID, its own. See `tasks/vtc-mvp/vta-driven-keys.md` §10.
        .route("/.well-known/did.jsonl", get(did_log::did_log))
        // API surface — existing TrustTaskRouter result nested at
        // the configured mount.
        .nest(&routing.api.mount, api);

    // Admin UX surface. The cookie-scope guard in
    // `validate_routing` already refuses admin_ui at `/`; here we
    // just trust the prior validation.
    app = app.nest(&routing.admin_ui.mount, admin_placeholder);

    // Website surface. axum 0.8 refuses `nest("/", ...)`; when the
    // mount is the root, merge instead so the placeholder's
    // fallback (with security headers attached) becomes the
    // parent's fallback. Non-root mounts use the regular nest path.
    if routing.website.mount == "/" {
        app = app.merge(website_placeholder);
    } else {
        app = app.nest(&routing.website.mount, website_placeholder);
    }

    app
}

/// Production assembly: same as [`assemble`] but **replaces** the
/// website 503 placeholder with the real static handler when a
/// [`crate::website::WebsiteState`] is provided.
///
/// Mirrors the no-state path's nest/merge logic exactly so the
/// route-priority semantics don't drift between the two builds.
#[cfg(feature = "website")]
pub fn assemble_with_website(
    routing: &RoutingConfig,
    api: Router<AppState>,
    website_state: Option<crate::website::WebsiteState>,
) -> Router<AppState> {
    use axum::middleware::from_fn;

    use crate::routing::security_headers::security_headers;

    // Admin UX sub-router. Phase 5 M5.7 ships the real handler
    // when `admin-ui` is on AND `admin_ui.mode = "embedded"`.
    // External mode + the no-feature build fall back to the 503
    // placeholder.
    //
    // We use explicit `route("/")` + `route("/{*path}")` rather
    // than `Router::fallback`, because axum 0.8 doesn't propagate
    // the nested router's fallback through `Router::merge` of a
    // sibling router (the website surface) — the website
    // fallback ends up intercepting requests to `/admin/*`. Two
    // wildcard routes cover every reachable path.
    #[cfg(feature = "admin-ui")]
    let admin: Router<AppState> = Router::new()
        .route("/build-info.json", get(admin_ui::build_info))
        .route("/plugins.json", get(admin_ui::plugins_manifest))
        .route("/plugins/{id}/{*rel_path}", get(admin_ui::plugin_asset))
        .route("/", get(admin_ui::serve_spa))
        .route("/{*path}", get(admin_ui::serve_spa))
        .layer(from_fn(security_headers));
    #[cfg(not(feature = "admin-ui"))]
    let admin: Router<AppState> = Router::new()
        .route("/", any(placeholder_503))
        .route("/{*path}", any(placeholder_503))
        .layer(from_fn(security_headers));

    // Website sub-router. Two dispatch paths, same rationale for
    // explicit wildcard routes as the admin block above.
    //
    // - Operator configured `website.root_dir` → serve from the
    //   filesystem via the M5.4 handler. `website_state` is
    //   `Some`.
    // - No `root_dir` → serve the in-tree default landing page
    //   from `vtc-service/website-default/`. `website_state` is
    //   `None`. This is the freshly-installed-daemon
    //   out-of-the-box experience.
    //
    // Both paths share the security-headers layer so the default
    // CSP applies uniformly.
    // Built as `Router<()>` (state baked in via `with_state` for
    // the operator-config branch; the default-site branch is
    // state-less) so the parent `Router<AppState>` can mount it
    // via `fallback_service` / `nest_service`. axum 0.8's `merge`
    // doesn't preserve nested-router precedence when the merged
    // router has a wildcard `route("/{*path}")` — the website's
    // wildcard scores higher than the admin nest, so `/admin/*`
    // ends up routed to the website. The service-level mount
    // sidesteps that.
    let website: axum::Router<()> = match website_state {
        Some(state) => Router::new()
            .route("/", get(crate::website::serve))
            .route("/{*path}", get(crate::website::serve))
            .layer(from_fn(security_headers))
            .with_state(state),
        None => Router::new()
            .route("/", get(crate::website::default_site::serve))
            .route("/{*path}", get(crate::website::default_site::serve))
            .layer(from_fn(security_headers)),
    };

    let spec = openapi_spec();
    let mut app: Router<AppState> = Router::new()
        .route("/health", get(health::health))
        // Machine-readable API description — see the matching comment in
        // `assemble`.
        .route("/openapi.json", get(move || serve_openapi(spec.clone())))
        // `did:webvh` log publication — see the matching comment in
        // `assemble`. Parent-root mount so a serverless VTC's
        // `did:webvh:<scid>:<host>` resolves to
        // `https://<host>/.well-known/did.jsonl`, the URL we serve.
        .route("/.well-known/did.jsonl", get(did_log::did_log))
        .nest(&routing.api.mount, api);
    app = app.nest(&routing.admin_ui.mount, admin);
    // axum 0.8's `nest("/admin", inner)` registers `/admin` (bare)
    // and `/admin/{*rest}` (sub-paths). Neither matches `/admin/`
    // exactly — that path has no characters after the slash, so the
    // wildcard fails — and the request falls through to the website
    // fallback. Operators routinely paste `/admin/` into a browser,
    // so we register the trailing-slash form explicitly to point at
    // the same SPA handler.
    let admin_slash = format!("{}/", routing.admin_ui.mount.trim_end_matches('/'));
    #[cfg(feature = "admin-ui")]
    {
        app = app.route(admin_slash.as_str(), get(admin_ui::serve_spa));
    }
    #[cfg(not(feature = "admin-ui"))]
    {
        app = app.route(admin_slash.as_str(), any(placeholder_503));
    }
    if routing.website.mount == "/" {
        app = app.fallback_service(website);
    } else {
        app = app.nest_service(&routing.website.mount, website);
    }
    app
}

/// Placeholder 503 handler used by the admin sub-router when the
/// `admin-ui` feature is off, and by the website sub-router in
/// the no-`website`-feature build.
#[cfg_attr(all(feature = "website", feature = "admin-ui"), allow(dead_code))]
async fn placeholder_503() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "surface not yet implemented",
    )
}

#[cfg(test)]
mod openapi_tests {
    use super::*;

    #[test]
    fn openapi_spec_documents_the_migrated_route_and_security_scheme() {
        let spec = openapi_spec();
        assert_eq!(spec.info.title, "Verifiable Trust Community (VTC) API");
        // The migrated route is nested under the /v1 API mount.
        let diag = spec
            .paths
            .paths
            .get("/v1/health/diagnostics")
            .expect("/v1/health/diagnostics must be documented");
        assert!(diag.get.is_some(), "diagnostics documents a GET operation");
        // The bearer scheme + the response schema are present.
        let components = spec.components.as_ref().expect("components present");
        assert!(components.security_schemes.contains_key("bearer_jwt"));
        assert!(
            components.schemas.contains_key("DiagnosticsResponse"),
            "DiagnosticsResponse schema must be emitted"
        );
    }

    #[test]
    fn openapi_spec_covers_the_route_groups() {
        let spec = openapi_spec();
        let paths = &spec.paths.paths;
        // A representative path (all nested under /v1) from each major group.
        for p in [
            "/v1/acl",
            "/v1/acl/{did}",
            "/v1/audit",
            "/v1/config",
            "/v1/auth/challenge",
            "/v1/auth/sessions",
            "/v1/admin/config",
            "/v1/admin/invites",
            "/v1/admin/passkeys",
            "/v1/members",
            "/v1/members/{did}",
            "/v1/community/profile",
            "/v1/join-requests",
            "/v1/policies",
            "/v1/credentials/endorsements",
            "/v1/endorsement-types",
            "/v1/schemas",
            "/v1/relationships",
            "/v1/directory/{did}",
            "/v1/install/claim/start",
        ] {
            assert!(paths.contains_key(p), "spec missing documented path {p}");
        }
        assert!(
            paths.len() >= 55,
            "expected the documented surface to be >= 55 paths, got {}",
            paths.len()
        );
    }

    // ── Route-posture backstop (P2.6) ──────────────────────────────────────
    //
    // The router is assembled across two chains (`build_api_chain`,
    // `build_unauth_routes`) and auth posture is enforced by per-handler
    // extractors, so whether a route is authenticated — and, if not, whether it
    // sits behind the rate-limiter — isn't locally legible at any one site. That
    // is exactly how the P0.5 misplacement slipped in (attacker-driven crypto
    // POSTs left on the unauthenticated 1 MiB / no-limiter main chain).
    //
    // These tests turn the OpenAPI spec (the route inventory + each op's
    // `security` requirement) into a posture assertion: **every** unauthenticated
    // operation must be explicitly classified as either governed (the
    // rate-limited, 64 KiB `build_unauth_routes` chain) or an approved public
    // exception. A new unauthenticated route fails the suite until it is
    // classified, and a route that flips its auth gate breaks the matching
    // allowlist — making the P0.5 regression class impossible to land silently.

    /// Unauthenticated operations that ride the governed chain
    /// (`build_unauth_routes`): tower-governor rate limit + [`UNAUTH_BODY_SIZE`]
    /// body cap. Attacker-driven crypto / IO belongs here.
    const GOVERNED_UNAUTH: &[(&str, &str)] = &[
        ("POST", "/v1/auth/challenge"),
        ("POST", "/v1/auth/"),
        ("POST", "/v1/auth/refresh"),
        ("POST", "/v1/auth/admin-login"),
        ("POST", "/v1/auth/admin-session"),
        ("POST", "/v1/auth/passkey-login/start"),
        ("POST", "/v1/auth/passkey-login/finish"),
        ("POST", "/v1/auth/recognise/challenge"),
        ("POST", "/v1/auth/recognise"),
        ("POST", "/v1/install/claim/start"),
        ("POST", "/v1/install/claim/finish"),
        ("POST", "/v1/join-requests"),
        ("POST", "/v1/join-requests/{id}/accept"),
        ("POST", "/v1/join-requests/{id}/status"),
    ];

    /// Unauthenticated operations intentionally left OFF the governed chain
    /// (public reads + the rate-limited-elsewhere bootstrap). Each is a
    /// deliberate decision recorded here so a *new* unauthenticated route can't
    /// quietly join this set.
    const PUBLIC_UNGOVERNED: &[(&str, &str)] = &[
        // Public, cacheable community metadata — no secrets, cheap to serve.
        ("GET", "/v1/community/public-profile"),
        // Public join manifest (what a community asks applicants to present).
        ("GET", "/v1/join-requests/manifest"),
        // Verifier-facing status list — public by the W3C BitstringStatusList model.
        ("GET", "/v1/status-lists/{purpose}"),
        // TEE/admin first-boot bootstrap — single-use, setup-JWT gated in-handler.
        ("POST", "/v1/admin/bootstrap"),
    ];

    /// Collect every documented operation as `(METHOD, path, secured)` where
    /// `secured` reflects the op's OpenAPI `security` requirement (bearer JWT).
    fn documented_ops() -> Vec<(&'static str, String, bool)> {
        let spec = openapi_spec();
        let mut ops = Vec::new();
        for (path, item) in &spec.paths.paths {
            for (method, op) in [
                ("GET", &item.get),
                ("POST", &item.post),
                ("PATCH", &item.patch),
                ("DELETE", &item.delete),
                ("PUT", &item.put),
            ] {
                if let Some(op) = op {
                    let secured = op.security.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
                    ops.push((method, path.clone(), secured));
                }
            }
        }
        ops
    }

    fn in_allowlist(list: &[(&str, &str)], method: &str, path: &str) -> bool {
        list.iter().any(|(m, p)| *m == method && *p == path)
    }

    /// The core P0.5 backstop: every unauthenticated operation is classified,
    /// and every authenticated operation stays off the governed unauth chain.
    #[test]
    fn every_unauthenticated_route_is_classified() {
        for (method, path, secured) in documented_ops() {
            let governed = in_allowlist(GOVERNED_UNAUTH, method, &path);
            let public = in_allowlist(PUBLIC_UNGOVERNED, method, &path);
            if secured {
                assert!(
                    !governed,
                    "{method} {path} requires a bearer JWT but is listed on the unauthenticated \
                     governed chain — an authenticated route must not sit in GOVERNED_UNAUTH"
                );
            } else {
                assert!(
                    governed || public,
                    "{method} {path} is UNAUTHENTICATED but unclassified — add it to the governed \
                     unauth chain (GOVERNED_UNAUTH) or, if it is a deliberate public endpoint, to \
                     PUBLIC_UNGOVERNED. (This is the P0.5 backstop: an unauth route must never \
                     silently land on the 1 MiB no-limiter main chain.)"
                );
                assert!(
                    !(governed && public),
                    "{method} {path} is in both GOVERNED_UNAUTH and PUBLIC_UNGOVERNED — pick one"
                );
            }
        }
    }

    /// The allowlists can't drift: every entry must still be a documented,
    /// unauthenticated operation (so a removed/renamed/now-authenticated route
    /// can't leave a stale exception behind).
    #[test]
    fn posture_allowlists_have_no_stale_entries() {
        let ops = documented_ops();
        let is_unauth_op = |method: &str, path: &str| {
            ops.iter()
                .any(|(m, p, secured)| *m == method && p == path && !secured)
        };
        for (method, path) in GOVERNED_UNAUTH.iter().chain(PUBLIC_UNGOVERNED) {
            assert!(
                is_unauth_op(method, path),
                "posture allowlist entry {method} {path} is not a documented unauthenticated \
                 operation — remove it or fix the path/method"
            );
        }
    }
}
