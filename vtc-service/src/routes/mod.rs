pub(crate) mod acl;
pub(crate) mod admin;
#[cfg(feature = "admin-ui")]
mod admin_ui;
pub(crate) mod audit;
pub mod auth;
pub(crate) mod backup;
pub(crate) mod ceremonies;
pub(crate) mod community;
pub(crate) mod credential_exchange;
pub(crate) mod did_log;
pub(crate) mod directory;
pub(crate) mod endorsement_types;
pub(crate) mod endorsements;
pub(crate) mod health;
pub(crate) mod install;
pub(crate) mod invitations;
pub mod join_requests;
pub(crate) mod members;
pub(crate) mod policies;
pub mod recognise;
pub(crate) mod recognition_admin;
pub(crate) mod registry_admin;
pub(crate) mod relationships;
pub(crate) mod rooms;
pub(crate) mod schemas;
pub(crate) mod status_lists;
pub mod trust_tasks;
pub(crate) mod vetting;
/// Hidden-vetter admission: the operator's publish route (development branch `zkp-pcs`).
#[cfg(feature = "vetting-pcs")]
pub mod vetting_hidden;
#[cfg(feature = "website")]
pub(crate) mod website;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use ipnetwork::IpNetwork;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use vti_common::rate_limit::TrustedProxyKeyExtractor;
use vti_common::trust_task::{TrustTask, task_routes};

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
    // Schemas reachable *only* from a query parameter. utoipa collects
    // schemas transitively from `request_body` and `body =`, but not through
    // an `IntoParams` field, so a `params(...)`-only type is referenced by the
    // document and absent from its components — a dangling `$ref`, which
    // `no_dangling_refs` below fails on and `openapi-typescript` refuses to
    // generate from at all.
    //
    // And the `git-ns/*` administrator reads' response bodies, which no route
    // returns — they are Trust Task responses on the document endpoint
    // (`git_ns::admin_reads`) — but which the admin console's wire types are
    // generated from, so no shape is written twice.
    //
    // Likewise the admin verbs with no route at all — signed documents only —
    // whose shapes the console's signed calls are typed by.
    components(schemas(
        policies::read::PolicyStatusFilter,
        crate::git_ns::admin_reads::GitNsNamespaceList,
        crate::git_ns::admin_reads::GitNsRepoList,
        crate::git_ns::admin_reads::GitNsRightList,
        crate::git_ns::admin_reads::GitNsDepartedGrants,
        crate::git_ns::admin_reads::GitNsJobList,
        crate::git_ns::admin_reads::GitNsProjection,
        crate::git_ns::admin_reads::GitNsAccountList,
        crate::git_ns::admin_reads::GitNsActivity,
        // A repository's drift, as `git-ns/view/0.5`'s `repos[].sync` carries it.
        vta_sdk::openapi::GitNsView01DriftItem,
        acl::AclListResponse,
        acl::AclEntryEnvelope,
        vta_sdk::openapi::VetterList01Payload,
        vta_sdk::openapi::VetterList01Response,
        endorsement_types::RegisterBody,
        endorsement_types::RegisterResponse,
        vta_sdk::openapi::EndorsementTypeDelete01Response,
        // The operational verbs the console signs (`trust_tasks::admin_tasks`).
        health::DiagnosticsResponse,
        vta_sdk::openapi::RegistrySyncJobsList01Response,
        vta_sdk::openapi::RegistrySyncJobsRetry01Response,
        vta_sdk::openapi::RegistrySyncJobsDiscard01Response,
        vta_sdk::openapi::RegistryRecordsList01Response,
        audit::AuditListResponse,
        crate::config_store::EffectiveConfig,
        admin::config::PatchResponse,
        admin::config::ReloadResponse,
        admin::config::RestartResponse,
        admin::invites::ListInvitesResponse,
        admin::invites::CreateInviteRequest,
        admin::invites::CreateInviteResponse,
        admin::invites::RevokeInviteResponse,
        auth::SessionListResponse,
        auth::RevokeSessionResponse,
        // The community verbs the console signs (`trust_tasks::community_tasks`).
        community::profile::CommunityProfileResponse,
        ceremonies::CeremonyListResponse,
        directory::DirectoryResponse,
        vti_common::pagination::Paginated<crate::endorsement_types::EndorsementType>,
        recognition_admin::RecognitionCheck,
        members::read::RemovedMembersResponse,
        members::read::MemberEnvelope,
        members::request_vmc::RequestVmcBody,
        members::request_vmc::RequestVmcResponse,
        join_requests::read::JoinRequestEnvelope,
        relationships::RelationshipsGraph,
        invitations::IssueInvitationBody,
        invitations::IssueInvitationResponse,
        invitations::InvitationListResponse,
        invitations::RevokeResponse,
        vta_sdk::openapi::InvitationDeliver01Payload,
        vta_sdk::openapi::InvitationDeliver01Response,
        // The verbs whose shapes are documented for codegen though every
        // bearer route is gone: the roster and join queue, a member's
        // credentials, the join decision, a vetter grant, and the policy log.
        vti_common::pagination::Paginated<members::read::MemberResponse>,
        vti_common::pagination::Paginated<crate::join::JoinRequest>,
        vta_sdk::openapi::MemberCredentials01Response,
        join_requests::decide::DecideResponse,
        vta_sdk::openapi::VetterGrant01Response,
        policies::read::PolicyListResponse,
        policies::read::PolicyModuleResponse,
        policies::admin::UploadResponse,
        crate::policy::PolicyPurpose,
        // The administration surfaces the console signs (`trust_tasks::surface_tasks`).
        join_requests::read::JoinRequestVettingResponse,
        join_requests::read::JoinRequestVetting,
        join_requests::read::JoinRequestVettingStatement,
        crate::schemas::AcceptsCriterion,
        schemas::RegisterAcceptsBody,
        rooms::HostedRoom,
        // The custom-endorsement reads/revoke the console signs
        // (`vtc/endorsements/{list,show,revoke}/0.1`) — bearer REST routes for
        // all three had no caller once the spine dispatched them (tt-tf#689)
        // and were removed.
        endorsements::EndorsementRow,
        vti_common::pagination::Paginated<endorsements::EndorsementRow>,
        endorsements::EndorsementEnvelope,
        endorsements::RevokeResponse,
        // The admin resend-on-behalf the console signs
        // (`vtc/vetting/vetters/resend/0.2`) — its admin-only bearer REST
        // route had no caller once the spine dispatched it (tt-tf#689) and
        // was removed. `0.1`'s response shape covers `0.2`'s too: neither
        // adds a member.
        vta_sdk::openapi::VetterResend01Response,
        // The website admin verbs the console signs
        // (`vtc/website/{files/list,files/delete,generations/list,rollback}/0.1`,
        // `trust_tasks::website_tasks`) — every bearer REST route for these had
        // no caller once vtc-client/cnm-cli/admin-ui moved onto the signed door.
        website::files::ListResponse,
        website::files::FileEntry,
        website::files::DeleteResponse,
        website::generations::GenerationsResponse,
        website::generations::GenerationRow,
        website::generations::RollbackResponse,
        // The vetting admin reads the console signs
        // (`vtc/vetting/vetters/grants/list/0.1`, `vtc/vetting/auto-grant/
        // {show,update}/0.1`, `vtc/vetting/revocations/list/0.1`,
        // `trust_tasks::surface_tasks`) — their admin-only bearer REST routes
        // had no caller left once `vtc-client` and the admin console signed
        // them instead, so nothing else forces these shapes into the spec any
        // more; the admin-ui's generated wire types still need them.
        vta_sdk::protocols::vetting::VetterGrantRow,
        vta_sdk::protocols::vetting::VetterProfileSummary,
        vta_sdk::protocols::vetting::GrantOrigin,
        vta_sdk::protocols::vetting::AutoGrantStatus,
        vta_sdk::protocols::vetting::AutoGrantConfig,
        vta_sdk::protocols::vetting::AutoGrantSweep,
        crate::routes::vetting::VettingRevocationRow,
        crate::routes::vetting::RevocationReviewState,
    )),
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
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .nest("/v1", build_api_chain(&RoutingConfig::default(), &[]))
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

/// Attach the static Trust-Task URL gate to a `routes!(...)` group in one call.
///
/// Collapses the former two-step `let <name> = TrustTask::new(<url>).expect(...)`
/// declaration + `task_routes(routes!(handler), <name>)` usage into a single
/// `tt(routes!(handler), <url>)`, so each mount reads as "handler(s) → their
/// Trust-Task URL" on one line and the URL lives at the route, not in a separate
/// block at the top of the builder.
fn tt(
    routes: utoipa_axum::router::UtoipaMethodRouter<AppState>,
    url: &'static str,
) -> utoipa_axum::router::UtoipaMethodRouter<AppState> {
    task_routes(routes, TrustTask::new(url).expect("static Trust-Task URL"))
}

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
    router_with_inner(routing, website_state, &[])
}

#[cfg(feature = "website")]
pub fn router_with_xff(
    routing: &RoutingConfig,
    website_state: Option<crate::website::WebsiteState>,
    trust_xff_cidrs: &[IpNetwork],
) -> Router<AppState> {
    router_with_inner(routing, website_state, trust_xff_cidrs)
}

#[cfg(not(feature = "website"))]
pub fn router_with(routing: &RoutingConfig) -> Router<AppState> {
    router_with_inner(routing, &[])
}

#[cfg(not(feature = "website"))]
pub fn router_with_xff(routing: &RoutingConfig, trust_xff_cidrs: &[IpNetwork]) -> Router<AppState> {
    router_with_inner(routing, trust_xff_cidrs)
}

#[cfg(not(feature = "website"))]
fn router_with_inner(routing: &RoutingConfig, trust_xff_cidrs: &[IpNetwork]) -> Router<AppState> {
    // `build_api_chain` returns an `OpenApiRouter` (the single source of truth
    // for both routes and `/openapi.json`); split off the served axum `Router`
    // for `assemble` to nest. The OpenAPI document is rebuilt from the same
    // assembly by [`openapi_spec`] (which `assemble` serves), so the two cannot
    // drift.
    let api_chain = build_api_chain(routing, trust_xff_cidrs)
        .split_for_parts()
        .0;
    with_csrf(assemble(routing, api_chain))
}

#[cfg(feature = "website")]
fn router_with_inner(
    routing: &RoutingConfig,
    website_state: Option<crate::website::WebsiteState>,
    trust_xff_cidrs: &[IpNetwork],
) -> Router<AppState> {
    let api_chain = build_api_chain(routing, trust_xff_cidrs)
        .split_for_parts()
        .0;
    with_csrf(assemble_with_website(routing, api_chain, website_state))
}

/// Attach the CSRF double-submit + `Sec-Fetch-Site` middleware
/// (Phase 5 M5.2.2). Applied here in the canonical router builder
/// — not in `server.rs` — so every integration test exercises CSRF
/// exactly as production does (P3.2). The matcher in `routing::csrf`
/// compares against the post-nest URI, so the layer must sit outside
/// the `/v1` nest, which it does (the assembled router is the full
/// path surface). `server.rs` wraps this with host-dispatch / CORS /
/// trace / timeout, leaving the inner→outer ordering identical to the
/// previous in-`server.rs` placement.
fn with_csrf(app: Router<AppState>) -> Router<AppState> {
    app.layer(axum::middleware::from_fn(crate::routing::csrf::enforce))
}

/// Build the merged API+unauth surface. Identical shape regardless
/// of the `website` feature; `routing` is currently unused inside
/// the chain (the API mount prefix is applied by [`assemble`] /
/// [`assemble_with_website`]) but threaded through so a future
/// per-mount override can land without changing this function's
/// signature.
fn build_api_chain(
    _routing: &RoutingConfig,
    trust_xff_cidrs: &[IpNetwork],
) -> OpenApiRouter<AppState> {
    // Canonical cross-cutting auth tasks from trusttasks-tf. The legacy
    // openvtc/vtc/auth/legacy/* slugs were VTC-specific reimplementations
    // of primitives that VTA + did-hosting also have; consolidating here
    // so a multi-service deployment can use one client library.
    // Browser-SPA convenience surface: `whoami` + `sign-out`. Both
    // are bound to the access-token session (cookie or bearer);
    // sign-out revokes the server-side session and clears the
    // browser cookies in one trip.
    // Audit log list — super-admin only since envelopes carry
    // plaintext DIDs.
    // Admin invites — REST surface for `vtc admin invite`. Single
    // Trust Task covers GET + POST on `/admin/invites` (same Phase-0
    // workaround community/profile + admin/config use); DELETE on
    // `/admin/invites/{jti}` has its own Trust Task since it's on a
    // distinct mount.
    // `members_update` (`members/update/1.0`) shares the
    // `members/{did}` mount with `show` for now — TrustTaskRouter
    // doesn't support per-method Trust-Task selectors yet
    // (same Phase-0 workaround `admin/config` + `community/profile`
    // use). When that lands, split show + update.
    // `members_admin_remove` (`members/admin-remove/1.0`) shares
    // the `members/{did}` mount with show + update for now —
    // TrustTaskRouter doesn't support per-method Trust-Task
    // selectors yet. The standalone task exists on disk +
    // index.json so the soft-gate surface stays complete.
    // POST + GET share `/v1/join-requests`, each carrying its own Trust
    // Task. The earlier note here said enforcement had to collapse onto
    // `submit` until TrustTaskRouter gained per-method selectors; that
    // was mistaken — `task_routes` layers the *method* router and axum
    // merges same-path routers per method, so both verbs are enforced
    // independently.
    // The unauthenticated `/join-requests` POST submit and `/status` move to
    // `build_unauth_routes` (P0.5) so the governor + 64 KiB cap apply; their
    // Trust Tasks are declared there. (`accept` is gone — retired upstream,
    // folded into `members/vmc` + `requestId`.) The admin GET list shares the
    // `/join-requests` path with the governed POST but carries its own
    // `join-requests/list/0.1` task (axum merges same-path method routers
    // per method).
    // Policies (Phase 2 M2.3). Three distinct Trust Tasks for the
    // three POST endpoints — upload, activate, test — so SIEM
    // filters + soft-gate consumers can target each precisely.
    // Phase 4 M4.3 + M4.4 — personhood lifecycle.
    // `members_personhood_revoke` (`members/personhood/revoke/1.0`)
    // exists on disk + in index.json so the soft-gate surface
    // stays complete, but the DELETE method shares the
    // `members/personhood/assert/1.0` mount at the router
    // layer pending per-method selectors. Same workaround as
    // `members/{did}` show + update + admin-remove.
    // Phase 4 M4.6 — VRC trust-graph endpoints.
    // Phase 4 M4.8 — endorsement type registry + custom
    // endorsement CRUD. Each verb carries its own canonical
    // task (same-path verbs are enforced per method — see
    // `vti_common::trust_task::openapi`).
    // `endorsements_show` + `endorsements_revoke` share the
    // `endorsements/{id}` mount with the Trust Task header
    // pinned to the `show` variant. Standalone tasks ship on
    // disk + in index.json so the soft-gate surface stays
    // complete (same workaround as members/{did}, etc.).
    // Phase 3 M3.8 — trust-registry reconciler diagnostics.
    // Admin-gated (not super-admin) so on-call ops can read
    // queue depth + RTBF-batched + failed counts without the
    // super-admin role.
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
        // The git namespace family has no REST route at all: every mutation
        // and every read — the administrator's view, the namespace and
        // repository listings, the break-glass list, each repository's
        // drift, the rights lists, the bridge job queue, the Trust Registry
        // projection, the linked-account roster and the activity feed alike
        // — is a signed `git-ns/*` Trust Task on the document endpoint
        // (`git_ns::admin_reads`, `git_ns::tasks`), authorized by the
        // signer's own git rights or ACL capability.
        // BitstringStatusList publication (M2.11). Trust-Task-
        // exempt — external verifiers don't carry our extension
        // header (same rationale as `did.jsonl`).
        .routes(routes!(status_lists::show))
        // Auth routes. `POST /v1/auth/{challenge,authenticate,refresh}`
        // are unauthenticated and live in `build_unauth_routes` so the
        // tower-governor + tighter body cap apply. The two
        // session-management endpoints below are authenticated and
        // stay on the main chain.
        //
        // The session listing and revocation are the signed
        // `auth/sessions/list/0.1` and `auth/revoke-session/0.2`, served by the
        // spine (`trust_tasks::admin_tasks`) on every transport; neither has a
        // route. `whoami` describes the bearer session the request carries,
        // which a signed document does not have, so it stays with the session
        // surface.
        .routes(tt(
            routes!(auth::whoami),
            "https://trusttasks.org/spec/auth/whoami/0.1",
        ))
        // Sign-out ends the browser's cookie session: it clears the cookie
        // pair `auth/admin-session` set, which no Trust Task describes. It had
        // borrowed `revoke-session`, whose request names a session or a
        // subject and whose response counts them; sign-out takes neither and
        // answers `204`. It carries no binding, and goes when the cookie
        // session does.
        .routes(routes!(auth::sign_out))
        // Audit log (super-admin only): `audit/list` and `audit/verify` are
        // signed documents only.
        // Config lives at `/v1/admin/config` on canonical `config/{show,patch}`.
        // The pre-MVP `GET, PATCH /v1/config` surface is gone (#710): every field
        // it carried has a canonical owner — `vtc_did` / `vtc_name` /
        // `vtc_description` on `vtc/community/profile/{show,update}`,
        // `public_url` in the config-store overlay reached through
        // `config/{show,patch}`.
        // The ACL has no route: the five `acl/*` tasks are signed documents
        // served only at `POST /v1/trust-tasks` (`trust_tasks::acl_tasks`),
        // on every transport.
        //
        // Community profile. The read (`vtc/community/profile/show/0.1`) and the
        // edit (`vtc/community/profile/update/0.1`) are signed documents only.
        // Public read of the community profile. Trust-Task-exempt and
        // unauthenticated — visitors landing on the default public
        // website need the community's name + description + DIDs to
        // render before any session exists. Curated subset only (no
        // extensions, no registry status).
        .routes(routes!(community::profile::get_public_profile))
        // The community DID as a QR code, for a wallet to scan off the landing
        // page. Public for the same reason as the profile: it is the same DID.
        .routes(routes!(community::did_qr::get_did_qr))
        // Community branding (`vtc/community/branding/{show,update}/0.1`) and
        // what the community asks an applicant to tell it about themselves
        // (`vtc/community/requested-attributes/{show,update}/0.1`), both
        // published on `join-requests/manifest/0.2`, are signed documents
        // only now (`trust_tasks::surface_tasks`) — their admin-only bearer
        // REST mounts had no caller left once `vtc-client` and the admin
        // console signed them instead.
        // Whether the join manifest answers a caller this community cannot
        // identify. Admin REST with no Trust Task of its own — and not a
        // member of the profile, whose `show` response is a published schema
        // that permits no new ones.
        // The runtime configuration (`config/{show,patch,reload,restart}/0.1`)
        // has no route: each is a signed document served by the spine
        // (`trust_tasks::admin_tasks`) on every transport.
        // Export / import (`vtc/config/{export,import}/0.1`) have no route
        // here: both declare `proof` REQUIRED and are served only as signed
        // documents at `POST /v1/trust-tasks` (#1641 phase 2, batch 3). Their
        // bearer routes were removed rather than kept transitional, because no
        // client called them.
        // Install claim (`vtc/install/claim/{start,finish}/0.2`) and admin
        // bootstrap (`vtc/admin/bootstrap/0.1`, M0.6.2 — closes the install
        // carve-out and writes the first admin ACL entry) are signed
        // documents only now (`trust_tasks::install_tasks`): each verb's own
        // bearer artifact (the install JWT, the `registrationId` `start`
        // minted, the setup-session JWT) is the credential, so no proof is
        // required and no REST route binds them. Their dedicated,
        // `Trust-Task`-header-gated REST mounts had no caller once the admin
        // console signed the documents instead.
        // Admin passkey management (M0.6.3), on the canonical
        // `auth/passkey/*` tasks (trust-tasks-tf#145).
        //
        // Each leg now carries its OWN task, where the retired
        // `admin/passkeys/{register,revoke}/1.0` pair had start and
        // finish sharing one URI. A shared URI could not describe
        // either leg honestly: start takes no assertion and returns a
        // challenge, finish takes the assertion and returns nothing
        // like a challenge, so one schema covering both had to permit
        // every member of each — which is how a finish missing its UV
        // assertion validated cleanly.
        //
        // Step-up UV is unchanged in behaviour and is now *specified*:
        // `enroll/start/0.2` returns `uvOptions` alongside the
        // registration challenge and `enroll/finish/0.2` requires the
        // matching `uvCredential`; revoke's two legs do the same. The
        // canonical specs were written from this implementation, so
        // the wire shape is what it always was.
        .routes(tt(
            routes!(admin::passkeys::list),
            "https://trusttasks.org/spec/auth/passkey/list/0.1",
        ))
        .routes(tt(
            routes!(admin::passkeys::register_start),
            "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2",
        ))
        .routes(tt(
            routes!(admin::passkeys::register_finish),
            "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2",
        ))
        .routes(tt(
            routes!(admin::passkeys::revoke_start),
            "https://trusttasks.org/spec/auth/passkey/revoke/start/0.1",
        ))
        .routes(tt(
            routes!(admin::passkeys::revoke_finish),
            "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.1",
        ))
        // Members' step-up passkeys (`crate::step_up_passkey`) have no route
        // here: issuing, redeeming, revoking and an administrator's listing
        // (`auth/passkey/admin-list/0.1`) are Trust Tasks served only by the
        // spine (`trust_tasks::step_up_passkey_tasks`), on every transport.
        // The console's signing keys are `auth/signing-key/*` on the spine
        // (`trust_tasks::signing_key_tasks`), and have no route.
        // Admin invites (`vtc/admin/invites/{list,create,revoke}/0.1`) have no
        // route: each is a signed document served by the spine
        // (`trust_tasks::admin_tasks`) on every transport.
        // A self-hosted community's own DID log (Keyring VTI-35) is the signed
        // `did-management/did/register/0.1` document only — see
        // `admin::did_register`.
        // Directory ceremony (read-only field projection via the
        // ceremony decision pipeline).
        // Ceremony registry — the admin-UI renders its flow + simulator
        // from these manifests (purpose / fields / facts template).
        // Members (Phase 1 M1.4–M1.6). The roster (`vtc/members/list/0.1`) is a
        // signed document only.
        // Departed (tombstoned/historical) members. The literal `/removed`
        // must precede the `/{did}` catchall so axum's path-trie doesn't route
        // "removed" as a DID. The purge (`vtc/members/purge/0.1`) and a
        // member's own departure (`vtc/members/self-remove/0.1`) have no
        // route: both are signed documents only.
        // Renewal (M2.13) is a signed document only
        // (`vtc/members/renew/0.1`, `trust_tasks::member_tasks`); the bearer
        // REST route it once also served had no caller once the spine
        // dispatched it (#1809) and was removed.
        //
        // DID rotation (M2.15.1) is likewise a signed document only —
        // `vtc/members/rotate-challenge/0.1` opens the two-step ceremony,
        // `vtc/members/rotate/0.1` applies the co-signed swap atomically —
        // for the same reason.
        // Reciprocal-VMC request — ask an active member to issue + send the
        // member → community half of the membership pair. The member replies
        // asynchronously over the `members/vmc/1.0` DIDComm surface.
        // Phase 4 M4.3 + M4.4 — personhood lifecycle. The challenge, the
        // assertion and the revoke are all signed documents only
        // (`vtc/members/personhood/{challenge,assert,revoke}/0.1`); the
        // revoke's bearer REST route had no caller once the spine dispatched
        // it (#1809) and was removed.
        // Phase 4 M4.6 — the VRC trust-graph member list
        // (`vtc/relationships/list/0.2`) is a signed document only; its
        // bearer REST route lost its last caller (the admin console) when
        // that console moved onto the signed door and was removed.
        // #1215 — the membership pair's bodies for one member
        // (`vtc/members/credentials/0.1`) is a signed document only.
        // Admin connections-graph view — the member-relationship (VRC) graph.
        //
        // Relationship revoke (`vtc/relationships/{revoke/0.1,revoke/0.2}`) is
        // a signed document only. `0.1` kept a bearer REST route because it
        // could reach only two of the three capacities the bearer route
        // authorized — the edge's own issuer, or an administrator — and not
        // the third: a `VrcRevokeAuthorization` proving control of a pairwise
        // relationship DID. `0.2` (trustoverip/dtgwg-trust-tasks-tf#689) adds
        // that as an optional `pop` bound to the document's own `id` rather
        // than to a REST session, so the signed door now reaches all three
        // and the REST route was removed (see `trust_tasks::member_tasks`'s
        // `handle_relationships_revoke_v0_2`).
        // Suspend and restore (#1079) are `vtc/relationships/{suspend,restore}`
        // on the spine (`trust_tasks::surface_tasks`), and have no route.
        // #1067 — the VPC (persona annotation) on an existing
        // edge. POST + DELETE share one task mount, the same
        // workaround the personhood assert/revoke pair uses; the
        // two verbs are one operation in either direction.
        .routes(tt(
            routes!(relationships::attach_persona, relationships::detach_persona),
            "https://trusttasks.org/spec/vtc/relationships/persona/0.1",
        ))
        // Phase 4 M4.8.1 — operator-uploaded endorsement type registry. The
        // listing is REST; `register` and `delete` are signed documents only.
        // The community schema store (Issues + Accepts registry) is
        // `vtc/schemas/*` on the spine, and has no route.
        // Phase 4 M4.8.2-4 — custom endorsement issuance, retrieval and
        // revocation (`vtc/endorsements/{issue,list,show,revoke}/0.1`) are
        // all signed documents only now: each bearer REST route had no
        // caller once the spine dispatched it and was removed (issuance,
        // #1809; retrieval and revocation, tt-tf#689).
        // Invitation Credential (VIC) issuance + listing — the operator side of
        // the VIC auto-join ceremony. Admin / Moderator / Issuer. POST + GET on
        // /invitations share the `issue/1.0` mount; the standalone `list/1.0`
        // task is declared on disk for the soft-gate surface.
        // Split per method, as with admin/invites above: issuance returns a
        // bearer credential, listing must never re-disclose one. The old
        // shared `issue/1.0` mount could not state both contracts.
        // Revoke an outstanding invitation (flips its revocation bit).
        // Get an issued invitation to the DID it admits: push an offer to it,
        // or return the offer for a QR code (Keyring VTI-21 / VTI-32).
        // Recognition (trust-graph) lookup — admin window into TRQP recognise.
        // Naming vetters (`vtc/vetting/vetters/grant/0.1`, OpenVTC vetting
        // design §10) is a signed document only, withdrawn through
        // endorsements/revoke.
        // The vetter registry's admin surface. Resend
        // (`vtc/vetting/vetters/resend/{0.1,0.2}`) is a signed document only:
        // `0.1` enforces the task a vetter sends for themselves, `0.2` adds
        // the `memberDid` an administrator names to resend on a vetter's
        // behalf (tt-tf#689) — what let the admin-only REST resend route
        // retire. The grant listing (`vtc/vetting/vetters/grants/list/0.1`),
        // the automatic-grant configuration
        // (`vtc/vetting/auto-grant/{show,update}/0.1`) and the withdrawal
        // notices (`vtc/vetting/revocations/list/0.1`) are signed documents
        // only too now (`trust_tasks::surface_tasks`) — their admin-only
        // bearer REST mounts had no caller left once `vtc-client` and the
        // admin console signed them instead.
        // The public listing (`vtc/vetting/vetters/list/0.1`) has no route:
        // the console sends the same signed document an applicant does.
        // The by-DID lookup the listing cannot answer (`vetters/show/0.1`,
        // #1651) is a signed document only.
        // Hidden-vetter admission (development branch `zkp-pcs`): derive this
        // community's PCS keys and publish them on a criterion. Admin REST with
        // no Trust Task of its own — turning the mode on is an act of
        // administration, not a task a member can ask for.
        .merge({
            #[cfg(feature = "vetting-pcs")]
            {
                OpenApiRouter::new().routes(routes!(vetting_hidden::publish_hidden_vetting))
            }
            #[cfg(not(feature = "vetting-pcs"))]
            {
                OpenApiRouter::new()
            }
        });
    // A member's update and removal (`vtc/members/{update,admin-remove}/0.1`)
    // are signed documents only.
    // Join requests (Phase 1 M1.7–M1.10). The admin queue
    // (`vtc/join-requests/list/0.1`) and its decision
    // (`vtc/join-requests/decide/0.1`) are signed documents only.
    // The vetting facts a request was decided on — admin REST with no Trust
    // Task of its own.
    // The join manifest has no route: the console reads it as the signed
    // `vtc/join-requests/manifest/0.2` document applicants send.
    // (Manifest discovery moved to the single `POST /v1/trust-tasks`
    // document endpoint — `join-requests/manifest/1.0` is now a Trust
    // Task verb, no longer a bespoke GET.)
    // The administrator's credential query (`vtc/join-requests/query`),
    // a join request's vetting facts (`vtc/join-requests/vetting/show`) and
    // the host's rooms (`vtc/rooms/list`) are served on the spine, and
    // have no route.
    // Policies: every verb is a signed document only
    // (`trust_tasks::policy_tasks`).

    // Phase 5 M5.5 — public-website management. Every verb is a signed
    // document now (`trust_tasks::website_tasks`): the chunked upload,
    // deploy and ranged reads already were; the listing, delete, generation
    // history and rollback verbs join them here. None has a REST route —
    // their dedicated, `Trust-Task`-header-gated mounts had no caller once
    // the admin console signed the documents instead, and nothing in this
    // repository (no admin-ui page, no `cnm`/`vtc-client` command) called
    // them either.

    // P3.9 — encrypted backup / restore has no route: a backup is the
    // `vtc/backup/export` + `backup/*` Trust Tasks, over TSP or DIDComm only.

    let api = api
        // §14.4 — every authenticated API route inherits the 1 MiB
        // global body cap. The per-route overrides above for
        // `/v1/website/*` apply first; this layer
        // is the default for everything else.
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

    // Unauthenticated routes — tighter body cap + per-IP governor.
    let unauth = build_unauth_routes(trust_xff_cidrs);
    api.merge(unauth)
}

/// Build the unauthenticated sub-router: POST routes that drive expensive
/// crypto against attacker-controlled bytes, plus the single Trust Task
/// document endpoint (`POST /trust-tasks`), which now also carries
/// `auth/challenge`, `auth/authenticate` and pre-session install/recognise
/// verbs that used to have dedicated mounts here.
///
/// - `POST /auth/refresh` (also the admin console's cookie session renewal)
/// - `POST /trust-tasks`
///
/// Layers:
/// - [`UNAUTH_BODY_SIZE`] body cap (tighter than the 1 MiB main
///   API cap — generous enough for a JWE / sealed-transfer
///   envelope, small enough to reject blob floods).
/// - Per-IP `tower-governor` via [`TrustedProxyKeyExtractor`] (or the peer
///   address when `trust_xff_cidrs` is empty): a burst of 10, then one
///   request every 5 s. `per_second(5)` is a replenishment *interval*, not a
///   rate — a bigger number is a tighter limit. A refusal is a `429` in the
///   shape [`crate::routing::rate_limit`] defines, reporting limiter `unauth`.
fn build_unauth_routes(trust_xff_cidrs: &[IpNetwork]) -> OpenApiRouter<AppState> {
    // Canonical cross-cutting auth tasks from trusttasks-tf.
    //
    // Bearer→cookie bridge: the SPA posts an access token it already
    // holds (from the VTA-wallet login or `POST /v1/auth/`), the daemon
    // validates it and mirrors it into the `vtc_admin_session` + `csrf`
    // cookies. This is the *only* cookie-session mint besides passkey
    // login — the fused `/v1/auth/admin-login` that authenticated and set
    // cookies in one call was removed in #710, since it re-implemented
    // `POST /v1/auth/` to add a side-effect this task already provides.
    // Browser-friendly passkey login — one canonical spec serves both
    // initial login and AAL step-up, selected by the start payload's
    // `purpose` field (0.2's camelCase `stepUp`). Login is genuinely
    // unauthenticated; step-up authenticates the caller inside the
    // handler, which is why both live on this chain.
    // Phase 3 M3.10 — cross-community session mint. Sits in the
    // unauth chain (not the main API chain) so the tower-governor
    // + 64 KB body cap apply: the handler runs DID resolution,
    // outbound HTTP fetch of the foreign `statusListCredential`
    // URL, Rego policy eval, and a session JWT mint, all driven by
    // attacker-supplied JSON. Behind the rate limit, a sustained
    // SSRF / CPU-amplification probe is throttled to one request
    // every 5 s per source IP after a burst of 10.
    // Step 1 of the recognise flow — issues the single-use challenge nonce the
    // holder binds into the VP presented to `/auth/recognise`. Same unauth
    // chain (governor + body cap) as the other challenge endpoints.
    // P0.5 — the unauthenticated join-request POSTs (submit / status, plus
    // the member-facing `members/vmc` delivery that closes an approved join)
    // do the same attacker-driven crypto as recognise (Ed25519 holder-binding
    // verify, reciprocal-VC counter-sign verify, Rego eval) but were left on
    // the 1 MiB / no-limiter main chain. Move them here so the governor + 64
    // KiB cap apply. The admin GET list + show + POST decide and the
    // public GET manifest stay on the `api` chain.

    // `TrustedProxyKeyExtractor` needs `ConnectInfo` to identify the peer. In
    // production the `axum::serve` call in `server.rs` wires
    // `into_make_service_with_connect_info` so it's always present; in
    // integration tests built on `Router::oneshot` it is not, and the
    // extractor refuses every request. A synthetic-`ConnectInfo` middleware
    // inserts a `127.0.0.1` placeholder **only when missing** so those calls
    // take the peer-IP path.
    //
    // It is layered **only when nothing is trusted**, and that condition is
    // the whole safety argument: a synthesised peer is a manufactured anchor,
    // and with a non-empty trust list it could land *inside* a trusted CIDR —
    // at which point a request with no peer at all would be allowed to name
    // its own rate-limit bucket through `X-Forwarded-For`. With an empty list
    // no address is trusted, so the placeholder can only ever be keyed on
    // directly. A configured VTC therefore keeps the fail-closed behaviour
    // (no peer → refused), which is what production sees anyway.
    let synth_connect_info = trust_xff_cidrs.is_empty().then(|| {
        axum::middleware::from_fn(vti_common::rate_limit::insert_default_connect_info_if_missing)
    });

    let unauth_router = OpenApiRouter::<AppState>::new()
        // Redeem a credential offer over HTTPS — for a holder with no messaging
        // service, such as an invitee who scanned a delivered offer. The
        // key-binding proof inside is the authority; the governor and body cap
        // bound what an unauthenticated caller can make it verify.
        .routes(tt(
            routes!(credential_exchange::request),
            <trust_tasks_rs::specs::credential_exchange::request::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        ))
        // `auth/challenge/0.1` and `auth/authenticate/0.1`'s dedicated,
        // `Trust-Task`-header-gated REST mounts had no caller left once
        // `vta_sdk::auth_light` (shared by the VTA client and `cnm
        // vetting`'s bearer-session login, `VtcClient::connect`) switched to
        // signing `auth/challenge/0.1` / `authenticate/0.2` documents against
        // `POST /v1/trust-tasks` instead (#1858) — the same door
        // `trust_tasks::auth_tasks` already dispatched `0.2`/`0.3` on. See
        // that module's doc for the pre-session dispatch this family gets.
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
        // Completes the wallet's loop. Without this alias the extension could
        // log in header-free above but had to send a `Trust-Task` header (or,
        // before the REST fast-path, an authcrypt DIDComm envelope) to spend
        // the refresh token it was just handed — so it re-ran the whole SIOP
        // round-trip on every access-token expiry instead. Same handler; the
        // op `type` rides in the body exactly as it does on `/wallet/auth/`.
        .route("/wallet/auth/refresh", post(auth::refresh))
        // `auth/refresh/0.1`'s dedicated REST mount stays: it is also the
        // admin console's own **cookie**-bound session renewal
        // (`vtc_admin_refresh`), which has no signed-document equivalent — a
        // browser cookie carries no DID key to sign with. `auth/refresh/0.2`
        // (`trust_tasks::auth_tasks`) adds the signed-document path beside
        // it for TSP/DIDComm/HTTPS callers that hold a key; see that
        // module's doc for the full argument.
        .routes(tt(
            routes!(auth::refresh),
            "https://trusttasks.org/spec/auth/refresh/0.1",
        ))
        .routes(tt(
            routes!(auth::admin_session),
            "https://trusttasks.org/spec/vtc/auth/admin-session/0.1",
        ))
        .routes(tt(
            routes!(auth::passkey_login_start),
            "https://trusttasks.org/spec/auth/passkey/login/start/0.2",
        ))
        .routes(tt(
            routes!(auth::passkey_login_finish),
            "https://trusttasks.org/spec/auth/passkey/login/finish/0.2",
        ))
        // Install claim (`vtc/install/claim/{start,finish}/0.2`) and
        // cross-community recognition (`vtc/auth/recognise/{challenge/0.1,
        // 0.2}`) are signed documents only now (`trust_tasks::install_tasks`,
        // `trust_tasks::recognise_tasks`); their dedicated, `Trust-Task`-
        // header-gated REST mounts had no caller left (recognise never had one
        // in this workspace; the admin console signs install/claim + bootstrap
        // instead).
        //
        // `vtc/relationships/publish/0.2` (publishing a relationship edge,
        // authenticated by the Trust Task document's own proof rather than a
        // bearer token, #1084) was already served on the spine
        // (`trust_tasks::member_tasks::handle_relationships_publish`) —
        // `vtc-client` has signed it since #1845, and its bearer route
        // (`routes::relationships::publish`, the twin `publish_inner` also
        // calls) had no caller left either.
        // The single Trust Task document endpoint (P0.5: governed unauth
        // chain). The holder-facing join ceremony verbs (submit/request,
        // manifest, status) all arrive here as Trust Task documents
        // and are routed internally by document `type`; the holder is
        // authenticated by the document's `eddsa-jcs-2022` proof. No
        // `Trust-Task` header gate — the document's own `type` is the
        // identity.
        //
        // Admin verbs **are** routed here since #1641 phase 2, starting with
        // the member ones. "Unauthenticated" is a property of the transport,
        // not of the authority: the spine holds a document to the proof,
        // recipient, freshness and replay rules its specification declares, and
        // the verb reads the *verified signer's* ACL entry. See
        // `trust_tasks::admin_signer`.
        //
        // Its body cap is not `UNAUTH_BODY_SIZE`: each Trust Task type declares
        // its own largest document (`crate::trust_tasks::size`, 64 KiB unless
        // its specification needs more, and only while it is served), and the
        // spine refuses a document over its type's limit before parsing it.
        // The route admits the largest any served type accepts, so that check
        // is the one that decides.
        .layer(DefaultBodyLimit::max(UNAUTH_BODY_SIZE));

    // One extractor covers both cases: with an empty CIDR list
    // `TrustedProxyKeyExtractor` trusts nothing and so keys on the socket
    // peer, which is exactly `PeerIpKeyExtractor`. Branching on the list only
    // to pick between two behaviours that already coincide is a chance to get
    // the arms the wrong way round for no gain.
    let cfg = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .key_extractor(TrustedProxyKeyExtractor::new(trust_xff_cidrs.to_vec()))
            .finish()
            .expect("governor config values are static and non-zero"),
    );
    // `/trust-tasks` is not behind the tower layer: it charges a document to
    // one of several budgets depending on who signed it
    // (`routing::trust_task_admission`). Anonymous documents still pay this
    // governor's own limiter state, so an address has one anonymous budget
    // across the whole chain, not one here and another on `/trust-tasks`.
    let limits = crate::routing::trust_task_admission::TrustTaskLimits::new(
        cfg.limiter().clone(),
        TrustedProxyKeyExtractor::new(trust_xff_cidrs.to_vec()),
    );
    let unauth_router = unauth_router
        .layer(
            GovernorLayer::new(cfg)
                .error_handler(crate::routing::rate_limit::governor_error_response),
        )
        .merge(
            OpenApiRouter::<AppState>::new()
                .routes(routes!(trust_tasks::dispatch))
                .layer(axum::middleware::from_fn_with_state(
                    limits,
                    crate::routing::trust_task_admission::client_address,
                ))
                .layer(DefaultBodyLimit::max(
                    crate::trust_tasks::size::largest_max_document_bytes(),
                )),
        );
    match synth_connect_info {
        Some(layer) => unauth_router.layer(layer),
        None => unauth_router,
    }
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
    fn openapi_spec_documents_the_bearer_scheme_and_the_signed_verbs_shapes() {
        let spec = openapi_spec();
        assert_eq!(spec.info.title, "Verifiable Trust Community (VTC) API");
        // The bearer scheme is present, and the response schema of a verb
        // served only as a signed document is still published: the console's
        // wire types are generated from it.
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
            "/v1/auth/refresh",
            "/v1/admin/passkeys",
            "/v1/relationships/{id}/persona",
            "/v1/credential-exchange/request",
        ] {
            assert!(paths.contains_key(p), "spec missing documented path {p}");
        }
        // A floor, not a count: it catches the spec losing whole groups, and
        // falls as REST routes move to signed-only Trust Tasks — most
        // recently pre-session auth, install claim + admin bootstrap,
        // cross-community recognition, relationships publish, four website
        // admin verbs, `auth/challenge`+`authenticate`, and the vetter grant
        // listing / auto-grant / withdrawal notices / community branding /
        // requested attributes (`trust_tasks::{auth_tasks,install_tasks,
        // recognise_tasks,website_tasks,surface_tasks}` / `member_tasks`).
        assert!(
            paths.len() >= 15,
            "expected the documented surface to be >= 15 paths, got {}",
            paths.len()
        );
    }

    /// The verbs served only as signed documents at `POST /v1/trust-tasks`
    /// have no REST route: no path, and no method on a path that stays for
    /// another verb.
    #[test]
    fn signed_only_verbs_have_no_route() {
        let spec = openapi_spec();
        let paths = &spec.paths.paths;
        for p in [
            "/v1/acl",
            "/v1/acl/{did}",
            "/v1/members/me",
            "/v1/members/{did}/purge",
            "/v1/members/{did}/personhood/challenge",
            "/v1/members/{did}/personhood",
            "/v1/members/{did}/relationships",
            "/v1/members/me/renew",
            "/v1/members/me/rotate",
            "/v1/members/me/rotate/challenge",
            "/v1/endorsement-types/{type_uri}",
            "/v1/vetting/vetters/list",
            "/v1/join-requests/manifest",
            "/v1/join-requests/{id}/status",
            "/v1/health/diagnostics",
            "/v1/registry/sync-jobs",
            "/v1/registry/sync-jobs/retry",
            "/v1/registry/sync-jobs/discard",
            "/v1/registry/records",
            "/v1/audit",
            "/v1/admin/config",
            "/v1/admin/config/reload",
            "/v1/admin/config/restart",
            "/v1/admin/invites",
            "/v1/admin/invites/{jti}",
            "/v1/auth/sessions",
            "/v1/auth/sessions/{session_id}",
            "/v1/git-ns/drift",
            "/v1/git-ns/rights",
            "/v1/git-ns/rights/issued-by-departed",
            "/v1/git-ns/jobs",
            "/v1/git-ns/projection",
            "/v1/git-ns/accounts",
            "/v1/git-ns/activity",
            "/v1/community/profile",
            "/v1/ceremonies",
            "/v1/directory/{did}",
            "/v1/recognition/check",
            "/v1/members/removed",
            "/v1/members/{did}/request-vmc",
            "/v1/join-requests/{id}",
            "/v1/relationships/graph",
            "/v1/invitations",
            "/v1/invitations/{id}",
            "/v1/invitations/deliver",
            "/v1/endorsement-types",
            "/v1/members",
            "/v1/members/{did}",
            "/v1/members/{did}/credentials",
            "/v1/join-requests",
            "/v1/join-requests/{id}/decide",
            "/v1/policies",
            "/v1/policies/{id}",
            "/v1/policies/{id}/activate",
            "/v1/admin/did/register",
            "/v1/audit/verify",
            "/v1/vetting/vetters/show",
            "/v1/community/join-discovery",
            "/v1/join-requests/query",
            "/v1/join-requests/{id}/vetting",
            "/v1/relationships/{id}/suspend",
            "/v1/relationships/{id}/restore",
            "/v1/rooms",
            "/v1/schemas",
            "/v1/schemas/accepts",
            "/v1/schemas/accepts/{id}",
            "/v1/schemas/{type_uri}",
            // Relationship revoke (`vtc/relationships/revoke/{0.1,0.2}`) lost
            // its last route: `0.2`'s pairwise `pop` reaches the capacity the
            // bearer route existed for (tt-tf#689).
            "/v1/relationships/{id}",
            // Endorsement retrieval and revocation
            // (`vtc/endorsements/{list,show,revoke}/0.1`) had no caller left
            // once the spine dispatched them (tt-tf#689).
            "/v1/credentials/endorsements",
            "/v1/credentials/endorsements/{id}",
            // Admin resend of another member's vetter grant
            // (`vtc/vetting/vetters/resend/0.2`'s `memberDid`) replaces the
            // admin-only REST route (tt-tf#689).
            "/v1/vetting/vetters/{memberDid}/resend",
            // `auth/challenge/0.1` and `auth/authenticate/{0.1,0.2,0.3}`
            // (`trust_tasks::auth_tasks`) are signed documents only now:
            // `vta_sdk::auth_light` (shared by the VTA client and `cnm
            // vetting`'s bearer-session login) switched to posting them
            // against `/v1/trust-tasks` (#1858), so their dedicated,
            // `Trust-Task`-header-gated REST mounts had no caller left.
            "/v1/auth/challenge",
            "/v1/auth/",
            //
            // First-admin onboarding (`trust_tasks::install_tasks`) and
            // cross-community recognition (`trust_tasks::recognise_tasks`).
            "/v1/install/claim/start",
            "/v1/install/claim/finish",
            "/v1/admin/bootstrap",
            "/v1/auth/recognise/challenge",
            "/v1/auth/recognise",
            // `vtc/relationships/publish/0.2` — already served on the spine
            // (`trust_tasks::member_tasks`); its bearer-less REST route had no
            // caller left once `vtc-client` signed it instead (#1845).
            "/v1/relationships",
            // The website's listing, delete, generation history and rollback
            // (`trust_tasks::website_tasks`) replace their dedicated,
            // `Trust-Task`-header-gated REST mounts.
            "/v1/website/files",
            "/v1/website/files/{*path}",
            "/v1/website/generations",
            "/v1/website/rollback/{gen_num}",
            // The vetter grant listing (`vtc/vetting/vetters/grants/list/0.1`),
            // automatic-grant configuration
            // (`vtc/vetting/auto-grant/{show,update}/0.1`), withdrawal notices
            // (`vtc/vetting/revocations/list/0.1`), community branding
            // (`vtc/community/branding/{show,update}/0.1`) and requested
            // attributes (`vtc/community/requested-attributes/{show,update}/0.1`)
            // are signed documents only (`trust_tasks::surface_tasks`) — their
            // admin-only bearer REST mounts had no caller left once
            // `vtc-client` and the admin console signed them instead. Naming a
            // vetter (`vtc/vetting/vetters/grant/0.1`) was already spine-only,
            // so this path never carried a `POST` either.
            "/v1/vetting/vetters",
            "/v1/vetting/auto-grant",
            "/v1/vetting/revocations",
            "/v1/community/branding",
            "/v1/community/requested-attributes",
        ] {
            assert!(!paths.contains_key(p), "{p} is a signed document only");
        }
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
        // `auth/refresh/0.1` keeps its dedicated mount: it is also the admin
        // console's cookie-bound session renewal, which has no
        // signed-document equivalent. `auth/challenge/0.1` and
        // `auth/authenticate/0.1` lost theirs — `vta_sdk::auth_light` (and
        // `cnm vetting`'s bearer-session login through it) now signs
        // `auth/challenge/0.1` / `authenticate/0.2` documents against the
        // single Trust Task endpoint below instead (#1858). First-admin
        // onboarding (`install/claim/*`, `admin/bootstrap`) and
        // cross-community recognition (`auth/recognise/*`) moved there too —
        // neither has a dedicated REST mount any more.
        ("POST", "/v1/auth/refresh"),
        ("POST", "/v1/auth/admin-session"),
        ("POST", "/v1/auth/passkey-login/start"),
        ("POST", "/v1/auth/passkey-login/finish"),
        // The single Trust Task document endpoint — the holder-facing join
        // ceremony (submit/accept/manifest/status) dispatches internally by
        // document `type`, and so, since this batch, does every pre-session
        // install/bootstrap/recognise verb (plus `auth/authenticate/{0.2,0.3}`
        // and `auth/refresh/0.2`, alongside the `auth/*` REST mounts above).
        ("POST", "/v1/trust-tasks"),
        // Redeem a credential offer over HTTPS (`credential-exchange/request`):
        // the key-binding proof is the authority, and the governor + body cap
        // bound what an unauthenticated caller can make it verify.
        ("POST", "/v1/credential-exchange/request"),
    ];

    /// Unauthenticated operations intentionally left OFF the governed chain
    /// (public reads). Each is a deliberate decision recorded here so a *new*
    /// unauthenticated route can't quietly join this set.
    const PUBLIC_UNGOVERNED: &[(&str, &str)] = &[
        // Public, cacheable community metadata — no secrets, cheap to serve.
        ("GET", "/v1/community/public-profile"),
        // The community DID as an SVG QR code — the same public DID, drawn.
        ("GET", "/v1/community/did-qr.svg"),
        // (The join manifest is now the `join-requests/manifest/1.0` Trust
        // Task verb on `POST /v1/trust-tasks`, not a bespoke public GET.)
        // Verifier-facing status list — public by the W3C BitstringStatusList model.
        ("GET", "/v1/status-lists/{purpose}"),
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
