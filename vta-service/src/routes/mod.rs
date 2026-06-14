mod acl;
#[cfg(feature = "tee")]
mod attestation;
mod audit;
mod auth;
mod auth_portal;
mod backup;
mod backup_blob;
mod bootstrap;
mod cache;
mod capabilities;
mod config;
mod contexts;
mod did_templates;
#[cfg(feature = "webvh")]
mod did_webvh;
mod health;
pub mod keys;
#[cfg(feature = "webvh")]
mod passkey_vms;
#[cfg(feature = "webvh")]
mod protocol;
mod step_up;
mod vta;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method};
use axum::routing::{get, post};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::server::AppState;

/// OpenAPI document root for the VTA REST surface.
///
/// The router is the single source of truth for *paths* — every handler
/// annotated with `#[utoipa::path]` and registered via `routes!()` on the
/// [`OpenApiRouter`] contributes its operation here, so the served
/// `/openapi.json` cannot drift from the wired routes. This struct only seeds
/// the document-level metadata (title/version) and the security scheme; it
/// declares no `paths` of its own.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Verifiable Trust Agent (VTA) API",
        description = "Key-management, DID-webvh, provisioning, and runtime \
                       service-management REST surface of a Verifiable Trust Agent.",
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
///
/// Unauthenticated by design — the document describes the API *shape*, not any
/// secret, and black-box conformance/fuzz tooling (schemathesis, RESTler)
/// fetches it before it holds a token.
async fn serve_openapi(api: utoipa::openapi::OpenApi) -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(api)
}

/// Maximum request body size (1 MB). Protects against memory exhaustion,
/// especially critical in TEE deployments where enclave memory is limited.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Tighter body cap for unauthenticated endpoints that drive expensive
/// crypto on attacker-controlled bytes (DIDComm `pack`/`unpack`,
/// signature verify, sealed-transfer parse). Sized to fit a generous
/// JWE / sealed-transfer payload but reject 1 MB blob floods that the
/// rate limiter alone cannot starve out.
const UNAUTH_BODY_SIZE: usize = 64 * 1024;

/// Body-size cap for the backup-descriptor blob endpoints. The whole
/// point of the descriptor pattern is to escape the trust-task
/// envelope's 1 MB cap, so this needs a much larger budget. 100 MB
/// covers a typical-to-large VTA's full backup (keys + ACL +
/// contexts + WebVH DID logs + audit). A future enhancement could
/// make this config-driven, but baking the conservative ceiling in
/// avoids an operator footgun (set-to-10-GB).
///
/// `pub(super)` so the blob route handler can pass it to
/// `axum::body::to_bytes` — the per-handler cap is the canonical
/// source of truth; the router-level layer is disabled (see
/// `backup_blob_router` construction below).
pub(super) const BACKUP_BLOB_BODY_SIZE: usize = 100 * 1024 * 1024;

/// Per-client-IP rate-limit budget for unauthenticated endpoints.
///
/// 5 req/sec with a 10-request burst — loose enough that a legit operator
/// running provisioning scripts doesn't hit it, tight enough that a
/// sustained flood from one IP is rejected with 429. These endpoints do
/// real crypto work (attestation, HPKE seal, Ed25519 verify) so throttling
/// them protects VTA CPU regardless of any reverse proxy upstream.
const UNAUTH_RPS: u64 = 5;
const UNAUTH_BURST: u32 = 10;

/// Global per-request timeout. The REST surface runs on a current-thread
/// runtime, so a handler that stalls on network I/O (a dead mediator, a
/// slow remote DID host) would otherwise hold its connection — and a
/// caller's patience — indefinitely. Generous on purpose: longer than any
/// legitimate single request (local-fast backups, self-limiting mediator
/// handshakes, a 100 MB blob transfer at modest bandwidth) but bounded, so
/// "indefinite" becomes "120 s then 408". Not a substitute for the
/// handshake/op-specific timeouts, which stay; this is the backstop.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Apply the unauthenticated-endpoint rate limiter to `router`.
///
/// Split out so the two key extractors — which instantiate
/// `GovernorConfig` at distinct generic types — are confined here and the
/// returned `Router<AppState>` is uniform (type-erased by axum). Used for
/// both the unauth branch and the token-gated backup-blob branch, which is
/// otherwise an unthrottled large-body write surface.
///
/// `trust_xff`: `false` keys on the socket peer (`PeerIpKeyExtractor`,
/// spoof-safe for direct binding); `true` honours `X-Forwarded-For`
/// (`SmartIpKeyExtractor`, only safe behind a header-sanitising proxy).
fn apply_unauth_governor(
    router: OpenApiRouter<AppState>,
    trust_xff: bool,
) -> OpenApiRouter<AppState> {
    if trust_xff {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(UNAUTH_RPS)
                .burst_size(UNAUTH_BURST)
                .key_extractor(tower_governor::key_extractor::SmartIpKeyExtractor)
                .finish()
                .expect("governor config values are static and non-zero"),
        );
        router.layer(GovernorLayer::new(cfg))
    } else {
        let cfg = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(UNAUTH_RPS)
                .burst_size(UNAUTH_BURST)
                .key_extractor(tower_governor::key_extractor::PeerIpKeyExtractor)
                .finish()
                .expect("governor config values are static and non-zero"),
        );
        router.layer(GovernorLayer::new(cfg))
    }
}

/// Health-check route — served without the request/response trace layer.
/// Minimal response only; detailed info requires authentication.
pub fn health_router() -> Router<AppState> {
    Router::new().route("/health", get(health::health))
}

/// Health-check route with the same CORS policy as the API surface.
///
/// `/health` is deliberately kept out of the trace + metrics layers
/// (it's a high-frequency liveness probe and would swamp the logs),
/// which is why `server.rs` merges it *after* those layers are applied
/// to the main router. CORS, however, must still cover it: browser
/// tools (e.g. `examples/vta-auth-demo`) probe `/health` cross-origin
/// as their first connectivity check, and without an
/// `Access-Control-Allow-Origin` header the browser blocks the read
/// with an opaque "Failed to fetch". Apply the same origin allowlist
/// here so the probe works whenever the API CORS is configured; an
/// empty allowlist yields no layer (legacy no-cross-origin behaviour).
pub fn health_router_with_cors(allowed_origins: &[String]) -> Router<AppState> {
    let router = health_router();
    match build_cors_layer(allowed_origins) {
        Some(cors) => router.layer(cors),
        None => router,
    }
}

/// Build a CORS layer from a list of allowed origins. Returns
/// `None` when the list is empty — the caller must skip the layer
/// in that case so a fresh-install VTA keeps the legacy
/// no-cross-origin behaviour.
///
/// Cross-origin requests with `Authorization` headers don't carry
/// browser credentials (no `allow_credentials`), so the bearer
/// token is the only client-side state in the cross-origin path.
/// Wildcard origins are deliberately not accepted — every allowed
/// origin must be explicit so a misconfiguration can't let
/// arbitrary sites borrow operator tokens.
fn build_cors_layer(allowed_origins: &[String]) -> Option<CorsLayer> {
    if allowed_origins.is_empty() {
        return None;
    }
    // Filter:
    //   - `*` — tower-http's `AllowOrigin::list` panics on the
    //     wildcard. We deliberately don't fall through to
    //     `AllowOrigin::any()` either; explicit origins only.
    //   - malformed values that can't be parsed as a header value.
    let parsed: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter(|o| !o.is_empty() && *o != "*")
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if parsed.is_empty() {
        // Either an operator passed only invalid entries (a
        // typo'd config that should be visible in startup logs)
        // or the original list was filtered down to nothing. Skip
        // the layer rather than partially-apply CORS — a
        // half-configured CORS surface is worse than none.
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PATCH])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-backup-token"),
            ])
            .max_age(std::time::Duration::from_secs(60)),
    )
}

pub fn router() -> Router<AppState> {
    router_with_cors(&[], false)
}

/// Assemble the VTA REST surface as an [`OpenApiRouter`] — the single source
/// of truth for both the wired routes and the served OpenAPI document. Routes
/// registered via `routes!()` contribute their `#[utoipa::path]` operation;
/// routes still on plain `.route(...)` are served but not yet described. Global
/// layers (body cap, timeout, CORS) and the `/openapi.json` route are applied
/// by [`router_with_cors`] after splitting.
///
/// `trust_xff` selects the rate-limiter's IP-attribution
/// strategy (L2 from the May 2026 security review):
///
/// - `false` (default) → `PeerIpKeyExtractor` keys on the socket
///   peer. Safe for direct-binding deployments; not bypassable
///   by header spoofing.
/// - `true` → `SmartIpKeyExtractor` honours `X-Forwarded-For` /
///   `Forwarded`. Only safe behind a trust-boundary reverse
///   proxy that overwrites or strips these headers from external
///   requests. Misconfiguring this is a silent rate-limit bypass.
fn build_api_router(trust_xff: bool) -> OpenApiRouter<AppState> {
    // Per-IP rate-limit layer applied to every unauthenticated endpoint.
    // Authenticated routes stay unthrottled — JWT auth is itself a gate,
    // and legitimate operator traffic against the management plane
    // shouldn't be rate-limited.
    //
    // The branches build the layer separately because the two key
    // extractors instantiate `GovernorConfig` at distinct generic
    // types — the layer itself is type-erased via the axum
    // dispatcher so the downstream router shape stays uniform.
    let unauth = OpenApiRouter::new()
        // Sealed-transfer bootstrap (token or attestation gated inside)
        .routes(routes!(bootstrap::request))
        // Passkey login (DID-VM-resolved WebAuthn assertions).
        // Trust-task URIs: vta/auth/passkey-login-{start,finish}/1.0.
        // Unauthenticated — the user has no session before
        // passkey-login-finish issues the JWT.
        .routes(routes!(auth::passkey_login_start))
        .routes(routes!(auth::passkey_login_finish))
        // Auth flow entry points
        .routes(routes!(auth::challenge))
        .routes(routes!(auth::authenticate))
        .routes(routes!(auth::refresh));
    // Public, unauthenticated TEE attestation endpoints. These take no
    // auth extractor and run crypto on caller input (report generation),
    // so they MUST sit on the rate-limited + body-capped unauth branch —
    // not the main router, where they previously bypassed both. The
    // super-admin `/attestation/mnemonic` routes stay on the authed
    // router (JWT is their gate).
    #[cfg(feature = "tee")]
    let unauth = unauth
        .routes(routes!(attestation::status))
        .routes(routes!(
            attestation::cached_report,
            attestation::generate_report
        ))
        .routes(routes!(attestation::did_log));
    #[cfg(feature = "webvh")]
    let unauth = unauth
        // Public did.jsonl retrieval — matches webvh's world-readable
        // log model, security is cryptographic not access-gated. Rate-
        // limited via the same governor layer as the other unauth
        // endpoints.
        .routes(routes!(did_webvh::get_did_log_public_handler));
    // Tighter body cap on unauth endpoints — see UNAUTH_BODY_SIZE.
    // Applied after ALL unauth routes (including the cfg-gated ones) are
    // registered so every POST on this branch (auth, attestation report)
    // gets the 64 KB ceiling, not just the base set. Layered here (not
    // globally) so authenticated endpoints keep MAX_BODY_SIZE for backup
    // import etc.
    let unauth = unauth.layer(DefaultBodyLimit::max(UNAUTH_BODY_SIZE));
    // Rate-limit every unauth endpoint (see `apply_unauth_governor`).
    let unauth = apply_unauth_governor(unauth, trust_xff);

    // Auth portal — same-origin popup target for cross-origin WebAuthn
    // flows. Sits on its own router branch so:
    //  - It's NOT behind the rate-limit layer (operator may refresh
    //    repeatedly while testing).
    //  - It's NOT behind UNAUTH_BODY_SIZE (the HTML response is
    //    bigger than that; the cap is for inbound bodies but separate
    //    branches keep the contract obvious).
    //  - It's NOT behind CORS itself — the response is meant to be
    //    loaded directly into a popup window same-origin, not fetched
    //    cross-origin.
    // See `routes::auth_portal` for the full security model.
    let auth_portal_router =
        OpenApiRouter::new().route("/auth/portal", get(auth_portal::portal_handler));

    // Authenticated provision-integration (context-admin gated). Kept
    // separate from `unauth` so the rate-limiter doesn't apply — the
    // endpoint already hard-gates on `AdminAuth`.
    #[cfg(feature = "webvh")]
    let auth_provision = OpenApiRouter::new().routes(routes!(bootstrap::provision_integration));

    let router = OpenApiRouter::with_openapi(ApiDoc::openapi()).merge(unauth);
    #[cfg(feature = "webvh")]
    let router = router.merge(auth_provision);
    let router = router.merge(auth_portal_router);

    let router = router
        .routes(routes!(auth::session_list, auth::revoke_sessions_by_did))
        .routes(routes!(auth::revoke_session))
        // Trust-task envelope dispatcher (per
        // docs/05-design-notes/trust-task-uri-registry.md). Phase 2
        // scaffold; handlers register per Phase 3 slice. Not yet documented
        // in OpenAPI (dynamic envelope payload).
        .route(
            "/api/trust-tasks",
            post(crate::trust_tasks::dispatch_trust_task),
        )
        .routes(routes!(config::get_config, config::update_config))
        .routes(routes!(keys::list_keys, keys::create_key))
        .routes(routes!(
            keys::get_key,
            keys::invalidate_key,
            keys::rename_key
        ))
        .routes(routes!(keys::get_key_secret))
        .routes(routes!(keys::sign_with_key))
        .routes(routes!(keys::get_wrapping_key))
        .routes(routes!(keys::import_key))
        .routes(routes!(keys::list_seeds))
        .routes(routes!(keys::rotate_seed))
        // Context routes
        .routes(routes!(
            contexts::list_contexts_handler,
            contexts::create_context_handler
        ))
        .routes(routes!(
            contexts::get_context_handler,
            contexts::update_context_handler,
            contexts::delete_context_handler
        ))
        .routes(routes!(contexts::update_context_did_handler))
        .routes(routes!(contexts::preview_delete_context_handler))
        // DID template routes (global scope — Phase 2)
        .routes(routes!(
            did_templates::list_handler,
            did_templates::create_handler
        ))
        .routes(routes!(
            did_templates::get_handler,
            did_templates::update_handler,
            did_templates::delete_handler
        ))
        .routes(routes!(did_templates::render_handler))
        // DID templates — context scope (Phase 3)
        .routes(routes!(
            did_templates::list_context_handler,
            did_templates::create_context_handler
        ))
        .routes(routes!(
            did_templates::get_context_handler,
            did_templates::update_context_handler,
            did_templates::delete_context_handler
        ))
        .routes(routes!(did_templates::render_context_handler))
        // Step-up policy management (read posture; super-admin set).
        .routes(routes!(
            step_up::get_step_up_policy,
            step_up::put_step_up_policy
        ))
        // ACL routes (flattened for consistency)
        .routes(routes!(acl::list_acl, acl::create_acl))
        // Static segment registered before `/acl/{did}` so it isn't captured
        // as a DID. Self-service key rotation (any authenticated caller).
        .routes(routes!(acl::swap_acl))
        .routes(routes!(acl::get_acl, acl::update_acl, acl::delete_acl))
        // Audit log routes
        .routes(routes!(audit::list_audit_logs))
        .routes(routes!(audit::get_retention, audit::update_retention))
        // Cache routes (token caching / key-value store)
        .routes(routes!(
            cache::get_cached,
            cache::put_cached,
            cache::delete_cached
        ));

    // TEE attestation routes (feature-gated). The unauthenticated ones
    // (`status`, `report`, `did-log`) live on the rate-limited `unauth`
    // branch above; only the super-admin-gated mnemonic export stays on
    // the authed router (JWT is its gate, so it's intentionally off the
    // rate limiter like every other authed route).
    #[cfg(feature = "tee")]
    let router = router.routes(routes!(
        attestation::mnemonic_status,
        attestation::mnemonic_export
    ));
    // `GET /attestation/admin-credential` retired in Phase 3 —
    // sealed-bootstrap Mode B replaces it via `POST /bootstrap/request`.

    // Protocol management routes (DIDComm enable/disable/migrate;
    // spec docs/05-design-notes/didcomm-protocol-management.md).
    // Plus the symmetric REST routes (spec
    // docs/05-design-notes/runtime-service-management.md §3.4).
    #[cfg(feature = "webvh")]
    let router = router
        .routes(routes!(protocol::enable_didcomm_handler))
        .routes(routes!(protocol::get_didcomm_status_handler))
        .routes(routes!(protocol::disable_didcomm_handler))
        .routes(routes!(protocol::enable_rest_handler))
        .routes(routes!(protocol::update_rest_handler))
        .routes(routes!(protocol::disable_rest_handler))
        .routes(routes!(protocol::rollback_rest_handler))
        .routes(routes!(protocol::enable_webauthn_handler))
        .routes(routes!(protocol::update_webauthn_handler))
        .routes(routes!(protocol::disable_webauthn_handler))
        .routes(routes!(protocol::rollback_webauthn_handler))
        .routes(routes!(protocol::list_services_handler))
        // GET list-drain + POST cancel share /services/didcomm/drain.
        .routes(routes!(
            protocol::list_drain_handler,
            protocol::drain_cancel_handler
        ))
        .routes(routes!(protocol::update_didcomm_handler))
        .routes(routes!(protocol::rollback_didcomm_handler))
        // Alias mount of the drain-cancel handler; its #[utoipa::path] lives on
        // the canonical /services/didcomm/drain entry above, so this stays a
        // plain (undocumented) route to avoid a duplicate operation.
        .route(
            "/mediators/drain/cancel",
            post(protocol::drain_cancel_handler),
        )
        .routes(routes!(protocol::mediator_report_handler));

    // WebVH routes (feature-gated)
    #[cfg(feature = "webvh")]
    let router = router
        .routes(routes!(
            did_webvh::list_servers_handler,
            did_webvh::add_server_handler
        ))
        .routes(routes!(
            did_webvh::update_server_handler,
            did_webvh::remove_server_handler
        ))
        .routes(routes!(did_webvh::list_server_domains_handler))
        .routes(routes!(
            did_webvh::list_dids_handler,
            did_webvh::create_did_handler
        ))
        .routes(routes!(
            did_webvh::get_did_handler,
            did_webvh::delete_did_handler
        ))
        .routes(routes!(did_webvh::get_did_log_handler))
        .routes(routes!(did_webvh::register_did_with_server_handler))
        .routes(routes!(did_webvh::update_did_handler))
        .routes(routes!(did_webvh::rotate_did_keys_handler))
        // Passkey-as-verificationMethod enrolment. See
        // `docs/02-vta/passkey-verification-methods.md` (forthcoming).
        // First-time enrolment expects a short-lived enrolment-scope
        // JWT minted by `pnm passkey-enroll-token`; subsequent calls
        // use a passkey-derived session JWT.
        .routes(routes!(passkey_vms::enroll_challenge_handler))
        .routes(routes!(
            passkey_vms::enroll_submit_handler,
            passkey_vms::list_passkeys_handler
        ))
        .routes(routes!(passkey_vms::revoke_passkey_handler));

    // VTA management routes
    let router = router
        .routes(routes!(vta::restart))
        .routes(routes!(vta::metrics))
        .routes(routes!(backup::export))
        .routes(routes!(backup::import));

    // Backup-descriptor blob endpoints. NOT JWT-gated — the
    // `X-Backup-Token` header IS the credential (one-shot for
    // GET, bound to bundle_id, hashed server-side). Justified
    // in `docs/05-design-notes/backup-descriptor-pattern.md`
    // §"Auth model".
    //
    // Body limit: an explicit `BACKUP_BLOB_BODY_SIZE` (100 MB) layer —
    // NOT `disable()`. The global `MAX_BODY_SIZE` (1 MB) is too small for
    // backups (10s of MB), but `disable()` meant any future handler added
    // to this branch silently inherited an *unlimited* body. The layer is
    // a branch backstop at the same value the handler already enforces via
    // `axum::body::to_bytes` (both at `BACKUP_BLOB_BODY_SIZE`, so they
    // agree — no ambiguous override).
    //
    // Rate-limited like the unauth branch: the token gate is real, but
    // without throttling an attacker replaying/guessing bundle_ids gets
    // free 100 MB disk-write attempts and free SHA-256 over 100 MB bodies.
    let backup_blob_router = OpenApiRouter::new()
        .routes(routes!(backup_blob::get_blob, backup_blob::post_blob))
        .layer(DefaultBodyLimit::max(BACKUP_BLOB_BODY_SIZE));
    let backup_blob_router = apply_unauth_governor(backup_blob_router, trust_xff);
    let router = router.merge(backup_blob_router);

    // Authenticated health details and capabilities
    router
        .route("/health/details", get(health::health_details))
        // First route migrated to the OpenAPI-aware registration: its
        // `#[utoipa::path]` operation lands in the served `/openapi.json`.
        .routes(routes!(capabilities::capabilities))
}

/// The assembled OpenAPI 3.1 document describing the VTA REST surface.
///
/// Built from the same [`build_api_router`] assembly that wires the live
/// routes, so the document cannot drift from what the service actually serves.
/// Exposed for tests and offline emission; the running service serves this at
/// `GET /openapi.json`.
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    // CORS attribution doesn't affect the documented surface; build with the
    // safe default.
    build_api_router(false).split_for_parts().1
}

/// Build the router and conditionally apply a CORS layer for the given list of
/// allowed origins. Wraps [`build_api_router`] for callers (production VTA
/// front-ends) that already hold a config; empty list = no layer = legacy
/// behaviour. See [`build_api_router`] for the `trust_xff` semantics.
pub fn router_with_cors(allowed_origins: &[String], trust_xff: bool) -> Router<AppState> {
    // Finalise the OpenAPI document from the assembled router (paths come from
    // the `routes!()` registrations) and recover a plain axum `Router` to layer
    // + serve. Splitting here, *before* the global layers, lets `/openapi.json`
    // be added as a sibling that the same global layers then wrap.
    let (router, api) = build_api_router(trust_xff).split_for_parts();
    let router = router.route("/openapi.json", get(move || serve_openapi(api.clone())));

    // Apply global request body size limit to protect enclave memory,
    // plus the global request timeout backstop (no handler may hold a
    // connection indefinitely). The blob branch's own 100 MB body limit,
    // applied inner to this 1 MB global one, still wins for that branch
    // (the inner layer sets the limit extension last).
    let router =
        router
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ));

    // Apply CORS conditionally — empty origin list = no layer at all
    // (preserves the legacy no-cross-origin behaviour for production
    // deployments that don't need browser-side fetch). CORS stays
    // outermost so preflight handling and headers wrap the timeout.
    match build_cors_layer(allowed_origins) {
        Some(cors) => router.layer(cors),
        None => router,
    }
}

#[cfg(test)]
mod cors_tests {
    use super::*;

    #[test]
    fn empty_list_disables_cors_entirely() {
        assert!(build_cors_layer(&[]).is_none());
    }

    #[test]
    fn explicit_origin_produces_layer() {
        let layer = build_cors_layer(&["http://localhost:8000".to_string()]);
        assert!(layer.is_some());
    }

    #[test]
    fn invalid_origin_filtered_out_and_empty_result_returns_none() {
        // `\n` is invalid in a header value. If it's the only entry,
        // the filter empties the list and we end up at the
        // no-layer branch — a fresh-install VTA shouldn't get a
        // partially-applied CORS surface just because a config typo
        // got past serde.
        let bad_origin = "http://localhost:8000\n".to_string();
        assert!(build_cors_layer(&[bad_origin]).is_none());
    }

    #[test]
    fn wildcard_alone_yields_no_layer() {
        // tower-http's `AllowOrigin::list` PANICS on the literal
        // `*`. The build_cors_layer filter strips wildcards
        // explicitly so an operator typo can't bring down the
        // VTA at startup. (Wildcards would also expose bearer
        // tokens to any origin, which is exactly the kind of
        // config error we want to refuse — better empty than
        // permissive.)
        assert!(
            build_cors_layer(&["*".to_string()]).is_none(),
            "wildcard must be filtered to None, never partial-applied"
        );
    }

    #[test]
    fn wildcard_mixed_with_explicit_origins_drops_wildcard_keeps_others() {
        // Defensive: a mixed list shouldn't break the layer
        // build — the wildcard is dropped and the explicit
        // entries remain.
        let layer = build_cors_layer(&["*".to_string(), "http://localhost:8000".to_string()]);
        assert!(layer.is_some());
    }

    #[test]
    fn empty_origin_string_filtered() {
        // Operator pastes a blank line into config — should be
        // skipped, not turned into an empty header value.
        let layer = build_cors_layer(&["".to_string(), "http://x".to_string()]);
        assert!(layer.is_some());
    }

    #[test]
    fn openapi_spec_describes_registered_routes() {
        let spec = openapi_spec();
        // The document-level metadata + security scheme are seeded by ApiDoc.
        assert_eq!(spec.info.title, "Verifiable Trust Agent (VTA) API");
        let schemes = &spec
            .components
            .as_ref()
            .expect("components present once a route contributes a schema")
            .security_schemes;
        assert!(
            schemes.contains_key("bearer_jwt"),
            "bearer_jwt security scheme must be registered"
        );
        // The first migrated route's `#[utoipa::path]` operation is present,
        // with its response schema referenced.
        let cap = spec
            .paths
            .paths
            .get("/capabilities")
            .expect("/capabilities operation must be in the spec");
        assert!(
            cap.get.is_some(),
            "/capabilities must document a GET operation"
        );
        assert!(
            spec.components
                .as_ref()
                .unwrap()
                .schemas
                .contains_key("CapabilitiesResponse"),
            "CapabilitiesResponse schema must be emitted"
        );
    }

    #[test]
    fn openapi_spec_covers_the_route_groups() {
        let spec = openapi_spec();
        let paths = &spec.paths.paths;
        // A representative path from each major route group must be documented.
        for p in [
            "/auth/challenge",
            "/keys",
            "/keys/{key_id}",
            "/contexts",
            "/acl",
            "/acl/{did}",
            "/did-templates",
            "/audit/logs",
            "/cache/{key}",
            "/config",
            "/step-up/policy",
            "/capabilities",
            "/vta/restart",
            "/backup/export",
            "/backup/blob/{bundle_id}",
            // webvh (default feature) groups
            "/services/didcomm/enable",
            "/services",
            "/webvh/dids",
            "/webvh/servers",
            "/did/verification-methods/passkey",
        ] {
            assert!(paths.contains_key(p), "spec missing documented path {p}");
        }
        // The full surface should be substantial — guard against a regression
        // that silently drops the bulk of the routes.
        assert!(
            paths.len() >= 60,
            "expected the documented surface to be >= 60 paths, got {}",
            paths.len()
        );
    }

    #[test]
    fn health_router_with_cors_builds_both_branches() {
        // Both the with-origins (layer applied) and empty (no layer)
        // branches must construct without panicking. `.layer(cors)`
        // on a wildcard would panic inside tower-http, but
        // `build_cors_layer` filters wildcards to `None` first — this
        // guards the wiring that depends on that invariant.
        let _with = health_router_with_cors(&["http://localhost:8000".to_string()]);
        let _without = health_router_with_cors(&[]);
        let _wildcard_only = health_router_with_cors(&["*".to_string()]);
    }
}
