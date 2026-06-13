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
use axum::routing::{delete, get, post, put};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;

use crate::server::AppState;

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
fn apply_unauth_governor(router: Router<AppState>, trust_xff: bool) -> Router<AppState> {
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

/// Build the router and conditionally apply a CORS layer for the
/// given list of allowed origins. Wraps [`router()`] for callers
/// (production VTA front-ends) that already hold a config; empty
/// list = no layer = legacy behaviour.
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
pub fn router_with_cors(allowed_origins: &[String], trust_xff: bool) -> Router<AppState> {
    // Per-IP rate-limit layer applied to every unauthenticated endpoint.
    // Authenticated routes stay unthrottled — JWT auth is itself a gate,
    // and legitimate operator traffic against the management plane
    // shouldn't be rate-limited.
    //
    // The branches build the layer separately because the two key
    // extractors instantiate `GovernorConfig` at distinct generic
    // types — the layer itself is type-erased via the axum
    // dispatcher so the downstream router shape stays uniform.
    let unauth = Router::new()
        // Sealed-transfer bootstrap (token or attestation gated inside)
        .route("/bootstrap/request", post(bootstrap::request))
        // Passkey login (DID-VM-resolved WebAuthn assertions).
        // Trust-task URIs: vta/auth/passkey-login-{start,finish}/1.0.
        // Unauthenticated — the user has no session before
        // passkey-login-finish issues the JWT.
        .route("/auth/passkey-login/start", post(auth::passkey_login_start))
        .route(
            "/auth/passkey-login/finish",
            post(auth::passkey_login_finish),
        )
        // Auth flow entry points
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh));
    // Public, unauthenticated TEE attestation endpoints. These take no
    // auth extractor and run crypto on caller input (report generation),
    // so they MUST sit on the rate-limited + body-capped unauth branch —
    // not the main router, where they previously bypassed both. The
    // super-admin `/attestation/mnemonic` routes stay on the authed
    // router (JWT is their gate).
    #[cfg(feature = "tee")]
    let unauth = unauth
        .route("/attestation/status", get(attestation::status))
        .route(
            "/attestation/report",
            get(attestation::cached_report).post(attestation::generate_report),
        )
        .route("/attestation/did-log", get(attestation::did_log));
    #[cfg(feature = "webvh")]
    let unauth = unauth
        // Public did.jsonl retrieval — matches webvh's world-readable
        // log model, security is cryptographic not access-gated. Rate-
        // limited via the same governor layer as the other unauth
        // endpoints.
        .route("/did/{did}/log", get(did_webvh::get_did_log_public_handler));
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
    let auth_portal_router = Router::new().route("/auth/portal", get(auth_portal::portal_handler));

    // Authenticated provision-integration (context-admin gated). Kept
    // separate from `unauth` so the rate-limiter doesn't apply — the
    // endpoint already hard-gates on `AdminAuth`.
    #[cfg(feature = "webvh")]
    let auth_provision = Router::new().route(
        "/bootstrap/provision-integration",
        post(bootstrap::provision_integration),
    );

    let router = Router::new().merge(unauth);
    #[cfg(feature = "webvh")]
    let router = router.merge(auth_provision);
    let router = router.merge(auth_portal_router);

    let router = router
        .route(
            "/auth/sessions",
            get(auth::session_list).delete(auth::revoke_sessions_by_did),
        )
        .route("/auth/sessions/{session_id}", delete(auth::revoke_session))
        // Trust-task envelope dispatcher (per
        // docs/05-design-notes/trust-task-uri-registry.md). Phase 2
        // scaffold; handlers register per Phase 3 slice.
        .route(
            "/api/trust-tasks",
            post(crate::trust_tasks::dispatch_trust_task),
        )
        .route(
            "/config",
            get(config::get_config).patch(config::update_config),
        )
        .route("/keys", get(keys::list_keys).post(keys::create_key))
        .route(
            "/keys/{key_id}",
            get(keys::get_key)
                .delete(keys::invalidate_key)
                .patch(keys::rename_key),
        )
        .route("/keys/{key_id}/secret", get(keys::get_key_secret))
        .route("/keys/{key_id}/sign", post(keys::sign_with_key))
        .route("/keys/import/wrapping-key", get(keys::get_wrapping_key))
        .route("/keys/import", post(keys::import_key))
        .route("/keys/seeds", get(keys::list_seeds))
        .route("/keys/seeds/rotate", post(keys::rotate_seed))
        // Context routes
        .route(
            "/contexts",
            get(contexts::list_contexts_handler).post(contexts::create_context_handler),
        )
        .route(
            "/contexts/{id}",
            get(contexts::get_context_handler)
                .patch(contexts::update_context_handler)
                .delete(contexts::delete_context_handler),
        )
        .route(
            "/contexts/{id}/did",
            put(contexts::update_context_did_handler),
        )
        .route(
            "/contexts/{id}/delete-preview",
            get(contexts::preview_delete_context_handler),
        )
        // DID template routes (global scope — Phase 2)
        .route(
            "/did-templates",
            get(did_templates::list_handler).post(did_templates::create_handler),
        )
        .route(
            "/did-templates/{name}",
            get(did_templates::get_handler)
                .put(did_templates::update_handler)
                .delete(did_templates::delete_handler),
        )
        .route(
            "/did-templates/{name}/render",
            post(did_templates::render_handler),
        )
        // DID templates — context scope (Phase 3)
        .route(
            "/contexts/{id}/did-templates",
            get(did_templates::list_context_handler).post(did_templates::create_context_handler),
        )
        .route(
            "/contexts/{id}/did-templates/{name}",
            get(did_templates::get_context_handler)
                .put(did_templates::update_context_handler)
                .delete(did_templates::delete_context_handler),
        )
        .route(
            "/contexts/{id}/did-templates/{name}/render",
            post(did_templates::render_context_handler),
        )
        // Step-up policy management (read posture; super-admin set).
        .route(
            "/step-up/policy",
            get(step_up::get_step_up_policy).put(step_up::put_step_up_policy),
        )
        // ACL routes (flattened for consistency)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        // Static segment registered before `/acl/{did}` so it isn't captured
        // as a DID. Self-service key rotation (any authenticated caller).
        .route("/acl/swap", post(acl::swap_acl))
        .route(
            "/acl/{did}",
            get(acl::get_acl)
                .patch(acl::update_acl)
                .delete(acl::delete_acl),
        )
        // Audit log routes
        .route("/audit/logs", get(audit::list_audit_logs))
        .route(
            "/audit/retention",
            get(audit::get_retention).patch(audit::update_retention),
        )
        // Cache routes (token caching / key-value store)
        .route(
            "/cache/{key}",
            get(cache::get_cached)
                .put(cache::put_cached)
                .delete(cache::delete_cached),
        );

    // TEE attestation routes (feature-gated). The unauthenticated ones
    // (`status`, `report`, `did-log`) live on the rate-limited `unauth`
    // branch above; only the super-admin-gated mnemonic export stays on
    // the authed router (JWT is its gate, so it's intentionally off the
    // rate limiter like every other authed route).
    #[cfg(feature = "tee")]
    let router = router.route(
        "/attestation/mnemonic",
        get(attestation::mnemonic_status).post(attestation::mnemonic_export),
    );
    // `GET /attestation/admin-credential` retired in Phase 3 —
    // sealed-bootstrap Mode B replaces it via `POST /bootstrap/request`.

    // Protocol management routes (DIDComm enable/disable/migrate;
    // spec docs/05-design-notes/didcomm-protocol-management.md).
    // Plus the symmetric REST routes (spec
    // docs/05-design-notes/runtime-service-management.md §3.4).
    #[cfg(feature = "webvh")]
    let router = router
        .route(
            "/services/didcomm/enable",
            post(protocol::enable_didcomm_handler),
        )
        .route(
            "/services/didcomm",
            get(protocol::get_didcomm_status_handler),
        )
        .route(
            "/services/didcomm/disable",
            post(protocol::disable_didcomm_handler),
        )
        .route("/services/rest/enable", post(protocol::enable_rest_handler))
        .route("/services/rest/update", post(protocol::update_rest_handler))
        .route(
            "/services/rest/disable",
            post(protocol::disable_rest_handler),
        )
        .route(
            "/services/rest/rollback",
            post(protocol::rollback_rest_handler),
        )
        .route(
            "/services/webauthn/enable",
            post(protocol::enable_webauthn_handler),
        )
        .route(
            "/services/webauthn/update",
            post(protocol::update_webauthn_handler),
        )
        .route(
            "/services/webauthn/disable",
            post(protocol::disable_webauthn_handler),
        )
        .route(
            "/services/webauthn/rollback",
            post(protocol::rollback_webauthn_handler),
        )
        .route("/services", get(protocol::list_services_handler))
        .route("/services/didcomm/drain", get(protocol::list_drain_handler))
        .route(
            "/services/didcomm/update",
            post(protocol::update_didcomm_handler),
        )
        .route(
            "/services/didcomm/rollback",
            post(protocol::rollback_didcomm_handler),
        )
        .route(
            "/mediators/drain/cancel",
            post(protocol::drain_cancel_handler),
        )
        .route("/mediators/report", get(protocol::mediator_report_handler));

    // WebVH routes (feature-gated)
    #[cfg(feature = "webvh")]
    let router = router
        .route(
            "/webvh/servers",
            get(did_webvh::list_servers_handler).post(did_webvh::add_server_handler),
        )
        .route(
            "/webvh/servers/{id}",
            axum::routing::patch(did_webvh::update_server_handler)
                .delete(did_webvh::remove_server_handler),
        )
        .route(
            "/webvh/servers/{id}/domains",
            get(did_webvh::list_server_domains_handler),
        )
        .route(
            "/webvh/dids",
            get(did_webvh::list_dids_handler).post(did_webvh::create_did_handler),
        )
        .route(
            "/webvh/dids/{did}",
            get(did_webvh::get_did_handler).delete(did_webvh::delete_did_handler),
        )
        .route("/webvh/dids/{did}/log", get(did_webvh::get_did_log_handler))
        .route(
            "/webvh/dids/{did}/register-server",
            post(did_webvh::register_did_with_server_handler),
        )
        .route(
            "/contexts/{ctx_id}/dids/{scid}/update",
            post(did_webvh::update_did_handler),
        )
        .route(
            "/contexts/{ctx_id}/dids/{scid}/rotate-keys",
            post(did_webvh::rotate_did_keys_handler),
        )
        // Passkey-as-verificationMethod enrolment. See
        // `docs/02-vta/passkey-verification-methods.md` (forthcoming).
        // First-time enrolment expects a short-lived enrolment-scope
        // JWT minted by `pnm passkey-enroll-token`; subsequent calls
        // use a passkey-derived session JWT.
        .route(
            "/did/verification-methods/passkey/challenge",
            post(passkey_vms::enroll_challenge_handler),
        )
        .route(
            "/did/verification-methods/passkey",
            post(passkey_vms::enroll_submit_handler).get(passkey_vms::list_passkeys_handler),
        )
        .route(
            "/did/verification-methods/passkey/{fragment}",
            delete(passkey_vms::revoke_passkey_handler),
        );

    // VTA management routes
    let router = router
        .route("/vta/restart", post(vta::restart))
        .route("/metrics", get(vta::metrics))
        .route("/backup/export", post(backup::export))
        .route("/backup/import", post(backup::import));

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
    let backup_blob_router = Router::new()
        .route(
            "/backup/blob/{bundle_id}",
            get(backup_blob::get_blob).post(backup_blob::post_blob),
        )
        .layer(DefaultBodyLimit::max(BACKUP_BLOB_BODY_SIZE));
    let backup_blob_router = apply_unauth_governor(backup_blob_router, trust_xff);
    let router = router.merge(backup_blob_router);

    // Authenticated health details and capabilities
    let router = router
        .route("/health/details", get(health::health_details))
        .route("/capabilities", get(capabilities::capabilities));

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
