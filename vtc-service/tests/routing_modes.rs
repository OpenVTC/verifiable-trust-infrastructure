//! Routing-mode integration tests (Phase 5 M5.1.3).
//!
//! Verifies the per-surface nest structure introduced in M5.1.1
//! and the subdomain-mode `Host` header check from M5.1.2:
//!
//! - **`/health`** stays at the parent-router root and is exempt
//!   from Trust-Task validation in both modes.
//! - **`POST /v1/auth/challenge`** reaches the API surface (the
//!   handler returns 400 here because the ACL is empty — that
//!   confirms the route is wired through, not auth-rejected).
//! - **`GET /admin/anything`** falls through to the 503
//!   placeholder.
//! - **`GET /anything-else`** falls through to the website 503
//!   placeholder.
//! - **Subdomain mode strict**: configured Host header passes,
//!   unrecognised Host returns 404 `HostNotRecognised`.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use vtc_service::config::{MountConfig, RoutingConfig};
use vtc_service::routes;
use vtc_service::routing::host_dispatch::{HostMap, enforce};

/// Build a router using only the placeholder + health surfaces;
/// the API sub-router needs full `AppState` but route-priority
/// tests only need to see whether prefixes dispatch correctly.
/// We rely on `routes::router_with()` plus a default state where
/// every keyspace is open against a tempdir.
async fn build_router(routing: &RoutingConfig) -> (Router, tempfile::TempDir) {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
    use vtc_service::config::AppConfig;
    use vtc_service::server::AppState;
    use vti_common::auth::jwt::JwtKeys;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    init_jwt_provider();

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let install_ks = store.keyspace("install").unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").expect("jwt keys"));

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:key:z6MkTestVTC"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks: store.keyspace("sessions").unwrap(),
        acl_ks: store.keyspace("acl").unwrap(),
        community_ks: store.keyspace("community").unwrap(),
        config_ks: store.keyspace("config").unwrap(),
        passkey_ks: store.keyspace("passkey").unwrap(),
        install_ks: install_ks.clone(),
        members_ks: store.keyspace("members").unwrap(),
        join_requests_ks: store.keyspace("join_requests").unwrap(),
        policies_ks: store.keyspace("policies").unwrap(),
        active_policies_ks: store.keyspace("active_policies").unwrap(),
        status_lists_ks: store.keyspace("status_lists").unwrap(),
        registry_records_ks: store.keyspace("registry_records").unwrap(),
        sync_queue_ks: store.keyspace("sync_queue").unwrap(),
        sync_cursor_ks: store.keyspace("sync_cursor").unwrap(),
        relationships_ks: store.keyspace("relationships").unwrap(),
        relationships_by_did_ks: store.keyspace("relationships_by_did").unwrap(),
        endorsement_types_ks: store.keyspace("endorsement_types").unwrap(),
        schemas_ks: store.keyspace("schemas").unwrap(),
        endorsements_ks: store.keyspace("endorsements").unwrap(),
        registry_client: None,
        registry_health: vtc_service::registry::RegistryHealth::new(),
        credential_signer: None,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn: None,
        public_url: None,
        install_signer: None,
        install_store: vtc_service::install::InstallTokenStore::new(install_ks),
        audit_ks: store.keyspace("audit").unwrap(),
        audit_key_ks: store.keyspace("audit_key").unwrap(),
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    #[cfg(feature = "website")]
    let router = routes::router_with(routing, None).with_state(state);
    #[cfg(not(feature = "website"))]
    let router = routes::router_with(routing).with_state(state);
    (router, dir)
}

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

async fn request(router: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn path_mode_health_at_root_is_exempt() {
    let routing = RoutingConfig::default();
    let (router, _dir) = build_router(&routing).await;

    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let (status, _) = request(&router, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/health must respond 200 without a Trust-Task header"
    );
}

#[tokio::test]
async fn path_mode_admin_surface_serves_embedded_spa() {
    // Phase 5 M5.7: the admin UX feature is default-on, so
    // `/admin/*` serves the baked in-tree SPA rather than the
    // 503 placeholder.
    let routing = RoutingConfig::default();
    let (router, _dir) = build_router(&routing).await;

    let req = Request::builder()
        .method("GET")
        .uri("/admin/build-info.json")
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["indexSha256"].is_string(), "got {json}");
}

#[tokio::test]
async fn path_mode_admin_bare_prefix_serves_admin_spa() {
    // `GET /admin` (no trailing slash) must hit the admin SPA's
    // `index.html`. Bare `/admin` is what operators type in browsers.
    let routing = RoutingConfig::default();
    let (router, _dir) = build_router(&routing).await;

    let req = Request::builder()
        .method("GET")
        .uri("/admin")
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&router, req).await;
    assert_eq!(status, StatusCode::OK, "/admin returned {status}");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("VTC Admin"),
        "/admin did not serve admin SPA — got first 200 chars: {}",
        &html[..html.len().min(200)]
    );
}

#[tokio::test]
async fn path_mode_admin_trailing_slash_serves_admin_spa() {
    // `GET /admin/` (with trailing slash) must also hit the admin
    // SPA, not fall through to the website's default landing page —
    // user-reported regression.
    let routing = RoutingConfig::default();
    let (router, _dir) = build_router(&routing).await;

    let req = Request::builder()
        .method("GET")
        .uri("/admin/")
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&router, req).await;
    assert_eq!(status, StatusCode::OK, "/admin/ returned {status}");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("VTC Admin"),
        "/admin/ did not serve admin SPA — got first 200 chars: {}",
        &html[..html.len().min(200)]
    );
}

#[tokio::test]
async fn path_mode_website_fallback_serves_default_landing_page() {
    // Follow-up to M5.4: when `website.root_dir` is unset, the
    // catch-all serves the in-tree default landing page from
    // `vtc-service/website-default/` instead of returning 503.
    let routing = RoutingConfig::default();
    let (router, _dir) = build_router(&routing).await;

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Verifiable Trust Community"),
        "default landing page drifted: {html}"
    );
}

#[tokio::test]
async fn subdomain_mode_strict_404s_unknown_host() {
    // Stand up the host-dispatch middleware standalone — easier
    // than exercising the full nested router from server.rs.
    let routing = RoutingConfig {
        api: MountConfig {
            mount: "/v1".into(),
            host: Some("api.example.com".into()),
        },
        admin_ui: MountConfig {
            mount: "/admin".into(),
            host: Some("admin.example.com".into()),
        },
        website: MountConfig {
            mount: "/".into(),
            host: Some("example.com".into()),
        },
        subdomain_mode_strict: true,
    };

    async fn ok() -> &'static str {
        "ok"
    }

    let map = HostMap::from_routing(&routing);
    let app = Router::new()
        .route("/", axum::routing::get(ok))
        .layer(axum::middleware::from_fn_with_state(map, enforce));

    // Known host → 200.
    let req = Request::builder()
        .uri("/")
        .header("Host", "api.example.com")
        .body(Body::empty())
        .unwrap();
    let (status, _) = request(&app, req).await;
    assert_eq!(status, StatusCode::OK);

    // Unknown host → 404 HostNotRecognised.
    let req = Request::builder()
        .uri("/")
        .header("Host", "evil.example.com")
        .body(Body::empty())
        .unwrap();
    let (status, body) = request(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], "HostNotRecognised");
}

#[tokio::test]
async fn subdomain_mode_non_strict_falls_through() {
    let routing = RoutingConfig {
        api: MountConfig {
            mount: "/v1".into(),
            host: Some("api.example.com".into()),
        },
        admin_ui: MountConfig {
            mount: "/admin".into(),
            host: None,
        },
        website: MountConfig {
            mount: "/".into(),
            host: None,
        },
        subdomain_mode_strict: false,
    };

    async fn ok() -> &'static str {
        "ok"
    }

    let map = HostMap::from_routing(&routing);
    let app = Router::new()
        .route("/", axum::routing::get(ok))
        .layer(axum::middleware::from_fn_with_state(map, enforce));

    // Unknown host with strict = false → request falls through
    // to the parent router (path-mode behaviour).
    let req = Request::builder()
        .uri("/")
        .header("Host", "evil.example.com")
        .body(Body::empty())
        .unwrap();
    let (status, _) = request(&app, req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pure_path_mode_middleware_is_noop() {
    // Every surface has host = None → middleware short-circuits,
    // any Host header passes through.
    let routing = RoutingConfig::default();

    async fn ok() -> &'static str {
        "ok"
    }

    let map = HostMap::from_routing(&routing);
    let app = Router::new()
        .route("/", axum::routing::get(ok))
        .layer(axum::middleware::from_fn_with_state(map, enforce));

    let req = Request::builder()
        .uri("/")
        .header("Host", "whatever.example.com")
        .body(Body::empty())
        .unwrap();
    let (status, _) = request(&app, req).await;
    assert_eq!(status, StatusCode::OK);
}
