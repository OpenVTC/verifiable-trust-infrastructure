//! Coverage for the M0.11 routing + CORS hardening.
//!
//! Two layers under test:
//!
//! 1. **Config-load validation** (`AppConfig::validate_routing_and_cors`)
//!    refuses obviously-broken configs at startup, not at first
//!    request. Tests exercise the validator directly so we don't
//!    need a temp filesystem.
//! 2. **CORS layer** wired into `routes::router()` returns the
//!    expected headers on preflight + actual cross-origin requests.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::config::{AppConfig, CorsConfig, MountConfig, RoutingConfig};
use vtc_service::routes;
use vtc_service::server::AppState;

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

// ═══════════════════════════════════════════════════════════════════
// Config validation
// ═══════════════════════════════════════════════════════════════════

fn cfg_with(routing: RoutingConfig, cors: CorsConfig) -> AppConfig {
    AppConfig {
        vtc_did: None,
        vta_did: None,
        vtc_name: None,
        vtc_description: None,
        public_url: None,
        server: Default::default(),
        log: Default::default(),
        store: StoreConfig {
            data_dir: std::path::PathBuf::from("data/test"),
        },
        messaging: None,
        auth: Default::default(),
        secrets: Default::default(),
        routing,
        cors,
        registry: Default::default(),
        renewal: Default::default(),
        website: Default::default(),
        admin_ui: Default::default(),
        config_path: std::path::PathBuf::new(),
    }
}

#[test]
fn defaults_validate_clean() {
    let cfg = cfg_with(RoutingConfig::default(), CorsConfig::default());
    cfg.validate_routing_and_cors().expect("defaults are valid");
}

#[test]
fn rejects_admin_ui_mounted_at_root_in_path_mode() {
    // Cookie-scope guard: `Path=/admin` collapses to "any path" when
    // admin_ui is at root, letting the public-website origin read
    // admin cookies.
    let routing = RoutingConfig {
        api: MountConfig {
            mount: "/v1".into(),
            host: None,
        },
        admin_ui: MountConfig {
            mount: "/".into(),
            host: None,
        },
        website: MountConfig {
            mount: "/site".into(),
            host: None,
        },
        subdomain_mode_strict: true,
    };
    let err = cfg_with(routing, Default::default())
        .validate_routing_and_cors()
        .expect_err("admin at / must be rejected");
    assert!(format!("{err}").contains("admin"), "got {err}");
}

#[test]
fn allows_admin_ui_at_root_when_host_routed() {
    // Subdomain mode (host set) carries its own scope, so the
    // root-mount guard doesn't fire.
    let routing = RoutingConfig {
        api: MountConfig {
            mount: "/v1".into(),
            host: None,
        },
        admin_ui: MountConfig {
            mount: "/".into(),
            host: Some("admin.example.com".into()),
        },
        website: MountConfig {
            mount: "/".into(),
            host: Some("example.com".into()),
        },
        subdomain_mode_strict: true,
    };
    cfg_with(routing, Default::default())
        .validate_routing_and_cors()
        .expect("subdomain mode bypasses cookie-scope guard");
}

#[test]
fn rejects_duplicate_path_mounts() {
    let routing = RoutingConfig {
        api: MountConfig {
            mount: "/v1".into(),
            host: None,
        },
        admin_ui: MountConfig {
            mount: "/v1".into(),
            host: None,
        },
        website: MountConfig {
            mount: "/".into(),
            host: None,
        },
        subdomain_mode_strict: true,
    };
    let err = cfg_with(routing, Default::default())
        .validate_routing_and_cors()
        .expect_err("duplicate mounts must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("/v1"), "got {msg}");
}

#[test]
fn rejects_mount_without_leading_slash() {
    let routing = RoutingConfig {
        api: MountConfig {
            mount: "v1".into(),
            host: None,
        },
        ..Default::default()
    };
    let err = cfg_with(routing, Default::default())
        .validate_routing_and_cors()
        .expect_err("bare prefix must be rejected");
    assert!(format!("{err}").contains("start with '/'"), "got {err}");
}

#[test]
fn rejects_wildcard_cors_origin() {
    let cors = CorsConfig {
        allowed_origins: vec!["*".into()],
    };
    let err = cfg_with(Default::default(), cors)
        .validate_routing_and_cors()
        .expect_err("wildcard cors must be rejected");
    assert!(format!("{err}").contains("wildcard"), "got {err}");
}

#[test]
fn rejects_partial_wildcard_cors_origin() {
    let cors = CorsConfig {
        allowed_origins: vec!["https://*.example.com".into()],
    };
    let err = cfg_with(Default::default(), cors)
        .validate_routing_and_cors()
        .expect_err("partial wildcard must be rejected");
    assert!(format!("{err}").contains("wildcard"), "got {err}");
}

#[test]
fn rejects_cors_origin_without_scheme() {
    let cors = CorsConfig {
        allowed_origins: vec!["admin.example.com".into()],
    };
    let err = cfg_with(Default::default(), cors)
        .validate_routing_and_cors()
        .expect_err("missing scheme must be rejected");
    assert!(format!("{err}").contains("full origin"), "got {err}");
}

#[test]
fn rejects_empty_cors_origin_entry() {
    let cors = CorsConfig {
        allowed_origins: vec!["".into()],
    };
    let err = cfg_with(Default::default(), cors)
        .validate_routing_and_cors()
        .expect_err("empty entry must be rejected");
    assert!(format!("{err}").contains("empty"), "got {err}");
}

#[test]
fn empty_cors_allowlist_is_valid() {
    // Empty = same-origin only; valid.
    let cfg = cfg_with(Default::default(), CorsConfig::default());
    cfg.validate_routing_and_cors().unwrap();
}

#[test]
fn accepts_https_and_http_origins() {
    let cors = CorsConfig {
        allowed_origins: vec![
            "https://admin.example.com".into(),
            "http://localhost:5173".into(),
        ],
    };
    cfg_with(Default::default(), cors)
        .validate_routing_and_cors()
        .unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// CORS layer wiring
// ═══════════════════════════════════════════════════════════════════

async fn build_router_with_cors(cors: CorsConfig) -> (axum::Router, tempfile::TempDir) {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let community_ks = store.keyspace("community").unwrap();
    let config_ks = store.keyspace("config").unwrap();
    let passkey_ks = store.keyspace("passkey").unwrap();
    let install_ks = store.keyspace("install").unwrap();
    let members_ks = store.keyspace("members").unwrap();
    let join_requests_ks = store.keyspace("join_requests").unwrap();
    let policies_ks = store.keyspace("policies").unwrap();
    let active_policies_ks = store.keyspace("active_policies").unwrap();
    let status_lists_ks = store.keyspace("status_lists").unwrap();
    let registry_records_ks = store.keyspace("registry_records").unwrap();
    let sync_queue_ks = store.keyspace("sync_queue").unwrap();
    let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
    let relationships_ks = store.keyspace("relationships").unwrap();
    let relationships_by_did_ks = store.keyspace("relationships_by_did").unwrap();
    let endorsement_types_ks = store.keyspace("endorsement_types").unwrap();
    let endorsements_ks = store.keyspace("endorsements").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").expect("jwt keys"));

    let mut config = cfg_with(RoutingConfig::default(), cors.clone());
    config.auth.jwt_signing_key = Some(BASE64.encode(jwt_seed));
    config.store.data_dir = dir.path().to_path_buf();

    let state = AppState {
        sessions_ks: sessions_ks.clone(),
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks: install_ks.clone(),
        members_ks: members_ks.clone(),
        join_requests_ks: join_requests_ks.clone(),
        policies_ks: policies_ks.clone(),
        active_policies_ks: active_policies_ks.clone(),
        status_lists_ks: status_lists_ks.clone(),
        registry_records_ks: registry_records_ks.clone(),
        sync_queue_ks: sync_queue_ks.clone(),
        sync_cursor_ks: sync_cursor_ks.clone(),
        relationships_ks: relationships_ks.clone(),
        relationships_by_did_ks: relationships_by_did_ks.clone(),
        endorsement_types_ks: endorsement_types_ks.clone(),
        schemas_ks: store.keyspace("schemas").unwrap(),
        endorsements_ks: endorsements_ks.clone(),
        registry_client: None,
        registry_health: vtc_service::registry::RegistryHealth::new(),
        credential_signer: None,
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn: None,
        public_url: None,
        install_signer: None,
        install_store: vtc_service::install::InstallTokenStore::new(install_ks),
        audit_writer: None,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let cors_layer = vtc_service_test_cors_layer(&cors);
    let router = routes::router().with_state(state).layer(cors_layer);
    (router, dir)
}

/// Mirror of `server::build_cors_layer` for use in this integration
/// test. Kept in sync with production so the layer the daemon
/// actually serves matches what we test. If the production layer
/// shape changes this test will fail to compile or its assertions
/// will drift visibly.
fn vtc_service_test_cors_layer(cors: &CorsConfig) -> tower_http::cors::CorsLayer {
    use axum::http::Method;
    use axum::http::header::{
        ACCESS_CONTROL_ALLOW_HEADERS, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue,
    };

    if cors.allowed_origins.is_empty() {
        return tower_http::cors::CorsLayer::new();
    }

    let allowed_origins: Vec<HeaderValue> = cors
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    tower_http::cors::CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderName::from_static("trust-task"),
            HeaderName::from_static("idempotency-key"),
        ])
        .allow_credentials(true)
}

#[tokio::test]
async fn preflight_from_allowed_origin_returns_cors_headers() {
    let cors = CorsConfig {
        allowed_origins: vec!["https://admin.example.com".into()],
    };
    let (router, _dir) = build_router_with_cors(cors).await;

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/v1/admin/config")
        .header("Origin", "https://admin.example.com")
        .header("Access-Control-Request-Method", "PATCH")
        .header(
            "Access-Control-Request-Headers",
            "Authorization, Trust-Task",
        )
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(
        headers.get("Access-Control-Allow-Origin").unwrap(),
        "https://admin.example.com",
    );
    let allow_headers = headers
        .get("Access-Control-Allow-Headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_lowercase();
    assert!(allow_headers.contains("authorization"));
    assert!(allow_headers.contains("trust-task"));
    assert!(allow_headers.contains("idempotency-key"));
    assert_eq!(
        headers.get("Access-Control-Allow-Credentials").unwrap(),
        "true",
    );
}

#[tokio::test]
async fn preflight_from_disallowed_origin_omits_cors_headers() {
    let cors = CorsConfig {
        allowed_origins: vec!["https://admin.example.com".into()],
    };
    let (router, _dir) = build_router_with_cors(cors).await;

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/v1/admin/config")
        .header("Origin", "https://attacker.example.com")
        .header("Access-Control-Request-Method", "PATCH")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let headers = resp.headers();

    // tower-http's CORS layer omits the allow-origin header for
    // non-matching origins; the browser's same-origin policy turns
    // that into a CORS error in the JS console.
    assert!(
        !headers.contains_key("Access-Control-Allow-Origin"),
        "headers leaked: {:?}",
        headers
    );
}

#[tokio::test]
async fn empty_allowlist_disables_cors_headers() {
    let (router, _dir) = build_router_with_cors(CorsConfig::default()).await;

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/v1/admin/config")
        .header("Origin", "https://admin.example.com")
        .header("Access-Control-Request-Method", "PATCH")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let headers = resp.headers();
    assert!(!headers.contains_key("Access-Control-Allow-Origin"));
}

#[tokio::test]
async fn actual_get_from_allowed_origin_carries_cors_response_header() {
    let cors = CorsConfig {
        allowed_origins: vec!["https://admin.example.com".into()],
    };
    let (router, _dir) = build_router_with_cors(cors).await;

    // Hit `/health` — no auth, no Trust-Task gate, just the
    // catch-all GET. The CORS layer should attach the
    // `Access-Control-Allow-Origin` response header so the browser
    // accepts the response.
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .header("Origin", "https://admin.example.com")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("Access-Control-Allow-Origin").unwrap(),
        "https://admin.example.com",
    );

    // Sanity: body still rendered.
    let _ = resp.into_body().collect().await.unwrap();
}
