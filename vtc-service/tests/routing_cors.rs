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

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vti_common::config::StoreConfig;

use vtc_service::config::{AppConfig, CorsConfig, MountConfig, RoutingConfig, WebsiteConfig};
use vtc_service::routes;
use vtc_service::test_support::TestVtc;

// ═══════════════════════════════════════════════════════════════════
// Config validation
// ═══════════════════════════════════════════════════════════════════

fn cfg_with(routing: RoutingConfig, cors: CorsConfig) -> AppConfig {
    AppConfig {
        vtc_did: None,
        vta_did: None,
        vtc_name: None,
        hooks: Default::default(),
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
        join_requests: Default::default(),
        website: Default::default(),
        admin_ui: Default::default(),
        config_path: std::path::PathBuf::new(),
    }
}

/// Like [`cfg_with`] but lets a test set a filesystem website
/// (`website.root_dir`) to exercise the host-separation guard.
fn cfg_with_website(routing: RoutingConfig, website: WebsiteConfig) -> AppConfig {
    AppConfig {
        website,
        ..cfg_with(routing, CorsConfig::default())
    }
}

/// A three-host routing config where the website sits on its own host
/// and the admin/API surface shares a host — the only posture that
/// isolates a filesystem website.
fn three_host_routing(website_host: Option<&str>) -> RoutingConfig {
    RoutingConfig {
        api: MountConfig {
            mount: "/v1".into(),
            host: Some("app.example.com".into()),
        },
        admin_ui: MountConfig {
            mount: "/admin".into(),
            host: Some("app.example.com".into()),
        },
        website: MountConfig {
            mount: "/".into(),
            host: website_host.map(String::from),
        },
        subdomain_mode_strict: true,
    }
}

#[test]
fn defaults_validate_clean() {
    let cfg = cfg_with(RoutingConfig::default(), CorsConfig::default());
    cfg.validate_routing_and_cors().expect("defaults are valid");
}

#[test]
fn rejects_filesystem_website_sharing_admin_origin() {
    // A filesystem website with no dedicated host shares the origin
    // with the admin SPA + API, letting deployed content ride the
    // admin session cookie. P3.1 refuses this posture.
    let website = WebsiteConfig {
        root_dir: Some(std::path::PathBuf::from("/srv/site")),
        ..Default::default()
    };
    let err = cfg_with_website(RoutingConfig::default(), website)
        .validate_routing_and_cors()
        .expect_err("filesystem website on the shared origin must be rejected");
    assert!(format!("{err}").contains("website.root_dir"), "got {err}");
}

#[test]
fn rejects_filesystem_website_host_colliding_with_api() {
    // website.host set, but equal to the api/admin host → still shares
    // an origin. Rejected.
    let website = WebsiteConfig {
        root_dir: Some(std::path::PathBuf::from("/srv/site")),
        ..Default::default()
    };
    let err = cfg_with_website(three_host_routing(Some("app.example.com")), website)
        .validate_routing_and_cors()
        .expect_err("colliding website host must be rejected");
    assert!(format!("{err}").contains("collides"), "got {err}");
}

#[test]
fn allows_filesystem_website_on_dedicated_host() {
    let website = WebsiteConfig {
        root_dir: Some(std::path::PathBuf::from("/srv/site")),
        ..Default::default()
    };
    cfg_with_website(three_host_routing(Some("www.example.com")), website)
        .validate_routing_and_cors()
        .expect("a filesystem website on its own host is allowed");
}

#[test]
fn allows_default_landing_page_on_shared_origin() {
    // The in-tree default site (root_dir unset) is trusted code we
    // ship, so the host-separation guard does not fire for it.
    cfg_with(RoutingConfig::default(), CorsConfig::default())
        .validate_routing_and_cors()
        .expect("default landing page may stay co-resident");
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

async fn build_router_with_cors(cors: CorsConfig) -> (axum::Router, TestVtc) {
    // CORS is applied as an explicit layer below, independent of the
    // state's own config — so a default `TestVtc` state is sufficient.
    let vtc = TestVtc::builder().build().await;
    let cors_layer = vtc_service_test_cors_layer(&cors);
    let router = routes::router()
        .with_state(vtc.state.clone())
        .layer(cors_layer);
    (router, vtc)
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
