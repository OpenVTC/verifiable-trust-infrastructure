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
use vtc_service::test_support::TestVtc;

/// Build a router using the requested routing config over a default
/// `TestVtc` state. Route-priority tests only need to see whether
/// prefixes dispatch correctly.
async fn build_router(routing: &RoutingConfig) -> (Router, TestVtc) {
    let vtc = TestVtc::builder()
        .vtc_did("did:key:z6MkTestVTC")
        .build()
        .await;
    #[cfg(feature = "website")]
    let router = routes::router_with(routing, None).with_state(vtc.state.clone());
    #[cfg(not(feature = "website"))]
    let router = routes::router_with(routing).with_state(vtc.state.clone());
    (router, vtc)
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
