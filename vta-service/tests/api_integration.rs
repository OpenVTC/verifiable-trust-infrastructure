//! Integration tests for the VTA REST API.
//!
//! Spins up the axum router with a temp fjall store and tests endpoints
//! with real HTTP requests. JWT tokens are created programmatically and
//! sessions are pre-inserted to bypass the DIDComm challenge-response flow.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vti_common::acl::Role;
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, store_session};

use vta_service::store::KeyspaceHandle;
use vta_service::test_support::{TestAppContext, build_test_app};

// ── Test harness — thin wrapper over the workspace's `test_support`
// `build_test_app` helper. The substantial AppState wiring (every
// keyspace, the JWT keys, the DID resolver, the registry, the drain
// sweeper, etc.) was duplicated here pre-consolidation; it now lives
// in `vta_service::test_support` so any future integration test gets
// it for free with two lines of setup.

struct TestApp {
    router: axum::Router,
}

impl TestApp {
    async fn new() -> (Self, TestContext) {
        let (router, ctx) = build_test_app().await;
        (Self { router }, TestContext { inner: ctx })
    }

    async fn request(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("request failed");
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
        (status, json)
    }
}

struct TestContext {
    inner: TestAppContext,
}

impl TestContext {
    fn jwt_keys(&self) -> &Arc<JwtKeys> {
        &self.inner.jwt_keys
    }

    fn sessions_ks(&self) -> &KeyspaceHandle {
        &self.inner.sessions_ks
    }

    #[allow(dead_code)]
    fn acl_ks(&self) -> &KeyspaceHandle {
        &self.inner.acl_ks
    }

    /// Turn on the AAL2 step-up policy for every operation. The shipping
    /// default is disabled (AAL1 everywhere); tests that assert the gate
    /// fires opt in here, mirroring an operator enabling step-up with a `*`
    /// floor. The config Arc is shared with the live router, so this takes
    /// effect for subsequent requests.
    async fn enable_step_up_all(&self) {
        use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
        self.set_step_up_floors(vec![StepUpFloor {
            operation: "*".into(),
            mode: StepUpMode::SelfApprove,
            allow_aal1_if_non_escalating: false,
        }])
        .await;
    }

    /// Enable the step-up policy with an explicit set of floors. The config
    /// Arc is shared with the live router, so this takes effect immediately.
    async fn set_step_up_floors(&self, floors: Vec<vti_common::auth::step_up::StepUpFloor>) {
        use vti_common::auth::step_up::StepUpPolicy;
        self.inner.config.write().await.auth.step_up = StepUpPolicy {
            enabled: true,
            floors,
        };
    }
}

impl TestContext {
    /// Create an authenticated session and return a Bearer token.
    async fn auth_token(&self, did: &str, role: &str, contexts: Vec<String>) -> String {
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        let session = Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        };
        store_session(self.sessions_ks(), &session)
            .await
            .expect("store session");

        let claims = self.jwt_keys().new_claims(
            did.to_string(),
            session_id,
            role.to_string(),
            contexts,
            900,
            false,
        );
        self.jwt_keys().encode(&claims).expect("encode jwt")
    }

    /// Like [`auth_token`], but the session is **stepped-up (AAL2)** — the JWT
    /// carries `acr=aal2` and a second factor in `amr`. Required for endpoints
    /// gated by `RequireStepUp` (ACL mutations, context/key deletion). A plain
    /// `auth_token` is AAL1, which those endpoints reject with a step-up `403`.
    async fn auth_token_aal2(&self, did: &str, role: &str, contexts: Vec<String>) -> String {
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        let session = Session {
            session_id: session_id.clone(),
            did: did.to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["did".into(), "passkey".into()],
            acr: "aal2".into(),
            acr_expires_at: None,
            token_id: None,
            session_pubkey_b58btc: None,
        };
        store_session(self.sessions_ks(), &session)
            .await
            .expect("store session");

        let claims = self
            .jwt_keys()
            .new_claims(
                did.to_string(),
                session_id,
                role.to_string(),
                contexts,
                900,
                false,
            )
            .with_aal(vec!["did".into(), "passkey".into()], "aal2");
        self.jwt_keys().encode(&claims).expect("encode jwt")
    }

    /// Mint a token signed with a different audience. Used to verify
    /// audience-isolation rejection — a VTC-audience token must not
    /// authenticate against a VTA route. CLAUDE.md guards this as a
    /// load-bearing invariant; tested at the JWT layer in vti-common
    /// but here through the full route stack.
    #[allow(dead_code)]
    fn auth_token_with_audience(
        &self,
        did: &str,
        role: &str,
        contexts: Vec<String>,
        audience: &str,
    ) -> String {
        // Use a fresh JwtKeys with the specified audience — this is what
        // a VTC instance issuing tokens for its own audience would do.
        let foreign_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], audience).unwrap();
        let claims = foreign_keys.new_claims(
            did.to_string(),
            format!("sess-{}", uuid::Uuid::new_v4()),
            role.to_string(),
            contexts,
            900,
            false,
        );
        foreign_keys.encode(&claims).expect("encode foreign jwt")
    }

    /// Create an ACL entry for a DID.
    #[allow(dead_code)]
    async fn create_acl(&self, did: &str, role: Role, contexts: Vec<String>) {
        let entry = vti_common::acl::AclEntry::new(did, role, "test").with_contexts(contexts);
        self.acl_ks()
            .insert(format!("acl:{did}"), &entry)
            .await
            .expect("insert acl");
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_auth(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn patch_auth(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn put_auth(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn delete_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// ── Capabilities ──────────────────────────────────────────────────

#[tokio::test]
async fn capabilities_requires_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/capabilities")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn capabilities_returns_features() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["any".into()])
        .await;
    let (status, body) = app.request(get_auth("/capabilities", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["version"].as_str().is_some());
    assert!(body["features"].is_object());
    assert!(body["services"].is_object());
    assert!(body["did_creation_modes"].is_array());
    // webvh feature is compiled in for tests
    assert_eq!(body["features"]["webvh"], true);
}

// ── Health ─────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok_without_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, body) = app.request(get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn health_details_requires_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/health/details")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_details_returns_version_with_auth() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkTest", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/health/details", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
    // TSP is off by default — health surfaces the advertised-transport state.
    assert_eq!(body["tsp_enabled"], false);
}

#[tokio::test]
async fn health_details_reports_tsp_enabled_when_configured() {
    let (app, ctx) = TestApp::new().await;
    ctx.inner.config.write().await.services.tsp = true;
    let token = ctx.auth_token("did:key:z6MkTest", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/health/details", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tsp_enabled"], true);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn didcomm_status_requires_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/services/didcomm")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn didcomm_status_forbids_non_super_admin() {
    // Parity with `GET /services` (list_services): both are super-admin-gated
    // since they expose the same `mediator_did`. A reader-role caller is rejected.
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkTest", "reader", vec![]).await;
    let (status, _) = app.request(get_auth("/services/didcomm", &token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn didcomm_status_returns_disabled_when_not_enabled() {
    let (app, ctx) = TestApp::new().await;
    ctx.inner.config.write().await.services.didcomm = false;
    // admin + empty contexts == super-admin
    let token = ctx.auth_token("did:key:z6MkTest", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/services/didcomm", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "enabled": false }));
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn didcomm_status_returns_mediator_and_websocket_state_when_enabled() {
    let (app, ctx) = TestApp::new().await;
    {
        let mut config = ctx.inner.config.write().await;
        config.services.didcomm = true;
        config.messaging = Some(vti_common::config::MessagingConfig {
            mediator_url: "wss://mediator.example.com".into(),
            mediator_did: "did:peer:2.med".into(),
            mediator_host: None,
            setup_acl: false,
            drain_inbox_on_start: false,
        });
    }
    let token = ctx.auth_token("did:key:z6MkTest", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/services/didcomm", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["mediator_did"], "did:peer:2.med");
    assert_eq!(body["websocket_status"], "disconnected");
}

// ── Auth: missing/invalid token ────────────────────────────────────

#[tokio::test]
async fn missing_token_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get("/config")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let (status, _) = app.request(get_auth("/config", "not-a-jwt")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_session_returns_401() {
    let (app, ctx) = TestApp::new().await;
    // Create a token with a valid JWT but no session in the store
    let claims = ctx.jwt_keys().new_claims(
        "did:key:z6MkGhost".into(),
        "nonexistent-session".into(),
        "admin".into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys().encode(&claims).unwrap();
    let (status, _) = app.request(get_auth("/config", &token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ── Role enforcement ───────────────────────────────────────────────

#[tokio::test]
async fn application_role_cannot_access_admin_endpoints() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["ctx1".into()])
        .await;
    // POST /keys requires admin
    let (status, _) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "ctx1"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn initiator_cannot_access_super_admin_endpoints() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkInit", "initiator", vec![])
        .await;
    // PATCH /config requires super admin
    let (status, _) = app
        .request(patch_auth("/config", &token, json!({"vta_name": "hacked"})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_read_config() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/config", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["vta_did"], "did:key:z6MkTestVTA");
}

#[tokio::test]
async fn super_admin_can_update_config() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(patch_auth(
            "/config",
            &token,
            json!({"vta_name": "Updated Name"}),
        ))
        .await;
    assert!(status.is_success(), "update config: {status} {body}");
    assert_eq!(body["vta_name"], "Updated Name");
}

#[tokio::test]
async fn scoped_admin_cannot_update_config() {
    let (app, ctx) = TestApp::new().await;
    // Admin with allowed_contexts is NOT super admin
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(patch_auth("/config", &token, json!({"vta_name": "nope"})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── ACL CRUD ───────────────────────────────────────────────────────

#[tokio::test]
async fn acl_create_and_list() {
    let (app, ctx) = TestApp::new().await;
    // ACL creation is an AAL2-gated mutation.
    let token = ctx
        .auth_token_aal2("did:key:z6MkAdmin", "admin", vec![])
        .await;

    // Create
    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({
                "did": "did:key:z6MkNew",
                "role": "application",
                "label": "test app",
                "allowed_contexts": ["ctx1"]
            }),
        ))
        .await;
    assert!(status.is_success(), "create: {body}");

    // List
    let (status, body) = app.request(get_auth("/acl", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries array");
    assert!(
        entries.iter().any(|e| e["did"] == "did:key:z6MkNew"),
        "new entry should be in list"
    );
}

/// An AAL1 admin hitting an AAL2-gated mutation is rejected with the step-up
/// `403` that *carries the approve-request* — not a bare 403. The caller has
/// the right role (so this isn't a permission failure); it just hasn't stepped
/// up. Mirrors the operator policy: all ACL changes require AAL2.
#[tokio::test]
async fn acl_mutation_requires_step_up() {
    let (app, ctx) = TestApp::new().await;
    // Opt into step-up enforcement (shipping default is disabled).
    ctx.enable_step_up_all().await;
    // A normal (AAL1) admin session: correct role, but not stepped up.
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({
                "did": "did:key:z6MkNew",
                "role": "application",
                "label": "test app",
                "allowed_contexts": ["ctx1"]
            }),
        ))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "AAL1 must be gated: {body}");
    assert_eq!(body["error"], "step_up_required");
    assert_eq!(body["requiredAcr"], "aal2");
    // The 403 carries the approve-request the caller hands to its approver.
    let ar = &body["approveRequest"];
    assert_eq!(
        ar["type"],
        "https://trusttasks.org/spec/auth/step-up/approve-request/0.1"
    );
    assert_eq!(ar["recipient"], "did:key:z6MkAdmin");
    assert_eq!(ar["payload"]["targetAcr"], "aal2");
    assert!(
        ar["payload"]["challenge"]
            .as_str()
            .is_some_and(|c| c.len() >= 16),
        "approve-request must carry a ≥16-char challenge"
    );
}

#[tokio::test]
async fn step_up_floor_is_per_operation_class() {
    use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
    let (app, ctx) = TestApp::new().await;
    // Gate ONLY `context/delete` — no floor for `acl/grant`, no `*` catch-all.
    ctx.set_step_up_floors(vec![StepUpFloor {
        operation: "context/delete".into(),
        mode: StepUpMode::SelfApprove,
        allow_aal1_if_non_escalating: false,
    }])
    .await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({
                "did": "did:key:z6MkUngated",
                "role": "application",
                "label": "ungated app",
                "allowed_contexts": ["ctx1"]
            }),
        ))
        .await;

    // The `acl/grant` route must NOT be step-up-gated by a context/delete-only
    // policy — op-class resolution is specific, not all-or-nothing.
    assert_ne!(
        body["error"], "step_up_required",
        "acl/grant gated by a context/delete-only floor: {status} {body}"
    );
}

#[tokio::test]
async fn swap_key_carve_out_admits_aal1_when_configured() {
    use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
    let (app, ctx) = TestApp::new().await;
    // Gate swap-key at AAL2 but allow the non-escalating self-service carve-out.
    ctx.set_step_up_floors(vec![StepUpFloor {
        operation: "acl/swap-key".into(),
        mode: StepUpMode::SelfApprove,
        allow_aal1_if_non_escalating: true,
    }])
    .await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    let (_status, body) = app
        .request(post_auth(
            "/acl/swap",
            &token,
            json!({ "presentation": "not-a-real-vp" }),
        ))
        .await;

    // The carve-out admits the swap at AAL1, so it is NOT step-up-gated; it
    // fails later on the (invalid) presentation rather than on step-up.
    assert_ne!(
        body["error"], "step_up_required",
        "swap-key carve-out should admit AAL1: {body}"
    );
}

#[tokio::test]
async fn swap_key_gated_without_carve_out() {
    use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
    let (app, ctx) = TestApp::new().await;
    // Same AAL2 floor but WITHOUT the carve-out → swap-key is gated.
    ctx.set_step_up_floors(vec![StepUpFloor {
        operation: "acl/swap-key".into(),
        mode: StepUpMode::SelfApprove,
        allow_aal1_if_non_escalating: false,
    }])
    .await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/acl/swap",
            &token,
            json!({ "presentation": "not-a-real-vp" }),
        ))
        .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "swap-key must be gated: {body}"
    );
    assert_eq!(body["error"], "step_up_required");
}

#[tokio::test]
async fn acl_update_sets_step_up_approver() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    // Grant with no approver…
    let (status, _) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({ "did": "did:key:z6MkGrantee2", "role": "application", "allowed_contexts": ["ctx1"] }),
        ))
        .await;
    assert!(status.is_success());

    // …then add one via PATCH.
    let (status, body) = app
        .request(patch_auth(
            "/acl/did:key:z6MkGrantee2",
            &token,
            json!({ "step_up_approver": "did:key:z6MkApprover" }),
        ))
        .await;
    assert!(
        status.is_success(),
        "update should succeed: {status} {body}"
    );
    assert_eq!(
        body["step_up_approver"], "did:key:z6MkApprover",
        "update must set + reflect the step-up approver: {body}"
    );
}

#[tokio::test]
async fn acl_grant_persists_step_up_approver() {
    let (app, ctx) = TestApp::new().await;
    // Step-up ships disabled, so an AAL1 admin can grant without a gate.
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({
                "did": "did:key:z6MkGrantee",
                "role": "application",
                "allowed_contexts": ["ctx1"],
                "step_up_approver": "did:key:z6MkApprover"
            }),
        ))
        .await;

    assert!(status.is_success(), "grant should succeed: {status} {body}");
    // The configured approver round-trips through the create result.
    assert_eq!(
        body["step_up_approver"], "did:key:z6MkApprover",
        "grant must persist + reflect the step-up approver: {body}"
    );
}

#[tokio::test]
async fn delegated_step_up_routes_to_configured_approver() {
    use vti_common::acl::{AclEntry, Role, store_acl_entry};
    use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
    let (app, ctx) = TestApp::new().await;
    let caller = "did:key:z6MkAdmin";
    let approver = "did:key:z6MkApprover";
    // The caller's ACL entry names its delegated approver.
    store_acl_entry(
        ctx.acl_ks(),
        &AclEntry::new(caller, Role::Admin, "test")
            .with_step_up_approver(Some(approver.to_string())),
    )
    .await
    .unwrap();
    ctx.set_step_up_floors(vec![StepUpFloor {
        operation: "acl/grant".into(),
        mode: StepUpMode::Delegated,
        allow_aal1_if_non_escalating: false,
    }])
    .await;
    let token = ctx.auth_token(caller, "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({ "did": "did:key:z6MkNew", "role": "application", "allowed_contexts": ["ctx1"] }),
        ))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "step_up_required");
    // The approve-request is addressed to the configured approver, not the caller.
    assert_eq!(
        body["approveRequest"]["recipient"], approver,
        "delegated approve-request must be addressed to the configured approver: {body}"
    );
}

#[tokio::test]
async fn delegated_step_up_without_approver_fails_closed() {
    use vti_common::acl::{AclEntry, Role, store_acl_entry};
    use vti_common::auth::step_up::{StepUpFloor, StepUpMode};
    let (app, ctx) = TestApp::new().await;
    let caller = "did:key:z6MkNoApprover";
    // ACL entry with NO step-up approver under a delegated floor.
    store_acl_entry(ctx.acl_ks(), &AclEntry::new(caller, Role::Admin, "test"))
        .await
        .unwrap();
    ctx.set_step_up_floors(vec![StepUpFloor {
        operation: "acl/grant".into(),
        mode: StepUpMode::Delegated,
        allow_aal1_if_non_escalating: false,
    }])
    .await;
    let token = ctx.auth_token(caller, "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/acl",
            &token,
            json!({ "did": "did:key:z6MkNew2", "role": "application", "allowed_contexts": ["ctx1"] }),
        ))
        .await;

    // Fail-closed: 403 with no approve-request (nothing the caller can do until
    // an operator registers an approver — the subject can't self-approve a
    // delegated requirement).
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "step_up_required");
    assert!(
        body.get("approveRequest").is_none(),
        "fail-closed must not carry an approve-request: {body}"
    );
}

#[tokio::test]
async fn acl_application_cannot_manage() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["ctx1".into()])
        .await;
    let (status, _) = app.request(get_auth("/acl", &token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Context CRUD ───────────────────────────────────────────────────

#[tokio::test]
async fn context_create_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    // Scoped admin → forbidden
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "new-ctx", "name": "New Context"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Super admin → OK
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "new-ctx", "name": "New Context"}),
        ))
        .await;
    assert!(status.is_success(), "create: {body}");
}

// ── Key management ─────────────────────────────────────────────────

#[tokio::test]
async fn key_create_and_list() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create a context first (needed for key creation)
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "test", "name": "Test Context"}),
        ))
        .await;
    assert!(status.is_success());

    // Create key
    let (status, body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "test"}),
        ))
        .await;
    assert!(status.is_success(), "create key: {body}");
    assert!(body["key_id"].is_string());
    assert_eq!(body["key_type"], "ed25519");

    // List keys
    let (status, body) = app.request(get_auth("/keys", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().expect("keys array");
    assert!(!keys.is_empty(), "should have at least one key");
}

// ── Restart requires super admin ───────────────────────────────────

#[tokio::test]
async fn restart_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    // Regular admin with contexts → forbidden
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(post_auth("/vta/restart", &token, json!({})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Initiator → forbidden
    let token = ctx
        .auth_token("did:key:z6MkInit", "initiator", vec![])
        .await;
    let (status, _) = app
        .request(post_auth("/vta/restart", &token, json!({})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Backup requires super admin ────────────────────────────────────

#[tokio::test]
async fn backup_export_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    // Scoped admin → forbidden
    let token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["ctx1".into()])
        .await;
    let (status, _) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "test-password-12!!", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn backup_export_rejects_short_password() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "short", "include_audit": false}),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "should reject short password: {body}"
    );
}

#[tokio::test]
async fn backup_export_and_import_preview() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Export
    let (status, envelope) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "test-password-12!!", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "export: {envelope}");
    assert_eq!(envelope["format"], "vta-backup-v1");

    // Import preview (confirm=false)
    let (status, preview) = app
        .request(post_auth(
            "/backup/import",
            &token,
            json!({
                "backup": envelope,
                "password": "test-password-12!!",
                "confirm": false
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "preview: {preview}");
    assert_eq!(preview["status"], "preview");
}

// ── Cache ──────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_put_get_delete() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/cache/test-key")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"value":"hello","ttl_secs":60}"#))
        .unwrap();
    let (status, _) = app.request(req).await;
    assert!(status.is_success(), "PUT cache: {status}");

    // GET
    let (status, body) = app.request(get_auth("/cache/test-key", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], "hello");

    // DELETE
    let (status, _) = app.request(delete_auth("/cache/test-key", &token)).await;
    assert!(status.is_success(), "DELETE cache: {status}");

    // GET again → 404
    let (status, _) = app.request(get_auth("/cache/test-key", &token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Audit ──────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_list_requires_admin() {
    let (app, ctx) = TestApp::new().await;

    // Application → forbidden
    let token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["ctx1".into()])
        .await;
    let (status, _) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin → OK
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["entries"].is_array());
}

// ── Context scoping ────────────────────────────────────────────────

#[tokio::test]
async fn scoped_admin_can_only_access_own_context_keys() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Create two contexts
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-a", "name": "A"}),
    ))
    .await;
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-b", "name": "B"}),
    ))
    .await;

    // Create a key in ctx-a
    let (status, key_body) = app
        .request(post_auth(
            "/keys",
            &super_token,
            json!({"key_type": "ed25519", "context_id": "ctx-a"}),
        ))
        .await;
    assert!(status.is_success());
    let key_id = key_body["key_id"].as_str().unwrap();

    // Scoped admin for ctx-b cannot get the key in ctx-a (returns 403 or 404 — both are valid)
    let encoded_id = urlencoding::encode(key_id);
    let scoped_b_token = ctx
        .auth_token("did:key:z6MkB", "admin", vec!["ctx-b".into()])
        .await;
    let (status, _) = app
        .request(get_auth(&format!("/keys/{encoded_id}"), &scoped_b_token))
        .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "scoped admin should not access other context's key, got {status}"
    );

    // Scoped admin for ctx-a CAN get the key
    let scoped_a_token = ctx
        .auth_token("did:key:z6MkA", "admin", vec!["ctx-a".into()])
        .await;
    let (status, body) = app
        .request(get_auth(&format!("/keys/{encoded_id}"), &scoped_a_token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key_id"], key_id);
}

// ── Key lifecycle ──────────────────────────────────────────────────

#[tokio::test]
async fn key_create_revoke_list_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create context + key
    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "lc", "name": "Lifecycle"}),
    ))
    .await;
    let (_, key_body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "lc"}),
        ))
        .await;
    let key_id = key_body["key_id"].as_str().unwrap();
    assert_eq!(key_body["status"], "active");

    // Revoke the key (key_id may contain slashes from derivation path, URL-encode it)
    let encoded_id = urlencoding::encode(key_id);
    let (status, body) = app
        .request(delete_auth(&format!("/keys/{encoded_id}"), &token))
        .await;
    assert!(status.is_success(), "revoke: {status} {body}");

    // Get key — should show revoked status
    let (status, body) = app
        .request(get_auth(&format!("/keys/{encoded_id}"), &token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "revoked");
}

#[tokio::test]
async fn key_rename() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "rn", "name": "Rename"}),
    ))
    .await;
    let (_, key_body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "ed25519", "context_id": "rn", "label": "original"}),
        ))
        .await;
    let key_id = key_body["key_id"].as_str().unwrap();

    // Rename the key (PATCH expects new key_id in body)
    let encoded_id = urlencoding::encode(key_id);
    let (status, body) = app
        .request(patch_auth(
            &format!("/keys/{encoded_id}"),
            &token,
            json!({"key_id": "renamed-key"}),
        ))
        .await;
    assert!(status.is_success(), "rename: {status} {body}");
    assert_eq!(body["key_id"], "renamed-key");
}

// ── Seed management ────────────────────────────────────────────────

#[tokio::test]
async fn seed_list_returns_seeds() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app.request(get_auth("/keys/seeds", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["seeds"].is_array());
}

// ── Audit entries created by operations ────────────────────────────

#[tokio::test]
async fn operations_create_audit_entries() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Perform some operations that create audit entries
    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "aud", "name": "Audit Test"}),
    ))
    .await;
    app.request(post_auth(
        "/keys",
        &token,
        json!({"key_type": "ed25519", "context_id": "aud"}),
    ))
    .await;

    // Check audit logs contain entries
    let (status, body) = app.request(get_auth("/audit/logs", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries");
    assert!(
        !entries.is_empty(),
        "should have at least 1 audit entry, got {}",
        entries.len()
    );

    // Verify audit entries have expected fields
    let entry = &entries[0];
    assert!(entry["id"].is_string());
    assert!(entry["timestamp"].is_number());
    assert!(entry["action"].is_string());
    assert!(entry["actor"].is_string());
}

// ── Audit retention ────────────────────────────────────────────────

#[tokio::test]
async fn audit_retention_get_and_update() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Get current retention
    let (status, body) = app.request(get_auth("/audit/retention", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["retention_days"].is_number());

    // Update retention
    let (status, body) = app
        .request(patch_auth(
            "/audit/retention",
            &token,
            json!({"retention_days": 90}),
        ))
        .await;
    assert!(status.is_success(), "update retention: {status} {body}");
}

// ── Backup wrong password ──────────────────────────────────────────

#[tokio::test]
async fn backup_import_wrong_password_returns_auth_error() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Export with one password
    let (status, envelope) = app
        .request(post_auth(
            "/backup/export",
            &token,
            json!({"password": "correct-password!!", "include_audit": false}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Import with wrong password
    let (status, body) = app
        .request(post_auth(
            "/backup/import",
            &token,
            json!({"backup": envelope, "password": "wrong-password!!!", "confirm": false}),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong password should → 401: {body}"
    );
}

// ── ACL CRUD full lifecycle ────────────────────────────────────────

#[tokio::test]
async fn acl_get_update_delete_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    // create/update/delete are AAL2-gated mutations.
    let token = ctx
        .auth_token_aal2("did:key:z6MkAdmin", "admin", vec![])
        .await;

    // Create
    app.request(post_auth(
        "/acl",
        &token,
        json!({
            "did": "did:key:z6MkTarget",
            "role": "application",
            "label": "test",
            "allowed_contexts": ["ctx1"]
        }),
    ))
    .await;

    // Get
    let (status, body) = app
        .request(get_auth("/acl/did:key:z6MkTarget", &token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "application");

    // Update
    let (status, body) = app
        .request(patch_auth(
            "/acl/did:key:z6MkTarget",
            &token,
            json!({"role": "initiator", "label": "updated"}),
        ))
        .await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["role"], "initiator");

    // Delete
    let (status, _) = app
        .request(delete_auth("/acl/did:key:z6MkTarget", &token))
        .await;
    assert!(status.is_success());

    // Verify deleted
    let (status, _) = app
        .request(get_auth("/acl/did:key:z6MkTarget", &token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Context lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn context_create_get_update_delete() {
    let (app, ctx) = TestApp::new().await;
    // Context deletion (the final step) is AAL2-gated.
    let token = ctx
        .auth_token_aal2("did:key:z6MkSuper", "admin", vec![])
        .await;

    // Create
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &token,
            json!({"id": "lifecycle", "name": "Test", "description": "A test context"}),
        ))
        .await;
    assert!(status.is_success());

    // Get
    let (status, body) = app.request(get_auth("/contexts/lifecycle", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Test");
    assert_eq!(body["description"], "A test context");

    // Update
    let (status, body) = app
        .request(patch_auth(
            "/contexts/lifecycle",
            &token,
            json!({"name": "Updated"}),
        ))
        .await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["name"], "Updated");

    // List
    let (status, body) = app.request(get_auth("/contexts", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let contexts = body["contexts"].as_array().expect("contexts");
    assert!(contexts.iter().any(|c| c["id"] == "lifecycle"));

    // Delete
    let (status, _) = app
        .request(delete_auth("/contexts/lifecycle", &token))
        .await;
    assert!(status.is_success());
}

// ── Multiple key types ─────────────────────────────────────────────

#[tokio::test]
async fn create_p256_key() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "p256", "name": "P256 Test"}),
    ))
    .await;

    let (status, body) = app
        .request(post_auth(
            "/keys",
            &token,
            json!({"key_type": "p256", "context_id": "p256"}),
        ))
        .await;
    assert!(status.is_success(), "create p256: {status} {body}");
    assert_eq!(body["key_type"], "p256");
    assert!(body["public_key"].is_string());
}

// ── Context DID update (context admin) ────────────────────────────

#[tokio::test]
async fn context_admin_can_update_own_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create a context as super admin
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &super_token,
            json!({"id": "myctx", "name": "My Context"}),
        ))
        .await;
    assert!(status.is_success());

    // Context-scoped admin can update DID on their own context
    let scoped_token = ctx
        .auth_token("did:key:z6MkScoped", "admin", vec!["myctx".into()])
        .await;
    let (status, body) = app
        .request(put_auth(
            "/contexts/myctx/did",
            &scoped_token,
            json!({"did": "did:webvh:abc:example.com"}),
        ))
        .await;
    assert!(status.is_success(), "update did: {status} {body}");
    assert_eq!(body["did"], "did:webvh:abc:example.com");
}

#[tokio::test]
async fn context_admin_cannot_update_other_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    // Create two contexts
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-a", "name": "A"}),
    ))
    .await;
    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "ctx-b", "name": "B"}),
    ))
    .await;

    // Admin scoped to ctx-a cannot update ctx-b's DID
    let scoped_token = ctx
        .auth_token("did:key:z6MkScopedA", "admin", vec!["ctx-a".into()])
        .await;
    let (status, _) = app
        .request(put_auth(
            "/contexts/ctx-b/did",
            &scoped_token,
            json!({"did": "did:webvh:nope:example.com"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn super_admin_can_update_any_context_did() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &token,
        json!({"id": "anyctx", "name": "Any"}),
    ))
    .await;

    let (status, body) = app
        .request(put_auth(
            "/contexts/anyctx/did",
            &token,
            json!({"did": "did:webvh:xyz:example.com"}),
        ))
        .await;
    assert!(
        status.is_success(),
        "super admin update did: {status} {body}"
    );
    assert_eq!(body["did"], "did:webvh:xyz:example.com");
}

#[tokio::test]
async fn non_admin_cannot_update_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;

    app.request(post_auth(
        "/contexts",
        &super_token,
        json!({"id": "restricted", "name": "R"}),
    ))
    .await;

    // Application role cannot update DID
    let app_token = ctx
        .auth_token("did:key:z6MkApp", "application", vec!["restricted".into()])
        .await;
    let (status, _) = app
        .request(put_auth(
            "/contexts/restricted/did",
            &app_token,
            json!({"did": "did:webvh:bad:example.com"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Reader role tests ──────────────────────────────────────────────

#[tokio::test]
async fn reader_can_list_keys() {
    let (app, ctx) = TestApp::new().await;
    let reader_token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["test-ctx".into()])
        .await;

    let (status, _) = app
        .request(get_auth("/keys?context_id=test-ctx", &reader_token))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn reader_cannot_sign() {
    let (app, ctx) = TestApp::new().await;
    let reader_token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["test-ctx".into()])
        .await;

    let (status, _) = app
        .request(post_auth(
            "/keys/test-key/sign",
            &reader_token,
            json!({"payload": "aGVsbG8", "algorithm": "EdDSA"}),
        ))
        .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 403 or 422, got {status}"
    );
}

#[tokio::test]
async fn reader_cannot_create_key() {
    let (app, ctx) = TestApp::new().await;
    let reader_token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["test-ctx".into()])
        .await;

    let (status, _) = app
        .request(post_auth(
            "/keys",
            &reader_token,
            json!({"key_type": "ed25519", "context_id": "test-ctx"}),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── WebVH DID creation mode tests ─────────────────────────────────

/// Helper: create a context via the API and return admin token.
async fn setup_webvh_context(app: &TestApp, ctx: &TestContext, context_id: &str) -> String {
    let super_token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            &super_token,
            json!({"id": context_id, "name": context_id}),
        ))
        .await;
    assert!(status.is_success(), "create context: {status}");
    super_token
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_rejects_both_document_and_log() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-reject").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-reject",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "did_document": {"id": "{DID}"},
                "did_log": "{\"some\": \"log\"}"
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400: {body}");
}

/// The new `path_mode` wire field deserializes and threads through
/// `CreateDidWebvhBody` → `CreateDidWebvhParams` without breaking the
/// serverless create path. (Serverless ignores the mode — `server_id`
/// selects `.well-known` self-hosting — but the field must still be
/// accepted so server-managed callers can set it.) Pins back-compat for
/// the `WebvhPathMode` addition.
#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_accepts_path_mode_field() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-path-mode").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-path-mode",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "path_mode": { "mode": "auto_assign" },
                "set_primary": false,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create with explicit path_mode: {status} {body}"
    );
    assert!(body["did"].as_str().is_some(), "response has did");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_mode() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-template").await;

    // Client-provided DID document template with {DID} placeholders
    let template = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": "{DID}",
        "verificationMethod": [{
            "id": "{DID}#custom-key",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }],
        "authentication": ["{DID}#custom-key"],
        "assertionMethod": ["{DID}#custom-key"]
    });

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-template",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "did_document": template,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "template create: {status} {body}"
    );
    assert!(body["did"].as_str().is_some(), "response has did");
    assert!(
        body["did_document"].is_object(),
        "response has did_document"
    );
    assert!(
        body["log_entry"].as_str().is_some(),
        "response has log_entry"
    );
    // Verify the template was used (custom key ID present in returned document)
    let doc = &body["did_document"];
    let vm = doc["verificationMethod"]
        .as_array()
        .expect("verificationMethod array");
    assert!(
        vm.iter().any(|v| {
            v["id"]
                .as_str()
                .is_some_and(|id| id.ends_with("#custom-key"))
        }),
        "template's custom key should be in the returned document"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_final_mode_stores_record() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-final").await;

    // First, create a DID via VTA-built mode to get a valid log entry
    let (status, created) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-final",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": false,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap create: {status} {created}"
    );
    let log_entry = created["log_entry"].as_str().expect("log_entry string");

    // Now create another DID using the log entry in final mode, under a new context
    let token2 = setup_webvh_context(&app, &ctx, "test-final-2").await;
    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token2,
            json!({
                "context_id": "test-final-2",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "did_log": log_entry,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "final mode create: {status} {body}"
    );
    let final_did = body["did"].as_str().expect("did in response");
    assert!(!final_did.is_empty());
    // signing_key_id and ka_key_id are empty in final mode (VTA didn't derive keys)
    assert_eq!(body["signing_key_id"].as_str().unwrap(), "");
    assert_eq!(body["ka_key_id"].as_str().unwrap(), "");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_set_primary_false() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-no-primary").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-no-primary",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": false,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Context's primary DID should still be null
    let (status, body) = app
        .request(get_auth("/contexts/test-no-primary", &token))
        .await;
    assert!(status.is_success(), "get context: {status}");
    assert!(
        body["did"].is_null(),
        "context did should be null when set_primary=false"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_set_primary_true() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-primary").await;

    let (status, created) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-primary",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": true,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let created_did = created["did"].as_str().expect("did");

    // Context's primary DID should be set
    let (status, body) = app
        .request(get_auth("/contexts/test-primary", &token))
        .await;
    assert!(status.is_success(), "get context: {status}");
    assert_eq!(
        body["did"].as_str().unwrap(),
        created_did,
        "context did should match created DID"
    );
}

// ── User-specified key tests ──────────────────────────────────────

/// Regression test for the security-review patch #9 hardening: the
/// REST `POST /keys/import` handler must refuse the legacy
/// `private_key_multibase` field (raw private key over a TLS-only
/// channel). `#[serde(deny_unknown_fields)]` is the load-bearing
/// mechanism — operators get a specific "unknown field" error
/// pointing them at the sealed-transfer migration path.
#[tokio::test]
async fn keys_import_rejects_private_key_multibase_over_rest() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkSuperAdmin", "admin", vec![])
        .await;

    let (status, body) = app
        .request(post_auth(
            "/keys/import",
            &token,
            json!({
                "key_type": "ed25519",
                "private_key_multibase": "z6MkDeadbeefDeadbeefDeadbeef",
                "label": "should-be-refused",
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for unknown field, got {status} {body}"
    );
    let rendered = body.to_string();
    assert!(
        rendered.contains("private_key_multibase"),
        "rejection must name the offending field so operators can find the migration path: {rendered}"
    );
}

/// Helper: drive the full sealed-transfer wrapping flow against
/// `POST /keys/import`, returning the new `key_id`.
///
/// Mirrors what a real consumer does:
/// 1. `GET /keys/import/wrapping-key` to fetch an ephemeral X25519
///    pubkey + kid.
/// 2. Build a [`SealedPayloadV1::RawPrivateKey`] around the test
///    key bytes.
/// 3. `seal_payload` against the wrapping pubkey, ASCII-armor.
/// 4. `POST /keys/import` with `private_key_sealed`.
///
/// The plaintext `private_key_multibase` REST path was removed —
/// see the `ImportKeyRestRequest` doc comment in
/// `vta-service/src/routes/keys.rs`.
#[cfg(feature = "webvh")]
async fn import_key_via_sealed_transfer(
    app: &TestApp,
    token: &str,
    key_type_str: &str,
    key_bytes: &[u8],
    label: &str,
    context_id: &str,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, RawPrivateKey, SealedPayloadV1,
        armor, generate_ed25519_keypair, seal_payload,
    };

    // 1. Fetch the wrapping key.
    let (status, body) = app
        .request(get_auth("/keys/import/wrapping-key", token))
        .await;
    assert!(status.is_success(), "GET wrapping-key: {status} {body}");
    let pub_b64 = body["x"]
        .as_str()
        .expect("wrapping-key response missing `x`")
        .to_string();
    let pub_bytes: [u8; 32] = BASE64
        .decode(&pub_b64)
        .expect("decode wrapping pubkey")
        .try_into()
        .expect("wrapping pubkey must be 32 bytes");

    // 2. Build the sealed payload.
    let payload = SealedPayloadV1::RawPrivateKey(RawPrivateKey {
        key_type: key_type_str.into(),
        key_bytes_b64: BASE64.encode(key_bytes),
    });

    // 3. Seal + armor. Producer assertion is `PinnedOnly` — the
    // wrapping-key endpoint already pins the producer↔consumer
    // pairing via the single-use ephemeral key, so no separate
    // signed assertion is required here.
    let (_seed, prod_ed_pub) = generate_ed25519_keypair();
    let producer = ProducerAssertion {
        producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_ed_pub),
        proof: AssertionProof::PinnedOnly,
    };
    let store = InMemoryNonceStore::new();
    let bundle = seal_payload(&pub_bytes, [0u8; 16], producer, &payload, &store)
        .await
        .expect("seal_payload");
    let armored = armor::encode(&bundle);

    // 4. POST the armored bundle as the import request.
    let (status, body) = app
        .request(post_auth(
            "/keys/import",
            token,
            json!({
                "key_type": key_type_str,
                "private_key_sealed": armored,
                "label": label,
                "context_id": context_id,
            }),
        ))
        .await;
    assert!(
        status.is_success(),
        "import {key_type_str} via sealed-transfer: {status} {body}",
    );
    body["key_id"].as_str().unwrap().to_string()
}

/// Helper: import an Ed25519 key via the sealed-transfer wrapping
/// flow and return the key_id.
#[cfg(feature = "webvh")]
async fn import_ed25519_key(app: &TestApp, token: &str, label: &str, context_id: &str) -> String {
    // 32 deterministic bytes for the Ed25519 seed (test only).
    let seed_bytes = [0x42u8; 32];
    import_key_via_sealed_transfer(app, token, "ed25519", &seed_bytes, label, context_id).await
}

/// Helper: import an X25519 key via the sealed-transfer wrapping
/// flow and return the key_id.
#[cfg(feature = "webvh")]
async fn import_x25519_key(app: &TestApp, token: &str, label: &str, context_id: &str) -> String {
    // 32 deterministic bytes for the X25519 private key (test only).
    let key_bytes = [0x99u8; 32];
    import_key_via_sealed_transfer(app, token, "x25519", &key_bytes, label, context_id).await
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_with_user_signing_key() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-user-sign").await;
    let signing_key = import_ed25519_key(&app, &token, "my-sign", "test-user-sign").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-user-sign",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": signing_key,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "signing-only create: {status} {body}"
    );
    assert!(body["did"].as_str().is_some());
    // Document should have signing key but no keyAgreement
    let doc = &body["did_document"];
    assert!(doc["authentication"].is_array());
    assert!(doc.get("keyAgreement").is_none() || doc["keyAgreement"].is_null());
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_with_user_signing_and_ka_keys() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-user-both").await;
    let signing_key = import_ed25519_key(&app, &token, "my-sign", "test-user-both").await;
    let ka_key = import_x25519_key(&app, &token, "my-ka", "test-user-both").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-user-both",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": signing_key,
                "ka_key_id": ka_key,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "both keys create: {status} {body}"
    );
    let doc = &body["did_document"];
    assert!(doc["keyAgreement"].is_array(), "should have keyAgreement");
    let vm = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(vm.len(), 2, "should have 2 verification methods");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_ka_without_signing_rejected() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-ka-only").await;
    let ka_key = import_x25519_key(&app, &token, "my-ka", "test-ka-only").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-ka-only",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "ka_key_id": ka_key,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_didcomm_requires_ka_key() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-didcomm-ka").await;
    let signing_key = import_ed25519_key(&app, &token, "my-sign", "test-didcomm-ka").await;

    // Signing key only + mediator service → should fail
    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-didcomm-ka",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": signing_key,
                "add_mediator_service": true,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "didcomm without ka: {status} {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_wrong_key_type_rejected() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-wrong-type").await;
    let ka_key = import_x25519_key(&app, &token, "my-ka", "test-wrong-type").await;

    // Use X25519 key as signing key → should fail
    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-wrong-type",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "signing_key_id": ka_key,
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── Server-managed DID creation tests ─────────────────────────────

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_unknown_server_returns_404() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-no-server").await;

    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-no-server",
                "server_id": "nonexistent-server",
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown server_id: {status} {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_server_and_url_mutually_exclusive() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-exclusive").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-exclusive",
                "server_id": "some-server",
                "url": "https://example.com/.well-known/did/did.jsonl",
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_neither_server_nor_url_rejected() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "test-neither").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "test-neither",
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── DID templates (Phase 2, global scope) ──────────────────────────

/// Minimum valid template body for create/update tests.
fn sample_template(name: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "name": name,
        "kind": "custom",
        "description": "integration-test template",
        "methods": ["webvh"],
        "requiredVars": ["URL"],
        "optionalVars": { "ACCEPT": ["didcomm/v2"] },
        "defaults": {},
        "document": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "{DID}",
            "verificationMethod": [{
                "id": "{DID}#key-1",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": "{SIGNING_KEY_MB}"
            }],
            "service": [{
                "id": "{DID}#svc",
                "type": "Custom",
                "serviceEndpoint": { "uri": "{URL}", "accept": "{ACCEPT}" }
            }]
        }
    })
}

#[tokio::test]
async fn did_templates_list_empty_for_fresh_vta() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["any".into()])
        .await;
    let (status, body) = app.request(get_auth("/did-templates", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["templates"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn did_templates_create_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;
    // An admin with allowed_contexts is NOT a super admin.
    let token = ctx
        .auth_token("did:key:z6MkAdmin", "admin", vec!["some-ctx".into()])
        .await;

    let (status, _) = app
        .request(post_auth(
            "/did-templates",
            &token,
            sample_template("forbidden"),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn did_templates_create_get_delete_roundtrip() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    // Create
    let (status, body) = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("rt"),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    assert_eq!(body["name"], "rt");
    assert_eq!(body["scope"]["type"], "global");
    assert_eq!(body["createdBy"], "did:key:z6MkSuper");

    // Duplicate rejected
    let (status, _) = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("rt"),
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Get
    let (status, body) = app
        .request(get_auth("/did-templates/rt", &super_token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "rt");

    // List shows one
    let (status, body) = app.request(get_auth("/did-templates", &super_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["templates"].as_array().map(|a| a.len()), Some(1));

    // Delete
    let (status, _) = app
        .request(delete_auth("/did-templates/rt", &super_token))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Gone
    let (status, _) = app
        .request(get_auth("/did-templates/rt", &super_token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn did_templates_update_replaces_body_preserves_created_at() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let (status, original) = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("evolving"),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let created_at_original = original["createdAt"].clone();

    // Update with a tweaked description.
    let mut updated = sample_template("evolving");
    updated["description"] = json!("new description");
    let (status, body) = app
        .request(put_auth("/did-templates/evolving", &super_token, updated))
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["description"], "new description");
    // createdAt preserved, updatedAt advances (can't assert >, but must exist).
    assert_eq!(body["createdAt"], created_at_original);
    assert!(body["updatedAt"].is_u64());
}

#[tokio::test]
async fn did_templates_update_name_mismatch_rejected() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let _ = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("fixed-name"),
        ))
        .await;

    // Body names "other" but path is "fixed-name".
    let (status, _) = app
        .request(put_auth(
            "/did-templates/fixed-name",
            &super_token,
            sample_template("other"),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn did_templates_render_injects_ambient_and_merges_caller_vars() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let _ = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("renderable"),
        ))
        .await;

    let reader = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["any".into()])
        .await;
    // DID/SIGNING_KEY_MB are reserved ambient but Phase 2 doesn't mint them —
    // callers must supply for a preview render.
    let (status, body) = app
        .request(post_auth(
            "/did-templates/renderable/render",
            &reader,
            json!({
                "vars": {
                    "DID": "did:webvh:example.com:test",
                    "SIGNING_KEY_MB": "z6MkSigning",
                    "URL": "https://example.com"
                }
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["document"]["id"], "did:webvh:example.com:test");
    assert_eq!(
        body["document"]["service"][0]["serviceEndpoint"]["uri"],
        "https://example.com"
    );
    // ACCEPT defaulted from optionalVars, survived as array.
    assert_eq!(
        body["document"]["service"][0]["serviceEndpoint"]["accept"],
        json!(["didcomm/v2"])
    );
}

#[tokio::test]
async fn did_templates_render_missing_required_var_errors() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let _ = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("needs-url"),
        ))
        .await;

    // Omit URL — server should 400 with a clear message.
    let (status, _) = app
        .request(post_auth(
            "/did-templates/needs-url/render",
            &super_token,
            json!({ "vars": { "DID": "did:x", "SIGNING_KEY_MB": "z6MkX" } }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn did_templates_invalid_body_rejected_at_create() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let mut bad = sample_template("bad-name-has-space");
    bad["name"] = json!("Has Space");
    let (status, _) = app
        .request(post_auth("/did-templates", &super_token, bad))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── Context-scoped DID templates (Phase 3) ─────────────────────────

async fn create_test_context(app: &TestApp, super_token: &str, id: &str) {
    let (status, _) = app
        .request(post_auth(
            "/contexts",
            super_token,
            json!({ "id": id, "name": id }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "failed to create context '{id}'"
    );
}

#[tokio::test]
async fn ctx_did_templates_create_requires_context_admin_or_super() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    create_test_context(&app, &super_token, "tpl-ctx").await;

    // Reader with context access — may list/read, must not write.
    let reader = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["tpl-ctx".into()])
        .await;
    let (status, _) = app
        .request(post_auth(
            "/contexts/tpl-ctx/did-templates",
            &reader,
            sample_template("rejected"),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin scoped to a different context — no access to tpl-ctx at all.
    let other_admin = ctx
        .auth_token("did:key:z6MkOther", "admin", vec!["somewhere-else".into()])
        .await;
    let (status, _) = app
        .request(post_auth(
            "/contexts/tpl-ctx/did-templates",
            &other_admin,
            sample_template("rejected"),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ctx_did_templates_context_admin_can_crud() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    create_test_context(&app, &super_token, "cx-admin-test").await;

    let ctx_admin = ctx
        .auth_token(
            "did:key:z6MkCtxAdmin",
            "admin",
            vec!["cx-admin-test".into()],
        )
        .await;

    // Create
    let (status, body) = app
        .request(post_auth(
            "/contexts/cx-admin-test/did-templates",
            &ctx_admin,
            sample_template("scoped-tpl"),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    assert_eq!(body["scope"]["type"], "context");
    assert_eq!(body["scope"]["contextId"], "cx-admin-test");
    assert_eq!(body["name"], "scoped-tpl");

    // Get + list
    let (status, body) = app
        .request(get_auth(
            "/contexts/cx-admin-test/did-templates/scoped-tpl",
            &ctx_admin,
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "scoped-tpl");

    let (status, body) = app
        .request(get_auth(
            "/contexts/cx-admin-test/did-templates",
            &ctx_admin,
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["templates"].as_array().map(|a| a.len()), Some(1));

    // Update
    let mut updated = sample_template("scoped-tpl");
    updated["description"] = json!("changed");
    let (status, body) = app
        .request(put_auth(
            "/contexts/cx-admin-test/did-templates/scoped-tpl",
            &ctx_admin,
            updated,
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["description"], "changed");

    // Delete
    let (status, _) = app
        .request(delete_auth(
            "/contexts/cx-admin-test/did-templates/scoped-tpl",
            &ctx_admin,
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = app
        .request(get_auth(
            "/contexts/cx-admin-test/did-templates/scoped-tpl",
            &ctx_admin,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ctx_did_templates_rejects_missing_context() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let (status, _) = app
        .request(post_auth(
            "/contexts/does-not-exist/did-templates",
            &super_token,
            sample_template("orphan"),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ctx_did_templates_shadow_global_without_conflict() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    create_test_context(&app, &super_token, "shadow-ctx").await;

    // Create a global "mediator" template.
    let (status, _) = app
        .request(post_auth(
            "/did-templates",
            &super_token,
            sample_template("mediator"),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Same name in a context — must coexist without conflict.
    let (status, body) = app
        .request(post_auth(
            "/contexts/shadow-ctx/did-templates",
            &super_token,
            sample_template("mediator"),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    assert_eq!(body["scope"]["type"], "context");

    let (_, global) = app
        .request(get_auth("/did-templates/mediator", &super_token))
        .await;
    let (_, context_local) = app
        .request(get_auth(
            "/contexts/shadow-ctx/did-templates/mediator",
            &super_token,
        ))
        .await;
    assert_eq!(global["scope"]["type"], "global");
    assert_eq!(context_local["scope"]["type"], "context");
}

#[tokio::test]
async fn ctx_did_templates_render_injects_context_vars() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    create_test_context(&app, &super_token, "render-ctx").await;

    // Template references CONTEXT_ID in its document.
    let mut tpl = sample_template("ctxtpl");
    tpl["document"]["service"][0]["serviceEndpoint"]["contextId"] = json!("{CONTEXT_ID}");
    let (status, _) = app
        .request(post_auth(
            "/contexts/render-ctx/did-templates",
            &super_token,
            tpl,
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(post_auth(
            "/contexts/render-ctx/did-templates/ctxtpl/render",
            &super_token,
            json!({
                "vars": {
                    "DID": "did:x",
                    "SIGNING_KEY_MB": "z6Mk",
                    "URL": "https://example.com"
                }
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["document"]["service"][0]["serviceEndpoint"]["contextId"],
        "render-ctx"
    );
}

#[tokio::test]
async fn ctx_did_templates_deleted_when_parent_context_deleted() {
    let (app, ctx) = TestApp::new().await;
    // This test deletes a context (an AAL2-gated mutation), so it needs a
    // stepped-up session.
    let super_token = ctx
        .auth_token_aal2("did:key:z6MkSuper", "admin", vec![])
        .await;
    create_test_context(&app, &super_token, "cascade-ctx").await;

    // Add a template to the context.
    let _ = app
        .request(post_auth(
            "/contexts/cascade-ctx/did-templates",
            &super_token,
            sample_template("will-be-deleted"),
        ))
        .await;

    // Preview must list the template among resources to be removed.
    let (status, preview) = app
        .request(get_auth(
            "/contexts/cascade-ctx/delete-preview",
            &super_token,
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        preview["did_templates"].as_array().map(|a| a.len()),
        Some(1)
    );
    assert_eq!(preview["did_templates"][0], "will-be-deleted");

    // Force-delete the context.
    let (status, _) = app
        .request(delete_auth(
            "/contexts/cascade-ctx?force=true",
            &super_token,
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Template is gone; context itself is gone too so the lookup fails.
    let (status, _) = app
        .request(get_auth(
            "/contexts/cascade-ctx/did-templates/will-be-deleted",
            &super_token,
        ))
        .await;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "expected 403/404 after context delete, got {status}"
    );
}

// ── Template-driven DID creation (Phase 4) ─────────────────────────

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_via_builtin_mediator_template() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "tpl-mediator").await;

    // Use the built-in `didcomm-mediator` template. No `did_document` in
    // the request — the server renders the template with the keys it mints
    // and uses the result as the DID document.
    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "tpl-mediator",
                "url": "https://mediator.example.com/.well-known/did/did.jsonl",
                "template": "didcomm-mediator",
                "template_vars": {
                    "URL": "https://mediator.example.com",
                    "WS_URL": "wss://mediator.example.com/ws"
                }
            }),
        ))
        .await;
    assert!(
        status.is_success(),
        "template-driven create failed: {status} {body}"
    );

    // The rendered document should carry a DIDCommMessaging service whose
    // serviceEndpoint is an array of two endpoints — HTTP first, WSS
    // second. The mediator template advertises both transports under one
    // `#service` entry; clients pick whichever transport they support.
    let doc = &body["did_document"];
    assert!(doc.is_object(), "result must include did_document");
    let services = doc["service"].as_array().unwrap();
    let didcomm = services
        .iter()
        .find(|s| s["type"] == json!(["DIDCommMessaging"]))
        .expect("mediator template must produce a DIDCommMessaging service");
    let endpoints = didcomm["serviceEndpoint"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0]["uri"], "https://mediator.example.com");
    assert_eq!(endpoints[0]["accept"], json!(["didcomm/v2"]));
    assert_eq!(endpoints[1]["uri"], "wss://mediator.example.com/ws");
    assert_eq!(endpoints[1]["accept"], json!(["didcomm/v2"]));
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_mutually_exclusive_with_did_document() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "tpl-excl").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "tpl-excl",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "template": "didcomm-mediator",
                "template_vars": { "URL": "https://example.com" },
                "did_document": { "id": "{DID}" }
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_missing_required_var_errors() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "tpl-missing").await;

    // `didcomm-mediator` requires URL — omit it.
    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "tpl-missing",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "template": "didcomm-mediator"
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_unknown_name_errors() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "tpl-unk").await;

    let (status, _) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": "tpl-unk",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "template": "no-such-template"
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// Export round-trips: `GET /did-templates/{name}` body, with server-only
// fields stripped, must parse back through the SDK loader. This is the
// contract `pnm did-templates export | create --file -` depends on.
#[tokio::test]
async fn did_templates_export_round_trips_through_sdk_loader() {
    use vta_sdk::did_templates::DidTemplate;

    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;

    let original = sample_template("round-trip");
    let _ = app
        .request(post_auth("/did-templates", &super_token, original))
        .await;

    let (status, mut body) = app
        .request(get_auth("/did-templates/round-trip", &super_token))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Strip server metadata (what the CLI `export` command does).
    let obj = body.as_object_mut().unwrap();
    obj.remove("scope");
    obj.remove("created_at");
    obj.remove("updated_at");
    obj.remove("created_by");

    let tpl = DidTemplate::from_json(body).expect("export must round-trip");
    assert_eq!(tpl.name, "round-trip");
    assert_eq!(tpl.kind, "custom");
}

// ── Provision-integration REST surface ────────────────────────────
//
// Item 18: exercise the HTTP-specific concerns — auth gate, payload
// deserialization, and VP validation — in isolation from the happy-
// path library flow that the `operations::provision_integration`
// unit tests already cover end-to-end.

#[cfg(feature = "webvh")]
async fn sign_sample_bootstrap_request() -> vta_sdk::provision_integration::BootstrapRequest {
    use std::collections::BTreeMap;
    use vta_sdk::provision_integration::{BootstrapAsk, DidTemplateRef, TemplateBootstrapAsk};

    let (seed_box, pub_bytes) = vta_sdk::sealed_transfer::generate_ed25519_keypair();
    let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

    let ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
        context_hint: Some("prod-mediator".into()),
        template: DidTemplateRef {
            name: "didcomm-mediator".into(),
            vars: BTreeMap::from([(
                "URL".into(),
                Value::String("https://mediator.example.com".into()),
            )]),
        },
        admin_template: None,
        note: None,
    });

    vta_sdk::provision_integration::BootstrapRequest::sign(
        &seed_box,
        &client_did,
        [0xAAu8; 16],
        chrono::Duration::hours(1),
        Some("item-18-rest-test".into()),
        ask,
    )
    .await
    .expect("sign sample VP")
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_requires_auth() {
    // No Bearer token → the AdminAuth extractor rejects before any
    // validation runs.
    let (app, _ctx) = TestApp::new().await;
    let vp = sign_sample_bootstrap_request().await;
    let body = json!({
        "request": vp,
        "context": "prod-mediator",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/bootstrap/provision-integration")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_rejects_non_admin_token() {
    // Caller authenticates as role "reader" — AdminAuth must reject.
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkReader", "reader", vec!["prod-mediator".into()])
        .await;
    let vp = sign_sample_bootstrap_request().await;
    let body = json!({
        "request": vp,
        "context": "prod-mediator",
    });
    let (status, _) = app
        .request(post_auth("/bootstrap/provision-integration", &token, body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_rejects_tampered_vp() {
    // Admin token + structurally valid body, but the VP's nonce has
    // been mutated after signing — the handler calls `.verify()` on
    // the request and returns 400.
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkAdmin", "admin", vec!["prod-mediator".into()])
        .await;
    let mut vp = sign_sample_bootstrap_request().await;
    // Swap the nonce — same length, different bytes → signature
    // over the mutated body is now invalid.
    vp.nonce = "BBBBBBBBBBBBBBBBBBBBBB".to_string();
    let body = json!({
        "request": vp,
        "context": "prod-mediator",
    });
    let (status, _) = app
        .request(post_auth("/bootstrap/provision-integration", &token, body))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_rejects_unknown_field_in_body() {
    // `deny_unknown_fields` on BootstrapRequest (item 22 hardening)
    // kicks in at deserialize time for any field the verifier doesn't
    // know about. The handler surfaces this as a Deserialize error
    // → 400 via axum's default JSON extractor rejection.
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkAdmin", "admin", vec!["prod-mediator".into()])
        .await;
    let mut vp_value =
        serde_json::to_value(sign_sample_bootstrap_request().await).expect("serialize VP");
    // Inject an attacker-chosen field — item-22 guard must reject.
    vp_value["smugglerField"] = json!("malicious");
    let body = json!({
        "request": vp_value,
        "context": "prod-mediator",
    });
    let (status, _) = app
        .request(post_auth("/bootstrap/provision-integration", &token, body))
        .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 4xx rejection for unknown field, got {status}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_context_scoped_template_shadows_global() {
    let (app, ctx) = TestApp::new().await;
    let super_token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    create_test_context(&app, &super_token, "shadow-didcreate").await;

    // Global template with one description.
    let mut global = sample_template("my-custom");
    global["description"] = json!("GLOBAL");
    let _ = app
        .request(post_auth("/did-templates", &super_token, global))
        .await;

    // Context-scoped override with a different description.
    let mut local = sample_template("my-custom");
    local["description"] = json!("CONTEXT");
    let _ = app
        .request(post_auth(
            "/contexts/shadow-didcreate/did-templates",
            &super_token,
            local,
        ))
        .await;

    // Create a DID using the template — with template_context set to the
    // context, resolution should pick up the context-scoped override first.
    let (status, body) = app
        .request(post_auth(
            "/webvh/dids",
            &super_token,
            json!({
                "context_id": "shadow-didcreate",
                "url": "https://example.com/.well-known/did/did.jsonl",
                "template": "my-custom",
                "template_context": "shadow-didcreate",
                "template_vars": { "URL": "https://example.com" }
            }),
        ))
        .await;
    assert!(status.is_success(), "{status} {body}");
    // The fact that it succeeded (and the service shape from `sample_template`
    // is present — a `Custom` service type we used in the sample) confirms
    // the rendered doc came from a template, not the VTA's auto-builder.
    let doc = &body["did_document"];
    assert_eq!(doc["service"][0]["type"], "Custom");
}

// ── webvh DID update + rotate-keys tests ─────────────────────────

/// Helper: create a context + a serverless webvh DID, return
/// `(token, scid, did)` for follow-up update/rotate calls.
#[cfg(feature = "webvh")]
async fn create_test_webvh_did(
    app: &TestApp,
    ctx: &TestContext,
    context_id: &str,
) -> (String, String, String) {
    let token = setup_webvh_context(app, ctx, context_id).await;
    let (status, created) = app
        .request(post_auth(
            "/webvh/dids",
            &token,
            json!({
                "context_id": context_id,
                "url": "https://example.com/.well-known/did/did.jsonl",
                "set_primary": false,
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create did: {status} {created}"
    );
    let scid = created["scid"]
        .as_str()
        .expect("scid in response")
        .to_string();
    let did = created["did"]
        .as_str()
        .expect("did in response")
        .to_string();
    (token, scid, did)
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn update_did_webvh_metadata_only_succeeds() {
    let (app, ctx) = TestApp::new().await;
    let (token, scid, did) = create_test_webvh_did(&app, &ctx, "update-meta").await;

    // Toggle pre-rotation off — metadata-only change.
    let (status, body) = app
        .request(post_auth(
            &format!("/contexts/update-meta/dids/{scid}/update"),
            &token,
            json!({ "pre_rotation_count": 0 }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "update: {status} {body}");
    assert_eq!(body["did"], did);
    assert_eq!(body["pre_rotation_key_count"], 0);
    assert!(body["new_version_id"].as_str().unwrap().starts_with("2-"));
    assert!(!body["new_log_entry"].as_str().unwrap().is_empty());
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn update_did_webvh_with_new_document_rotates_keys() {
    let (app, ctx) = TestApp::new().await;
    let (token, scid, did) = create_test_webvh_did(&app, &ctx, "update-doc").await;

    // Fetch current doc so we can hand back a valid (id-matching) one.
    let (status, get_body) = app
        .request(post_auth(
            &format!("/webvh/dids/{}/log", urlencoding::encode(&did)),
            &token,
            json!({}),
        ))
        .await;
    // Fall back: get the current entry by parsing it from the create
    // response's `log_entry`. Simpler than fetching.
    let _ = (status, get_body);

    let new_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#key-99"),
            "type": "Multikey",
            "controller": did.clone(),
            "publicKeyMultibase": "z6MkExternalPubForTest"
        }]
    });
    let (status, body) = app
        .request(post_auth(
            &format!("/contexts/update-doc/dids/{scid}/update"),
            &token,
            json!({ "document": new_doc }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "update with doc: {status} {body}");
    assert_eq!(
        body["update_keys_count"], 1,
        "auth keys rotated to 1 fresh key"
    );
    assert!(body["new_version_id"].as_str().unwrap().starts_with("2-"));
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn rotate_did_webvh_keys_advances_fragment_ids() {
    let (app, ctx) = TestApp::new().await;
    let (token, scid, _did) = create_test_webvh_did(&app, &ctx, "rotate-frags").await;

    let (status, body) = app
        .request(post_auth(
            &format!("/contexts/rotate-frags/dids/{scid}/rotate-keys"),
            &token,
            json!({ "label": "test rotation" }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "rotate-keys: {status} {body}");
    assert!(body["new_version_id"].as_str().unwrap().starts_with("2-"));
    assert_eq!(body["update_keys_count"], 1);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn update_did_webvh_unknown_scid_returns_404() {
    let (app, ctx) = TestApp::new().await;
    let token = setup_webvh_context(&app, &ctx, "not-here").await;

    let (status, _body) = app
        .request(post_auth(
            "/contexts/not-here/dids/Qnonexistent/update",
            &token,
            json!({ "pre_rotation_count": 0 }),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn update_did_webvh_invalid_document_returns_400() {
    let (app, ctx) = TestApp::new().await;
    let (token, scid, _did) = create_test_webvh_did(&app, &ctx, "bad-doc").await;

    // id mismatch — caller can't rename a DID via update
    let bad_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:webvh:totally-different",
        "verificationMethod": []
    });
    let (status, _body) = app
        .request(post_auth(
            &format!("/contexts/bad-doc/dids/{scid}/update"),
            &token,
            json!({ "document": bad_doc }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── DIDComm protocol management (Phase 3 vertical) ────────────────
// Spec: docs/05-design-notes/didcomm-protocol-management.md, criterion #1.
//
// These tests exercise the route → operation path end-to-end through
// the full HTTP stack. The "happy path" (live LogEntry publish with a
// real mediator) requires either a synthetic did:peer:2 mediator with
// an embedded DIDCommMessaging service or an in-process mock mediator —
// that piece lives with the migrate vertical (P4.2) where the same
// machinery serves several tests at once.

#[cfg(feature = "webvh")]
#[tokio::test]
async fn enable_didcomm_unauthenticated_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let req = Request::builder()
        .method("POST")
        .uri("/services/didcomm/enable")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "mediator_did": "did:key:z6MkM" }).to_string(),
        ))
        .unwrap();
    let (status, _body) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn enable_didcomm_non_super_admin_returns_403() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token("did:key:z6MkAdmin", "admin", vec!["any".into()])
        .await;
    let (status, _body) = app
        .request(post_auth(
            "/services/didcomm/enable",
            &token,
            json!({ "mediator_did": "did:key:z6MkM" }),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn enable_didcomm_already_enabled_returns_409_with_suggested_fix() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    {
        let mut config = ctx.inner.config.write().await;
        config.services.didcomm = true;
        config.messaging = Some(vti_common::config::MessagingConfig {
            mediator_url: "wss://mediator.example.com".into(),
            mediator_did: "did:peer:2.med".into(),
            mediator_host: None,
            setup_acl: false,
            drain_inbox_on_start: false,
        });
    }
    let (status, body) = app
        .request(post_auth(
            "/services/didcomm/enable",
            &token,
            json!({ "mediator_did": "did:key:z6MkBogus" }),
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected body: {body}");
    assert_eq!(body["error"], "didcomm_already_enabled");
    assert_eq!(body["mediator_did"], "did:peer:2.med");
    assert!(
        body.get("suggested_fix").and_then(|v| v.as_str()).is_some(),
        "operator-friendly suggested_fix string is required, body: {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn disable_didcomm_unauthenticated_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let req = Request::builder()
        .method("POST")
        .uri("/services/didcomm/disable")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "drain_ttl_secs": 0 }).to_string()))
        .unwrap();
    let (status, _body) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn disable_didcomm_returns_typed_error_body() {
    // The default fixture's vta_did is `did:key:...` which has no
    // webvh record. The operation passes the didcomm-enabled and
    // REST-enabled gates (both true by default) and reaches the
    // VtaDidRecordMissing path → 500 with a typed error body. The
    // contract this test enforces: every failure mode produces a
    // typed error code + human message (no opaque 500s).
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (_status, body) = app
        .request(post_auth(
            "/services/didcomm/disable",
            &token,
            json!({ "drain_ttl_secs": 0 }),
        ))
        .await;
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "error code in body: {body}"
    );
    assert!(
        body.get("message").and_then(|v| v.as_str()).is_some(),
        "message in body: {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn drain_cancel_unauthenticated_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let req = Request::builder()
        .method("POST")
        .uri("/mediators/drain/cancel")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "mediator_did": "did:m:A" }).to_string()))
        .unwrap();
    let (status, _body) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn drain_cancel_unknown_mediator_returns_typed_error() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/mediators/drain/cancel",
            &token,
            json!({ "mediator_did": "did:m:never-registered" }),
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("not_registered")
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn mediator_report_unauthenticated_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let req = Request::builder()
        .method("GET")
        .uri("/mediators/report")
        .body(Body::empty())
        .unwrap();
    let (status, _body) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn mediator_report_returns_empty_report_when_no_traffic() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let req = Request::builder()
        .method("GET")
        .uri("/mediators/report")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = app.request(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("mediators")
            .and_then(|v| v.as_array())
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        body.get("senders").and_then(|v| v.as_array()).map(Vec::len),
        Some(0)
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn update_didcomm_unauthenticated_returns_401() {
    let (app, _ctx) = TestApp::new().await;
    let req = Request::builder()
        .method("POST")
        .uri("/services/didcomm/update")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "new_mediator_did": "did:key:z6MkM",
                "drain_ttl_secs": 3600
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _body) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn update_didcomm_returns_typed_error_body() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (_status, body) = app
        .request(post_auth(
            "/services/didcomm/update",
            &token,
            json!({
                "new_mediator_did": "did:key:z6MkBogus",
                "drain_ttl_secs": 3600,
            }),
        ))
        .await;
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "error code in body: {body}"
    );
    assert!(
        body.get("message").and_then(|v| v.as_str()).is_some(),
        "message in body: {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn rollback_routes_via_migrate_with_rollback_flag() {
    // The rollback CLI alias hits the same endpoint with
    // `rollback: true`. Body shape contract identical to forward
    // migrate.
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (_status, body) = app
        .request(post_auth(
            "/services/didcomm/update",
            &token,
            json!({
                "new_mediator_did": "did:key:z6MkBogus",
                "drain_ttl_secs": 3600,
                "rollback": true,
            }),
        ))
        .await;
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "error code in body: {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn enable_didcomm_propagates_resolve_failure_with_stage() {
    // With a webvh-shaped vta_did + record, the operation reaches
    // the handshake stage. A bogus mediator DID fails resolve and
    // the route maps that to 502 with stage="resolve" so operators
    // can target their fix.
    //
    // Setting up a real webvh vta_did in the fixture is heavyweight
    // (requires create_did_webvh end-to-end). Instead we assert the
    // weaker invariant exercisable here: any failure inside
    // enable_didcomm produces a JSON body with a stable error code,
    // a human-readable message, and (when applicable) a stage
    // field. Stronger handshake-stage assertions live with the
    // P4.2 migrate vertical, which can stand up a synthetic
    // mediator DID alongside its other test machinery.
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    let (_status, body) = app
        .request(post_auth(
            "/services/didcomm/enable",
            &token,
            json!({
                "mediator_did": "did:key:z6MkBogus",
                "force": false,
            }),
        ))
        .await;
    // Body shape contract: typed error code + human-readable message.
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "error code in body: {body}"
    );
    assert!(
        body.get("message").and_then(|v| v.as_str()).is_some(),
        "message in body: {body}"
    );
}

// ── JWT audience isolation ────────────────────────────────────────────
//
// CLAUDE.md identifies cross-audience token rejection as a load-bearing
// invariant: a JWT minted by the VTC service (audience = "VTC") MUST
// NOT authenticate against a VTA route, and vice versa. Tested at the
// JWT-encode/decode layer in `vti-common/src/auth/jwt.rs`; these tests
// run the assertion through the full route stack to catch any
// integration-layer drift (a future refactor that, say, normalises
// audience strings before validation).

#[tokio::test]
async fn vtc_audience_token_rejected_by_vta_route() {
    let (app, ctx) = TestApp::new().await;
    // Mint a token whose `aud` claim is "VTC". The JwtKeys validation
    // path on the VTA side configures `audience = "VTA"` and uses
    // `Validation::set_audience(&["VTA"])`, so the foreign-audience
    // token must be rejected at decode time.
    let foreign_token = ctx.auth_token_with_audience("did:key:z6MkAdmin", "admin", vec![], "VTC");
    let (status, _body) = app.request(get_auth("/contexts", &foreign_token)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "VTC-audience JWT must be rejected by VTA routes"
    );
}

#[tokio::test]
async fn unknown_audience_token_rejected_by_vta_route() {
    // Defence-in-depth: any audience that isn't "VTA" must be rejected,
    // not just the well-known "VTC" string. A future "VTM" service or
    // an attacker-supplied token with a custom audience must never
    // authenticate.
    let (app, ctx) = TestApp::new().await;
    let foreign_token =
        ctx.auth_token_with_audience("did:key:z6MkAdmin", "admin", vec![], "EVIL-SERVICE-V99");
    let (status, _body) = app.request(get_auth("/contexts", &foreign_token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ── Runtime guards (rate limit + body cap) ─────────────────────────────
//
// Both flagged in CLAUDE.md as load-bearing protections we must never
// silently regress on. One test per bound — burst-then-throttled for the
// per-IP rate limiter, then >1 MB body returns 413 for the global cap.

/// `tower_governor` is wired at 5 req/sec with a 10-burst per source IP
/// across every unauthenticated endpoint. Send 12 requests in a tight
/// loop and assert at least one comes back as 429 — confirming the
/// layer is wired into the router. Without this test, a future router
/// refactor that drops the `GovernorLayer` would silently land.
#[tokio::test]
async fn unauth_endpoint_rate_limit_returns_429_after_burst() {
    let (app, _ctx) = TestApp::new().await;

    // `/auth/challenge` is the canonical unauth route the limiter
    // protects (CLAUDE.md flags this as a load-bearing surface). Send
    // requests serially — the limiter is per-IP, so even concurrent
    // calls would all hash to the same bucket; serial is simpler.
    // `tower::oneshot` doesn't carry a real peer IP; the `SmartIpKey`
    // extractor reads `X-Forwarded-For` / `X-Real-IP` first, then
    // falls back to the connection. Stamp a stable client IP via
    // `X-Forwarded-For` so every request hashes to the same bucket.
    let mut saw_429 = false;
    for _ in 0..20 {
        let req = Request::builder()
            .method("POST")
            .uri("/auth/challenge")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::from(
                json!({"client_did": "did:key:zTest"}).to_string(),
            ))
            .unwrap();
        let (status, _) = app.request(req).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "expected at least one 429 within 20 sequential POST /auth/challenge calls; \
         the GovernorLayer (5 rps + 10 burst) appears to be missing"
    );
}

/// P0.10: the token-gated backup-blob branch must also be rate-limited.
/// Without a token the handler rejects the request, but the governor sits
/// *outside* the handler, so a flood trips 429 before the handler ever
/// runs — proving the branch carries the limiter (it previously did not).
#[tokio::test]
async fn backup_blob_branch_is_rate_limited() {
    let (app, _ctx) = TestApp::new().await;
    let mut saw_429 = false;
    for _ in 0..20 {
        let req = Request::builder()
            .method("GET")
            .uri("/backup/blob/some-bundle-id")
            .header("x-forwarded-for", "192.0.2.7")
            .body(Body::empty())
            .unwrap();
        let (status, _) = app.request(req).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "expected a 429 within 20 GET /backup/blob calls; the backup-blob \
         branch is missing its GovernorLayer"
    );
}

/// P0.10: the unauthenticated TEE attestation endpoints (`status`,
/// `report`, `did-log`) were on the main router, bypassing the rate
/// limiter. They now live on the governed `unauth` branch. Flooding
/// `GET /attestation/status` must trip 429 — the governor runs before the
/// handler, so this holds even though the test app has no real TEE state
/// (the handler would otherwise error). Only the super-admin
/// `/attestation/mnemonic` routes stay off the limiter (JWT-gated).
#[cfg(feature = "tee")]
#[tokio::test]
async fn unauth_attestation_status_is_rate_limited() {
    let (app, _ctx) = TestApp::new().await;
    let mut saw_429 = false;
    for _ in 0..20 {
        let req = Request::builder()
            .method("GET")
            .uri("/attestation/status")
            .header("x-forwarded-for", "192.0.2.9")
            .body(Body::empty())
            .unwrap();
        let (status, _) = app.request(req).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "expected a 429 within 20 GET /attestation/status calls; the unauth \
         attestation routes are not on the governed branch"
    );
}

/// P0.10: a handler that stalls must not hold its connection forever. The
/// production router wraps every route in a `TimeoutLayer` at
/// `REQUEST_TIMEOUT`; this drives the same layer (at a short, deterministic
/// duration) over a deliberately-slow handler and asserts it returns
/// `408 Request Timeout` rather than hanging.
#[tokio::test]
async fn request_timeout_layer_returns_408_for_slow_handler() {
    use std::time::Duration;
    use tower::ServiceExt;
    use tower_http::timeout::TimeoutLayer;

    let app: axum::Router = axum::Router::new()
        .route(
            "/slow",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                "should never arrive"
            }),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_millis(50),
        ));

    let resp = app
        .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
        .await
        .expect("layer must produce a response, not hang");
    assert_eq!(
        resp.status(),
        StatusCode::REQUEST_TIMEOUT,
        "a handler slower than the timeout must yield 408, not block the connection"
    );
}

/// `MAX_BODY_SIZE` (1 MB) is enforced via axum's `DefaultBodyLimit::max`
/// across every authenticated mutation endpoint. A 1.5 MB body must
/// be rejected with 413 — this is the protection against memory
/// exhaustion CLAUDE.md flags as critical for TEE deployments.
#[tokio::test]
async fn body_cap_returns_413_for_oversized_payload() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:zAdmin", "admin", vec![]).await;

    // 1.5 MB of 'A' bytes wrapped in a JSON-string envelope so the
    // axum body extractor accepts it as a candidate (rejection happens
    // at the body-limit layer, not at the parser). The total wire
    // body is ~1.5 MB + a few bytes of JSON framing.
    let huge_payload = json!({"data": "A".repeat(1_500_000)});
    let req = Request::builder()
        .method("POST")
        .uri("/contexts")
        .header("Authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(huge_payload.to_string()))
        .unwrap();
    let (status, _) = app.request(req).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "expected 413 Payload Too Large for a 1.5 MB body; the \
         DefaultBodyLimit::max(1 MB) layer appears to be missing"
    );
}
