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
use vta_service::test_support::{TestAppContext, build_provisionable_test_app, build_test_app};

// ── Test harness — thin wrapper over the workspace's `test_support`
// `build_test_app` helper. The substantial AppState wiring (every
// keyspace, the JWT keys, the DID resolver, the registry, the drain
// sweeper, etc.) was duplicated here pre-consolidation; it now lives
// in `vta_service::test_support` so any future integration test gets
// it for free with two lines of setup.

struct TestApp {
    router: axum::Router,
    /// The VTA's DID — the `recipient` a hand-built Trust Task document names.
    vta_did: String,
}

impl TestApp {
    async fn new() -> (Self, TestContext) {
        let (router, ctx) = build_test_app().await;
        let vta_did = ctx.vta_did.clone();
        (Self { router, vta_did }, TestContext { inner: ctx })
    }

    /// Like [`TestApp::new`] but with a real, self-resolving VTA signing
    /// identity (`{vta_did}#key-0` provisioned). Needed by tests that drive a
    /// path which **mints a VTA-signed document** — e.g. the step-up gate,
    /// whose approve-request now carries the spec-REQUIRED proof — since the
    /// cheap sentinel-DID app has no issuer key to sign with.
    async fn new_signing() -> (Self, TestContext) {
        let (router, ctx) = build_provisionable_test_app().await;
        let vta_did = ctx.vta_did.clone();
        (Self { router, vta_did }, TestContext { inner: ctx })
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

    /// Demand a stepped-up (AAL2) session for **every** task, by installing the
    /// rule an operator would. Enforcement ships off, so a test asserting the
    /// gate fires opts in here.
    ///
    /// This replaces the `[auth.step_up]` `*` floor. The floors were a second,
    /// parallel answer to "does this need another human decision?", resolved
    /// out of band from the rules — which is how an operator came to see a
    /// step-up demand that `pnm approvals list` could not explain. There is now
    /// one trigger, and this is how you pull it.
    async fn enable_step_up_all(&self) {
        self.install_rule(
            "stepup-all",
            "package vta.policy\nimport rego.v1\n\
             decision := {\"decision\": \"requireStepUp\"} if input.consumer.acr != \"aal2\"\n\
             decision := {\"decision\": \"allow\"} if input.consumer.acr == \"aal2\"",
        )
        .await;
    }

    /// Install one Rego module and turn enforcement on. The keyspace and the
    /// config Arc are shared with the live router, so this takes effect for
    /// subsequent requests.
    ///
    /// The module must decide **every** input it will see, not only the one the
    /// test cares about: an abstaining policy default-denies, which fails a
    /// "this route is NOT gated" assertion for the wrong reason.
    async fn install_rule(&self, id: &str, rego: &str) {
        self.inner.config.write().await.policy.enforcement = true;
        vta_service::policy::storage::store_policy(
            &self.inner.policy_ks,
            &vta_service::policy::types::PolicyModule {
                id: id.into(),
                name: id.into(),
                description: None,
                module: rego.into(),
                applies_to: vec![],
                priority: 0,
                enabled: true,
                version: 1,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                ext: Value::Null,
            },
        )
        .await
        .expect("store the policy module");
    }
}

impl TestContext {
    /// Store the ACL row a token stands for, when there is none.
    ///
    /// A real token is only minted for a DID with an entry, and an ACL write
    /// is bounded by the writer's own entry (VTI-ACL-053), so a token with no
    /// row behind it describes a caller that cannot exist. A row a test seeded
    /// itself is left as it is.
    async fn ensure_token_entry(&self, did: &str, role: &str, contexts: &[String]) {
        let Ok(role) = Role::parse(role) else {
            return;
        };
        if vti_common::acl::get_acl_entry(self.acl_ks(), did)
            .await
            .expect("read acl")
            .is_none()
        {
            self.create_acl(did, role, contexts.to_vec()).await;
        }
    }

    /// Create an authenticated session and return a Bearer token.
    async fn auth_token(&self, did: &str, role: &str, contexts: Vec<String>) -> String {
        self.ensure_token_entry(did, role, &contexts).await;
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

/// A POST carrying no bearer token, for asserting that a surface is gated.
fn post_unauth(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
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

// ── Capabilities ──────────────────────────────────────────────────

/// The Trust-Task surface is authenticated.
///
/// This was `capabilities_requires_auth`, pointed at the retired task (#1043).
/// The property is the spine's, not that task's, so it is asserted through the
/// discovery task that replaced it rather than deleted with its subject.
/// A hand-built Trust Task document that a conforming VTA will accept.
///
/// The spine enforces SPEC §7.2, so a document needs an in-band `recipient`
/// (item 5b — every dispatched spec declares it REQUIRED) and, for 72 of the
/// 109, a `proof` from the same identity the token authenticates (items 6, 7a).
/// Tests that hand-roll an envelope have to carry both or they are refused
/// before they reach the behaviour they mean to check.
fn signed_doc(
    ctx: &TestContext,
    id: &str,
    type_uri: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    let (did, _vm) = vta_service::test_support::test_admin_did();
    let mut doc: trust_tasks_rs::TrustTask<serde_json::Value> = serde_json::from_value(json!({
        "id": id,
        "type": type_uri,
        "issuer": did,
        "recipient": ctx.inner.vta_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as_test_admin(&mut doc);
    serde_json::to_value(&doc).expect("envelope serialises")
}

/// `trust-task-discovery/0.1` answers from the dispatch table.
///
/// The property worth pinning is not that it returns *something* but that it
/// returns the tasks this service actually routes — a discovery response
/// assembled from a hand-maintained list would pass a laxer assertion while
/// advertising tasks that 404 on a live call.
#[tokio::test]
async fn trust_task_discovery_reports_dispatched_tasks() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token(
            &vta_service::test_support::test_admin_did().0,
            "reader",
            vec!["any".into()],
        )
        .await;
    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            signed_doc(
                &ctx,
                "urn:uuid:4c3d5e6f-7081-4293-a4b5-c6d7e8f90123",
                "https://trusttasks.org/spec/trust-task-discovery/0.1",
                json!({ "patterns": ["acl/*"] }),
            ),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let types = body["payload"]["supportedTypes"]
        .as_array()
        .unwrap_or_else(|| panic!("supportedTypes must be an array: {body}"));
    assert!(!types.is_empty(), "acl/* must match something: {body}");
    assert!(
        types
            .iter()
            .all(|t| t.as_str().is_some_and(|s| s.contains("/spec/acl/"))),
        "the pattern must narrow the answer, got: {types:?}"
    );
    // MAJOR.MINOR of the framework release this VTA targets — 0.1's schema
    // admits no PATCH.
    assert_eq!(
        body["payload"]["frameworkVersion"],
        vti_common::trust_task::discovery::FRAMEWORK_VERSION_MAJOR_MINOR
    );
}

/// `trust-task-discovery/0.3` is answered in 0.3, and its acceptance window is
/// the one this VTA enforces (VTI-TRN-047), measured end to end: a document
/// issued past the advertised window, sent to the same service, is refused as
/// `expired`, and one inside it is not.
///
/// An advertisement wider than the enforced window — the case VTI-TRN-047
/// forbids — would have a producer deliver documents this service then
/// refuses; this is where the two meet on the wire.
#[tokio::test]
async fn vti_trn_047_discovery_0_3_advertises_the_window_the_vta_enforces() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token(
            &vta_service::test_support::test_admin_did().0,
            "reader",
            vec!["any".into()],
        )
        .await;
    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            signed_doc(
                &ctx,
                "urn:uuid:6e5f7081-92a3-44b5-86d7-e8f901234567",
                "https://trusttasks.org/spec/trust-task-discovery/0.3",
                json!({ "patterns": ["trust-task-discovery/*"] }),
            ),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["type"], "https://trusttasks.org/spec/trust-task-discovery/0.3#response",
        "a 0.3 query is answered in 0.3: {body}"
    );
    let payload = &body["payload"];
    assert_eq!(
        payload["frameworkVersion"],
        vti_common::trust_task::discovery::FRAMEWORK_VERSION
    );
    let types = payload["supportedTypes"].as_array().expect("an array");
    for version in ["0.1", "0.3"] {
        let uri = format!("https://trusttasks.org/spec/trust-task-discovery/{version}");
        assert!(types.iter().any(|t| *t == uri), "{uri} listed: {types:?}");
    }
    let max_age = payload["acceptanceWindow"]["maxAgeSeconds"]
        .as_i64()
        .unwrap_or_else(|| panic!("a response-level window: {body}"));
    let skew = payload["acceptanceWindow"]["clockSkewSeconds"]
        .as_i64()
        .unwrap_or_else(|| panic!("a response-level window: {body}"));

    // Signed with an `issuedAt` of the caller's choosing.
    let issued_ago = |secs: i64, id: &str| {
        let (did, _vm) = vta_service::test_support::test_admin_did();
        let issued = chrono::Utc::now() - chrono::TimeDelta::seconds(secs);
        let mut doc: trust_tasks_rs::TrustTask<serde_json::Value> = serde_json::from_value(json!({
            "id": id,
            "type": "https://trusttasks.org/spec/trust-task-discovery/0.3",
            "issuer": did,
            "recipient": ctx.inner.vta_did,
            "issuedAt": issued.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .expect("envelope deserialises");
        vta_service::test_support::sign_as_test_admin(&mut doc);
        serde_json::to_value(&doc).expect("envelope serialises")
    };

    // Past the advertised window, skew included: refused.
    let (_, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            issued_ago(
                max_age + skew + 2,
                "urn:uuid:7f608192-a3b4-45c6-97e8-f90123456789",
            ),
        ))
        .await;
    assert_eq!(body["payload"]["code"], "expired", "{body}");

    // Past `maxAgeSeconds` but inside the skew: still accepted, which is why a
    // producer SHOULD NOT (rather than MUST NOT) send it there.
    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            issued_ago(
                max_age + skew - 5,
                "urn:uuid:80719203-b4c5-46d7-a8f9-012345678901",
            ),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "inside the advertised window: {body}"
    );
}

/// An empty pattern list means "everything", and everything is a lot.
///
/// Separate from the narrowed case because the two exercise opposite branches:
/// this one would also pass if pattern matching were broken open, so it is the
/// narrowed test above that carries the real weight.
#[tokio::test]
async fn trust_task_discovery_defaults_to_everything() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx
        .auth_token(
            &vta_service::test_support::test_admin_did().0,
            "reader",
            vec!["any".into()],
        )
        .await;
    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            signed_doc(
                &ctx,
                "urn:uuid:5d4e6f70-8192-43a4-b5c6-d7e8f9012345",
                "https://trusttasks.org/spec/trust-task-discovery/0.1",
                json!({}),
            ),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let types = body["payload"]["supportedTypes"].as_array().unwrap();
    assert!(
        types.len() > 50,
        "an unfiltered query must report the whole table, got {}",
        types.len()
    );
    assert!(
        types
            .iter()
            .any(|t| t == "https://trusttasks.org/spec/trust-task-discovery/0.1"),
        "discovery must advertise itself"
    );
}

// ── Health ─────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok_without_auth() {
    let (app, _ctx) = TestApp::new().await;
    let (status, body) = app.request(get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

/// `GET /health/details` is gone: the report is two Trust Tasks now.
#[tokio::test]
async fn the_health_details_route_is_gone() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkTest", "admin", vec![]).await;
    let (status, _) = app.request(get_auth("/health/details", &token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Post an anonymous (no credential, unsigned) Trust Task to `/trust-tasks`.
async fn post_anonymous(app: &TestApp, type_uri: &str, xff: &str) -> (StatusCode, Value) {
    let doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "recipient": app.vta_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json")
        .header("x-forwarded-for", xff)
        .body(Body::from(doc.to_string()))
        .unwrap();
    app.request(req).await
}

/// `vta/health/details/0.1` over HTTPS: public, so an anonymous caller is
/// answered — with the fixed flags only, never the version.
#[tokio::test]
async fn health_details_task_answers_an_anonymous_https_caller() {
    let (app, _ctx) = TestApp::new().await;
    let (status, body) = post_anonymous(
        &app,
        vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1,
        "192.0.2.21",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["status"], "ok", "{body}");
    // TSP is off by default — health surfaces the advertised-transport state.
    assert_eq!(body["payload"]["tspEnabled"], false, "{body}");
    assert!(body["payload"].get("version").is_none(), "{body}");
    assert!(body["payload"].get("restored").is_none(), "{body}");
}

#[tokio::test]
async fn health_details_task_reports_tsp_enabled_when_configured() {
    let (app, ctx) = TestApp::new().await;
    ctx.inner.config.write().await.services.tsp = true;
    let (status, body) = post_anonymous(
        &app,
        vta_sdk::trust_tasks::TASK_VTA_HEALTH_DETAILS_0_1,
        "192.0.2.22",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["tspEnabled"], true, "{body}");
}

/// `vta/restore/status/0.1` over HTTPS: an administrator's signed request is
/// answered with the version; an anonymous one is refused before dispatch,
/// because the task is not public.
#[tokio::test]
async fn restore_status_task_answers_an_administrator_over_https() {
    let (app, ctx) = TestApp::new().await;
    let admin = vta_service::test_support::test_admin_did().0;
    ctx.create_acl(&admin, Role::Admin, vec![]).await;
    let token = ctx.auth_token(&admin, "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            signed_doc(
                &ctx,
                &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                vta_sdk::trust_tasks::TASK_VTA_RESTORE_STATUS_0_1,
                json!({}),
            ),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["payload"]["version"].is_string(), "{body}");
    assert_eq!(body["payload"]["restored"], false, "{body}");

    let (status, _) = post_anonymous(
        &app,
        vta_sdk::trust_tasks::TASK_VTA_RESTORE_STATUS_0_1,
        "192.0.2.23",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ── Auth: missing/invalid token ────────────────────────────────────

#[tokio::test]
async fn swap_key_is_gated_by_the_rules() {
    // Signing app: the gate mints a signed approve-request (spec: proof REQUIRED).
    let (app, ctx) = TestApp::new_signing().await;
    ctx.enable_step_up_all().await;
    let admin = vta_service::test_support::test_admin_did().0;
    let token = ctx.auth_token(&admin, "admin", vec![]).await;

    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            signed_doc(
                &ctx,
                &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                vta_sdk::trust_tasks::TASK_ACL_SWAP_KEY_0_1,
                json!({
                    "currentSubject": admin,
                    "newSubject": "did:key:z6MkNewSubject",
                    "linkProof": "not-a-real-vp",
                }),
            ),
        ))
        .await;

    assert!(
        !status.is_success(),
        "swap-key must be gated: {status} {body}"
    );
    // Gated *before* the handler, so the bogus link proof is never reached —
    // the refusal is about the missing elevation, not about the VP.
    let rendered = body.to_string();
    assert!(
        !rendered.contains("not-a-real-vp") && !rendered.contains("presentation"),
        "the refusal must come from the gate, not the handler: {rendered}"
    );
    assert!(
        rendered.contains("step") || rendered.contains("Step"),
        "the refusal must be the step-up gate: {rendered}"
    );
}

// The two delegated-step-up tests that lived here are gone with the floors.
// `[auth.step_up]` was the only thing that could route an approve-request to
// someone other than the subject; a rule's `requireStepUp` is self-approve by
// construction. Someone-else-approves is the consent flow's job now
// (`requireConsent` + an approver set), which is a strictly stronger mechanism:
// it carries a threshold, an approver-still-authorized re-check at consume
// time, and a signed statement of the effects the human is agreeing to.
// `AclEntry.stepUp.approver` survives as a wire field — the two tests below
// cover its round-trip — but nothing reads it to route a step-up any more.

// ── Context CRUD ───────────────────────────────────────────────────

// ── Key management ─────────────────────────────────────────────────

// ── Restart requires super admin ───────────────────────────────────

// ── Backup is Trust Tasks only ─────────────────────────────────────

/// The inline `/backup/{export,import}` routes are gone, not refused: a backup
/// moves only as the `vta/backup/*` Trust Tasks over an end-to-end transport
/// (VTI-VTA-003), so REST has no handler to answer with.
#[tokio::test]
async fn the_inline_backup_routes_are_gone() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkSuper", "admin", vec![]).await;
    for path in ["/backup/export", "/backup/import"] {
        let (status, body) = app
            .request(post_auth(
                path,
                &token,
                json!({"password": "test-password-12!!"}),
            ))
            .await;
        // 405 where the GET-only public did-log catch-all matches the path:
        // either way, nothing answers a POST.
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "{path}: {status} {body}"
        );
    }
}

// ── WebVH DID creation mode tests ─────────────────────────────────

/// Helper: create a context via `contexts/create/1.0` on `/trust-tasks` and
/// return the admin token. `contexts/create/1.0` is `IS_PROOF_REQUIRED`, so
/// the token and the document's signer must name the same DID
/// (`test_admin_did`) — mixing an ad-hoc bearer identity with this proof
/// would be refused on the issuer/transport-identity mismatch (SPEC §7.2
/// item 6), not on anything this helper means to check.
async fn setup_webvh_context(app: &TestApp, ctx: &TestContext, context_id: &str) -> String {
    let super_token = ctx
        .auth_token(
            &vta_service::test_support::test_admin_did().0,
            "admin",
            vec![],
        )
        .await;
    let (status, _) = app
        .request(post_auth(
            "/trust-tasks",
            &super_token,
            signed_doc(
                ctx,
                &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
                json!({"id": context_id, "name": context_id}),
            ),
        ))
        .await;
    assert!(status.is_success(), "create context: {status}");
    super_token
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

/// Send `provision/integration/0.3` over REST as the test admin, whose bearer
/// carries `role` in `contexts`. The `/bootstrap/provision-integration` route is
/// gone; `/trust-tasks` is the same dispatcher TSP and DIDComm reach.
#[cfg(feature = "webvh")]
async fn provision_task(
    app: &TestApp,
    ctx: &TestContext,
    role: &str,
    contexts: Vec<String>,
    payload: Value,
) -> (StatusCode, Value) {
    let token = ctx
        .auth_token(
            &vta_service::test_support::test_admin_did().0,
            role,
            contexts,
        )
        .await;
    app.request(post_auth(
        "/trust-tasks",
        &token,
        signed_doc(
            ctx,
            &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_0_3,
            payload,
        ),
    ))
    .await
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_requires_auth() {
    // No bearer token: refused before any validation runs.
    let (app, ctx) = TestApp::new().await;
    let vp = sign_sample_bootstrap_request().await;
    let doc = signed_doc(
        &ctx,
        &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        vta_sdk::trust_tasks::TASK_PROVISION_INTEGRATION_0_3,
        json!({ "request": vp, "context": "prod-mediator" }),
    );
    let (status, _) = app.request(post_unauth("/trust-tasks", doc)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_rejects_non_admin_token() {
    // The relayer authenticates as a reader: not an admin in the context.
    let (app, ctx) = TestApp::new().await;
    let vp = sign_sample_bootstrap_request().await;
    let (status, body) = provision_task(
        &app,
        &ctx,
        "reader",
        vec!["prod-mediator".into()],
        json!({ "request": vp, "context": "prod-mediator" }),
    )
    .await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(body["payload"]["code"], "permissionDenied", "{body}");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_rejects_tampered_vp() {
    // The VP's nonce is mutated after signing, so its proof no longer covers
    // the bytes: the holder layer refuses it however the relayer is authorised.
    let (app, ctx) = TestApp::new().await;
    let mut vp = sign_sample_bootstrap_request().await;
    vp.nonce = "BBBBBBBBBBBBBBBBBBBBBB".to_string();
    let (status, body) = provision_task(
        &app,
        &ctx,
        "admin",
        vec!["prod-mediator".into()],
        json!({ "request": vp, "context": "prod-mediator" }),
    )
    .await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(body["payload"]["code"], "malformedRequest", "{body}");
}

/// Sign a `provision/integration/0.1`-shape VP: `ask.type` PascalCase
/// (`TemplateBootstrap`), signed over that exact wire form.
///
/// Built as raw JSON rather than through `BootstrapRequest::sign`,
/// because vta-sdk ≥ 0.21.11 emits the 0.2 camelCase tag — the whole
/// point here is to reproduce a holder that predates that flip, which
/// shipped integrations still are.
#[cfg(feature = "webvh")]
async fn sign_pascalcase_bootstrap_request() -> Value {
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use vta_sdk::provision_integration::{BOOTSTRAP_CONTEXT_URL, VC_V2_CONTEXT_URL};

    let (seed_box, pub_bytes) = vta_sdk::sealed_transfer::generate_ed25519_keypair();
    let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
    let mb = client_did
        .strip_prefix("did:key:")
        .expect("did:key prefix")
        .to_string();
    let vm_id = format!("{client_did}#{mb}");
    let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(&seed_box));
    signer.id = vm_id;

    let now = chrono::Utc::now();
    let mut doc = json!({
        "@context": [VC_V2_CONTEXT_URL, BOOTSTRAP_CONTEXT_URL],
        "type": ["VerifiablePresentation", "BootstrapRequest"],
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "holder": client_did,
        "nonce": B64URL.encode([0xA1u8; 16]),
        "validUntil": (now + chrono::Duration::hours(1)).to_rfc3339(),
        "label": "v0.1-pascalcase-rest-test",
        "ask": {
            "type": "TemplateBootstrap",
            "contextHint": "prod-mediator",
            "template": {
                "name": "didcomm-mediator",
                "vars": { "URL": "https://mediator.example.com" }
            }
        }
    });

    let proof = DataIntegrityProof::sign(
        &doc,
        &signer,
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_created(now),
    )
    .await
    .expect("sign PascalCase VP");
    doc.as_object_mut()
        .unwrap()
        .insert("proof".into(), serde_json::to_value(&proof).unwrap());
    doc
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_accepts_a_v0_1_pascalcase_holder() {
    // A holder on vta-sdk < 0.21.11 signs `ask.type` as PascalCase. The handler
    // must verify the proof against the bytes as received; re-serialising the
    // typed struct would re-emit the 0.2 `templateBootstrap` tag and reject the
    // holder's own valid signature as a forgery.
    //
    // Asserted as the absence of a *proof* failure rather than success:
    // provisioning proper needs template + context state this fixture app does
    // not stand up, so it legitimately fails further in.
    let (app, ctx) = TestApp::new().await;
    let (_status, body) = provision_task(
        &app,
        &ctx,
        "admin",
        vec!["prod-mediator".into()],
        json!({
            "request": sign_pascalcase_bootstrap_request().await,
            "context": "prod-mediator",
        }),
    )
    .await;
    let err = body.to_string();
    assert!(
        !err.contains("signature invalid") && !err.contains("verify BootstrapRequest"),
        "0.1-cased holder must clear proof verification, got {err}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn provision_integration_rejects_unknown_field_in_body() {
    // `deny_unknown_fields` on BootstrapRequest (item 22 hardening): a member
    // the verifier does not know is refused, not ignored.
    let (app, ctx) = TestApp::new().await;
    let mut vp_value =
        serde_json::to_value(sign_sample_bootstrap_request().await).expect("serialize VP");
    vp_value["smugglerField"] = json!("malicious");
    let (status, body) = provision_task(
        &app,
        &ctx,
        "admin",
        vec!["prod-mediator".into()],
        json!({ "request": vp_value, "context": "prod-mediator" }),
    )
    .await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(body["payload"]["code"], "malformedRequest", "{body}");
}

/// The REST route is gone: `provision/integration` is a Trust Task only.
#[cfg(feature = "webvh")]
#[tokio::test]
async fn the_provision_integration_rest_route_is_gone() {
    let (app, ctx) = TestApp::new().await;
    let token = ctx.auth_token("did:key:z6MkAdmin", "admin", vec![]).await;
    let (status, body) = app
        .request(post_auth(
            "/bootstrap/provision-integration",
            &token,
            json!({}),
        ))
        .await;
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
        "{status} {body}"
    );
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
    // `POST /webvh/dids` is gone — `webvh/dids/create/1.0` on `/trust-tasks` is
    // the only way in now, on every transport.
    let (status, body) = app
        .request(post_auth(
            "/trust-tasks",
            &token,
            signed_doc(
                ctx,
                &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
                json!({
                    "contextId": context_id,
                    "url": "https://example.com/.well-known/did/did.jsonl",
                    "setPrimary": false,
                }),
            ),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "create did: {status} {body}");
    let created = &body["payload"];
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

/// Send a `webvh/dids/*` Trust Task over REST, signed by the test admin (who
/// holds the bearer too, since the spine binds the document to its sender).
/// The REST routes these tests once drove are gone; `/trust-tasks` is the
/// same dispatcher TSP and DIDComm reach.
#[cfg(feature = "webvh")]
async fn webvh_task(
    app: &TestApp,
    ctx: &TestContext,
    type_uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let token = ctx
        .auth_token(
            &vta_service::test_support::test_admin_did().0,
            "admin",
            vec![],
        )
        .await;
    app.request(post_auth(
        "/trust-tasks",
        &token,
        signed_doc(
            ctx,
            &format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            type_uri,
            payload,
        ),
    ))
    .await
}

#[cfg(feature = "webvh")]
const TASK_UPDATE: &str = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";
#[cfg(feature = "webvh")]
const TASK_ROTATE: &str = "https://trusttasks.org/spec/vta/webvh/dids/rotate-keys/1.0";

#[cfg(feature = "webvh")]
#[tokio::test]
async fn webvh_dids_update_metadata_only_succeeds() {
    let (app, ctx) = TestApp::new().await;
    let (_token, _scid, did) = create_test_webvh_did(&app, &ctx, "update-meta").await;

    // Toggle pre-rotation off — metadata-only change.
    let (status, body) = webvh_task(
        &app,
        &ctx,
        TASK_UPDATE,
        json!({ "did": did, "preRotationCount": 0 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update: {status} {body}");
    let body = &body["payload"];
    assert_eq!(body["did"], did);
    assert_eq!(body["preRotationKeyCount"], 0);
    assert!(body["newVersionId"].as_str().unwrap().starts_with("2-"));
    assert!(!body["newLogEntry"].as_str().unwrap().is_empty());
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn webvh_dids_update_with_new_document_rotates_keys() {
    let (app, ctx) = TestApp::new().await;
    let (_token, _scid, did) = create_test_webvh_did(&app, &ctx, "update-doc").await;

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
    let (status, body) = webvh_task(
        &app,
        &ctx,
        TASK_UPDATE,
        json!({ "did": did, "document": new_doc }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update with doc: {status} {body}");
    let body = &body["payload"];
    assert_eq!(
        body["updateKeysCount"], 1,
        "auth keys rotated to 1 fresh key"
    );
    assert!(body["newVersionId"].as_str().unwrap().starts_with("2-"));
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn webvh_dids_rotate_keys_advances_fragment_ids() {
    let (app, ctx) = TestApp::new().await;
    let (_token, _scid, did) = create_test_webvh_did(&app, &ctx, "rotate-frags").await;

    let (status, body) = webvh_task(
        &app,
        &ctx,
        TASK_ROTATE,
        json!({ "did": did, "label": "test rotation" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate-keys: {status} {body}");
    let body = &body["payload"];
    assert!(body["newVersionId"].as_str().unwrap().starts_with("2-"));
    assert_eq!(body["updateKeysCount"], 1);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn webvh_dids_update_unknown_did_is_refused() {
    let (app, ctx) = TestApp::new().await;
    let _ = setup_webvh_context(&app, &ctx, "not-here").await;

    let (status, body) = webvh_task(
        &app,
        &ctx,
        TASK_UPDATE,
        json!({ "did": "did:webvh:Qnonexistent:example.com", "preRotationCount": 0 }),
    )
    .await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(body["payload"]["code"], "taskFailed", "{body}");
    assert_eq!(body["payload"]["details"]["reason"], "not_found", "{body}");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn webvh_dids_update_invalid_document_is_refused() {
    let (app, ctx) = TestApp::new().await;
    let (_token, _scid, did) = create_test_webvh_did(&app, &ctx, "bad-doc").await;

    // id mismatch — caller can't rename a DID via update
    let bad_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:webvh:totally-different",
        "verificationMethod": []
    });
    let (status, body) = webvh_task(
        &app,
        &ctx,
        TASK_UPDATE,
        json!({ "did": did, "document": bad_doc }),
    )
    .await;
    assert!(!status.is_success(), "{status} {body}");
    assert!(
        body.to_string().contains("malformedRequest"),
        "{status} {body}"
    );
}

/// The `(context, scid)` routes and the realign route are gone: their Trust
/// Tasks above are the only way in, on every transport.
#[cfg(feature = "webvh")]
// ── DIDComm protocol management (Phase 3 vertical) ────────────────
// Spec: docs/05-design-notes/didcomm-protocol-management.md, criterion #1.
//
// These tests exercise the route → operation path end-to-end through
// the full HTTP stack. The "happy path" (live LogEntry publish with a
// real mediator) requires either a synthetic did:peer:2 mediator with
// an embedded DIDCommMessaging service or an in-process mock mediator —
// that piece lives with the migrate vertical (P4.2) where the same
// machinery serves several tests at once.

// ── JWT audience isolation ────────────────────────────────────────────
//
// CLAUDE.md identifies cross-audience token rejection as a load-bearing
// invariant: a JWT minted by the VTC service (audience = "VTC") MUST
// NOT authenticate against a VTA route, and vice versa. Tested at the
// JWT-encode/decode layer in `vti-common/src/auth/jwt.rs`; these tests
// run the assertion through the full route stack to catch any
// integration-layer drift (a future refactor that, say, normalises
// audience strings before validation).

// ── Runtime guards (rate limit + body cap) ─────────────────────────────
//
// Both flagged in CLAUDE.md as load-bearing protections we must never
// silently regress on. One test per bound — burst-then-throttled for the
// per-IP rate limiter, then >1 MB body returns 413 for the global cap.

/// The auth limiter is wired at one token every 5 s with a 10-burst per
/// source IP across the unauthenticated auth endpoints. Send requests in a
/// tight loop and assert one comes back as 429 carrying the VTA's 429
/// contract — confirming the layer is wired into the router. Without this
/// test, a future router refactor that drops the limiter would silently land.
#[tokio::test]
async fn unauth_endpoint_rate_limit_returns_429_after_burst() {
    let (app, _ctx) = TestApp::new().await;

    // An anonymous `auth/challenge` document at `/trust-tasks` is the unauth path the limiter
    // protects (CLAUDE.md flags this as a load-bearing surface). Send
    // requests serially — the limiter is per-IP, so even concurrent
    // calls would all hash to the same bucket; serial is simpler.
    // `tower::oneshot` doesn't carry a real peer IP; the `SmartIpKey`
    // extractor reads `X-Forwarded-For` / `X-Real-IP` first, then
    // falls back to the connection. Stamp a stable client IP via
    // `X-Forwarded-For` so every request hashes to the same bucket.
    let mut rejection = None;
    for _ in 0..20 {
        let resp = app
            .router
            .clone()
            .oneshot(auth_challenge_request("192.0.2.1"))
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rejection = Some(resp);
            break;
        }
    }
    let resp = rejection.expect(
        "expected at least one 429 within 20 sequential anonymous auth/challenge documents at /trust-tasks; \
         the auth rate limiter (10 burst) appears to be missing",
    );
    assert_eq!(resp.headers()[vta_sdk::rate_limit::SOURCE_HEADER], "vta");
    assert_eq!(resp.headers()["x-rate-limit-scope"], "auth");
    assert!(resp.headers().contains_key("retry-after"));
}

fn auth_challenge_request(ip: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(Body::from(
            // An anonymous `auth/challenge` document: the pre-session sign-in
            // step, which the anonymous `/trust-tasks` limiter meters.
            json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_0_1,
                "issuer": "did:key:zTest",
                "issuedAt": "2026-09-30T00:00:00Z",
                "payload": { "subject": "did:key:zTest" }
            })
            .to_string(),
        ))
        .unwrap()
}

#[cfg(feature = "webvh")]
fn did_log_request(uri: &str, ip: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-forwarded-for", ip)
        .body(Body::empty())
        .unwrap()
}

/// The public DID-log routes sit on their own limiter. Resolving a
/// self-hosted VTA DID used to spend the auth budget — a `pnm` command's DID
/// fetch plus challenge + authenticate is 3 of 10 tokens — so a few commands
/// in a row were refused. A did.jsonl flood from one IP must leave that IP's
/// auth budget intact, and trip only the `did-log` limiter.
#[cfg(feature = "webvh")]
#[tokio::test]
async fn did_log_flood_does_not_spend_auth_budget() {
    let (app, _ctx) = TestApp::new().await;
    let ip = "192.0.2.21";
    // Both the fixed well-known route and the canonical catch-all share the
    // did-log bucket.
    let mut rejection = None;
    for i in 0..100 {
        let uri = if i % 2 == 0 {
            "/.well-known/did.jsonl"
        } else {
            "/tenant/vta/did.jsonl"
        };
        let resp = app
            .router
            .clone()
            .oneshot(did_log_request(uri, ip))
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            assert!(
                i >= 60,
                "did-log limiter tripped after {i}, below its 60 burst"
            );
            rejection = Some(resp);
            break;
        }
    }
    let resp = rejection.expect("100 did.jsonl GETs must trip the did-log limiter");
    assert_eq!(resp.headers()[vta_sdk::rate_limit::SOURCE_HEADER], "vta");
    assert_eq!(resp.headers()["x-rate-limit-scope"], "did-log");

    // The same IP's auth bucket is untouched: the full burst still passes.
    for _ in 0..10 {
        let (status, _) = app.request(auth_challenge_request(ip)).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a did.jsonl flood must not spend the auth budget"
        );
    }
}

/// And the converse: exhausting the auth limiter must not stop the same IP
/// from resolving the VTA's DID.
#[cfg(feature = "webvh")]
#[tokio::test]
async fn auth_flood_does_not_spend_did_log_budget() {
    let (app, _ctx) = TestApp::new().await;
    let ip = "192.0.2.22";
    let mut tripped = false;
    for _ in 0..20 {
        let (status, _) = app.request(auth_challenge_request(ip)).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "20 challenges must trip the auth limiter");
    for _ in 0..20 {
        let (status, _) = app
            .request(did_log_request("/.well-known/did.jsonl", ip))
            .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "an auth flood must not spend the did-log budget"
        );
    }
}

/// The rate-limit quotas are runtime config: a super-admin `PATCH /config`
/// changes what the running router enforces on the very next request, with no
/// rebuild or restart — tightening and loosening alike.
#[cfg(feature = "webvh")]

/// P0.10: the token-gated backup-blob branch must also be rate-limited.
/// Without a token the handler rejects the request, but the governor sits
/// *outside* the handler, so a flood trips 429 before the handler ever
/// runs — proving the branch carries the limiter (it previously did not).
#[tokio::test]
async fn backup_blob_branch_is_rate_limited() {
    let (app, _ctx) = TestApp::new().await;
    let mut rejection = None;
    for _ in 0..20 {
        let req = Request::builder()
            .method("GET")
            .uri("/backup/blob/some-bundle-id")
            .header("x-forwarded-for", "192.0.2.7")
            .body(Body::empty())
            .unwrap();
        let resp = app.router.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rejection = Some(resp);
            break;
        }
    }
    let resp = rejection.expect(
        "expected a 429 within 20 GET /backup/blob calls; the backup-blob \
         branch is missing its rate limiter",
    );
    assert_eq!(resp.headers()[vta_sdk::rate_limit::SOURCE_HEADER], "vta");
    assert_eq!(resp.headers()["x-rate-limit-scope"], "backup-blob");
}

/// A public Trust Task (`vta_sdk::trust_tasks::PUBLIC_URIS` — the attestation
/// reads) may be sent to `/trust-tasks` with no credential, and every such
/// anonymous request is charged to the unauthenticated limiter. They were
/// REST routes on the governed `unauth` branch (P0.10); on `/trust-tasks`, which
/// also serves JWT callers who must stay off the limiter, the limiter charges
/// only requests that present no credential. The limiter runs before the
/// handler, so this holds in a build with no TEE at all.
#[tokio::test]
async fn anonymous_public_trust_tasks_are_rate_limited() {
    let (app, _ctx) = TestApp::new().await;
    let doc = serde_json::json!({
        "id": "urn:uuid:00000000-0000-4000-8000-00000000a771",
        "type": vta_sdk::trust_tasks::TASK_ATTESTATION_STATUS_0_1,
        "payload": {},
    });
    let mut saw_429 = false;
    for _ in 0..20 {
        let req = Request::builder()
            .method("POST")
            .uri("/trust-tasks")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "192.0.2.9")
            .body(Body::from(doc.to_string()))
            .unwrap();
        let (status, _) = app.request(req).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "expected a 429 within 20 anonymous /trust-tasks calls; anonymous public \
         tasks are not on the unauthenticated limiter"
    );
}

/// Anonymity is for public tasks only. Any other task sent with no credential
/// is refused before it is dispatched — 401, and nothing runs.
#[tokio::test]
async fn an_anonymous_non_public_trust_task_is_refused() {
    let (app, _ctx) = TestApp::new().await;
    let doc = serde_json::json!({
        "id": "urn:uuid:00000000-0000-4000-8000-00000000a772",
        "type": vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0,
        "payload": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "192.0.2.10")
        .body(Body::from(doc.to_string()))
        .unwrap();
    let (status, body) = app.request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body:?}");
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

/// Every REST-exception row (`deprecation::rest_exceptions_table`) names a route
/// the service serves, with that method, and is not stamped deprecated.
///
/// Same reasoning as `every_superseded_row_names_a_live_route`: a row that
/// outlives its route keeps claiming an exception for nothing, and one naming
/// the wrong path or method leaves the real route undeclared.
#[tokio::test]
async fn every_rest_exception_names_a_live_route() {
    use axum::extract::MatchedPath;
    use axum::http::HeaderValue;

    async fn echo_matched_path(
        req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let matched = req
            .extensions()
            .get::<MatchedPath>()
            .map(|m| m.as_str().to_owned());
        let mut resp = next.run(req).await;
        if let Some(m) = matched
            && let Ok(v) = HeaderValue::from_str(&m)
        {
            resp.headers_mut().insert("x-probe-matched-path", v);
        }
        resp
    }

    let (app, _ctx) = TestApp::new().await;
    let probe = app
        .router
        .clone()
        .layer(axum::middleware::from_fn(echo_matched_path));

    for row in vta_service::deprecation::rest_exceptions_table() {
        let uri: String = row
            .path
            .split('/')
            .map(|seg| if seg.starts_with('{') { "probe" } else { seg })
            .collect::<Vec<_>>()
            .join("/");

        let req = Request::builder()
            .method(row.method)
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = probe.clone().oneshot(req).await.expect("request failed");

        let matched = resp
            .headers()
            .get("x-probe-matched-path")
            .map(|v| v.to_str().unwrap().to_owned());
        assert_eq!(
            matched.as_deref(),
            Some(row.path),
            "the REST-exception row `{} {}` does not match a live route — it matched \
             {matched:?}. Drop the row if the route was removed; correct it if it is a typo.",
            row.method,
            row.path
        );
        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "the REST-exception row `{} {}` names a path the service serves but not \
             that method.",
            row.method,
            row.path
        );
        assert!(
            resp.headers().get("deprecation").is_none(),
            "the REST exception `{} {}` is stamped deprecated",
            row.method,
            row.path
        );
    }
}
