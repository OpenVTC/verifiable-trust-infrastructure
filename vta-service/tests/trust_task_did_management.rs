//! Integration coverage for the DID-templates slice (global + context scope)
//! and `did:webvh` DID creation, ported from the REST `api_integration.rs`
//! suite onto the signed Trust Task dispatcher (`POST /trust-tasks`) after
//! #1858 retired the REST routes these behaviours used to be exercised
//! through.
//!
//! See `trust_task_admin.rs` for the harness rationale (every caller is a
//! real, derivable `did:key` so it can sign the document it issues — SPEC
//! §7.2 item 6 binds a document's in-band `issuer` to the
//! transport-authenticated caller whenever `issuer` is present, regardless of
//! whether the task requires a proof) and for the REST-status → Trust-Task
//! `code` mapping this file also relies on.

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
use vta_service::test_support::{TestAppContext, build_test_app, did_for_seed, sign_as};

// ── Test harness — identical to trust_task_admin.rs's; kept file-local
// rather than shared, matching this workspace's existing convention of each
// integration-test binary carrying its own compact harness (see
// `whoami_trust_task.rs`, `sessions_list_trust_task.rs`, etc.).

struct TestApp {
    router: axum::Router,
}

struct Caller {
    seed: u8,
    #[allow(dead_code)]
    did: String,
    token: String,
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

    async fn task(
        &self,
        ctx: &TestContext,
        caller: &Caller,
        type_uri: &str,
        payload: Value,
    ) -> (StatusCode, Value) {
        let doc = signed_doc(ctx, caller.seed, &uuid_urn(), type_uri, payload);
        let (status, body) = self
            .request(post_auth("/trust-tasks", &caller.token, doc))
            .await;
        (status, body["payload"].clone())
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

    fn acl_ks(&self) -> &KeyspaceHandle {
        &self.inner.acl_ks
    }

    async fn login(&self, seed: u8, role: &str, contexts: Vec<String>) -> Caller {
        let did = did_for_seed(seed).0;
        self.ensure_token_entry(&did, role, &contexts).await;
        let session_id = format!("sess-{}", uuid::Uuid::new_v4());
        let session = Session {
            session_id: session_id.clone(),
            did: did.clone(),
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
            did.clone(),
            session_id,
            role.to_string(),
            contexts,
            900,
            false,
        );
        let token = self.jwt_keys().encode(&claims).expect("encode jwt");
        Caller { seed, did, token }
    }

    async fn ensure_token_entry(&self, did: &str, role: &str, contexts: &[String]) {
        let Ok(role) = Role::parse(role) else {
            return;
        };
        if vti_common::acl::get_acl_entry(self.acl_ks(), did)
            .await
            .expect("read acl")
            .is_none()
        {
            let entry =
                vti_common::acl::AclEntry::new(did, role, "test").with_contexts(contexts.to_vec());
            self.acl_ks()
                .insert(format!("acl:{did}"), &entry)
                .await
                .expect("insert acl");
        }
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn uuid_urn() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
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

fn signed_doc(ctx: &TestContext, seed: u8, id: &str, type_uri: &str, payload: Value) -> Value {
    let did = did_for_seed(seed).0;
    let mut doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": id,
        "type": type_uri,
        "issuer": did,
        "recipient": ctx.inner.vta_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    }))
    .expect("envelope deserialises");
    sign_as(seed, &mut doc);
    serde_json::to_value(&doc).expect("envelope serialises")
}

const SEED_SUPER: u8 = 0x20;
const SEED_SCOPED: u8 = 0x21;
const SEED_READER: u8 = 0x22;
const SEED_CTX_ADMIN: u8 = 0x23;
const SEED_OTHER_ADMIN: u8 = 0x24;

async fn setup_context(app: &TestApp, ctx: &TestContext, id: &str) -> Caller {
    let admin = ctx.login(SEED_SUPER, "admin", vec![]).await;
    let (status, body) = app
        .task(
            ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": id, "name": id}),
        )
        .await;
    assert!(status.is_success(), "create context {id}: {body}");
    admin
}

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

/// `did-templates/create/2.0` payload: the template document nests under
/// `template`, with an optional sibling `contextId` selecting scope.
fn create_req(context_id: Option<&str>, template: Value) -> Value {
    let mut body = json!({"template": template});
    if let Some(c) = context_id {
        body["contextId"] = json!(c);
    }
    body
}

/// `did-templates/update/2.0` payload: `name` (the resource id) and the
/// replacement `template`, both siblings of an optional scope `contextId`.
fn update_req(context_id: Option<&str>, name: &str, template: Value) -> Value {
    let mut body = json!({"name": name, "template": template});
    if let Some(c) = context_id {
        body["contextId"] = json!(c);
    }
    body
}

// ── DID templates (global scope) ────────────────────────────────────

#[tokio::test]
async fn did_templates_list_empty_for_fresh_vta() {
    let (app, ctx) = TestApp::new().await;
    let reader = ctx.login(SEED_READER, "reader", vec!["any".into()]).await;
    let (status, body) = app
        .task(
            &ctx,
            &reader,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_LIST_2_0,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["templates"].as_array().map(|a| a.len()),
        Some(0),
        "{body}"
    );
}

#[tokio::test]
async fn did_templates_create_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;
    // An admin with allowed_contexts is NOT a super admin.
    let scoped = ctx
        .login(SEED_SCOPED, "admin", vec!["some-ctx".into()])
        .await;

    let (status, body) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, sample_template("forbidden")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn did_templates_create_get_list_delete_roundtrip() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, sample_template("rt")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["name"], "rt");
    assert_eq!(body["scope"]["type"], "global");
    assert_eq!(body["createdBy"], did_for_seed(SEED_SUPER).0);

    // Duplicate rejected.
    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, sample_template("rt")),
        )
        .await;
    assert!(!status.is_success(), "{body}");
    assert_eq!(body["code"], "taskFailed", "{body}");
    assert_eq!(body["details"]["reason"], "conflict", "{body}");

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "rt"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "rt");

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_LIST_2_0,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["templates"].as_array().map(|a| a.len()), Some(1));

    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0,
            json!({"name": "rt"}),
        )
        .await;
    assert!(status.is_success());

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "rt"}),
        )
        .await;
    assert!(!status.is_success(), "{body}");
    assert_eq!(body["details"]["reason"], "not_found", "{body}");
}

#[tokio::test]
async fn did_templates_update_replaces_body() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, sample_template("evolving")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let mut updated = sample_template("evolving");
    updated["description"] = json!("new description");
    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0,
            update_req(None, "evolving", updated),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["description"], "new description");
}

#[tokio::test]
async fn did_templates_render_injects_ambient_and_merges_caller_vars() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    app.task(
        &ctx,
        &super_admin,
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
        create_req(None, sample_template("renderable")),
    )
    .await;

    let reader = ctx.login(SEED_READER, "reader", vec!["any".into()]).await;
    // DID/SIGNING_KEY_MB are reserved ambient but Phase 2 doesn't mint them —
    // callers must supply for a preview render.
    let (status, body) = app
        .task(
            &ctx,
            &reader,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0,
            json!({
                "name": "renderable",
                "vars": {
                    "DID": "did:webvh:example.com:test",
                    "SIGNING_KEY_MB": "z6MkSigning",
                    "URL": "https://example.com"
                }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["document"]["id"], "did:webvh:example.com:test");
    assert_eq!(
        body["document"]["service"][0]["serviceEndpoint"]["uri"],
        "https://example.com"
    );
    assert_eq!(
        body["document"]["service"][0]["serviceEndpoint"]["accept"],
        json!(["didcomm/v2"])
    );
}

#[tokio::test]
async fn did_templates_render_missing_required_var_errors() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    app.task(
        &ctx,
        &super_admin,
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
        create_req(None, sample_template("needs-url")),
    )
    .await;

    // Omit URL — server should refuse with a clear message.
    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0,
            json!({"name": "needs-url", "vars": {"DID": "did:x", "SIGNING_KEY_MB": "z6MkX"}}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "malformedRequest", "{body}");
}

#[tokio::test]
async fn did_templates_invalid_body_rejected_at_create() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    let mut bad = sample_template("bad-name-has-space");
    bad["name"] = json!("Has Space");
    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, bad),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "malformedRequest", "{body}");
}

// ── Context-scoped DID templates ─────────────────────────────────────

#[tokio::test]
async fn ctx_did_templates_create_requires_context_admin_or_super() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = setup_context(&app, &ctx, "tpl-ctx").await;
    let _ = super_admin;

    // Reader with context access — may list/read, must not write.
    let reader = ctx
        .login(SEED_READER, "reader", vec!["tpl-ctx".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &reader,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("tpl-ctx"), sample_template("rejected")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Admin scoped to a different context — no access to tpl-ctx at all.
    let other_admin = ctx
        .login(SEED_OTHER_ADMIN, "admin", vec!["somewhere-else".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &other_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("tpl-ctx"), sample_template("rejected")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn ctx_did_templates_context_admin_can_crud() {
    let (app, ctx) = TestApp::new().await;
    setup_context(&app, &ctx, "cx-admin-test").await;

    let ctx_admin = ctx
        .login(SEED_CTX_ADMIN, "admin", vec!["cx-admin-test".into()])
        .await;

    let (status, body) = app
        .task(
            &ctx,
            &ctx_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("cx-admin-test"), sample_template("scoped-tpl")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["scope"]["type"], "context");
    assert_eq!(body["scope"]["contextId"], "cx-admin-test");
    assert_eq!(body["name"], "scoped-tpl");

    let (status, body) = app
        .task(
            &ctx,
            &ctx_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "scoped-tpl", "contextId": "cx-admin-test"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "scoped-tpl");

    let (status, body) = app
        .task(
            &ctx,
            &ctx_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_LIST_2_0,
            json!({"contextId": "cx-admin-test"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["templates"].as_array().map(|a| a.len()), Some(1));

    let mut updated = sample_template("scoped-tpl");
    updated["description"] = json!("changed");
    let (status, body) = app
        .task(
            &ctx,
            &ctx_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0,
            update_req(Some("cx-admin-test"), "scoped-tpl", updated),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["description"], "changed");

    let (status, _) = app
        .task(
            &ctx,
            &ctx_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0,
            json!({"name": "scoped-tpl", "contextId": "cx-admin-test"}),
        )
        .await;
    assert!(status.is_success());

    let (status, _) = app
        .task(
            &ctx,
            &ctx_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "scoped-tpl", "contextId": "cx-admin-test"}),
        )
        .await;
    assert!(!status.is_success());
}

#[tokio::test]
async fn ctx_did_templates_rejects_missing_context() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("does-not-exist"), sample_template("orphan")),
        )
        .await;
    assert!(!status.is_success(), "{body}");
    assert_eq!(body["details"]["reason"], "not_found", "{body}");
}

#[tokio::test]
async fn ctx_did_templates_shadow_global_without_conflict() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = setup_context(&app, &ctx, "shadow-ctx").await;

    let mut global = sample_template("mediator");
    global["description"] = json!("GLOBAL");
    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, global),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("shadow-ctx"), sample_template("mediator")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["scope"]["type"], "context");

    let (_, global) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "mediator"}),
        )
        .await;
    let (_, context_local) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "mediator", "contextId": "shadow-ctx"}),
        )
        .await;
    assert_eq!(global["scope"]["type"], "global");
    assert_eq!(context_local["scope"]["type"], "context");
}

#[tokio::test]
async fn ctx_did_templates_render_injects_context_vars() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = setup_context(&app, &ctx, "render-ctx").await;

    let mut tpl = sample_template("ctxtpl");
    tpl["document"]["service"][0]["serviceEndpoint"]["contextId"] = json!("{CONTEXT_ID}");
    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("render-ctx"), tpl),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0,
            json!({
                "name": "ctxtpl",
                "contextId": "render-ctx",
                "vars": {"DID": "did:x", "SIGNING_KEY_MB": "z6Mk", "URL": "https://example.com"}
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["document"]["service"][0]["serviceEndpoint"]["contextId"],
        "render-ctx"
    );
}

/// Deleting a context force-cascades its templates: the preview lists them,
/// and afterward the template (and the context) reads as gone.
#[tokio::test]
async fn ctx_did_templates_deleted_when_parent_context_deleted() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = setup_context(&app, &ctx, "cascade-ctx").await;

    app.task(
        &ctx,
        &super_admin,
        vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
        create_req(Some("cascade-ctx"), sample_template("will-be-deleted")),
    )
    .await;

    let (status, preview) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0,
            json!({"id": "cascade-ctx"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["didTemplates"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(preview["didTemplates"][0], "will-be-deleted");

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0,
            json!({"id": "cascade-ctx", "force": true}),
        )
        .await;
    assert!(status.is_success(), "{body}");

    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_GET_2_0,
            json!({"name": "will-be-deleted", "contextId": "cascade-ctx"}),
        )
        .await;
    assert!(
        !status.is_success(),
        "template must not survive the context it was scoped to"
    );
}

// ── `did:webvh` DID creation ──────────────────────────────────────────

#[cfg(feature = "webvh")]
async fn webvh_create(
    app: &TestApp,
    ctx: &TestContext,
    caller: &Caller,
    payload: Value,
) -> (StatusCode, Value) {
    app.task(
        ctx,
        caller,
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
        payload,
    )
    .await
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_rejects_both_document_and_log() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-reject").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-reject",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "didDocument": {"id": "{DID}"},
            "didLog": "{\"some\": \"log\"}"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected malformedRequest: {body}"
    );
}

/// The `pathMode` wire member deserializes and threads through without
/// breaking the serverless create path (`.well-known` self-hosting).
#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_accepts_path_mode_field() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-path-mode").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-path-mode",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "pathMode": {"mode": "autoAssign"},
            "setPrimary": false,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create with explicit pathMode: {status} {body}"
    );
    assert!(body["did"].as_str().is_some(), "response has did");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_mode() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-template").await;

    let template = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
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

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-template",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "didDocument": template,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "template create: {status} {body}");
    assert!(body["did"].as_str().is_some(), "response has did");
    assert!(body["didDocument"].is_object(), "response has didDocument");
    let doc = &body["didDocument"];
    let vm = doc["verificationMethod"]
        .as_array()
        .expect("verificationMethod array");
    assert!(
        vm.iter().any(|v| v["id"]
            .as_str()
            .is_some_and(|id| id.ends_with("#custom-key"))),
        "template's custom key should be in the returned document"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_final_mode_stores_record() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-final").await;

    let (status, created) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-final",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "setPrimary": false,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bootstrap create: {status} {created}"
    );
    let log_entry = created["logEntry"].as_str().expect("logEntry string");

    let admin2 = setup_context(&app, &ctx, "test-final-2").await;
    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin2,
        json!({
            "contextId": "test-final-2",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "didLog": log_entry,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "final mode create: {status} {body}");
    let final_did = body["did"].as_str().expect("did in response");
    assert!(!final_did.is_empty());
    assert_eq!(body["signingKeyId"].as_str().unwrap(), "");
    assert_eq!(body["kaKeyId"].as_str().unwrap(), "");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_set_primary_false() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-no-primary").await;

    let (status, _) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-no-primary",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "setPrimary": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0,
            json!({"id": "test-no-primary"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["did"].is_null(),
        "context did should be null when setPrimary=false"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_set_primary_true() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-primary").await;

    let (status, created) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-primary",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "setPrimary": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let created_did = created["did"].as_str().expect("did");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0,
            json!({"id": "test-primary"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["did"].as_str().unwrap(),
        created_did,
        "context did should match created DID"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_unknown_server_returns_not_found() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-no-server").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({"contextId": "test-no-server", "serverId": "nonexistent-server"}),
    )
    .await;
    assert!(
        !status.is_success(),
        "unknown serverId must be refused: {status} {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_server_and_url_mutually_exclusive() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-exclusive").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "test-exclusive",
            "serverId": "some-server",
            "url": "https://example.com/.well-known/did/did.jsonl",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_neither_server_nor_url_rejected() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test-neither").await;

    let (status, body) =
        webvh_create(&app, &ctx, &admin, json!({"contextId": "test-neither"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

// ── Template-driven DID creation ──────────────────────────────────────

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_via_builtin_mediator_template() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "tpl-mediator").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "tpl-mediator",
            "url": "https://mediator.example.com/.well-known/did/did.jsonl",
            "template": "didcomm-mediator",
            "templateVars": {
                "URL": "https://mediator.example.com",
                "WS_URL": "wss://mediator.example.com/ws"
            }
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "template-driven create failed: {status} {body}"
    );

    let doc = &body["didDocument"];
    assert!(doc.is_object(), "result must include didDocument");
    let services = doc["service"].as_array().unwrap();
    let didcomm = services
        .iter()
        .find(|s| s["type"] == json!(["DIDCommMessaging"]))
        .expect("mediator template must produce a DIDCommMessaging service");
    let endpoints = didcomm["serviceEndpoint"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0]["uri"], "https://mediator.example.com");
    assert_eq!(endpoints[1]["uri"], "wss://mediator.example.com/ws");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_mutually_exclusive_with_did_document() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "tpl-excl").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "tpl-excl",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "template": "didcomm-mediator",
            "templateVars": {"URL": "https://example.com"},
            "didDocument": {"id": "{DID}"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_missing_required_var_errors() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "tpl-missing").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "tpl-missing",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "template": "didcomm-mediator"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_template_unknown_name_errors() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "tpl-unk").await;

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "tpl-unk",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "template": "no-such-template"
        }),
    )
    .await;
    assert!(
        !status.is_success(),
        "unknown template must be refused: {status} {body}"
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn create_did_webvh_context_scoped_template_shadows_global() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "shadow-didcreate").await;

    let mut global = sample_template("my-custom");
    global["description"] = json!("GLOBAL");
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(None, global),
        )
        .await;
    assert!(status.is_success(), "global template: {body}");

    let mut local = sample_template("my-custom");
    local["description"] = json!("CONTEXT");
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0,
            create_req(Some("shadow-didcreate"), local),
        )
        .await;
    assert!(status.is_success(), "context template: {body}");

    let (status, body) = webvh_create(
        &app,
        &ctx,
        &admin,
        json!({
            "contextId": "shadow-didcreate",
            "url": "https://example.com/.well-known/did/did.jsonl",
            "template": "my-custom",
            "templateContext": "shadow-didcreate",
            "templateVars": {"URL": "https://example.com"}
        }),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
    let doc = &body["didDocument"];
    assert_eq!(doc["service"][0]["type"], "Custom");
}
