//! Integration coverage for the ACL, Contexts, Keys and Audit slices, ported
//! from the REST `api_integration.rs` suite onto the signed Trust Task
//! dispatcher (`POST /trust-tasks`) after #1858 retired the REST routes these
//! behaviours used to be exercised through.
//!
//! Every test here drives the same operation the deleted REST test did, via
//! the `(method, matched-path) -> Trust Task URI` mapping that used to live in
//! `vta-service::deprecation::SUPERSEDED` (origin/main, before that table was
//! itself deleted alongside the routes). REST status codes are mapped onto the
//! Trust Task error `code` per the HTTPS binding's status table
//! (`trust-tasks-https::status::status_for_code`): `malformedRequest` → 400,
//! `permissionDenied` → 403, `idConflict` → 409, everything else refused
//! (`taskFailed`, extended codes) → 422.
//!
//! SPEC §7.2 item 6 binds a document's in-band `issuer` to the
//! transport-authenticated caller (`auth.did`) whenever `issuer` is present,
//! independent of whether the task requires a proof — so every caller here is
//! a real, derivable `did:key` ([`did_for_seed`]) that can sign as itself,
//! rather than an opaque literal string a REST-only test could get away with.

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

// ── Test harness ────────────────────────────────────────────────────

struct TestApp {
    router: axum::Router,
}

/// An authenticated, signing-capable caller: a bearer token plus the seed that
/// derives the same `did:key` the token names, so a document this caller
/// issues can carry a proof the spine verifies as its own issuer.
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

    /// Dispatch a signed Trust Task and return `(status, payload)` — the
    /// envelope's `payload` member, which is where both the success body and
    /// the error (`code`/`message`/`details`) live.
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

    /// Mint a token for the `did:key` [`did_for_seed`] derives from `seed`,
    /// with `role` + `contexts` (empty `contexts` is unrestricted — super
    /// admin, for the `admin` role). Bypasses the live challenge-response
    /// handshake, same shortcut the REST-era harness used.
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

    /// Store the ACL row a token stands for, when there is none — a real
    /// token is only minted for a DID with an entry (VTI-ACL-053).
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

/// A hand-built Trust Task document a conforming VTA accepts: an in-band
/// `recipient` (SPEC §7.2 item 5b, every dispatched spec declares it
/// REQUIRED) and a `proof` from `seed`'s identity (item 7a — 72 of the 109
/// dispatched specs require one, and the issuer/caller identity check runs
/// regardless per the module doc above).
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

// Seeds naming each identity a test logs in as — distinct callers need
// distinct seeds so `did_for_seed` gives each one its own `did:key`. Grant
// *targets* that never authenticate (a bare `subject` in a payload) stay
// plain strings; only callers need a seed.
const SEED_ADMIN: u8 = 0x10;
const SEED_SUPER: u8 = 0x11;
const SEED_SCOPED: u8 = 0x12;
const SEED_APP: u8 = 0x13;
const SEED_READER: u8 = 0x14;
const SEED_SCOPED_A: u8 = 0x15;
const SEED_SCOPED_B: u8 = 0x16;

/// Create a context via `contexts/create/1.0`, returning the super-admin
/// caller that made it — reused by callers that just need a context to hang a
/// key or a template off of.
async fn setup_context(app: &TestApp, ctx: &TestContext, id: &str) -> Caller {
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;
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

// ── ACL CRUD ───────────────────────────────────────────────────────

#[tokio::test]
async fn acl_create_and_list() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1,
            json!({
                "entry": {
                    "subject": "did:key:z6MkNew",
                    "role": "application",
                    "label": "test app",
                    "scopes": ["ctx1"]
                }
            }),
        )
        .await;
    assert!(status.is_success(), "create: {body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries array");
    assert!(
        entries.iter().any(|e| e["subject"] == "did:key:z6MkNew"),
        "new entry should be in list: {body}"
    );
}

/// The `direction` filter (#822): the same `scope` reads two opposite ways, so
/// a caller sweeping a subtree to revoke it must be able to ask for the
/// second.
#[tokio::test]
async fn acl_list_filters_a_scope_in_both_directions() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    for (id, parent) in [
        ("acme", None),
        ("eng", Some("acme")),
        ("attestation", Some("acme/eng")),
        ("ops", Some("acme")),
        ("keys", Some("acme/ops")),
    ] {
        let mut req = json!({"id": id, "name": id});
        if let Some(p) = parent {
            req["parent"] = json!(p);
        }
        let (status, body) = app
            .task(
                &ctx,
                &admin,
                vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
                req,
            )
            .await;
        assert!(status.is_success(), "create context {id}: {body}");
    }

    for (did, scope) in [
        ("did:key:z6MkUnitAdmin", "acme/eng"),
        ("did:key:z6MkGateway", "acme/eng/attestation"),
        ("did:key:z6MkOps", "acme/ops/keys"),
    ] {
        let (status, body) = app
            .task(
                &ctx,
                &admin,
                vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1,
                json!({"entry": {"subject": did, "role": "application", "scopes": [scope]}}),
            )
            .await;
        assert!(status.is_success(), "create {did}: {body}");
    }

    let dids = |body: &Value| -> Vec<String> {
        let mut v: Vec<String> = body["entries"]
            .as_array()
            .expect("entries array")
            .iter()
            .map(|e| e["subject"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };

    // Default (absent direction) == acting-in: the unit's own admin, not the
    // leaf under it.
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_LIST_0_1,
            json!({"scope": "acme/eng"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let default_dids = dids(&body);
    assert!(default_dids.contains(&"did:key:z6MkUnitAdmin".to_string()));
    assert!(!default_dids.contains(&"did:key:z6MkGateway".to_string()));

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_LIST_0_1,
            json!({"scope": "acme/eng", "direction": "acting-in"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dids(&body), default_dids, "explicit acting-in == absent");

    // subtree: the leaf grant a revocation sweep must cut, and nothing from
    // the sibling unit.
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_LIST_0_1,
            json!({"scope": "acme/eng", "direction": "subtree"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let subtree = dids(&body);
    assert!(subtree.contains(&"did:key:z6MkGateway".to_string()));
    assert!(subtree.contains(&"did:key:z6MkUnitAdmin".to_string()));
    assert!(!subtree.contains(&"did:key:z6MkOps".to_string()));
}

#[tokio::test]
async fn acl_update_sets_step_up_approver() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    let (status, _) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1,
            json!({"entry": {"subject": "did:key:z6MkGrantee2", "role": "application", "scopes": ["ctx1"]}}),
        )
        .await;
    assert!(status.is_success());

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_UPDATE_0_1,
            json!({"subject": "did:key:z6MkGrantee2", "stepUp": {"approver": "did:key:z6MkApprover"}}),
        )
        .await;
    assert!(
        status.is_success(),
        "update should succeed: {status} {body}"
    );
    assert_eq!(
        body["entry"]["stepUp"]["approver"], "did:key:z6MkApprover",
        "update must set + reflect the step-up approver: {body}"
    );
}

#[tokio::test]
async fn acl_grant_persists_step_up_approver() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1,
            json!({
                "entry": {
                    "subject": "did:key:z6MkGrantee",
                    "role": "application",
                    "scopes": ["ctx1"],
                    "stepUp": {"approver": "did:key:z6MkApprover"}
                }
            }),
        )
        .await;
    assert!(status.is_success(), "grant should succeed: {status} {body}");
    assert_eq!(
        body["entry"]["stepUp"]["approver"], "did:key:z6MkApprover",
        "grant must persist + reflect the step-up approver: {body}"
    );
}

#[tokio::test]
async fn acl_application_cannot_manage() {
    let (app, ctx) = TestApp::new().await;
    let application = ctx
        .login(SEED_APP, "application", vec!["ctx1".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &application,
            vta_sdk::trust_tasks::TASK_ACL_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "permissionDenied", "{body}");
}

/// Full lifecycle: grant, show, update (label only — no `role` member;
/// `acl/update` no longer carries one), the compare-and-swapped role
/// transition, a stale `fromRole` conflicting, then revoke.
#[tokio::test]
async fn acl_show_update_change_role_revoke_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    app.task(
        &ctx,
        &admin,
        vta_sdk::trust_tasks::TASK_ACL_GRANT_0_1,
        json!({"entry": {"subject": "did:key:z6MkTarget", "role": "application", "label": "test", "scopes": ["ctx1"]}}),
    )
    .await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_SHOW_0_1,
            json!({"subject": "did:key:z6MkTarget"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["entry"]["role"], "application", "{body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_UPDATE_0_1,
            json!({"subject": "did:key:z6MkTarget", "label": "updated"}),
        )
        .await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(
        body["entry"]["role"], "application",
        "update must leave the role alone: {body}"
    );

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_CHANGE_ROLE_0_1,
            json!({"subject": "did:key:z6MkTarget", "fromRole": "application", "toRole": "initiator"}),
        )
        .await;
    assert!(status.is_success(), "change-role: {status} {body}");
    assert_eq!(body["entry"]["role"], "initiator", "{body}");

    // A stale `fromRole` is refused — they are `initiator` now.
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_CHANGE_ROLE_0_1,
            json!({"subject": "did:key:z6MkTarget", "fromRole": "application", "toRole": "admin"}),
        )
        .await;
    // `AppError::Conflict` rides out as `taskFailed`/`details.reason: conflict`
    // (422) — the framework defines no standard `conflict` code (only
    // `idConflict`, for a *document* replay, not an application-level state
    // conflict), so this family's compare-and-swap refusal uses the same
    // `taskFailed` discriminator every `NotFound`/`Conflict`/`Gone` app error
    // does (see `app_error_to_reject`).
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a stale fromRole must conflict: {body}"
    );
    assert_eq!(body["code"], "taskFailed", "{body}");
    assert_eq!(body["details"]["reason"], "conflict", "{body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_REVOKE_0_1,
            json!({"subject": "did:key:z6MkTarget"}),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_ACL_SHOW_0_1,
            json!({"subject": "did:key:z6MkTarget"}),
        )
        .await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(body["code"], "taskFailed", "{body}");
    assert_eq!(
        body["details"]["reason"], "not_found",
        "revoked entry must read as gone: {body}"
    );
}

// ── Context CRUD ───────────────────────────────────────────────────

#[tokio::test]
async fn context_create_requires_super_admin() {
    let (app, ctx) = TestApp::new().await;

    let scoped = ctx.login(SEED_SCOPED, "admin", vec!["ctx1".into()]).await;
    let (status, body) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": "new-ctx", "name": "New Context"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;
    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": "new-ctx", "name": "New Context"}),
        )
        .await;
    assert!(status.is_success(), "{body}");
}

#[tokio::test]
async fn context_create_get_update_list_delete() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": "lifecycle", "name": "Test", "description": "A test context"}),
        )
        .await;
    assert!(status.is_success());

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0,
            json!({"id": "lifecycle"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Test");
    assert_eq!(body["description"], "A test context");

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0,
            json!({"id": "lifecycle", "name": "Updated"}),
        )
        .await;
    assert!(status.is_success(), "update: {status} {body}");
    assert_eq!(body["name"], "Updated");

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let contexts = body["contexts"].as_array().expect("contexts");
    assert!(contexts.iter().any(|c| c["id"] == "lifecycle"));

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0,
            json!({"id": "lifecycle"}),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
}

#[tokio::test]
async fn context_admin_can_update_own_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": "myctx", "name": "My Context"}),
        )
        .await;
    assert!(status.is_success());

    let scoped = ctx.login(SEED_SCOPED, "admin", vec!["myctx".into()]).await;
    let (status, body) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            json!({"id": "myctx", "did": "did:webvh:abc:example.com"}),
        )
        .await;
    assert!(status.is_success(), "update did: {status} {body}");
    assert_eq!(body["did"], "did:webvh:abc:example.com");
}

/// An admin scoped to one context cannot update another's DID — refused
/// (`notFound`, since `contexts/update-did` states that it "does not
/// distinguish 'does not exist' from 'exists but not yours'").
#[tokio::test]
async fn context_admin_cannot_update_other_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    for id in ["ctx-a", "ctx-b"] {
        app.task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": id, "name": id}),
        )
        .await;
    }

    let scoped = ctx
        .login(SEED_SCOPED_A, "admin", vec!["ctx-a".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            json!({"id": "ctx-b", "did": "did:webvh:nope:example.com"}),
        )
        .await;
    assert!(!status.is_success(), "{status} {body}");
    assert_eq!(body["code"], "vta/contexts/update-did:notFound", "{body}");

    // The same code for an id that does not exist at all — the two are
    // indistinguishable from outside.
    let (_, absent) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            json!({"id": "ctx-ghost", "did": "did:webvh:nope:example.com"}),
        )
        .await;
    assert_eq!(
        absent["code"], "vta/contexts/update-did:notFound",
        "{absent}"
    );

    // And ctx-b was not modified by the refusal.
    let (_, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0,
            json!({"id": "ctx-b"}),
        )
        .await;
    assert_eq!(body["did"], json!(null), "{body}");
}

#[tokio::test]
async fn super_admin_can_update_any_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    app.task(
        &ctx,
        &super_admin,
        vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
        json!({"id": "anyctx", "name": "Any"}),
    )
    .await;

    let (status, body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            json!({"id": "anyctx", "did": "did:webvh:xyz:example.com"}),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    assert_eq!(body["did"], "did:webvh:xyz:example.com");
}

#[tokio::test]
async fn non_admin_cannot_update_context_did() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    app.task(
        &ctx,
        &super_admin,
        vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
        json!({"id": "restricted", "name": "R"}),
    )
    .await;

    let application = ctx
        .login(SEED_APP, "application", vec!["restricted".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &application,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            json!({"id": "restricted", "did": "did:webvh:bad:example.com"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// ── Key management ─────────────────────────────────────────────────

#[tokio::test]
async fn key_create_and_list() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "test").await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "ed25519", "contextId": "test"}),
        )
        .await;
    assert!(status.is_success(), "create key: {body}");
    assert!(body["key"]["keyId"].is_string(), "{body}");
    assert_eq!(body["key"]["keyType"], "ed25519", "{body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().expect("keys array");
    assert!(!keys.is_empty(), "should have at least one key");
}

#[tokio::test]
async fn create_p256_key() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "p256").await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "p256", "contextId": "p256"}),
        )
        .await;
    assert!(status.is_success(), "create p256: {status} {body}");
    assert_eq!(body["key"]["keyType"], "p256", "{body}");
    assert!(body["key"]["publicKey"].is_string(), "{body}");
}

#[tokio::test]
async fn key_create_revoke_show_lifecycle() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "lc").await;

    let (_, key_body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "ed25519", "contextId": "lc"}),
        )
        .await;
    let key_id = key_body["key"]["keyId"]
        .as_str()
        .unwrap_or_else(|| panic!("create answers {{ key }}: {key_body}"));
    assert_eq!(key_body["key"]["status"], "active", "{key_body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_REVOKE_0_1,
            json!({"keyId": key_id}),
        )
        .await;
    assert!(status.is_success(), "revoke: {status} {body}");
    assert_eq!(body["status"], "revoked", "{body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_SHOW_0_1,
            json!({"keyId": key_id}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key"]["status"], "revoked", "{body}");
}

#[tokio::test]
async fn key_rename() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "rn").await;

    let (_, key_body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "ed25519", "contextId": "rn", "label": "original"}),
        )
        .await;
    let key_id = key_body["key"]["keyId"]
        .as_str()
        .unwrap_or_else(|| panic!("create answers {{ key }}: {key_body}"))
        .to_string();

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_RENAME_0_1,
            json!({"keyId": key_id, "newKeyId": "renamed-key"}),
        )
        .await;
    assert!(status.is_success(), "rename: {status} {body}");
    assert_eq!(body["keyId"], "renamed-key", "{body}");
}

#[tokio::test]
async fn seed_list_returns_seeds() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["seeds"].is_array(), "{body}");
}

#[tokio::test]
async fn reader_can_list_keys() {
    let (app, ctx) = TestApp::new().await;
    let reader = ctx
        .login(SEED_READER, "reader", vec!["test-ctx".into()])
        .await;

    let (status, body) = app
        .task(
            &ctx,
            &reader,
            vta_sdk::trust_tasks::TASK_KEYS_LIST_0_1,
            json!({"contextId": "test-ctx"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn reader_cannot_sign() {
    let (app, ctx) = TestApp::new().await;
    let reader = ctx
        .login(SEED_READER, "reader", vec!["test-ctx".into()])
        .await;

    let (status, body) = app
        .task(
            &ctx,
            &reader,
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_0_1,
            json!({"keyId": "test-key", "payload": "aGVsbG8", "algorithm": "EdDSA"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "permissionDenied", "{body}");
}

#[tokio::test]
async fn reader_cannot_create_key() {
    let (app, ctx) = TestApp::new().await;
    let reader = ctx
        .login(SEED_READER, "reader", vec!["test-ctx".into()])
        .await;

    let (status, body) = app
        .task(
            &ctx,
            &reader,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "ed25519", "contextId": "test-ctx"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn application_role_cannot_mint_keys() {
    let (app, ctx) = TestApp::new().await;
    let application = ctx
        .login(SEED_APP, "application", vec!["ctx1".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &application,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "ed25519", "contextId": "ctx1"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn scoped_admin_can_only_access_own_context_keys() {
    let (app, ctx) = TestApp::new().await;
    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;

    for id in ["ctx-a", "ctx-b"] {
        app.task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            json!({"id": id, "name": id}),
        )
        .await;
    }

    let (status, key_body) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
            json!({"keyType": "ed25519", "contextId": "ctx-a"}),
        )
        .await;
    assert!(status.is_success());
    let key_id = key_body["key"]["keyId"]
        .as_str()
        .unwrap_or_else(|| panic!("create answers {{ key }}: {key_body}"))
        .to_string();

    let scoped_b = ctx
        .login(SEED_SCOPED_B, "admin", vec!["ctx-b".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &scoped_b,
            vta_sdk::trust_tasks::TASK_KEYS_SHOW_0_1,
            json!({"keyId": key_id}),
        )
        .await;
    assert!(
        !status.is_success(),
        "scoped admin should not access other context's key, got {status} {body}"
    );

    let scoped_a = ctx
        .login(SEED_SCOPED_A, "admin", vec!["ctx-a".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &scoped_a,
            vta_sdk::trust_tasks::TASK_KEYS_SHOW_0_1,
            json!({"keyId": key_id}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key"]["keyId"], key_id, "{body}");
}

/// `keys/import/0.1` refuses its cleartext carrier over HTTPS (hop-by-hop),
/// even though the dispatcher accepts it over DIDComm/TSP (end-to-end): one
/// dispatcher serves all three transports and cannot tell which one carried a
/// given request, so the transport-aware refusal has to be as conservative as
/// the weakest one.
#[tokio::test]
async fn keys_import_refuses_cleartext_over_https() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_KEYS_IMPORT_0_1,
            json!({"keyType": "ed25519", "privateKeyMultibase": "z6MkDeadbeefDeadbeefDeadbeef"}),
        )
        .await;
    assert!(
        !status.is_success(),
        "cleartext key over HTTPS must be refused: {status} {body}"
    );
    let rendered = body.to_string();
    assert!(
        rendered.contains("confidential end to end"),
        "the refusal must say why, so an operator can act on it: {rendered}"
    );
}

// ── Audit ──────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_list_requires_admin() {
    let (app, ctx) = TestApp::new().await;

    let application = ctx
        .login(SEED_APP, "application", vec!["ctx1".into()])
        .await;
    let (status, body) = app
        .task(
            &ctx,
            &application,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;
    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["entries"].is_array(), "{body}");
}

/// The RFC 3339 `from`/`to` bounds must actually bind server-side, not just
/// deserialize.
#[tokio::test]
async fn audit_time_bounds_are_parsed_and_applied() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "aud-bounds").await;
    app.task(
        &ctx,
        &admin,
        vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
        json!({"keyType": "ed25519", "contextId": "aud-bounds"}),
    )
    .await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body["entries"].as_array().expect("entries").is_empty(),
        "expected some audit entries to filter"
    );

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({"from": "2999-01-01T00:00:00Z"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["entries"].as_array().expect("entries").is_empty(),
        "a far-future `from` must exclude every entry — got {}",
        body["entries"]
    );

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({"to": "2000-01-01T00:00:00Z"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["entries"].as_array().expect("entries").is_empty(),
        "a far-past `to` must exclude every entry — got {}",
        body["entries"]
    );
}

/// The audit log is the whole agent's tail. A context-scoped admin must not
/// read another context's entries just by omitting the filter.
#[tokio::test]
async fn scoped_admin_cannot_read_the_whole_audit_log() {
    let (app, ctx) = TestApp::new().await;
    let scoped = ctx.login(SEED_SCOPED, "admin", vec!["ctx1".into()]).await;

    let (status, body) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a context-scoped admin must not read the unfiltered log: {body}"
    );

    let (status, _) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({"contextId": "ctx2"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = app
        .task(
            &ctx,
            &scoped,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({"contextId": "ctx1"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["entries"].is_array(), "{body}");

    let super_admin = ctx.login(SEED_SUPER, "admin", vec![]).await;
    let (status, _) = app
        .task(
            &ctx,
            &super_admin,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn operations_create_audit_entries() {
    let (app, ctx) = TestApp::new().await;
    let admin = setup_context(&app, &ctx, "aud").await;
    app.task(
        &ctx,
        &admin,
        vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1,
        json!({"keyType": "ed25519", "contextId": "aud"}),
    )
    .await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_0_1,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().expect("entries");
    assert!(!entries.is_empty(), "should have at least 1 audit entry");

    let entry = &entries[0];
    assert!(entry["eventId"].is_string(), "{entry}");
    let recorded_at = entry["recordedAt"]
        .as_str()
        .expect("recordedAt is a string");
    assert!(
        chrono::DateTime::parse_from_rfc3339(recorded_at).is_ok(),
        "recordedAt should be RFC 3339, got {recorded_at}"
    );
    assert!(entry["action"].is_string());
    assert!(entry["actor"].is_string());
}

#[tokio::test]
async fn audit_retention_get_and_update() {
    let (app, ctx) = TestApp::new().await;
    let admin = ctx.login(SEED_ADMIN, "admin", vec![]).await;

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["retentionDays"].is_number(), "{body}");

    let (status, body) = app
        .task(
            &ctx,
            &admin,
            vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0,
            json!({"retentionDays": 90}),
        )
        .await;
    assert!(status.is_success(), "update retention: {status} {body}");
    assert_eq!(body["retentionDays"], 90, "{body}");
}
