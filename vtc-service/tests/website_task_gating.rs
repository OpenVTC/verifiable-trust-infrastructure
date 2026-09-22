//! Trust-Task header gating on the `/v1/website/*` surface.
//!
//! The website mount is where "is this a Trust Task?" gets answered by shape
//! rather than by convention. A Trust Task's payload is a JSON document; three
//! of these endpoints move **raw file bytes** and one carries only a path.
//!
//! - `GET /website/files/{path}` — file bytes out. **Not** a Trust Task.
//! - `PUT /website/files/{path}` — file bytes in. **Not** a Trust Task.
//! - `POST /website/deploy` — bundle bytes in. **Not** a Trust Task.
//! - `DELETE /website/files/{path}` — a path, no payload. **Is** one, and now
//!   carries its own canonical task instead of borrowing the `show` label.
//!
//! All four previously sat behind `openvtc/vtc/website/files/show/1.0` (or
//! `…/deploy/1.0`), so a write and a delete were both announcing themselves as
//! a read. These tests pin the de-listing so a future "every route should have
//! a task" sweep doesn't quietly put the wrong header back.
//!
//! Authentication is untouched and asserted here too: de-listing removes a
//! *header* gate, never the `AdminAuth` gate.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use vti_common::acl::{AclEntry, Role, store_acl_entry};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

use vtc_service::test_support::TestVtc;

const ADMIN_DID: &str = "did:key:zWebsiteAdmin";
const DELETE_TASK: &str = "https://trusttasks.org/spec/vtc/website/files/delete/0.1";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/website/files/show/1.0";

struct Fixture {
    router: axum::Router,
    token: String,
    _vtc: TestVtc,
}

async fn build_fixture() -> Fixture {
    let vtc = TestVtc::builder().build().await;

    store_acl_entry(
        &vtc.state.acl_ks,
        &AclEntry::new(ADMIN_DID.to_string(), Role::Admin, "did:key:vtc-install"),
    )
    .await
    .unwrap();

    let session_id = "website-admin-session";
    store_session(
        &vtc.state.sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: ADMIN_DID.into(),
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
        },
    )
    .await
    .unwrap();

    let claims = vtc.jwt_keys.new_claims(
        ADMIN_DID.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        3600,
        false,
    );
    let token = vtc.jwt_keys.encode(&claims).unwrap();
    let router = vtc.router.clone();
    Fixture {
        router,
        token,
        _vtc: vtc,
    }
}

async fn send(
    fix: &Fixture,
    method: &str,
    uri: &str,
    trust_task: Option<&str>,
    authed: bool,
    body: Option<Vec<u8>>,
) -> (StatusCode, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = trust_task {
        builder = builder.header("Trust-Task", t);
    }
    if authed {
        builder = builder.header("Authorization", format!("Bearer {}", fix.token));
    }
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/octet-stream");
            Body::from(b)
        }
        None => Body::empty(),
    };
    let res = fix
        .router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = res.status();
    // The `error` discriminator, when the body is one of our JSON errors.
    // Status alone cannot distinguish "the header gate refused this" from a
    // handler's own 400, and that distinction is the whole point here.
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let err = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
    (status, err)
}

/// The router must actually build. Splitting `/website/files/{*path}` into two
/// `.route()` calls on the same path relies on axum merging same-path method
/// routers per verb — if that assumption were wrong this panics at
/// construction, and every other test in this file would fail for the wrong
/// reason.
#[tokio::test]
async fn the_split_file_mount_builds() {
    let fix = build_fixture().await;
    // A request that reaches *any* handler on the mount proves both verbs
    // survived the merge. 404 (no such file) is a handler response.
    let (status, _) = send(
        &fix,
        "GET",
        "/v1/website/files/nothing-here.txt",
        None,
        true,
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "GET was lost when the mount was split"
    );
}

#[tokio::test]
async fn raw_byte_routes_need_no_trust_task_header() {
    // The de-listing. Sending no header must not be refused — these are not
    // Trust Tasks.
    //
    // Asserted on the error *discriminator*, not the status: a re-added gate
    // answers `TrustTaskMissing`, which is a 400, and these handlers have
    // legitimate 400s of their own (a malformed bundle, a bad path). A
    // status-only assertion would pass straight through a regression.
    let fix = build_fixture().await;

    for (method, uri, body) in [
        ("GET", "/v1/website/files/index.html", None),
        (
            "PUT",
            "/v1/website/files/index.html",
            Some(b"<h1>hi</h1>".to_vec()),
        ),
        (
            "POST",
            "/v1/website/deploy",
            Some(b"not-a-real-zip".to_vec()),
        ),
    ] {
        let (_, err) = send(&fix, method, uri, None, true, body).await;
        assert!(
            !matches!(
                err.as_deref(),
                Some("TrustTaskMissing") | Some("TrustTaskMismatch")
            ),
            "{method} {uri} still demands a Trust-Task header (error={err:?})"
        );
    }
}

#[tokio::test]
async fn delete_carries_its_own_canonical_task() {
    let fix = build_fixture().await;

    // The canonical task is accepted (whatever the handler then does about a
    // missing file, it got past the header gate).
    let (_, err) = send(
        &fix,
        "DELETE",
        "/v1/website/files/gone.txt",
        Some(DELETE_TASK),
        true,
        None,
    )
    .await;
    assert!(
        !matches!(
            err.as_deref(),
            Some("TrustTaskMissing") | Some("TrustTaskMismatch")
        ),
        "the canonical delete task must be accepted (error={err:?})"
    );

    // The retired `show` task must NOT be — that mislabelling (a delete
    // announcing itself as a read) is exactly what this change removes.
    let (status, err) = send(
        &fix,
        "DELETE",
        "/v1/website/files/gone.txt",
        Some(SHOW_TASK),
        true,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        err.as_deref(),
        Some("TrustTaskMismatch"),
        "the retired show task must no longer satisfy DELETE"
    );
}

#[tokio::test]
async fn de_listing_removes_a_header_gate_not_the_auth_gate() {
    // The load-bearing distinction. Dropping the Trust-Task requirement must
    // not make these routes reachable unauthenticated — `AdminAuth` is what
    // protects them, and it is untouched.
    //
    // Each case is sent with whatever header the route *does* require (none
    // for the de-listed three, the canonical task for DELETE), so 401 is the
    // only remaining reason to refuse. Otherwise the header gate — which is a
    // middleware layer, and so runs before any extractor — would answer 400
    // first and this would pass without ever reaching the auth check.
    let fix = build_fixture().await;

    for (method, uri, task, body) in [
        ("GET", "/v1/website/files/index.html", None, None),
        (
            "PUT",
            "/v1/website/files/index.html",
            None,
            Some(b"pwned".to_vec()),
        ),
        ("POST", "/v1/website/deploy", None, Some(b"pwned".to_vec())),
        (
            "DELETE",
            "/v1/website/files/index.html",
            Some(DELETE_TASK),
            None,
        ),
    ] {
        let (status, _) = send(&fix, method, uri, task, false, body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must still refuse an unauthenticated caller"
        );
    }
}

// ---------------------------------------------------------------------------
// #1600 — the codes the website tasks declare, read from the generated
// bindings.
// ---------------------------------------------------------------------------

use trust_tasks_rs::specs::vtc::website as website_spec;

const FILES_DELETE_ERR_NOT_FOUND: &str =
    website_spec::files::delete::v0_1::error_codes::NOT_FOUND.code;
const GENERATIONS_LIST_ERR_NOT_MANAGED: &str =
    website_spec::generations::list::v0_1::error_codes::NOT_MANAGED.code;
const ROLLBACK_ERR_NOT_MANAGED: &str = website_spec::rollback::v0_1::error_codes::NOT_MANAGED.code;
const ROLLBACK_ERR_GENERATION_NOT_FOUND: &str =
    website_spec::rollback::v0_1::error_codes::GENERATION_NOT_FOUND.code;

const GENERATIONS_TASK: &str = "https://trusttasks.org/spec/vtc/website/generations/list/0.1";
const ROLLBACK_TASK: &str = "https://trusttasks.org/spec/vtc/website/rollback/0.1";

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

/// Point the website at a fresh directory in `mode`. The directory is returned
/// so it outlives the test's requests.
async fn configure_website(fix: &Fixture, mode: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = fix._vtc.state.config.write().await;
    cfg.website.root_dir = Some(dir.path().to_path_buf());
    cfg.website.deploy_mode = mode.to_string();
    dir
}

/// An authenticated admin call returning the whole JSON body.
async fn admin_call(fix: &Fixture, method: &str, uri: &str, task: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Trust-Task", task)
        .header("Authorization", format!("Bearer {}", fix.token))
        .body(Body::empty())
        .unwrap();
    let res = fix.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn deleting_a_missing_file_is_the_declared_not_found() {
    let fix = build_fixture().await;
    let _root = configure_website(&fix, "live").await;
    let (status, body) = admin_call(
        &fix,
        "DELETE",
        "/v1/website/files/never-written.txt",
        DELETE_TASK,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(rest_error_code(&body), FILES_DELETE_ERR_NOT_FOUND, "{body}");
}

/// Live mode has no generations, so both managed-only tasks answer
/// `notManaged` there; in managed mode a label naming nothing is
/// `generationNotFound`. Statuses unchanged (400, 400, 404).
#[tokio::test]
async fn the_generation_tasks_answer_with_the_codes_their_specs_declare() {
    let fix = build_fixture().await;
    let live = configure_website(&fix, "live").await;

    let (status, body) = admin_call(&fix, "GET", "/v1/website/generations", GENERATIONS_TASK).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        rest_error_code(&body),
        GENERATIONS_LIST_ERR_NOT_MANAGED,
        "{body}"
    );

    let (status, body) = admin_call(&fix, "POST", "/v1/website/rollback/1", ROLLBACK_TASK).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(rest_error_code(&body), ROLLBACK_ERR_NOT_MANAGED, "{body}");
    drop(live);

    let _managed = configure_website(&fix, "managed").await;
    let (status, body) = admin_call(&fix, "POST", "/v1/website/rollback/99", ROLLBACK_TASK).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        rest_error_code(&body),
        ROLLBACK_ERR_GENERATION_NOT_FOUND,
        "{body}"
    );
}
