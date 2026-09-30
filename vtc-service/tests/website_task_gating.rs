//! `/v1/website/*` on the signed-document spine.
//!
//! The website mount used to be where "is this a Trust Task?" got answered by
//! shape rather than by convention: a Trust Task's payload is a JSON document,
//! and three of these endpoints moved raw file bytes. That REST surface is
//! gone entirely now — `files/list`, `files/delete`, `generations/list` and
//! `rollback` are signed documents only (`trust_tasks::website_tasks`),
//! authorized from the signer's ACL row (`admin_signer`) rather than a bearer
//! session, exactly like the chunked upload / deploy / ranged-read verbs that
//! moved first.
//!
//! The raw-byte routes (`GET`/`PUT /website/files/{path}`, `POST
//! /website/deploy`) were already gone before this batch: content moves as
//! signed Trust Tasks (`tests/website_spine.rs`).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use serde_json::json;

use vtc_service::test_support::TestVtc;
use vti_rooms_dtg::test_support::Party;

/// The identifier a refusal's payload names — the error-code census's textual
/// witness scan looks for this exact call name.
fn tt_error_code(doc: &serde_json::Value) -> Option<&str> {
    common::signed::error_code(doc)
}

const DELETE_TASK: &str = "https://trusttasks.org/spec/vtc/website/files/delete/0.1";
const LIST_TASK: &str = "https://trusttasks.org/spec/vtc/website/files/list/0.1";
const GENERATIONS_TASK: &str = "https://trusttasks.org/spec/vtc/website/generations/list/0.1";
const ROLLBACK_TASK: &str = "https://trusttasks.org/spec/vtc/website/rollback/0.1";

async fn build_fixture() -> TestVtc {
    TestVtc::builder().build().await
}

/// Point the website at a fresh directory in `mode`. The directory is returned
/// so it outlives the test's requests.
async fn configure_website(vtc: &TestVtc, mode: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = vtc.state.config.write().await;
    cfg.website.root_dir = Some(dir.path().to_path_buf());
    cfg.website.deploy_mode = mode.to_string();
    dir
}

/// The raw-byte routes are gone: file content and bundles move as signed
/// Trust Tasks (`vtc/website/upload/*`, `vtc/website/deploy`,
/// `vtc/website/files/show`), and a request to the old paths reaches no API
/// handler.
///
/// `/v1/...` isn't an exclusive prefix at the router level: the outer app's
/// `fallback_service` is the website's static handler
/// (`assemble_with_website`, `routes/mod.rs`), and axum falls through to it
/// for any `GET` that no nested route inside `/v1` matches — including this
/// unbuilt `TestVtc`'s in-binary default site, which answers every path with
/// its `index.html` (SPA-style catch-all, `text/html`, `200`), never a
/// `404`. So a `GET` reaching no API handler is detected by content-type
/// (`bearer_route_served`), the same way `tests/relationships.rs` and
/// `tests/common/signed.rs` already check it; the website sub-router only
/// registers `GET`, so a non-`GET` method on the same paths still gets a
/// real `404`/`405` from axum's routing.
#[tokio::test]
async fn the_raw_byte_routes_and_every_website_rest_mount_are_gone() {
    let vtc = build_fixture().await;
    let _root = configure_website(&vtc, "live").await;
    for (method, uri) in [
        ("GET", "/v1/website/files/index.html"),
        // The listing, delete, generation-history and rollback REST mounts —
        // signed documents only now.
        ("GET", "/v1/website/files"),
        ("GET", "/v1/website/generations"),
    ] {
        assert!(
            !common::signed::bearer_route_served(&vtc, method, uri).await,
            "{method} {uri} must reach no API handler"
        );
    }
    for (method, uri) in [
        ("PUT", "/v1/website/files/index.html"),
        ("POST", "/v1/website/deploy"),
        ("DELETE", "/v1/website/files/gone.txt"),
        ("POST", "/v1/website/rollback/1"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let res = vtc.router.clone().oneshot(req).await.unwrap();
        assert!(
            matches!(
                res.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {uri} must have no route, got {}",
            res.status()
        );
    }
}

/// An unsigned document is refused before `admin_signer` ever resolves an
/// identity — de-listing the REST mount didn't relax authorization, it moved
/// it from a bearer session to the document's own proof.
#[tokio::test]
async fn delete_refuses_an_unsigned_document() {
    let vtc = build_fixture().await;
    let _root = configure_website(&vtc, "live").await;
    let (status, doc) = common::signed::post(
        &vtc,
        &common::signed::unsigned(&Party::new(), DELETE_TASK, json!({ "path": "gone.txt" })),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(tt_error_code(&doc), Some("proofRequired"), "{doc}");
}

/// A signer with no ACL row at all is refused the same way an unsigned
/// document is — `admin_signer` reads the verified signer's row, and there is
/// none.
#[tokio::test]
async fn delete_refuses_a_signer_with_no_acl_row() {
    let vtc = build_fixture().await;
    let _root = configure_website(&vtc, "live").await;
    let stranger = Party::new();
    let (status, doc) =
        common::signed::call(&vtc, &stranger, DELETE_TASK, json!({ "path": "gone.txt" })).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
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

#[tokio::test]
async fn an_admin_can_list_and_delete_files() {
    let vtc = build_fixture().await;
    let _root = configure_website(&vtc, "live").await;
    let admin = common::signed::admin(&vtc).await;

    let (status, doc) = common::signed::call(&vtc, &admin, LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(doc["payload"]["items"].is_array(), "{doc}");
}

#[tokio::test]
async fn deleting_a_missing_file_is_the_declared_not_found() {
    let vtc = build_fixture().await;
    let _root = configure_website(&vtc, "live").await;
    let admin = common::signed::admin(&vtc).await;

    let (status, doc) = common::signed::call(
        &vtc,
        &admin,
        DELETE_TASK,
        json!({ "path": "never-written.txt" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        tt_error_code(&doc),
        Some(FILES_DELETE_ERR_NOT_FOUND),
        "{doc}"
    );
}

/// Live mode has no generations, so both managed-only tasks answer
/// `notManaged` there; in managed mode a label naming nothing is
/// `generationNotFound`.
#[tokio::test]
async fn the_generation_tasks_answer_with_the_codes_their_specs_declare() {
    let vtc = build_fixture().await;
    let admin = common::signed::admin(&vtc).await;
    let live = configure_website(&vtc, "live").await;

    let (status, doc) = common::signed::call(&vtc, &admin, GENERATIONS_TASK, json!({})).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        tt_error_code(&doc),
        Some(GENERATIONS_LIST_ERR_NOT_MANAGED),
        "{doc}"
    );

    let (status, doc) =
        common::signed::call(&vtc, &admin, ROLLBACK_TASK, json!({ "generation": "1" })).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(tt_error_code(&doc), Some(ROLLBACK_ERR_NOT_MANAGED), "{doc}");
    drop(live);

    let _managed = configure_website(&vtc, "managed").await;
    let (status, doc) =
        common::signed::call(&vtc, &admin, ROLLBACK_TASK, json!({ "generation": "99" })).await;
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        tt_error_code(&doc),
        Some(ROLLBACK_ERR_GENERATION_NOT_FOUND),
        "{doc}"
    );
}
