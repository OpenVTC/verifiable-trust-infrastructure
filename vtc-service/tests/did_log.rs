//! Integration coverage for `GET /.well-known/did.jsonl`.
//!
//! The VTC publishes exactly one did:webvh log — its own — at the
//! `.well-known` path its `did:webvh:<scid>:<host>` resolves to.
//! Tests verify the happy path + the boundary cases the design doc
//! (`tasks/vtc-mvp/vta-driven-keys.md` §10) calls out:
//!
//! - Trust-Task-exempt (no header → 200).
//! - 404 when `config.vtc_did`'s log file is absent on disk.
//! - 404 when the configured DID's SCID is malformed (no path
//!   traversal reaches the filesystem).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use vtc_service::test_support::TestVtc;

// A real `did:webvh` is `did:webvh:<scid>:<host>[:<path>]` — the SCID is
// the FIRST label after the method, the host second (see the did:webvh
// spec and `vta-sdk::session::url_from_did`, which reads the host as the
// 2nd component). This is the serverless shape the VTC mints for itself;
// it resolves to `https://<host>/.well-known/did.jsonl`. The host carries
// dots, which is exactly the case that must round-trip.
const VTC_DID: &str = "did:webvh:abc123:vtc.example.com";
// The setup wizard writes the log to `did/<label>.jsonl`, where <label>
// is the *final* colon component of the DID — for this serverless DID
// that's the host. The serve route reads back the same name, so tests
// seed the file under this label, not the SCID.
const VTC_LOG_LABEL: &str = "vtc.example.com";

struct Fixture {
    router: axum::Router,
    data_dir: std::path::PathBuf,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture(vtc_did: &str) -> Fixture {
    let vtc = TestVtc::builder().vtc_did(vtc_did).build().await;
    let data_dir = vtc.data_dir().to_path_buf();
    Fixture {
        router: vtc.router.clone(),
        data_dir,
        _vtc: vtc,
    }
}

fn seed_did_log(data_dir: &std::path::Path, scid: &str, content: &str) {
    let did_dir = data_dir.join("did");
    std::fs::create_dir_all(&did_dir).expect("create did dir");
    std::fs::write(did_dir.join(format!("{scid}.jsonl")), content).expect("write did log");
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, Vec<u8>, Option<String>) {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let ct = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec(), ct)
}

#[tokio::test]
async fn serverless_dotted_host_did_resolves_as_jsonl() {
    // The regression this whole file exists for: a serverless VTC DID
    // `did:webvh:<scid>:<host>` whose host carries dots must resolve at
    // `/.well-known/did.jsonl`. The old SCID-grammar gate rejected the
    // dots and 404'd the VTC's own DID.
    let fix = build_fixture(VTC_DID).await;
    let log = r#"{"versionId":"1-abc","parameters":{}}
{"versionId":"2-def","parameters":{}}
"#;
    seed_did_log(&fix.data_dir, VTC_LOG_LABEL, log);

    let (status, body, ct) = get(&fix.router, "/.well-known/did.jsonl").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, log.as_bytes());
    assert_eq!(ct.as_deref(), Some("application/jsonl"));
}

#[tokio::test]
async fn did_log_response_carries_nosniff() {
    // P3.7: the log is served at the parent root, outside the website
    // sub-router's security-headers middleware — a browser must not
    // content-sniff the jsonl into something executable.
    let fix = build_fixture(VTC_DID).await;
    seed_did_log(&fix.data_dir, VTC_LOG_LABEL, "{\"versionId\":\"1-abc\"}\n");

    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/did.jsonl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
    );
}

#[tokio::test]
async fn returns_404_when_only_a_foreign_label_log_exists() {
    // The VTC serves exactly its own DID's log. A stray log file under
    // some other label on disk must not be served — we read only the
    // label derived from `config.vtc_did`.
    let fix = build_fixture(VTC_DID).await;
    seed_did_log(&fix.data_dir, "different", "{}");

    let (status, _, _) = get(&fix.router, "/.well-known/did.jsonl").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn returns_404_when_file_missing() {
    let fix = build_fixture(VTC_DID).await;
    // no seed_did_log — file absent
    let (status, _, _) = get(&fix.router, "/.well-known/did.jsonl").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn returns_404_when_configured_label_would_traverse() {
    // The label is taken from `config.vtc_did`, not the URL. A
    // configured DID whose final component contains path-traversal
    // characters is rejected before any filesystem read, so it can't
    // escape the `did/` directory.
    let fix = build_fixture("did:webvh:abc123:../../etc/passwd").await;
    let (status, _, _) = get(&fix.router, "/.well-known/did.jsonl").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_is_trust_task_exempt() {
    // No `Trust-Task` header should still serve the response; if
    // the route was Trust-Task-gated this would 400.
    let fix = build_fixture(VTC_DID).await;
    seed_did_log(&fix.data_dir, VTC_LOG_LABEL, "{}");

    let res = fix
        .router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/did.jsonl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
}
