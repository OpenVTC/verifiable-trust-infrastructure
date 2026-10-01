//! The website's content as signed Trust Tasks (`trust_tasks::website_tasks`):
//! a chunked upload (`vtc/website/upload/{begin,chunk,commit,abort}`),
//! `vtc/website/deploy`, and ranged reads (`vtc/website/files/show`).
//!
//! What is pinned: hashes are committed at `begin` and verified at `commit`
//! (each chunk against its digest on arrival, the whole against the SHA-256
//! before anything is written); chunks are at most 256 KiB, and a full-size
//! chunk document is admitted for an administrator; upload state belongs to
//! the identity that began it, is bounded per identity, and expires; and each
//! refusal carries the code its specification declares.

use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{admin, call, error_code, party_with_role, payload};
use vtc_service::acl::VtcRole;
use vtc_service::test_support::TestVtc;

const BEGIN: &str = "https://trusttasks.org/spec/vtc/website/upload/begin/0.1";
const CHUNK: &str = "https://trusttasks.org/spec/vtc/website/upload/chunk/0.1";
const COMMIT: &str = "https://trusttasks.org/spec/vtc/website/upload/commit/0.1";
const ABORT: &str = "https://trusttasks.org/spec/vtc/website/upload/abort/0.1";
const DEPLOY: &str = "https://trusttasks.org/spec/vtc/website/deploy/0.1";
const SHOW: &str = "https://trusttasks.org/spec/vtc/website/files/show/0.1";

const KIB: usize = 1024;
/// The smallest chunk the transfer allows.
const MIN: usize = 16 * KIB;

/// A VTC serving a website from a fresh directory, in `mode`.
async fn vtc(mode: &str) -> (TestVtc, tempfile::TempDir) {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    let dir = tempfile::tempdir().unwrap();
    {
        let mut cfg = vtc.state.config.write().await;
        cfg.website.root_dir = Some(dir.path().join("site"));
        cfg.website.deploy_mode = mode.to_string();
    }
    std::fs::create_dir_all(dir.path().join("site")).unwrap();
    (vtc, dir)
}

fn digest(bytes: &[u8]) -> String {
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    vta_sdk::protocols::backup_management::chunked::sha256_digest_multibase(&hash)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `begin` for `bytes` at `chunk_size`, toward `target`.
fn begin_for(target: Value, bytes: &[u8], chunk_size: usize) -> Value {
    let digests: Vec<String> = bytes.chunks(chunk_size).map(digest).collect();
    json!({
        "target": target,
        "expectedSha256": hex::encode(Sha256::digest(bytes)),
        "expectedSizeBytes": bytes.len(),
        "chunks": { "chunkSize": chunk_size, "chunkCount": digests.len(), "chunkDigests": digests },
    })
}

/// Begin an upload and send every chunk; the upload id.
async fn uploaded(
    vtc: &TestVtc,
    by: &Party,
    target: Value,
    bytes: &[u8],
    chunk_size: usize,
) -> String {
    let (status, doc) = call(vtc, by, BEGIN, begin_for(target, bytes, chunk_size)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let id = payload(&doc)["uploadId"].as_str().unwrap().to_string();
    for (index, chunk) in bytes.chunks(chunk_size).enumerate() {
        let (status, doc) = call(
            vtc,
            by,
            CHUNK,
            json!({ "uploadId": id, "index": index, "digestMultibase": digest(chunk), "data": b64(chunk) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "chunk {index}: {doc}");
    }
    id
}

fn file(path: &str) -> Value {
    json!({ "kind": "file", "path": path })
}

fn bundle(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut gz);
        for (name, body) in entries {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(name).unwrap();
            hdr.set_size(body.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append(&hdr, *body).unwrap();
        }
        tar.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[tokio::test]
async fn a_file_is_uploaded_in_chunks_committed_and_read_back() {
    let (vtc, dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    let body = b"<h1>Kernel developers</h1>".repeat(2000);

    let id = uploaded(&vtc, &admin, file("docs/index.html"), &body, MIN).await;
    let (status, doc) = call(&vtc, &admin, COMMIT, json!({ "uploadId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let etag = hex::encode(Sha256::digest(&body));
    assert_eq!(payload(&doc)["file"]["etag"], etag.as_str(), "{doc}");
    assert_eq!(
        std::fs::read(dir.path().join("site/docs/index.html")).unwrap(),
        body
    );

    // A committed upload takes nothing more.
    let (_, doc) = call(
        &vtc,
        &admin,
        CHUNK,
        json!({ "uploadId": id, "index": 0, "digestMultibase": digest(&body[..MIN]), "data": b64(&body[..MIN]) }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/upload/chunk:notFound"),
        "{doc}"
    );

    // A ranged read, then the rest.
    let (_, doc) = call(
        &vtc,
        &admin,
        SHOW,
        json!({ "path": "docs/index.html", "length": 100 }),
    )
    .await;
    let first = payload(&doc);
    assert_eq!(first["etag"], etag.as_str());
    assert_eq!(first["sizeBytes"], body.len());
    assert_eq!(first["contentType"], "text/html");
    assert_eq!(first["complete"], false);
    let (_, doc) = call(
        &vtc,
        &admin,
        SHOW,
        json!({ "path": "docs/index.html", "offset": 100, "ifMatch": etag }),
    )
    .await;
    let rest = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload(&doc)["data"].as_str().unwrap())
        .unwrap();
    assert_eq!(rest, body[100..]);
    assert_eq!(payload(&doc)["complete"], true);
}

/// Hashes are committed at `begin`: a chunk that is not what its digest said
/// is refused on arrival, and a commit before every chunk has arrived is
/// `incomplete` and leaves the upload open.
#[tokio::test]
async fn chunks_are_checked_against_the_manifest_committed_at_begin() {
    let (vtc, _dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    let body = vec![7u8; 3 * MIN + 10];
    let (_, doc) = call(&vtc, &admin, BEGIN, begin_for(file("a.txt"), &body, MIN)).await;
    let id = payload(&doc)["uploadId"].as_str().unwrap().to_string();

    let forged = vec![8u8; MIN];
    let (_, doc) = call(
        &vtc,
        &admin,
        CHUNK,
        json!({ "uploadId": id, "index": 0, "digestMultibase": digest(&forged), "data": b64(&forged) }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/upload/chunk:chunkMismatch"),
        "{doc}"
    );
    let (_, doc) = call(
        &vtc,
        &admin,
        CHUNK,
        json!({ "uploadId": id, "index": 9, "digestMultibase": digest(&body[..MIN]), "data": b64(&body[..MIN]) }),
    )
    .await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/upload/chunk:chunkOutOfRange"),
        "{doc}"
    );

    let (_, doc) = call(&vtc, &admin, COMMIT, json!({ "uploadId": id })).await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/upload/commit:incomplete"),
        "{doc}"
    );
    assert_eq!(payload(&doc)["details"]["missingCount"], 4, "{doc}");
}

/// `begin`'s refusals, before anything is reserved.
#[tokio::test]
async fn begin_refuses_what_could_never_commit() {
    let (vtc, _dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    let body = b"hello".to_vec();
    let code = |doc: &Value| error_code(doc).unwrap_or_default().to_string();

    let (_, doc) = call(&vtc, &admin, BEGIN, begin_for(file(".env"), &body, MIN)).await;
    assert_eq!(code(&doc), "vtc/website/upload/begin:pathRefused", "{doc}");

    let mut wrong = begin_for(file("a.txt"), &body, MIN);
    wrong["chunks"]["chunkCount"] = json!(7);
    let (_, doc) = call(&vtc, &admin, BEGIN, wrong).await;
    assert_eq!(
        code(&doc),
        "vtc/website/upload/begin:invalidManifest",
        "{doc}"
    );

    let big = 20 * 1024 * 1024;
    let mut huge = begin_for(file("a.txt"), &body, MIN);
    huge["expectedSizeBytes"] = json!(big);
    let (_, doc) = call(&vtc, &admin, BEGIN, huge).await;
    assert_eq!(code(&doc), "vtc/website/upload/begin:tooLarge", "{doc}");

    let (_, doc) = call(
        &vtc,
        &admin,
        BEGIN,
        json!({
            "target": { "kind": "bundle", "path": "x" },
            "expectedSha256": hex::encode(Sha256::digest(&body)),
            "expectedSizeBytes": body.len(),
            "chunks": { "chunkSize": MIN, "chunkCount": 1, "chunkDigests": [digest(&body)] },
        }),
    )
    .await;
    assert_eq!(code(&doc), "malformedRequest", "{doc}");

    let (vtc, _dir) = self::vtc("managed").await;
    let admin = crate::common::signed::admin(&vtc).await;
    let (_, doc) = call(&vtc, &admin, BEGIN, begin_for(file("a.txt"), &body, MIN)).await;
    assert_eq!(
        code(&doc),
        "vtc/website/upload/begin:singleFileWritesDisabled",
        "{doc}"
    );
}

/// `ifMatch` is committed at `begin` and checked at `commit`.
#[tokio::test]
async fn a_stale_if_match_fails_the_commit() {
    let (vtc, dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    std::fs::write(dir.path().join("site/page.html"), b"current").unwrap();
    let body = b"replacement".to_vec();
    let target = json!({ "kind": "file", "path": "page.html", "ifMatch": hex::encode(Sha256::digest(b"stale")) });
    let id = uploaded(&vtc, &admin, target, &body, MIN).await;
    let (_, doc) = call(&vtc, &admin, COMMIT, json!({ "uploadId": id })).await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/upload/commit:preconditionFailed"),
        "{doc}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("site/page.html")).unwrap(),
        b"current"
    );
}

/// A bundle is staged at commit and published by deploy, which consumes it.
#[tokio::test]
async fn a_bundle_is_staged_then_deployed() {
    let (vtc, dir) = vtc("managed").await;
    let admin = admin(&vtc).await;
    let bytes = bundle(&[("index.html", b"<h1>v1</h1>"), ("css/site.css", b"body{}")]);
    let id = uploaded(&vtc, &admin, json!({ "kind": "bundle" }), &bytes, MIN).await;

    let (status, doc) = call(&vtc, &admin, COMMIT, json!({ "uploadId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(payload(&doc)["stagedUntil"].is_string(), "{doc}");
    assert!(
        !dir.path().join("site/current").exists(),
        "commit does not change the site"
    );

    let (status, doc) = call(&vtc, &admin, DEPLOY, json!({ "uploadId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(payload(&doc)["deployMode"], "managed");
    assert_eq!(payload(&doc)["targetGeneration"], 1);
    assert_eq!(
        std::fs::read(dir.path().join("site/current/index.html")).unwrap(),
        b"<h1>v1</h1>"
    );
    let (_, doc) = call(&vtc, &admin, DEPLOY, json!({ "uploadId": id })).await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/deploy:notFound"),
        "{doc}"
    );

    // A bundle the site refuses is refused whole.
    let bad = bundle(&[("run.php", b"<?php ?>")]);
    let id = uploaded(&vtc, &admin, json!({ "kind": "bundle" }), &bad, MIN).await;
    call(&vtc, &admin, COMMIT, json!({ "uploadId": id })).await;
    let (_, doc) = call(&vtc, &admin, DEPLOY, json!({ "uploadId": id })).await;
    assert_eq!(
        error_code(&doc),
        Some("vtc/website/deploy:bundleRefused"),
        "{doc}"
    );
}

/// An upload is its beginner's: another administrator is told `notFound`.
/// Abort is idempotent.
#[tokio::test]
async fn an_upload_belongs_to_its_identity_and_aborts_once() {
    let (vtc, _dir) = vtc("live").await;
    let alice = admin(&vtc).await;
    let bob = admin(&vtc).await;
    let body = b"abc".to_vec();
    let (_, doc) = call(&vtc, &alice, BEGIN, begin_for(file("a.txt"), &body, MIN)).await;
    let id = payload(&doc)["uploadId"].as_str().unwrap().to_string();

    for (task, code) in [
        (COMMIT, "vtc/website/upload/commit:notFound"),
        (ABORT, "vtc/website/upload/abort:notFound"),
        (DEPLOY, "vtc/website/deploy:notFound"),
    ] {
        let (_, doc) = call(&vtc, &bob, task, json!({ "uploadId": id })).await;
        assert_eq!(error_code(&doc), Some(code), "{task}: {doc}");
    }
    let (_, doc) = call(&vtc, &alice, ABORT, json!({ "uploadId": id })).await;
    assert_eq!(payload(&doc)["aborted"], true, "{doc}");
    let (_, doc) = call(&vtc, &alice, ABORT, json!({ "uploadId": id })).await;
    assert_eq!(payload(&doc)["aborted"], false, "{doc}");
}

/// Upload state is bounded per identity: a fourth open upload is refused
/// until one ends.
#[tokio::test]
async fn open_uploads_are_bounded_per_identity() {
    let (vtc, _dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    let body = b"abc".to_vec();
    let mut ids = Vec::new();
    for i in 0..vti_common::backup_transfer::MAX_OPEN_BUNDLES_PER_DID {
        let (status, doc) = call(
            &vtc,
            &admin,
            BEGIN,
            begin_for(file(&format!("f{i}.txt")), &body, MIN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        ids.push(payload(&doc)["uploadId"].as_str().unwrap().to_string());
    }
    let (status, doc) = call(&vtc, &admin, BEGIN, begin_for(file("more.txt"), &body, MIN)).await;
    assert!(!status.is_success(), "{doc}");
    call(&vtc, &admin, ABORT, json!({ "uploadId": ids[0] })).await;
    let (status, doc) = call(&vtc, &admin, BEGIN, begin_for(file("more.txt"), &body, MIN)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

/// A full 256 KiB chunk — a ~350 KiB document — is admitted for an
/// administrator; a larger chunk size is refused at begin.
#[tokio::test]
async fn a_full_size_chunk_fits_and_a_larger_one_is_refused() {
    let (vtc, dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    let body: Vec<u8> = (0..(256 * KIB + 10)).map(|i| (i % 251) as u8).collect();
    let id = uploaded(&vtc, &admin, file("big.bin"), &body, 256 * KIB).await;
    let (status, doc) = call(&vtc, &admin, COMMIT, json!({ "uploadId": id })).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(
        std::fs::read(dir.path().join("site/big.bin")).unwrap(),
        body
    );

    let (_, doc) = call(
        &vtc,
        &admin,
        BEGIN,
        begin_for(file("x.bin"), &body, 256 * KIB + 1),
    )
    .await;
    assert!(error_code(&doc).is_some(), "{doc}");
}

#[tokio::test]
async fn files_show_answers_its_declared_codes() {
    let (vtc, dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    std::fs::write(dir.path().join("site/a.txt"), b"abc").unwrap();
    for (body, code) in [
        (
            json!({ "path": "missing.txt" }),
            "vtc/website/files/show:notFound",
        ),
        (
            json!({ "path": ".secret" }),
            "vtc/website/files/show:pathRefused",
        ),
        (
            json!({ "path": "a.txt", "ifMatch": hex::encode(Sha256::digest(b"other")) }),
            "vtc/website/files/show:changed",
        ),
        (
            json!({ "path": "a.txt", "offset": 4 }),
            "vtc/website/files/show:rangeOutOfBounds",
        ),
    ] {
        let (_, doc) = call(&vtc, &admin, SHOW, body.clone()).await;
        assert_eq!(error_code(&doc), Some(code), "{body}: {doc}");
    }
    let (_, doc) = call(&vtc, &admin, SHOW, json!({ "path": "a.txt", "offset": 3 })).await;
    assert_eq!(payload(&doc)["data"], "", "{doc}");
    assert_eq!(payload(&doc)["complete"], true);
}

/// The routes took `AdminAuth`.
#[tokio::test]
async fn below_an_administrator_is_refused() {
    let (vtc, _dir) = vtc("live").await;
    let moderator = party_with_role(&vtc, VtcRole::Moderator, &[]).await;
    let (status, _) = call(
        &vtc,
        &moderator,
        BEGIN,
        begin_for(file("a.txt"), b"abc", MIN),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&vtc, &moderator, SHOW, json!({ "path": "a.txt" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ─── the codes the specifications declare ───────────────────────────────

const BEGIN_ERR_NOT_CONFIGURED: &str = "vtc/website/upload/begin:notConfigured";
const BEGIN_ERR_TOO_LARGE: &str = "vtc/website/upload/begin:tooLarge";
const BEGIN_ERR_PATH_REFUSED: &str = "vtc/website/upload/begin:pathRefused";
const BEGIN_ERR_SINGLE_FILE_WRITES_DISABLED: &str =
    "vtc/website/upload/begin:singleFileWritesDisabled";
const BEGIN_ERR_INVALID_MANIFEST: &str = "vtc/website/upload/begin:invalidManifest";
const CHUNK_ERR_NOT_FOUND: &str = "vtc/website/upload/chunk:notFound";
const CHUNK_ERR_CHUNK_OUT_OF_RANGE: &str = "vtc/website/upload/chunk:chunkOutOfRange";
const CHUNK_ERR_CHUNK_MISMATCH: &str = "vtc/website/upload/chunk:chunkMismatch";
const COMMIT_ERR_NOT_FOUND: &str = "vtc/website/upload/commit:notFound";
const COMMIT_ERR_INCOMPLETE: &str = "vtc/website/upload/commit:incomplete";
const COMMIT_ERR_DIGEST_MISMATCH: &str = "vtc/website/upload/commit:digestMismatch";
const COMMIT_ERR_PRECONDITION_FAILED: &str = "vtc/website/upload/commit:preconditionFailed";
const COMMIT_ERR_PATH_REFUSED: &str = "vtc/website/upload/commit:pathRefused";
const COMMIT_ERR_SINGLE_FILE_WRITES_DISABLED: &str =
    "vtc/website/upload/commit:singleFileWritesDisabled";
const ABORT_ERR_NOT_FOUND: &str = "vtc/website/upload/abort:notFound";
const DEPLOY_ERR_NOT_FOUND: &str = "vtc/website/deploy:notFound";
const DEPLOY_ERR_BUNDLE_REFUSED: &str = "vtc/website/deploy:bundleRefused";
const SHOW_ERR_NOT_FOUND: &str = "vtc/website/files/show:notFound";
const SHOW_ERR_PATH_REFUSED: &str = "vtc/website/files/show:pathRefused";
const SHOW_ERR_CHANGED: &str = "vtc/website/files/show:changed";
const SHOW_ERR_RANGE_OUT_OF_BOUNDS: &str = "vtc/website/files/show:rangeOutOfBounds";

fn tt_error_code(doc: &Value) -> Option<&str> {
    error_code(doc)
}

/// Every declared code, driven by the case that produces it.
#[tokio::test]
async fn the_codes_the_specifications_declare_are_answered() {
    // A community serving no website.
    let bare = TestVtc::builder().build().await;
    let admin_of_bare = admin(&bare).await;
    let (_, doc) = call(
        &bare,
        &admin_of_bare,
        BEGIN,
        begin_for(file("a.txt"), b"abc", MIN),
    )
    .await;
    assert_eq!(tt_error_code(&doc), Some(BEGIN_ERR_NOT_CONFIGURED), "{doc}");

    let (vtc, dir) = vtc("live").await;
    let admin = admin(&vtc).await;
    let body = vec![3u8; MIN + 5];
    let ask = |task: &'static str, payload: Value| {
        let (vtc, admin) = (&vtc, &admin);
        async move { call(vtc, admin, task, payload).await.1 }
    };

    let mut huge = begin_for(file("a.txt"), &body, MIN);
    huge["expectedSizeBytes"] = json!(64 * 1024 * 1024);
    assert_eq!(
        tt_error_code(&ask(BEGIN, huge).await),
        Some(BEGIN_ERR_TOO_LARGE)
    );
    assert_eq!(
        tt_error_code(&ask(BEGIN, begin_for(file(".hidden"), &body, MIN)).await),
        Some(BEGIN_ERR_PATH_REFUSED)
    );
    let mut wrong = begin_for(file("a.txt"), &body, MIN);
    wrong["chunks"]["chunkCount"] = json!(9);
    assert_eq!(
        tt_error_code(&ask(BEGIN, wrong).await),
        Some(BEGIN_ERR_INVALID_MANIFEST)
    );

    // Chunks.
    let doc = ask(BEGIN, begin_for(file("a.txt"), &body, MIN)).await;
    let id = payload(&doc)["uploadId"].as_str().unwrap().to_string();
    let unknown = uuid::Uuid::new_v4().to_string();
    let chunk0 = |upload: &str, index: u64, bytes: &[u8]| json!({ "uploadId": upload, "index": index, "digestMultibase": digest(bytes), "data": b64(bytes) });
    assert_eq!(
        tt_error_code(&ask(CHUNK, chunk0(&unknown, 0, &body[..MIN])).await),
        Some(CHUNK_ERR_NOT_FOUND)
    );
    assert_eq!(
        tt_error_code(&ask(CHUNK, chunk0(&id, 5, &body[..MIN])).await),
        Some(CHUNK_ERR_CHUNK_OUT_OF_RANGE)
    );
    assert_eq!(
        tt_error_code(&ask(CHUNK, chunk0(&id, 0, &vec![9u8; MIN])).await),
        Some(CHUNK_ERR_CHUNK_MISMATCH)
    );

    // Commits.
    assert_eq!(
        tt_error_code(&ask(COMMIT, json!({ "uploadId": unknown })).await),
        Some(COMMIT_ERR_NOT_FOUND)
    );
    assert_eq!(
        tt_error_code(&ask(COMMIT, json!({ "uploadId": id })).await),
        Some(COMMIT_ERR_INCOMPLETE)
    );
    // An identity holds three open uploads at most; end this one.
    ask(ABORT, json!({ "uploadId": id })).await;
    // Every chunk right, the committed whole wrong.
    let mut lying = begin_for(file("b.txt"), &body, MIN);
    lying["expectedSha256"] = json!(hex::encode(Sha256::digest(b"something else")));
    let doc = ask(BEGIN, lying).await;
    let liar = payload(&doc)["uploadId"].as_str().unwrap().to_string();
    for (i, c) in body.chunks(MIN).enumerate() {
        ask(CHUNK, chunk0(&liar, i as u64, c)).await;
    }
    assert_eq!(
        tt_error_code(&ask(COMMIT, json!({ "uploadId": liar })).await),
        Some(COMMIT_ERR_DIGEST_MISMATCH)
    );
    std::fs::write(dir.path().join("site/c.txt"), b"now").unwrap();
    let stale =
        json!({ "kind": "file", "path": "c.txt", "ifMatch": hex::encode(Sha256::digest(b"then")) });
    let pre = uploaded(&vtc, &admin, stale, &body, MIN).await;
    assert_eq!(
        tt_error_code(&ask(COMMIT, json!({ "uploadId": pre })).await),
        Some(COMMIT_ERR_PRECONDITION_FAILED)
    );
    ask(ABORT, json!({ "uploadId": pre })).await;
    // The path and the mode are checked again at commit.
    let late = uploaded(&vtc, &admin, file("d.txt"), &body, MIN).await;
    let other = uploaded(&vtc, &admin, file("e.txt"), &body, MIN).await;
    vtc.state
        .config
        .write()
        .await
        .website
        .executable_blocklist
        .push(".txt".into());
    assert_eq!(
        tt_error_code(&ask(COMMIT, json!({ "uploadId": late })).await),
        Some(COMMIT_ERR_PATH_REFUSED)
    );
    vtc.state.config.write().await.website.deploy_mode = "managed".into();
    assert_eq!(
        tt_error_code(&ask(COMMIT, json!({ "uploadId": other })).await),
        Some(COMMIT_ERR_SINGLE_FILE_WRITES_DISABLED)
    );
    assert_eq!(
        tt_error_code(&ask(BEGIN, begin_for(file("f.html"), &body, MIN)).await),
        Some(BEGIN_ERR_SINGLE_FILE_WRITES_DISABLED)
    );

    assert_eq!(
        tt_error_code(&ask(ABORT, json!({ "uploadId": unknown })).await),
        Some(ABORT_ERR_NOT_FOUND)
    );
    assert_eq!(
        tt_error_code(&ask(DEPLOY, json!({ "uploadId": unknown })).await),
        Some(DEPLOY_ERR_NOT_FOUND)
    );
    let refused = bundle(&[("run.php", b"<?php ?>")]);
    let staged = uploaded(&vtc, &admin, json!({ "kind": "bundle" }), &refused, MIN).await;
    ask(COMMIT, json!({ "uploadId": staged })).await;
    assert_eq!(
        tt_error_code(&ask(DEPLOY, json!({ "uploadId": staged })).await),
        Some(DEPLOY_ERR_BUNDLE_REFUSED)
    );

    // Reads (back in live mode, with the blocklist restored).
    {
        let mut cfg = vtc.state.config.write().await;
        cfg.website.deploy_mode = "live".into();
        cfg.website.executable_blocklist.retain(|e| e != ".txt");
    }
    assert_eq!(
        tt_error_code(&ask(SHOW, json!({ "path": "nothing.txt" })).await),
        Some(SHOW_ERR_NOT_FOUND)
    );
    assert_eq!(
        tt_error_code(&ask(SHOW, json!({ "path": ".env" })).await),
        Some(SHOW_ERR_PATH_REFUSED)
    );
    assert_eq!(
        tt_error_code(
            &ask(
                SHOW,
                json!({ "path": "c.txt", "ifMatch": hex::encode(Sha256::digest(b"then")) })
            )
            .await
        ),
        Some(SHOW_ERR_CHANGED)
    );
    assert_eq!(
        tt_error_code(&ask(SHOW, json!({ "path": "c.txt", "offset": 99 })).await),
        Some(SHOW_ERR_RANGE_OUT_OF_BOUNDS)
    );
}
