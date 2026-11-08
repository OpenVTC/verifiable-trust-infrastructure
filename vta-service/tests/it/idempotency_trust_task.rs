//! Acceptance tests for Trust-Task idempotency: the **lost-reply** contract.
//!
//! # What is being tested, and why it needs a test at all
//!
//! A client's request times out. Usually it never arrived, so retrying is
//! correct. Sometimes the VTA processed it and only the reply was lost — and
//! there, a retry produces a *second durable effect*. That second effect is
//! invisible to the party responsible for it, which is exactly why it needs a
//! test rather than an argument: the failure mode is silence.
//!
//! Every test here simulates the lost reply the honest way — by submitting the
//! **same document twice** and then counting what actually exists on the server.
//! Asserting that the second call returned `200` would prove nothing; two
//! successful creates also return `200` twice. The assertion that matters is on
//! the *number of keys that exist afterwards*.
//!
//! `no_key_still_creates_two` is the control. Without it, every other assertion
//! in this file would still pass if idempotency silently did nothing and
//! `keys/create` happened to be naturally convergent.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::build_test_app;

const KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";
const KEYS_LIST: &str = "https://trusttasks.org/spec/keys/list/0.2";
/// The caller's signing seed. A `did:key` derived from it, rather than a
/// hand-written DID, because SPEC §7.2 item 7a wants a proof on `keys/create`
/// and item 6 wants the in-band issuer to be the identity the token
/// authenticates — so the DID and the key have to come from one place.
const CALLER_SEED: u8 = 0x40;

fn caller() -> String {
    vta_service::test_support::did_for_seed(CALLER_SEED).0
}
/// A second caller, seeded like the first. It used to be a hand-written DID
/// with no key behind it, which worked while nothing verified proofs — the
/// document claimed that issuer and was signed by the first caller, and the VTA
/// took its word for it. It cannot now.
const OTHER_SEED: u8 = 0x41;

fn other_caller() -> String {
    vta_service::test_support::did_for_seed(OTHER_SEED).0
}
const CONTEXT: &str = "test";

/// A live app with the `test` context in place and an unrestricted admin token
/// for [`caller().as_str()`].
///
/// `keys/create` needs a real context to derive under, so every test that
/// counts keys has to create one first.
async fn app() -> (axum::Router, String) {
    let (router, ctx) = build_test_app().await;
    vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Idempotency tests")
        .await
        .expect("context");
    let token = ctx.mint_token(caller().as_str(), "admin", vec![]).await;
    (router, token)
}

/// As [`app`], plus a second caller's token — for the scoping test.
async fn app_with_second_caller() -> (axum::Router, String, String) {
    let (router, ctx) = build_test_app().await;
    vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Idempotency tests")
        .await
        .expect("context");
    let mine = ctx.mint_token(caller().as_str(), "admin", vec![]).await;
    let theirs = ctx.mint_token(&other_caller(), "admin", vec![]).await;
    (router, mine, theirs)
}

/// A `keys/create` document, optionally carrying an idempotency key.
///
/// `envelope_id` is always fresh, deliberately: that is what a real retry looks
/// like, and it is the reason the envelope-id replay cache cannot catch this
/// case. If these tests reused the envelope id they would be exercising the
/// wrong layer and passing for the wrong reason.
fn create_doc(envelope_id: &str, label: &str, idempotency_key: Option<&str>) -> Value {
    create_doc_as(CALLER_SEED, envelope_id, label, idempotency_key)
}

/// The same document, issued and signed by whichever seeded identity `seed`
/// names. Split out because a proof only counts as the issuer's when the two
/// come from the same key.
fn create_doc_as(seed: u8, envelope_id: &str, label: &str, idempotency_key: Option<&str>) -> Value {
    let mut doc = json!({
        "id": format!("urn:uuid:{envelope_id}"),
        "type": KEYS_CREATE,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": vta_service::test_support::did_for_seed(seed).0,
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": {
            "keyType": "ed25519",
            "derivationPath": "",
            "label": label,
            "contextId": CONTEXT,
        },
    });
    if let Some(k) = idempotency_key {
        doc["idempotencyKey"] = json!(k);
    }
    // Signed last: the proof is taken over the finished document, so attaching
    // it before `idempotencyKey` would sign a document that is not the one sent.
    let mut typed: trust_tasks_rs::TrustTask<Value> =
        serde_json::from_value(doc).expect("envelope deserialises");
    vta_service::test_support::sign_as(seed, &mut typed);
    serde_json::to_value(&typed).expect("envelope serialises")
}

async fn post(router: &axum::Router, token: &str, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// How many keys the caller's context actually holds. The only assertion that
/// distinguishes "deduplicated" from "happened twice and both succeeded".
async fn key_count(router: &axum::Router, token: &str) -> usize {
    let doc = json!({
        "id": format!("urn:uuid:{}", uuid_ish()),
        "type": KEYS_LIST,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": caller(),
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": { "contextId": CONTEXT },
    });
    let (status, body) = post(router, token, &doc).await;
    assert_eq!(status, StatusCode::OK, "keys/list must succeed: {body}");
    body["payload"]["keys"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default()
}

/// Distinct-enough envelope ids without pulling `uuid` into the test's deps.
fn uuid_ish() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("gen-{}", N.fetch_add(1, Ordering::Relaxed))
}

// ── The control ─────────────────────────────────────────────────────

/// Without a key, two submissions create two keys.
///
/// This is what the whole file is measured against. If `keys/create` were
/// naturally convergent, or if the dispatcher deduplicated on something else,
/// every other test here would pass while proving nothing.
#[tokio::test]
async fn no_key_still_creates_two() {
    let (router, token) = app().await;
    let before = key_count(&router, &token).await;

    let (s1, b1) = post(&router, &token, &create_doc("a1", "first", None)).await;
    assert_eq!(s1, StatusCode::OK, "{b1}");
    let (s2, b2) = post(&router, &token, &create_doc("a2", "first", None)).await;
    assert_eq!(s2, StatusCode::OK, "{b2}");

    assert_eq!(
        key_count(&router, &token).await,
        before + 2,
        "an unkeyed resubmission must still create a second key — this is the \
         behaviour idempotency is measured against, and the guarantee that \
         existing callers are unaffected"
    );
}

// ── The contract ────────────────────────────────────────────────────

/// The lost reply: the same request, the same key, a fresh envelope — one key.
#[tokio::test]
async fn a_retry_under_the_same_key_converges_to_one_effect() {
    let (router, token) = app().await;
    let before = key_count(&router, &token).await;

    let (s1, first) = post(
        &router,
        &token,
        &create_doc("b1", "converge", Some("urn:uuid:idem-converge")),
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "{first}");

    // The retry. Different envelope id — a real client mints a fresh one every
    // attempt — same idempotency key, same payload.
    let (s2, second) = post(
        &router,
        &token,
        &create_doc("b2", "converge", Some("urn:uuid:idem-converge")),
    )
    .await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "the retry is answered, not refused: {second}"
    );

    assert_eq!(
        key_count(&router, &token).await,
        before + 1,
        "the retry must not mint a second key"
    );
    assert_eq!(
        first["payload"]["key"]["keyId"], second["payload"]["key"]["keyId"],
        "the retry must be answered with the original result, not a new one"
    );
}

/// Two genuinely separate operations are two operations. A key scopes one
/// attempt-group; it must not collapse distinct work.
#[tokio::test]
async fn distinct_keys_still_create_distinct_effects() {
    let (router, token) = app().await;
    let before = key_count(&router, &token).await;

    for (env, key) in [("c1", "urn:uuid:idem-c1"), ("c2", "urn:uuid:idem-c2")] {
        let (s, b) = post(&router, &token, &create_doc(env, "distinct", Some(key))).await;
        assert_eq!(s, StatusCode::OK, "{b}");
    }

    assert_eq!(key_count(&router, &token).await, before + 2);
}

/// Reusing a key for a *different* request must be refused, not answered from
/// the first request's result. Silently returning the wrong answer is worse
/// than either creating a duplicate or erroring.
#[tokio::test]
async fn the_same_key_with_a_different_payload_is_refused() {
    let (router, token) = app().await;

    let (s1, b1) = post(
        &router,
        &token,
        &create_doc("d1", "original", Some("urn:uuid:idem-conflict")),
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "{b1}");
    let before = key_count(&router, &token).await;

    let (s2, b2) = post(
        &router,
        &token,
        &create_doc("d2", "changed", Some("urn:uuid:idem-conflict")),
    )
    .await;

    assert_ne!(
        s2,
        StatusCode::OK,
        "a key reused with a different payload must be refused: {b2}"
    );
    let msg = b2.to_string();
    assert!(
        msg.contains("idempotency key"),
        "the refusal must name the cause so a caller can fix it: {b2}"
    );
    assert_eq!(
        key_count(&router, &token).await,
        before,
        "a refused request must not have created anything"
    );
}

/// A key is scoped to one operation. Carrying it to a different task would let
/// one request be answered with another's result.
#[tokio::test]
async fn the_same_key_on_a_different_task_is_refused() {
    let (router, token) = app().await;

    let (s1, b1) = post(
        &router,
        &token,
        &create_doc("e1", "cross", Some("urn:uuid:idem-cross")),
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "{b1}");

    // `webvh/dids/create` is also classified `Keyed`, so it reaches the same
    // claim path rather than being skipped before the key is examined.
    let other = json!({
        "id": "urn:uuid:e2",
        "type": "https://trusttasks.org/spec/vta/webvh/dids/create/1.2",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": caller(),
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "idempotencyKey": "urn:uuid:idem-cross",
        "payload": { "contextId": CONTEXT, "portable": true },
    });
    let (s2, b2) = post(&router, &token, &other).await;
    assert_ne!(s2, StatusCode::OK, "one key must not span two tasks: {b2}");
}

/// Two callers must not collide — or probe each other — by guessing keys.
#[tokio::test]
async fn one_callers_key_does_not_block_another() {
    let (router, mine, theirs) = app_with_second_caller().await;

    let shared = Some("urn:uuid:idem-shared-value");
    let (s1, b1) = post(&router, &mine, &create_doc("f1", "mine", shared)).await;
    assert_eq!(s1, StatusCode::OK, "{b1}");

    let doc = create_doc_as(OTHER_SEED, "f2", "theirs", shared);
    let (s2, b2) = post(&router, &theirs, &doc).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "records are scoped by caller; another caller's key must not block this one: {b2}"
    );
}

/// A key on a task where a repeat is harmless costs a dedup record and buys
/// nothing, so the dispatcher skips it entirely. The request must still work.
#[tokio::test]
async fn a_key_on_a_retry_safe_task_is_ignored_not_rejected() {
    let (router, token) = app().await;

    let doc = json!({
        "id": "urn:uuid:g1",
        "type": KEYS_LIST,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": caller(),
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "idempotencyKey": "urn:uuid:idem-on-a-read",
        "payload": { "contextId": CONTEXT },
    });
    let (s1, b1) = post(&router, &token, &doc).await;
    assert_eq!(s1, StatusCode::OK, "{b1}");

    // Same key, same read, twice — a read is not deduplicated, so the second
    // call answers normally rather than replaying or conflicting.
    let mut again = doc.clone();
    again["id"] = json!("urn:uuid:g2");
    let (s2, b2) = post(&router, &token, &again).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "a read carrying a key must answer normally: {b2}"
    );
}

/// A malformed key is treated as absent rather than as an error — the request
/// behaves exactly as an unkeyed one. Rejecting it would break callers to
/// enforce a convenience.
#[tokio::test]
async fn an_unusable_key_falls_back_to_unkeyed_behaviour() {
    let (router, token) = app().await;
    let before = key_count(&router, &token).await;

    for (env, key) in [("h1", ""), ("h2", "   ")] {
        let (s, b) = post(&router, &token, &create_doc(env, "blank", Some(key))).await;
        assert_eq!(s, StatusCode::OK, "a blank key must not reject: {b}");
    }

    assert_eq!(
        key_count(&router, &token).await,
        before + 2,
        "an unusable key means unkeyed, so both submissions take effect"
    );
}

/// A failed task releases its claim, so the retry actually runs. Caching a
/// failure would turn one transient error into a sticky one for the record's
/// whole lifetime.
#[tokio::test]
async fn a_failed_task_does_not_hold_its_key() {
    let (router, token) = app().await;
    let key = Some("urn:uuid:idem-after-failure");

    // A malformed payload fails inside the handler rather than at the schema
    // gate, so the claim is taken and then released.
    let mut bad = create_doc("i1", "fails", key);
    bad["payload"]["contextId"] = json!("no-such-context-exists");
    let (s1, _) = post(&router, &token, &bad).await;
    assert_ne!(
        s1,
        StatusCode::OK,
        "the setup for this test must actually fail"
    );

    let before = key_count(&router, &token).await;
    let (s2, b2) = post(&router, &token, &create_doc("i2", "succeeds", key)).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "a key held by a failed attempt must be free for the retry: {b2}"
    );
    assert_eq!(
        key_count(&router, &token).await,
        before + 1,
        "and that retry must actually do the work"
    );
}

// ── Across a restart, and across an interrupted attempt (#2402) ─────
//
// Everything above runs in one process against one live store. These build
// the VTA twice over the same directory — the first app, its router, context
// and every keyspace handle dropped before the second is built — so what the
// second app sees is only what reached the disk. The caller is the same DID
// throughout (`Principal::Did`), re-authenticated against the reopened store.

use vta_service::test_support::{TestAppContext, TestAppOptions, build_test_app_with};
use vti_common::idempotency::{EntryState, IdempotencyStore, Principal};

/// The app over `dir`, the `test` context in place, and a token for
/// [`caller`]. On a reopened store the context is already there.
async fn app_at(dir: &std::path::Path) -> (axum::Router, TestAppContext, String) {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        data_dir: Some(dir.to_path_buf()),
        ..Default::default()
    })
    .await;
    if vta_service::contexts::get_context(&ctx.contexts_ks, CONTEXT)
        .await
        .expect("read context")
        .is_none()
    {
        vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Idempotency tests")
            .await
            .expect("context");
    }
    let token = ctx.mint_token(caller().as_str(), "admin", vec![]).await;
    (router, ctx, token)
}

/// Drop the first app and show the store was released: fjall locks its
/// directory while any handle lives, so a reopen succeeding here is the proof
/// that nothing from the first lifetime is still holding the database.
fn shut_down(dir: &std::path::Path, router: axum::Router, ctx: TestAppContext) {
    let config = vti_common::config::StoreConfig {
        data_dir: dir.to_path_buf(),
    };
    assert!(
        vti_common::store::Store::open(&config).is_err(),
        "the directory must be locked while the first app lives, or reopening it proves nothing"
    );
    drop(router);
    drop(ctx);
    drop(vti_common::store::Store::open(&config).expect("store released by the first app"));
}

async fn idempotency_record(
    ctx: &TestAppContext,
    key: &str,
) -> vti_common::idempotency::CacheEntry {
    IdempotencyStore::new(ctx.state.idempotency_ks.clone())
        .get(&Principal::Did(caller()).hash(), key)
        .await
        .expect("read idempotency record")
        .expect("the keyed request left a record")
}

/// Put back the record a process leaves when it dies after the handler
/// committed its effect but before `record_outcome` ran: the claim, in flight,
/// no response — exactly what `claim` wrote, `claimed_ago` in the past.
async fn interrupt_after_effect(ctx: &TestAppContext, key: &str, claimed_ago: chrono::Duration) {
    let mut entry = idempotency_record(ctx, key).await;
    entry.state = EntryState::InFlight;
    entry.response_status = 0;
    entry.response_headers.clear();
    entry.response_body.clear();
    entry.created_at = chrono::Utc::now() - claimed_ago;
    IdempotencyStore::new(ctx.state.idempotency_ks.clone())
        .put(&Principal::Did(caller()).hash(), &entry)
        .await
        .expect("write the interrupted claim");
}

/// VTI-OPS-061 / VTI-OPS-065 across a restart: the same key on a fresh
/// envelope converges on the first effect; the same key with another payload
/// is refused; and the controls — another key, no key — still perform, so the
/// convergence is the key's doing, not `keys/create` being convergent or the
/// envelope-id replay cache (every envelope here is new).
#[tokio::test]
async fn vti_ops_061_a_keyed_effect_survives_a_restart_once() {
    let dir = tempfile::tempdir().expect("temp dir");

    let (router, ctx, token) = app_at(dir.path()).await;
    let (s, first) = post(
        &router,
        &token,
        &create_doc("r1", "restart", Some("urn:uuid:idem-restart")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let key_id = first["payload"]["key"]["keyId"].clone();
    assert!(key_id.is_string(), "{first}");
    assert_eq!(key_count(&router, &token).await, 1);
    shut_down(dir.path(), router, ctx);

    let (router, _ctx, token) = app_at(dir.path()).await;
    assert_eq!(
        key_count(&router, &token).await,
        1,
        "the first effect is on disk"
    );

    let (s, retry) = post(
        &router,
        &token,
        &create_doc("r2", "restart", Some("urn:uuid:idem-restart")),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the retry is answered, not refused: {retry}"
    );
    assert_eq!(
        retry["payload"]["key"]["keyId"], key_id,
        "answered with the first result"
    );
    assert_eq!(key_count(&router, &token).await, 1, "no second key");

    let (s, changed) = post(
        &router,
        &token,
        &create_doc("r3", "different", Some("urn:uuid:idem-restart")),
    )
    .await;
    assert_ne!(s, StatusCode::OK, "{changed}");
    assert!(changed.to_string().contains("idempotency key"), "{changed}");
    assert_eq!(
        key_count(&router, &token).await,
        1,
        "the refusal made nothing"
    );

    let (s, b) = post(
        &router,
        &token,
        &create_doc("r4", "restart", Some("urn:uuid:idem-restart-other")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, b) = post(&router, &token, &create_doc("r5", "restart", None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        key_count(&router, &token).await,
        3,
        "another key and no key each perform: the controls"
    );
}

/// VTI-OPS-061 at the commit point: the process dies after `keys/create`
/// committed its key and before the outcome was recorded. After the restart the
/// retry under that key is told to wait while the claim could still be live,
/// and once it cannot, is told the outcome is unknown — and the task is never
/// run again under that key. Before #2402 the stale claim was reclaimed and the
/// retry minted a second key.
#[tokio::test]
async fn vti_ops_061_an_attempt_interrupted_after_its_effect_is_never_rerun() {
    const KEY: &str = "urn:uuid:idem-interrupted";
    let dir = tempfile::tempdir().expect("temp dir");

    let (router, ctx, token) = app_at(dir.path()).await;
    let (s, first) = post(&router, &token, &create_doc("i1", "interrupted", Some(KEY))).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    assert_eq!(key_count(&router, &token).await, 1);
    interrupt_after_effect(&ctx, KEY, chrono::Duration::zero()).await;
    shut_down(dir.path(), router, ctx);

    let (router, ctx, token) = app_at(dir.path()).await;

    // Inside the grace: the claim may belong to a live attempt.
    let (_, waiting) = post(&router, &token, &create_doc("i2", "interrupted", Some(KEY))).await;
    assert_eq!(waiting["payload"]["code"], "unavailable", "{waiting}");
    assert_eq!(
        key_count(&router, &token).await,
        1,
        "not run while in flight"
    );

    // Past the grace: the attempt is dead and its outcome unknown. Asked
    // twice, because the answer must not turn into a reclaim.
    interrupt_after_effect(&ctx, KEY, chrono::Duration::minutes(11)).await;
    for envelope in ["i3", "i4"] {
        let (s, unknown) = post(
            &router,
            &token,
            &create_doc(envelope, "interrupted", Some(KEY)),
        )
        .await;
        // The count first: if this regresses, the failure should report the
        // duplicate itself, not a status code.
        assert_eq!(
            key_count(&router, &token).await,
            1,
            "an abandoned attempt is never re-run: the duplicate #2402 asked about"
        );
        assert_ne!(s, StatusCode::OK, "{unknown}");
        assert_eq!(unknown["payload"]["code"], "taskFailed", "{unknown}");
        assert!(
            unknown["payload"]["details"]["claimedAt"].is_string(),
            "the refusal says when the lost attempt started: {unknown}"
        );
    }
    assert_eq!(
        idempotency_record(&ctx, KEY).await.state,
        EntryState::InFlight,
        "the refusal leaves the record as the interruption left it"
    );

    // The way forward the refusal names: check, then a new key.
    let (s, b) = post(
        &router,
        &token,
        &create_doc("i5", "interrupted", Some("urn:uuid:idem-interrupted-2")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(key_count(&router, &token).await, 2);
}
