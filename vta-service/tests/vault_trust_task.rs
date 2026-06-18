//! Wire-level safety net for the password-vault Trust Task slice
//! (`routes/trust_tasks/vault.rs`) — the prerequisite for the P2.4 refactor
//! that relocates these handlers to `operations/secret_vault/`.
//!
//! Before this file the slice (~2k LOC) had only the `resolve_siop_audience`
//! unit test; the capability gates and context-scope enforcement — the
//! security-critical checks a code-move most easily breaks — had no `/api/
//! trust-tasks` coverage. This exercises every vault URI at the wire:
//!
//! - **gate-denied** for all 7 URIs (role lacking the capability),
//! - **cross-context-denied**, preserving the *checked-after-load* semantics
//!   for the handlers that resolve the entry first (`get`, `release`,
//!   `proxy-login`, `sign-trust-task`) vs *checked-before-load* (`list`,
//!   `upsert`),
//! - a **happy path** for the read/delete handlers (no consumer crypto), and
//! - a **dispatch-reached** assertion for the consumer-crypto handlers
//!   (`release` / `proxy-login` / `sign-trust-task`): a request that clears the
//!   gate + context check but names a missing entry must reach the handler and
//!   reject there, proving the gate ordering and wiring. Their full
//!   sealing/JWE happy paths are covered by the `operations`-layer tests; the
//!   net here locks the route-level behaviour P2.4 moves.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use multibase::Base;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
use vti_common::vault::{
    SecretKind, SiteTarget, StoredVaultEntry, VaultEntry, VaultSecret, VaultStatus,
    put_stored_vault_entry,
};

// URIs (kept as literals so a constant rename in the SDK surfaces here too).
const LIST: &str = "https://trusttasks.org/spec/vault/list/0.1";
const GET: &str = "https://trusttasks.org/spec/vault/get/0.1";
const UPSERT: &str = "https://trusttasks.org/spec/vault/upsert/0.1";
const DELETE: &str = "https://trusttasks.org/spec/vault/delete/0.1";
const ARCHIVE: &str = "https://trusttasks.org/spec/vault/archive/0.1";
const UNARCHIVE: &str = "https://trusttasks.org/spec/vault/unarchive/0.1";
const RESTORE: &str = "https://trusttasks.org/spec/vault/restore/0.1";
const PURGE: &str = "https://trusttasks.org/spec/vault/purge/0.1";
const RELEASE: &str = "https://trusttasks.org/spec/vault/release/0.1";
const PROXY_LOGIN: &str = "https://trusttasks.org/spec/vault/proxy-login/0.1";
const SIGN_TT: &str = "https://trusttasks.org/spec/vault/sign-trust-task/0.1";

/// A fixed holder `did:key` (Ed25519, multicodec 0xed01). Vault auth is bearer,
/// so the key is never used to sign — only as a stable subject DID.
fn holder_did() -> String {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:{}", multibase::encode(Base::Base58Btc, mc))
}

/// Create an authenticated session for `did` with the given `role` +
/// `allowed_contexts`, and return a bearer token for it.
async fn authed(ctx: &TestAppContext, role: &str, allowed_contexts: &[&str]) -> String {
    let did = holder_did();
    let session_id = format!("sess-vault-{role}-{}", allowed_contexts.join("_"));
    let session = Session {
        session_id: session_id.clone(),
        did: did.clone(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    let contexts: Vec<String> = allowed_contexts.iter().map(|s| s.to_string()).collect();
    let claims = ctx
        .jwt_keys
        .new_claims(did, session_id, role.to_string(), contexts, 900, false);
    ctx.jwt_keys.encode(&claims).unwrap()
}

/// POST a vault Trust Task and return `(status, body-as-string)`.
async fn post_vault(
    router: &axum::Router,
    token: &str,
    uri: &str,
    payload: Value,
) -> (StatusCode, String) {
    let doc = json!({
        "id": format!("tt-{}", uuid::Uuid::new_v4()),
        "type": uri,
        "issuer": holder_did(),
        "recipient": "did:key:z6MkTestVTA",
        "payload": payload,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Seed a password vault entry in `context_id`.
async fn seed_entry(ctx: &TestAppContext, id: &str, context_id: &str) {
    let now = "2026-01-01T00:00:00Z".to_string();
    let entry = StoredVaultEntry {
        entry: VaultEntry {
            id: id.to_string(),
            context_id: context_id.to_string(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://example.com".to_string(),
            }],
            label: "Test Entry".to_string(),
            secret_kind: SecretKind::Password,
            tags: Vec::new(),
            notes: None,
            favicon: None,
            selectors: Vec::new(),
            custom_field_names: Vec::new(),
            attachments: Vec::new(),
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: now.clone(),
            created_by: None,
            updated_at: now,
            updated_by: None,
            last_used_at: None,
            version: 1,
            principal_did: None,
            status: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        },
        secret: VaultSecret::Password {
            username: Some("alice".to_string()),
            password: "hunter2-very-secret".to_string(),
            totp: None,
            login_config: None,
            secure_notes: None,
            custom_fields: Vec::new(),
        },
    };
    put_stored_vault_entry(&ctx.vault_ks, &entry).await.unwrap();
}

// ── gate-denied: Monitor carries no vault capability, so every URI is denied ──

#[tokio::test]
async fn every_vault_uri_denied_without_capability() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "monitor", &[]).await;

    // (uri, minimal-but-parseable payload). The capability gate runs before
    // payload parsing, so even an empty/partial payload must be denied.
    let cases: Vec<(&str, Value)> = vec![
        (LIST, json!({})),
        (GET, json!({ "id": "entry-1" })),
        (
            UPSERT,
            json!({ "contextId": "ctx1", "targets": [], "label": "x", "secretKind": "password" }),
        ),
        (DELETE, json!({ "id": "entry-1" })),
        (ARCHIVE, json!({ "id": "entry-1" })),
        (UNARCHIVE, json!({ "id": "entry-1" })),
        (RESTORE, json!({ "id": "entry-1" })),
        (PURGE, json!({ "id": "entry-1" })),
        (RELEASE, json!({ "entryId": "entry-1" })),
        (PROXY_LOGIN, json!({ "entryId": "entry-1" })),
        (
            SIGN_TT,
            json!({ "entryId": "entry-1", "unsignedEnvelope": {} }),
        ),
    ];

    for (uri, payload) in cases {
        let (status, body) = post_vault(&router, &token, uri, payload).await;
        assert_ne!(status, StatusCode::OK, "{uri} must be denied for Monitor");
        assert!(
            body.contains("does not carry") && body.contains("capability"),
            "{uri} denial should cite the missing capability, got: {body}"
        );
    }
}

/// A `Reader` carries `VaultRead` only, so the write/release/proxy/sign gates
/// still deny while `list`/`get` are allowed — proving the gates are
/// capability-specific, not a blanket role check.
#[tokio::test]
async fn reader_passes_read_gates_but_not_the_others() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "reader", &[]).await;

    // Read gates: pass (list returns OK; get reaches not-found, i.e. past gate).
    let (list_status, _) = post_vault(&router, &token, LIST, json!({})).await;
    assert_eq!(list_status, StatusCode::OK, "Reader may list");

    let (get_status, get_body) = post_vault(&router, &token, GET, json!({ "id": "nope" })).await;
    assert_ne!(get_status, StatusCode::OK);
    assert!(
        !get_body.contains("does not carry"),
        "Reader cleared the VaultRead gate (not a capability denial): {get_body}"
    );

    // Non-read gates: denied.
    for (uri, payload) in [
        (
            UPSERT,
            json!({ "contextId": "ctx1", "targets": [], "label": "x", "secretKind": "password" }),
        ),
        (DELETE, json!({ "id": "entry-1" })),
        (ARCHIVE, json!({ "id": "entry-1" })),
        (UNARCHIVE, json!({ "id": "entry-1" })),
        (RESTORE, json!({ "id": "entry-1" })),
        (PURGE, json!({ "id": "entry-1" })),
        (RELEASE, json!({ "entryId": "entry-1" })),
        (PROXY_LOGIN, json!({ "entryId": "entry-1" })),
        (
            SIGN_TT,
            json!({ "entryId": "entry-1", "unsignedEnvelope": {} }),
        ),
    ] {
        let (status, body) = post_vault(&router, &token, uri, payload).await;
        assert_ne!(status, StatusCode::OK, "Reader must not pass {uri}");
        assert!(
            body.contains("does not carry"),
            "{uri} should be a capability denial for Reader, got: {body}"
        );
    }
}

// ── happy paths: read + delete (no consumer crypto) ──

#[tokio::test]
async fn list_happy_path_returns_seeded_entry() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-a", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    let (status, body) = post_vault(&router, &token, LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let entries = v["payload"]["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "expected the one seeded entry: {body}");
    assert_eq!(entries[0]["id"], "entry-a");
}

#[tokio::test]
async fn get_happy_path_returns_entry_metadata() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-b", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    let (status, body) = post_vault(&router, &token, GET, json!({ "id": "entry-b" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["payload"]["entry"]["id"], "entry-b", "{body}");
    assert_eq!(v["payload"]["entry"]["label"], "Test Entry");
}

#[tokio::test]
async fn delete_is_recoverable_soft_delete() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-c", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    // Soft delete → tombstone with a real grace window (graceUntil > deletedAt).
    let (status, body) = post_vault(&router, &token, DELETE, json!({ "id": "entry-c" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let deleted_at = v["payload"]["deletedAt"].as_str().unwrap();
    let grace_until = v["payload"]["graceUntil"].as_str().unwrap();
    assert!(
        grace_until > deleted_at,
        "soft delete has a real grace window: {body}"
    );

    // The entry is still retrievable (status=deleted), restorable...
    let (get_status, get_body) = post_vault(&router, &token, GET, json!({ "id": "entry-c" })).await;
    assert_eq!(
        get_status,
        StatusCode::OK,
        "tombstone is still gettable: {get_body}"
    );
    let g: Value = serde_json::from_str(&get_body).unwrap();
    assert_eq!(g["payload"]["entry"]["status"], "deleted", "{get_body}");

    // ...but excluded from the default (active-only) list.
    let (_, list_body) = post_vault(&router, &token, LIST, json!({})).await;
    assert!(
        !list_body.contains("entry-c"),
        "default list hides tombstones: {list_body}"
    );
    // ...and visible under the trash view.
    let (_, trash_body) = post_vault(&router, &token, LIST, json!({ "status": "deleted" })).await;
    assert!(
        trash_body.contains("entry-c"),
        "trash view shows tombstones: {trash_body}"
    );

    // Restore brings it back to active.
    let (rs, rb) = post_vault(&router, &token, RESTORE, json!({ "id": "entry-c" })).await;
    assert_eq!(rs, StatusCode::OK, "{rb}");
    let (_, list2) = post_vault(&router, &token, LIST, json!({})).await;
    assert!(
        list2.contains("entry-c"),
        "restored entry is active again: {list2}"
    );
}

#[tokio::test]
async fn delete_force_hard_deletes_immediately() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-f", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    let (status, body) = post_vault(
        &router,
        &token,
        DELETE,
        json!({ "id": "entry-f", "force": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Forced delete is gone for good — no grace window, not gettable.
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["payload"]["graceUntil"], v["payload"]["deletedAt"],
        "forced → no grace window"
    );
    let (get_status, _) = post_vault(&router, &token, GET, json!({ "id": "entry-f" })).await;
    assert_ne!(get_status, StatusCode::OK, "force-deleted entry is gone");
}

#[tokio::test]
async fn archive_hides_and_blocks_then_unarchive_restores() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-a", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    // Archive → dropped from default list, refused for release.
    let (status, body) = post_vault(&router, &token, ARCHIVE, json!({ "id": "entry-a" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, list_body) = post_vault(&router, &token, LIST, json!({})).await;
    assert!(
        !list_body.contains("entry-a"),
        "archived entry hidden from default list"
    );
    let (rel_status, _) =
        post_vault(&router, &token, RELEASE, json!({ "entryId": "entry-a" })).await;
    assert_ne!(
        rel_status,
        StatusCode::OK,
        "archived entry refuses release (not_found)"
    );

    // Double-archive is rejected.
    let (again, again_body) =
        post_vault(&router, &token, ARCHIVE, json!({ "id": "entry-a" })).await;
    assert_ne!(
        again,
        StatusCode::OK,
        "double-archive rejected: {again_body}"
    );

    // Unarchive returns it to active + listable.
    let (us, ub) = post_vault(&router, &token, UNARCHIVE, json!({ "id": "entry-a" })).await;
    assert_eq!(us, StatusCode::OK, "{ub}");
    let (_, list2) = post_vault(&router, &token, LIST, json!({})).await;
    assert!(
        list2.contains("entry-a"),
        "unarchived entry is active again"
    );
}

#[tokio::test]
async fn purge_is_irreversible() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-p", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    // Soft-delete then purge the tombstone.
    let (_, _) = post_vault(&router, &token, DELETE, json!({ "id": "entry-p" })).await;
    let (ps, pb) = post_vault(&router, &token, PURGE, json!({ "id": "entry-p" })).await;
    assert_eq!(ps, StatusCode::OK, "{pb}");
    // Gone from every view.
    let (get_status, _) = post_vault(&router, &token, GET, json!({ "id": "entry-p" })).await;
    assert_ne!(get_status, StatusCode::OK, "purged entry is gone");
    let (_, trash_body) = post_vault(&router, &token, LIST, json!({ "status": "deleted" })).await;
    assert!(
        !trash_body.contains("entry-p"),
        "purged entry gone from trash too"
    );
}

#[tokio::test]
async fn restore_of_active_entry_is_rejected() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-r", "ctx1").await;
    let token = authed(&ctx, "admin", &[]).await;

    // Restoring an entry that was never deleted is a no-op error.
    let (status, body) = post_vault(&router, &token, RESTORE, json!({ "id": "entry-r" })).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "restore of an active entry is rejected: {body}"
    );
    assert!(body.contains("not_deleted"), "{body}");
}

// ── cross-context-denied ──

/// `get` resolves the entry first, *then* checks its context against the
/// caller's `allowed_contexts` — the checked-after-load semantics P2.4 must
/// preserve. Caller scoped to `ctx-allowed`; entry lives in `ctx-other`.
#[tokio::test]
async fn get_cross_context_denied_after_load() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "entry-other", "ctx-other").await;
    let token = authed(&ctx, "admin", &["ctx-allowed"]).await;

    let (status, body) = post_vault(&router, &token, GET, json!({ "id": "entry-other" })).await;
    assert_ne!(status, StatusCode::OK);
    assert!(
        body.contains("scope denied"),
        "expected context-scope denial, got: {body}"
    );
}

/// `list` with an explicit `contextId` outside the caller's scope is denied
/// before the store read (checked-before-load).
#[tokio::test]
async fn list_cross_context_denied() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "admin", &["ctx-allowed"]).await;

    let (status, body) =
        post_vault(&router, &token, LIST, json!({ "contextId": "ctx-other" })).await;
    assert_ne!(status, StatusCode::OK);
    assert!(body.contains("scope denied"), "{body}");
}

/// `upsert` targeting a context outside the caller's scope is denied before
/// any store interaction.
#[tokio::test]
async fn upsert_cross_context_denied() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "admin", &["ctx-allowed"]).await;

    let (status, body) = post_vault(
        &router,
        &token,
        UPSERT,
        json!({ "contextId": "ctx-other", "targets": [], "label": "x", "secretKind": "password" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    assert!(body.contains("scope denied"), "{body}");
}

/// A `list` scoped to a subset of contexts and queried *without* a filter
/// narrows the result set to visible contexts (defence-in-depth path).
#[tokio::test]
async fn list_without_filter_narrows_to_visible_contexts() {
    let (router, ctx) = build_test_app().await;
    seed_entry(&ctx, "vis", "ctx-allowed").await;
    seed_entry(&ctx, "hidden", "ctx-other").await;
    let token = authed(&ctx, "admin", &["ctx-allowed"]).await;

    let (status, body) = post_vault(&router, &token, LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let entries = v["payload"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "only the visible-context entry: {body}");
    assert_eq!(entries[0]["id"], "vis");
}

// ── dispatch-reached for the consumer-crypto handlers ──
//
// release / proxy-login / sign-trust-task seal/sign against a stored entry's
// secret; their full happy paths need a consumer key + DIDComm envelopes and
// are covered by the operations-layer tests. Here we prove each clears the
// gate and reaches the handler body by naming a missing entry: the response is
// a not-found-style reject (NOT a capability denial), confirming gate ordering
// and that the arm is wired.

#[tokio::test]
async fn release_reaches_handler_past_gate() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "admin", &[]).await;
    let (status, body) =
        post_vault(&router, &token, RELEASE, json!({ "entryId": "missing" })).await;
    assert_ne!(status, StatusCode::OK);
    assert!(
        !body.contains("does not carry"),
        "release cleared the FillRelease gate, so this is a handler-level reject: {body}"
    );
}

#[tokio::test]
async fn proxy_login_reaches_handler_past_gate() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "admin", &[]).await;
    let (status, body) = post_vault(
        &router,
        &token,
        PROXY_LOGIN,
        json!({ "entryId": "missing" }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    assert!(
        !body.contains("does not carry"),
        "proxy-login cleared the ProxyLogin gate: {body}"
    );
}

#[tokio::test]
async fn sign_trust_task_reaches_handler_past_gate() {
    let (router, ctx) = build_test_app().await;
    let token = authed(&ctx, "admin", &[]).await;
    let (status, body) = post_vault(
        &router,
        &token,
        SIGN_TT,
        json!({ "entryId": "missing", "unsignedEnvelope": { "id": "x", "type": "y", "payload": {} } }),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    assert!(
        !body.contains("does not carry"),
        "sign-trust-task cleared the SignTrustTask gate: {body}"
    );
}
