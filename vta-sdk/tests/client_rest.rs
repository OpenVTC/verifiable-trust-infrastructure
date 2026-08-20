//! REST client coverage harness for `vta_sdk::client::VtaClient`.
//!
//! Exercises every public REST endpoint the SDK exposes against a
//! `wiremock` server. For each endpoint we verify:
//!   - request method + path (incl. URL-encoding for DIDs/IDs with
//!     reserved characters)
//!   - the `Authorization: Bearer …` header is attached
//!   - the SDK deserializes a happy-path response body correctly
//!   - HTTP error status codes map to the expected `VtaError` variant
//!
//! Out of scope: DIDComm transport (covered separately by
//! `provision_client_e2e.rs` and the inline `didcomm_session` tests),
//! attestation verification (in `attestation.rs`), and the sealed-bundle
//! open path (in `sealed_transfer/`).

#![cfg(feature = "client")]

use chrono::Utc;
use serde_json::{Value, json};
use vta_sdk::client::*;
use vta_sdk::error::VtaError;
use vta_sdk::keys::{KeyOrigin, KeyStatus, KeyType};
use vta_sdk::protocols::key_management::sign::SignAlgorithm;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Trust Tasks HTTPS binding test surface ─────────────────────────────
//
// Every `rpc_tt` call posts the same envelope to the same path, so a mock can
// no longer be selected by method and route. What identifies a call now is the
// envelope `type` and the `payload` — which is strictly more precise, because
// the payload is what the VTA actually acts on.

const TASK_ACL_LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";
const TASK_KEYS_LIST: &str = "https://trusttasks.org/spec/keys/list/0.1";
const TASK_AUDIT_LIST: &str = "https://trusttasks.org/spec/audit/list/0.1";
/// `get_key_secret` dispatches this: the operation moved to the seeds slice
/// because it acts on the seed behind the key, not the key itself.
const TASK_SEEDS_EXPORT_MNEMONIC: &str =
    "https://trusttasks.org/spec/vta/seeds/export-mnemonic/1.0";
const TASK_WEBVH_DIDS_LIST: &str = "https://trusttasks.org/spec/vta/webvh/dids/list/1.0";

/// A success response document carrying `payload`.
fn tt_ok(payload: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "type": "urn:test:response",
        "payload": payload,
    }))
}

/// Assert a key is *absent* from the payload.
///
/// `body_partial_json` can only assert presence, so omission — which is the
/// whole point of a field a forward-compatible VTA would reject — needs its
/// own matcher.
fn no_payload_key(key: &'static str) -> impl Fn(&wiremock::Request) -> bool {
    move |req: &wiremock::Request| {
        serde_json::from_slice::<Value>(&req.body)
            .ok()
            .and_then(|v| v.get("payload").cloned())
            .map(|p| p.get(key).is_none())
            .unwrap_or(false)
    }
}

// ── Test harness ────────────────────────────────────────────────────

const TOKEN: &str = "test-token";

async fn client(server: &MockServer) -> VtaClient {
    let c = VtaClient::new(&server.uri());
    c.set_token_async(TOKEN.into()).await;
    c
}

fn err_body(msg: &str) -> Value {
    json!({ "error": msg })
}

fn auth_match() -> impl wiremock::Match {
    header("authorization", &*format!("Bearer {TOKEN}"))
}

/// Mount the reply to one typed call.
///
/// Every operation now leaves over the HTTPS binding — `POST /api/trust-tasks`
/// carrying a Trust Task document — so there is no per-operation method or
/// path left to match on. The `m` and `p` arguments are retained because each
/// test still documents which REST route its operation *used* to occupy, and
/// losing that would make this file harder to read against its own history;
/// they are deliberately not matched.
///
/// The body a test supplies is the operation's payload, so it is wrapped in a
/// response document the way a conforming server replies. What each operation
/// *dispatches* is asserted separately, in `dispatches_the_canonical_task`.
/// Mock the Trust Tasks HTTPS binding: every `rpc_tt`/`rpc_tt_void` call posts
/// to `/api/trust-tasks` regardless of the operation, so the method and path
/// arguments no longer select anything. They are kept because the call sites
/// read better naming the operation being mocked, and because a future
/// per-task assertion will want them back.
async fn mount_json(
    server: &MockServer,
    _m: &str,
    _p: &str,
    status: u16,
    body: Value,
) -> wiremock::MockGuard {
    let resp = ResponseTemplate::new(status).set_body_json(json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "type": "urn:test:response",
        "payload": body,
    }));
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(resp)
        .expect(1)
        .mount_as_scoped(server)
        .await
}

/// Mock a genuinely-REST route — one with no trust-task twin, which therefore
/// keeps its bespoke method and path. Backup blob streaming, the import
/// wrapping key and the deprecated legacy-`rpc` DID verbs are the whole set;
/// anything else reaching for this helper is probably a task in disguise.
async fn mount_rest_json(
    server: &MockServer,
    m: &str,
    p: &str,
    status: u16,
    body: Value,
) -> wiremock::MockGuard {
    Mock::given(method(m))
        .and(path(p))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(1)
        .mount_as_scoped(server)
        .await
}

async fn mount_rest_status(
    server: &MockServer,
    m: &str,
    p: &str,
    status: u16,
) -> wiremock::MockGuard {
    Mock::given(method(m))
        .and(path(p))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(status).set_body_json(err_body("bad")))
        .expect(1)
        .mount_as_scoped(server)
        .await
}

async fn mount_status(server: &MockServer, _m: &str, _p: &str, status: u16) -> wiremock::MockGuard {
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(status).set_body_json(err_body("bad")))
        .expect(1)
        .mount_as_scoped(server)
        .await
}

fn iso(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap()
        .with_timezone(&Utc)
}

// ── Health (no auth) ────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "version": "0.5.0",
            "mediator_url": "https://mediator.example.com",
            "mediator_did": "did:web:mediator.example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = VtaClient::new(&server.uri());
    let h = c.health().await.unwrap();
    assert_eq!(h.status, "ok");
    assert_eq!(h.version.as_deref(), Some("0.5.0"));
    assert_eq!(
        h.mediator_did.as_deref(),
        Some("did:web:mediator.example.com")
    );
}

#[tokio::test]
async fn health_minimal_body_deserializes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&server)
        .await;
    let c = VtaClient::new(&server.uri());
    let h = c.health().await.unwrap();
    assert_eq!(h.status, "ok");
    assert!(h.version.is_none());
}

#[tokio::test]
async fn health_500_maps_to_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(503).set_body_json(err_body("down")))
        .mount(&server)
        .await;
    let c = VtaClient::new(&server.uri());
    let err = c.health().await.unwrap_err();
    assert!(matches!(err, VtaError::Server { status: 503, .. }));
}

// ── Discovery + VTA management ──────────────────────────────────────

#[tokio::test]
async fn capabilities_returns_features() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/capabilities",
        200,
        json!({
            "version": "0.5.0",
            "features": {"webvh": true, "didcomm": false, "tee": false, "rest": true},
            "services": {"rest": true, "didcomm": false},
            "webvh_servers": [{"id": "s1"}],
            "did_creation_modes": ["webvh"]
        }),
    )
    .await;
    let c = client(&server).await;
    let caps = c.capabilities().await.unwrap();
    assert_eq!(caps.version, "0.5.0");
    assert!(caps.features.webvh);
    assert!(!caps.features.didcomm);
    assert_eq!(caps.webvh_servers.len(), 1);
    assert_eq!(caps.webvh_servers[0].id, "s1");
}

#[tokio::test]
async fn restart_returns_status() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/vta/restart",
        200,
        json!({"status": "restarting"}),
    )
    .await;
    let c = client(&server).await;
    assert_eq!(c.restart().await.unwrap().status, "restarting");
}

#[tokio::test]
async fn get_config_returns_the_registry() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/config",
        200,
        json!({
            "fields": [
                { "key": "vta_did", "value": "did:web:vta.example.com",
                  "source": "setup", "requiresRestart": false },
                { "key": "vta_name", "value": "primary",
                  "source": "toml", "requiresRestart": false },
                { "key": "public_url", "value": "https://vta.example.com",
                  "source": "toml", "requiresRestart": true }
            ]
        }),
    )
    .await;
    let c = client(&server).await;
    let cfg = c.get_config().await.unwrap();
    assert_eq!(cfg.config.vta_did(), Some("did:web:vta.example.com"));
    assert_eq!(
        cfg.config.get("vta_name").and_then(|v| v.as_str()),
        Some("primary")
    );
    // `public_url` is boot-stable, and the registry says so rather than
    // leaving a caller to discover it by restarting.
    assert!(
        cfg.config
            .fields
            .iter()
            .find(|f| f.key == "public_url")
            .expect("public_url registered")
            .requires_restart
    );
}

#[tokio::test]
async fn update_config_sends_the_overrides_map() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/config",
        200,
        json!({ "applied": ["vta_name"], "pendingRestart": [], "rejected": [] }),
    )
    .await;
    let c = client(&server).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("vta_name".to_string(), json!("new"));
    let res = c
        .update_config(UpdateConfigRequest {
            patch: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody {
                overrides,
            },
        })
        .await
        .unwrap();
    assert_eq!(res.applied, vec!["vta_name"]);
    assert!(res.rejected.is_empty());
}

/// Identity is readable but not patchable: naming `vta_did` comes back under
/// `rejected`, never applied. Before the fold onto canonical `config/patch`,
/// the VTA wrote it straight to `config.toml` with no guard.
#[tokio::test]
async fn update_config_reports_identity_as_rejected() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/config",
        200,
        json!({
            "applied": [],
            "pendingRestart": [],
            "rejected": [{ "key": "vta_did", "reason": "the VTA's own identity is set at setup" }]
        }),
    )
    .await;
    let c = client(&server).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("vta_did".to_string(), json!("did:web:attacker"));
    let res = c
        .update_config(UpdateConfigRequest {
            patch: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody {
                overrides,
            },
        })
        .await
        .unwrap();
    assert!(res.applied.is_empty(), "identity must never be applied");
    assert_eq!(res.rejected.len(), 1);
    assert_eq!(res.rejected[0].key, "vta_did");
}

// ── Backup ──────────────────────────────────────────────────────────

#[allow(deprecated)] // pins the inline path until rollout step 6 removes it
#[tokio::test]
async fn backup_export_returns_envelope() {
    let server = MockServer::start().await;
    let envelope = json!({
        "version": 1,
        "format": "vtabak/v1",
        "created_at": "2026-05-05T12:00:00Z",
        "source_version": "0.5.0",
        "kdf": {"algorithm": "argon2id", "salt": "AAAA", "m_cost": 65536, "t_cost": 3, "p_cost": 4},
        "encryption": {"algorithm": "AES-256-GCM", "nonce": "AAAA"},
        "includes_audit": false,
        "ciphertext": "AAAA"
    });
    let _g = mount_rest_json(&server, "POST", "/backup/export", 200, envelope).await;
    let c = client(&server).await;
    let env = c.backup_export("hunter2hunter2", false).await.unwrap();
    assert_eq!(env.version, 1);
    assert!(!env.includes_audit);
}

#[allow(deprecated)] // pins the inline path until rollout step 6 removes it
#[tokio::test]
async fn backup_export_403_maps_to_forbidden() {
    let server = MockServer::start().await;
    let _g = mount_rest_status(&server, "POST", "/backup/export", 403).await;
    let c = client(&server).await;
    let err = c.backup_export("pw", false).await.unwrap_err();
    assert!(matches!(err, VtaError::Forbidden(_)));
    assert!(err.is_auth());
}

// ── Keys ────────────────────────────────────────────────────────────

/// One record in the canonical `keys/_shared/0.1/key-record` shape — camelCase,
/// which is what the VTA emits on every transport after the keys fold.
fn key_record_json(id: &str) -> Value {
    json!({
        "keyId": id,
        "derivationPath": "m/44'/0'/0'",
        "keyType": "ed25519",
        "status": "active",
        "publicKey": "z6Mkpub",
        "label": null,
        "contextId": null,
        "seedId": 1,
        "origin": "derived",
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z"
    })
}

/// The `{ key }` envelope canonical single-record responses carry.
fn key_envelope(id: &str) -> Value {
    json!({ "key": key_record_json(id) })
}

/// The same envelope for a key that arrived from outside. `origin` is the
/// member that says a seed restore will not bring this one back, so a fixture
/// that always said `derived` would let a broken mapping pass.
fn imported_key_envelope(id: &str) -> Value {
    let mut record = key_record_json(id);
    record["origin"] = json!("imported");
    json!({ "key": record })
}

#[tokio::test]
async fn create_key_round_trip() {
    let server = MockServer::start().await;
    let _g = mount_json(&server, "POST", "/keys", 200, key_envelope("k1")).await;
    let c = client(&server).await;
    let req = CreateKeyRequest::new(KeyType::Ed25519)
        .derivation_path("m/0/0")
        .label("k1");
    let resp = c.create_key(req).await.unwrap();
    assert_eq!(resp.key_id, "k1");
    assert_eq!(resp.key_type, KeyType::Ed25519);
    assert_eq!(resp.status, KeyStatus::Active);
}

#[tokio::test]
async fn list_keys_paginates_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({
            "type": TASK_KEYS_LIST,
            "payload": {
                "offset": 10, "limit": 5,
                "status": "active", "contextId": "ctx-a"
            }
        })))
        .respond_with(tt_ok(json!({
            "keys": [key_record_json("k1")],
            "total": 1
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c
        .list_keys(10, 5, Some("active"), Some("ctx-a"))
        .await
        .unwrap();
    assert_eq!(resp.total, 1);
    assert_eq!(resp.keys.len(), 1);
}

#[tokio::test]
async fn get_key_path_encodes_did_fragment() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/keys/did:web:example.com%23key-1",
        200,
        key_envelope("did:web:example.com#key-1"),
    )
    .await;
    let c = client(&server).await;
    let key = c.get_key("did:web:example.com#key-1").await.unwrap();
    assert_eq!(key.key_id, "did:web:example.com#key-1");
}

#[tokio::test]
async fn get_key_404_maps_to_not_found() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "GET", "/keys/missing", 404).await;
    let c = client(&server).await;
    let err = c.get_key("missing").await.unwrap_err();
    assert!(err.is_not_found(), "got {err:?}");
}

#[tokio::test]
async fn get_key_secret_returns_multibase() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/keys/k1/secret",
        200,
        json!({
            "key_id": "k1",
            "key_type": "ed25519",
            "public_key_multibase": "z6Mkpub",
            "private_key_multibase": "zPriv"
        }),
    )
    .await;
    let c = client(&server).await;
    let s = c.get_key_secret("k1").await.unwrap();
    assert_eq!(s.private_key_multibase, "zPriv");
    assert_eq!(s.key_type, KeyType::Ed25519);
}

#[tokio::test]
async fn sign_posts_base64url_payload() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/keys/k1/sign",
        200,
        json!({
            "key_id": "k1",
            "signature": "AQID",
            "algorithm": "eddsa"
        }),
    )
    .await;
    let c = client(&server).await;
    let sig = c.sign("k1", b"hello", SignAlgorithm::EdDSA).await.unwrap();
    assert_eq!(sig.signature, "AQID");
    assert_eq!(sig.algorithm, SignAlgorithm::EdDSA);
}

#[tokio::test]
async fn invalidate_key_deletes() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "DELETE",
        "/keys/k1",
        200,
        json!({
            "key_id": "k1",
            "status": "revoked",
            "updated_at": "2026-01-01T00:00:00Z"
        }),
    )
    .await;
    let c = client(&server).await;
    let resp = c.invalidate_key("k1").await.unwrap();
    assert_eq!(resp.status, KeyStatus::Revoked);
}

#[tokio::test]
async fn rename_key_patches() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/keys/old",
        200,
        json!({"key_id": "new", "updated_at": "2026-01-01T00:00:00Z"}),
    )
    .await;
    let c = client(&server).await;
    let resp = c.rename_key("old", "new").await.unwrap();
    assert_eq!(resp.key_id, "new");
}

#[tokio::test]
async fn rename_key_409_maps_to_conflict() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "PATCH", "/keys/old", 409).await;
    let c = client(&server).await;
    let err = c.rename_key("old", "new").await.unwrap_err();
    assert!(err.is_conflict());
}

#[tokio::test]
async fn get_wrapping_key_returns_jwk() {
    let server = MockServer::start().await;
    let _g = mount_rest_json(
        &server,
        "GET",
        "/keys/import/wrapping-key",
        200,
        json!({"kid": "k1", "kty": "OKP", "crv": "X25519", "x": "AAAA"}),
    )
    .await;
    let c = client(&server).await;
    let k = c.get_wrapping_key().await.unwrap();
    assert_eq!(k.kid, "k1");
    assert_eq!(k.crv, "X25519");
}

#[tokio::test]
async fn import_key_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/keys/import",
        200,
        imported_key_envelope("imported"),
    )
    .await;
    let c = client(&server).await;
    let req = ImportKeyRequest {
        key_type: KeyType::Ed25519,
        private_key_sealed: Some("armored".into()),
        private_key_jwe: None,
        private_key_multibase: None,
        label: Some("imported".into()),
        context_id: None,
    };
    let resp = c.import_key(req).await.unwrap();
    assert_eq!(resp.key_id, "imported");
    assert_eq!(resp.origin, KeyOrigin::Imported);
}

// ── Seeds ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_seeds_returns_active() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/keys/seeds",
        200,
        json!({
            "seeds": [
                {"id": 1, "status": "active", "created_at": "2026-01-01T00:00:00Z", "retired_at": null}
            ],
            "active_seed_id": 1
        }),
    )
    .await;
    let c = client(&server).await;
    let resp = c.list_seeds().await.unwrap();
    assert_eq!(resp.active_seed_id, 1);
    assert_eq!(resp.seeds.len(), 1);
}

#[tokio::test]
async fn rotate_seed_with_mnemonic() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/keys/seeds/rotate",
        200,
        json!({"previous_seed_id": 1, "new_seed_id": 2}),
    )
    .await;
    let c = client(&server).await;
    let r = c.rotate_seed(Some("word ".repeat(24))).await.unwrap();
    assert_eq!(r.previous_seed_id, 1);
    assert_eq!(r.new_seed_id, 2);
}

// ── ACL ─────────────────────────────────────────────────────────────

/// One entry in the canonical `acl/_shared/0.1/acl-entry` wire shape:
/// `subject`/`scopes`, RFC 3339 timestamps, nested `stepUp`/`approve`.
fn acl_entry_json(did: &str) -> Value {
    json!({
        "subject": did,
        "role": "admin",
        "label": "ops",
        "scopes": ["ctx-a"],
        "createdAt": "2023-11-14T22:13:20Z",
        "createdBy": "did:web:vta",
    })
}

/// The `{ entry }` envelope canonical single-entry responses carry.
fn acl_entry_envelope(did: &str) -> Value {
    json!({ "entry": acl_entry_json(did) })
}

#[tokio::test]
async fn list_acl_no_filter() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/acl",
        200,
        json!({"entries": [acl_entry_json("did:key:zAdmin")], "truncated": false}),
    )
    .await;
    let c = client(&server).await;
    let resp = c.list_acl(None).await.unwrap();
    assert_eq!(resp.entries.len(), 1);
}

#[tokio::test]
async fn list_acl_with_context_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        // `scope`, not `context`: the task payload names the filter
        // differently from the query string it replaced.
        .and(body_partial_json(json!({
            "type": TASK_ACL_LIST,
            "payload": {"scope": "ctx-a"}
        })))
        .respond_with(tt_ok(json!({"entries": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c.list_acl(Some("ctx-a")).await.unwrap();
    assert!(resp.entries.is_empty());
}

/// A non-default direction rides the query string; `list_acl` and an explicit
/// `acting-in` must stay byte-identical to the historical request, so an older
/// VTA keeps answering them.
#[tokio::test]
async fn list_acl_sends_the_direction_only_when_it_is_not_the_default() {
    use vta_sdk::acl::ContextDirection;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({
            "payload": {"scope": "acme/eng", "direction": "subtree"}
        })))
        .respond_with(tt_ok(json!({"entries": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.list_acl_in_direction(Some("acme/eng"), ContextDirection::Subtree)
        .await
        .unwrap();
    server.reset().await;

    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({"payload": {"scope": "acme/eng"}})))
        // An old VTA rejects an unknown field, so the default direction must
        // be omitted rather than spelled out.
        .and(no_payload_key("direction"))
        .respond_with(tt_ok(json!({"entries": []})))
        .expect(2)
        .mount(&server)
        .await;
    c.list_acl(Some("acme/eng")).await.unwrap();
    c.list_acl_in_direction(Some("acme/eng"), ContextDirection::ActingIn)
        .await
        .unwrap();
}

/// Self-service key rotation is the one ACL verb whose REST route answers the
/// maintainer's flat stored row, so the client sends the canonical Trust Task
/// on REST too — through `/api/trust-tasks`, not `POST /acl/swap`. Parsing the
/// legacy route's reply is what left this method failing with
/// `missing field 'subject'` on every transport after the canonical fold.
#[tokio::test]
async fn swap_acl_sends_the_canonical_task_over_rest() {
    let server = MockServer::start().await;
    let _g = Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(wiremock::matchers::body_partial_json(json!({
            "type": "https://trusttasks.org/spec/acl/swap-key/0.1",
            "payload": {
                "currentSubject": "did:key:zOld",
                // Read out of the presentation rather than taken on trust
                // from the caller — the maintainer refuses the pair when the
                // proof says something else.
                "newSubject": "did:key:zNew",
            },
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "urn:uuid:0000",
            "type": "https://trusttasks.org/spec/acl/swap-key/0.1#response",
            "payload": {
                "entry": acl_entry_json("did:key:zNew"),
                "previousSubject": "did:key:zOld",
            },
        })))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let c = client(&server).await;
    let entry = c
        .swap_acl_for(
            "did:key:zOld",
            SwapAclRequest::new(swap_presentation("did:key:zNew")),
        )
        .await
        .unwrap();
    assert_eq!(entry.did, "did:key:zNew");
}

/// A REST client has a token, not a DID, so it cannot infer which VID is being
/// swapped out. Failing here — naming the method that takes it — beats sending
/// a request the VTA can only refuse.
#[tokio::test]
async fn swap_acl_over_rest_says_which_method_takes_the_subject() {
    let c = VtaClient::new("https://vta.example.com");
    let err = c
        .swap_acl(SwapAclRequest::new(swap_presentation("did:key:zNew")))
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("swap_acl_for"), "unhelpful error: {msg}");
}

/// A compact JWS whose payload carries `iss` — the shape `swap_acl` reads
/// `newSubject` out of. Unsigned: nothing client-side verifies it, and the
/// maintainer checks the real signature.
fn swap_presentation(iss: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        b64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#),
        b64.encode(serde_json::to_vec(&json!({ "iss": iss })).unwrap()),
        b64.encode([0u8; 64]),
    )
}

#[tokio::test]
async fn get_acl_path_encodes_did() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/acl/did:web:example.com",
        200,
        acl_entry_envelope("did:web:example.com"),
    )
    .await;
    let c = client(&server).await;
    let resp = c.get_acl("did:web:example.com").await.unwrap();
    assert_eq!(resp.did, "did:web:example.com");
}

#[tokio::test]
async fn create_acl_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/acl",
        200,
        acl_entry_envelope("did:key:zAdmin"),
    )
    .await;
    let c = client(&server).await;
    let req = CreateAclRequest::new("did:key:zAdmin", "admin")
        .label("ops")
        .contexts(vec!["ctx-a".into()])
        .expires_at(1_700_000_000);
    let resp = c.create_acl(req).await.unwrap();
    assert_eq!(resp.did, "did:key:zAdmin");
}

#[tokio::test]
async fn create_acl_409_maps_to_conflict() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "POST", "/acl", 409).await;
    let c = client(&server).await;
    let req = CreateAclRequest::new("did:key:zAdmin", "admin");
    let err = c.create_acl(req).await.unwrap_err();
    assert!(err.is_conflict());
}

#[tokio::test]
async fn update_acl_patches() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/acl/did:key:zAdmin",
        200,
        acl_entry_envelope("did:key:zAdmin"),
    )
    .await;
    let c = client(&server).await;
    let req = UpdateAclRequest {
        label: None,
        allowed_contexts: Some(vec!["ctx-b".into()]),
        step_up_approver: None,
        step_up_require: None,
        approve_scope: None,
        allowed_keys: None,
    };
    let resp = c.update_acl("did:key:zAdmin", req).await.unwrap();
    assert_eq!(resp.did, "did:key:zAdmin");
}

#[tokio::test]
async fn delete_acl_returns_unit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_acl("did:key:zAdmin").await.unwrap();
}

#[tokio::test]
async fn delete_acl_404_maps_to_not_found() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "DELETE", "/acl/x", 404).await;
    let c = client(&server).await;
    let err = c.delete_acl("x").await.unwrap_err();
    assert!(err.is_not_found());
}

// ── Contexts ────────────────────────────────────────────────────────

fn context_json(id: &str) -> Value {
    json!({
        "id": id,
        "name": "Primary",
        "did": "did:web:vta.example.com",
        "description": null,
        "base_path": "m/26'/2'/0'",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    })
}

#[tokio::test]
async fn list_contexts_returns_array() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/contexts",
        200,
        json!({"contexts": [context_json("primary")]}),
    )
    .await;
    let c = client(&server).await;
    let r = c.list_contexts().await.unwrap();
    assert_eq!(r.contexts.len(), 1);
    assert_eq!(r.contexts[0].id, "primary");
}

#[tokio::test]
async fn get_context_path_encodes_id() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/contexts/with%2Fslash",
        200,
        context_json("with/slash"),
    )
    .await;
    let c = client(&server).await;
    let r = c.get_context("with/slash").await.unwrap();
    assert_eq!(r.id, "with/slash");
}

#[tokio::test]
async fn create_context_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(&server, "POST", "/contexts", 200, context_json("primary")).await;
    let c = client(&server).await;
    let req = CreateContextRequest::new("primary", "Primary").description("first");
    let r = c.create_context(req).await.unwrap();
    assert_eq!(r.id, "primary");
    assert_eq!(r.created_at, iso("2026-01-01T00:00:00Z"));
}

#[tokio::test]
async fn update_context_patches() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/contexts/primary",
        200,
        context_json("primary"),
    )
    .await;
    let c = client(&server).await;
    let req = UpdateContextRequest {
        name: Some("Renamed".into()),
        did: None,
        description: None,
        context_policy: None,
    };
    c.update_context("primary", req).await.unwrap();
}

#[tokio::test]
async fn update_context_did_puts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PUT",
        "/contexts/primary/did",
        200,
        context_json("primary"),
    )
    .await;
    let c = client(&server).await;
    c.update_context_did("primary", "did:web:new")
        .await
        .unwrap();
}

#[tokio::test]
async fn preview_delete_context_returns_summary() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/contexts/primary/delete-preview",
        200,
        json!({
            "id": "primary",
            "keys": ["k1"],
            "webvh_dids": [],
            "acl_entries_removed": [],
            "acl_entries_updated": [],
            "did_templates": []
        }),
    )
    .await;
    let c = client(&server).await;
    let r = c.preview_delete_context("primary").await.unwrap();
    assert_eq!(r.id, "primary");
    assert_eq!(r.keys.len(), 1);
}

#[tokio::test]
async fn delete_context_with_force_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_context("primary", true).await.unwrap();
}

#[tokio::test]
async fn delete_context_no_force_omits_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_context("primary", false).await.unwrap();
}

// ── WebVH servers ───────────────────────────────────────────────────

fn webvh_server_json(id: &str) -> Value {
    json!({
        "id": id,
        "did": "did:web:server.example.com",
        "label": null,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    })
}

#[tokio::test]
async fn add_webvh_server_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/webvh/servers",
        200,
        webvh_server_json("s1"),
    )
    .await;
    let c = client(&server).await;
    let req = AddWebvhServerRequest {
        id: "s1".into(),
        did: "did:web:server.example.com".into(),
        label: None,
    };
    let r = c.add_webvh_server(req).await.unwrap();
    assert_eq!(r.id, "s1");
}

#[tokio::test]
async fn list_webvh_servers_returns_array() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/webvh/servers",
        200,
        json!({"servers": [webvh_server_json("s1")]}),
    )
    .await;
    let c = client(&server).await;
    let r = c.list_webvh_servers().await.unwrap();
    assert_eq!(r.servers.len(), 1);
}

/// The relay had no test at all before it moved onto a Trust Task. `createdAt`
/// is asserted because the VTA used to drop it: canonical `DomainEntry`
/// requires it, so a response missing it fails its own schema — and a caller
/// cannot tell a relay that withheld a member from a host that never sent one.
#[tokio::test]
async fn list_webvh_server_domains_relays_the_hosts_view() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/webvh/servers/primary-host/domains",
        200,
        json!({
            "domains": [{
                "name": "did.example.com",
                "label": "Production",
                "status": "active",
                "defaultDomain": true,
                "createdAt": "2026-03-01T00:00:00Z"
            }],
            "default": "did.example.com"
        }),
    )
    .await;
    let c = client(&server).await;
    let r = c.list_webvh_server_domains("primary-host").await.unwrap();
    assert_eq!(r.domains.len(), 1);
    assert_eq!(r.domains[0].name, "did.example.com");
    assert_eq!(
        r.domains[0].created_at.as_deref(),
        Some("2026-03-01T00:00:00Z"),
        "the relay must preserve createdAt"
    );
    assert_eq!(r.default.as_deref(), Some("did.example.com"));
}

/// A server the VTA can reach but holds no grant on answers with an empty list,
/// which is a true answer — not an error, and not "no domains exist".
#[tokio::test]
async fn list_webvh_server_domains_empty_is_a_successful_answer() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/webvh/servers/bare-host/domains",
        200,
        json!({ "domains": [] }),
    )
    .await;
    let c = client(&server).await;
    let r = c.list_webvh_server_domains("bare-host").await.unwrap();
    assert!(r.domains.is_empty());
    assert!(r.default.is_none());
}

#[tokio::test]
async fn update_webvh_server_patches() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/webvh/servers/s1",
        200,
        webvh_server_json("s1"),
    )
    .await;
    let c = client(&server).await;
    let req = UpdateWebvhServerRequest {
        label: Some("primary".into()),
    };
    c.update_webvh_server("s1", req).await.unwrap();
}

#[tokio::test]
async fn remove_webvh_server_deletes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.remove_webvh_server("s1").await.unwrap();
}

// ── WebVH DIDs ──────────────────────────────────────────────────────

fn webvh_did_record_json(did: &str) -> Value {
    json!({
        "did": did,
        "server_id": "s1",
        "mnemonic": "",
        "scid": "Qabc",
        "context_id": "primary",
        "portable": false,
        "log_entry_count": 1,
        "pre_rotation_count": 0,
        "next_fragment_id": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    })
}

#[tokio::test]
async fn create_did_webvh_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/webvh/dids",
        200,
        json!({
            "did": "did:webvh:Qabc:server.example.com:primary",
            "context_id": "primary",
            "server_id": "s1",
            "mnemonic": null,
            "scid": "Qabc",
            "portable": false,
            "signing_key_id": "k0",
            "ka_key_id": "k1",
            "pre_rotation_key_count": 0,
            "created_at": "2026-01-01T00:00:00Z"
        }),
    )
    .await;
    let c = client(&server).await;
    let req = CreateDidWebvhRequest {
        context_id: "primary".into(),
        server_id: Some("s1".into()),
        url: None,
        path: None,
        path_mode: None,
        domain: None,
        label: None,
        portable: false,
        add_mediator_service: false,
        add_tsp_service: false,
        additional_services: None,
        pre_rotation_count: 0,
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template: None,
        template_context: None,
        template_vars: Default::default(),
    };
    let r = c.create_did_webvh(req).await.unwrap();
    assert_eq!(r.scid, "Qabc");
}

#[tokio::test]
async fn list_dids_webvh_filters_by_context() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({
            "type": TASK_WEBVH_DIDS_LIST,
            // camelCase: the payload is built from `ListDidsWebvhBody`, which
            // emits the canonical spelling rather than whatever a hand-written
            // literal happened to say.
            "payload": {"contextId": "primary", "serverId": "s1"}
        })))
        .respond_with(tt_ok(json!({
            "dids": [webvh_did_record_json("did:webvh:Qabc:server.example.com:primary")]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let r = c
        .list_dids_webvh(Some("primary"), Some("s1"))
        .await
        .unwrap();
    assert_eq!(r.dids.len(), 1);
}

#[tokio::test]
async fn get_did_webvh_returns_record() {
    let server = MockServer::start().await;
    let did = "did:webvh:Qabc:server.example.com:primary";
    let _g = mount_json(
        &server,
        "GET",
        "/webvh/dids/did:webvh:Qabc:server.example.com:primary",
        200,
        webvh_did_record_json(did),
    )
    .await;
    let c = client(&server).await;
    let r = c.get_did_webvh(did).await.unwrap();
    assert_eq!(r.did, did);
}

#[tokio::test]
async fn get_did_webvh_log_returns_log() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/webvh/dids/did:webvh:abc/log",
        200,
        json!({"did": "did:webvh:abc", "log": "{\"versionId\":\"1\"}\n"}),
    )
    .await;
    let c = client(&server).await;
    let r = c.get_did_webvh_log("did:webvh:abc").await.unwrap();
    assert!(r.log.is_some());
}

#[tokio::test]
async fn delete_did_webvh_returns_unit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_did_webvh("did:webvh:abc").await.unwrap();
}

/// The canonical form keys on the DID and rides `/api/trust-tasks` on REST
/// too, so one payload shape serves all three transports. The body's members
/// sit *beside* `did` — the maintainer reads them back with `serde(flatten)`,
/// and a nested body would arrive as an update that changes nothing.
#[tokio::test]
async fn update_did_webvh_by_did_sends_the_canonical_task() {
    let server = MockServer::start().await;
    let _g = Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(wiremock::matchers::body_partial_json(json!({
            "type": "https://trusttasks.org/spec/vta/webvh/dids/update/1.0",
            "payload": {
                "did": "did:webvh:Qabc:host:slug",
                "document": {"id": "did:webvh:Qabc:host:slug"},
            },
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "urn:uuid:0000",
            "type": "https://trusttasks.org/spec/vta/webvh/dids/update/1.0#response",
            "payload": {
                "did": "did:webvh:Qabc:host:slug",
                "newVersionId": "2-z",
                "newScid": "Qabc",
                "newLogEntry": "{}",
                "updateKeysCount": 1,
                "preRotationKeyCount": 0
            },
        })))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let c = client(&server).await;
    let body = vta_sdk::protocols::did_management::update::UpdateDidWebvhBody {
        document: Some(json!({"id": "did:webvh:Qabc:host:slug"})),
        ..Default::default()
    };
    let r = c
        .update_did_webvh_by_did("did:webvh:Qabc:host:slug", body)
        .await
        .unwrap();
    assert_eq!(r.new_version_id, "2-z");
}

#[allow(deprecated)] // pins the legacy route until the method is removed
#[tokio::test]
async fn update_did_webvh_posts_to_context_path() {
    let server = MockServer::start().await;
    let _g = mount_rest_json(
        &server,
        "POST",
        "/contexts/primary/dids/Qabc/update",
        200,
        json!({
            "did": "did:webvh:Qabc",
            "new_version_id": "2-z",
            "new_scid": "Qabc",
            "new_log_entry": "{}",
            "update_keys_count": 1,
            "pre_rotation_key_count": 0
        }),
    )
    .await;
    let c = client(&server).await;
    let body = vta_sdk::protocols::did_management::update::UpdateDidWebvhBody {
        document: Some(json!({"id": "did:webvh:Qabc"})),
        ..Default::default()
    };
    let r = c.update_did_webvh("primary", "Qabc", body).await.unwrap();
    assert_eq!(r.new_version_id, "2-z");
}

#[allow(deprecated)] // pins the legacy route until the method is removed
#[tokio::test]
async fn rotate_did_webvh_keys_posts() {
    let server = MockServer::start().await;
    let _g = mount_rest_json(
        &server,
        "POST",
        "/contexts/primary/dids/Qabc/rotate-keys",
        200,
        json!({
            "did": "did:webvh:Qabc",
            "new_version_id": "3-z",
            "new_scid": "Qabc",
            "new_log_entry": "{}",
            "update_keys_count": 1,
            "pre_rotation_key_count": 2
        }),
    )
    .await;
    let c = client(&server).await;
    let body = vta_sdk::protocols::did_management::update::RotateDidWebvhKeysBody {
        pre_rotation_count: Some(2),
        label: Some("scheduled".into()),
    };
    let r = c
        .rotate_did_webvh_keys("primary", "Qabc", body)
        .await
        .unwrap();
    assert_eq!(r.pre_rotation_key_count, 2);
}

// ── Audit ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_audit_logs_paginates() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        // camelCase, per canonical `audit/list/0.1`. A snake_case key
        // here would be dropped by the handler's serde binding and the
        // filter would silently not apply.
        .and(body_partial_json(json!({
            "type": TASK_AUDIT_LIST,
            "payload": {
                "pageSize": 25,
                "action": "key.create",
                "cursor": "opaque-token"
            }
        })))
        .respond_with(tt_ok(json!({
            "entries": [{
                "eventId": "e1",
                "recordedAt": "2026-07-01T00:00:00+00:00",
                "action": "key.create",
                "outcome": "success",
                "actor": "did:key:zActor",
            }],
            "truncated": true,
            "cursor": "next-token"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
        page_size: Some(25),
        action: Some("key.create".into()),
        cursor: Some("opaque-token".into()),
        ..Default::default()
    };
    let r = c.list_audit_logs(&params).await.unwrap();
    assert!(r.truncated);
    assert_eq!(r.cursor.as_deref(), Some("next-token"));
    assert_eq!(r.entries[0].event_id, "e1");
    assert_eq!(r.entries[0].action, "key.create");
}

/// An RFC 3339 `from` ends in a `+00:00` offset. Unencoded, the `+`
/// decodes as a space and the server sees an unparseable datetime, so
/// the bound silently goes missing — the failure mode is "more rows
/// than you asked for", which on an audit query reads as a full log.
#[tokio::test]
async fn audit_list_percent_encodes_rfc3339_bounds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({
            "payload": {"from": "2026-07-01T00:00:00Z"}
        })))
        .respond_with(tt_ok(json!({"entries": [], "truncated": false})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
        from: Some("2026-07-01T00:00:00Z".parse().unwrap()),
        ..Default::default()
    };
    let r = c.list_audit_logs(&params).await.unwrap();
    assert!(!r.truncated);
}

#[tokio::test]
async fn get_audit_retention_returns_days() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/audit/retention",
        200,
        json!({"retention_days": 90}),
    )
    .await;
    let c = client(&server).await;
    let r = c.get_audit_retention().await.unwrap();
    assert_eq!(r.retention_days, 90);
}

#[tokio::test]
async fn update_audit_retention_patches() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/audit/retention",
        200,
        json!({"retention_days": 30}),
    )
    .await;
    let c = client(&server).await;
    let r = c.update_audit_retention(30).await.unwrap();
    assert_eq!(r.retention_days, 30);
}

// ── DID templates: global ───────────────────────────────────────────

fn template_record_json(name: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "name": name,
        "kind": "custom",
        "description": null,
        "methods": [],
        "requiredVars": [],
        "optionalVars": {},
        "defaults": {},
        "document": {"id": "{DID}"},
        "scope": {"type": "global"},
        "createdAt": 1_700_000_000_u64,
        "updatedAt": 1_700_000_000_u64,
        "createdBy": "did:web:vta"
    })
}

fn sample_template(name: &str) -> vta_sdk::did_templates::DidTemplate {
    serde_json::from_value(json!({
        "schemaVersion": 1,
        "name": name,
        "kind": "custom",
        "document": {"id": "{DID}"}
    }))
    .unwrap()
}

#[tokio::test]
async fn list_did_templates_returns_array() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/did-templates",
        200,
        json!({"templates": [template_record_json("custom-1")]}),
    )
    .await;
    let c = client(&server).await;
    let r = c.list_did_templates().await.unwrap();
    assert_eq!(r.len(), 1);
}

#[tokio::test]
async fn get_did_template_returns_one() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/did-templates/custom-1",
        200,
        template_record_json("custom-1"),
    )
    .await;
    let c = client(&server).await;
    let r = c.get_did_template("custom-1").await.unwrap();
    assert_eq!(r.template.name, "custom-1");
}

#[tokio::test]
async fn create_did_template_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/did-templates",
        200,
        template_record_json("new"),
    )
    .await;
    let c = client(&server).await;
    let r = c.create_did_template(sample_template("new")).await.unwrap();
    assert_eq!(r.template.name, "new");
}

#[tokio::test]
async fn update_did_template_puts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PUT",
        "/did-templates/x",
        200,
        template_record_json("x"),
    )
    .await;
    let c = client(&server).await;
    c.update_did_template("x", sample_template("x"))
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_did_template_returns_unit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_did_template("x").await.unwrap();
}

#[tokio::test]
async fn render_did_template_unwraps_document() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/did-templates/x/render",
        200,
        json!({"document": {"id": "did:web:rendered"}}),
    )
    .await;
    let c = client(&server).await;
    let r = c
        .render_did_template("x", Default::default())
        .await
        .unwrap();
    assert_eq!(r["id"], "did:web:rendered");
}

// ── DID templates: context-scoped ───────────────────────────────────

#[tokio::test]
async fn list_context_did_templates_returns_array() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/contexts/primary/did-templates",
        200,
        json!({"templates": []}),
    )
    .await;
    let c = client(&server).await;
    assert!(
        c.list_context_did_templates("primary")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn get_context_did_template_returns_one() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/contexts/primary/did-templates/x",
        200,
        template_record_json("x"),
    )
    .await;
    let c = client(&server).await;
    c.get_context_did_template("primary", "x").await.unwrap();
}

#[tokio::test]
async fn create_context_did_template_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/contexts/primary/did-templates",
        200,
        template_record_json("x"),
    )
    .await;
    let c = client(&server).await;
    c.create_context_did_template("primary", sample_template("x"))
        .await
        .unwrap();
}

#[tokio::test]
async fn update_context_did_template_puts() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PUT",
        "/contexts/primary/did-templates/x",
        200,
        template_record_json("x"),
    )
    .await;
    let c = client(&server).await;
    c.update_context_did_template("primary", "x", sample_template("x"))
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_context_did_template_returns_unit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"payload": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_context_did_template("primary", "x").await.unwrap();
}

#[tokio::test]
async fn render_context_did_template_unwraps_document() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/contexts/primary/did-templates/x/render",
        200,
        json!({"document": {"id": "did:web:ctx-rendered"}}),
    )
    .await;
    let c = client(&server).await;
    let r = c
        .render_context_did_template("primary", "x", Default::default())
        .await
        .unwrap();
    assert_eq!(r["id"], "did:web:ctx-rendered");
}

// ── check_auth ──────────────────────────────────────────────────────

#[tokio::test]
async fn check_auth_true_when_200() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health/details"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    assert!(c.check_auth().await.unwrap());
}

#[tokio::test]
async fn check_auth_false_when_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health/details"))
        .respond_with(ResponseTemplate::new(401).set_body_json(err_body("expired")))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    assert!(!c.check_auth().await.unwrap());
}

// ── Convenience: paginated secret fetch ─────────────────────────────

#[tokio::test]
async fn fetch_context_secrets_walks_all_pages() {
    let server = MockServer::start().await;

    // Page 1: 100 keys, total = 101
    let mut page1_keys = Vec::new();
    for i in 0..100 {
        page1_keys.push(key_record_json(&format!("k{i}")));
    }
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({
            "type": TASK_KEYS_LIST,
            "payload": {"offset": 0}
        })))
        .respond_with(tt_ok(json!({
            "keys": page1_keys,
            "total": 101
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Page 2: 1 key
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(json!({
            "type": TASK_KEYS_LIST,
            "payload": {"offset": 100}
        })))
        .respond_with(tt_ok(json!({
            "keys": [key_record_json("k100")],
            "total": 101
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Each get_key_secret responds with a fixed multibase pair. The
    // mock matches /keys/{id}/secret regardless of which key id; the
    // x25519 multibase below is a literal `[2u8; 32]` encoded with
    // multicodec X25519 (0xec01) — `secret_from_key_response` accepts
    // any 32-byte key, so the value just needs to round-trip.
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(auth_match())
        .and(body_partial_json(
            json!({"type": TASK_SEEDS_EXPORT_MNEMONIC}),
        ))
        .respond_with(tt_ok(json!({
            "key_id": "k",
            "key_type": "x25519",
            "public_key_multibase": "z6LSqHQEbN8eMpx9NhMTXmxqYDhtbW5kqwQYWN9y91vxqMtq",
            "private_key_multibase": "z3wei5qxuQ8mvebtP4WQiK3CsPuiL6XvfVmuhXKfzKKAwgvY"
        })))
        .expect(101)
        .mount(&server)
        .await;

    let c = client(&server).await;
    let secrets = c.fetch_context_secrets("primary").await.unwrap();
    assert_eq!(secrets.len(), 101);
}

// ── Error-mapping coverage (status → typed variant) ─────────────────

#[tokio::test]
async fn http_400_maps_to_validation() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "GET", "/config", 400).await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    assert!(matches!(err, VtaError::Validation(_)));
}

#[tokio::test]
async fn http_401_maps_to_auth() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "GET", "/config", 401).await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    assert!(matches!(err, VtaError::Auth(_)));
}

#[tokio::test]
async fn http_410_maps_to_gone() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "GET", "/config", 410).await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    assert!(err.is_gone());
}

#[tokio::test]
async fn http_422_maps_to_validation() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "GET", "/config", 422).await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    assert!(matches!(err, VtaError::Validation(_)));
}

#[tokio::test]
async fn http_418_maps_to_other() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "GET", "/config", 418).await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    assert!(matches!(err, VtaError::Other(_)));
}

#[tokio::test]
async fn malformed_error_body_falls_back_to_raw_text() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .respond_with(ResponseTemplate::new(500).set_body_string("not json"))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    match err {
        VtaError::Server { status, body } => {
            assert_eq!(status, 500);
            assert_eq!(body, "unknown error: not json");
        }
        other => panic!("expected Server, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_error_body_is_truncated() {
    // A large non-JSON body (e.g. a proxy error page) must not bloat the
    // error string. The fallback truncates the raw text and marks it with `…`.
    let server = MockServer::start().await;
    let huge = "x".repeat(10_000);
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .respond_with(ResponseTemplate::new(500).set_body_string(huge))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let err = c.get_config().await.unwrap_err();
    match err {
        VtaError::Server { status, body } => {
            assert_eq!(status, 500);
            // "unknown error: " (15) + 256 chars + "…" — far smaller than 10k.
            assert!(body.len() < 600, "body not truncated: {} bytes", body.len());
            assert!(body.starts_with("unknown error: x"));
            assert!(body.ends_with('…'), "expected truncation marker");
        }
        other => panic!("expected Server, got {other:?}"),
    }
}

// ── Connection/transport ────────────────────────────────────────────

#[tokio::test]
async fn network_error_when_server_unreachable() {
    // Port 1 is reserved (TCPMUX) and effectively never listens on
    // dev/CI machines — connection refused → reqwest::Error → Network.
    let c = VtaClient::new("http://127.0.0.1:1");
    c.set_token_async(TOKEN.into()).await;
    let err = c.get_config().await.unwrap_err();
    assert!(err.is_network(), "got {err:?}");
}

// ── REST URL accessors ──────────────────────────────────────────────

#[tokio::test]
async fn rest_url_returned_after_construction() {
    let c = VtaClient::new("https://vta.example.com");
    assert_eq!(c.rest_url(), Some("https://vta.example.com"));
}

#[tokio::test]
async fn token_expires_at_none_until_set() {
    let c = VtaClient::new("https://vta.example.com");
    assert!(c.token_expires_at().await.is_none());
}

#[tokio::test]
async fn shutdown_is_noop_for_rest() {
    // REST-only client: shutdown() is documented as a no-op. Just make
    // sure it doesn't panic or hang.
    let c = VtaClient::new("https://vta.example.com");
    c.shutdown().await;
}
