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
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// Helper to mount a single mock that matches method + path + auth and
/// returns a JSON body. The mock is auto-asserted via `.expect(1)` so a
/// missing or extra call surfaces in the test failure.
async fn mount_json(
    server: &MockServer,
    m: &str,
    p: &str,
    status: u16,
    body: Value,
) -> wiremock::MockGuard {
    let resp = ResponseTemplate::new(status).set_body_json(body);
    Mock::given(method(m))
        .and(path(p))
        .and(auth_match())
        .respond_with(resp)
        .expect(1)
        .mount_as_scoped(server)
        .await
}

async fn mount_status(server: &MockServer, m: &str, p: &str, status: u16) -> wiremock::MockGuard {
    Mock::given(method(m))
        .and(path(p))
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
async fn get_config_returns_fields() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/config",
        200,
        json!({
            "vta_did": "did:web:vta.example.com",
            "vta_name": "primary",
            "public_url": "https://vta.example.com"
        }),
    )
    .await;
    let c = client(&server).await;
    let cfg = c.get_config().await.unwrap();
    assert_eq!(
        cfg.community_vta_did.as_deref(),
        Some("did:web:vta.example.com")
    );
    assert_eq!(cfg.community_vta_name.as_deref(), Some("primary"));
}

#[tokio::test]
async fn update_config_sends_patch_body() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "PATCH",
        "/config",
        200,
        json!({
            "vta_did": "did:web:new",
            "vta_name": "new",
            "public_url": null
        }),
    )
    .await;
    let c = client(&server).await;
    let req = UpdateConfigRequest {
        vta_did: Some("did:web:new".into()),
        vta_name: Some("new".into()),
        public_url: None,
    };
    let cfg = c.update_config(req).await.unwrap();
    assert_eq!(cfg.community_vta_name.as_deref(), Some("new"));
}

// ── Backup ──────────────────────────────────────────────────────────

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
    let _g = mount_json(&server, "POST", "/backup/export", 200, envelope).await;
    let c = client(&server).await;
    let env = c.backup_export("hunter2hunter2", false).await.unwrap();
    assert_eq!(env.version, 1);
    assert!(!env.includes_audit);
}

#[tokio::test]
async fn backup_export_403_maps_to_forbidden() {
    let server = MockServer::start().await;
    let _g = mount_status(&server, "POST", "/backup/export", 403).await;
    let c = client(&server).await;
    let err = c.backup_export("pw", false).await.unwrap_err();
    assert!(matches!(err, VtaError::Forbidden(_)));
    assert!(err.is_auth());
}

// ── Keys ────────────────────────────────────────────────────────────

fn key_record_json(id: &str) -> Value {
    json!({
        "key_id": id,
        "derivation_path": "m/44'/0'/0'",
        "key_type": "ed25519",
        "status": "active",
        "public_key": "z6Mkpub",
        "label": null,
        "context_id": null,
        "seed_id": 1,
        "origin": "derived",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    })
}

#[tokio::test]
async fn create_key_round_trip() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "POST",
        "/keys",
        200,
        json!({
            "key_id": "k1",
            "key_type": "ed25519",
            "derivation_path": "m/0/0",
            "public_key": "z6Mkpub",
            "status": "active",
            "label": null,
            "created_at": "2026-01-01T00:00:00Z"
        }),
    )
    .await;
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
    Mock::given(method("GET"))
        .and(path("/keys"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("offset", "10"))
        .and(wiremock::matchers::query_param("limit", "5"))
        .and(wiremock::matchers::query_param("status", "active"))
        .and(wiremock::matchers::query_param("context_id", "ctx-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
        key_record_json("did:web:example.com#key-1"),
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
    let _g = mount_json(
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
        json!({
            "key_id": "imported",
            "key_type": "ed25519",
            "public_key": "z6Mkpub",
            "status": "active",
            "label": null,
            "origin": "imported",
            "created_at": "2026-01-01T00:00:00Z"
        }),
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

fn acl_entry_json(did: &str) -> Value {
    json!({
        "did": did,
        "role": "admin",
        "label": "ops",
        "allowed_contexts": ["ctx-a"],
        "created_at": 1_700_000_000_u64,
        "created_by": "did:web:vta",
        "expires_at": null
    })
}

#[tokio::test]
async fn list_acl_no_filter() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/acl",
        200,
        json!({"entries": [acl_entry_json("did:key:zAdmin")]}),
    )
    .await;
    let c = client(&server).await;
    let resp = c.list_acl(None).await.unwrap();
    assert_eq!(resp.entries.len(), 1);
}

#[tokio::test]
async fn list_acl_with_context_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/acl"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("context", "ctx-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let resp = c.list_acl(Some("ctx-a")).await.unwrap();
    assert!(resp.entries.is_empty());
}

#[tokio::test]
async fn get_acl_path_encodes_did() {
    let server = MockServer::start().await;
    let _g = mount_json(
        &server,
        "GET",
        "/acl/did:web:example.com",
        200,
        acl_entry_json("did:web:example.com"),
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
        acl_entry_json("did:key:zAdmin"),
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
        acl_entry_json("did:key:zAdmin"),
    )
    .await;
    let c = client(&server).await;
    let req = UpdateAclRequest {
        role: Some("reader".into()),
        label: None,
        allowed_contexts: Some(vec!["ctx-b".into()]),
        step_up_approver: None,
        step_up_require: None,
        approve_scope: None,
    };
    let resp = c.update_acl("did:key:zAdmin", req).await.unwrap();
    assert_eq!(resp.did, "did:key:zAdmin");
}

#[tokio::test]
async fn delete_acl_returns_unit() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/acl/did:key:zAdmin"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(204))
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
    Mock::given(method("DELETE"))
        .and(path("/contexts/primary"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("force", "true"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_context("primary", true).await.unwrap();
}

#[tokio::test]
async fn delete_context_no_force_omits_query() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/contexts/primary"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(204))
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
    Mock::given(method("DELETE"))
        .and(path("/webvh/servers/s1"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(204))
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
    Mock::given(method("GET"))
        .and(path("/webvh/dids"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("context_id", "primary"))
        .and(wiremock::matchers::query_param("server_id", "s1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
    Mock::given(method("DELETE"))
        .and(path("/webvh/dids/did:webvh:abc"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    c.delete_did_webvh("did:webvh:abc").await.unwrap();
}

#[tokio::test]
async fn update_did_webvh_posts_to_context_path() {
    let server = MockServer::start().await;
    let _g = mount_json(
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

#[tokio::test]
async fn rotate_did_webvh_keys_posts() {
    let server = MockServer::start().await;
    let _g = mount_json(
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
    Mock::given(method("GET"))
        .and(path("/audit/logs"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("page", "2"))
        .and(wiremock::matchers::query_param("page_size", "25"))
        .and(wiremock::matchers::query_param("action", "key.create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [],
            "total": 0,
            "page": 2,
            "page_size": 25,
            "total_pages": 0
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server).await;
    let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
        page: 2,
        page_size: 25,
        action: Some("key.create".into()),
        ..Default::default()
    };
    let r = c.list_audit_logs(&params).await.unwrap();
    assert_eq!(r.page, 2);
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
    Mock::given(method("DELETE"))
        .and(path("/did-templates/x"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(204))
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
    Mock::given(method("DELETE"))
        .and(path("/contexts/primary/did-templates/x"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(204))
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
    Mock::given(method("GET"))
        .and(path("/keys"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": page1_keys,
            "total": 101
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Page 2: 1 key
    Mock::given(method("GET"))
        .and(path("/keys"))
        .and(auth_match())
        .and(wiremock::matchers::query_param("offset", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
    Mock::given(method("GET"))
        .and(path_regex(r"^/keys/[^/]+/secret$"))
        .and(auth_match())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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

// `path_regex` is in `wiremock::matchers` — re-exported here for
// readability above.
use wiremock::matchers::path_regex;

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
    Mock::given(method("GET"))
        .and(path("/config"))
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
    Mock::given(method("GET"))
        .and(path("/config"))
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
