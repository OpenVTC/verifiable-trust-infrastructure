//! Coverage for `VtaClient::Transport::DIDComm` arms — each REST
//! method's DIDComm path through `session::send_and_wait`.
//!
//! Builds a `VtaClient` via `connect_didcomm` against a `TestMediator`
//! and a `TestVtaResponder` that runs as the VTA. Each test exercises
//! a single SDK method and asserts the SDK's request shape (msg_type)
//! and response decoding work end-to-end through the routing/2.0
//! forward envelope path enforced by the test mediator.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use vta_sdk::client::*;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::error::VtaError;
use vta_sdk::keys::{KeyOrigin, KeyStatus, KeyType};
use vta_sdk::protocols::key_management::sign::SignAlgorithm;
use vta_sdk::protocols::{
    acl_management, audit_management, backup_management, context_management, did_management,
    discovery, key_management, seed_management, vta_management,
};
use vta_sdk::trust_tasks;

mod common;
use common::test_vta_responder::{ResponderReply, TestVtaResponder};

// ── Test fixtures ───────────────────────────────────────────────────

fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

/// Stand up mediator + responder + VtaClient bound to them. Returns
/// owned handles so the caller controls shutdown order. The handler
/// receives `(msg_type, body)` and returns a [`ResponderReply`].
async fn build_didcomm<F>(
    handler: F,
) -> (
    affinidi_messaging_test_mediator::TestMediatorHandle,
    TestVtaResponder,
    VtaClient,
)
where
    F: Fn(&str, &Value) -> ResponderReply + Send + Sync + 'static,
{
    common::init_tracing();
    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (mediator, responder) =
        TestVtaResponder::spawn_with_mediator(vec![client_did.clone()], handler)
            .await
            .expect("responder + mediator spawn");
    let client = VtaClient::connect_didcomm(
        &client_did,
        &client_priv,
        responder.did(),
        mediator.did(),
        None,
    )
    .await
    .expect("client connects via didcomm");
    (mediator, responder, client)
}

async fn shutdown_all(
    client: VtaClient,
    responder: TestVtaResponder,
    mediator: affinidi_messaging_test_mediator::TestMediatorHandle,
) {
    client.shutdown().await;
    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

fn key_record_json(id: &str) -> Value {
    json!({
        "key_id": id,
        "derivation_path": "m/0/0",
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

fn acl_entry_json(did: &str) -> Value {
    json!({
        "did": did,
        "role": "admin",
        "label": "ops",
        "allowed_contexts": ["primary"],
        "created_at": 1_700_000_000_u64,
        "created_by": "did:web:vta",
        "expires_at": null
    })
}

// ── Discovery / VTA management ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capabilities_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == discovery::DISCOVER_CAPABILITIES {
            ResponderReply::ok(
                discovery::DISCOVER_CAPABILITIES_RESULT,
                json!({
                    "version": "0.5.0",
                    "features": {"webvh": true, "didcomm": true, "tee": false, "rest": true},
                    "services": {"rest": true, "didcomm": true},
                    "webvh_servers": [],
                    "did_creation_modes": ["webvh"]
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let caps = client.capabilities().await.unwrap();
    assert_eq!(caps.version, "0.5.0");
    assert!(caps.features.didcomm);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == vta_management::RESTART {
            ResponderReply::ok(
                vta_management::RESTART_RESULT,
                json!({"status": "restarting"}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    assert_eq!(client.restart().await.unwrap().status, "restarting");

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_config_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == vta_management::GET_CONFIG {
            ResponderReply::ok(
                vta_management::GET_CONFIG_RESULT,
                json!({
                    "vta_did": "did:web:vta.example.com",
                    "vta_name": "primary",
                    "public_url": "https://vta.example.com"
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let cfg = client.get_config().await.unwrap();
    assert_eq!(cfg.community_vta_name.as_deref(), Some("primary"));

    shutdown_all(client, responder, mediator).await;
}

// ── Keys ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_keys_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == key_management::LIST_KEYS {
            ResponderReply::ok(
                key_management::LIST_KEYS_RESULT,
                json!({"keys": [key_record_json("k1"), key_record_json("k2")], "total": 2}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let resp = client.list_keys(0, 10, None, None).await.unwrap();
    assert_eq!(resp.total, 2);
    assert_eq!(resp.keys.len(), 2);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_key_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == key_management::GET_KEY {
            ResponderReply::ok(key_management::GET_KEY_RESULT, key_record_json("k1"))
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let key = client.get_key("k1").await.unwrap();
    assert_eq!(key.key_id, "k1");

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_key_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, body| {
        if msg_type == key_management::CREATE_KEY {
            assert_eq!(body["key_type"], "ed25519");
            ResponderReply::ok(
                key_management::CREATE_KEY_RESULT,
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
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let req = CreateKeyRequest::new(KeyType::Ed25519);
    let resp = client.create_key(req).await.unwrap();
    assert_eq!(resp.key_id, "k1");
    assert_eq!(resp.status, KeyStatus::Active);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_via_didcomm_round_trips_payload() {
    let (mediator, responder, client) = build_didcomm(|msg_type, body| {
        if msg_type == key_management::SIGN_REQUEST {
            // Verify the SDK base64url-encoded the payload.
            assert_eq!(body["payload"], "aGVsbG8");
            ResponderReply::ok(
                key_management::SIGN_RESULT,
                json!({"key_id": "k1", "signature": "AQID", "algorithm": "eddsa"}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let sig = client
        .sign("k1", b"hello", SignAlgorithm::EdDSA)
        .await
        .unwrap();
    assert_eq!(sig.signature, "AQID");

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidate_key_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == key_management::REVOKE_KEY {
            ResponderReply::ok(
                key_management::REVOKE_KEY_RESULT,
                json!({
                    "key_id": "k1",
                    "status": "revoked",
                    "updated_at": "2026-01-01T00:00:00Z"
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let resp = client.invalidate_key("k1").await.unwrap();
    assert_eq!(resp.status, KeyStatus::Revoked);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_key_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == key_management::RENAME_KEY {
            ResponderReply::ok(
                key_management::RENAME_KEY_RESULT,
                json!({"key_id": "new", "updated_at": "2026-01-01T00:00:00Z"}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let resp = client.rename_key("old", "new").await.unwrap();
    assert_eq!(resp.key_id, "new");

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_key_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == key_management::IMPORT_KEY {
            ResponderReply::ok(
                key_management::IMPORT_KEY_RESULT,
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
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let req = ImportKeyRequest {
        key_type: KeyType::Ed25519,
        private_key_sealed: None,
        private_key_jwe: None,
        private_key_multibase: Some("zSeed".into()),
        label: None,
        context_id: None,
    };
    let resp = client.import_key(req).await.unwrap();
    assert_eq!(resp.key_id, "imported");
    assert_eq!(resp.origin, KeyOrigin::Imported);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_key_secret_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == key_management::GET_KEY_SECRET {
            ResponderReply::ok(
                key_management::GET_KEY_SECRET_RESULT,
                json!({
                    "key_id": "k1",
                    "key_type": "ed25519",
                    "public_key_multibase": "z6Mkpub",
                    "private_key_multibase": "zPriv"
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let s = client.get_key_secret("k1").await.unwrap();
    assert_eq!(s.private_key_multibase, "zPriv");

    shutdown_all(client, responder, mediator).await;
}

// ── Seeds ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_seeds_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == seed_management::LIST_SEEDS {
            ResponderReply::ok(
                seed_management::LIST_SEEDS_RESULT,
                json!({
                    "seeds": [{
                        "id": 1, "status": "active",
                        "created_at": "2026-01-01T00:00:00Z", "retired_at": null
                    }],
                    "active_seed_id": 1
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.list_seeds().await.unwrap();
    assert_eq!(r.active_seed_id, 1);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_seed_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == seed_management::ROTATE_SEED {
            ResponderReply::ok(
                seed_management::ROTATE_SEED_RESULT,
                json!({"previous_seed_id": 1, "new_seed_id": 2}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.rotate_seed(None).await.unwrap();
    assert_eq!(r.new_seed_id, 2);

    shutdown_all(client, responder, mediator).await;
}

// ── ACL ─────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_acl_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == acl_management::LIST_ACL {
            ResponderReply::ok(
                acl_management::LIST_ACL_RESULT,
                json!({"entries": [acl_entry_json("did:key:zAdmin")]}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.list_acl(None).await.unwrap();
    assert_eq!(r.entries.len(), 1);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_acl_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == acl_management::CREATE_ACL {
            ResponderReply::ok(
                acl_management::CREATE_ACL_RESULT,
                acl_entry_json("did:key:zAdmin"),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let req = CreateAclRequest::new("did:key:zAdmin", "admin");
    let resp = client.create_acl(req).await.unwrap();
    assert_eq!(resp.did, "did:key:zAdmin");

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_acl_via_didcomm_returns_unit() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == acl_management::DELETE_ACL {
            // rpc_void path: any non-error response works; the SDK
            // doesn't deserialize the body for unit-returning calls.
            ResponderReply::ok(acl_management::DELETE_ACL_RESULT, json!({}))
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    client.delete_acl("did:key:zAdmin").await.unwrap();

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_acl_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == acl_management::UPDATE_ACL {
            ResponderReply::ok(
                acl_management::UPDATE_ACL_RESULT,
                acl_entry_json("did:key:zAdmin"),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let req = UpdateAclRequest {
        role: Some("reader".into()),
        label: None,
        allowed_contexts: None,
        step_up_approver: None,
        step_up_require: None,
    };
    client.update_acl("did:key:zAdmin", req).await.unwrap();

    shutdown_all(client, responder, mediator).await;
}

// ── Contexts ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_contexts_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == context_management::LIST_CONTEXTS {
            ResponderReply::ok(
                context_management::LIST_CONTEXTS_RESULT,
                json!({"contexts": [context_json("primary")]}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.list_contexts().await.unwrap();
    assert_eq!(r.contexts.len(), 1);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_context_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == context_management::CREATE_CONTEXT {
            ResponderReply::ok(
                context_management::CREATE_CONTEXT_RESULT,
                context_json("primary"),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let req = CreateContextRequest::new("primary", "Primary");
    client.create_context(req).await.unwrap();

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_context_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, body| {
        if msg_type == context_management::DELETE_CONTEXT {
            assert_eq!(body["force"], true);
            ResponderReply::ok(context_management::DELETE_CONTEXT_RESULT, json!({}))
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    client.delete_context("primary", true).await.unwrap();

    shutdown_all(client, responder, mediator).await;
}

// ── Audit ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_audit_retention_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == audit_management::GET_RETENTION {
            ResponderReply::ok(
                audit_management::GET_RETENTION_RESULT,
                json!({"retention_days": 90}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.get_audit_retention().await.unwrap();
    assert_eq!(r.retention_days, 90);

    shutdown_all(client, responder, mediator).await;
}

// ── DID templates ───────────────────────────────────────────────────

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

/// DIDComm template management is dispatched as a Trust Task: the SDK sends the
/// binding-envelope type carrying `{type: vta/did-templates/list/1.0, payload}`,
/// and the VTA replies with a trust-task document whose `payload` is the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_did_templates_via_didcomm() {
    const TT_ENVELOPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
    let (mediator, responder, client) = build_didcomm(|msg_type, body| {
        if msg_type == TT_ENVELOPE
            && body.get("type").and_then(|v| v.as_str())
                == Some(trust_tasks::TASK_DID_TEMPLATES_LIST_1_0)
        {
            ResponderReply::ok(
                TT_ENVELOPE,
                json!({
                    "id": "urn:uuid:resp-1",
                    "type": format!("{}#response", trust_tasks::TASK_DID_TEMPLATES_LIST_1_0),
                    "payload": {"templates": [template_record_json("custom-1")]}
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.list_did_templates().await.unwrap();
    assert_eq!(r.len(), 1);

    shutdown_all(client, responder, mediator).await;
}

// ── WebVH ────────────────────────────────────────────────────────────

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_dids_webvh_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == did_management::LIST_DIDS_WEBVH {
            ResponderReply::ok(
                did_management::LIST_DIDS_WEBVH_RESULT,
                json!({"dids": [webvh_did_record_json("did:webvh:abc")]}),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let r = client.list_dids_webvh(None, None).await.unwrap();
    assert_eq!(r.dids.len(), 1);

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_did_webvh_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == did_management::DELETE_DID_WEBVH {
            ResponderReply::ok(did_management::DELETE_DID_WEBVH_RESULT, json!({}))
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    client.delete_did_webvh("did:webvh:abc").await.unwrap();

    shutdown_all(client, responder, mediator).await;
}

// ── Backup ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_export_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|msg_type, _body| {
        if msg_type == backup_management::EXPORT_BACKUP {
            ResponderReply::ok(
                backup_management::EXPORT_BACKUP_RESULT,
                json!({
                    "version": 1,
                    "format": "vtabak/v1",
                    "created_at": "2026-05-05T12:00:00Z",
                    "source_version": "0.5.0",
                    "kdf": {"algorithm": "argon2id", "salt": "AAAA", "m_cost": 65536, "t_cost": 3, "p_cost": 4},
                    "encryption": {"algorithm": "AES-256-GCM", "nonce": "AAAA"},
                    "includes_audit": false,
                    "ciphertext": "AAAA"
                }),
            )
        } else {
            ResponderReply::problem_report("e.p.msg.not-found", "no handler")
        }
    })
    .await;

    let env = client.backup_export("hunter2hunter2", false).await.unwrap();
    assert_eq!(env.version, 1);

    shutdown_all(client, responder, mediator).await;
}

// ── Error mapping through the rpc layer ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_keys_problem_report_maps_to_typed_error() {
    let (mediator, responder, client) = build_didcomm(|_msg_type, _body| {
        ResponderReply::problem_report("e.p.msg.unauthorized", "expired token")
    })
    .await;

    let err = client.list_keys(0, 10, None, None).await.unwrap_err();
    assert!(matches!(err, VtaError::Auth(_)), "got {err:?}");

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_keys_unknown_problem_code_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|_msg_type, _body| {
        ResponderReply::problem_report("e.custom.weird", "domain-specific")
    })
    .await;

    let err = client.list_keys(0, 10, None, None).await.unwrap_err();
    match err {
        VtaError::DidcommRemote { code, .. } => assert_eq!(code, "e.custom.weird"),
        other => panic!("expected DidcommRemote, got {other:?}"),
    }

    shutdown_all(client, responder, mediator).await;
}

// ── Unsupported-transport branches ──────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_wrapping_key_returns_unsupported_transport_via_didcomm() {
    let (mediator, responder, client) = build_didcomm(|_, _| ResponderReply::Drop).await;

    let err = client.get_wrapping_key().await.unwrap_err();
    assert!(
        matches!(err, VtaError::UnsupportedTransport(_)),
        "got {err:?}"
    );

    shutdown_all(client, responder, mediator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_via_didcomm_without_rest_url_is_unsupported_transport() {
    let (mediator, responder, client) = build_didcomm(|_, _| ResponderReply::Drop).await;

    // `connect_didcomm` was called with `rest_url: None`, so the
    // DIDComm transport's `health()` arm rejects with
    // `UnsupportedTransport`.
    let err = client.health().await.unwrap_err();
    assert!(
        matches!(err, VtaError::UnsupportedTransport(_)),
        "got {err:?}"
    );

    shutdown_all(client, responder, mediator).await;
}

// ── check_auth: DIDComm-side always returns true ────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_auth_via_didcomm_always_true() {
    let (mediator, responder, client) = build_didcomm(|_, _| ResponderReply::Drop).await;

    // Documented behavior: DIDComm sessions are always authenticated.
    assert!(client.check_auth().await.unwrap());

    shutdown_all(client, responder, mediator).await;
}

// ── Session lifecycle: sequential reuse must not duel (#290 / #296) ──

/// Two sequential `connect → use → close` cycles for the **same** client DID
/// against one mediator must not overlap. If a cycle leaked its session (no
/// `shutdown()`), the next cycle's session would fight it on the mediator
/// (`Duplicate WebSocket connection: closing old session …`) and the
/// round-trip would time out. [`VtaClient::with_didcomm`] guarantees
/// `shutdown()` on scope exit, so both cycles complete cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_didcomm_sequential_cycles_for_same_did_do_not_duel() {
    common::init_tracing();
    let (client_did, client_priv) = did_key_from_seed(0x11);

    // One persistent mediator + VTA responder for both cycles.
    let (mediator, responder) = TestVtaResponder::spawn_with_mediator(
        vec![client_did.clone()],
        |msg_type: &str, _body: &Value| {
            if msg_type == discovery::DISCOVER_CAPABILITIES {
                ResponderReply::ok(
                    discovery::DISCOVER_CAPABILITIES_RESULT,
                    json!({
                        "version": "0.5.0",
                        "features": {"webvh": true, "didcomm": true, "tee": false, "rest": true},
                        "services": {"rest": true, "didcomm": true},
                        "webvh_servers": [],
                        "did_creation_modes": ["webvh"]
                    }),
                )
            } else {
                ResponderReply::problem_report("e.p.msg.not-found", "no handler")
            }
        },
    )
    .await
    .expect("responder + mediator spawn");

    for cycle in 0..2u8 {
        let caps = VtaClient::with_didcomm(
            &client_did,
            &client_priv,
            responder.did(),
            mediator.did(),
            None,
            |client| async move { client.capabilities().await },
        )
        .await
        .unwrap_or_else(|e| panic!("cycle {cycle} round-trip failed — leaked-session duel? {e:?}"));
        assert_eq!(caps.version, "0.5.0", "cycle {cycle}");
    }

    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

// ── Provision runner shuts its session down on the error path (#300) ──

/// The `provision_client` DIDComm runner opens its own setup-key
/// [`DIDCommSession`] internally (not via [`VtaClient`]), so it owns the
/// `shutdown()` obligation. Before the fix it dropped the session on the
/// error path, tripping the `LeakGuard` `debug_assert!` (#292/#300) in
/// debug builds.
///
/// Drive one provisioning flight whose VTA denies the request
/// (`e.p.msg.forbidden`): the round-trip returns `Err`, and the runner
/// must still have shut the session down — reaching this assertion at
/// all (no `LeakGuard` panic) is the regression check. The acceptance
/// criterion in #300 is exactly "a debug-build provisioning run against
/// the mock VTA does not trip the LeakGuard."
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_admin_rotation_didcomm_shuts_session_down_on_error() {
    use vta_sdk::protocols::provision_integration_management::CANONICAL_PROVISION_INTEGRATION;
    use vta_sdk::provision_client::{ProvisionAsk, provision_admin_rotation_via_didcomm};

    common::init_tracing();
    // The setup DID the operator would have enrolled via `pnm acl create`.
    let (setup_did, setup_priv) = did_key_from_seed(0x11);

    let (mediator, responder) = TestVtaResponder::spawn_with_mediator(
        vec![setup_did.clone()],
        |msg_type: &str, _body: &Value| {
            if msg_type == CANONICAL_PROVISION_INTEGRATION {
                // Deny — exercises the runner's error path, which must
                // still shut the session down before returning.
                ResponderReply::problem_report("e.p.msg.forbidden", "denied for test")
            } else {
                ResponderReply::problem_report("e.p.msg.not-found", "no handler")
            }
        },
    )
    .await
    .expect("responder + mediator spawn");

    let ask = ProvisionAsk::vta_admin_rotated("test-context");
    let result = provision_admin_rotation_via_didcomm(
        &setup_did,
        &setup_priv,
        responder.did(),
        mediator.did(),
        &ask,
    )
    .await;

    // The VTA denied the request, so the round-trip fails — but reaching
    // this line (no LeakGuard panic from a dropped, un-shut-down session)
    // is the actual regression assertion for #300.
    assert!(
        result.is_err(),
        "expected the denying VTA to fail the round-trip"
    );

    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}
