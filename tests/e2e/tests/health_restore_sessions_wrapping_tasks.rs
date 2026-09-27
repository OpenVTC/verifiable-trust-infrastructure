//! The four Trust Tasks that replaced REST routes — `vta/health/details/0.1`,
//! `vta/restore/status/0.1`, `auth/revoke-session/0.2` and
//! `keys/import-wrapping-key/0.1` — reach a running VTA over **TSP, DIDComm
//! and HTTPS** alike, through the SDK a real client uses.
//!
//! ## Why this exists
//!
//! Every one of them used to be a REST route (`GET /health/details`,
//! `DELETE /auth/sessions…`, `GET /keys/import/wrapping-key`), which a VTA
//! reachable only over a mediator could not serve at all. The handler tests in
//! `vta-service` drive the dispatch core directly; only a VTA behind a real
//! mediator shows that each task is dispatched on the shared spine for every
//! transport, that the reply comes back signed and verifies at the client, and
//! — for the public task — that a sender the VTA's ACL does not know is still
//! answered over DIDComm and TSP.
//!
//! Hermetic: `MockVta::start_with_transports` embeds a `TestMediator`, and the
//! same mock serves the HTTPS binding (`POST /trust-tasks`).
//!
//! Each test runs on 8 MiB worker stacks, for the reason `backup_chunked`
//! records: in a debug build the VTA's DIDComm inbound task polls the whole
//! dispatch future on a worker stack.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use vta_sdk::client::{RevokeSessions, SurfaceTransport, VtaClient};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::sealed_transfer::{
    AssertionProof, InMemoryNonceStore, ProducerAssertion, RawPrivateKey, SealedPayloadV1, armor,
    generate_ed25519_keypair, seal_payload,
};
use vta_service::acl::Role;
use vta_service::test_support::MockVta;
use vti_common::auth::session::{Session, SessionState, list_sessions, now_epoch, store_session};

mod common;

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

fn run(fut: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(fut);
}

/// One client per transport, each its own DID (the mediator allows one socket
/// per DID). `seed` picks the three identities: `seed` for HTTPS, `seed + 1`
/// for DIDComm, `seed + 2` for TSP. `role` is what each is granted in the ACL;
/// `None` grants nothing, so the DIDComm and TSP senders are unknown to the VTA.
async fn clients(mock: &MockVta, seed: u8, role: Option<Role>) -> Vec<(&'static str, VtaClient)> {
    let https = mock
        .signing_client(
            seed,
            match &role {
                Some(Role::Admin) | None => "admin",
                Some(_) => "reader",
            },
            match &role {
                Some(Role::Admin) | None => vec![],
                Some(_) => vec!["ctx-a".into()],
            },
        )
        .await;

    let (didcomm_did, didcomm_priv) = did_key_from_seed(seed + 1);
    let (tsp_did, tsp_priv) = did_key_from_seed(seed + 2);
    for did in [&didcomm_did, &tsp_did] {
        mock.register_mediator_account(did).await;
        match &role {
            Some(Role::Admin) => mock.grant_super_admin(did).await,
            Some(r) => {
                mock.authorize_did(did, r.clone(), vec!["ctx-a".into()])
                    .await
            }
            None => {}
        }
    }
    let didcomm = VtaClient::connect_didcomm(
        &didcomm_did,
        &didcomm_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("client connects over DIDComm");
    assert_eq!(didcomm.trust_task_transport(), SurfaceTransport::Didcomm);
    let tsp = VtaClient::connect_tsp(
        &tsp_did,
        &tsp_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("client connects over TSP");
    assert_eq!(tsp.trust_task_transport(), SurfaceTransport::Tsp);

    vec![("https", https), ("didcomm", didcomm), ("tsp", tsp)]
}

async fn shutdown(clients: Vec<(&'static str, VtaClient)>, mock: MockVta) {
    for (_, c) in clients {
        c.shutdown().await;
    }
    mock.shutdown().await;
}

async fn seed_session(mock: &MockVta, session_id: &str, did: &str) {
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(format!("rt-{session_id}")),
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&mock.ctx.sessions_ks, &session)
        .await
        .unwrap();
}

async fn session_count(mock: &MockVta, did: &str) -> usize {
    list_sessions(&mock.ctx.sessions_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|s| s.did == did)
        .count()
}

/// `vta/health/details/0.1` is public: the VTA answers it on every transport,
/// signed, including to DIDComm and TSP senders its ACL has never heard of —
/// and never with a version or a restore record.
#[test]
fn vta_health_details_0_1_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let clients = clients(&mock, 0xA0, None).await;
        for (transport, client) in &clients {
            let details = client
                .health_details()
                .await
                .unwrap_or_else(|e| panic!("{transport}: {e}"));
            let v = serde_json::to_value(&details).unwrap();
            assert_eq!(v["status"], "ok", "{transport}: {v}");
            assert!(v["sealed"].is_boolean(), "{transport}: {v}");
            assert!(v.get("version").is_none(), "{transport}: {v}");
        }
        shutdown(clients, mock).await;
    });
}

/// `vta/restore/status/0.1` answers an administrator on every transport, and
/// refuses anyone else before reading any restore state.
#[test]
fn vta_restore_status_0_1_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let admins = clients(&mock, 0xA4, Some(Role::Admin)).await;
        for (transport, client) in &admins {
            let status = client
                .restore_status()
                .await
                .unwrap_or_else(|e| panic!("{transport}: {e}"));
            assert!(!status.version.is_empty(), "{transport}");
            assert!(!status.restored, "{transport}");
            assert!(status.restore.is_none(), "{transport}");
        }
        let readers = clients(&mock, 0xA8, Some(Role::Reader)).await;
        for (transport, client) in &readers {
            let err = client
                .restore_status()
                .await
                .expect_err("a reader is not an administrator");
            assert!(err.is_auth(), "{transport}: {err}");
        }
        for (_, c) in admins {
            c.shutdown().await;
        }
        shutdown(readers, mock).await;
    });
}

/// `auth/revoke-session/0.2`'s `subject` form ends every session of a subject
/// on every transport; a named session that does not exist answers zero.
#[test]
fn auth_revoke_session_0_2_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let clients = clients(&mock, 0xAC, Some(Role::Admin)).await;
        for (i, (transport, client)) in clients.iter().enumerate() {
            let subject = format!("did:key:z6MkRevokeSubject{transport}");
            seed_session(&mock, &format!("sess-{i}-a"), &subject).await;
            seed_session(&mock, &format!("sess-{i}-b"), &subject).await;
            let revoked = client
                .revoke_sessions(RevokeSessions::Subject(&subject), Some("access-withdrawn"))
                .await
                .unwrap_or_else(|e| panic!("{transport}: {e}"));
            assert_eq!(revoked, 2, "{transport}");
            assert_eq!(session_count(&mock, &subject).await, 0, "{transport}");

            let revoked = client
                .revoke_sessions(RevokeSessions::Session("sess-never-existed"), None)
                .await
                .unwrap_or_else(|e| panic!("{transport}: {e}"));
            assert_eq!(revoked, 0, "{transport}");
        }
        shutdown(clients, mock).await;
    });
}

/// Seal `key` to a wrapping key's X25519 counterpart.
async fn seal_to(wrapping_did_key: &str, key: [u8; 32]) -> String {
    let x = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(
        &affinidi_crypto::did_key::did_key_to_ed25519_pub(wrapping_did_key).unwrap(),
    )
    .unwrap();
    let (_seed, prod) = generate_ed25519_keypair();
    let bundle = seal_payload(
        &x,
        [7u8; 16],
        ProducerAssertion {
            producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod),
            proof: AssertionProof::PinnedOnly,
        },
        &SealedPayloadV1::RawPrivateKey(RawPrivateKey {
            key_type: "ed25519".into(),
            key_bytes_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
        }),
        &InMemoryNonceStore::new(),
    )
    .await
    .unwrap();
    armor::encode(&bundle)
}

/// `keys/import-wrapping-key/0.1` hands out a verified Ed25519 `did:key` on
/// every transport, and a key sealed to its X25519 counterpart imports — over
/// HTTPS too, where the cleartext carrier is refused and this is the only way
/// in.
#[test]
fn keys_import_wrapping_key_0_1_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let clients = clients(&mock, 0xB0, Some(Role::Admin)).await;
        for (i, (transport, client)) in clients.iter().enumerate() {
            let wrapping = client
                .get_wrapping_key()
                .await
                .unwrap_or_else(|e| panic!("{transport}: {e}"));
            assert!(
                wrapping.wrapping_key.starts_with("did:key:z6Mk"),
                "{transport}: {}",
                wrapping.wrapping_key.as_str()
            );
            let sealed = seal_to(&wrapping.wrapping_key, [0x50 + i as u8; 32]).await;
            let imported = client
                .import_key(vta_sdk::client::ImportKeyRequest {
                    key_type: vta_sdk::keys::KeyType::Ed25519,
                    private_key_sealed: Some(sealed),
                    private_key_jwe: None,
                    private_key_multibase: None,
                    label: Some(format!("wrapped-over-{transport}")),
                    context_id: None,
                })
                .await
                .unwrap_or_else(|e| panic!("{transport}: sealed import failed: {e}"));
            assert!(!imported.key_id.is_empty(), "{transport}");
        }
        shutdown(clients, mock).await;
    });
}
