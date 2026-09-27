//! Keyring VTI-23 and VTI-27 against a running VTA over **TSP, DIDComm and
//! HTTPS**, through the SDK a real client uses.
//!
//! - **VTI-27** — an ACL refusal reaches the client as a typed authorization
//!   error on every transport. Over DIDComm and TSP it is a signed
//!   `trust-task-error` in the binding envelope; a problem-report, which is what
//!   the finding describes, is not an envelope and a client keyed on the
//!   envelope type reads it as an empty success.
//! - **VTI-23** — a least-privilege manager on `initiator` mints a persona DID
//!   and a key (both `key-mint`) without the admin role; releasing a key needs
//!   `key-export`, which a context administrator holds and an initiator does
//!   not (VTI-VTA-003 — an initiator acts as a key through the signing oracle).
//!
//! The dispatch-level halves, including the bare-payload refusal of VTI-09
//! that the SDK cannot be made to send, are in `vta-service`
//! (`messaging::{router,tsp_inbound}::keyring_vti_09_27`,
//! `tests/keyring_vti_09_23_https.rs`).
//!
//! Hermetic: `MockVta::start_with_transports` embeds a `TestMediator`. 8 MiB
//! worker stacks, for the reason `backup_chunked` records.

use ed25519_dalek::SigningKey;
use vta_sdk::client::{CreateDidWebvhRequest, CreateKeyRequest, SurfaceTransport, VtaClient};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::keys::KeyType;
use vta_service::acl::Role;
use vta_service::test_support::MockVta;

mod common;

const CONTEXT: &str = "ctx1";

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
/// per DID): `seed` for HTTPS, `seed + 1` for DIDComm, `seed + 2` for TSP.
/// `grant` is the ACL entry each gets — role and contexts — or `None` for a
/// DIDComm and TSP sender the VTA has never heard of (HTTPS then holds a
/// reader token, the nearest a bearer caller can come to having no standing).
async fn clients(
    mock: &MockVta,
    seed: u8,
    grant: Option<(Role, Vec<String>)>,
) -> Vec<(&'static str, VtaClient)> {
    let https = match &grant {
        Some((role, contexts)) => {
            mock.signing_client(seed, &role.to_string(), contexts.clone())
                .await
        }
        None => {
            mock.signing_client(seed, "reader", vec![CONTEXT.into()])
                .await
        }
    };

    let (didcomm_did, didcomm_priv) = did_key_from_seed(seed + 1);
    let (tsp_did, tsp_priv) = did_key_from_seed(seed + 2);
    for did in [&didcomm_did, &tsp_did] {
        mock.register_mediator_account(did).await;
        if let Some((role, contexts)) = &grant {
            mock.authorize_did(did, role.clone(), contexts.clone())
                .await;
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

async fn close(clients: Vec<(&'static str, VtaClient)>) {
    for (_, c) in clients {
        c.shutdown().await;
    }
}

fn key_in_context(label: String) -> CreateKeyRequest {
    CreateKeyRequest {
        key_type: KeyType::Ed25519,
        derivation_path: None,
        key_id: None,
        mnemonic: None,
        label: Some(label),
        context_id: Some(CONTEXT.into()),
        internal: None,
    }
}

/// VTI-27: a restricted task from a sender the ACL does not accept comes back
/// as a typed authorization error — not a transport failure and not a
/// success — on every transport.
#[test]
fn vti_27_an_acl_refusal_is_a_typed_error_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let strangers = clients(&mock, 0xC0, None).await;
        for (transport, client) in &strangers {
            let err = client
                .restore_status()
                .await
                .expect_err("a sender without standing is refused");
            assert!(
                err.is_auth(),
                "{transport}: the refusal must arrive as an authorization error: {err}"
            );
        }
        close(strangers).await;
        mock.shutdown().await;
    });
}

/// VTI-23: an `initiator` scoped to a context mints a persona DID and a key in
/// it on every transport — `key-mint`, not the admin role.
#[test]
fn vti_23_an_initiator_mints_a_did_and_a_key_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let managers = clients(&mock, 0xC4, Some((Role::Initiator, vec![CONTEXT.into()]))).await;
        for (transport, client) in &managers {
            let persona = client
                .create_did_webvh(CreateDidWebvhRequest {
                    context_id: CONTEXT.into(),
                    server_id: None,
                    url: Some(format!(
                        "https://webvh-host.test/dids/persona-{transport}/did.jsonl"
                    )),
                    path: None,
                    path_mode: None,
                    domain: None,
                    label: Some(format!("persona-{transport}")),
                    portable: false,
                    add_mediator_service: false,
                    add_tsp_service: false,
                    additional_services: None,
                    pre_rotation_count: 0,
                    did_document: None,
                    did_log: None,
                    set_primary: false,
                    signing_key_id: None,
                    ka_key_id: None,
                    template: None,
                    template_context: None,
                    template_vars: Default::default(),
                })
                .await
                .unwrap_or_else(|e| panic!("{transport}: an initiator mints a persona: {e}"));
            assert!(persona.did.starts_with("did:webvh:"), "{transport}");

            let key = client
                .create_key(key_in_context(format!("persona-key-{transport}")))
                .await
                .unwrap_or_else(|e| panic!("{transport}: an initiator creates a key: {e}"));
            assert!(!key.key_id.is_empty(), "{transport}");
        }
        close(managers).await;
        mock.shutdown().await;
    });
}

/// VTI-23: releasing a key needs `key-export`. A context administrator holds
/// it and takes its context's key over the end-to-end transports; an
/// initiator is refused on every transport with an authorization error.
#[test]
fn vti_23_key_export_needs_key_export_over_tsp_didcomm_and_https() {
    run(async {
        common::init_tracing();
        let mock = MockVta::start_with_transports().await;
        let admins = clients(&mock, 0xC8, Some((Role::Admin, vec![CONTEXT.into()]))).await;
        let managers = clients(&mock, 0xCC, Some((Role::Initiator, vec![CONTEXT.into()]))).await;

        let (_, https_admin) = &admins[0];
        let key = https_admin
            .create_key(key_in_context("exportable-persona-key".into()))
            .await
            .expect("a context admin creates a key");

        for (transport, client) in admins.iter().filter(|(t, _)| *t != "https") {
            let secret = client
                .get_key_secret(&key.key_id)
                .await
                .unwrap_or_else(|e| panic!("{transport}: a holder of key-export exports: {e}"));
            assert_eq!(secret.key_id, key.key_id, "{transport}");
        }
        for (transport, client) in &managers {
            let err = client
                .get_key_secret(&key.key_id)
                .await
                .expect_err("an initiator does not carry key-export");
            assert!(err.is_auth(), "{transport}: {err}");
        }
        close(admins).await;
        close(managers).await;
        mock.shutdown().await;
    });
}
