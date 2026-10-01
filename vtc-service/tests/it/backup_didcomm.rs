//! A community backup, exported and restored by `vtc-client` over a live
//! DIDComm session to the production listener.
//!
//! The unit tests drive the `backup/*` handlers with hand-built documents, and
//! the client's own tests stop at its refusal to go without a session. Neither
//! shows the pair agree: that the client's chunked export reassembles what the
//! VTC staged, verifies each chunk against the manifest the VTC signed, and
//! that the upload the client builds is one the VTC accepts. This runs the
//! real client against the real listener, through a mediator.
//!
//! Requires `--features didcomm-harness`; CI runs it.

#![cfg(feature = "didcomm-harness")]

use serde_json::Value;

use vtc_client::VtcClient;
use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::test_support::MockVtcDidcomm;
use vti_common::audit::{AuditEnvelope, AuditEvent};

const PASSWORD: &str = "a-long-enough-backup-password";

/// A deterministic `did:key` and its multibase private key.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
    );
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    (did, multibase::encode(multibase::Base::Base58Btc, &buf))
}

async fn backup_exports(mock: &MockVtcDidcomm) -> usize {
    mock.vtc
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .expect("read the audit log")
        .iter()
        .filter(|(_, v)| {
            serde_json::from_slice::<AuditEnvelope>(v)
                .is_ok_and(|e| matches!(e.event, AuditEvent::BackupExported(_)))
        })
        .count()
}

/// Export over DIDComm, then preview the same backup back in: the envelope
/// crosses several chunks each way, the export is audited, and the preview
/// counts the rows it would restore without writing any.
#[tokio::test]
async fn a_backup_round_trips_over_didcomm() {
    let mock = MockVtcDidcomm::start().await;

    // Everything an export needs: a secret store holding the signing bundle,
    // and somewhere for a restore to write its config.
    {
        let mut config = mock.vtc.state.config.write().await;
        config.secrets.backend = Some(vtc_service::config::SecretBackend::Plaintext);
        config.config_path = mock.vtc.data_dir().join("config.toml");
        vtc_service::keys::seed_store::create_secret_store(&config)
            .expect("plaintext store")
            .set(b"signing-bundle")
            .await
            .expect("seed the store");
    }
    // Enough state that the bundle spans several 32 KiB chunks.
    for i in 0..40u32 {
        mock.vtc
            .state
            .members_ks
            .insert_raw(format!("bulk:{i}").into_bytes(), vec![b'x'; 2048])
            .await
            .expect("seed a member row");
    }

    let (admin_did, admin_key) = did_key_from_seed(0x5b);
    store_acl_entry(
        &mock.vtc.state.acl_ks,
        &VtcAclEntry {
            did: admin_did.clone(),
            role: VtcRole::Admin,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .expect("seed the super-admin");
    mock.register_local_did(&admin_did).await;

    let client = VtcClient::connect_didcomm(
        &admin_did,
        &admin_key,
        mock.vtc_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("connect over DIDComm");

    assert_eq!(backup_exports(&mock).await, 0);
    let envelope = client
        .export_backup(PASSWORD, false)
        .await
        .expect("export over DIDComm");
    assert_eq!(envelope["format"], "vtc-backup-v1");
    assert_eq!(envelope["sourceDid"].as_str(), Some(mock.vtc_did()));
    assert!(
        serde_json::to_vec(&envelope).unwrap().len() > 2 * 32 * 1024,
        "the envelope should span several chunks"
    );
    assert_eq!(
        backup_exports(&mock).await,
        1,
        "the export is recorded before it is released"
    );

    let preview: Value = client
        .import_backup(&envelope, PASSWORD, false)
        .await
        .expect("preview over DIDComm");
    assert_eq!(preview["status"], "preview", "{preview}");
    assert!(preview["counts"]["members"].as_u64().unwrap_or(0) >= 40);

    let wrong = client
        .import_backup(&envelope, "not-the-backup-password", false)
        .await;
    assert!(wrong.is_err(), "a wrong password opens nothing");

    client.shutdown().await;
    mock.shutdown().await;
}
