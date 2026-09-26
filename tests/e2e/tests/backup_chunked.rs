//! A backup moves end to end over a mediator transport, chunk by chunk.
//!
//! ## Why this exists
//!
//! Before the `chunkedTrustTask` algorithm a VTA reachable only over DIDComm or
//! TSP could not be backed up remotely at all: the descriptor flow's only
//! algorithm (`stream`) moves the bytes over an HTTPS endpoint such a VTA does
//! not publish, and the legacy inline message is refused by a mediator's 1 MiB
//! limit. The op-layer tests in `vta-backup` pin the chunk state machine and the
//! client tests in `vta-sdk` pin verification, but only a running VTA behind a
//! real mediator shows the pieces agree on the wire — that a `get-chunk`
//! response actually fits a mediator message, that the spine admits the
//! authenticated sender as the bundle's owner, and that the SDK picks the
//! chunked algorithm from the transport rather than reaching for REST.
//!
//! Hermetic: `MockVta::start_with_transports` embeds a `TestMediator`. The mock
//! has no `public_url`, so `stream` is unavailable to it — which is exactly the
//! deployment this algorithm exists for, and makes a silent fallback to the
//! blob endpoint impossible to pass by accident.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use vta_sdk::client::{ChunkedDownload, SurfaceTransport, TransferProgress, VtaClient};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::error::VtaError;
use vta_sdk::protocols::backup_management::chunked::initiate_export_1_1;
use vta_sdk::trust_tasks::{TASK_BACKUP_INITIATE_EXPORT_1_0, TASK_BACKUP_INITIATE_EXPORT_1_1};
use vta_service::test_support::MockVta;

mod common;

/// Long enough to be distinguishable from a fixture, and a valid backup password.
const PASSWORD: &str = "fixture-value-not-a-password";

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

/// **The headline.** A DIDComm client exports a running VTA and imports the
/// result back in preview, with every byte moving as a Trust Task over the
/// mediator.
///
/// Runs on an explicit runtime with 8 MiB worker stacks rather than
/// `#[tokio::test]`'s 2 MiB. In a debug build the VTA's DIDComm inbound task
/// polls the whole Trust-Task dispatch future on a worker stack, and with
/// `VtaClient::connect_didcomm` in the same process that overflows the default
/// stack on the first task — including `backup/abort/1.0`, which this change
/// does not touch. Release builds are unaffected. It is recorded here rather
/// than papered over: it is the stack depth of the dispatch path, not of the
/// chunked algorithm, and the fix belongs to that path.
#[test]
fn a_backup_round_trips_over_didcomm_in_chunks() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(round_trip_over_didcomm());
}

async fn round_trip_over_didcomm() {
    common::init_tracing();

    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x81);
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;

    let client = VtaClient::connect_didcomm(
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("client connects to the VTA over DIDComm");
    assert_eq!(client.trust_task_transport(), SurfaceTransport::Didcomm);

    let mut seen: Vec<TransferProgress> = Vec::new();
    let exported = client
        .backup_export_with_progress(PASSWORD, false, &mut |p| seen.push(p))
        .await;
    let bytes = match exported {
        Ok(b) => b,
        Err(e) => {
            client.shutdown().await;
            mock.shutdown().await;
            panic!("chunked export over DIDComm failed: {e}");
        }
    };

    // Progress was reported, ended complete, and counted the bytes returned.
    let last = *seen.last().expect("a chunked export reports progress");
    assert_eq!(last.chunks_done, last.chunks_total);
    assert_eq!(last.bytes_done, bytes.len() as u64);

    // What came back is a backup envelope — verified per chunk and as a whole
    // inside the SDK, so reaching here means both checks passed.
    let envelope: Value = serde_json::from_slice(&bytes).expect("the export is JSON");
    assert!(
        envelope.get("ciphertext").is_some(),
        "not a backup envelope: {envelope:#}"
    );

    // Import it back in preview: upload in chunks, then finalize with
    // `confirm: false`, which decrypts and counts but changes nothing.
    let preview = client
        .backup_import_via_descriptor(&bytes, PASSWORD, false)
        .await;
    let preview = match preview {
        Ok(p) => p,
        Err(e) => {
            client.shutdown().await;
            mock.shutdown().await;
            panic!("chunked import preview over DIDComm failed: {e}");
        }
    };
    assert_eq!(preview.status, "preview");
    let _ = client.backup_abort_bundle(&preview.bundle_id).await;

    client.shutdown().await;
    mock.shutdown().await;
}

/// The chunk tasks through the real spine, driven step by step: a manifest,
/// a non-consuming read, an out-of-range index refused with the declared code,
/// and completion releasing the bundle so a further read is refused.
///
/// Over DIDComm, so it runs on 8 MiB worker stacks for the same reason as
/// [`a_backup_round_trips_over_didcomm_in_chunks`].
#[test]
fn chunk_tasks_are_served_by_the_dispatch_spine() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(chunk_tasks_over_didcomm());
}

async fn chunk_tasks_over_didcomm() {
    common::init_tracing();

    // Backup export tasks are refused over a hop-by-hop transport, so the
    // chunk tasks are driven over DIDComm, as a real producer sends them.
    let mock = MockVta::start_with_transports().await;
    let (client_did, client_priv) = did_key_from_seed(0x82);
    mock.register_mediator_account(&client_did).await;
    mock.grant_super_admin(&client_did).await;
    let client = VtaClient::connect_didcomm(
        &client_did,
        &client_priv,
        mock.vta_did(),
        mock.mediator_did(),
        None,
    )
    .await
    .expect("client connects to the VTA over DIDComm");

    let response: initiate_export_1_1::Response = client
        .post_trust_task(
            TASK_BACKUP_INITIATE_EXPORT_1_1,
            json!({ "password": PASSWORD, "algorithm": "chunkedTrustTask" }),
        )
        .await
        .expect("a chunked export needs no public_url");
    let initiate_export_1_1::BundleDescriptor::ChunkedDescriptor(descriptor) = response.descriptor
    else {
        panic!("asked for chunkedTrustTask and got another algorithm");
    };

    let mut download = ChunkedDownload::new(&descriptor).expect("the manifest is consistent");
    let bundle_id = download.bundle_id().to_string();
    download
        .fetch_missing(&client, &mut |_| {})
        .await
        .expect("every chunk is served and verifies");
    let first = download.assemble().expect("the chunks assemble");

    // Non-consuming: a second pull of the same bundle yields the same bytes.
    let mut again = ChunkedDownload::new(&descriptor).unwrap();
    again.fetch_missing(&client, &mut |_| {}).await.unwrap();
    assert_eq!(again.assemble().unwrap(), first);

    // An index past the manifest is refused with get-chunk's declared code.
    let count = descriptor.chunks.chunk_count.0.get();
    let err = client
        .post_trust_task::<_, Value>(
            vta_sdk::trust_tasks::TASK_BACKUP_GET_CHUNK_1_0,
            json!({ "bundleId": bundle_id, "index": count }),
        )
        .await
        .expect_err("an out-of-range index is refused");
    assert!(
        err.to_string().contains("chunkOutOfRange"),
        "expected vta/backup/get-chunk:chunkOutOfRange, got {err:?}"
    );

    // Completion releases the bundle: `downloaded` is true because every index
    // was served, and a read afterwards is refused.
    let done: Value = client
        .post_trust_task(
            vta_sdk::trust_tasks::TASK_BACKUP_COMPLETE_EXPORT_1_0,
            json!({ "bundleId": bundle_id }),
        )
        .await
        .expect("complete-export");
    assert_eq!(done["downloaded"], json!(true), "{done:#}");
    let err = client
        .post_trust_task::<_, Value>(
            vta_sdk::trust_tasks::TASK_BACKUP_GET_CHUNK_1_0,
            json!({ "bundleId": bundle_id, "index": 0 }),
        )
        .await
        .expect_err("a completed bundle serves nothing");
    assert!(
        err.to_string().contains("terminalState"),
        "expected vta/backup/get-chunk:terminalState, got {err:?}"
    );

    client.shutdown().await;
    mock.shutdown().await;
}

/// The 1.0 initiator is unchanged, and a 1.1 request that does not name
/// `chunkedTrustTask` takes the same path: on a VTA with no public HTTPS address
/// both refuse `stream` with `transportUnavailable` rather than substituting the
/// chunked algorithm the producer did not ask for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_requests_are_never_answered_with_chunks() {
    common::init_tracing();

    let mock = MockVta::start().await;
    let client = mock.signing_client(0x83, "admin", Vec::new()).await;

    for uri in [
        TASK_BACKUP_INITIATE_EXPORT_1_0,
        TASK_BACKUP_INITIATE_EXPORT_1_1,
    ] {
        let err = client
            .post_trust_task::<_, Value>(uri, json!({ "password": PASSWORD }))
            .await
            .expect_err("stream has no address to publish on this VTA");
        assert!(
            matches!(err, VtaError::UnsupportedTransport(_)),
            "{uri}: expected transportUnavailable → UnsupportedTransport, got {err:?}"
        );
    }

    mock.shutdown().await;
}
