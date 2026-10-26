//! Room traffic is admitted on what it proves (`routing::trust_task_admission`,
//! `docs/02-vta/data-rooms.md` §8.2): a `rooms/*` document is charged to its
//! address's room ceiling before it is verified, and — once its room has
//! authorized it — to the presenter's budget in that room, or for a file chunk
//! to the transfer budget. Never to the anonymous governor's burst of 10.
//!
//! Driven through the real router, every request from one address, as two
//! members on one machine (or behind one NAT) would send them.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use vta_sdk::rate_limit::SOURCE_HEADER;
use vti_common::blob_store::sha256_digest_multibase;
use vti_rooms::Visibility;
use vti_rooms::blobs::Manifest;
use vti_rooms_dtg::test_support::{Party, RoomFixture};

use vtc_service::config::RoomRateLimitsConfig;
use vtc_service::test_support::TestVtc;

use crate::common::signed::signed;

const INFO: &str = "https://trusttasks.org/spec/rooms/info/0.1";
const LIST: &str = "https://trusttasks.org/spec/rooms/records/list/0.1";
const BLOB_GET: &str = "https://trusttasks.org/spec/rooms/blobs/get/0.2";
const BLOB_CHUNK: &str = "https://trusttasks.org/spec/rooms/blobs/chunk/0.1";

const CHUNK: usize = 16_384;

/// One reply: status, the limiter a `429` names, and the document.
struct Reply {
    status: StatusCode,
    limiter: Option<String>,
    body: Value,
}

/// Post `doc` from `ip`.
async fn post_from(vtc: &TestVtc, ip: [u8; 4], doc: &Value) -> Reply {
    let peer = std::net::SocketAddr::from((ip, 40_000));
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let res = vtc.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        assert_eq!(res.headers()[SOURCE_HEADER], "vtc");
        assert!(res.headers().contains_key("retry-after"));
    }
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Reply {
        status,
        limiter: (status == StatusCode::TOO_MANY_REQUESTS)
            .then(|| body["limiter"].as_str().unwrap_or_default().to_string()),
        body,
    }
}

const NAT: [u8; 4] = [198, 51, 100, 7];

/// A room hosted here, with its owner and a second member.
async fn hosted(vtc: &TestVtc) -> RoomFixture {
    let f = RoomFixture::new(Visibility::Attributed).await;
    vti_rooms::storage::create_room(&vtc.state.rooms_ks, &f.room)
        .await
        .unwrap();
    vtc.state
        .room_storage
        .assign_new_room(&f.room.room_id)
        .await
        .unwrap();
    f
}

async fn info(vtc: &TestVtc, f: &RoomFixture, who: &Party, ip: [u8; 4]) -> Reply {
    let presentation = if who.did == f.owner.did {
        f.as_owner()
    } else {
        f.as_successor()
    };
    let doc = signed(
        who,
        INFO,
        json!({ "roomId": f.room.room_id, "presentation": presentation }),
    )
    .await;
    post_from(vtc, ip, &doc).await
}

/// A member reading a room sends far more than the anonymous burst of 10 —
/// and is not refused for it.
#[tokio::test]
async fn a_member_makes_a_realistic_burst_of_room_reads() {
    let vtc = TestVtc::builder().build().await;
    let f = hosted(&vtc).await;
    for i in 0..40 {
        let uri = if i % 2 == 0 { INFO } else { LIST };
        let doc = signed(
            &f.owner,
            uri,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
        )
        .await;
        let r = post_from(&vtc, NAT, &doc).await;
        assert_eq!(r.status, StatusCode::OK, "read {i}: {}", r.body);
    }
}

/// A file of many chunks downloads end to end from one address without a
/// single `429`, interleaved with the member's other reads.
#[tokio::test]
async fn a_file_of_several_chunks_downloads_without_429() {
    let vtc = TestVtc::builder().build().await;
    let f = hosted(&vtc).await;
    let chunks = 24usize;
    let bytes: Vec<u8> = (0..CHUNK * chunks).map(|i| (i % 251) as u8).collect();
    let digests: Vec<String> = bytes
        .chunks(CHUNK)
        .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
        .collect();
    let manifest = Manifest::parse(&json!({
        "size": bytes.len(),
        "chunks": { "chunkSize": CHUNK, "chunkCount": chunks, "chunkDigests": digests },
        "digest": sha256_digest_multibase(&Sha256::digest(&bytes).into()),
    }))
    .unwrap();
    let files = &vtc.state.room_files;
    let owner = f.owner.did.as_str();
    let begun = files
        .begin(&f.room, owner, Some(owner), manifest)
        .await
        .unwrap();
    let id = begun.upload_id.to_string();
    for (i, c) in bytes.chunks(CHUNK).enumerate() {
        files
            .put_chunk(owner, &id, i as u64, &digests[i], c)
            .await
            .unwrap();
    }
    let blob_ref = files.commit(owner, &id).await.unwrap().blob_ref;

    let doc = signed(
        &f.owner,
        BLOB_GET,
        json!({ "roomId": f.room.room_id, "blobRef": blob_ref, "presentation": f.as_owner() }),
    )
    .await;
    let started = post_from(&vtc, NAT, &doc).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.body);
    let download_id = started.body["payload"]["downloadId"]
        .as_str()
        .expect("a download id")
        .to_string();

    let mut got = Vec::with_capacity(bytes.len());
    for i in 0..chunks {
        let doc = signed(
            &f.owner,
            BLOB_CHUNK,
            json!({ "downloadId": download_id, "index": i }),
        )
        .await;
        let r = post_from(&vtc, NAT, &doc).await;
        assert_eq!(r.status, StatusCode::OK, "chunk {i}: {}", r.body);
        let data = r.body["payload"]["data"].as_str().unwrap();
        got.extend(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
                .unwrap(),
        );
        if i % 4 == 0 {
            assert_eq!(info(&vtc, &f, &f.owner, NAT).await.status, StatusCode::OK);
        }
    }
    assert_eq!(got, bytes);
}

/// Two members behind one address: one exhausting their budget in a room
/// leaves the other's untouched.
#[tokio::test]
async fn two_presenters_behind_one_address_have_their_own_budgets() {
    let vtc = TestVtc::builder()
        .with_room_rate_limits(RoomRateLimitsConfig {
            presenter_burst: Some(5),
            presenter_interval_ms: Some(3_600_000),
            ..Default::default()
        })
        .build()
        .await;
    let f = hosted(&vtc).await;
    for i in 0..5 {
        let r = info(&vtc, &f, &f.owner, NAT).await;
        assert_eq!(r.status, StatusCode::OK, "owner read {i}: {}", r.body);
    }
    let refused = info(&vtc, &f, &f.owner, NAT).await;
    assert_eq!(refused.limiter.as_deref(), Some("room-presenter"));
    assert_eq!(refused.body["error"], "rate_limited");

    for i in 0..5 {
        let r = info(&vtc, &f, &f.successor, NAT).await;
        assert_eq!(
            r.status,
            StatusCode::OK,
            "the second member's read {i} paid for the first's: {}",
            r.body
        );
    }
}

/// A presenter the room does not authorize buys nothing by signing: every
/// such document costs the address's room ceiling extra, so a flood from one
/// address stops there — after a handful, not after its burst.
#[tokio::test]
async fn an_unverifiable_flood_stops_at_the_address_ceiling() {
    let vtc = TestVtc::builder()
        .with_room_rate_limits(RoomRateLimitsConfig {
            address_burst: Some(60),
            address_interval_ms: Some(3_600_000),
            ..Default::default()
        })
        .build()
        .await;
    let f = hosted(&vtc).await;
    let flooder = Party::new();
    let attacker = [203, 0, 113, 9];
    let mut sent = 0;
    let refused = loop {
        sent += 1;
        assert!(sent <= 10, "no refusal after {sent} unauthorized documents");
        // The owner's presentation, signed by someone else: refused by the room.
        let doc = signed(
            &flooder,
            INFO,
            json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
        )
        .await;
        let r = post_from(&vtc, attacker, &doc).await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            break r;
        }
        assert_ne!(r.status, StatusCode::OK, "the room authorized a stranger");
    };
    assert_eq!(refused.limiter.as_deref(), Some("room-address"));
    assert!(sent < 60, "refused only at the burst ({sent})");

    // The member, from their own address, is unaffected.
    assert_eq!(
        info(&vtc, &f, &f.owner, NAT).await.status,
        StatusCode::OK,
        "the flood cost a member elsewhere their budget"
    );
}

/// Upload chunks are larger than the 64 KiB a party with no ACL entry may send,
/// and used to take the large-document budget — five a minute per address — so
/// a file of more than five chunks could not be uploaded in under a minute.
/// Charged to the room budgets instead, every chunk of a larger file lands.
#[tokio::test]
async fn an_upload_of_more_large_chunks_than_the_large_document_budget_lands() {
    const BIG: usize = 65_536;
    let vtc = TestVtc::builder().build().await;
    let f = hosted(&vtc).await;
    let chunks = 8usize;
    let bytes: Vec<u8> = (0..BIG * chunks).map(|i| (i % 241) as u8).collect();
    let digests: Vec<String> = bytes
        .chunks(BIG)
        .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
        .collect();
    let manifest = Manifest::parse(&json!({
        "size": bytes.len(),
        "chunks": { "chunkSize": BIG, "chunkCount": chunks, "chunkDigests": digests },
        "digest": sha256_digest_multibase(&Sha256::digest(&bytes).into()),
    }))
    .unwrap();
    // Proxied, as a member's client uploads: the owner begins, naming a key generated for
    // this upload alone, and that key sends every chunk (`rooms/blobs/upload/begin/0.2`).
    let owner = f.owner.did.as_str();
    let upload_key = Party::new();
    let begun = vtc
        .state
        .room_files
        .begin_v2(
            &f.room,
            owner,
            Some(owner),
            manifest,
            vti_rooms::blobs::UploadOffer {
                upload_key_did: Some(upload_key.did.clone()),
                direct_parts: None,
            },
        )
        .await
        .unwrap();
    let upload_id = begun.upload_id.to_string();
    for (i, c) in bytes.chunks(BIG).enumerate() {
        let doc = signed(
            &upload_key,
            "https://trusttasks.org/spec/rooms/blobs/upload/chunk/0.2",
            json!({
                "uploadId": upload_id,
                "index": i,
                "data": base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    c,
                ),
                "digestMultibase": digests[i],
            }),
        )
        .await;
        assert!(serde_json::to_vec(&doc).unwrap().len() > 64 * 1024);
        let r = post_from(&vtc, NAT, &doc).await;
        assert_eq!(r.status, StatusCode::OK, "chunk {i}: {}", r.body);
    }
    vtc.state
        .room_files
        .commit_as(
            vti_rooms::blobs::UploadCaller::V2(&upload_key.did),
            &upload_id,
        )
        .await
        .expect("every chunk arrived");
}

/// A blob of `chunks` chunks of 64 KiB, each past the default document size once encoded.
fn big_blob(chunks: usize, seed: u8) -> (Vec<u8>, Vec<String>, Manifest) {
    const BIG: usize = 65_536;
    let bytes: Vec<u8> = (0..BIG * chunks)
        .map(|i| ((i % 241) as u8).wrapping_add(seed))
        .collect();
    let digests: Vec<String> = bytes
        .chunks(BIG)
        .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
        .collect();
    let manifest = Manifest::parse(&json!({
        "size": bytes.len(),
        "chunks": { "chunkSize": BIG, "chunkCount": chunks, "chunkDigests": digests },
        "digest": sha256_digest_multibase(&Sha256::digest(&bytes).into()),
    }))
    .unwrap();
    (bytes, digests, manifest)
}

const UPLOAD_CHUNK_V2: &str = "https://trusttasks.org/spec/rooms/blobs/upload/chunk/0.2";

/// A `rooms/blobs/upload/chunk/0.2` document, signed by the upload's key.
async fn key_chunk(key: &Party, upload_id: &str, i: usize, data: &[u8], digest: &str) -> Value {
    let doc = signed(
        key,
        UPLOAD_CHUNK_V2,
        json!({
            "uploadId": upload_id,
            "index": i,
            "data": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data),
            "digestMultibase": digest,
        }),
    )
    .await;
    assert!(serde_json::to_vec(&doc).unwrap().len() > 64 * 1024);
    doc
}

/// `0.2` upload chunks are signed by the upload's single-use key, which holds no ACL
/// entry and no budget of its own. They are admitted at their size on the strength of
/// the open upload that names the key, and charged to the **owner's** transfer budget in
/// the room — so minting a key per file buys a member no second budget.
#[tokio::test]
async fn upload_key_chunks_land_and_are_charged_to_the_owner() {
    let vtc = TestVtc::builder()
        .with_room_rate_limits(RoomRateLimitsConfig {
            transfer_burst: Some(3),
            transfer_interval_ms: Some(3_600_000),
            ..Default::default()
        })
        .build()
        .await;
    let f = hosted(&vtc).await;
    let owner = f.owner.did.as_str();
    let files = &vtc.state.room_files;

    let (bytes, digests, manifest) = big_blob(4, 1);
    let key = Party::new();
    let begun = files
        .begin_v2(
            &f.room,
            owner,
            Some(owner),
            manifest,
            vti_rooms::blobs::UploadOffer {
                upload_key_did: Some(key.did.clone()),
                direct_parts: None,
            },
        )
        .await
        .unwrap();
    let id = begun.upload_id.to_string();
    for (i, c) in bytes.chunks(65_536).take(3).enumerate() {
        let doc = key_chunk(&key, &id, i, c, &digests[i]).await;
        let r = post_from(&vtc, NAT, &doc).await;
        assert_eq!(r.status, StatusCode::OK, "chunk {i}: {}", r.body);
    }
    let doc = key_chunk(&key, &id, 3, &bytes[3 * 65_536..], &digests[3]).await;
    let refused = post_from(&vtc, NAT, &doc).await;
    assert_eq!(
        refused.limiter.as_deref(),
        Some("room-transfer"),
        "{}",
        refused.body
    );

    // A second file, under a fresh key, spends the same member's budget.
    let (bytes2, digests2, manifest2) = big_blob(1, 2);
    let key2 = Party::new();
    let begun2 = files
        .begin_v2(
            &f.room,
            owner,
            Some(owner),
            manifest2,
            vti_rooms::blobs::UploadOffer {
                upload_key_did: Some(key2.did.clone()),
                direct_parts: None,
            },
        )
        .await
        .unwrap();
    let doc = key_chunk(
        &key2,
        &begun2.upload_id.to_string(),
        0,
        &bytes2,
        &digests2[0],
    )
    .await;
    let refused = post_from(&vtc, NAT, &doc).await;
    assert_eq!(
        refused.limiter.as_deref(),
        Some("room-transfer"),
        "a fresh upload key bought a fresh budget: {}",
        refused.body
    );
}
