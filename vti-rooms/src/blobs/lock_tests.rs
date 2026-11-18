//! What waits on what (#2595, #2596): a commit's upload holds up no other room's records or
//! files, and a room's records lock holds up no other room.

use std::path::Path;
use std::time::Duration as StdDuration;

use vti_common::blob_store::{Health, local::LocalDirStore, sha256_digest_multibase};

use super::*;

const CHUNK: usize = 16_384;
const MEMBER: &str = "did:key:zMember";

/// A local store whose `put` waits until it is let go, as a slow upload to a remote store
/// would.
struct Slow {
    inner: LocalDirStore,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    hold: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl BlobStore for Slow {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError> {
        if self.hold.load(std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.put(key, staged, size).await
    }
    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError> {
        self.inner.get_range(at, start, end).await
    }
    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError> {
        self.inner.delete(at).await
    }
    async fn health(&self) -> Health {
        self.inner.health().await
    }
}

fn fixture() -> (tempfile::TempDir, BlobHost, Arc<Slow>) {
    let dir = tempfile::tempdir().unwrap();
    let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
        data_dir: dir.path().join("store"),
    })
    .unwrap();
    let slow = Arc::new(Slow {
        inner: LocalDirStore::new(dir.path().join("blobs")),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        hold: std::sync::atomic::AtomicBool::new(false),
    });
    let host = BlobHost::new(
        store.keyspace(ROOM_BLOBS_KEYSPACE).unwrap(),
        store.keyspace(ROOM_BLOB_TRANSFERS_KEYSPACE).unwrap(),
        dir.path().join("staging"),
        Arc::new(FixedStore::new("local", slow.clone())),
        HostLimits::default(),
    );
    (dir, host, slow)
}

fn room(id: &str) -> Room {
    Room {
        room_id: id.into(),
        owner_did: "did:key:zOwner".into(),
        visibility: Visibility::Attributed,
        retention_policy: crate::RetentionPolicy::Chained,
        anchor_cadence: Default::default(),
        epoch: 1,
        next_version: 1,
        retention_days: 90,
        epoch_expires_at: None,
        created_at: 0,
        updated_at: 0,
        mirror_of: None,
        record_retention: None,
        last_prune: None,
        signal_delay: Default::default(),
        epoch_floor: None,
        frozen_at: None,
    }
}

fn blob(len: usize, seed: u8) -> (Vec<u8>, Manifest) {
    let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
    let digest = sha256_digest_multibase(&Sha256::digest(&bytes).into());
    let raw = serde_json::json!({
        "size": len,
        "chunks": { "chunkSize": CHUNK, "chunkCount": 1, "chunkDigests": [digest] },
        "digest": digest,
    });
    (bytes, Manifest::parse(&raw).unwrap())
}

/// Two room identifiers whose record locks are different stripes.
fn rooms_on_two_stripes(h: &BlobHost) -> (Room, Room) {
    let a = "did:web:example.com:room-a".to_string();
    let first = h.rooms.of(&a) as *const _;
    let b = (0..)
        .map(|i| format!("did:web:example.com:room-b{i}"))
        .find(|b| !std::ptr::eq(h.rooms.of(b), first))
        .unwrap();
    (room(&a), room(&b))
}

async fn quickly<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(StdDuration::from_secs(5), f)
        .await
        .unwrap_or_else(|_| panic!("{what} waited"))
}

/// A commit writing to a slow store holds neither the host lock nor any room's lock while
/// it writes: records are read and written, and other uploads begin and commit, meanwhile.
#[tokio::test]
async fn a_commit_uploading_holds_up_nothing_else() {
    let (_d, h, slow) = fixture();
    let (a, b) = rooms_on_two_stripes(&h);

    let (bytes, manifest) = blob(1_000, 1);
    let digest = manifest.chunk_digests[0].clone();
    let begun = h.begin(&a, MEMBER, Some(MEMBER), manifest).await.unwrap();
    let id = begun.upload_id.to_string();
    h.put_chunk(MEMBER, &id, 0, &digest, &bytes).await.unwrap();

    slow.hold.store(true, std::sync::atomic::Ordering::SeqCst);
    let commit = h.commit(MEMBER, &id);
    let meanwhile = async {
        slow.entered.notified().await;
        slow.hold.store(false, std::sync::atomic::Ordering::SeqCst);
        // Reads and writes of records, in the committing room and another.
        for r in [&a, &b] {
            quickly("a read", h.read_snapshot(&r.room_id)).await;
            quickly(
                "a record write",
                h.prepare_record(r, Some(MEMBER), "k", &[]),
            )
            .await
            .unwrap()
            .apply()
            .await
            .unwrap();
        }
        // Another upload, begun and committed to completion.
        let (bytes, manifest) = blob(2_000, 2);
        let digest = manifest.chunk_digests[0].clone();
        let other = quickly("a begin", h.begin(&b, MEMBER, Some(MEMBER), manifest))
            .await
            .unwrap();
        let other = other.upload_id.to_string();
        quickly("a chunk", h.put_chunk(MEMBER, &other, 0, &digest, &bytes))
            .await
            .unwrap();
        quickly("a commit", h.commit(MEMBER, &other)).await.unwrap();
        quickly("a sweep", h.sweep()).await.unwrap();
        slow.release.notify_one();
    };
    let (committed, ()) = tokio::join!(commit, meanwhile);
    let committed = committed.unwrap();
    assert!(
        h.blob(&a.room_id, &committed.blob_ref)
            .await
            .unwrap()
            .is_some()
    );
    // Charged once, as before.
    assert_eq!(h.room_usage(&a.room_id).await.unwrap().files, 1);
    assert_eq!(h.room_usage(&a.room_id).await.unwrap().reserved_files, 0);
}

/// Reads in a room share its lock; a write in one room holds up no other.
#[tokio::test]
async fn record_locks_are_per_room_and_reads_share_them() {
    let (_d, h, _slow) = fixture();
    let (a, b) = rooms_on_two_stripes(&h);

    let _r1 = h.read_snapshot(&a.room_id).await;
    let _r2 = quickly("a second read", h.read_snapshot(&a.room_id)).await;
    drop((_r1, _r2));

    let _writing = h.records_lock(&a.room_id).await;
    quickly("a read in another room", h.read_snapshot(&b.room_id)).await;
    quickly(
        "a write in another room",
        h.prepare_record(&b, None, "k", &[]),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(StdDuration::from_millis(100), h.read_snapshot(&a.room_id))
            .await
            .is_err(),
        "a read in the room being written waits for the write"
    );
}

/// A download serves every chunk from the manifest it was committed with, parsed once.
#[tokio::test]
async fn a_download_reads_its_manifest_once() {
    let (_d, h, _slow) = fixture();
    let a = room("did:web:example.com:dl");
    let len = CHUNK * 3 + 10;
    let bytes: Vec<u8> = (0..len).map(|i| i as u8).collect();
    let digests: Vec<String> = bytes
        .chunks(CHUNK)
        .map(|c| sha256_digest_multibase(&Sha256::digest(c).into()))
        .collect();
    let raw = serde_json::json!({
        "size": len,
        "chunks": { "chunkSize": CHUNK, "chunkCount": digests.len(), "chunkDigests": digests },
        "digest": sha256_digest_multibase(&Sha256::digest(&bytes).into()),
    });
    let manifest = Manifest::parse(&raw).unwrap();
    let begun = h.begin(&a, MEMBER, Some(MEMBER), manifest).await.unwrap();
    let id = begun.upload_id.to_string();
    for (i, c) in bytes.chunks(CHUNK).enumerate() {
        h.put_chunk(MEMBER, &id, i as u64, &digests[i], c)
            .await
            .unwrap();
    }
    let blob_ref = h.commit(MEMBER, &id).await.unwrap().blob_ref;

    let dl = h
        .open_download(&a, MEMBER, Some(MEMBER), &blob_ref)
        .await
        .unwrap();
    let mut got = Vec::new();
    for i in 0..digests.len() as u64 {
        let chunk = h
            .read_chunk(MEMBER, &dl.download_id.to_string(), i)
            .await
            .unwrap();
        assert_eq!(chunk.digest_multibase, digests[i as usize]);
        got.extend(chunk.data);
    }
    assert_eq!(got, bytes);
    assert!(
        h.manifests.get(&blob_ref).is_some(),
        "parsed once, then cached"
    );
    let err = h
        .read_chunk(MEMBER, &dl.download_id.to_string(), digests.len() as u64)
        .await
        .unwrap_err();
    assert!(matches!(err, BlobError::ChunkOutOfRange { .. }), "{err:?}");
}
