//! [`BlobHost::purge_room`]: every byte and row of one room goes, the shared counters
//! come back to what they were before the room's files, another room is untouched, and a
//! store that fails leaves exactly what it could not delete for the next call.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use vti_common::blob_store::{Health, local::LocalDirStore, sha256_digest_multibase};

use super::*;

const CHUNK: usize = 16_384;
const MEMBER: &str = "did:key:zMember";
const OTHER: &str = "did:key:zOther";
const ROOM: &str = "did:key:zRoom";
const NEIGHBOUR: &str = "did:key:zNeighbour";

/// A local store whose deletions can be made to fail.
struct Flaky {
    inner: LocalDirStore,
    fail: AtomicBool,
}

#[async_trait::async_trait]
impl BlobStore for Flaky {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    async fn put(&self, key: &BlobKey, staged: &Path, size: u64) -> Result<BackendRef, AppError> {
        self.inner.put(key, staged, size).await
    }
    async fn get_range(&self, at: &BackendRef, start: u64, end: u64) -> Result<Vec<u8>, AppError> {
        self.inner.get_range(at, start, end).await
    }
    async fn delete(&self, at: &BackendRef) -> Result<Deletion, AppError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AppError::Internal("storage is unreachable".into()));
        }
        self.inner.delete(at).await
    }
    async fn health(&self) -> Health {
        self.inner.health().await
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    host: BlobHost,
    store: Arc<Flaky>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
        data_dir: dir.path().join("store"),
    })
    .unwrap();
    let flaky = Arc::new(Flaky {
        inner: LocalDirStore::new(dir.path().join("blobs")),
        fail: AtomicBool::new(false),
    });
    let host = BlobHost::new(
        store.keyspace(ROOM_BLOBS_KEYSPACE).unwrap(),
        store.keyspace(ROOM_BLOB_TRANSFERS_KEYSPACE).unwrap(),
        dir.path().join("staging"),
        Arc::new(FixedStore::new("local", flaky.clone())),
        HostLimits::default(),
    );
    Fixture {
        dir,
        host,
        store: flaky,
    }
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
        epoch_floor: None,
        frozen_at: None,
    }
}

/// A one-chunk blob of `len` bytes.
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

/// Commit a blob, and — when `record` names one — a record naming it.
async fn upload(
    h: &BlobHost,
    r: &Room,
    member: &str,
    len: usize,
    seed: u8,
    record: Option<&str>,
) -> String {
    let (bytes, manifest) = blob(len, seed);
    let digest = manifest.chunk_digests[0].clone();
    let begun = h.begin(r, member, Some(member), manifest).await.unwrap();
    let id = begun.upload_id.to_string();
    h.put_chunk(member, &id, 0, &digest, &bytes).await.unwrap();
    let blob_ref = h.commit(member, &id).await.unwrap().blob_ref;
    if let Some(key) = record {
        h.prepare_record(r, Some(member), key, std::slice::from_ref(&blob_ref))
            .await
            .unwrap()
            .apply()
            .await
            .unwrap();
    }
    blob_ref
}

fn object(f: &Fixture, room_id: &str, blob_ref: &str) -> std::path::PathBuf {
    let key = BlobKey::for_room(room_id, blob_ref).unwrap();
    f.dir.path().join("blobs").join(key.as_str())
}

async fn counters(f: &Fixture) -> (StorageUsage, StorageUsage) {
    (
        f.host.counter(STORAGE_USAGE_KEY).await.unwrap(),
        f.host.counter(&config_usage_key("local")).await.unwrap(),
    )
}

/// Every row of the blob index that names `room_id`, by its hash or by the id itself.
async fn rows_of(f: &Fixture, room_id: &str) -> Vec<String> {
    let h = room_hash(room_id);
    f.host
        .blobs
        .prefix_iter_raw(Vec::<u8>::new())
        .await
        .unwrap()
        .into_iter()
        .filter(|(k, v)| {
            String::from_utf8_lossy(k).contains(&h) || String::from_utf8_lossy(v).contains(room_id)
        })
        .map(|(k, _)| String::from_utf8_lossy(&k).into_owned())
        .collect()
}

/// The room holds a file named by a record, one never named, one orphaned, an upload
/// still open with a chunk staged, a download handle, limit overrides at every scope
/// and a usage history. Returns the committed blobs and the open upload's id.
async fn populate(f: &Fixture, r: &Room) -> (Vec<String>, Uuid) {
    let named = upload(&f.host, r, MEMBER, 1_000, 1, Some("rec-1")).await;
    let unnamed = upload(&f.host, r, OTHER, 2_000, 2, None).await;
    let orphan = upload(&f.host, r, MEMBER, 3_000, 3, Some("rec-3")).await;
    f.host
        .prepare_record(r, Some(MEMBER), "rec-3", &[])
        .await
        .unwrap()
        .apply()
        .await
        .unwrap();
    assert_eq!(
        f.host
            .blob(&r.room_id, &orphan)
            .await
            .unwrap()
            .unwrap()
            .state,
        BlobState::Orphaned
    );

    let (bytes, manifest) = blob(4_000, 4);
    let digest = manifest.chunk_digests[0].clone();
    let begun = f
        .host
        .begin(r, MEMBER, Some(MEMBER), manifest)
        .await
        .unwrap();
    f.host
        .put_chunk(MEMBER, &begun.upload_id.to_string(), 0, &digest, &bytes)
        .await
        .unwrap();

    f.host
        .open_download(r, MEMBER, Some(MEMBER), &named)
        .await
        .unwrap();
    let limits = Some(ScopeLimits {
        max_files: Some(50),
        max_file_bytes: None,
        max_bytes: None,
    });
    for target in [
        LimitTarget::Room,
        LimitTarget::MemberDefault,
        LimitTarget::Member(MEMBER.into()),
    ] {
        f.host
            .set_limit_override(r, &target, limits, None)
            .await
            .unwrap();
    }
    // The collection pass writes the day's rows; within the grace it deletes nothing.
    f.host.sweep().await.unwrap();
    (vec![named, unnamed, orphan], begun.upload_id)
}

#[tokio::test]
async fn a_purge_removes_every_byte_and_row_of_the_room_and_gives_back_the_shared_counters() {
    let f = fixture();
    let neighbour = room(NEIGHBOUR);
    let kept = upload(&f.host, &neighbour, MEMBER, 5_000, 9, Some("rec-n")).await;
    let neighbour_usage = f.host.room_usage(NEIGHBOUR).await.unwrap();
    let before = counters(&f).await;

    let r = room(ROOM);
    let (blobs, open) = populate(&f, &r).await;
    for b in &blobs {
        assert!(object(&f, ROOM, b).exists());
    }
    let during = counters(&f).await;
    assert_eq!(during.0.files, before.0.files + 3);
    assert_eq!(during.0.reserved_bytes, before.0.reserved_bytes + 4_000);
    assert!(!rows_of(&f, ROOM).await.is_empty());

    let stats = f.host.purge_room(ROOM).await.unwrap();
    assert_eq!(stats.deleted, 3, "{stats:?}");
    assert!(stats.is_complete(), "{stats:?}");
    assert_eq!(stats.last_error, None);

    for b in &blobs {
        assert!(!object(&f, ROOM, b).exists(), "the bytes are gone at once");
    }
    assert_eq!(rows_of(&f, ROOM).await, Vec::<String>::new());
    assert_eq!(
        counters(&f).await,
        before,
        "storage and config counters are as before the room's files"
    );
    let slot = bundle_store::get_bundle(&f.host.transfers, &open)
        .await
        .unwrap()
        .unwrap();
    assert!(
        slot.state.is_terminal() && slot.blob_path.is_none(),
        "the staged chunk is dropped"
    );
    assert!(f.host.rooms_with_files().await.unwrap() == vec![NEIGHBOUR.to_string()]);

    // The neighbour is untouched.
    assert!(object(&f, NEIGHBOUR, &kept).exists());
    assert!(f.host.blob(NEIGHBOUR, &kept).await.unwrap().is_some());
    assert_eq!(f.host.room_usage(NEIGHBOUR).await.unwrap(), neighbour_usage);
}

#[tokio::test]
async fn a_second_purge_finds_nothing_and_is_complete() {
    let f = fixture();
    let r = room(ROOM);
    populate(&f, &r).await;
    assert!(f.host.purge_room(ROOM).await.unwrap().is_complete());

    let again = f.host.purge_room(ROOM).await.unwrap();
    assert_eq!(
        again,
        PurgeStats {
            deleted: 0,
            remaining: 0,
            last_error: None
        }
    );
    // A room that never had files is complete at once too.
    assert!(
        f.host
            .purge_room("did:key:zNever")
            .await
            .unwrap()
            .is_complete()
    );
}

#[tokio::test]
async fn a_failing_store_leaves_its_rows_for_the_next_call() {
    let f = fixture();
    let before = counters(&f).await;
    let r = room(ROOM);
    let (blobs, _) = populate(&f, &r).await;

    f.store.fail.store(true, Ordering::SeqCst);
    let stuck = f.host.purge_room(ROOM).await.unwrap();
    assert_eq!(stuck.remaining, 3, "{stuck:?}");
    assert_eq!(stuck.deleted, 0);
    assert!(!stuck.is_complete());
    assert!(
        stuck
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("unreachable"))
    );
    for b in &blobs {
        assert!(
            f.host.blob(ROOM, b).await.unwrap().is_some(),
            "the row stays to be retried"
        );
        assert!(object(&f, ROOM, b).exists());
    }
    // The open upload had no bytes at the store: it went, and its reservation with it.
    let (storage, _) = counters(&f).await;
    assert_eq!(storage.reserved_bytes, before.0.reserved_bytes);
    assert_eq!(storage.files, before.0.files + 3);
    // The room's bookkeeping waits for the purge to finish.
    assert!(f.host.room_usage(ROOM).await.unwrap().files > 0);

    f.store.fail.store(false, Ordering::SeqCst);
    let done = f.host.purge_room(ROOM).await.unwrap();
    assert_eq!((done.deleted, done.remaining), (3, 0), "{done:?}");
    assert_eq!(rows_of(&f, ROOM).await, Vec::<String>::new());
    assert_eq!(counters(&f).await, before);
}
