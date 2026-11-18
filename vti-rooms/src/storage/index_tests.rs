//! The record indexes (#2595): every head, trace and page they answer is the one a scan of
//! the records answers, byte for byte — existing members verify these roots and traces.

use super::*;
use crate::Visibility;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

async fn open() -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .unwrap();
    let rooms = store.keyspace(crate::ROOMS_KEYSPACE).unwrap();
    let records = store.keyspace(crate::ROOM_RECORDS_KEYSPACE).unwrap();
    (dir, rooms, records)
}

fn room(id: &str) -> Room {
    Room {
        room_id: id.into(),
        owner_did: "did:key:zOwner".into(),
        visibility: Visibility::Open,
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

fn record(key: &str, body: &str) -> Record {
    Record {
        key: key.into(),
        version: 0,
        epoch: None,
        status: RecordStatus::Active,
        pinned: false,
        sealed: None,
        nonce: None,
        sealed_version: None,
        cleartext: Some(serde_json::json!({ "body": body })),
        author: Some("did:key:zBob".into()),
        updated_at: 0,
        created_at: None,
        created_by: None,
        body_stored_at: None,
    }
}

/// The head and every trace, as computed before the index: a scan of every record.
async fn by_scan(
    records: &KeyspaceHandle,
    room_id: &str,
) -> (
    crate::merkle::TreeHead,
    Vec<(String, crate::merkle::InclusionProof)>,
) {
    let mut all = list_records(records, room_id, None, None).await.unwrap();
    let head = crate::merkle::tree_head(&mut all).unwrap();
    let leaves: Vec<_> = all
        .iter()
        .map(|r| crate::merkle::leaf_hash(&r.committed()).unwrap())
        .collect();
    let traces = all
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                r.key.clone(),
                crate::merkle::inclusion_proof(&leaves, i).unwrap(),
            )
        })
        .collect();
    (head, traces)
}

async fn assert_matches_scan(records: &KeyspaceHandle, room_id: &str) {
    let (head, traces) = by_scan(records, room_id).await;
    // Twice: computed, then from the cached head.
    assert_eq!(tree_head(records, room_id).await.unwrap(), head);
    assert_eq!(tree_head(records, room_id).await.unwrap(), head);
    for (key, trace) in traces {
        let (h, t) = tree_head_with_trace(records, room_id, &key).await.unwrap();
        assert_eq!(h, head, "the head beside `{key}`'s trace");
        assert_eq!(t.as_ref(), Some(&trace), "`{key}`'s trace");
    }
    let (h, t) = tree_head_with_trace(records, room_id, "absent")
        .await
        .unwrap();
    assert_eq!(h, head);
    assert!(t.is_none());
}

/// Every page of `order`, walked to the end with the cursor.
async fn walk(
    records: &KeyspaceHandle,
    room_id: &str,
    prefix: Option<&str>,
    since: Option<u64>,
    order: RecordOrder,
    limit: usize,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = list_records_page_in(
            records,
            room_id,
            prefix,
            since,
            cursor.as_deref(),
            Some(limit),
            order,
        )
        .await
        .unwrap();
        assert!(page.records.len() <= limit);
        out.extend(page.records.iter().map(|r| (r.key.clone(), r.version)));
        match page.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    out
}

async fn assert_pages_match_scan(records: &KeyspaceHandle, room_id: &str) {
    for prefix in [None, Some("a/")] {
        for since in [None, Some(0), Some(3), Some(7)] {
            let mut expected: Vec<(String, u64)> = list_records(records, room_id, prefix, since)
                .await
                .unwrap()
                .into_iter()
                .map(|r| (r.key, r.version))
                .collect();
            for limit in [1, 2, 5, 500] {
                let oldest = walk(
                    records,
                    room_id,
                    prefix,
                    since,
                    RecordOrder::OldestFirst,
                    limit,
                )
                .await;
                assert_eq!(
                    oldest, expected,
                    "oldest first, {prefix:?} {since:?} {limit}"
                );
            }
            expected.reverse();
            for limit in [1, 3, 500] {
                let newest = walk(
                    records,
                    room_id,
                    prefix,
                    since,
                    RecordOrder::NewestFirst,
                    limit,
                )
                .await;
                assert_eq!(
                    newest, expected,
                    "newest first, {prefix:?} {since:?} {limit}"
                );
            }
        }
    }
}

#[tokio::test]
async fn heads_traces_and_pages_match_a_scan_through_every_kind_of_write() {
    let (_d, rooms, records) = open().await;
    let id = "did:web:example.com:r";
    create_room(&rooms, &room(id)).await.unwrap();
    assert_matches_scan(&records, id).await;

    for (i, key) in ["a/1", "b/1", "a/2", "c", "a/3", "b/2"].iter().enumerate() {
        put_record(&rooms, &records, id, record(key, "v1"), None, i as u64)
            .await
            .unwrap();
        assert_matches_scan(&records, id).await;
    }
    // Rewrites move a key to a new version.
    put_record(&rooms, &records, id, record("a/1", "v2"), None, 10)
        .await
        .unwrap();
    put_record(&rooms, &records, id, record("c", "v2"), None, 11)
        .await
        .unwrap();
    assert_matches_scan(&records, id).await;
    assert_pages_match_scan(&records, id).await;

    // Curation: a retraction and a pin.
    curate_record(
        &rooms,
        &records,
        id,
        "b/1",
        Curation {
            status: Some(RecordStatus::Retracted),
            ..Default::default()
        },
        12,
    )
    .await
    .unwrap();
    curate_record(
        &rooms,
        &records,
        id,
        "a/2",
        Curation {
            pinned: Some(true),
            ..Default::default()
        },
        13,
    )
    .await
    .unwrap();
    assert_matches_scan(&records, id).await;
    assert_pages_match_scan(&records, id).await;

    // A prune and an erasure.
    remove_pruned(&rooms, &records, id, &["a/3".into(), "b/2".into()], 14)
        .await
        .unwrap();
    purge_record(&records, id, "c").await.unwrap();
    assert_matches_scan(&records, id).await;
    assert_pages_match_scan(&records, id).await;
}

/// A room written before the index existed has no index rows: the first read builds them,
/// and answers what a scan answers — and a first write builds them before it writes.
#[tokio::test]
async fn a_room_without_an_index_is_indexed_on_first_use() {
    let (_d, rooms, records) = open().await;
    let id = "did:web:example.com:old";
    create_room(&rooms, &room(id)).await.unwrap();
    for (i, key) in ["k1", "k2", "k3", "a/1"].iter().enumerate() {
        put_record(&rooms, &records, id, record(key, "x"), None, i as u64)
            .await
            .unwrap();
    }
    // As the store stood before #2595: records, and nothing else.
    index::purge(&records, id).await.unwrap();
    assert!(
        records
            .get_raw(index::head_key(id))
            .await
            .unwrap()
            .is_none()
    );
    assert_matches_scan(&records, id).await;
    assert_pages_match_scan(&records, id).await;

    index::purge(&records, id).await.unwrap();
    put_record(&rooms, &records, id, record("k2", "y"), None, 9)
        .await
        .unwrap();
    assert_matches_scan(&records, id).await;
    assert_pages_match_scan(&records, id).await;
}

/// A head computed before a write is never cached after it: the reader's cache write is
/// conditional on the stale marker it read, and every write replaces the marker.
#[tokio::test]
async fn a_head_is_not_cached_over_a_later_write() {
    let (_d, rooms, records) = open().await;
    let id = "did:web:example.com:race";
    create_room(&rooms, &room(id)).await.unwrap();
    put_record(&rooms, &records, id, record("k1", "x"), None, 1)
        .await
        .unwrap();
    let marker = records.get_raw(index::head_key(id)).await.unwrap().unwrap();
    put_record(&rooms, &records, id, record("k2", "x"), None, 2)
        .await
        .unwrap();
    let mut batch = vti_common::store::Batch::new();
    batch
        .require_unchanged(index::head_key(id), marker)
        .insert_raw(index::head_key(id), b"{}".to_vec());
    assert!(!records.apply_batch(batch).await.unwrap().is_applied());
    assert_matches_scan(&records, id).await;
}

/// A record row rewritten around the index is caught up by `reindex_room`.
#[tokio::test]
async fn reindex_room_rebuilds_from_the_records() {
    let (_d, rooms, records) = open().await;
    let id = "did:web:example.com:raw";
    create_room(&rooms, &room(id)).await.unwrap();
    let mut r = put_record(&rooms, &records, id, record("k", "x"), None, 1)
        .await
        .unwrap();
    r.updated_at = 99;
    records
        .insert(record_storage_key(id, "k"), &r)
        .await
        .unwrap();
    reindex_room(&records, id).await.unwrap();
    assert_matches_scan(&records, id).await;
}

/// Removing a room removes its index rows with it.
#[tokio::test]
async fn a_purged_room_leaves_no_index_rows() {
    let (_d, rooms, records) = open().await;
    let id = "did:web:example.com:gone";
    create_room(&rooms, &room(id)).await.unwrap();
    put_record(&rooms, &records, id, record("k", "x"), None, 1)
        .await
        .unwrap();
    tree_head(&records, id).await.unwrap();
    // The links and revocations keyspaces hold nothing for this room; any handle serves.
    purge_room_rows(&rooms, &records, &records, &rooms, id)
        .await
        .unwrap();
    for prefix in index::prefixes(id) {
        assert!(records.prefix_keys(prefix).await.unwrap().is_empty());
    }
    assert!(
        records
            .get_raw(index::head_key(id))
            .await
            .unwrap()
            .is_none()
    );
}
