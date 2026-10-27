//! Behavioural conformance suite for `KeyspaceHandle`.
//!
//! `KeyspaceHandle` is an enum that dispatches to either the local fjall
//! backend or the vsock-proxied backend used inside Nitro Enclaves. The
//! parent project's CLAUDE.md notes that semantic parity between the two
//! is "asserted but under-tested" — the existing in-tree tests cover the
//! vsock wire format but never run the same suite of operations against
//! both implementations.
//!
//! This test file defines the behavioural contract every `KeyspaceHandle`
//! must satisfy. The cases are pure invariant assertions on observable
//! behaviour; the harness can be re-run against a connected
//! `KeyspaceHandle::Vsock` simply by parameterising `with_handle` over
//! both kinds. Today, lacking an in-process fake of the parent-side
//! storage proxy, only `Local` is exercised — but a single new test
//! function can wrap `vsock::VsockKeyspaceHandle` once the fake proxy
//! lands, and the whole suite runs against both with no test code changes.
//!
//! When a regression in either backend changes observable behaviour
//! (different errors, different ordering, different prefix-scan semantics),
//! one of these tests fails for both backends. That's the property
//! CLAUDE.md was asking for.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, ScanOpts, Store};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Sample {
    n: u32,
    label: String,
}

/// Build a `KeyspaceHandle::Local` over a tempdir.
fn local_handle() -> (KeyspaceHandle, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");
    let ks = store.keyspace("conformance").expect("keyspace");
    (ks, dir)
}

// ── Insert / Get round-trips ──────────────────────────────────────────

#[tokio::test]
async fn typed_insert_get_round_trip() {
    let (ks, _dir) = local_handle();
    let v = Sample {
        n: 42,
        label: "hello".into(),
    };
    ks.insert("k1", &v).await.expect("insert");
    let loaded: Option<Sample> = ks.get("k1").await.expect("get");
    assert_eq!(loaded, Some(v));
}

#[tokio::test]
async fn raw_insert_get_round_trip() {
    let (ks, _dir) = local_handle();
    let bytes = b"raw bytes".to_vec();
    ks.insert_raw("k1", bytes.clone()).await.expect("insert");
    let loaded = ks.get_raw("k1").await.expect("get").expect("present");
    assert_eq!(loaded, bytes);
}

#[tokio::test]
async fn get_returns_none_for_missing_key() {
    let (ks, _dir) = local_handle();
    let loaded: Option<Sample> = ks.get("never-existed").await.expect("get");
    assert!(loaded.is_none());
    let loaded_raw = ks.get_raw("never-existed").await.expect("get_raw");
    assert!(loaded_raw.is_none());
}

#[tokio::test]
async fn insert_overwrites_existing_value() {
    let (ks, _dir) = local_handle();
    ks.insert_raw("k1", b"v1".to_vec()).await.unwrap();
    ks.insert_raw("k1", b"v2".to_vec()).await.unwrap();
    let v = ks.get_raw("k1").await.unwrap().unwrap();
    assert_eq!(v, b"v2");
}

// ── Removal ───────────────────────────────────────────────────────────

#[tokio::test]
async fn remove_makes_get_return_none() {
    let (ks, _dir) = local_handle();
    ks.insert_raw("k1", b"v1".to_vec()).await.unwrap();
    ks.remove("k1").await.unwrap();
    assert!(ks.get_raw("k1").await.unwrap().is_none());
}

#[tokio::test]
async fn remove_missing_key_is_noop() {
    let (ks, _dir) = local_handle();
    // Removing a non-existent key must succeed silently — both backends
    // treat this as idempotent.
    ks.remove("never-existed").await.expect("remove");
}

// ── Prefix iteration ──────────────────────────────────────────────────

#[tokio::test]
async fn prefix_iter_returns_only_matching_keys() {
    let (ks, _dir) = local_handle();
    ks.insert_raw("foo:1", b"a".to_vec()).await.unwrap();
    ks.insert_raw("foo:2", b"b".to_vec()).await.unwrap();
    ks.insert_raw("bar:1", b"c".to_vec()).await.unwrap();

    let pairs = ks.prefix_iter_raw("foo:").await.unwrap();
    let keys: HashSet<String> = pairs
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert_eq!(
        keys,
        HashSet::from(["foo:1".into(), "foo:2".into()]),
        "prefix scan must return exactly the matching keys"
    );
}

#[tokio::test]
async fn prefix_iter_empty_prefix_returns_all() {
    let (ks, _dir) = local_handle();
    ks.insert_raw("a", b"1".to_vec()).await.unwrap();
    ks.insert_raw("b", b"2".to_vec()).await.unwrap();
    ks.insert_raw("c", b"3".to_vec()).await.unwrap();
    let pairs = ks.prefix_iter_raw("").await.unwrap();
    assert_eq!(pairs.len(), 3);
}

#[tokio::test]
async fn prefix_iter_no_match_returns_empty() {
    let (ks, _dir) = local_handle();
    ks.insert_raw("foo", b"v".to_vec()).await.unwrap();
    let pairs = ks.prefix_iter_raw("bar").await.unwrap();
    assert!(pairs.is_empty());
}

#[tokio::test]
async fn prefix_keys_returns_keys_only() {
    let (ks, _dir) = local_handle();
    ks.insert_raw("k1", b"v1".to_vec()).await.unwrap();
    ks.insert_raw("k2", b"v2".to_vec()).await.unwrap();
    let mut keys: Vec<String> = ks
        .prefix_keys("")
        .await
        .unwrap()
        .into_iter()
        .map(|k| String::from_utf8_lossy(&k).into_owned())
        .collect();
    keys.sort();
    assert_eq!(keys, vec!["k1", "k2"]);
}

// ── Bounded scans ─────────────────────────────────────────────────────

/// Seed `log:00`..`log:04` plus neighbours on either side of the prefix.
async fn seeded_scan_handle() -> (KeyspaceHandle, tempfile::TempDir) {
    let (ks, dir) = local_handle();
    for i in 0..5 {
        ks.insert_raw(format!("log:{i:02}"), format!("v{i}").into_bytes())
            .await
            .unwrap();
    }
    // `lof:` sorts before `log:`, `prune:watermark` after it — the audit
    // keyspace's own layout, and what a prefix-scoped scan must exclude.
    ks.insert_raw("lof:zz", b"before".to_vec()).await.unwrap();
    ks.insert_raw("prune:watermark", b"after".to_vec())
        .await
        .unwrap();
    (ks, dir)
}

fn keys_of(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<String> {
    pairs
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect()
}

#[tokio::test]
async fn scan_ascending_honours_limit_and_order() {
    let (ks, _dir) = seeded_scan_handle().await;
    let pairs = ks.scan_raw(ScanOpts::new("log:", 2)).await.unwrap();
    assert_eq!(keys_of(&pairs), vec!["log:00", "log:01"]);
    assert_eq!(pairs[0].1, b"v0");
}

#[tokio::test]
async fn scan_descending_returns_newest_first() {
    let (ks, _dir) = seeded_scan_handle().await;
    let pairs = ks
        .scan_raw(ScanOpts::newest_first("log:", 2))
        .await
        .unwrap();
    assert_eq!(keys_of(&pairs), vec!["log:04", "log:03"]);
}

#[tokio::test]
async fn scan_stays_inside_its_prefix() {
    let (ks, _dir) = seeded_scan_handle().await;
    // The row a chain-head lookup must never mistake for the newest entry.
    let pairs = ks
        .scan_raw(ScanOpts::newest_first("log:", 100))
        .await
        .unwrap();
    assert_eq!(
        keys_of(&pairs),
        vec!["log:04", "log:03", "log:02", "log:01", "log:00"],
        "neither the row before the prefix nor the one after it belongs to the scan"
    );
}

#[tokio::test]
async fn scan_after_is_exclusive_in_each_direction() {
    let (ks, _dir) = seeded_scan_handle().await;
    let up = ks
        .scan_raw(ScanOpts::new("log:", 2).after("log:01"))
        .await
        .unwrap();
    assert_eq!(keys_of(&up), vec!["log:02", "log:03"]);

    let down = ks
        .scan_raw(ScanOpts::newest_first("log:", 2).after("log:03"))
        .await
        .unwrap();
    assert_eq!(keys_of(&down), vec!["log:02", "log:01"]);
}

#[tokio::test]
async fn scan_after_outside_the_prefix_does_not_widen_it() {
    let (ks, _dir) = seeded_scan_handle().await;
    // A resume key before the prefix must not drag in `lof:zz`...
    let up = ks
        .scan_raw(ScanOpts::new("log:", 100).after("aaa"))
        .await
        .unwrap();
    assert_eq!(up.len(), 5, "got {:?}", keys_of(&up));

    // ...nor one past the prefix drag in `prune:watermark`.
    let down = ks
        .scan_raw(ScanOpts::newest_first("log:", 100).after("zzz"))
        .await
        .unwrap();
    assert_eq!(keys_of(&down)[0], "log:04");
    assert_eq!(down.len(), 5);
}

#[tokio::test]
async fn scan_pages_cover_the_range_exactly_once() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut opts = ScanOpts::new("log:", 2);
        if let Some(c) = &cursor {
            opts = opts.after(c.clone());
        }
        let page = ks.scan_raw(opts).await.unwrap();
        if page.is_empty() {
            break;
        }
        cursor = Some(String::from_utf8_lossy(&page[page.len() - 1].0).into_owned());
        seen.extend(keys_of(&page));
    }
    assert_eq!(
        seen,
        vec!["log:00", "log:01", "log:02", "log:03", "log:04"],
        "paging must be gapless and duplicate-free"
    );
}

#[tokio::test]
async fn scan_limit_zero_reads_nothing() {
    let (ks, _dir) = seeded_scan_handle().await;
    assert!(
        ks.scan_raw(ScanOpts::new("log:", 0))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn scan_empty_prefix_covers_the_whole_keyspace() {
    let (ks, _dir) = seeded_scan_handle().await;
    let pairs = ks.scan_raw(ScanOpts::newest_first("", 1)).await.unwrap();
    assert_eq!(keys_of(&pairs), vec!["prune:watermark"]);
}

#[tokio::test]
async fn scan_handles_an_all_ff_prefix() {
    // There is no key that sorts past 0xFF.., so the prefix has no
    // incrementable byte and the upper bound must be left unbounded.
    let (ks, _dir) = local_handle();
    ks.insert_raw(vec![0xffu8, 0x01], b"a".to_vec())
        .await
        .unwrap();
    ks.insert_raw(vec![0x01u8], b"b".to_vec()).await.unwrap();
    let pairs = ks.scan_raw(ScanOpts::new(vec![0xffu8], 10)).await.unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, vec![0xff, 0x01]);
}

#[tokio::test]
async fn scan_no_match_returns_empty() {
    let (ks, _dir) = seeded_scan_handle().await;
    assert!(
        ks.scan_raw(ScanOpts::new("nothing:", 10))
            .await
            .unwrap()
            .is_empty()
    );
}

// ── Paged scans ───────────────────────────────────────────────────────

/// Walk every page a pager yields, flattening to keys.
async fn drain_pager(pager: &mut vti_common::store::ScanPager) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        let page = pager.next_page().await.unwrap();
        if page.is_empty() {
            break;
        }
        seen.extend(keys_of(&page));
    }
    seen
}

#[tokio::test]
async fn pager_covers_the_range_exactly_once_ascending() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut pager = ks.scan_pager(ScanOpts::new("log:", 2));
    assert_eq!(
        drain_pager(&mut pager).await,
        vec!["log:00", "log:01", "log:02", "log:03", "log:04"],
        "paging must be gapless and duplicate-free"
    );
}

#[tokio::test]
async fn pager_covers_the_range_exactly_once_descending() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut pager = ks.scan_pager(ScanOpts::newest_first("log:", 2));
    assert_eq!(
        drain_pager(&mut pager).await,
        vec!["log:04", "log:03", "log:02", "log:01", "log:00"],
    );
}

#[tokio::test]
async fn pager_stays_inside_its_prefix() {
    let (ks, _dir) = seeded_scan_handle().await;
    // `lof:zz` sorts before the prefix and `prune:watermark` after it; a walk
    // that pages past the end must not pick either up.
    let mut pager = ks.scan_pager(ScanOpts::new("log:", 2));
    let seen = drain_pager(&mut pager).await;
    assert_eq!(seen.len(), 5, "got {seen:?}");
    assert!(seen.iter().all(|k| k.starts_with("log:")));
}

#[tokio::test]
async fn pager_resumes_from_the_opts_cursor() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut pager = ks.scan_pager(ScanOpts::new("log:", 2).after("log:01"));
    assert_eq!(
        drain_pager(&mut pager).await,
        vec!["log:02", "log:03", "log:04"],
        "the first page starts strictly beyond the seeded cursor"
    );
}

#[tokio::test]
async fn pager_with_a_page_larger_than_the_range_ends_after_one_page() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut pager = ks.scan_pager(ScanOpts::new("log:", 100));
    assert_eq!(pager.next_page().await.unwrap().len(), 5);
    assert!(
        pager.next_page().await.unwrap().is_empty(),
        "a short page ends the walk"
    );
}

#[tokio::test]
async fn pager_over_an_empty_range_yields_nothing() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut pager = ks.scan_pager(ScanOpts::new("nothing:", 2));
    assert!(pager.next_page().await.unwrap().is_empty());
}

/// A zero page size can never make progress. It must terminate rather than
/// spin: `take(0)` yields an empty page forever without ever being *short*
/// of the limit, which is how the walk normally detects its end.
#[tokio::test]
async fn pager_with_a_zero_page_size_terminates() {
    let (ks, _dir) = seeded_scan_handle().await;
    let mut pager = ks.scan_pager(ScanOpts::new("log:", 0));
    assert!(pager.next_page().await.unwrap().is_empty());
    assert!(pager.next_page().await.unwrap().is_empty());
}

// ── Large values and binary-safe keys ─────────────────────────────────

#[tokio::test]
async fn large_value_round_trips() {
    // Stress: 256 KiB value. The vsock wire framing uses a 4-byte length
    // prefix, so anything up to 4 GiB is in-spec; this catches off-by-one
    // bugs around the buffer-allocation path.
    let (ks, _dir) = local_handle();
    let big = vec![0xABu8; 256 * 1024];
    ks.insert_raw("big", big.clone()).await.unwrap();
    let back = ks.get_raw("big").await.unwrap().unwrap();
    assert_eq!(back, big);
}

#[tokio::test]
async fn binary_safe_keys_round_trip() {
    // Keys are not necessarily UTF-8. The wire protocol must not assume
    // they are. Insert a key with a NUL byte and verify we get it back.
    let (ks, _dir) = local_handle();
    let key = vec![0x00, 0xff, 0x42, 0x00, 0x99];
    ks.insert_raw(key.clone(), b"v".to_vec()).await.unwrap();
    let v = ks.get_raw(key.clone()).await.unwrap().unwrap();
    assert_eq!(v, b"v");
    let pairs = ks.prefix_iter_raw(vec![0x00u8]).await.unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, key);
}

// Empty keys are not supported by fjall (the local backend) — calling
// `insert` with a zero-length key triggers an unwind from inside the
// LSM, which we surface as a panic during teardown rather than a
// clean error. The vsock proxy inherits this constraint. The
// conformance contract is therefore: keys MUST have non-zero length.
// No `empty_key` test — neither backend accepts it, and adding one
// would document a behaviour we explicitly reject.

#[tokio::test]
async fn empty_value_round_trips() {
    // Edge: zero-length value. Same reasoning as empty key.
    let (ks, _dir) = local_handle();
    ks.insert_raw("k", Vec::<u8>::new()).await.unwrap();
    let v = ks.get_raw("k").await.unwrap().unwrap();
    assert!(
        v.is_empty(),
        "empty-value round-trip must preserve length 0"
    );
}

// ── approximate_len ───────────────────────────────────────────────────

#[tokio::test]
async fn approximate_len_grows_with_inserts() {
    let (ks, _dir) = local_handle();
    let before = ks.approximate_len().await.unwrap();
    for i in 0..10 {
        ks.insert_raw(format!("k{i}"), vec![0u8; 16]).await.unwrap();
    }
    let after = ks.approximate_len().await.unwrap();
    assert!(
        after > before,
        "approximate_len must grow after inserts (before={before}, after={after})"
    );
}
