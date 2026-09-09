//! What the record commitment actually costs, measured rather than assumed.
//!
//! `storage::tree_head` is deliberately uncached: a cache would have to be
//! invalidated by every put, curate and prune, and **a stale root is worse than
//! a slow one** — it is a *wrong* commitment, and the failure it produces is an
//! honest host appearing to equivocate, which is the exact accusation the
//! machinery exists to make credible.
//!
//! The standing decision is therefore "correct first, and cache when there is a
//! measurement saying where". This is that measurement. It is a test rather than
//! a benchmark because its job is to be *run* and read, not to gate anything: it
//! asserts only an order of magnitude, so it fails if the cost changes by 10x
//! and not if a laptop is busy.

use std::time::Instant;

use vti_rooms::{Record, RecordStatus};

fn room(n: usize) -> Vec<Record> {
    (0..n)
        .map(|i| Record {
            // Opaque keys, as a sealed tier requires — and the realistic case
            // for sorting, since they share no prefix.
            key: format!("{:032x}", i * 2_654_435_761usize),
            version: i as u64 + 1,
            epoch: Some(3),
            status: RecordStatus::Active,
            pinned: false,
            // A realistic sealed body. The leaf commits to the ciphertext, so
            // the hash input scales with what a room actually stores.
            sealed: Some("A".repeat(2048)),
            nonce: Some("bm9uY2UtMTI".into()),
            cleartext: None,
            author: None,
            updated_at: 1_756_000_000,
        })
        .collect()
}

#[test]
fn the_commitment_costs_what_it_looks_like_it_costs() {
    let mut sizes: Vec<(usize, u128)> = Vec::new();
    for n in [100usize, 1_000, 10_000] {
        let mut records = room(n);
        let started = Instant::now();
        let head = vti_rooms::merkle::tree_head(&mut records).expect("commits");
        let micros = started.elapsed().as_micros();
        assert_eq!(head.record_count, n as u64);
        sizes.push((n, micros));
        println!("tree_head over {n:>6} records × 2 KiB: {micros:>8} µs");
    }

    // The shape, not the number. Hashing is linear in total bytes and the sort
    // is n log n, so ten times the records should cost roughly ten times as
    // much — and conspicuously not a hundred times, which is what an accidental
    // quadratic would look like and is the thing worth catching.
    let (_, small) = sizes[0];
    let (_, large) = sizes[2];
    assert!(
        large < small.max(1) * 1_000,
        "100x the records cost more than 1000x the time — that is not linear: {sizes:?}"
    );
}
