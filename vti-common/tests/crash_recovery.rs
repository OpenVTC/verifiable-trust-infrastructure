//! Crash recovery of multi-row store writes, by killing a real writer.
//!
//! The test re-runs its own binary as a child that moves one row back and
//! forth between two keys with `KeyspaceHandle::apply_batch`, acknowledging
//! each applied move on stdout. The parent `SIGKILL`s it mid-stream, reopens
//! the store — fjall replays its journal — and checks the two properties a
//! batch promises across a crash:
//!
//! - **all or nothing**: exactly one of the two keys holds the row. A move
//!   torn in half would leave both (the old row still live beside its
//!   replacement) or neither.
//! - **acknowledged writes survive**: the row holds a generation at least as
//!   new as the last one the child acknowledged. Each write reaches the OS
//!   before `apply_batch` returns, so a process crash loses none of them.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vti_common::config::StoreConfig;
use vti_common::store::{Batch, Store};

const CHILD_ENV: &str = "VTI_CRASH_RECOVERY_CHILD_DIR";
const TEST_NAME: &str = "a_killed_writer_leaves_every_batch_whole";
const KILLS: usize = 8;

fn open(dir: &Path) -> Store {
    Store::open(&StoreConfig {
        data_dir: dir.to_path_buf(),
    })
    .expect("open store")
}

/// The child: move the row from whichever key holds it to the other, forever.
async fn writer(dir: &Path) -> ! {
    let ks = open(dir).keyspace("crash").unwrap();
    let mut generation: u64 = match ks.get_raw("a").await.unwrap() {
        Some(_) => 0,
        None if ks.get_raw("b").await.unwrap().is_none() => {
            ks.insert_raw("a", 0u64.to_be_bytes().to_vec())
                .await
                .unwrap();
            0
        }
        None => 0,
    };
    loop {
        let (from, to) = if ks.get_raw("a").await.unwrap().is_some() {
            ("a", "b")
        } else {
            ("b", "a")
        };
        let held = ks.get_raw(from).await.unwrap().unwrap();
        generation = generation.max(u64::from_be_bytes(held[..8].try_into().unwrap())) + 1;
        let mut batch = Batch::new();
        batch
            .require_present(from)
            .require_absent(to)
            .remove(from)
            .insert_raw(to, generation.to_be_bytes().to_vec());
        assert!(ks.apply_batch(batch).await.unwrap().is_applied());
        println!("{generation}");
    }
}

#[tokio::test]
async fn a_killed_writer_leaves_every_batch_whole() {
    if let Ok(dir) = std::env::var(CHILD_ENV) {
        writer(Path::new(&dir)).await;
    }

    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    for kill in 0..KILLS {
        let mut child = Command::new(&exe)
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

        // Let it run for a varying number of moves, then kill it mid-stream.
        let target = 200 + kill as u64 * 137;
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut acked = 0u64;
        while acked < target {
            assert!(Instant::now() < deadline, "writer stalled at {acked}");
            match lines.next() {
                Some(Ok(line)) => {
                    if let Ok(g) = line.trim().parse() {
                        acked = g;
                    }
                }
                _ => panic!("writer exited before it was killed"),
            }
        }
        child.kill().unwrap(); // SIGKILL: no destructors, no flush
        child.wait().unwrap();

        let ks = open(dir.path()).keyspace("crash").unwrap();
        let a = ks.get_raw("a").await.unwrap();
        let b = ks.get_raw("b").await.unwrap();
        let held = match (a, b) {
            (Some(v), None) | (None, Some(v)) => v,
            (a, b) => panic!(
                "kill {kill}: a torn move — a present: {}, b present: {}",
                a.is_some(),
                b.is_some()
            ),
        };
        let recovered = u64::from_be_bytes(held[..8].try_into().unwrap());
        assert!(
            recovered >= acked,
            "kill {kill}: acknowledged generation {acked} lost (recovered {recovered})"
        );
    }
}
