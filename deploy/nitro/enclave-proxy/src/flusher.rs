//! Background memtable flusher for the parent-side fjall database.
//!
//! A copy of `vti_common::store::flusher` (this proxy deliberately links no
//! enclave or workspace code) — keep the two in sync. fjall 3.1 only flushes
//! a keyspace once it alone holds 64 MiB of unflushed writes and never
//! enforces its database-wide write-buffer limit, so a store spread over
//! many small keyspaces keeps every write in memory and replays it all from
//! the journal at startup. See the vti-common module for the full story.

use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fjall::{Database, KeyspaceCreateOptions};
use tracing::{debug, info, warn};

/// Unflushed-bytes limit used when `fjall.write_buffer` is not configured.
/// Small enough to sit comfortably inside a 64 MiB pod alongside the
/// service itself; large enough that a busy service writes tables of a
/// reasonable size rather than many tiny ones.
pub const DEFAULT_WRITE_BUFFER_LIMIT: u64 = 8 * 1024 * 1024; // 8 MiB

/// How often the flusher checks the database. The check is two atomic
/// reads, so this is cheap.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// Longest a write may sit only in memory before it is flushed, however
/// small the backlog is. Keeps a quiet service's journal short, so a
/// restart replays little.
pub const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(300);

/// When the [`Flusher`] seals the database's memtables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlushPolicy {
    /// How often to check.
    pub interval: Duration,
    /// Flush as soon as this many bytes are unflushed across all keyspaces.
    pub write_buffer_limit: u64,
    /// Flush anything still unflushed after this long.
    pub max_idle: Duration,
}

impl Default for FlushPolicy {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            write_buffer_limit: DEFAULT_WRITE_BUFFER_LIMIT,
            max_idle: DEFAULT_MAX_IDLE,
        }
    }
}

// The builders are used by the tests; the proxy itself runs the defaults.
#[cfg_attr(not(test), allow(dead_code))]
impl FlushPolicy {
    /// The default policy with the write-buffer limit taken from
    /// `fjall.write_buffer` / `STORAGE_FJALL_WRITE_BUFFER` when set.
    pub fn from_write_buffer(write_buffer: Option<u64>) -> Self {
        Self {
            write_buffer_limit: write_buffer.unwrap_or(DEFAULT_WRITE_BUFFER_LIMIT),
            ..Self::default()
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

/// Seal every keyspace that holds unflushed writes, queueing each for
/// fjall's flush workers. Returns how many keyspaces were sealed. Empty
/// keyspaces are skipped by fjall itself, so this is safe to call at any
/// time.
pub fn flush_all(db: &Database) -> usize {
    let mut sealed = 0;
    for name in db.list_keyspace_names() {
        let name: &str = &name;
        // Opening an existing keyspace returns the live handle; the create
        // options are only used when the keyspace does not exist yet, which
        // cannot happen for a name the database just listed (barring a
        // concurrent delete, which then simply fails below).
        match db
            .keyspace(name, KeyspaceCreateOptions::default)
            .and_then(|ks| ks.rotate_memtable())
        {
            Ok(true) => sealed += 1,
            Ok(false) => {}
            Err(e) => {
                warn!(keyspace = name, error = %e, "[storage] flusher: could not seal memtable")
            }
        }
    }
    sealed
}

/// A running background flusher. Stops, and releases its handle on the
/// database, when dropped.
pub struct Flusher {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Flusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flusher").finish_non_exhaustive()
    }
}

impl Flusher {
    /// Start flushing `db` according to `policy`. Fails only if the OS
    /// refuses to start a thread.
    pub fn spawn(db: Database, policy: FlushPolicy) -> std::io::Result<Self> {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("fjall-flusher".into())
            .spawn(move || run(&db, policy, &stopped))?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        // Dropping the sender wakes the thread at once (Disconnected).
        // Joining guarantees its clone of the database is gone before we
        // return, so a caller that drops the store and reopens the same
        // directory never finds it still locked.
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(db: &Database, policy: FlushPolicy, stopped: &mpsc::Receiver<()>) {
    // Startup: whatever the journal replay put back in memory goes to disk.
    let replayed = db.write_buffer_size();
    if replayed > 0 {
        let sealed = flush_all(db);
        info!(
            unflushed_bytes = replayed,
            keyspaces = sealed,
            "[storage] flusher: flushing writes replayed from the journal"
        );
    }

    let mut dirty_since: Option<Instant> = None;
    loop {
        match stopped.recv_timeout(policy.interval) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // Disconnected (the Flusher was dropped) or an explicit stop.
            _ => return,
        }

        let unflushed = db.write_buffer_size();
        if unflushed == 0 {
            dirty_since = None;
            continue;
        }
        let since = *dirty_since.get_or_insert_with(Instant::now);

        let over_limit = unflushed >= policy.write_buffer_limit;
        if over_limit || since.elapsed() >= policy.max_idle {
            let sealed = flush_all(db);
            debug!(
                unflushed_bytes = unflushed,
                keyspaces = sealed,
                reason = if over_limit {
                    "write buffer limit"
                } else {
                    "idle"
                },
                "[storage] flusher: sealed memtables"
            );
            dirty_since = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir() -> std::path::PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "enclave-proxy-flusher-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn wait_until(mut f: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn flusher_enforces_the_write_buffer_limit() {
        let dir = temp_dir();
        let db = Database::builder(&dir).open().unwrap();
        let _flusher = Flusher::spawn(
            db.clone(),
            FlushPolicy::from_write_buffer(Some(2 * 1024 * 1024))
                .with_interval(Duration::from_millis(50)),
        )
        .unwrap();
        // Ten keyspaces, ~2 MiB each: none reaches fjall's own 64 MiB trigger.
        let kss: Vec<_> = (0..10)
            .map(|i| {
                db.keyspace(&format!("ks{i}"), KeyspaceCreateOptions::default)
                    .unwrap()
            })
            .collect();
        let value = vec![7u8; 1024];
        for n in 0..2_000u32 {
            for ks in &kss {
                ks.insert(n.to_be_bytes(), &value).unwrap();
            }
        }
        assert!(wait_until(|| db.write_buffer_size() < 2 * 1024 * 1024));
        assert!(kss.iter().map(|k| k.table_count()).sum::<usize>() > 0);
        drop((kss, _flusher, db));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_the_flusher_releases_the_database() {
        let dir = temp_dir();
        {
            let db = Database::builder(&dir).open().unwrap();
            let _flusher = Flusher::spawn(db.clone(), FlushPolicy::default()).unwrap();
            db.keyspace("a", KeyspaceCreateOptions::default)
                .unwrap()
                .insert("k", "v")
                .unwrap();
        }
        let db = Database::builder(&dir).open().unwrap();
        let ks = db.keyspace("a", KeyspaceCreateOptions::default).unwrap();
        assert_eq!(ks.get("k").unwrap().as_deref(), Some(&b"v"[..]));
        drop((ks, db));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
