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
use tracing::{debug, error, info, warn};

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

/// Longest [`Flusher`]'s `Drop` waits for the thread to stop. A seal only
/// queues work for fjall's own flush workers, so the thread normally stops
/// at once; this bounds shutdown if a disk stalls mid-call.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

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

/// What one [`flush_all`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlushPass {
    /// Keyspaces sealed and queued for flushing.
    pub sealed: usize,
    /// Keyspaces that could not be sealed. Each is logged at `error`.
    pub failed: usize,
}

/// Seal every keyspace that holds unflushed writes, queueing each for
/// fjall's flush workers. Empty keyspaces are skipped by fjall itself, so
/// this is safe to call at any time.
///
/// The loop is over the database's own keyspaces, whose names are fixed by
/// the enclave's store code, not by callers.
pub fn flush_all(db: &Database) -> FlushPass {
    let mut pass = FlushPass::default();
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
            Ok(true) => pass.sealed += 1,
            Ok(false) => {}
            Err(e) => {
                pass.failed += 1;
                error!(keyspace = name, error = %e, "[storage] flusher: could not seal memtable; its writes stay in memory");
            }
        }
    }
    pass
}

/// A running background flusher. Stops, and releases its handle on the
/// database, when dropped.
pub struct Flusher {
    stop: Option<mpsc::Sender<()>>,
    /// Disconnects when the thread exits, so `Drop` can wait with a bound.
    /// In a `Mutex` only to make `Flusher` `Sync`; `Drop` reaches it
    /// through `get_mut`, without locking.
    stopped: std::sync::Mutex<mpsc::Receiver<()>>,
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
    ///
    /// Callers fail store startup on that error rather than run without a
    /// flusher: a store that never flushes grows until it is OOM-killed, so a
    /// refusal at startup is the safer and more visible failure.
    pub fn spawn(db: Database, policy: FlushPolicy) -> std::io::Result<Self> {
        let (stop, stop_rx) = mpsc::channel::<()>();
        let (exited, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("fjall-flusher".into())
            .spawn(move || {
                // Dropped when the thread returns, however it returns.
                let _exited = exited;
                run(&db, policy, &stop_rx);
            })?;
        Ok(Self {
            stop: Some(stop),
            stopped: std::sync::Mutex::new(stopped),
            thread: Some(thread),
        })
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        // Dropping the sender wakes the thread at once (Disconnected).
        // Waiting for it guarantees its clone of the database is gone before
        // we return, so a caller that drops the store and reopens the same
        // directory never finds it still locked. The wait is bounded: if the
        // thread is stuck in a stalled disk call, shutdown goes on without it
        // and the thread finishes (and releases the database) on its own.
        drop(self.stop.take());
        let Some(thread) = self.thread.take() else {
            return;
        };
        let stopped = self
            .stopped
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match stopped.recv_timeout(STOP_TIMEOUT) {
            Err(mpsc::RecvTimeoutError::Disconnected) | Ok(()) => {
                let _ = thread.join();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                error!(
                    timeout_secs = STOP_TIMEOUT.as_secs(),
                    "[storage] flusher: thread did not stop in time; leaving it to finish on its own"
                );
            }
        }
    }
}

fn run(db: &Database, policy: FlushPolicy, stopped: &mpsc::Receiver<()>) {
    // Startup: whatever the journal replay put back in memory goes to disk.
    let replayed = db.write_buffer_size();
    let mut failing_passes: u64 = 0;
    if replayed > 0 {
        let pass = flush_all(db);
        info!(
            unflushed_bytes = replayed,
            keyspaces = pass.sealed,
            "[storage] flusher: flushing writes replayed from the journal"
        );
        note_failures(pass, &mut failing_passes);
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
            let pass = flush_all(db);
            debug!(
                unflushed_bytes = unflushed,
                keyspaces = pass.sealed,
                reason = if over_limit {
                    "write buffer limit"
                } else {
                    "idle"
                },
                "[storage] flusher: sealed memtables"
            );
            note_failures(pass, &mut failing_passes);
            dirty_since = None;
        }
    }
}

/// Track passes in a row that failed to seal some keyspace, so a persistent
/// failure reads as one in the logs instead of as isolated errors.
fn note_failures(pass: FlushPass, failing_passes: &mut u64) {
    if pass.failed == 0 {
        if *failing_passes > 0 {
            warn!(
                after_failing_passes = *failing_passes,
                "[storage] flusher: sealing memtables recovered"
            );
        }
        *failing_passes = 0;
        return;
    }
    *failing_passes += 1;
    error!(
        failed_keyspaces = pass.failed,
        consecutive_failing_passes = *failing_passes,
        "[storage] flusher: memtables could not be sealed; memory will keep growing until this clears"
    );
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
