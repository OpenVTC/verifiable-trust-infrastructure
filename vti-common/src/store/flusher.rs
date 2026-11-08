//! Background memtable flusher for a local fjall database.
//!
//! fjall 3.1 (checked against 3.1.12 and 3.1.13) only flushes a keyspace's
//! memtable to disk once that one keyspace holds `max_memtable_size`
//! (64 MiB by default) of unflushed writes. Its database-wide write-buffer
//! limit (`Builder::max_write_buffer_size`) is stored but never read, and
//! its journal limit (`max_journaling_size`) is only checked while a flush
//! runs. A service that spreads its writes over many small keyspaces — the
//! VTA has ~37 — therefore never flushes at all: every write it has ever
//! made, including every overwritten version of a record, stays in memory
//! and is replayed from the journal at startup. On staging this OOM-killed
//! keyring runner VTAs whose live data was under 1 MB.
//!
//! [`Flusher`] closes that gap from the outside. A background thread checks
//! the database's unflushed bytes every [`FlushPolicy::interval`] and seals
//! (`rotate_memtable`) every non-empty keyspace when the total reaches
//! [`FlushPolicy::write_buffer_limit`], or when anything has sat unflushed
//! for [`FlushPolicy::max_idle`]. Sealing *every* keyspace, not just the
//! largest, matters: fjall can only delete a journal file once every
//! keyspace has flushed past it, so one quiet keyspace would otherwise pin
//! the whole journal. The first check runs as soon as the thread starts, so
//! a database that replayed a large journal on open drains it right away.
//!
//! `max_memtable_size` is not a usable fix on its own: fjall persists it
//! when a keyspace is created and reads it back on every open, so changing
//! it only affects keyspaces created afterwards.
//!
//! The fjall calls used here (`write_buffer_size`, `rotate_memtable`) are
//! public but `#[doc(hidden)]`. Re-check this module when bumping fjall:
//! if upstream starts enforcing the write-buffer limit itself, it can go.

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

    pub fn with_max_idle(mut self, max_idle: Duration) -> Self {
        self.max_idle = max_idle;
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
/// the services (`vta-keyspaces`, the VTC's keyspace list), not by callers.
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
                error!(keyspace = name, error = %e, "flusher: could not seal memtable; its writes stay in memory");
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
                    "flusher: thread did not stop in time; leaving it to finish on its own"
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
            unflushed = %crate::config::human_bytes(replayed),
            keyspaces = pass.sealed,
            "flusher: flushing writes replayed from the journal"
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
                unflushed = %crate::config::human_bytes(unflushed),
                keyspaces = pass.sealed,
                reason = if over_limit { "write buffer limit" } else { "idle" },
                "flusher: sealed memtables"
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
                "flusher: sealing memtables recovered"
            );
        }
        *failing_passes = 0;
        return;
    }
    *failing_passes += 1;
    error!(
        failed_keyspaces = pass.failed,
        consecutive_failing_passes = *failing_passes,
        "flusher: memtables could not be sealed; memory will keep growing until this clears"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Writes spread across many keyspaces, none reaching fjall's own
    /// 64 MiB per-keyspace trigger. Without the flusher fjall keeps all of
    /// it in memory (the staging OOM); with it, unflushed bytes come back
    /// down and data lands in on-disk tables.
    fn write_spread(db: &Database, keyspaces: usize, per_keyspace: usize) -> Vec<fjall::Keyspace> {
        let kss: Vec<_> = (0..keyspaces)
            .map(|i| {
                db.keyspace(&format!("ks{i}"), KeyspaceCreateOptions::default)
                    .unwrap()
            })
            .collect();
        let value = vec![7u8; 1024];
        for n in 0..per_keyspace as u32 {
            for ks in &kss {
                ks.insert(n.to_be_bytes(), &value).unwrap();
            }
        }
        kss
    }

    #[test]
    fn without_flusher_small_keyspaces_never_flush() {
        // Documents the fjall behaviour this module exists for. If this
        // starts failing after a fjall bump, upstream may have fixed it.
        let dir = tempfile::tempdir().unwrap();
        let db = Database::builder(dir.path()).open().unwrap();
        let kss = write_spread(&db, 10, 2_000); // ~20 MiB
        std::thread::sleep(Duration::from_millis(500));
        assert!(db.write_buffer_size() > 16 * 1024 * 1024);
        assert_eq!(kss.iter().map(|k| k.table_count()).sum::<usize>(), 0);
    }

    #[test]
    fn flusher_enforces_the_write_buffer_limit() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::builder(dir.path()).open().unwrap();
        let _flusher = Flusher::spawn(
            db.clone(),
            FlushPolicy::from_write_buffer(Some(2 * 1024 * 1024))
                .with_interval(Duration::from_millis(50)),
        )
        .unwrap();

        let kss = write_spread(&db, 10, 2_000); // ~20 MiB
        assert!(
            wait_until(|| db.write_buffer_size() < 2 * 1024 * 1024),
            "unflushed bytes stayed at {}",
            db.write_buffer_size()
        );
        assert!(kss.iter().map(|k| k.table_count()).sum::<usize>() > 0);
        // Every key is still readable after the flush.
        for ks in &kss {
            assert_eq!(ks.len().unwrap(), 2_000);
        }
    }

    #[test]
    fn flusher_flushes_a_small_backlog_once_idle() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::builder(dir.path()).open().unwrap();
        let _flusher = Flusher::spawn(
            db.clone(),
            FlushPolicy::default()
                .with_interval(Duration::from_millis(50))
                .with_max_idle(Duration::from_millis(200)),
        )
        .unwrap();

        let ks = db
            .keyspace("quiet", KeyspaceCreateOptions::default)
            .unwrap();
        ks.insert("k", "v").unwrap();
        assert!(wait_until(|| db.write_buffer_size() == 0));
        assert!(ks.table_count() > 0);
    }

    #[test]
    fn flusher_drains_a_replayed_journal_on_start() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = Database::builder(dir.path()).open().unwrap();
            write_spread(&db, 5, 1_000); // ~5 MiB, never flushed
            db.persist(fjall::PersistMode::SyncAll).unwrap();
        }
        let db = Database::builder(dir.path()).open().unwrap();
        assert!(
            db.write_buffer_size() > 0,
            "journal replay should refill memtables"
        );
        let _flusher = Flusher::spawn(
            db.clone(),
            // Long interval and idle time: only the startup pass can flush.
            FlushPolicy::default()
                .with_interval(Duration::from_secs(3600))
                .with_max_idle(Duration::from_secs(3600)),
        )
        .unwrap();
        assert!(wait_until(|| db.write_buffer_size() == 0));
    }

    #[test]
    fn dropping_the_flusher_releases_the_database() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = Database::builder(dir.path()).open().unwrap();
            let _flusher = Flusher::spawn(db.clone(), FlushPolicy::default()).unwrap();
            db.keyspace("a", KeyspaceCreateOptions::default)
                .unwrap()
                .insert("k", "v")
                .unwrap();
        }
        // The flusher's clone is gone, so the directory can be reopened.
        let db = Database::builder(dir.path()).open().unwrap();
        let ks = db.keyspace("a", KeyspaceCreateOptions::default).unwrap();
        assert_eq!(ks.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    }
}
