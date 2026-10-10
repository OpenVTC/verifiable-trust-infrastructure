//! Vsock log forwarder — sends tracing output over a vsock connection on
//! port 5700, where the parent's enclave-proxy prints it, with stderr (the
//! enclave console) as the fallback.
//!
//! A bounded mpsc channel decouples the synchronous `Write` impl (called by
//! tracing-subscriber) from the async vsock I/O.
//!
//! # Where a line goes
//!
//! - **Connected:** the channel only. Inside the enclave stderr is the
//!   console: a production enclave runs without `--debug-mode`, so nobody can
//!   read it, and each write is synchronous and serialised on the `Stderr`
//!   lock. Writing every line there capped request throughput (load tests:
//!   about 97 signs/s with the tee against at least 160 without the
//!   per-request lines).
//! - **Disconnected** (boot, reconnects): stderr *and* the channel. The
//!   channel is not drained while the connection is down, so the lines
//!   written during an outage — usually the ones that explain it — reach the
//!   parent once it reconnects, in order, after the line whose write failed.
//!
//! # What can be lost, exactly
//!
//! Memory is bounded by [`CHANNEL_CAPACITY`]. When the channel is full (a
//! burst faster than the parent drains, or an outage longer than the queue)
//! a line is not queued, and then:
//!
//! - it is **counted**: before the next line that does fit, the channel gets
//!   one `vsock-log: dropped N lines (queue full)` line, so the parent's log
//!   says where and how much is missing;
//! - a **WARN or ERROR** line is written to stderr instead, so it is never
//!   lost without a trace (the level comes from the event's metadata, not
//!   from parsing the text). INFO and below keep the fast path and are only
//!   counted.
//!
//! The one remaining loss is a line already handed to a write that then
//! fails twice in a row (on the old connection and on the new one).

use std::future::Future;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;

/// Vsock port for log forwarding (enclave → parent).
pub const VSOCK_LOG_PORT: u32 = 5700;

/// CID 3 = parent instance (Nitro vsock convention).
const PARENT_CID: u32 = 3;

/// Max buffered log lines; beyond this, lines are counted (and WARN/ERROR
/// go to stderr) — see the module docs.
const CHANNEL_CAPACITY: usize = 2048;

/// Max time to wait for the initial vsock connection before proceeding.
/// The background task will keep retrying if this times out.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// State shared by the writers and the drain task.
#[derive(Default)]
struct Shared {
    /// Whether the vsock forwarder is connected. Set by the drain task.
    connected: AtomicBool,
    /// Lines that did not fit in the channel since the last drop marker.
    dropped: AtomicU64,
}

/// Start the vsock log forwarder.
///
/// Attempts to connect to the parent's log receiver (vsock port 5700) with
/// a brief timeout. If the connection succeeds, early boot logs will be
/// forwarded immediately. If it times out, the background task retries
/// asynchronously — no boot delay beyond the timeout.
///
/// Also installs a panic hook that flushes buffered logs to the vsock
/// connection before aborting, so crash messages are visible on the parent.
pub async fn start() -> TeeMakeWriter {
    use tokio_vsock::{VsockAddr, VsockStream};

    let (tx, rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let shared = Arc::new(Shared::default());

    // Try to establish the initial connection synchronously (with timeout)
    // so early boot logs aren't lost.
    let addr = VsockAddr::new(PARENT_CID, VSOCK_LOG_PORT);
    eprintln!("[vsock-log] connecting to parent CID {PARENT_CID} port {VSOCK_LOG_PORT}...");
    let initial_stream =
        match tokio::time::timeout(CONNECT_TIMEOUT, VsockStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                eprintln!("[vsock-log] connected to parent vsock:{VSOCK_LOG_PORT}");
                Some(stream)
            }
            Ok(Err(e)) => {
                eprintln!(
                    "[vsock-log] failed to connect to parent vsock:{VSOCK_LOG_PORT}: {e} — \
                 will retry in background"
                );
                None
            }
            Err(_) => {
                eprintln!(
                    "[vsock-log] connection to parent vsock:{VSOCK_LOG_PORT} timed out after {}s — \
                 will retry in background",
                    CONNECT_TIMEOUT.as_secs()
                );
                None
            }
        };

    tokio::spawn(drain_task(
        rx,
        initial_stream,
        shared.clone(),
        move || VsockStream::connect(addr),
        HEARTBEAT_INTERVAL,
    ));

    // Install panic hook that flushes remaining logs before aborting.
    let panic_tx = tx.clone();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Format the panic message and send it through the vsock channel
        let msg = format!("[PANIC] {info}\n");
        let _ = panic_tx.try_send(msg.into_bytes());
        // Give the background task a moment to flush
        std::thread::sleep(std::time::Duration::from_millis(200));
        // Call the default hook (prints to stderr)
        default_hook(info);
    }));

    TeeMakeWriter {
        tx: Arc::new(tx),
        shared,
        console: stderr_console,
    }
}

fn stderr_console() -> Box<dyn Write + Send> {
    Box::new(std::io::stderr())
}

/// Heartbeat interval — sent over the vsock log channel when idle.
/// The parent's log receiver uses a timeout slightly longer than this
/// to detect dead connections.
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Heartbeat line — the proxy recognizes this and doesn't print it.
const HEARTBEAT_LINE: &[u8] = b"__heartbeat__\n";

/// Background task: drains the channel and writes to the stream. Sends
/// periodic heartbeats when idle so the proxy can detect dead connections.
/// Reconnects with backoff if the connection drops.
///
/// Generic over the stream and how to open it, so the policy is tested
/// without vsock. `shared.connected` is true while a connection is up; the
/// writer sends lines to stderr only while it is false.
async fn drain_task<S, C, F>(
    mut rx: mpsc::Receiver<Vec<u8>>,
    initial_stream: Option<S>,
    shared: Arc<Shared>,
    mut connect: C,
    heartbeat: std::time::Duration,
) where
    S: AsyncWrite + Unpin,
    C: FnMut() -> F,
    F: Future<Output = std::io::Result<S>>,
{
    let mut stream = match initial_stream {
        Some(s) => s,
        None => connect_with_backoff(&mut connect).await,
    };
    shared.connected.store(true, Ordering::SeqCst);

    loop {
        tokio::select! {
            msg = rx.recv() => {
                let Some(buf) = msg else { return }; // Channel closed — shutting down
                if stream.write_all(&buf).await.is_err() {
                    // Connection lost. The queue is left alone while we
                    // reconnect (stderr is the fallback meanwhile), so
                    // nothing written during the outage is thrown away.
                    shared.connected.store(false, Ordering::SeqCst);
                    stream = connect_with_backoff(&mut connect).await;
                    shared.connected.store(true, Ordering::SeqCst);
                    // This line first, then the queue, in order.
                    let _ = stream.write_all(&buf).await;
                }
            }
            _ = tokio::time::sleep(heartbeat) => {
                // No log data for a while — send heartbeat to keep connection alive
                // and let the proxy know we're still running.
                if stream.write_all(HEARTBEAT_LINE).await.is_err() {
                    shared.connected.store(false, Ordering::SeqCst);
                    stream = connect_with_backoff(&mut connect).await;
                    shared.connected.store(true, Ordering::SeqCst);
                }
            }
        }
    }
}

/// Connect with exponential backoff. Does not touch the queue: the channel
/// is bounded, so memory cannot grow, and what it holds is sent once the
/// connection is back.
async fn connect_with_backoff<S, C, F>(connect: &mut C) -> S
where
    C: FnMut() -> F,
    F: Future<Output = std::io::Result<S>>,
{
    let mut backoff_ms = 100u64;
    let mut attempts = 0u32;
    loop {
        match connect().await {
            Ok(s) => {
                eprintln!("[vsock-log] reconnected after {attempts} attempts");
                return s;
            }
            Err(e) => {
                attempts += 1;
                if attempts <= 3 || attempts.is_multiple_of(10) {
                    eprintln!(
                        "[vsock-log] connect attempt {attempts} failed: {e} (retry in {backoff_ms}ms)"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(5_000);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MakeWriter: vsock channel, with stderr as the fallback
// ---------------------------------------------------------------------------

/// A `MakeWriter` that produces `TeeWriter` instances.
#[derive(Clone)]
pub struct TeeMakeWriter {
    tx: Arc<mpsc::Sender<Vec<u8>>>,
    shared: Arc<Shared>,
    /// Opens the fallback console writer (stderr; a buffer in tests).
    console: fn() -> Box<dyn Write + Send>,
}

impl TeeMakeWriter {
    fn writer(&self, important: bool) -> TeeWriter {
        let console = (!self.shared.connected.load(Ordering::SeqCst)).then(self.console);
        TeeWriter {
            wrote_console: console.is_some(),
            console,
            open_console: self.console,
            important,
            tx: self.tx.clone(),
            shared: self.shared.clone(),
            vsock_buf: Vec::with_capacity(256),
        }
    }
}

impl<'a> MakeWriter<'a> for TeeMakeWriter {
    type Writer = TeeWriter;

    /// No metadata: treat the line as important, so the fallback errs
    /// towards keeping it.
    fn make_writer(&'a self) -> Self::Writer {
        self.writer(true)
    }

    /// The fmt layer calls this for every event: WARN and ERROR are the lines
    /// that must survive a full queue.
    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        self.writer(*meta.level() <= tracing::Level::WARN)
    }
}

/// Writes one log line to the vsock channel, and to stderr when the vsock
/// forwarder was disconnected as the line started. The vsock side buffers
/// until `flush` is called or the writer is dropped, then queues the
/// complete line — see the module docs for what happens when it cannot.
pub struct TeeWriter {
    console: Option<Box<dyn Write + Send>>,
    /// Whether this line has already gone to the console.
    wrote_console: bool,
    open_console: fn() -> Box<dyn Write + Send>,
    /// WARN or ERROR: written to stderr rather than dropped.
    important: bool,
    tx: Arc<mpsc::Sender<Vec<u8>>>,
    shared: Arc<Shared>,
    vsock_buf: Vec<u8>,
}

impl TeeWriter {
    /// Queue the buffered line, preceded by a drop marker if lines were lost
    /// since the last one. A line that does not fit is counted, and written
    /// to stderr if it is important and not already there.
    fn send(&mut self) {
        if self.vsock_buf.is_empty() {
            return;
        }
        let line = std::mem::take(&mut self.vsock_buf);

        let dropped = self.shared.dropped.swap(0, Ordering::SeqCst);
        if dropped > 0 {
            let marker = format!("vsock-log: dropped {dropped} lines (queue full)\n");
            if self.tx.try_send(marker.into_bytes()).is_err() {
                // Still no room: keep the count for the next attempt, and
                // this line joins it below.
                self.shared.dropped.fetch_add(dropped, Ordering::SeqCst);
                self.lost(line);
                return;
            }
        }
        if let Err(e) = self.tx.try_send(line) {
            let line = match e {
                mpsc::error::TrySendError::Full(l) | mpsc::error::TrySendError::Closed(l) => l,
            };
            self.lost(line);
        }
    }

    /// The line did not fit in the channel.
    fn lost(&mut self, line: Vec<u8>) {
        self.shared.dropped.fetch_add(1, Ordering::SeqCst);
        if self.important && !self.wrote_console {
            let mut console = (self.open_console)();
            let _ = console.write_all(&line);
            let _ = console.flush();
            self.wrote_console = true;
        }
    }
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(console) = self.console.as_mut() {
            console.write_all(buf)?;
        }
        // Buffer for vsock (queued on flush/drop)
        self.vsock_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(console) = self.console.as_mut() {
            console.flush()?;
        }
        self.send();
        Ok(())
    }
}

impl Drop for TeeWriter {
    fn drop(&mut self) {
        self.send();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::*;

    /// Console output captured by `test_console`, shared across the tests in
    /// this module (they run in one process), so each test uses a distinct
    /// marker and looks only for its own.
    static CONSOLE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    struct TestConsole;

    impl Write for TestConsole {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            CONSOLE.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_console() -> Box<dyn Write + Send> {
        Box::new(TestConsole)
    }

    fn console_has(marker: &[u8]) -> bool {
        CONSOLE
            .lock()
            .unwrap()
            .windows(marker.len())
            .any(|w| w == marker)
    }

    fn make_writer_cap(
        connected: bool,
        capacity: usize,
    ) -> (TeeMakeWriter, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity);
        let shared = Arc::new(Shared::default());
        shared.connected.store(connected, Ordering::SeqCst);
        let make = TeeMakeWriter {
            tx: Arc::new(tx),
            shared,
            console: test_console,
        };
        (make, rx)
    }

    fn make_writer(connected: bool) -> (TeeMakeWriter, mpsc::Receiver<Vec<u8>>) {
        make_writer_cap(connected, 8)
    }

    fn line(make: &TeeMakeWriter, important: bool, text: &[u8]) {
        let mut w = make.writer(important);
        w.write_all(text).unwrap();
        w.flush().unwrap();
    }

    #[test]
    fn test_connected_line_skips_console() {
        let (make, mut rx) = make_writer(true);
        let mut w = make.make_writer();
        w.write_all(b"connected-line\n").unwrap();
        w.flush().unwrap();
        assert_eq!(rx.try_recv().unwrap(), b"connected-line\n");
        assert!(!console_has(b"connected-line"), "console must stay quiet");
    }

    #[test]
    fn test_disconnected_line_goes_to_console_and_channel() {
        let (make, mut rx) = make_writer(false);
        let mut w = make.make_writer();
        w.write_all(b"fallback-line\n").unwrap();
        w.flush().unwrap();
        assert!(console_has(b"fallback-line"), "console is the fallback");
        assert_eq!(rx.try_recv().unwrap(), b"fallback-line\n");
    }

    #[test]
    fn test_reconnect_stops_console_output() {
        let (make, mut rx) = make_writer(false);
        make.make_writer().write_all(b"before-reconnect\n").unwrap();
        make.shared.connected.store(true, Ordering::SeqCst);
        make.make_writer().write_all(b"after-reconnect\n").unwrap();
        assert!(console_has(b"before-reconnect"));
        assert!(!console_has(b"after-reconnect"));
        assert_eq!(rx.try_recv().unwrap(), b"before-reconnect\n");
        assert_eq!(rx.try_recv().unwrap(), b"after-reconnect\n");
    }

    /// Finding 5 of the #1951 review: a full channel used to drop lines with
    /// no trace. Now they are counted, and the count reaches the parent ahead
    /// of the next line that fits.
    #[test]
    fn test_full_channel_counts_drops_and_emits_a_marker() {
        let (make, mut rx) = make_writer_cap(true, 2);
        line(&make, false, b"fill-1\n");
        line(&make, false, b"fill-2\n");
        line(&make, false, b"info-dropped-a\n");
        line(&make, false, b"info-dropped-b\n");
        assert_eq!(make.shared.dropped.load(Ordering::SeqCst), 2);
        assert!(!console_has(b"info-dropped"), "INFO stays on the fast path");

        // Room again: the marker goes first, then the line.
        assert_eq!(rx.try_recv().unwrap(), b"fill-1\n");
        assert_eq!(rx.try_recv().unwrap(), b"fill-2\n");
        line(&make, false, b"after-room\n");
        assert_eq!(
            rx.try_recv().unwrap(),
            b"vsock-log: dropped 2 lines (queue full)\n"
        );
        assert_eq!(rx.try_recv().unwrap(), b"after-room\n");
        assert_eq!(make.shared.dropped.load(Ordering::SeqCst), 0);
    }

    /// A marker that itself does not fit keeps the count, and the line that
    /// failed with it is added to it.
    #[test]
    fn test_marker_that_does_not_fit_keeps_the_count() {
        let (make, mut rx) = make_writer_cap(true, 1);
        line(&make, false, b"only-slot\n");
        line(&make, false, b"lost-1\n");
        line(&make, false, b"lost-2\n");
        assert_eq!(make.shared.dropped.load(Ordering::SeqCst), 2);
        assert_eq!(rx.try_recv().unwrap(), b"only-slot\n");
        line(&make, false, b"next\n");
        // One slot: the marker fits, the line does not, so it is counted.
        assert_eq!(
            rx.try_recv().unwrap(),
            b"vsock-log: dropped 2 lines (queue full)\n"
        );
        assert_eq!(make.shared.dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_full_channel_sends_warn_and_error_to_stderr() {
        let (make, _rx) = make_writer_cap(true, 1);
        line(&make, false, b"slot-taken\n");
        line(&make, true, b"warn-must-survive\n");
        assert!(console_has(b"warn-must-survive"));
        assert_eq!(
            make.shared.dropped.load(Ordering::SeqCst),
            1,
            "still counted"
        );
    }

    #[test]
    fn test_important_line_already_on_console_is_not_written_twice() {
        let (make, _rx) = make_writer_cap(false, 1);
        line(&make, false, b"slot-taken-2\n");
        line(&make, true, b"once-only-err\n");
        let n = CONSOLE
            .lock()
            .unwrap()
            .windows(b"once-only-err".len())
            .filter(|w| *w == b"once-only-err")
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn test_level_comes_from_metadata() {
        let (make, _rx) = make_writer(true);
        let warn = tracing::metadata::Metadata::new(
            "w",
            "t",
            tracing::Level::WARN,
            None,
            None,
            None,
            tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&CALLSITE)),
            tracing::metadata::Kind::EVENT,
        );
        let info = tracing::metadata::Metadata::new(
            "i",
            "t",
            tracing::Level::INFO,
            None,
            None,
            None,
            tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&CALLSITE)),
            tracing::metadata::Kind::EVENT,
        );
        assert!(make.make_writer_for(&warn).important);
        assert!(!make.make_writer_for(&info).important);
    }

    struct TestCallsite;
    static CALLSITE: TestCallsite = TestCallsite;
    impl tracing::callsite::Callsite for TestCallsite {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            unimplemented!()
        }
    }

    // ── drain task ──────────────────────────────────────────────────────

    /// A stream whose writes land in a shared buffer, or fail once `broken`.
    #[derive(Clone)]
    struct FakeStream {
        out: Arc<Mutex<Vec<u8>>>,
        broken: Arc<AtomicBool>,
    }

    impl AsyncWrite for FakeStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.broken.load(Ordering::SeqCst) {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            self.out.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Finding 4 of the #1951 review: lines queued while the connection was
    /// down were drained and dropped during the backoff. They now reach the
    /// parent after the reconnect, in order.
    #[tokio::test]
    async fn test_outage_keeps_queued_lines_and_replays_them_in_order() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let shared = Arc::new(Shared::default());

        let first = FakeStream {
            out: Arc::new(Mutex::new(Vec::new())),
            broken: Arc::new(AtomicBool::new(true)), // fails on first write
        };
        let second_out = Arc::new(Mutex::new(Vec::new()));
        // Two failed attempts, then a working connection.
        let attempts: Arc<Mutex<VecDeque<std::io::Result<FakeStream>>>> =
            Arc::new(Mutex::new(VecDeque::from([
                Err(std::io::ErrorKind::ConnectionRefused.into()),
                Err(std::io::ErrorKind::ConnectionRefused.into()),
                Ok(FakeStream {
                    out: second_out.clone(),
                    broken: Arc::new(AtomicBool::new(false)),
                }),
            ])));
        let connect = {
            let attempts = attempts.clone();
            move || {
                let next = attempts
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("connect called too often");
                async move { next }
            }
        };

        let task = tokio::spawn(drain_task(
            rx,
            Some(first),
            shared.clone(),
            connect,
            Duration::from_secs(3600),
        ));

        // The first line hits the broken stream; the rest queue up during
        // the outage.
        tx.send(b"line-1\n".to_vec()).await.unwrap();
        tokio::task::yield_now().await;
        tx.send(b"line-2\n".to_vec()).await.unwrap();
        tx.send(b"line-3\n".to_vec()).await.unwrap();

        // Backoff is 100 ms then 200 ms before the third attempt succeeds.
        let want = "line-1\nline-2\nline-3\n";
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while String::from_utf8(second_out.lock().unwrap().clone()).unwrap() != want {
            assert!(tokio::time::Instant::now() < deadline, "lines not replayed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(tx);
        task.await.unwrap();

        assert_eq!(
            String::from_utf8(second_out.lock().unwrap().clone()).unwrap(),
            "line-1\nline-2\nline-3\n"
        );
        assert!(shared.connected.load(Ordering::SeqCst));
    }
}
