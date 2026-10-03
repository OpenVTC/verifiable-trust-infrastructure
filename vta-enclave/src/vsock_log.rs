//! Vsock log forwarder — tees tracing output to both stderr and a vsock
//! connection on port 5700, where the parent's enclave-proxy prints it.
//!
//! Uses a bounded mpsc channel to decouple the synchronous `Write` impl
//! (called by tracing-subscriber) from the async vsock I/O. If the channel
//! fills up (proxy down for a while), log lines are silently dropped on
//! the vsock side.
//!
//! Lines go to stderr only while the vsock connection is down (boot,
//! reconnects). Inside the enclave stderr is the console: a production
//! enclave runs without `--debug-mode`, so nobody can read it, and each
//! write is synchronous and serialised on the `Stderr` lock. Writing every
//! line there capped request throughput (load tests: about 97 signs/s with
//! the tee against at least 160 without the per-request lines).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;

/// Vsock port for log forwarding (enclave → parent).
pub const VSOCK_LOG_PORT: u32 = 5700;

/// CID 3 = parent instance (Nitro vsock convention).
const PARENT_CID: u32 = 3;

/// Max buffered log lines before dropping on the vsock side.
const CHANNEL_CAPACITY: usize = 2048;

/// Max time to wait for the initial vsock connection before proceeding.
/// The background task will keep retrying if this times out.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
    let connected = Arc::new(AtomicBool::new(false));

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

    tokio::spawn(vsock_drain_task(rx, initial_stream, connected.clone()));

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
        connected,
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

/// Background task: drains the channel and writes to the vsock stream.
/// Sends periodic heartbeats when idle so the proxy can detect dead connections.
/// Reconnects with backoff if the connection drops.
///
/// `connected` is true while a connection is up; the writer sends lines to
/// stderr only while it is false.
async fn vsock_drain_task(
    mut rx: mpsc::Receiver<Vec<u8>>,
    initial_stream: Option<tokio_vsock::VsockStream>,
    connected: Arc<AtomicBool>,
) {
    use tokio::io::AsyncWriteExt;
    use tokio_vsock::VsockAddr;

    let addr = VsockAddr::new(PARENT_CID, VSOCK_LOG_PORT);

    // Use the pre-established connection if available
    let mut stream = if let Some(s) = initial_stream {
        s
    } else {
        connect_with_backoff(&addr, &mut rx).await
    };
    connected.store(true, Ordering::SeqCst);

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(buf) => {
                        if AsyncWriteExt::write_all(&mut stream, &buf).await.is_err() {
                            // Connection lost — reconnect, with stderr as the
                            // fallback meanwhile.
                            connected.store(false, Ordering::SeqCst);
                            stream = connect_with_backoff(&addr, &mut rx).await;
                            connected.store(true, Ordering::SeqCst);
                            // Retry writing this buffer on the new connection
                            let _ = AsyncWriteExt::write_all(&mut stream, &buf).await;
                        }
                    }
                    None => return, // Channel closed — VTA shutting down
                }
            }
            _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                // No log data for a while — send heartbeat to keep connection alive
                // and let the proxy know we're still running.
                if AsyncWriteExt::write_all(&mut stream, HEARTBEAT_LINE).await.is_err() {
                    connected.store(false, Ordering::SeqCst);
                    stream = connect_with_backoff(&addr, &mut rx).await;
                    connected.store(true, Ordering::SeqCst);
                }
            }
        }
    }
}

/// Connect to the parent with exponential backoff.
/// Drains queued messages during retries to prevent unbounded buffering.
async fn connect_with_backoff(
    addr: &tokio_vsock::VsockAddr,
    rx: &mut mpsc::Receiver<Vec<u8>>,
) -> tokio_vsock::VsockStream {
    let mut backoff_ms = 100u64;
    let mut attempts = 0u32;
    loop {
        match tokio_vsock::VsockStream::connect(*addr).await {
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
                // Drain queued messages to avoid memory growth
                while rx.try_recv().is_ok() {}
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
    /// Whether the vsock forwarder is connected. Set by the drain task.
    connected: Arc<AtomicBool>,
    /// Opens the fallback console writer (stderr; a buffer in tests).
    console: fn() -> Box<dyn Write + Send>,
}

impl<'a> MakeWriter<'a> for TeeMakeWriter {
    type Writer = TeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter {
            console: (!self.connected.load(Ordering::SeqCst)).then(self.console),
            tx: self.tx.clone(),
            vsock_buf: Vec::with_capacity(256),
        }
    }
}

/// Writes each log line to the vsock channel (best-effort), and to stderr
/// only when the vsock forwarder was disconnected as the line started. The
/// vsock side buffers until `flush` is called or the writer is dropped, then
/// sends the complete line over the channel.
pub struct TeeWriter {
    console: Option<Box<dyn Write + Send>>,
    tx: Arc<mpsc::Sender<Vec<u8>>>,
    vsock_buf: Vec<u8>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(console) = self.console.as_mut() {
            console.write_all(buf)?;
        }
        // Buffer for vsock (will be sent on flush/drop)
        self.vsock_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(console) = self.console.as_mut() {
            console.flush()?;
        }
        if !self.vsock_buf.is_empty() {
            // Best-effort send — if channel is full, drop silently
            let _ = self.tx.try_send(std::mem::take(&mut self.vsock_buf));
        }
        Ok(())
    }
}

impl Drop for TeeWriter {
    fn drop(&mut self) {
        // Flush any remaining buffered data on drop
        if !self.vsock_buf.is_empty() {
            let _ = self.tx.try_send(std::mem::take(&mut self.vsock_buf));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

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

    fn make_writer(connected: bool) -> (TeeMakeWriter, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(8);
        let make = TeeMakeWriter {
            tx: Arc::new(tx),
            connected: Arc::new(AtomicBool::new(connected)),
            console: test_console,
        };
        (make, rx)
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
        make.connected.store(true, Ordering::SeqCst);
        make.make_writer().write_all(b"after-reconnect\n").unwrap();
        assert!(console_has(b"before-reconnect"));
        assert!(!console_has(b"after-reconnect"));
        assert_eq!(rx.try_recv().unwrap(), b"before-reconnect\n");
        assert_eq!(rx.try_recv().unwrap(), b"after-reconnect\n");
    }
}
