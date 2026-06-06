//! Vsock log forwarder — tees tracing output to both stderr and a vsock
//! connection on port 5700, where the parent's enclave-proxy prints it.
//!
//! Uses a bounded mpsc channel to decouple the synchronous `Write` impl
//! (called by tracing-subscriber) from the async vsock I/O. If the channel
//! fills up (proxy down for a while), log lines are silently dropped on
//! the vsock side — stderr output is always unaffected.

use std::io::Write;
use std::sync::Arc;

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

    tokio::spawn(vsock_drain_task(rx, initial_stream));

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

    TeeMakeWriter { tx: Arc::new(tx) }
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
async fn vsock_drain_task(
    mut rx: mpsc::Receiver<Vec<u8>>,
    initial_stream: Option<tokio_vsock::VsockStream>,
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

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(buf) => {
                        if AsyncWriteExt::write_all(&mut stream, &buf).await.is_err() {
                            // Connection lost — reconnect
                            stream = connect_with_backoff(&addr, &mut rx).await;
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
                    stream = connect_with_backoff(&addr, &mut rx).await;
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
// MakeWriter that tees to stderr + vsock channel
// ---------------------------------------------------------------------------

/// A `MakeWriter` that produces `TeeWriter` instances.
#[derive(Clone)]
pub struct TeeMakeWriter {
    tx: Arc<mpsc::Sender<Vec<u8>>>,
}

impl<'a> MakeWriter<'a> for TeeMakeWriter {
    type Writer = TeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter {
            stderr: std::io::stderr(),
            tx: self.tx.clone(),
            vsock_buf: Vec::with_capacity(256),
        }
    }
}

/// Writes each log line to both stderr (always) and the vsock channel
/// (best-effort). The vsock side buffers until `flush` is called or the
/// writer is dropped, then sends the complete line over the channel.
pub struct TeeWriter {
    stderr: std::io::Stderr,
    tx: Arc<mpsc::Sender<Vec<u8>>>,
    vsock_buf: Vec<u8>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Always write to stderr
        self.stderr.write_all(buf)?;
        // Buffer for vsock (will be sent on flush/drop)
        self.vsock_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stderr.flush()?;
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
