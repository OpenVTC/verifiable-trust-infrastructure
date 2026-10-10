//! Connection pool for the enclave's storage client.
//!
//! The enclave reaches its store through the parent's storage proxy, one
//! framed request and response at a time per connection. A single shared
//! connection makes every storage operation in the process wait for the one
//! before it, so throughput is capped by the round-trip time whatever the
//! enclave's vCPU count. The pool lets independent operations run on separate
//! connections; the proxy already serves each connection in its own task.
//!
//! A connection is owned by exactly one request for the whole round trip and
//! goes back to the pool only after a complete response. A request that fails
//! or is cancelled part-way (its future dropped, for example by a request
//! timeout) drops its connection instead: a half-read connection would hand the
//! next caller the previous caller's response.
//!
//! The pool does not make multi-step operations atomic, and never did: the old
//! single-connection lock was released between the steps of `swap`,
//! `take_raw` and `move_if_unchanged` too. `super::key_locks` does that,
//! independently of how many connections there are.
//!
//! Transport-agnostic so the pool is testable off Linux; the vsock store
//! supplies the connector.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{trace, warn};

use crate::error::AppError;

/// Largest response frame accepted from the parent. Bounds what a misbehaving
/// parent can make the enclave allocate.
pub(crate) const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Largest request coalesced with its length prefix into one write. Storage
/// requests are almost all far below this; the rare large value (a backup
/// bundle chunk) is not copied.
const COALESCE_MAX: usize = 64 * 1024;

/// Deadline for one request and its response. The parent answers a storage
/// request in tens of microseconds; one that has not answered in this long is
/// wedged, and waiting longer only holds a pool permit — and, for a multi-step
/// operation, its key lock (`super::key_locks`) — for nothing. On expiry the
/// connection is dropped, never reused: its next bytes could be this answer.
pub(crate) const ROUND_TRIP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A bidirectional byte stream a storage connection runs over.
pub(crate) trait FrameStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> FrameStream for T {}

pub(crate) type BoxStream = Box<dyn FrameStream>;
type ConnectFuture = Pin<Box<dyn Future<Output = Result<BoxStream, AppError>> + Send>>;

/// Opens a new connection to the storage proxy.
pub(crate) type Connector = Arc<dyn Fn() -> ConnectFuture + Send + Sync>;

/// Bounded pool of storage connections.
pub(crate) struct ConnectionPool {
    connect: Connector,
    /// Connections not currently in use. Only touched for a push or pop, never
    /// across an await, so a std mutex is the right lock.
    idle: Mutex<Vec<BoxStream>>,
    /// One permit per connection that may exist; held for a whole round trip.
    permits: Semaphore,
    /// Per-round-trip deadline; [`ROUND_TRIP_TIMEOUT`] outside tests.
    timeout: std::time::Duration,
}

impl ConnectionPool {
    /// Create a pool allowing up to `max_connections` simultaneous connections,
    /// seeded with an already-open connection.
    pub(crate) fn new(connect: Connector, max_connections: usize, first: BoxStream) -> Self {
        Self {
            connect,
            idle: Mutex::new(vec![first]),
            permits: Semaphore::new(max_connections.max(1)),
            timeout: ROUND_TRIP_TIMEOUT,
        }
    }

    /// A shorter deadline, so a test can watch one expire.
    #[cfg(test)]
    pub(crate) fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send one **idempotent** request frame (get, insert, delete, scans,
    /// persist, HELLO) and return the response frame.
    ///
    /// Waits for a free connection slot, reuses a live idle connection if
    /// there is one, and resends once on a fresh connection if that fails at
    /// any point. Resending is harmless only because applying these twice is
    /// the same as applying them once; anything else goes through
    /// [`Self::request_once`].
    pub(crate) async fn request(&self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        self.request_tracked(payload, &AtomicBool::new(false)).await
    }

    /// [`Self::request`], setting `ever_sent` once any attempt's frame has
    /// been completely written — from then on the parent may have applied
    /// it, even if this future is dropped before the reply (which no error
    /// can report). A caller that tracks writes (`generation::WriteGuard`)
    /// reads it to tell a write that never left the enclave from one whose
    /// outcome is unknown.
    pub(crate) async fn request_tracked(
        &self,
        payload: &[u8],
        ever_sent: &AtomicBool,
    ) -> Result<Vec<u8>, AppError> {
        let _permit = self.permit().await?;

        if let Some(mut stream) = self.take_live_idle() {
            match round_trip_within(&mut stream, payload, self.timeout, ever_sent).await {
                Ok(resp) => {
                    self.put_idle(stream);
                    return Ok(resp);
                }
                Err(e) => warn!(error = %e.error(), "storage request failed, reconnecting"),
            }
        }

        let mut stream = (self.connect)().await?;
        trace!("storage connection opened");
        let resp = round_trip_within(&mut stream, payload, self.timeout, ever_sent)
            .await
            .map_err(RoundTripError::into_error)?;
        self.put_idle(stream);
        Ok(resp)
    }

    /// Send one **non-idempotent** request frame (take, insert-if-absent,
    /// swap, compare-and-move) and return the response frame.
    ///
    /// It is resent only if it failed before its frame was completely
    /// written: the proxy reads a whole frame before acting, so a partial one
    /// cannot have been applied. Once the frame is fully written, a failure is
    /// [`OnceError::OutcomeUnknown`] and is never resent — a resent take would
    /// find the row it had just deleted gone and refuse a legitimate claim, and
    /// a resent move would report the target it had just written as occupied.
    ///
    /// A connection the parent closed while idle would otherwise make that
    /// error routine (the write lands in a dead socket, the read gets EOF), so
    /// idle connections are checked first; see [`is_stale`].
    ///
    /// The store sends through [`Self::request_once_tracked`]; this
    /// untracked form is for tests.
    #[cfg(test)]
    pub(crate) async fn request_once(&self, payload: &[u8]) -> Result<Vec<u8>, OnceError> {
        self.request_once_tracked(payload, &AtomicBool::new(false))
            .await
    }

    /// [`Self::request_once`], setting `ever_sent` as
    /// [`Self::request_tracked`] does.
    pub(crate) async fn request_once_tracked(
        &self,
        payload: &[u8],
        ever_sent: &AtomicBool,
    ) -> Result<Vec<u8>, OnceError> {
        let _permit = self.permit().await.map_err(OnceError::NotSent)?;

        if let Some(mut stream) = self.take_live_idle() {
            match round_trip_within(&mut stream, payload, self.timeout, ever_sent).await {
                Ok(resp) => {
                    self.put_idle(stream);
                    return Ok(resp);
                }
                Err(RoundTripError::Unsent(e)) => {
                    warn!(error = %e, "storage request not sent, retrying on a new connection");
                }
                Err(RoundTripError::Sent(e)) => return Err(OnceError::OutcomeUnknown(e)),
            }
        }

        let mut stream = (self.connect)().await.map_err(OnceError::NotSent)?;
        trace!("storage connection opened");
        match round_trip_within(&mut stream, payload, self.timeout, ever_sent).await {
            Ok(resp) => {
                self.put_idle(stream);
                Ok(resp)
            }
            Err(RoundTripError::Unsent(e)) => Err(OnceError::NotSent(e)),
            Err(RoundTripError::Sent(e)) => Err(OnceError::OutcomeUnknown(e)),
        }
    }

    async fn permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, AppError> {
        self.permits
            .acquire()
            .await
            .map_err(|_| AppError::Internal("storage connection pool closed".into()))
    }

    /// An idle connection the parent has not closed, discarding any it has.
    fn take_live_idle(&self) -> Option<BoxStream> {
        loop {
            let mut stream = self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()?;
            if is_stale(&mut stream) {
                trace!("discarding a storage connection the parent closed");
                continue;
            }
            return Some(stream);
        }
    }

    fn put_idle(&self, stream: BoxStream) {
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(stream);
    }

    #[cfg(test)]
    fn idle_len(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Why a [`ConnectionPool::request_once`] failed.
#[derive(Debug)]
pub(crate) enum OnceError {
    /// The request frame never completely left the enclave, so it cannot have
    /// been applied.
    NotSent(AppError),
    /// The frame was fully written and then the exchange failed: the proxy
    /// may or may not have applied it. Never resent, never "fallen back" from
    /// (a fallback could apply it a second time).
    OutcomeUnknown(AppError),
}

impl From<OnceError> for AppError {
    fn from(e: OnceError) -> Self {
        match e {
            OnceError::NotSent(e) => e,
            OnceError::OutcomeUnknown(e) => {
                AppError::Internal(format!("storage operation outcome unknown: {e}"))
            }
        }
    }
}

/// Where a round trip failed.
enum RoundTripError {
    /// Before the request frame was completely written.
    Unsent(AppError),
    /// After it was: the proxy may have acted on it.
    Sent(AppError),
}

impl RoundTripError {
    fn error(&self) -> &AppError {
        match self {
            Self::Unsent(e) | Self::Sent(e) => e,
        }
    }

    fn into_error(self) -> AppError {
        match self {
            Self::Unsent(e) | Self::Sent(e) => e,
        }
    }
}

/// Whether an idle connection is unusable: the parent closed it (EOF), it
/// errored, or it holds bytes nobody asked for.
///
/// One non-blocking poll of the read side with a no-op waker. An idle
/// connection owes us nothing, so on a live one the poll is `Pending`;
/// `Ready` means EOF, an error, or unsolicited bytes, all of which make it
/// unfit to carry a request. This catches the common case — the proxy
/// restarted or dropped the connection while it sat idle — before any byte is
/// written, so a non-idempotent request never has to report "outcome unknown"
/// merely because its connection was already dead. It cannot catch a close
/// that lands after the check; that case is reported as outcome unknown, which
/// is the safe direction. Registering a no-op waker is harmless: the next
/// real read replaces it.
fn is_stale(stream: &mut BoxStream) -> bool {
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut byte = [0u8; 1];
    let mut buf = tokio::io::ReadBuf::new(&mut byte);
    !matches!(
        Pin::new(&mut **stream).poll_read(&mut cx, &mut buf),
        Poll::Pending
    )
}

/// Write one length-prefixed request frame and read one response frame.
#[cfg(test)]
async fn round_trip(stream: &mut BoxStream, payload: &[u8]) -> Result<Vec<u8>, RoundTripError> {
    round_trip_within(stream, payload, ROUND_TRIP_TIMEOUT, &AtomicBool::new(false)).await
}

/// [`round_trip_inner`] under a deadline. A deadline that expires after the
/// frame was completely written is [`RoundTripError::Sent`] — the proxy may be
/// applying it right now — and before that, [`RoundTripError::Unsent`]: a
/// partial frame is never acted on. Either way the caller drops the
/// connection.
///
/// `ever_sent` is the caller's: set (never cleared) at the same moment as
/// this attempt's `sent`, so it also survives the caller's future being
/// dropped mid-round-trip, where no error is returned to say so.
async fn round_trip_within(
    stream: &mut BoxStream,
    payload: &[u8],
    timeout: std::time::Duration,
    ever_sent: &AtomicBool,
) -> Result<Vec<u8>, RoundTripError> {
    let mut sent = false;
    let result = tokio::time::timeout(
        timeout,
        round_trip_inner(stream, payload, &mut sent, ever_sent),
    )
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let e = AppError::Internal(format!("storage request timed out after {timeout:?}"));
            Err(if sent {
                RoundTripError::Sent(e)
            } else {
                RoundTripError::Unsent(e)
            })
        }
    }
}

/// `*sent` (and `ever_sent`) become `true` once every byte of the request
/// frame is written.
async fn round_trip_inner(
    stream: &mut BoxStream,
    payload: &[u8],
    sent: &mut bool,
    ever_sent: &AtomicBool,
) -> Result<Vec<u8>, RoundTripError> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        RoundTripError::Unsent(AppError::Internal("storage request too large".into()))
    })?;
    let unsent = |e| RoundTripError::Unsent(AppError::vsock("vsock write")(e));
    // On an unbuffered vsock stream every write is its own packet across the
    // enclave boundary, so a small frame goes out as one write. Above
    // `COALESCE_MAX` the frame spans many packets whatever we do, and copying
    // it just to save the header's packet costs more than it saves.
    //
    // A failed `write_all` means the frame did not completely leave: the
    // proxy reads a whole frame before acting, so it cannot have been applied.
    if payload.len() <= COALESCE_MAX {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await.map_err(unsent)?;
    } else {
        stream.write_all(&len.to_be_bytes()).await.map_err(unsent)?;
        stream.write_all(payload).await.map_err(unsent)?;
    }
    // From here on every byte of the frame has been handed over, so any
    // failure — or the deadline — leaves the outcome unknown.
    *sent = true;
    ever_sent.store(true, Ordering::SeqCst);
    let sent = |op| move |e| RoundTripError::Sent(AppError::vsock(op)(e));
    stream.flush().await.map_err(sent("vsock flush"))?;

    let len = stream.read_u32().await.map_err(sent("vsock read"))?;
    if len > MAX_MESSAGE_SIZE {
        return Err(RoundTripError::Sent(AppError::Internal(format!(
            "vsock response too large: {len} > {MAX_MESSAGE_SIZE}"
        ))));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(sent("vsock read"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::DuplexStream;
    use tokio::sync::Notify;

    use super::*;

    /// How the mock storage proxy treats each request.
    #[derive(Clone, Default)]
    struct Server {
        /// Requests currently being served, across all connections.
        in_flight: Arc<AtomicUsize>,
        /// Highest value `in_flight` reached.
        peak: Arc<AtomicUsize>,
        /// Connections opened.
        connects: Arc<AtomicUsize>,
        /// When set, hold every response until notified.
        gate: Option<Arc<Notify>>,
        /// When set, close the first connection without answering.
        drop_first: bool,
        /// When set, the first connection reads one whole frame and then
        /// hangs up without answering it.
        hangup_after_first_frame: bool,
        /// Complete request frames received, across all connections.
        frames: Arc<AtomicUsize>,
    }

    impl Server {
        /// A pool whose connector opens in-memory connections to this server.
        fn pool(&self, max: usize) -> ConnectionPool {
            let server = self.clone();
            let connect: Connector = Arc::new(move || {
                let server = server.clone();
                Box::pin(async move { Ok(server.open()) })
            });
            let first = self.open();
            ConnectionPool::new(connect, max, first)
        }

        fn open(&self) -> BoxStream {
            let n = self.connects.fetch_add(1, Ordering::SeqCst);
            let (client, server_end) = tokio::io::duplex(64 * 1024);
            let server = self.clone();
            tokio::spawn(async move {
                if server.drop_first && n == 0 {
                    drop(server_end);
                    return;
                }
                let hang_up = server.hangup_after_first_frame && n == 0;
                server.serve(server_end, hang_up).await;
            });
            Box::new(client)
        }

        /// Echo every request frame back as its response.
        async fn serve(self, mut stream: DuplexStream, hang_up: bool) {
            while let Ok(len) = stream.read_u32().await {
                let mut buf = vec![0u8; len as usize];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                self.frames.fetch_add(1, Ordering::SeqCst);
                if hang_up {
                    return;
                }
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                if let Some(gate) = &self.gate {
                    gate.notified().await;
                }
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                if stream.write_u32(len).await.is_err() || stream.write_all(&buf).await.is_err() {
                    return;
                }
            }
        }
    }

    /// Wait until `cond` holds, or fail the test after a second.
    async fn eventually(cond: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cond() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition not reached within 1s");
    }

    #[tokio::test]
    async fn test_request_returns_response() {
        let pool = Server::default().pool(4);
        let resp = pool.request(b"ping").await.expect("request");
        assert_eq!(resp, b"ping");
        assert_eq!(pool.idle_len(), 1, "connection goes back to the pool");
    }

    #[tokio::test]
    async fn test_requests_run_concurrently() {
        // Every response waits until all four requests are at the server at
        // once. A single shared connection never gets there.
        let gate = Arc::new(Notify::new());
        let server = Server {
            gate: Some(gate.clone()),
            ..Server::default()
        };
        let pool = Arc::new(server.pool(4));
        let tasks: Vec<_> = (0..4u8)
            .map(|i| {
                let pool = pool.clone();
                tokio::spawn(async move { pool.request(&[i]).await })
            })
            .collect();

        let in_flight = server.in_flight.clone();
        eventually(|| in_flight.load(Ordering::SeqCst) == 4).await;
        while !tasks.iter().all(|t| t.is_finished()) {
            gate.notify_waiters();
            tokio::task::yield_now().await;
        }

        for (i, task) in tasks.into_iter().enumerate() {
            let resp = task.await.expect("join").expect("request");
            assert_eq!(resp, vec![i as u8], "each caller gets its own response");
        }
        assert_eq!(server.peak.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_connections_capped_at_max() {
        let gate = Arc::new(Notify::new());
        let server = Server {
            gate: Some(gate.clone()),
            ..Server::default()
        };
        let pool = Arc::new(server.pool(2));
        let tasks: Vec<_> = (0..6u8)
            .map(|i| {
                let pool = pool.clone();
                tokio::spawn(async move { pool.request(&[i]).await })
            })
            .collect();

        let in_flight = server.in_flight.clone();
        eventually(|| in_flight.load(Ordering::SeqCst) == 2).await;
        // Release in rounds until every request has been answered.
        let done = || tasks.iter().all(|t| t.is_finished());
        while !done() {
            gate.notify_waiters();
            tokio::task::yield_now().await;
        }
        for task in tasks {
            task.await.expect("join").expect("request");
        }
        assert_eq!(server.peak.load(Ordering::SeqCst), 2);
        assert!(server.connects.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test]
    async fn test_cancelled_request_discards_connection() {
        // The first request is abandoned while the server still owes it a
        // response. Reusing that connection would hand the next caller the
        // stale response.
        let gate = Arc::new(Notify::new());
        let server = Server {
            gate: Some(gate.clone()),
            ..Server::default()
        };
        let pool = server.pool(4);

        let abandoned =
            tokio::time::timeout(Duration::from_millis(20), pool.request(b"first")).await;
        assert!(abandoned.is_err(), "first request should time out");
        assert_eq!(pool.idle_len(), 0, "a cancelled request returns nothing");

        let next = pool.request(b"second");
        tokio::pin!(next);
        let in_flight = server.in_flight.clone();
        // Release the old connection's late response and the new request's.
        let resp = loop {
            tokio::select! {
                r = &mut next => break r.expect("request"),
                _ = tokio::task::yield_now() => {
                    if in_flight.load(Ordering::SeqCst) > 0 {
                        gate.notify_waiters();
                    }
                }
            }
        };
        assert_eq!(resp, b"second");
        assert_eq!(server.connects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_broken_connection_reconnects() {
        let server = Server {
            drop_first: true,
            ..Server::default()
        };
        let pool = server.pool(4);
        let resp = pool.request(b"retry").await.expect("request");
        assert_eq!(resp, b"retry");
        assert_eq!(server.connects.load(Ordering::SeqCst), 2);
        assert_eq!(pool.idle_len(), 1, "only the working connection is kept");
    }

    #[tokio::test]
    async fn test_large_request_round_trips_without_coalescing() {
        // Above COALESCE_MAX the header and payload go as two writes; the
        // echo server must still see one well-formed frame.
        let pool = Server::default().pool(1);
        let big = vec![0xA5u8; COALESCE_MAX + 1];
        let resp = pool.request(&big).await.expect("request");
        assert_eq!(resp, big);
    }

    #[tokio::test]
    async fn test_unanswered_request_times_out_and_frees_its_permit() {
        // A parent that takes the frame and never answers: the request fails
        // at the deadline instead of hanging, and the permit and the
        // connection are released, so the pool is not wedged.
        let gate = Arc::new(Notify::new());
        let server = Server {
            gate: Some(gate.clone()),
            ..Server::default()
        };
        let pool = server.pool(1).with_timeout(Duration::from_millis(100));
        let started = std::time::Instant::now();
        let err = pool.request(b"x").await.expect_err("times out");
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(pool.idle_len(), 0, "a timed-out connection is never reused");
        // The single permit is free again: the next request gets a fresh
        // connection (and also times out, the gate is still closed).
        tokio::time::timeout(Duration::from_secs(2), pool.request(b"y"))
            .await
            .expect("permit was released")
            .expect_err("still unanswered");
    }

    #[tokio::test]
    async fn test_oversized_response_rejected() {
        let (client, mut server_end) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let len = server_end.read_u32().await.expect("read");
            let mut buf = vec![0u8; len as usize];
            server_end.read_exact(&mut buf).await.expect("read");
            server_end
                .write_u32(MAX_MESSAGE_SIZE + 1)
                .await
                .expect("write");
        });
        let mut stream: BoxStream = Box::new(client);
        match round_trip(&mut stream, b"big").await {
            Err(RoundTripError::Sent(AppError::Internal(msg))) => {
                assert!(msg.contains("too large"), "got {msg}")
            }
            Err(e) => panic!("expected a too-large error, got {:?}", e.error()),
            Ok(_) => panic!("expected a too-large error"),
        }
    }

    /// A connection whose reads never complete and whose writes fail: a
    /// request on it fails before any byte of its frame leaves.
    struct WriteFails;

    impl AsyncRead for WriteFails {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for WriteFails {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn request_once_is_not_resent_after_its_frame_was_sent() {
        // The proxy receives the whole frame, then the connection drops
        // before the reply: it may have applied it.
        let server = Server {
            hangup_after_first_frame: true,
            ..Server::default()
        };
        let pool = server.pool(4);
        match pool.request_once(b"take").await {
            Err(OnceError::OutcomeUnknown(_)) => {}
            other => panic!("expected outcome unknown, got {other:?}"),
        }
        assert_eq!(server.frames.load(Ordering::SeqCst), 1, "never resent");
        assert_eq!(server.connects.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_idempotent_request_is_resent_in_the_same_situation() {
        let server = Server {
            hangup_after_first_frame: true,
            ..Server::default()
        };
        let pool = server.pool(4);
        assert_eq!(pool.request(b"get").await.expect("request"), b"get");
        assert_eq!(server.frames.load(Ordering::SeqCst), 2, "resent once");
    }

    #[tokio::test]
    async fn request_once_is_retried_when_its_frame_was_never_written() {
        let server = Server::default();
        let s = server.clone();
        let connect: Connector = Arc::new(move || {
            let s = s.clone();
            Box::pin(async move { Ok(s.open()) })
        });
        let pool = ConnectionPool::new(connect, 4, Box::new(WriteFails));
        assert_eq!(pool.request_once(b"take").await.expect("retried"), b"take");
        assert_eq!(server.frames.load(Ordering::SeqCst), 1, "applied once");
        assert_eq!(pool.idle_len(), 1, "only the working connection is kept");
    }

    /// An atomic request whose reply never comes: the deadline expires after
    /// its frame was received, so the outcome is unknown, and it is not
    /// resent — applied at most once.
    #[tokio::test]
    async fn request_once_timing_out_after_sending_is_outcome_unknown() {
        let gate = Arc::new(Notify::new());
        let server = Server {
            gate: Some(gate.clone()),
            ..Server::default()
        };
        let pool = server.pool(2).with_timeout(Duration::from_millis(100));
        match pool.request_once(b"take").await {
            Err(OnceError::OutcomeUnknown(e)) => {
                assert!(e.to_string().contains("timed out"), "{e}")
            }
            other => panic!("expected outcome unknown, got {other:?}"),
        }
        assert_eq!(server.frames.load(Ordering::SeqCst), 1, "never resent");
        assert_eq!(server.connects.load(Ordering::SeqCst), 1);
        assert_eq!(pool.idle_len(), 0, "the connection is dropped");
    }

    /// A connection that accepts no bytes: a write that never completes.
    struct WriteHangs;

    impl AsyncRead for WriteHangs {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for WriteHangs {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The deadline expiring before the frame was written: nothing can have
    /// been applied, so the request goes out once on a new connection.
    #[tokio::test]
    async fn request_once_timing_out_before_sending_is_retried() {
        let server = Server::default();
        let s = server.clone();
        let connect: Connector = Arc::new(move || {
            let s = s.clone();
            Box::pin(async move { Ok(s.open()) })
        });
        let pool = ConnectionPool::new(connect, 2, Box::new(WriteHangs))
            .with_timeout(Duration::from_millis(100));
        assert_eq!(pool.request_once(b"take").await.expect("retried"), b"take");
        assert_eq!(server.frames.load(Ordering::SeqCst), 1, "applied once");
    }

    #[tokio::test]
    async fn a_stale_idle_connection_is_discarded_without_error() {
        // The parent closed the idle connection (proxy restart): it is
        // noticed before anything is written, so even a non-idempotent
        // request just uses a new one.
        let server = Server {
            drop_first: true,
            ..Server::default()
        };
        let pool = server.pool(4);
        tokio::task::yield_now().await; // let the server side close
        assert_eq!(pool.request_once(b"take").await.expect("request"), b"take");
        assert_eq!(server.frames.load(Ordering::SeqCst), 1);
        assert_eq!(server.connects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_live_idle_connection_is_not_stale() {
        let pool = Server::default().pool(1);
        pool.request(b"warm").await.expect("request");
        let mut stream = pool.take_live_idle().expect("kept");
        assert!(!is_stale(&mut stream));
    }
}
