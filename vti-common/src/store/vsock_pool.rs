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

    /// Send one request frame and return the response frame.
    ///
    /// Waits for a free connection slot, reuses an idle connection if there is
    /// one, and retries once on a fresh connection if the idle one fails (it
    /// may have been closed by the parent).
    pub(crate) async fn request(&self, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| AppError::Internal("storage connection pool closed".into()))?;

        if let Some(mut stream) = self.take_idle() {
            match round_trip_within(&mut stream, payload, self.timeout).await {
                Ok(resp) => {
                    self.put_idle(stream);
                    return Ok(resp);
                }
                Err(e) => warn!(error = %e, "storage request failed, reconnecting"),
            }
        }

        let mut stream = (self.connect)().await?;
        trace!("storage connection opened");
        let resp = round_trip_within(&mut stream, payload, self.timeout).await?;
        self.put_idle(stream);
        Ok(resp)
    }

    fn take_idle(&self) -> Option<BoxStream> {
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
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

/// Write one length-prefixed request frame and read one response frame.
#[cfg(test)]
async fn round_trip(stream: &mut BoxStream, payload: &[u8]) -> Result<Vec<u8>, AppError> {
    round_trip_within(stream, payload, ROUND_TRIP_TIMEOUT).await
}

async fn round_trip_within(
    stream: &mut BoxStream,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, AppError> {
    match tokio::time::timeout(timeout, round_trip_inner(stream, payload)).await {
        Ok(result) => result,
        Err(_) => Err(AppError::Internal(format!(
            "storage request timed out after {timeout:?}"
        ))),
    }
}

async fn round_trip_inner(stream: &mut BoxStream, payload: &[u8]) -> Result<Vec<u8>, AppError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| AppError::Internal("storage request too large".into()))?;
    // On an unbuffered vsock stream every write is its own packet across the
    // enclave boundary, so a small frame goes out as one write. Above
    // `COALESCE_MAX` the frame spans many packets whatever we do, and copying
    // it just to save the header's packet costs more than it saves.
    if payload.len() <= COALESCE_MAX {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        stream
            .write_all(&frame)
            .await
            .map_err(AppError::vsock("vsock write"))?;
    } else {
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(AppError::vsock("vsock write"))?;
        stream
            .write_all(payload)
            .await
            .map_err(AppError::vsock("vsock write"))?;
    }
    stream
        .flush()
        .await
        .map_err(AppError::vsock("vsock flush"))?;

    let len = stream
        .read_u32()
        .await
        .map_err(AppError::vsock("vsock read"))?;
    if len > MAX_MESSAGE_SIZE {
        return Err(AppError::Internal(format!(
            "vsock response too large: {len} > {MAX_MESSAGE_SIZE}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(AppError::vsock("vsock read"))?;
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
                server.serve(server_end).await;
            });
            Box::new(client)
        }

        /// Echo every request frame back as its response.
        async fn serve(self, mut stream: DuplexStream) {
            while let Ok(len) = stream.read_u32().await {
                let mut buf = vec![0u8; len as usize];
                if stream.read_exact(&mut buf).await.is_err() {
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
            Err(AppError::Internal(msg)) => assert!(msg.contains("too large"), "got {msg}"),
            other => panic!("expected a too-large error, got {other:?}"),
        }
    }
}
