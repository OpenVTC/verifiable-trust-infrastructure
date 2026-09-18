//! HTTP/1.1 reverse proxy for the inbound channel — the trust boundary for
//! client-IP attribution.
//!
//! # Why this is not a byte bridge
//!
//! Every other channel in this proxy is a raw [`crate::bridge::bridge`], and
//! the inbound one used to be too. That is the correct shape for a tunnel,
//! and the wrong shape for the *only* hop that still knows who the client is.
//!
//! The enclave VTA sees its peer as `127.0.0.1`, because the last leg is
//! `socat VSOCK-LISTEN:5100 → TCP-CONNECT:127.0.0.1:8100` inside the enclave
//! (see `enclave-entrypoint.sh`). So every request looks identical to it, and
//! its per-IP rate limiters — `/auth`, `/bootstrap/request`, the public DID
//! log — collapse into one bucket that any single client can exhaust for
//! everyone.
//!
//! The VTA's answer is `[server] trust_xff_cidrs`: name the proxy in front of
//! it and the limiter reads `X-Forwarded-For` for requests arriving from that
//! address. That config is only safe if something on the path actually
//! *replaces* the header. A byte bridge does not — it forwards whatever the
//! client typed — so trusting `127.0.0.1` over a byte bridge means every
//! client can pick its own rate-limit bucket, which is worse than the shared
//! bucket it was meant to fix.
//!
//! This module is that something. It terminates HTTP/1.1 here, strips every
//! header a client could use to claim an identity, and then either sets
//! `X-Forwarded-For` to the address we actually accepted the connection from,
//! or — when that address is itself a declared trusted upstream — extends the
//! chain that upstream already sent.
//!
//! # A trusted upstream in front of this proxy
//!
//! `enclave-proxy` is not always the first hop. Behind an HTTP-aware load
//! balancer (an AWS ALB, say) that already appends the real client's address,
//! discarding what it sent and substituting the balancer's own node address
//! reproduces the one-shared-bucket problem this proxy exists to fix — every
//! client behind that node collapses into one identity, just one hop further
//! out. `trusted_upstream_cidrs` (read from the same `[server] trust_xff_cidrs`
//! the enclave VTA trusts — one declaration, not two) names the peers entitled
//! to make that claim. When the TCP peer is one of them, [`sanitise_forwarding_headers`]
//! *extends* the existing `X-Forwarded-For` with that peer instead of replacing
//! it, mirroring `vti_common::rate_limit::TrustedProxyKeyExtractor`'s chain
//! walk on the receiving end (a separate crate this proxy does not depend on —
//! the two are consistent by convention, not by shared code). An untrusted
//! peer's claim is still discarded
//! outright — trusting a hop is an explicit, per-CIDR decision, never assumed.
//!
//! # What this does and does not assume about the parent
//!
//! The parent instance is outside the enclave's trust boundary, and this does
//! not change that. The parent already carries every inbound byte and can
//! forge, drop or replay anything it likes; letting it name the client IP for
//! *rate-limiting* adds no authority it did not already have. Nothing
//! security-bearing is decided from this header — authentication is the DID
//! and JWT machinery inside the enclave, which the parent cannot forge.
//!
//! # Parsing
//!
//! The parse is hyper's, which is also the VTA's own server. Using the same
//! implementation on both ends is deliberate: a hand-rolled header rewriter
//! that disagrees with the upstream parser about where one request ends and
//! the next begins is how request smuggling happens, and keep-alive means
//! that boundary has to be found on every request, not just the first.
//!
//! # Limit: no protocol upgrades
//!
//! Requests and responses pass through whole, bodies streaming unbuffered, but
//! a `101 Switching Protocols` does not — the connection is served without
//! `with_upgrades()`, so a WebSocket handshake would be answered and then go
//! nowhere. That is correct today: the VTA's REST surface has no inbound
//! upgrade, and its DIDComm and TSP traffic is *outbound* over the mediator
//! channel, which is a separate byte bridge. Add an inbound upgrade to the VTA
//! and this is the second place that has to change.

use std::net::IpAddr;
use std::sync::Arc;

use hyper::Request;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use ipnetwork::IpNetwork;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::debug;

/// Headers removed from every inbound request before it reaches the enclave.
///
/// `x-forwarded-for` is the one the VTA reads today. The rest are here because
/// they carry the same meaning to the libraries an operator might reasonably
/// swap in (`tower_governor`'s `SmartIpKeyExtractor` reads `Forwarded` and
/// `X-Real-IP`; the `client-ip` family reads the vendor ones), and a header we
/// forget to strip is a header a client gets to choose. Stripping one the VTA
/// does not read costs nothing; leaving one it later starts reading costs the
/// limiter.
const CLIENT_IDENTITY_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "forwarded",
    "x-real-ip",
    "x-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-envoy-external-address",
    "fly-client-ip",
    "cloudfront-viewer-address",
];

/// Replace or extend `X-Forwarded-For` depending on whether `peer` is a
/// declared trusted upstream, after stripping every other identity header
/// unconditionally.
///
/// An untrusted peer's claim is attacker input with no more standing than any
/// other header it sent, so it is discarded and replaced with `peer` alone —
/// unchanged from treating this proxy as the outermost hop. A trusted peer
/// (named in `trusted_upstream_cidrs`) has already appended a claim this
/// proxy did not originate; extending it preserves that claim instead of
/// overwriting it with the peer's own address, which is what let a
/// legitimate load balancer's real-client attribution silently collapse into
/// one bucket per balancer node.
pub fn sanitise_forwarding_headers<B>(
    req: &mut Request<B>,
    peer: IpAddr,
    trusted_upstream_cidrs: &[IpNetwork],
) {
    let trusted = trusted_upstream_cidrs
        .iter()
        .any(|cidr| cidr.contains(peer));

    // Read the existing chain before any header is touched — extending it
    // requires knowing what it was.
    let existing_chain = trusted.then(|| existing_forwarded_entries(req)).flatten();

    let headers = req.headers_mut();
    for name in CLIENT_IDENTITY_HEADERS {
        let name = HeaderName::from_static(name);
        // `remove` drops every value bound to the name, but a header can be
        // present more than once; loop until the map reports it gone.
        while headers.remove(&name).is_some() {}
    }

    let value = match existing_chain {
        Some(entries) if !entries.is_empty() => format!("{}, {peer}", entries.join(", ")),
        _ => peer.to_string(),
    };
    // A comma-joined list of values that were already valid headers, plus an
    // `IpAddr` (which always renders as a valid header value), is itself
    // always a valid header value — the only way this can fail is a bug in
    // `std`, and dropping the header would silently fall the limiter back to
    // one shared bucket, so assert instead.
    let value = HeaderValue::from_str(&value).expect(
        "a joined chain of valid header values plus an IpAddr is itself a valid header value",
    );
    headers.insert(HeaderName::from_static("x-forwarded-for"), value);
}

/// Upper bound on entries read from the existing chain before this proxy's
/// own peer is appended below.
///
/// Mirrors `vti_common::rate_limit::MAX_FORWARDED_ENTRIES` (a separate crate
/// this one does not depend on — consistent by convention) minus one: the
/// receiver falls back to the peer once a chain exceeds that many entries,
/// and inside the enclave the peer is always the trusted loopback address, so
/// an unbounded extend here would let a client force itself into that shared
/// fallback bucket by sending enough entries. Truncating to one less than the
/// receiver's cap leaves room for the peer this function appends.
const MAX_EXISTING_ENTRIES: usize = 63;

/// The existing `X-Forwarded-For` chain as individual entries, in the order
/// the receiver's own chain-walk will see them, capped to
/// `MAX_EXISTING_ENTRIES` by dropping the leftmost (oldest, most
/// attacker-adjacent) entries — the receiver walks from the right, so nothing
/// it would ever reach is lost.
///
/// `None` if any header line isn't valid header text (obs-text, 0x80-0xFF):
/// the receiver's own walk aborts the same way on the same byte, and joining
/// around just the bad line here would let a client pair a claim with a byte
/// it knows fails `to_str()` and keep the claim anyway — the same escape as
/// leaving the chain unbounded.
fn existing_forwarded_entries<B>(req: &Request<B>) -> Option<Vec<String>> {
    let mut entries = Vec::new();
    for value in req.headers().get_all("x-forwarded-for") {
        let value = value.to_str().ok()?;
        for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            entries.push(entry.to_string());
        }
    }
    if entries.len() > MAX_EXISTING_ENTRIES {
        let excess = entries.len() - MAX_EXISTING_ENTRIES;
        entries.drain(..excess);
    }
    Some(entries)
}

/// Serve one accepted client connection, forwarding every request on it to
/// `upstream` with sanitised forwarding headers.
///
/// Bodies stream through unbuffered in both directions, so a large upload
/// costs the parent no memory — the VTA's own body caps still decide what is
/// too big. Keep-alive is handled by hyper on both sides: several requests on
/// the client connection are forwarded in order over the one upstream
/// connection, each re-sanitised.
pub async fn serve_sanitised<C, U>(
    client: C,
    upstream: U,
    peer: IpAddr,
    trusted_upstream_cidrs: Arc<Vec<IpNetwork>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(upstream)).await?;

    // The upstream connection needs its own task to drive I/O while the
    // server task awaits responses.
    let driver = tokio::spawn(async move {
        if let Err(e) = connection.await {
            debug!(error = %e, "[inbound] upstream connection ended");
        }
    });

    // `send_request` takes `&mut self` but a hyper service is `Fn`, so the
    // sender is shared. HTTP/1.1 is request-at-a-time on one connection
    // anyway, so serialising here costs nothing.
    let sender = Arc::new(Mutex::new(sender));
    let service = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        let sender = Arc::clone(&sender);
        let trusted_upstream_cidrs = Arc::clone(&trusted_upstream_cidrs);
        async move {
            sanitise_forwarding_headers(&mut req, peer, &trusted_upstream_cidrs);
            let mut sender = sender.lock().await;
            sender.ready().await?;
            sender.send_request(req).await
        }
    });

    let result = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(client), service)
        .await;

    driver.abort();
    result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> IpAddr {
        "203.0.113.9".parse().unwrap()
    }

    fn header_values(req: &Request<()>, name: &str) -> Vec<String> {
        req.headers()
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_client_supplied_chain_is_replaced_not_extended() {
        let mut req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "9.9.9.9, 10.0.0.1")
            .body(())
            .unwrap();
        sanitise_forwarding_headers(&mut req, peer(), &[]);
        assert_eq!(header_values(&req, "x-forwarded-for"), ["203.0.113.9"]);
    }

    /// Mirrors `vti_common::rate_limit::MAX_FORWARDED_ENTRIES` (a separate
    /// crate this one does not depend on) — the receiver falls back to the
    /// peer once a chain exceeds this many entries, and inside the enclave
    /// the peer is always the trusted loopback address. An unbounded extend
    /// here would let a client force itself into that shared fallback bucket
    /// by sending enough junk entries.
    ///
    /// Pins the *direction* of truncation, not just the count: the real
    /// client's claim sits at the rightmost end of the junk, exactly where a
    /// genuine multi-hop chain would put it. Keeping the wrong end (the
    /// leftmost, most attacker-adjacent entries) instead would still pass a
    /// bare length check while handing the receiver's chain-walk an
    /// attacker-chosen entry to land on — the same bug this proxy exists to
    /// fix, just relocated. A length-only assertion here does not catch that;
    /// verified by mutating `drain(..excess)` to `truncate(MAX_EXISTING_ENTRIES)`
    /// (keep-leftmost) and confirming this version of the test fails while a
    /// bare-count version does not.
    #[test]
    fn extended_chain_is_capped_keeping_the_rightmost_entries() {
        let trusted_peer: IpAddr = "10.0.1.50".parse().unwrap();
        let junk = (0..200)
            .map(|i| format!("1.2.3.{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", format!("{junk}, 203.0.113.42"))
            .body(())
            .unwrap();
        sanitise_forwarding_headers(&mut req, trusted_peer, &["10.0.0.0/8".parse().unwrap()]);

        let seen = header_values(&req, "x-forwarded-for");
        assert_eq!(seen.len(), 1);
        let entries: Vec<&str> = seen[0].split(", ").collect();
        assert_eq!(entries.len(), 64, "63 kept from the incoming chain + this proxy's own peer");
        assert_eq!(
            entries.last().copied(),
            Some("10.0.1.50"),
            "this proxy's own peer is always the last (newest) entry"
        );
        assert_eq!(
            entries[entries.len() - 2],
            "203.0.113.42",
            "the real client's claim — rightmost of the incoming chain — must survive truncation"
        );
        assert!(
            !entries.contains(&"1.2.3.0"),
            "the leftmost (oldest, attacker-adjacent) junk must be what gets dropped"
        );
    }

    /// Exact boundary behaviour of the cap: no truncation up to and including
    /// `MAX_EXISTING_ENTRIES`, then exactly one entry dropped per entry over
    /// it — including the exact edge (`MAX_EXISTING_ENTRIES + 1`) where
    /// truncation first kicks in.
    #[test]
    fn extended_chain_boundary_cases() {
        let trusted_peer: IpAddr = "10.0.1.50".parse().unwrap();
        for incoming_len in [62, 63, 64, 65, 200] {
            let chain = (0..incoming_len)
                .map(|i| format!("1.2.3.{i}"))
                .collect::<Vec<_>>()
                .join(", ");
            let mut req = Request::builder()
                .uri("/")
                .header("x-forwarded-for", chain)
                .body(())
                .unwrap();
            sanitise_forwarding_headers(&mut req, trusted_peer, &["10.0.0.0/8".parse().unwrap()]);

            let seen = header_values(&req, "x-forwarded-for");
            let emitted = seen[0].split(", ").count();
            // +1 for this proxy's own peer, appended after truncation.
            let expected = incoming_len.min(MAX_EXISTING_ENTRIES) + 1;
            assert_eq!(
                emitted, expected,
                "incoming_len={incoming_len}: expected {expected} emitted entries, got {emitted}"
            );
        }
    }

    /// A line that fails `to_str()` (obs-text, 0x80-0xFF) must make the whole
    /// existing chain unusable, not just that line — otherwise a client pairs
    /// a chosen claim with a byte it knows the parser rejects and keeps the
    /// claim anyway, the same escape as an unbounded chain (#1 above), on a
    /// path the receiver's own chain-walk closes by aborting on the same byte.
    #[test]
    fn a_line_that_fails_to_str_discards_the_whole_chain_not_just_that_line() {
        let trusted_peer: IpAddr = "10.0.1.50".parse().unwrap();
        let mut req = Request::builder().uri("/").body(()).unwrap();
        req.headers_mut().append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str("203.0.113.9").unwrap(),
        );
        req.headers_mut().append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_bytes(&[0x80, 0x81]).unwrap(),
        );

        sanitise_forwarding_headers(&mut req, trusted_peer, &["10.0.0.0/8".parse().unwrap()]);

        assert_eq!(header_values(&req, "x-forwarded-for"), ["10.0.1.50"]);
    }

    /// A single `remove` would leave the second line in place, and the VTA
    /// concatenates every line before walking the chain — so the leftover
    /// would be attacker-controlled input inside the value it reads.
    #[test]
    fn repeated_headers_are_all_removed() {
        let mut req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "9.9.9.9")
            .header("x-forwarded-for", "8.8.8.8")
            .body(())
            .unwrap();
        sanitise_forwarding_headers(&mut req, peer(), &[]);
        assert_eq!(header_values(&req, "x-forwarded-for"), ["203.0.113.9"]);
    }

    #[test]
    fn every_identity_header_is_stripped() {
        let mut builder = Request::builder().uri("/");
        for name in CLIENT_IDENTITY_HEADERS {
            builder = builder.header(*name, "9.9.9.9");
        }
        let mut req = builder.body(()).unwrap();
        sanitise_forwarding_headers(&mut req, peer(), &[]);
        for name in CLIENT_IDENTITY_HEADERS {
            if *name == "x-forwarded-for" {
                continue;
            }
            assert!(req.headers().get(*name).is_none(), "{name} survived");
        }
    }

    #[test]
    fn unrelated_headers_are_left_alone() {
        let mut req = Request::builder()
            .uri("/")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        sanitise_forwarding_headers(&mut req, peer(), &[]);
        assert_eq!(header_values(&req, "authorization"), ["Bearer token"]);
        assert_eq!(header_values(&req, "content-type"), ["application/json"]);
    }

    #[test]
    fn a_request_with_no_forwarding_headers_gains_one() {
        let mut req = Request::builder().uri("/").body(()).unwrap();
        sanitise_forwarding_headers(&mut req, "2001:db8::1".parse().unwrap(), &[]);
        assert_eq!(header_values(&req, "x-forwarded-for"), ["2001:db8::1"]);
    }

    // -----------------------------------------------------------------------
    // End to end, over real sockets. TCP stands in for vsock — `serve_sanitised`
    // is generic over the stream, and the enclave leg is the only difference.
    // -----------------------------------------------------------------------

    use std::convert::Infallible;
    use std::net::SocketAddr;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::{TcpListener, TcpStream};

    /// Stands in for the enclave VTA: answers with the `x-forwarded-for` it
    /// was handed, so the test reads exactly what the limiter would key on.
    async fn spawn_echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let seen = req
                            .headers()
                            .get_all("x-forwarded-for")
                            .iter()
                            .map(|v| v.to_str().unwrap().to_string())
                            .collect::<Vec<_>>()
                            .join("|");
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(seen))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    /// The proxy under test, with `peer` standing for the address it accepted
    /// the client connection from.
    async fn spawn_proxy(upstream: SocketAddr, peer: IpAddr) -> SocketAddr {
        spawn_proxy_trusting(upstream, peer, Vec::new()).await
    }

    /// Like [`spawn_proxy`], but with an explicit trusted-upstream CIDR list —
    /// for the tests exercising the append-not-replace path.
    async fn spawn_proxy_trusting(
        upstream: SocketAddr,
        peer: IpAddr,
        trusted_upstream_cidrs: Vec<IpNetwork>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let trusted_upstream_cidrs = Arc::new(trusted_upstream_cidrs);
        tokio::spawn(async move {
            loop {
                let (client, _) = listener.accept().await.unwrap();
                let trusted_upstream_cidrs = Arc::clone(&trusted_upstream_cidrs);
                tokio::spawn(async move {
                    let up = TcpStream::connect(upstream).await.unwrap();
                    let _ = serve_sanitised(client, up, peer, trusted_upstream_cidrs).await;
                });
            }
        });
        addr
    }

    async fn get_with_forged_xff(
        sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        forged: &[&str],
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().uri("/").header("host", "vta.test");
        for value in forged {
            builder = builder.header("x-forwarded-for", *value);
        }
        let resp = sender
            .send_request(builder.body(Empty::<Bytes>::new()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// The whole point: whatever the client claims, the enclave is told the
    /// address the proxy actually accepted the connection from.
    #[tokio::test]
    async fn forged_header_never_reaches_the_enclave() {
        let upstream = spawn_echo_upstream().await;
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        let proxy = spawn_proxy(upstream, peer).await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);

        let (status, seen) = get_with_forged_xff(&mut sender, &["9.9.9.9, 10.0.0.1"]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen, "198.51.100.7");
    }

    /// Keep-alive is where a rewriter that only fixed up the first request on
    /// a connection would leak: request two would carry the client's own
    /// header straight through.
    #[tokio::test]
    async fn every_request_on_a_kept_alive_connection_is_sanitised() {
        let upstream = spawn_echo_upstream().await;
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        let proxy = spawn_proxy(upstream, peer).await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);

        for forged in [
            &["9.9.9.9"][..],
            &["10.0.0.1"][..],
            &["9.9.9.9", "8.8.8.8"][..],
        ] {
            let (status, seen) = get_with_forged_xff(&mut sender, forged).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(seen, "198.51.100.7", "forged={forged:?}");
        }
    }

    /// A trusted upstream (e.g. an AWS ALB naming the real client) has its
    /// claim extended, not discarded — the fix for the one-bucket-per-balancer-
    /// node collapse this proxy would otherwise reproduce behind a real load
    /// balancer.
    #[tokio::test]
    async fn a_trusted_upstreams_header_is_extended_not_discarded() {
        let upstream = spawn_echo_upstream().await;
        // Stands in for the ALB node's own address — what this proxy's
        // `listener.accept()` actually reports as the peer.
        let alb_node_peer: IpAddr = "10.0.1.50".parse().unwrap();
        let proxy =
            spawn_proxy_trusting(upstream, alb_node_peer, vec!["10.0.0.0/8".parse().unwrap()])
                .await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);

        // Not attacker input — what a real ALB sets by default: the actual
        // client's public IP, already correctly appended.
        let (status, seen) = get_with_forged_xff(&mut sender, &["203.0.113.42"]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen, "203.0.113.42, 10.0.1.50");
    }

    /// An untrusted peer's claim still gets no benefit of the doubt just
    /// because *some* CIDR is configured elsewhere — trust is per-CIDR, not
    /// "any list is set".
    #[tokio::test]
    async fn an_untrusted_peer_is_unaffected_by_an_unrelated_trusted_cidr() {
        let upstream = spawn_echo_upstream().await;
        let untrusted_peer: IpAddr = "198.51.100.7".parse().unwrap();
        let proxy = spawn_proxy_trusting(
            upstream,
            untrusted_peer,
            vec!["10.0.0.0/8".parse().unwrap()],
        )
        .await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);

        let (status, seen) = get_with_forged_xff(&mut sender, &["203.0.113.42"]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen, "198.51.100.7");
    }
}
