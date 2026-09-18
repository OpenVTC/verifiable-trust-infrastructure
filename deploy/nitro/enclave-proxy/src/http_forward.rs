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
//! header a client could use to claim an identity, sets `X-Forwarded-For` to
//! the address we actually accepted the connection from, and forwards the
//! request over vsock unchanged in every other respect.
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

/// Replace every client-supplied identity header with a single
/// `X-Forwarded-For` naming the peer we accepted the connection from.
///
/// This *sets* rather than appends. Appending preserves a chain the client
/// wrote, and this proxy is the outermost hop — there is no upstream chain to
/// preserve, only attacker input to discard.
pub fn sanitise_forwarding_headers<B>(req: &mut Request<B>, peer: IpAddr) {
    let headers = req.headers_mut();
    for name in CLIENT_IDENTITY_HEADERS {
        let name = HeaderName::from_static(name);
        // `remove` drops every value bound to the name, but a header can be
        // present more than once; loop until the map reports it gone.
        while headers.remove(&name).is_some() {}
    }

    // An `IpAddr` always renders as a valid header value, so the only way
    // this can fail is a bug in `std`; dropping the header would silently
    // fall the limiter back to one shared bucket, so assert instead.
    let value = HeaderValue::from_str(&peer.to_string())
        .expect("an IpAddr always renders as a valid header value");
    headers.insert(HeaderName::from_static("x-forwarded-for"), value);
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
        async move {
            sanitise_forwarding_headers(&mut req, peer);
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
        sanitise_forwarding_headers(&mut req, peer());
        assert_eq!(header_values(&req, "x-forwarded-for"), ["203.0.113.9"]);
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
        sanitise_forwarding_headers(&mut req, peer());
        assert_eq!(header_values(&req, "x-forwarded-for"), ["203.0.113.9"]);
    }

    #[test]
    fn every_identity_header_is_stripped() {
        let mut builder = Request::builder().uri("/");
        for name in CLIENT_IDENTITY_HEADERS {
            builder = builder.header(*name, "9.9.9.9");
        }
        let mut req = builder.body(()).unwrap();
        sanitise_forwarding_headers(&mut req, peer());
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
        sanitise_forwarding_headers(&mut req, peer());
        assert_eq!(header_values(&req, "authorization"), ["Bearer token"]);
        assert_eq!(header_values(&req, "content-type"), ["application/json"]);
    }

    #[test]
    fn a_request_with_no_forwarding_headers_gains_one() {
        let mut req = Request::builder().uri("/").body(()).unwrap();
        sanitise_forwarding_headers(&mut req, "2001:db8::1".parse().unwrap());
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (client, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let up = TcpStream::connect(upstream).await.unwrap();
                    let _ = serve_sanitised(client, up, peer).await;
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
}
