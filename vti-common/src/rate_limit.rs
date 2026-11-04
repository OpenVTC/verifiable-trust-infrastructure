//! Client-IP attribution for the per-IP rate limiters: the rule in
//! `affinidi-rate-limit`'s `ClientIpExtractor`, which the mediator, the DID
//! resolver cache and the DID hosting service apply too, as a
//! `tower_governor` key extractor.
//!
//! A rate limiter is only as good as the identity it charges. Keying on the
//! socket peer is spoof-proof but collapses every client behind a reverse
//! proxy into one bucket; keying on `X-Forwarded-For` splits them apart but
//! lets anyone who can reach the socket pick their own bucket. Neither is
//! right on its own, so [`TrustedProxyKeyExtractor`] takes the peer as the
//! anchor and only reads the header when the peer is a proxy the operator
//! named.
//!
//! ## The header is a chain, and only its right-hand end is trustworthy
//!
//! Every conforming proxy *appends* the address it received the request from,
//! so `X-Forwarded-For: <client-supplied junk>, <real client>, <inner proxy>`
//! grows to the right and the attacker only ever controls the left. Reading
//! the leftmost entry — the "original client" the header nominally names — is
//! therefore reading attacker input. Reading the rightmost is safe but names
//! the *previous hop*, which is the real client only when exactly one proxy
//! sits in front.
//!
//! So [`TrustedProxyKeyExtractor::extract`] walks the chain from the right and
//! returns the first entry that is **not** itself a trusted proxy. With one
//! proxy that is the client; with a chain (ALB → nginx → service) it skips
//! each hop the operator declared and still lands on the client. Anything the
//! attacker wrote sits further left and is never reached.
//!
//! ## A Nitro enclave's parent has an address of its own
//!
//! A Nitro-enclave VTA serves REST on vsock, and the VTA's vsock listener
//! accepts only the parent instance (CID 3), reporting it as
//! [`VSOCK_PARENT_PEER`] — an address no TCP connection can carry. Naming it
//! in `trust_xff_cidrs` (`0.0.0.3/32`) trusts exactly the parent's proxy and
//! nothing else. Through the old in-enclave `socat` the peer was `127.0.0.1`,
//! which anything inside the enclave could also be.
//!
//! It is still a declaration, not a default: only the operator knows whether
//! the parent runs `deploy/nitro/enclave-proxy` (which rewrites
//! `X-Forwarded-For`) or `parent-proxy.sh` (which bridges bytes, so must not be
//! trusted, and refuses to start while `trust_xff_cidrs` is set).
//!
//! An untrusted peer, no header, or a chain trusted end to end resolves to the
//! peer, the un-spoofable value; no `ConnectInfo` at all is refused. A chain a
//! trusted proxy sent that cannot be read — a malformed entry from the client
//! entry rightwards, more than 64 entries — is refused with `400`. Charging it
//! to the proxy instead would hand its sender the proxy's bucket on top of its
//! own, and hide a misbehaving proxy behind unexplained `429`s. A range
//! covering every address (`0.0.0.0/0`, `::/0`) is refused when the extractor
//! is built.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use affinidi_rate_limit::{ClientIpExtractor, InvalidTrustedProxy, IpNet};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use ipnetwork::IpNetwork;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

/// The peer address a Nitro-enclave VTA's REST vsock listener reports for its
/// parent instance — the only vsock peer it accepts.
///
/// `0.0.0.3` is in `0.0.0.0/8`, "this host on this network" (RFC 1122
/// §3.2.1.3, RFC 6890): never a valid source address, so a TCP connection
/// cannot present it (Linux drops such packets as martians). A
/// `trust_xff_cidrs` entry of `0.0.0.3/32` therefore trusts the parent and
/// nothing else — no TCP peer, nothing inside the enclave. The `3` is the
/// parent's vsock CID, as a reminder.
pub const VSOCK_PARENT_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 3)), 0);

/// The client-address rule every per-IP limiter here charges by:
/// `affinidi-rate-limit`'s `ClientIpExtractor` over `trusted_cidrs`, as a
/// `tower_governor` key extractor.
///
/// **The CIDRs are a promise about the deployment.** Naming a proxy here
/// asserts that it overwrites `X-Forwarded-For` with the address it actually
/// accepted the connection from, or appends to it — *and* that nothing which
/// does neither can reach the socket. A layer-4 (TCP) forwarder does not
/// qualify: it passes the client's own header through untouched while making
/// every request look like it came from the forwarder, which turns this list
/// into a rate-limit bypass. See `docs/02-vta/rate-limiting.md`.
#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    clients: ClientIpExtractor,
}

impl TrustedProxyKeyExtractor {
    /// # Errors
    ///
    /// [`InvalidTrustedProxy`] for a range covering every address
    /// (`0.0.0.0/0`, `::/0`), which would let any client pick its bucket.
    pub fn new(trusted_cidrs: Vec<IpNetwork>) -> Result<Self, InvalidTrustedProxy> {
        let ranges = trusted_cidrs
            .iter()
            .map(|cidr| {
                IpNet::new(cidr.network(), cidr.prefix())
                    .expect("an IpNetwork's prefix is valid for its address family")
            })
            .collect();
        Ok(Self {
            clients: ClientIpExtractor::trusted_proxies(ranges)?,
        })
    }

    /// The crate's extractor, for code that resolves a client itself.
    pub fn clients(&self) -> &ClientIpExtractor {
        &self.clients
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<IpAddr, GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;
        self.clients
            .client_ip(peer, req.headers())
            .map_err(|e| GovernorError::Other {
                code: StatusCode::BAD_REQUEST,
                msg: Some(e.to_string()),
                headers: None,
            })
    }
}

/// Insert a loopback `ConnectInfo` when the request carries none.
///
/// `tower::oneshot`-style test calls have no socket behind them, so the
/// extractors — which require a peer — would refuse every request. This
/// supplies one.
///
/// **Test-harness use only, and only where nothing is trusted.** Synthesising
/// a peer manufactures the anchor the extractor exists to check; if the
/// synthetic address were inside a trusted CIDR it would hand the request its
/// own `X-Forwarded-For`. Production routers are served through
/// `into_make_service_with_connect_info`, which always supplies a real peer,
/// so they must not layer this.
pub async fn insert_default_connect_info_if_missing(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::net::Ipv4Addr;

    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_none()
    {
        let synthetic = ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        request.extensions_mut().insert(synthetic);
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(peer: Option<&str>, xff: Option<&str>) -> Request<()> {
        req_with_all(peer, xff.into_iter().collect())
    }

    fn req_with_all(peer: Option<&str>, xffs: Vec<&str>) -> Request<()> {
        let mut builder = Request::builder().uri("/");
        for xff in xffs {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut req = builder.body(()).unwrap();
        if let Some(peer) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        req
    }

    fn cidrs(nets: &[&str]) -> Vec<IpNetwork> {
        nets.iter().map(|n| n.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn loopback() -> TrustedProxyKeyExtractor {
        TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"])).unwrap()
    }

    const PARENT: &str = "0.0.0.3:0";

    #[test]
    fn vsock_parent_peer_constant_is_the_documented_address() {
        assert_eq!(VSOCK_PARENT_PEER, PARENT.parse::<SocketAddr>().unwrap());
    }

    fn parent_trusted() -> TrustedProxyKeyExtractor {
        TrustedProxyKeyExtractor::new(cidrs(&["0.0.0.3/32"])).unwrap()
    }

    #[test]
    fn xff_from_the_vsock_parent_is_honoured_when_declared() {
        let req = req_with(Some(PARENT), Some("9.9.9.9, 203.0.113.9"));
        assert_eq!(parent_trusted().extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[test]
    fn the_vsock_parent_without_xff_is_charged_to_itself() {
        let req = req_with(Some(PARENT), None);
        assert_eq!(parent_trusted().extract(&req).unwrap(), ip("0.0.0.3"));
    }

    #[test]
    fn the_vsock_parent_is_not_trusted_undeclared() {
        // A byte-bridging parent (parent-proxy.sh) forwards the client's own
        // header; with nothing declared it must not be read.
        let none = TrustedProxyKeyExtractor::new(vec![]).unwrap();
        let req = req_with(Some(PARENT), Some("203.0.113.9"));
        assert_eq!(none.extract(&req).unwrap(), ip("0.0.0.3"));
    }

    #[test]
    fn a_stale_loopback_entry_does_not_trust_the_vsock_parent() {
        // The pre-vsock config trusted 127.0.0.1/32. It fails safe: one shared
        // bucket, never a header the client chose.
        let req = req_with(Some(PARENT), Some("203.0.113.9"));
        assert_eq!(loopback().extract(&req).unwrap(), ip("0.0.0.3"));
    }

    #[test]
    fn declaring_the_parent_does_not_trust_loopback() {
        // Nothing inside the enclave can claim the parent's trust.
        let req = req_with(Some("127.0.0.1:1234"), Some("203.0.113.9"));
        assert_eq!(parent_trusted().extract(&req).unwrap(), ip("127.0.0.1"));
    }

    #[test]
    fn xff_from_an_untrusted_tcp_peer_is_ignored_even_naming_the_parent() {
        let req = req_with(Some("203.0.113.9:1234"), Some("0.0.0.3"));
        assert_eq!(parent_trusted().extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[test]
    fn untrusted_peer_keys_on_peer_ignoring_forged_xff() {
        let req = req_with(Some("203.0.113.9:1234"), Some("9.9.9.9"));
        assert_eq!(loopback().extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[test]
    fn trusted_peer_keys_on_the_client_the_proxy_appended() {
        // One proxy: it appends the address it accepted, so the client is the
        // rightmost entry and the forged prefix is ignored.
        let req = req_with(Some("127.0.0.1:1234"), Some("9.9.9.9, 203.0.113.9"));
        assert_eq!(loopback().extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[test]
    fn distinct_clients_through_trusted_peer_key_differently() {
        let a = req_with(Some("127.0.0.1:1"), Some("198.51.100.1"));
        let b = req_with(Some("127.0.0.1:2"), Some("198.51.100.2"));
        let extractor = loopback();
        assert_ne!(
            extractor.extract(&a).unwrap(),
            extractor.extract(&b).unwrap()
        );
    }

    #[test]
    fn empty_cidr_list_never_trusts_xff() {
        let extractor = TrustedProxyKeyExtractor::new(Vec::new()).unwrap();
        let req = req_with(Some("127.0.0.1:1234"), Some("9.9.9.9"));
        assert_eq!(extractor.extract(&req).unwrap(), ip("127.0.0.1"));
    }

    #[test]
    fn trusted_peer_without_xff_falls_back_to_peer() {
        let req = req_with(Some("127.0.0.1:1234"), None);
        assert_eq!(loopback().extract(&req).unwrap(), ip("127.0.0.1"));
    }

    #[test]
    fn missing_connect_info_is_unable_to_extract() {
        let req = req_with(None, Some("9.9.9.9"));
        assert!(matches!(
            loopback().extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }

    /// The case rightmost-only gets wrong: two declared hops in front, so the
    /// rightmost entry is the *outer proxy*, not the client. Skipping declared
    /// hops is what keeps each client in its own bucket.
    #[test]
    fn chained_trusted_proxies_are_skipped_to_reach_the_client() {
        let extractor =
            TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"])).unwrap();
        let req = req_with(
            Some("127.0.0.1:1234"),
            Some("198.51.100.7, 10.0.0.5, 10.0.0.6"),
        );
        assert_eq!(extractor.extract(&req).unwrap(), ip("198.51.100.7"));
    }

    /// An attacker prefixing the chain with addresses that *look* like declared
    /// hops still cannot reach past the entry the real proxy appended.
    #[test]
    fn forged_trusted_looking_prefix_cannot_reach_past_the_real_hop() {
        let extractor =
            TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"])).unwrap();
        let req = req_with(
            Some("127.0.0.1:1234"),
            Some("10.0.0.1, 10.0.0.2, 203.0.113.9"),
        );
        assert_eq!(extractor.extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[test]
    fn multiple_header_lines_concatenate_in_order() {
        let extractor =
            TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"])).unwrap();
        let req = req_with_all(Some("127.0.0.1:1"), vec!["198.51.100.7", "10.0.0.5"]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("198.51.100.7"));
    }

    fn assert_bad_request(result: Result<IpAddr, GovernorError>) {
        match result {
            Err(GovernorError::Other { code, .. }) => assert_eq!(code, StatusCode::BAD_REQUEST),
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    /// An unattributable chain from a trusted proxy is refused, not charged
    /// to the proxy's bucket.
    #[test]
    fn malformed_entry_is_refused() {
        let req = req_with(Some("127.0.0.1:1234"), Some("not-an-ip"));
        assert_bad_request(loopback().extract(&req));
    }

    /// A trailing comma from a sloppy proxy, or one the client sent before the
    /// proxy appended, must not end the walk — that would silently put every
    /// client back in the peer's single bucket.
    #[test]
    fn empty_entries_do_not_end_the_walk() {
        for header in ["203.0.113.9,", "9.9.9.9,, 203.0.113.9", " , 203.0.113.9"] {
            let req = req_with(Some("127.0.0.1:1234"), Some(header));
            assert_eq!(
                loopback().extract(&req).unwrap(),
                ip("203.0.113.9"),
                "{header}"
            );
        }
    }

    #[test]
    fn chain_trusted_end_to_end_falls_back_to_peer() {
        let extractor =
            TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"])).unwrap();
        let req = req_with(Some("127.0.0.1:1"), Some("10.0.0.5, 10.0.0.6"));
        assert_eq!(extractor.extract(&req).unwrap(), ip("127.0.0.1"));
    }

    #[test]
    fn absurdly_long_chain_is_refused() {
        let chain = (0..affinidi_rate_limit::MAX_FORWARDED_ENTRIES + 1)
            .map(|_| "203.0.113.9")
            .collect::<Vec<_>>()
            .join(", ");
        let req = req_with(Some("127.0.0.1:1"), Some(&chain));
        assert_bad_request(loopback().extract(&req));
    }

    #[test]
    fn port_and_bracket_forms_are_accepted() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"])).unwrap();
        for (entry, expected) in [
            ("203.0.113.9:443", "203.0.113.9"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
        ] {
            let req = req_with(Some("127.0.0.1:1"), Some(entry));
            assert_eq!(extractor.extract(&req).unwrap(), ip(expected), "{entry}");
        }
    }

    /// A dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d`. Without
    /// canonicalisation that never matches an IPv4 CIDR, and a correctly
    /// configured proxy would silently stop being trusted.
    #[test]
    fn ipv4_mapped_peer_matches_an_ipv4_cidr() {
        let req = req_with(Some("[::ffff:127.0.0.1]:1234"), Some("203.0.113.9"));
        assert_eq!(loopback().extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[tokio::test]
    async fn synthetic_connect_info_inserted_only_when_missing() {
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        async fn handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
            addr.ip().to_string()
        }

        let app = axum::Router::new()
            .route("/", get(handler))
            .layer(axum::middleware::from_fn(
                insert_default_connect_info_if_missing,
            ));

        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"127.0.0.1");
    }
}
