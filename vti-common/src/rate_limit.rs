//! Client-IP attribution for the per-IP rate limiters.
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
//! Every uncertainty resolves to the peer, which is the un-spoofable value:
//! no `ConnectInfo`, an untrusted peer, a malformed entry, an absurdly long
//! chain, or a chain that is trusted end to end. Falling back costs a shared
//! bucket; guessing costs the limiter.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderName, Request};
use ipnetwork::IpNetwork;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Upper bound on entries considered across all `X-Forwarded-For` headers.
///
/// A real chain is two or three hops. A header long enough to exceed this is
/// either a misconfiguration or someone probing the parser, and in both cases
/// falling back to the peer is the answer — so this is a fail-closed cap, not
/// a truncation.
const MAX_FORWARDED_ENTRIES: usize = 64;

/// Charges a request to the client IP, reading `X-Forwarded-For` only when the
/// socket peer is one of `trusted_cidrs`.
///
/// An empty list is the safe default and is exactly equivalent to
/// `PeerIpKeyExtractor`: nothing is trusted, so the header is never read.
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
    trusted_cidrs: Vec<IpNetwork>,
}

impl TrustedProxyKeyExtractor {
    pub fn new(trusted_cidrs: Vec<IpNetwork>) -> Self {
        Self { trusted_cidrs }
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    /// The rightmost entry that isn't a declared proxy, or `None` to fall back
    /// to the peer. `None` covers every uncertainty: a malformed entry, a
    /// non-ASCII header, an over-long chain, or a chain that is trusted the
    /// whole way down.
    fn client_from_chain(&self, headers: &HeaderMap) -> Option<IpAddr> {
        // Multiple header lines concatenate in order, so collect before
        // walking — the rightmost entry of the *last* line is the newest hop.
        let mut entries: Vec<&str> = Vec::new();
        for value in headers.get_all(X_FORWARDED_FOR) {
            let value = value.to_str().ok()?;
            // Empty entries are dropped rather than treated as malformed. A
            // proxy that emits a trailing comma, or a client that sent one
            // before the proxy appended, would otherwise end the walk at an
            // unparseable entry and put every client back in one bucket. It
            // gives an attacker nothing: whatever they wrote is left of the
            // entry the proxy appended, so the walk stops before reaching it.
            for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                if entries.len() == MAX_FORWARDED_ENTRIES {
                    return None;
                }
                entries.push(entry);
            }
        }

        for entry in entries.iter().rev() {
            let ip = parse_forwarded_ip(entry)?;
            if !self.is_trusted(ip) {
                return Some(ip);
            }
        }
        None
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<IpAddr, GovernorError> {
        // No peer means no un-spoofable anchor, so there is nothing to
        // attribute the request to. Refusing is the only safe answer —
        // passing it through would be an unmetered request.
        let peer = peer_ip(req).ok_or(GovernorError::UnableToExtractKey)?;
        if !self.is_trusted(peer) {
            return Ok(peer);
        }
        Ok(self.client_from_chain(req.headers()).unwrap_or(peer))
    }
}

fn peer_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| canonical(ci.0.ip()))
}

/// One `X-Forwarded-For` entry. The specification says a bare address, but
/// proxies in the wild also emit `addr:port` and `[v6]`/`[v6]:port`, and a
/// dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d` — which would
/// otherwise never match an IPv4 CIDR. Accept all of them, canonically.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Some(canonical(addr.ip()));
    }
    let bracketed = entry.strip_prefix('[')?.strip_suffix(']')?;
    bracketed.parse::<IpAddr>().ok().map(canonical)
}

/// Unwrap an IPv4-mapped IPv6 address so it matches an IPv4 CIDR.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
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
        TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]))
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
        let extractor = TrustedProxyKeyExtractor::new(Vec::new());
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
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"]));
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
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"]));
        let req = req_with(
            Some("127.0.0.1:1234"),
            Some("10.0.0.1, 10.0.0.2, 203.0.113.9"),
        );
        assert_eq!(extractor.extract(&req).unwrap(), ip("203.0.113.9"));
    }

    #[test]
    fn multiple_header_lines_concatenate_in_order() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"]));
        let req = req_with_all(Some("127.0.0.1:1"), vec!["198.51.100.7", "10.0.0.5"]);
        assert_eq!(extractor.extract(&req).unwrap(), ip("198.51.100.7"));
    }

    #[test]
    fn malformed_entry_falls_back_to_peer() {
        let req = req_with(Some("127.0.0.1:1234"), Some("not-an-ip"));
        assert_eq!(loopback().extract(&req).unwrap(), ip("127.0.0.1"));
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
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32", "10.0.0.0/8"]));
        let req = req_with(Some("127.0.0.1:1"), Some("10.0.0.5, 10.0.0.6"));
        assert_eq!(extractor.extract(&req).unwrap(), ip("127.0.0.1"));
    }

    #[test]
    fn absurdly_long_chain_falls_back_to_peer() {
        let chain = (0..MAX_FORWARDED_ENTRIES + 1)
            .map(|_| "203.0.113.9")
            .collect::<Vec<_>>()
            .join(", ");
        let req = req_with(Some("127.0.0.1:1"), Some(&chain));
        assert_eq!(loopback().extract(&req).unwrap(), ip("127.0.0.1"));
    }

    #[test]
    fn port_and_bracket_forms_are_accepted() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]));
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
