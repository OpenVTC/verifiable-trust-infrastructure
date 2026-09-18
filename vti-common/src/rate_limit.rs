use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::Request;
use ipnetwork::IpNetwork;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted_cidrs: Vec<IpNetwork>,
}

impl TrustedProxyKeyExtractor {
    pub fn new(trusted_cidrs: Vec<IpNetwork>) -> Self {
        Self { trusted_cidrs }
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<IpAddr, GovernorError> {
        let peer = peer_ip(req).ok_or(GovernorError::UnableToExtractKey)?;
        if self.trusted_cidrs.iter().any(|cidr| cidr.contains(peer))
            && let Ok(rightmost) = client_ip::rightmost_x_forwarded_for(req.headers())
        {
            return Ok(rightmost);
        }
        Ok(peer)
    }
}

fn peer_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

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
        let mut builder = Request::builder().uri("/");
        if let Some(xff) = xff {
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

    #[test]
    fn untrusted_peer_keys_on_peer_ignoring_forged_xff() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]));
        let req = req_with(Some("203.0.113.9:1234"), Some("9.9.9.9"));
        assert_eq!(
            extractor.extract(&req).unwrap(),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_keys_on_rightmost_xff() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]));
        let req = req_with(Some("127.0.0.1:1234"), Some("9.9.9.9, 203.0.113.9"));
        assert_eq!(
            extractor.extract(&req).unwrap(),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn distinct_clients_through_trusted_peer_key_differently() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]));
        let a = req_with(Some("127.0.0.1:1"), Some("198.51.100.1"));
        let b = req_with(Some("127.0.0.1:2"), Some("198.51.100.2"));
        assert_ne!(
            extractor.extract(&a).unwrap(),
            extractor.extract(&b).unwrap()
        );
    }

    #[test]
    fn empty_cidr_list_never_trusts_xff() {
        let extractor = TrustedProxyKeyExtractor::new(Vec::new());
        let req = req_with(Some("127.0.0.1:1234"), Some("9.9.9.9"));
        assert_eq!(
            extractor.extract(&req).unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_without_xff_falls_back_to_peer() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]));
        let req = req_with(Some("127.0.0.1:1234"), None);
        assert_eq!(
            extractor.extract(&req).unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn missing_connect_info_is_unable_to_extract() {
        let extractor = TrustedProxyKeyExtractor::new(cidrs(&["127.0.0.1/32"]));
        let req = req_with(None, Some("9.9.9.9"));
        assert!(matches!(
            extractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
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
