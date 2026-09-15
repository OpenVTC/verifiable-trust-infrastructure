//! Resolve a DID using the embedded Affinidi DID resolver and extract service endpoints.
//!
//! Uses `affinidi-did-resolver-cache-sdk` for local DID resolution — no external
//! resolver service needed. Supports did:key, did:web, did:webvh, and other methods.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use tracing::{debug, info, warn};

/// Resolved mediator endpoint.
#[derive(Debug, Clone)]
pub struct MediatorEndpoint {
    pub host: String,
    pub port: u16,
    /// Whether the endpoint uses TLS (wss:// or https://).
    pub tls: bool,
}

/// DID resolver wrapper — holds a lazily-initialized DIDCacheClient.
pub struct DIDResolver {
    client: DIDCacheClient,
}

impl DIDResolver {
    /// Initialize the embedded DID resolver.
    pub async fn new() -> Result<Self, String> {
        let config = DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config)
            .await
            .map_err(|e| format!("DID resolver init failed: {e}"))?;
        info!("embedded Affinidi DID resolver initialized");
        Ok(Self { client })
    }

    /// Resolve a mediator DID and extract the DIDComm messaging endpoint.
    ///
    /// Looks for a `DIDCommMessaging` service with a `serviceEndpoint` URI.
    pub async fn resolve_mediator_endpoint(
        &self,
        mediator_did: &str,
    ) -> Result<MediatorEndpoint, String> {
        info!(did = mediator_did, "resolving mediator DID");

        let resolved = self
            .client
            .resolve(mediator_did)
            .await
            .map_err(|e| format!("DID resolution failed for {mediator_did}: {e}"))?;

        let services = &resolved.doc.service;

        info!(
            did = mediator_did,
            service_count = services.len(),
            "scanning DID document services for DIDCommMessaging"
        );

        for (i, svc) in services.iter().enumerate() {
            let svc_id = svc.id.as_ref().map(|u| u.as_str()).unwrap_or("(no id)");
            let has_didcomm = svc.type_.iter().any(|t| t == "DIDCommMessaging");

            debug!(
                index = i,
                id = svc_id,
                types = ?svc.type_,
                "examining service"
            );

            if !has_didcomm {
                debug!(index = i, id = svc_id, "not DIDCommMessaging — skipping");
                continue;
            }

            // Try to extract the endpoint URI
            // get_uri() returns Option<String> — the primary URI
            if let Some(uri) = svc.service_endpoint.get_uri() {
                let uri = uri.trim_matches('"').to_string();
                info!(
                    did = mediator_did,
                    service_id = svc_id,
                    endpoint = %uri,
                    "found DIDCommMessaging endpoint"
                );
                let ep = parse_endpoint_url(&uri)?;
                info!(
                    host = %ep.host,
                    port = ep.port,
                    tls = ep.tls,
                    "parsed mediator endpoint"
                );
                return Ok(ep);
            }

            // Try get_uris() for array-style endpoints
            let uris = svc.service_endpoint.get_uris();
            if !uris.is_empty() {
                let uri = uris[0].trim_matches('"').to_string();
                info!(
                    did = mediator_did,
                    service_id = svc_id,
                    endpoint = %uri,
                    uri_count = uris.len(),
                    "found DIDCommMessaging endpoint (from array)"
                );
                let ep = parse_endpoint_url(&uri)?;
                info!(
                    host = %ep.host,
                    port = ep.port,
                    tls = ep.tls,
                    "parsed mediator endpoint"
                );
                return Ok(ep);
            }

            warn!(
                index = i,
                id = svc_id,
                "DIDCommMessaging service found but could not extract endpoint URI"
            );
        }

        // Log all service types found to help diagnose
        let all_types: Vec<&str> = services
            .iter()
            .flat_map(|s| s.type_.iter().map(|t| t.as_str()))
            .collect();

        Err(format!(
            "no DIDCommMessaging service with endpoint found in DID document for {mediator_did}. \
             Services present: {all_types:?}"
        ))
    }
}

/// Parse a WebSocket or HTTPS URL into host, port, and TLS flag.
fn parse_endpoint_url(url: &str) -> Result<MediatorEndpoint, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("invalid endpoint URL (no scheme): {url}"))?;

    let tls = match scheme {
        "wss" | "https" => true,
        "ws" | "http" => false,
        _ => {
            warn!(
                scheme,
                url, "unknown scheme in mediator endpoint, assuming TLS"
            );
            true
        }
    };

    // Split host:port from path
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(if tls { 443 } else { 80 });
        (h.to_string(), port)
    } else {
        (host_port.to_string(), if tls { 443 } else { 80 })
    };

    if host.is_empty() {
        return Err(format!("empty host in endpoint URL: {url}"));
    }

    Ok(MediatorEndpoint { host, port, tls })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wss_endpoint() {
        let ep = parse_endpoint_url("wss://mediator.example.com/ws").unwrap();
        assert_eq!(ep.host, "mediator.example.com");
        assert_eq!(ep.port, 443);
        assert!(ep.tls);
    }

    #[test]
    fn test_parse_https_with_port() {
        let ep = parse_endpoint_url("https://mediator.example.com:8443/didcomm").unwrap();
        assert_eq!(ep.host, "mediator.example.com");
        assert_eq!(ep.port, 8443);
        assert!(ep.tls);
    }

    #[test]
    fn test_parse_ws_no_tls() {
        let ep = parse_endpoint_url("ws://localhost:4443").unwrap();
        assert_eq!(ep.host, "localhost");
        assert_eq!(ep.port, 4443);
        assert!(!ep.tls);
    }

    #[test]
    fn test_parse_host_only() {
        let ep = parse_endpoint_url("wss://mediator.example.com").unwrap();
        assert_eq!(ep.host, "mediator.example.com");
        assert_eq!(ep.port, 443);
        assert!(ep.tls);
    }
}
