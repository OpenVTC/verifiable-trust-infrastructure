use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Proxy configuration, read from the VTA's config.toml.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Mediator DID (resolved via DID resolver to get the endpoint).
    pub mediator_did: Option<String>,
    /// Manual mediator host override (skips DID resolution).
    pub mediator_host_override: Option<String>,
    /// Mediator port override (default: from resolved URL, or 443).
    pub mediator_port_override: Option<u16>,
    /// KMS region (for allowlisting kms.<region>.amazonaws.com).
    pub kms_region: String,
    /// Enclave CID (auto-detected or from CLI).
    pub enclave_cid: u32,
    /// External listen port for inbound REST API.
    pub listen_port: u16,
    /// Vsock port assignments.
    pub vsock_inbound_port: u32,
    pub vsock_mediator_port: u32,
    pub vsock_https_port: u32,
    pub vsock_imds_port: u32,
    /// Extra hosts to allowlist for HTTPS proxy.
    pub allowlist_hosts: Vec<(String, u16)>,
    /// Vsock port for persistent storage proxy.
    pub vsock_storage_port: u32,
    /// Directory for the persistent key-value store (on parent EBS).
    pub storage_data_dir: PathBuf,
}

/// Partial VTA config — only the fields we need.
#[derive(Debug, Deserialize, Default)]
struct VtaConfig {
    messaging: Option<MessagingConfig>,
    tee: Option<TeeConfig>,
}

#[derive(Debug, Deserialize)]
struct MessagingConfig {
    mediator_did: Option<String>,
    /// Manual override — skips DID resolution if set.
    mediator_host: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TeeConfig {
    kms: Option<KmsConfig>,
}

#[derive(Debug, Deserialize)]
struct KmsConfig {
    region: Option<String>,
}

impl ProxyConfig {
    pub fn load(config_path: &Path, cli: &super::Cli) -> Self {
        // Parse VTA config.toml (best-effort — proxy still works without it)
        let vta_config = if config_path.exists() {
            let contents = std::fs::read_to_string(config_path).unwrap_or_default();
            toml::from_str::<VtaConfig>(&contents).unwrap_or_default()
        } else {
            tracing::warn!("config file not found: {} — using defaults", config_path.display());
            VtaConfig::default()
        };

        // Mediator DID from config
        let mediator_did = std::env::var("MEDIATOR_DID").ok().or_else(|| {
            vta_config
                .messaging
                .as_ref()
                .and_then(|m| m.mediator_did.clone())
        });

        // Manual host override (env var > config > None)
        let mediator_host_override = std::env::var("MEDIATOR_HOST").ok().or_else(|| {
            vta_config
                .messaging
                .as_ref()
                .and_then(|m| m.mediator_host.clone())
        });

        let mediator_port_override = std::env::var("MEDIATOR_PORT")
            .ok()
            .and_then(|p| p.parse().ok());

        let kms_region = std::env::var("AWS_REGION").ok().unwrap_or_else(|| {
            vta_config
                .tee
                .as_ref()
                .and_then(|t| t.kms.as_ref())
                .and_then(|k| k.region.clone())
                .unwrap_or_else(|| "us-east-1".to_string())
        });

        let listen_port = std::env::var("LISTEN_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(cli.listen_port);

        // Parse extra allowlisted hosts
        let mut allowlist_hosts: Vec<(String, u16)> = cli
            .allowlist
            .iter()
            .map(|s| parse_host_port(s))
            .collect();

        if let Ok(hosts) = std::env::var("ALLOWLIST_HOSTS") {
            for entry in hosts.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    allowlist_hosts.push(parse_host_port(entry));
                }
            }
        }

        ProxyConfig {
            mediator_did,
            mediator_host_override,
            mediator_port_override,
            kms_region,
            enclave_cid: cli.enclave_cid,
            listen_port,
            vsock_inbound_port: cli.vsock_inbound,
            vsock_mediator_port: cli.vsock_mediator,
            vsock_https_port: cli.vsock_https,
            vsock_imds_port: cli.vsock_imds,
            allowlist_hosts,
            vsock_storage_port: cli.vsock_storage,
            storage_data_dir: cli.storage_data_dir.clone(),
        }
    }

    /// Build the full allowlist including default + DID hosts + extras.
    ///
    /// Automatically extracts hostnames from the mediator DID so the
    /// enclave's TDK can resolve the DID via the HTTPS proxy.
    pub fn build_allowlist(&self) -> Vec<(String, u16)> {
        // AWS service endpoints the enclave always needs, derived from the tenant
        // KMS region:
        //   - kms.<region>       — attestation-gated secret bootstrap (seed/JWT).
        //   - dynamodb.<region>  — the anti-rollback anchor counter. The anchor is
        //     fail-closed: the enclave's first strongly-consistent GetItem (and the
        //     first-boot PutItem / conditional UpdateItem) must reach DynamoDB, or
        //     VTA startup aborts. This lives here (not in each deployment's extra
        //     hosts) because the DynamoDB anchor is VTI's own internal egress
        //     dependency and the region is already derived from the overlay ARN.
        let mut hosts = vec![
            (format!("kms.{}.amazonaws.com", self.kms_region), 443),
            (format!("dynamodb.{}.amazonaws.com", self.kms_region), 443),
        ];

        // Add manual mediator host if set
        if let Some(ref mh) = self.mediator_host_override {
            let port = self.mediator_port_override.unwrap_or(443);
            hosts.push((mh.clone(), port));
        }

        // Auto-add DID hosting servers from the mediator DID.
        // The enclave's TDK resolves the mediator DID via HTTPS, so
        // the hosting server must be in the allowlist.
        if let Some(ref did) = self.mediator_did {
            if let Some(host) = extract_host_from_did(did) {
                tracing::info!(did = %did, host = %host, "auto-allowlisting DID host from mediator DID");
                hosts.push((host, 443));
            }
        }

        hosts.extend(self.allowlist_hosts.clone());
        hosts
    }
}

/// Extract the hosting server hostname from a DID.
///
/// Supports did:web and did:webvh:
///   did:web:example.com → example.com
///   did:webvh:SCID:example.com:path → example.com
fn extract_host_from_did(did: &str) -> Option<String> {
    if let Some(rest) = did.strip_prefix("did:web:") {
        Some(rest.split('%').next().unwrap_or(rest)
            .split(':').next().unwrap_or(rest)
            .to_string())
    } else if let Some(rest) = did.strip_prefix("did:webvh:") {
        // did:webvh:SCID:host:path — skip SCID (first segment)
        rest.split(':').nth(1).map(|segment| {
            segment.split('%').next().unwrap_or(segment).to_string()
        })
    } else {
        None
    }
}

fn parse_host_port(s: &str) -> (String, u16) {
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (s.to_string(), 443)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A minimal ProxyConfig for allowlist tests: a region, no mediator, no extras.
    fn proxy_config(kms_region: &str) -> ProxyConfig {
        ProxyConfig {
            mediator_did: None,
            mediator_host_override: None,
            mediator_port_override: None,
            kms_region: kms_region.to_string(),
            enclave_cid: 16,
            listen_port: 8080,
            vsock_inbound_port: 5100,
            vsock_mediator_port: 5200,
            vsock_https_port: 5300,
            vsock_imds_port: 5400,
            allowlist_hosts: Vec::new(),
            vsock_storage_port: 5500,
            storage_data_dir: PathBuf::from("/tmp/vta-store"),
        }
    }

    #[test]
    fn allowlist_contains_kms_and_dynamodb_for_the_kms_region() {
        let allow = proxy_config("ap-southeast-1").build_allowlist();
        assert!(
            allow.contains(&("kms.ap-southeast-1.amazonaws.com".to_string(), 443)),
            "KMS endpoint must be allowlisted: {allow:?}"
        );
        // The anti-rollback anchor (DynamoDB) is fail-closed; without this the
        // enclave's GetItem/PutItem/UpdateItem are blocked with HTTP 403 and boot
        // aborts.
        assert!(
            allow.contains(&("dynamodb.ap-southeast-1.amazonaws.com".to_string(), 443)),
            "DynamoDB anchor endpoint must be allowlisted: {allow:?}"
        );
    }

    #[test]
    fn allowlist_endpoints_track_the_derived_kms_region() {
        let allow = proxy_config("us-east-1").build_allowlist();
        assert!(allow.contains(&("kms.us-east-1.amazonaws.com".to_string(), 443)));
        assert!(allow.contains(&("dynamodb.us-east-1.amazonaws.com".to_string(), 443)));
    }
}

