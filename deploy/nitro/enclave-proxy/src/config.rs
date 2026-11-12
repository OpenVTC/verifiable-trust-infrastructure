use ipnetwork::IpNetwork;
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
    /// A did:webs VTA identity's host and domain (`[tee.kms] vta_did_webs`):
    /// first boot registers the identity at its host over the host's
    /// Trust-Task HTTPS endpoint, so both must be reachable.
    pub webs_identity: Option<WebsIdentity>,
    /// Proxies whose connections to this listener are themselves trusted —
    /// the same `[server] trust_xff_cidrs` the enclave VTA reads. When the
    /// TCP peer is in this list, its `X-Forwarded-For` is a claim made by a
    /// declared proxy (e.g. an ALB) and is extended, not discarded. See
    /// `http_forward` for what this changes.
    pub trusted_upstream_cidrs: Vec<IpNetwork>,
}

/// Partial VTA config — only the fields we need.
#[derive(Debug, Deserialize, Default)]
struct VtaConfig {
    messaging: Option<MessagingConfig>,
    tee: Option<TeeConfig>,
    server: Option<ServerConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct ServerConfig {
    #[serde(default)]
    trust_xff_cidrs: Vec<String>,
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
    vta_did_webs: Option<WebsIdentity>,
}

/// `[tee.kms] vta_did_webs` — only the fields the allowlist needs. Mirrors
/// `vta_config::TeeWebsIdentityConfig`; this crate links no workspace code, so
/// it repeats the two names.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WebsIdentity {
    /// The did-hosting server's DID.
    pub server_did: String,
    /// The domain the DID is served on (`host` or `host:port`).
    pub domain: String,
}

impl ProxyConfig {
    pub fn load(config_path: &Path, cli: &super::Cli) -> Self {
        // Absence is best-effort (the proxy still works without it), but a
        // file the operator put there and got wrong is a misconfiguration,
        // not an absence — fail loudly rather than silently running with
        // trust_xff_cidrs defaulted to empty (a byte-for-byte revert to the
        // one-shared-bucket behavior this proxy exists to fix, with nothing
        // in the logs saying why).
        let vta_config = if config_path.exists() {
            let contents = std::fs::read_to_string(config_path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", config_path.display()));
            toml::from_str::<VtaConfig>(&contents)
                .unwrap_or_else(|e| panic!("failed to parse {}: {e}", config_path.display()))
        } else {
            tracing::warn!(
                "config file not found: {} — using defaults",
                config_path.display()
            );
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
        let mut allowlist_hosts: Vec<(String, u16)> =
            cli.allowlist.iter().map(|s| parse_host_port(s)).collect();

        if let Ok(hosts) = std::env::var("ALLOWLIST_HOSTS") {
            for entry in hosts.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    allowlist_hosts.push(parse_host_port(entry));
                }
            }
        }

        let webs_identity = vta_config
            .tee
            .as_ref()
            .and_then(|t| t.kms.as_ref())
            .and_then(|k| k.vta_did_webs.clone());

        let trusted_upstream_cidrs = vta_config
            .server
            .map(|s| s.trust_xff_cidrs)
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| match entry.parse::<IpNetwork>() {
                Ok(cidr) => Some(cidr),
                Err(e) => {
                    tracing::warn!("trust_xff_cidrs entry {entry:?} is not a valid CIDR: {e}");
                    None
                }
            })
            .collect();

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
            webs_identity,
            trusted_upstream_cidrs,
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
        if let Some(ref did) = self.mediator_did
            && let Some((host, port)) = extract_host_from_did(did)
        {
            tracing::info!(did = %did, host = %host, "auto-allowlisting DID host from mediator DID");
            hosts.push((host, port));
        }

        // A did:webs identity is registered at its host at first boot, over
        // the host's Trust-Task HTTPS endpoint, and resolved from its domain.
        // The host's endpoint is taken to be on its own DID's host; one served
        // elsewhere goes in ALLOWLIST_HOSTS.
        if let Some(ref webs) = self.webs_identity {
            if let Some((host, port)) = extract_host_from_did(&webs.server_did) {
                tracing::info!(did = %webs.server_did, host = %host, "auto-allowlisting the did:webs identity's hosting server");
                hosts.push((host, port));
            }
            let (host, port) = parse_host_port(&webs.domain);
            tracing::info!(domain = %webs.domain, "auto-allowlisting the did:webs identity's domain");
            hosts.push((host, port));
        }

        hosts.extend(self.allowlist_hosts.clone());
        hosts
    }
}

/// Extract the hosting server's host and port from a DID: the host segment,
/// whose port, if any, is percent-encoded (`%3A`), as every web-based method
/// spells it; 443 without one.
///
/// Supports did:web, did:webvh and did:webs:
///   did:web:example.com → (example.com, 443)
///   did:webvh:SCID:example.com%3A8080:path → (example.com, 8080)
///   did:webs:example.com:nodes:AID → (example.com, 443)
fn extract_host_from_did(did: &str) -> Option<(String, u16)> {
    let segment = if let Some(rest) = did.strip_prefix("did:web:") {
        rest.split(':').next()
    } else if let Some(rest) = did.strip_prefix("did:webvh:") {
        // did:webvh:SCID:host:path — skip SCID (first segment)
        rest.split(':').nth(1)
    } else if let Some(rest) = did.strip_prefix("did:webs:") {
        // did:webs:host[:path…]:AID — the host leads, the AID ends it.
        rest.split(':').next().filter(|_| rest.contains(':'))
    } else {
        None
    }?;
    let (host, port) = match segment
        .split_once("%3A")
        .or_else(|| segment.split_once("%3a"))
    {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (segment, 443),
    };
    (!host.is_empty()).then(|| (host.to_string(), port))
}

fn parse_host_port(s: &str) -> (String, u16) {
    if let Some((host, port)) = s.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), port);
    }
    (s.to_string(), 443)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
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
            webs_identity: None,
            trusted_upstream_cidrs: Vec::new(),
        }
    }

    #[test]
    fn host_from_web_and_webvh_dids() {
        assert_eq!(
            extract_host_from_did("did:web:example.com"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            extract_host_from_did("did:webvh:QmScid:example.com:vta"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            extract_host_from_did("did:webvh:QmScid:example.com%3A8080:vta"),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(extract_host_from_did("did:key:z6Mk"), None);
    }

    #[test]
    fn host_from_webs_dids() {
        let aid = "EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4";
        assert_eq!(
            extract_host_from_did(&format!("did:webs:did.example.com:{aid}")),
            Some(("did.example.com".into(), 443))
        );
        assert_eq!(
            extract_host_from_did(&format!("did:webs:did.example.com%3A8443:{aid}")),
            Some(("did.example.com".into(), 8443))
        );
        assert_eq!(
            extract_host_from_did(&format!("did:webs:did.example.com%3A8443:nodes:eu:{aid}")),
            Some(("did.example.com".into(), 8443))
        );
        // A host with no AID after it is not a did:webs.
        assert_eq!(extract_host_from_did("did:webs:did.example.com"), None);
        // Nor is a port that is not one.
        assert_eq!(
            extract_host_from_did(&format!("did:webs:did.example.com%3Ahttps:{aid}")),
            None
        );
    }

    /// `[tee.kms] vta_did_webs` admits the identity's host and domain: the
    /// enclave registers the DID there at first boot.
    #[test]
    fn webs_identity_allowlists_its_host_and_domain() {
        let dir = std::env::temp_dir().join(format!(
            "enclave-proxy-config-test-webs-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[tee.kms]\nregion = \"eu-west-1\"\nkey_arn = \"arn\"\n\
             [tee.kms.vta_did_webs]\nserver_did = \"did:webvh:QmScid:hosting.example.com\"\n\
             domain = \"did.example.com:8443\"\npath = \"nodes\"\n",
        )
        .unwrap();

        let cli = crate::Cli::parse_from(["enclave-proxy"]);
        let config = ProxyConfig::load(&config_path, &cli);
        let allow = config.build_allowlist();
        assert!(
            allow.contains(&("hosting.example.com".to_string(), 443)),
            "{allow:?}"
        );
        assert!(
            allow.contains(&("did.example.com".to_string(), 8443)),
            "{allow:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_webs_identity_adds_nothing() {
        let allow = proxy_config("us-east-1").build_allowlist();
        assert_eq!(allow.len(), 2, "{allow:?}");
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

    /// `trusted_upstream_cidrs` is read from the same `[server] trust_xff_cidrs`
    /// the enclave VTA itself trusts — one declaration, not two.
    #[test]
    fn trusted_upstream_cidrs_read_from_vta_server_config() {
        let dir =
            std::env::temp_dir().join(format!("enclave-proxy-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[server]\ntrust_xff_cidrs = [\"127.0.0.1/32\", \"10.0.0.0/8\"]\n",
        )
        .unwrap();

        let cli = crate::Cli::parse_from(["enclave-proxy"]);
        let config = ProxyConfig::load(&config_path, &cli);
        assert_eq!(
            config.trusted_upstream_cidrs,
            vec![
                "127.0.0.1/32".parse::<IpNetwork>().unwrap(),
                "10.0.0.0/8".parse::<IpNetwork>().unwrap(),
            ]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invalid_cidr_entries_are_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "enclave-proxy-config-test-invalid-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[server]\ntrust_xff_cidrs = [\"not-a-cidr\", \"127.0.0.1/32\"]\n",
        )
        .unwrap();

        let cli = crate::Cli::parse_from(["enclave-proxy"]);
        let config = ProxyConfig::load(&config_path, &cli);
        assert_eq!(
            config.trusted_upstream_cidrs,
            vec!["127.0.0.1/32".parse::<IpNetwork>().unwrap()]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_server_section_yields_no_trusted_upstreams() {
        let cli = crate::Cli::parse_from(["enclave-proxy"]);
        let config = ProxyConfig::load(std::path::Path::new("/nonexistent"), &cli);
        assert!(config.trusted_upstream_cidrs.is_empty());
    }

    /// A config file that *exists* but fails to parse (bad TOML syntax, here)
    /// is a misconfiguration the operator can fix, not an absence — it must
    /// panic rather than silently fall back to defaults (which would revert
    /// `trusted_upstream_cidrs` to empty with nothing in the logs saying why).
    /// Only a genuinely missing file (see the test above) gets the soft
    /// default.
    #[test]
    #[should_panic(expected = "failed to parse")]
    fn unparseable_config_file_panics_rather_than_silently_defaulting() {
        let dir = std::env::temp_dir().join(format!(
            "enclave-proxy-config-test-unparseable-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, "this is not valid toml [[[").unwrap();

        let cli = crate::Cli::parse_from(["enclave-proxy"]);
        let _ = ProxyConfig::load(&config_path, &cli);
    }
}
