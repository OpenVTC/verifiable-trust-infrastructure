//! Proxy channels: inbound REST, outbound mediator, outbound HTTPS, log receiver.

use std::sync::Arc;

use tokio::io::AsyncBufReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{debug, error, info, warn};

/// Maximum concurrent connections per proxy channel.
/// Prevents resource exhaustion from connection flooding.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

use crate::bridge::bridge;

// ---------------------------------------------------------------------------
// [1] Inbound: TCP → vsock (clients → enclave REST API)
// ---------------------------------------------------------------------------

pub async fn run_inbound(listen_port: u16, enclave_cid: u32, vsock_port: u32) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{listen_port}")).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind TCP:{listen_port}: {e}");
            return;
        }
    };
    info!("[inbound] listening on TCP:{listen_port} → vsock CID {enclave_cid}:{vsock_port}");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let (tcp_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[inbound] accept error: {e}");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("[inbound] connection limit reached ({MAX_CONCURRENT_CONNECTIONS}), rejecting {peer}");
                drop(tcp_stream);
                continue;
            }
        };
        debug!("[inbound] connection from {peer}");

        tokio::spawn(async move {
            let _permit = permit; // held until task completes
            match VsockStream::connect(VsockAddr::new(enclave_cid, vsock_port)).await {
                Ok(vsock_stream) => {
                    if let Err(e) = bridge(tcp_stream, vsock_stream).await {
                        debug!("[inbound] bridge error: {e}");
                    }
                }
                Err(e) => {
                    warn!("[inbound] vsock connect to CID {enclave_cid}:{vsock_port} failed: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// [2] Outbound: vsock → TLS (enclave DIDComm → mediator)
// ---------------------------------------------------------------------------

use crate::resolve::{DIDResolver, MediatorEndpoint};

/// Mediator configuration — either a resolved DID or a manual host override.
pub struct MediatorConfig {
    /// Mediator DID to resolve (e.g., "did:webvh:...").
    pub did: Option<String>,
    /// Manual host override — skips DID resolution if set.
    pub host_override: Option<String>,
    /// Manual port override.
    pub port_override: Option<u16>,
    /// Embedded DID resolver (shared, initialized once at startup).
    pub resolver: Option<std::sync::Arc<DIDResolver>>,
}

pub async fn run_mediator(
    vsock_port: u32,
    mediator_config: MediatorConfig,
) {
    let tls_connector = match build_tls_connector() {
        Ok(c) => c,
        Err(e) => {
            error!("[mediator] failed to build TLS connector: {e}");
            return;
        }
    };

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[mediator] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };

    // Resolve the initial mediator endpoint
    let mut endpoint = match resolve_mediator(&mediator_config).await {
        Some(ep) => ep,
        None => {
            error!("[mediator] no mediator endpoint configured or resolved — channel disabled");
            return;
        }
    };

    info!(
        "[mediator] listening on vsock:{vsock_port} → {}:{} (TLS)",
        endpoint.host, endpoint.port
    );

    let mut consecutive_failures: u32 = 0;

    loop {
        let (vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[mediator] accept error: {e}");
                continue;
            }
        };
        debug!("[mediator] connection from vsock peer {peer:?}");

        let host = endpoint.host.clone();
        let port = endpoint.port;
        let use_tls = endpoint.tls;
        let connector = tls_connector.clone();

        // Try to connect and bridge
        let success = tokio::spawn(async move {
            if use_tls {
                let tcp_stream = match TcpStream::connect(format!("{host}:{port}")).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("[mediator] TCP connect to {host}:{port} failed: {e}");
                        return false;
                    }
                };

                let server_name = match rustls::pki_types::ServerName::try_from(host.as_str()) {
                    Ok(sn) => sn.to_owned(),
                    Err(e) => {
                        warn!("[mediator] invalid server name {host}: {e}");
                        return false;
                    }
                };
                let tls_stream = match connector.connect(server_name, tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("[mediator] TLS handshake with {host}:{port} failed: {e}");
                        return false;
                    }
                };

                if let Err(e) = bridge(vsock_stream, tls_stream).await {
                    info!("[mediator] connection to {host}:{port} ended: {e}");
                    return false;
                }
            } else {
                // Plain TCP (no TLS) — for ws:// endpoints
                let tcp_stream = match TcpStream::connect(format!("{host}:{port}")).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("[mediator] TCP connect to {host}:{port} failed: {e}");
                        return false;
                    }
                };

                if let Err(e) = bridge(vsock_stream, tcp_stream).await {
                    info!("[mediator] connection to {host}:{port} ended: {e}");
                    return false;
                }
            }
            true
        })
        .await
        .unwrap_or(false);

        if success {
            if consecutive_failures > 0 {
                info!(
                    "[mediator] connection to {}:{} succeeded (recovered after {} failures)",
                    endpoint.host, endpoint.port, consecutive_failures
                );
            }
            consecutive_failures = 0;
        } else {
            consecutive_failures += 1;
            warn!(
                "[mediator] connection failure #{consecutive_failures} to {}:{}",
                endpoint.host, endpoint.port
            );

            // After 3 consecutive failures, re-resolve the mediator DID
            // in case the endpoint URL has changed
            if consecutive_failures >= 3 && mediator_config.did.is_some() {
                info!(
                    "[mediator] {consecutive_failures} consecutive failures — re-resolving mediator DID"
                );
                if let Some(new_ep) = resolve_mediator(&mediator_config).await {
                    if new_ep.host != endpoint.host || new_ep.port != endpoint.port {
                        info!(
                            "[mediator] endpoint changed: {}:{} → {}:{} (tls={})",
                            endpoint.host, endpoint.port,
                            new_ep.host, new_ep.port, new_ep.tls
                        );
                    } else {
                        info!(
                            "[mediator] re-resolved same endpoint: {}:{} (tls={})",
                            new_ep.host, new_ep.port, new_ep.tls
                        );
                    }
                    endpoint = new_ep;
                } else {
                    warn!("[mediator] re-resolution failed — keeping current endpoint {}:{}", endpoint.host, endpoint.port);
                }
                consecutive_failures = 0;
            }
        }
    }
}

/// Resolve the mediator endpoint from config.
///
/// Priority: MEDIATOR_HOST override > DID resolution > None.
async fn resolve_mediator(config: &MediatorConfig) -> Option<MediatorEndpoint> {
    // Manual override takes priority
    if let Some(ref host) = config.host_override {
        let port = config.port_override.unwrap_or(443);
        info!("[mediator] using manual host override: {host}:{port}");
        return Some(MediatorEndpoint {
            host: host.clone(),
            port,
            tls: true,
        });
    }

    // Resolve from DID using the embedded resolver
    let did = config.did.as_ref()?;
    let resolver = config.resolver.as_ref()?;
    match resolver.resolve_mediator_endpoint(did).await {
        Ok(mut ep) => {
            // Apply port override if set
            if let Some(port) = config.port_override {
                ep.port = port;
            }
            Some(ep)
        }
        Err(e) => {
            error!("[mediator] failed to resolve DID {did}: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// [3] Outbound: vsock → TCP (enclave HTTPS → allowlisted hosts)
// ---------------------------------------------------------------------------

/// Simple HTTPS CONNECT proxy: reads the HTTP CONNECT request from the
/// enclave, validates the target against the allowlist, establishes a TCP
/// connection, and bridges bytes bidirectionally.
pub async fn run_https_proxy(
    vsock_port: u32,
    allowlist: Vec<(String, u16)>,
) {
    let allowlist = Arc::new(allowlist);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[https] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!(
        "[https] listening on vsock:{vsock_port} — {} hosts allowlisted",
        allowlist.len()
    );

    loop {
        let (vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[https] accept error: {e}");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("[https] connection limit reached ({MAX_CONCURRENT_CONNECTIONS}), rejecting vsock peer {peer:?}");
                drop(vsock_stream);
                continue;
            }
        };
        debug!("[https] connection from vsock peer {peer:?}");

        let allowlist = Arc::clone(&allowlist);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connect_request(vsock_stream, &allowlist).await {
                debug!("[https] CONNECT handler error: {e}");
            }
        });
    }
}

/// Handle an HTTP CONNECT request from the enclave.
async fn handle_connect_request(
    mut stream: VsockStream,
    allowlist: &[(String, u16)],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut buf_reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    // Parse: CONNECT host:port HTTP/1.1
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        // SECURITY: Only CONNECT requests are allowed. Reject anything else
        // to prevent request smuggling through the proxy.
        let method = parts.first().unwrap_or(&"<empty>");
        let target = parts.get(1).unwrap_or(&"<none>");
        warn!(
            "[https] rejected non-CONNECT request: {method} {target} — \
             only CONNECT tunnels are supported. If this is from the \
             AWS SDK (IMDS/KMS), check that HTTPS_PROXY is set correctly \
             and NO_PROXY includes 169.254.169.254"
        );
        drop(buf_reader);
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await?;
        return Ok(());
    }

    let target = parts[1];
    let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        (target.to_string(), 443)
    };

    // Consume remaining headers
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Check allowlist
    let allowed = allowlist
        .iter()
        .any(|(h, p)| h == &host && *p == port);

    if !allowed {
        let allowed_hosts: Vec<String> = allowlist
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect();
        warn!(
            "[https] CONNECT to {host}:{port} BLOCKED — not in allowlist. \
             This request came from inside the enclave (via HTTPS_PROXY). \
             To allow this host, add it to the proxy allowlist: \
             ./enclave-proxy {host}:{port}\n\
             Current allowlist: {allowed_hosts:?}"
        );
        drop(buf_reader);
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await?;
        return Ok(());
    }

    info!("[https] CONNECT to {host}:{port} (allowed)");

    // Establish TCP connection to the target
    let tcp_stream = TcpStream::connect(format!("{host}:{port}")).await?;

    // Send 200 OK to the enclave
    drop(buf_reader);
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Bridge raw bytes (the enclave handles TLS itself)
    bridge(stream, tcp_stream).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// [4] Outbound: vsock → TCP (enclave IMDS → parent 169.254.169.254)
// ---------------------------------------------------------------------------

/// Proxies IMDS (Instance Metadata Service) requests from the enclave to
/// the parent's real IMDS endpoint at 169.254.169.254:80.
///
/// The AWS SDK inside the enclave fetches IAM role credentials from IMDS.
/// Since the enclave has no network access, this proxy bridges the request
/// through vsock to the parent, which can reach the real IMDS.
pub async fn run_imds(vsock_port: u32) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[imds] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!("[imds] listening on vsock:{vsock_port} → 169.254.169.254:80");

    loop {
        let (vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[imds] accept error: {e}");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("[imds] connection limit reached, rejecting vsock peer {peer:?}");
                drop(vsock_stream);
                continue;
            }
        };
        debug!("[imds] connection from vsock peer {peer:?}");

        tokio::spawn(async move {
            let _permit = permit;
            match TcpStream::connect("169.254.169.254:80").await {
                Ok(tcp_stream) => {
                    if let Err(e) = bridge(vsock_stream, tcp_stream).await {
                        debug!("[imds] bridge error: {e}");
                    }
                }
                Err(e) => {
                    warn!("[imds] failed to connect to 169.254.169.254:80: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// [6] Outbound: vsock → TCP (enclave DID resolver → sidecar)
// ---------------------------------------------------------------------------

/// Proxies DID resolver WebSocket connections from the enclave to the
/// affinidi-did-resolver-cache-server sidecar running on the parent.
///
/// The VTA's DID resolver SDK connects via WebSocket to ws://127.0.0.1:4445.
/// socat inside the enclave bridges that to vsock:5600. This channel bridges
/// vsock:5600 to the local sidecar at localhost:resolver_port.
pub async fn run_resolver(vsock_port: u32, resolver_port: u16) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[resolver] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!("[resolver] listening on vsock:{vsock_port} → localhost:{resolver_port} (DID resolver sidecar)");

    loop {
        let (vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[resolver] accept error: {e}");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("[resolver] connection limit reached, rejecting vsock peer {peer:?}");
                drop(vsock_stream);
                continue;
            }
        };
        debug!("[resolver] connection from vsock peer {peer:?}");

        tokio::spawn(async move {
            let _permit = permit;
            match TcpStream::connect(format!("127.0.0.1:{resolver_port}")).await {
                Ok(tcp_stream) => {
                    if let Err(e) = bridge(vsock_stream, tcp_stream).await {
                        debug!("[resolver] bridge error: {e}");
                    }
                }
                Err(e) => {
                    warn!("[resolver] failed to connect to localhost:{resolver_port}: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// [7] Log receiver: vsock → stdout (enclave logs → parent console)
// ---------------------------------------------------------------------------

/// Receive log lines from the enclave over vsock and print them to stdout.
///
/// Each line is printed with a `[vta]` prefix so enclave logs are clearly
/// distinguishable from the proxy's own tracing output. The listener
/// accepts connections in a loop so the enclave can reconnect after restarts.
pub(crate) async fn run_log_receiver(vsock_port: u32) {
    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[logs] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!("[logs] listening on vsock:{vsock_port} for enclave log stream");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[logs] accept error: {e}");
                continue;
            }
        };
        info!("[logs] enclave log stream connected");

        // The VTA sends a heartbeat every 15 seconds when idle.
        // If we don't receive anything for 45 seconds (3 missed heartbeats),
        // the connection is dead (enclave terminated without clean EOF).
        const DEAD_CONNECTION_TIMEOUT: std::time::Duration =
            std::time::Duration::from_secs(45);

        let reader = tokio::io::BufReader::new(stream);
        let mut lines = reader.lines();
        loop {
            match tokio::time::timeout(DEAD_CONNECTION_TIMEOUT, lines.next_line()).await {
                Ok(Ok(Some(line))) => {
                    // Filter out heartbeat lines — don't print them
                    if line != "__heartbeat__" {
                        println!("[vta] {line}");
                    }
                }
                Ok(Ok(None)) => {
                    // Clean EOF — enclave closed the connection
                    break;
                }
                Ok(Err(e)) => {
                    warn!("[logs] read error: {e}");
                    break;
                }
                Err(_) => {
                    // No data for 45s (3 missed heartbeats) — connection is dead
                    warn!("[logs] no heartbeat received for {}s — connection dead",
                        DEAD_CONNECTION_TIMEOUT.as_secs());
                    break;
                }
            }
        }
        warn!("[logs] enclave log stream disconnected — waiting for reconnect");
    }
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

fn build_tls_connector() -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// [0] Config: vsock → file (parent → enclave un-baked config envelope)
// ---------------------------------------------------------------------------

/// Serves the un-baked tenant config envelope to the enclave over vsock.
///
/// The enclave connects on first boot, reads the envelope
/// (`{ "version":1, "overlay":{ … }, "integrity":null }` — a small, typed,
/// allowlisted tenant overlay; see
/// `docs/05-design-notes/tenant-config-allowlist.md` §3.4), parses + validates
/// it in-process, and applies it onto the baked fleet-policy base config before
/// starting the VTA. The file is re-read per connection so a rotated envelope is
/// picked up on the enclave's next boot, and each connection is served by its
/// own task so the enclave can reconnect after a boot race or restart.
///
/// This side just streams the envelope bytes; it is shape-agnostic (it does not
/// parse the JSON), so it is unchanged from the earlier whole-config envelope —
/// only the file's contents differ (a small overlay, not a whole config.toml).
/// The shell equivalent is
/// `socat -U VSOCK-LISTEN:PORT,fork OPEN:envelope,rdonly` in `parent-proxy.sh`.
pub async fn run_config_server(vsock_port: u32, envelope_path: std::path::PathBuf) {
    use tokio::io::AsyncWriteExt;

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[config] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!("[config] listening on vsock:{vsock_port} → {}", envelope_path.display());

    loop {
        let (mut vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[config] accept error: {e}");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("[config] connection limit reached, rejecting vsock peer {peer:?}");
                drop(vsock_stream);
                continue;
            }
        };
        debug!("[config] connection from vsock peer {peer:?}");

        let path = envelope_path.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Re-read per connection (tiny boot-time file) so a rotated envelope
            // is served on the enclave's next boot.
            match std::fs::read(&path) {
                Ok(bytes) => {
                    if let Err(e) = vsock_stream.write_all(&bytes).await {
                        debug!("[config] write to vsock peer {peer:?} failed: {e}");
                    }
                    // Fully-qualified: VsockStream also has an inherent
                    // `shutdown(Shutdown)`; we want the async AsyncWriteExt one.
                    let _ = AsyncWriteExt::shutdown(&mut vsock_stream).await;
                    debug!("[config] served {} bytes to vsock peer {peer:?}", bytes.len());
                }
                Err(e) => {
                    error!("[config] failed to read envelope {}: {e}", path.display());
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_connect_target() {
        // Verify host:port parsing logic used in handle_connect_request
        let target = "kms.us-east-1.amazonaws.com:443";
        let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (target.to_string(), 443)
        };
        assert_eq!(host, "kms.us-east-1.amazonaws.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_target_no_port() {
        let target = "example.com";
        let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (target.to_string(), 443)
        };
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn allowlist_check() {
        let allowlist: Vec<(String, u16)> = vec![
            ("kms.us-east-1.amazonaws.com".into(), 443),
            ("mediator.example.com".into(), 443),
        ];

        // Allowed
        assert!(allowlist.iter().any(|(h, p)| h == "kms.us-east-1.amazonaws.com" && *p == 443));
        // Not allowed
        assert!(!allowlist.iter().any(|(h, p)| h == "evil.com" && *p == 443));
        // Wrong port
        assert!(!allowlist.iter().any(|(h, p)| h == "kms.us-east-1.amazonaws.com" && *p == 8080));
    }
}
