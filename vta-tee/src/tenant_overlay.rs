//! Fetch the tenant-config overlay from the parent over vsock and apply it.
//!
//! Compiled **only** for `feature = "tenant-overlay"` — the `BAKE_CONFIG=false`
//! (fleet) enclave build. A `BAKE_CONFIG=true` / self-host build does not
//! include this module at all, so its binary contains no vsock config-fetch
//! code path (design note §3.1/§3.8). The parent side that serves the envelope
//! is `deploy/nitro/enclave-proxy`'s `run_config_server` (vsock:5800).
//!
//! Wire shape (design note §3.4) — the parent streams these raw bytes then
//! closes the connection:
//!
//! ```json
//! { "version": 1, "overlay": { … }, "integrity": null }
//! ```
//!
//! `overlay` is deserialized into the allowlisted, `deny_unknown_fields`
//! [`TenantConfigOverlay`]; anything outside that shape is a hard parse error.

use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{info, warn};

use vta_config::AppConfig;
use vta_config::tenant_overlay::{TenantConfigOverlay, TenantOverlayError, apply_tenant_overlay};

/// Parent instance CID (host side is always CID 3 for a Nitro enclave).
const PARENT_CID: u32 = 3;
/// vsock port the parent serves the config envelope on (matches
/// `enclave-entrypoint.sh` `VSOCK_CONFIG_PORT` and `run_config_server`).
const CONFIG_PORT: u32 = 5800;
/// Envelope wire version this build understands. An envelope stamped with any
/// other version is hard-refused (never mis-parsed).
const SUPPORTED_ENVELOPE_VERSION: u32 = 1;
/// Hard cap on the envelope read from the (untrusted) parent. The enclave rootfs
/// is RAM carved from its fixed allocation, so an unbounded read is a
/// memory-exhaustion vector — mirror the service's 1 MiB request-body cap.
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

const CONNECT_MAX_ATTEMPTS: u32 = 30;
const CONNECT_BASE_DELAY: Duration = Duration::from_millis(500);
const CONNECT_MAX_DELAY: Duration = Duration::from_secs(3);
/// Per-attempt connect timeout — guards a parent that never accepts.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Overall read timeout — guards a parent that accepts then hangs.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Failure fetching or applying the tenant-config overlay. Every variant is
/// fail-closed: on real Nitro the caller aborts the boot rather than continue
/// with an un-overlaid (placeholder) config.
#[derive(Debug)]
pub enum OverlayFetchError {
    /// Could not connect to the parent config server after bounded retries.
    Connect(String),
    /// Read failed or timed out while streaming the envelope.
    Read(String),
    /// The envelope exceeded [`MAX_ENVELOPE_BYTES`].
    TooLarge(usize),
    /// The envelope JSON did not parse (bad JSON, or an unknown field in the
    /// `deny_unknown_fields` overlay).
    Parse(String),
    /// The envelope's `version` is not [`SUPPORTED_ENVELOPE_VERSION`].
    UnsupportedVersion(u32),
    /// The overlay parsed but failed validation/application (e.g. `key_arn`
    /// account not allowlisted).
    Apply(TenantOverlayError),
}

impl std::fmt::Display for OverlayFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "vsock connect to config server failed: {e}"),
            Self::Read(e) => write!(f, "reading config envelope failed: {e}"),
            Self::TooLarge(n) => write!(
                f,
                "config envelope exceeded the {MAX_ENVELOPE_BYTES}-byte cap ({n} bytes)"
            ),
            Self::Parse(e) => write!(f, "config envelope did not parse: {e}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "config envelope version {v} is unsupported (this enclave speaks \
                 v{SUPPORTED_ENVELOPE_VERSION})"
            ),
            Self::Apply(e) => write!(f, "applying tenant overlay failed: {e}"),
        }
    }
}

impl std::error::Error for OverlayFetchError {}

/// The parent's envelope. `integrity` is reserved (design note §3.4) — the
/// config-digest attestation is the current verification mechanism.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigEnvelope {
    version: u32,
    overlay: TenantConfigOverlay,
    #[serde(default)]
    #[allow(dead_code)]
    integrity: Option<serde_json::Value>,
}

/// Parse + version-check an envelope's bytes into the typed overlay. Split out
/// from the I/O so it is unit-testable without a live vsock peer.
fn parse_envelope(bytes: &[u8]) -> Result<TenantConfigOverlay, OverlayFetchError> {
    let envelope: ConfigEnvelope =
        serde_json::from_slice(bytes).map_err(|e| OverlayFetchError::Parse(e.to_string()))?;
    if envelope.version != SUPPORTED_ENVELOPE_VERSION {
        return Err(OverlayFetchError::UnsupportedVersion(envelope.version));
    }
    Ok(envelope.overlay)
}

/// Connect to the parent config server, retrying with bounded backoff so a
/// cold-boot ordering race (enclave up before the parent binds vsock:5800)
/// isn't an outage. Gives up after ~30 attempts.
async fn connect_with_retry() -> Result<VsockStream, OverlayFetchError> {
    let addr = VsockAddr::new(PARENT_CID, CONFIG_PORT);
    let mut delay = CONNECT_BASE_DELAY;
    for attempt in 1..=CONNECT_MAX_ATTEMPTS {
        match tokio::time::timeout(CONNECT_TIMEOUT, VsockStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                if attempt > 1 {
                    info!("connected to config server on attempt {attempt}");
                }
                return Ok(stream);
            }
            Ok(Err(e)) if attempt == CONNECT_MAX_ATTEMPTS => {
                return Err(OverlayFetchError::Connect(e.to_string()));
            }
            Err(_) if attempt == CONNECT_MAX_ATTEMPTS => {
                return Err(OverlayFetchError::Connect("connect timed out".into()));
            }
            Ok(Err(e)) => warn!(
                "config server not ready on vsock:{CONFIG_PORT} \
                 (attempt {attempt}/{CONNECT_MAX_ATTEMPTS}): {e}; retrying in {delay:?}"
            ),
            Err(_) => warn!(
                "config server connect timed out \
                 (attempt {attempt}/{CONNECT_MAX_ATTEMPTS}); retrying in {delay:?}"
            ),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(CONNECT_MAX_DELAY);
    }
    unreachable!("the loop returns on the final attempt")
}

/// Read the envelope bytes to EOF with a hard size cap and read timeout.
async fn read_envelope(stream: &mut VsockStream) -> Result<Vec<u8>, OverlayFetchError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(OverlayFetchError::Read(e.to_string())),
            Err(_) => return Err(OverlayFetchError::Read("read timed out".into())),
        };
        if n == 0 {
            break; // EOF — parent finished and shut the connection.
        }
        if buf.len() + n > MAX_ENVELOPE_BYTES {
            return Err(OverlayFetchError::TooLarge(buf.len() + n));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Fetch the tenant-config overlay from the parent over vsock and apply it onto
/// the baked base `config`, in place.
///
/// Fail-closed: any connect/read/parse/version/validation failure returns `Err`,
/// and the caller aborts the boot on real Nitro rather than run with a
/// placeholder config.
pub async fn fetch_and_apply_overlay(config: &mut AppConfig) -> Result<(), OverlayFetchError> {
    info!("fetching tenant-config overlay over vsock:{CONFIG_PORT}");
    let mut stream = connect_with_retry().await?;
    let bytes = read_envelope(&mut stream).await?;
    if bytes.is_empty() {
        return Err(OverlayFetchError::Read(
            "parent served an empty envelope".into(),
        ));
    }
    let overlay = parse_envelope(&bytes)?;
    apply_tenant_overlay(config, overlay).map_err(OverlayFetchError::Apply)?;
    info!("tenant-config overlay applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/abcd-ef01";

    #[test]
    fn parses_a_well_formed_v1_envelope() {
        let env = format!(
            r#"{{"version":1,"overlay":{{"vta_name":"acme","tee_kms":{{"key_arn":"{GOOD_ARN}"}}}},"integrity":null}}"#
        );
        let overlay = parse_envelope(env.as_bytes()).expect("valid envelope");
        assert_eq!(overlay.vta_name.as_deref(), Some("acme"));
        assert_eq!(overlay.tee_kms.unwrap().key_arn, GOOD_ARN);
    }

    #[test]
    fn rejects_wrong_version() {
        let env = r#"{"version":2,"overlay":{},"integrity":null}"#;
        assert!(matches!(
            parse_envelope(env.as_bytes()),
            Err(OverlayFetchError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_overlay_with_forbidden_field() {
        // `admin_did` is not on the allowlist → deny_unknown_fields → parse error.
        let env =
            r#"{"version":1,"overlay":{"tee_kms":{"key_arn":"x","admin_did":"did:key:zEvil"}}}"#;
        assert!(matches!(
            parse_envelope(env.as_bytes()),
            Err(OverlayFetchError::Parse(_))
        ));
    }

    #[test]
    fn rejects_envelope_with_unknown_field() {
        let env = r#"{"version":1,"overlay":{},"unexpected":"value"}"#;
        assert!(matches!(
            parse_envelope(env.as_bytes()),
            Err(OverlayFetchError::Parse(_))
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            parse_envelope(b"not json"),
            Err(OverlayFetchError::Parse(_))
        ));
    }
}
