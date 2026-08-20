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
use tracing::{debug, info, warn};

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
/// Overall read deadline, spanning the whole envelope — guards a parent that
/// accepts then hangs *or* dribbles. A per-`read()` timeout does not: a parent
/// sending one byte just inside every window never trips it, so the only bound
/// left is [`MAX_ENVELOPE_BYTES`] (1 MiB ≈ 120 days at that rate) and the enclave
/// hangs in `fetch_and_apply_overlay` instead of producing the fail-closed error
/// the caller is written to act on.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// `tokio-vsock` can report a stream connected just before Nitro finishes the
/// nonblocking handshake, making the first read return `ENOTCONN`. Retry only
/// that transient state, and only *before any byte has arrived* — see
/// [`read_envelope_to_eof`]. The outer [`READ_TIMEOUT`] remains the hard
/// deadline.
const NOT_CONNECTED_RETRY_DELAY: Duration = Duration::from_millis(10);

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
    /// Declared so `deny_unknown_fields` still *requires* it here. The value is
    /// read (and enforced) by `EnvelopeVersionProbe` before this type is parsed.
    #[allow(dead_code)]
    version: u32,
    overlay: TenantConfigOverlay,
    #[serde(default)]
    #[allow(dead_code)]
    integrity: Option<serde_json::Value>,
}

/// Just the `version` field, read leniently (no `deny_unknown_fields`) so the
/// version can be established *before* the strict typed parse — see
/// [`parse_envelope`].
#[derive(Debug, Deserialize)]
struct EnvelopeVersionProbe {
    version: u32,
}

/// Parse + version-check an envelope's bytes into the typed overlay. Split out
/// from the I/O so it is unit-testable without a live vsock peer.
///
/// Version is checked **first**, via a lenient probe. Deserializing the strict
/// [`ConfigEnvelope`] up front would make any future v2 envelope that adds an
/// overlay field fail as `Parse("unknown field …")` rather than
/// `UnsupportedVersion(2)` — both fail closed, but only the latter tells the
/// operator what is actually wrong, which is the entire reason the envelope
/// carries a version at all.
fn parse_envelope(bytes: &[u8]) -> Result<TenantConfigOverlay, OverlayFetchError> {
    let probe: EnvelopeVersionProbe =
        serde_json::from_slice(bytes).map_err(|e| OverlayFetchError::Parse(e.to_string()))?;
    if probe.version != SUPPORTED_ENVELOPE_VERSION {
        return Err(OverlayFetchError::UnsupportedVersion(probe.version));
    }

    let envelope: ConfigEnvelope =
        serde_json::from_slice(bytes).map_err(|e| OverlayFetchError::Parse(e.to_string()))?;
    Ok(envelope.overlay)
}

/// Whether `bytes` contains exactly one complete JSON value. This answers only
/// the transport-framing question; [`parse_envelope`] performs the strict
/// version and allowlist checks after the read completes.
fn is_complete_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
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

/// Read the envelope bytes to EOF with a hard size cap and an overall deadline.
///
/// The timeout wraps the *whole* read, not each `read()` call — see
/// [`READ_TIMEOUT`] for why the per-call form is not a bound at all against an
/// untrusted parent.
async fn read_envelope(stream: &mut VsockStream) -> Result<Vec<u8>, OverlayFetchError> {
    match tokio::time::timeout(READ_TIMEOUT, read_envelope_to_eof(stream)).await {
        Ok(result) => result,
        Err(_) => Err(OverlayFetchError::Read(format!(
            "envelope not fully received within {READ_TIMEOUT:?}"
        ))),
    }
}

/// The unbounded-in-time inner read. Only ever called under the
/// [`read_envelope`] deadline.
///
/// `ENOTCONN` while the buffer is empty is the handshake race
/// [`NOT_CONNECTED_RETRY_DELAY`] describes. Linux AF_VSOCK may also report
/// `ENOTCONN` instead of EOF after the peer has sent its complete payload and
/// shut down. In that second case the bytes are accepted as framed only if they
/// contain one complete JSON value. A partial or malformed buffer still fails
/// closed immediately; the normal strict envelope parse follows the read.
async fn read_envelope_to_eof<R>(stream: &mut R) -> Result<Vec<u8>, OverlayFetchError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut warned_not_connected = false;
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::NotConnected && buf.is_empty() => {
                // Log once, not once per 10ms tick: a boot that spent most of
                // READ_TIMEOUT here must not look identical to one that read
                // immediately, but ~1000 identical lines is not an improvement.
                if !warned_not_connected {
                    warned_not_connected = true;
                    warn!(
                        "config server accepted but the vsock handshake is not complete yet \
                         (ENOTCONN); retrying every {NOT_CONNECTED_RETRY_DELAY:?} until the \
                         {READ_TIMEOUT:?} read deadline"
                    );
                }
                tokio::time::sleep(NOT_CONNECTED_RETRY_DELAY).await;
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotConnected && is_complete_json(&buf) => {
                debug!(
                    "config server closed vsock with ENOTCONN after a complete {}-byte envelope; treating it as EOF",
                    buf.len()
                );
                break;
            }
            Err(e) => return Err(OverlayFetchError::Read(e.to_string())),
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
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, ReadBuf};

    const GOOD_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/abcd-ef01";

    /// One scripted `poll_read` outcome. A `ScriptedReader` walks these in
    /// order; running off the end is EOF, which is how the read loop
    /// terminates.
    enum Step {
        Err(std::io::ErrorKind),
        Bytes(&'static [u8]),
    }

    /// A reader that replays a fixed script of `poll_read` outcomes, counting
    /// how many polls it served so a test can pin "the loop stopped here".
    struct ScriptedReader {
        steps: Vec<Step>,
        polls: usize,
    }

    impl ScriptedReader {
        fn new(steps: Vec<Step>) -> Self {
            Self { steps, polls: 0 }
        }
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let idx = self.polls;
            self.polls += 1;
            match self.steps.get(idx) {
                Some(Step::Err(kind)) => Poll::Ready(Err(std::io::Error::from(*kind))),
                Some(Step::Bytes(payload)) => {
                    buf.put_slice(payload);
                    Poll::Ready(Ok(()))
                }
                // Off the end of the script: EOF.
                None => Poll::Ready(Ok(())),
            }
        }
    }

    #[tokio::test]
    async fn retries_transient_not_connected_read() {
        let mut reader = ScriptedReader::new(vec![
            Step::Err(std::io::ErrorKind::NotConnected),
            Step::Bytes(b"config envelope"),
        ]);

        assert_eq!(
            read_envelope_to_eof(&mut reader).await.unwrap(),
            b"config envelope"
        );
    }

    #[tokio::test]
    async fn rejects_non_transient_read_error() {
        let mut reader = ScriptedReader::new(vec![
            Step::Err(std::io::ErrorKind::PermissionDenied),
            Step::Bytes(b"must not be read"),
        ]);

        assert!(matches!(
            read_envelope_to_eof(&mut reader).await,
            Err(OverlayFetchError::Read(_))
        ));
        assert_eq!(reader.polls, 1, "a hard error must not be retried");
    }

    /// A post-payload `ENOTCONN` is Linux AF_VSOCK's observable close behavior
    /// in some parent/enclave timing windows. It is equivalent to EOF only when
    /// the buffered bytes are already one complete JSON value.
    #[tokio::test]
    async fn accepts_not_connected_after_complete_envelope() {
        const ENVELOPE: &[u8] = br#"{"version":1,"overlay":{},"integrity":null}"#;
        let mut reader = ScriptedReader::new(vec![
            Step::Bytes(ENVELOPE),
            Step::Err(std::io::ErrorKind::NotConnected),
            Step::Bytes(b"must not be read"),
        ]);

        assert_eq!(read_envelope_to_eof(&mut reader).await.unwrap(), ENVELOPE);
        assert_eq!(
            reader.polls, 2,
            "a complete envelope must terminate at ENOTCONN"
        );
    }

    #[tokio::test]
    async fn preserves_typed_error_after_complete_invalid_envelope() {
        const ENVELOPE: &[u8] = br#"{"version":2,"overlay":{"future_field":true}}"#;
        let mut reader = ScriptedReader::new(vec![
            Step::Bytes(ENVELOPE),
            Step::Err(std::io::ErrorKind::NotConnected),
        ]);

        let bytes = read_envelope_to_eof(&mut reader)
            .await
            .expect("a complete JSON value is transport-complete");
        assert!(matches!(
            parse_envelope(&bytes),
            Err(OverlayFetchError::UnsupportedVersion(2))
        ));
    }

    #[tokio::test]
    async fn rejects_not_connected_after_partial_envelope() {
        let mut reader = ScriptedReader::new(vec![
            Step::Bytes(b"{\"version\":1,"),
            Step::Err(std::io::ErrorKind::NotConnected),
            Step::Bytes(b"must not be read"),
        ]);

        assert!(matches!(
            read_envelope_to_eof(&mut reader).await,
            Err(OverlayFetchError::Read(_))
        ));
        assert_eq!(
            reader.polls, 2,
            "partial-envelope ENOTCONN must fail fast, not retry"
        );
    }

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

    #[test]
    fn a_future_version_reports_the_version_not_a_parse_error() {
        // Regression: the strict `ConfigEnvelope` used to be deserialized before
        // the version was checked, so any future envelope that adds an overlay
        // field tripped `deny_unknown_fields` and surfaced as
        // Parse("unknown field ...") — losing the only diagnostic the version
        // field exists to provide. Both fail closed; only one is actionable.
        let v2 =
            r#"{"version":2,"overlay":{"vta_name":"acme","future_field":"x"},"integrity":null}"#;
        assert!(
            matches!(
                parse_envelope(v2.as_bytes()),
                Err(OverlayFetchError::UnsupportedVersion(2))
            ),
            "a v2 envelope must be reported as an unsupported version"
        );

        // A future top-level field gets the same treatment.
        let v3 = r#"{"version":3,"overlay":{},"signature":"..."}"#;
        assert!(matches!(
            parse_envelope(v3.as_bytes()),
            Err(OverlayFetchError::UnsupportedVersion(3))
        ));

        // A v1 envelope is still held to the strict shape.
        let v1_unknown = r#"{"version":1,"overlay":{"future_field":"x"}}"#;
        assert!(matches!(
            parse_envelope(v1_unknown.as_bytes()),
            Err(OverlayFetchError::Parse(_))
        ));

        // A missing version is a parse error, not a silent v1 assumption.
        assert!(matches!(
            parse_envelope(br#"{"overlay":{}}"#),
            Err(OverlayFetchError::Parse(_))
        ));
    }
}
