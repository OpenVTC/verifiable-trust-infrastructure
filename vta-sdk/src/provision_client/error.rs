//! Errors for the integration-side provisioning workflow.

use std::path::PathBuf;

use crate::error::VtaError;
use crate::provision_integration::ProvisionIntegrationError;
use crate::sealed_transfer::SealedTransferError;

/// Errors returned by the provision-client surface. Public types in this
/// module return `Result<T, ProvisionError>` rather than `anyhow::Result`;
/// the only place `anyhow` is permitted is inside [`super::driver`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProvisionError {
    /// did:key generation or private-key extraction failed.
    #[error("did:key generation failed: {0}")]
    DidKeyGeneration(String),

    /// I/O failure reading or writing a setup-key file.
    #[error("setup key I/O at {}: {source}", path.display())]
    SetupKeyIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Setup-key file present but not parseable as the expected JSON shape.
    #[error("setup key parse at {}: {source}", path.display())]
    SetupKeyParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// Setup-key file has a `version` field we don't understand.
    #[error("unsupported setup-key version {version} in {}", path.display())]
    UnsupportedSetupKeyVersion { path: PathBuf, version: u8 },

    /// Generic JSON serialization failure (no path context).
    #[error("serialization failed: {0}")]
    Serialization(serde_json::Error),

    /// Setup key's multibase could not be decoded into a 32-byte seed.
    /// Indicates corruption of the on-disk setup-key file — the fix is
    /// to regenerate.
    #[error("setup key is malformed: {0}")]
    SetupKeyMalformed(String),

    /// Could not build the `DIDCommSession` to the VTA through its
    /// mediator. Wrapped SDK error includes the exact failure (DID
    /// resolution, WebSocket handshake, secrets insertion).
    #[error("could not open DIDComm session to VTA: {0}")]
    SessionOpen(String),

    /// VP construction or signing failed. Callers hitting this indicate
    /// a library bug or a broken signing-key invariant.
    #[error("could not build VP: {0}")]
    VpSign(#[from] ProvisionIntegrationError),

    /// The VTA rejected the request or the round-trip produced a
    /// transport-level error. `Forbidden` here usually means the ACL
    /// registration did not land for the setup DID (re-run
    /// `pnm acl create` and retry).
    #[error("provision-integration call failed: {0}")]
    Rpc(#[from] VtaError),

    /// The armored reply could not be parsed or did not contain
    /// exactly one bundle. Either a malformed VTA response or
    /// corruption in transit.
    #[error("sealed reply could not be decoded: {0}")]
    Armor(String),

    /// Opening the HPKE bundle failed. Most common cause: the setup
    /// key's X25519 derivation does not pair with the VTA's seal
    /// recipient (shouldn't happen because the VTA derived the
    /// recipient from the VP's `holder` — fire if it does).
    #[error("could not open sealed bundle: {0}")]
    Open(#[from] SealedTransferError),

    /// The payload was not a `TemplateBootstrap` variant — unexpected
    /// given we asked for that shape.
    #[error("sealed payload was the wrong variant (expected TemplateBootstrap)")]
    WrongPayload,

    /// VTA DID could not be resolved to a transport endpoint, and no
    /// fallback URL could be derived from the DID string.
    #[error("resolve {vta_did}: {message}")]
    Resolve { vta_did: String, message: String },

    /// The orchestration runner ended without emitting a terminal event
    /// (the channel was dropped before a `Connected` or `Failed` event
    /// arrived). Indicates a wiring bug — the runner should always emit
    /// a terminal event on every code path.
    #[error("workflow exited without a terminal event")]
    WorkflowAbandoned,

    /// The runner emitted a terminal `VtaEvent::Failed`. The string is
    /// operator-facing and ready to render.
    #[error("workflow failed: {0}")]
    WorkflowFailed(String),

    /// Generic I/O error not tied to a specific setup-key path
    /// (e.g. a writer error from the headless driver).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
