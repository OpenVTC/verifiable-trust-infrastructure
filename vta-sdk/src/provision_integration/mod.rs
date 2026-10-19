//! Provision-integration: VP-framed bootstrap requests + VC-issued admin
//! authorization for standing up VTA-managed integrations (mediators,
//! webvh-host servers, future kinds).
//!
//! See `docs/02-vta/provision-integration.md` for the design brief.
//!
//! Layering:
//! - Request: W3C VerifiablePresentation (see [`request`]) signed by the
//!   integration's ephemeral Ed25519 `client_did`. Holder presentation —
//!   no VCs inside, just the signed bootstrap ask.
//! - Credential: W3C VerifiableCredential (see [`credential`]) issued by
//!   the VTA's `vta_did`, carried inside the returned sealed bundle.
//!   Short-lived, revocation via ACL removal (see CLAUDE.md principles).
//! - Payload: [`payload::TemplateBootstrapPayload`] wraps the VC,
//!   integration key material, and first-boot config inside the
//!   existing `SealedPayloadV1::TemplateBootstrap` variant.
//!
//! Cryptosuite: `eddsa-jcs-2022` for both VP and VC. JCS (JSON
//! Canonicalization Scheme) doesn't require JSON-LD context resolution,
//! so offline verification works without a network-aware loader. The
//! custom contexts (`bootstrap-v1`, `vta-authorization-v1`) are still
//! referenced in `@context` — they document the terms for any future
//! JSON-LD-aware verifier — but they don't drive signing or
//! verification under this cryptosuite.

pub mod credential;
#[cfg(feature = "session")]
pub mod didcomm;
pub mod http;
pub mod payload;
pub mod request;
pub mod template_verify;

use thiserror::Error;

/// Errors from provision-integration operations (VP/VC sign, verify,
/// parse, envelope decode).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProvisionIntegrationError {
    /// JSON parse / structure error.
    #[error("parse error: {0}")]
    Parse(String),

    /// Cryptographic proof did not verify.
    #[error("proof verification failed: {0}")]
    BadProof(String),

    /// Credential / presentation is expired (past `validUntil`) or
    /// not-yet-valid (before `validFrom`).
    #[error("credential expired or not yet valid: {0}")]
    Expired(String),

    /// Holder DID on the presentation did not match the verification
    /// method used in the proof.
    #[error("holder/verification method mismatch: {0}")]
    HolderMismatch(String),

    /// Claims failed a shape / content check (wrong subject, missing
    /// required field, bad did:key format, etc.).
    #[error("invalid claim: {0}")]
    InvalidClaim(String),

    /// Underlying Data Integrity / secrets library error.
    #[error("data integrity error: {0}")]
    DataIntegrity(String),

    /// Sealed-transfer layer error (HPKE derivation, base64, etc.).
    #[error("sealed transfer error: {0}")]
    SealedTransfer(#[from] crate::sealed_transfer::SealedTransferError),
}

/// Canonical URL for the bootstrap-request JSON-LD context. Contents are
/// baked into the crate via `include_str!`; publishing at this URL is an
/// operational follow-up (see brief §"JSON-LD context files").
pub const BOOTSTRAP_CONTEXT_URL: &str = "https://openvtc.org/contexts/bootstrap-v1";

/// Canonical URL for the VTA-authorization credential JSON-LD context.
pub const VTA_AUTHORIZATION_CONTEXT_URL: &str = "https://openvtc.org/contexts/vta-authorization-v1";

/// W3C VC Data Model 2.0 base context.
pub const VC_V2_CONTEXT_URL: &str = "https://www.w3.org/ns/credentials/v2";

/// Raw JSON-LD for the bootstrap context (baked at compile time).
pub const BOOTSTRAP_CONTEXT_JSONLD: &str = include_str!("../../contexts/bootstrap-v1.jsonld");

/// Raw JSON-LD for the VTA-authorization context (baked at compile time).
pub const VTA_AUTHORIZATION_CONTEXT_JSONLD: &str =
    include_str!("../../contexts/vta-authorization-v1.jsonld");

pub use credential::{AdminOfClaim, OperatorOfClaim, VtaAuthorizationClaim};
pub use payload::{
    DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
    VtaTrustBundle,
};
pub use request::{
    AdminRotationAsk, BootstrapAsk, BootstrapRequest, DidTemplateRef, ProvisionRequestBuilder,
    SignedEphemeralRequest, TemplateBootstrapAsk, VerifiedBootstrapRequest,
};
