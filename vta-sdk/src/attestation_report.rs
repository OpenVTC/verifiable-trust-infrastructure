//! The `POST /attestation/config-report` wire response.
//!
//! This is the **unverified** wire form the VTA service serializes and an
//! external consumer deserializes. It is intentionally dependency-light (serde
//! only) so it is available without the `attest-verify` verifier stack; the
//! verification methods (`ConfigAttestationReport::verify` /
//! `ConfigAttestationReport::authenticate`) are added in the `attestation`
//! module under the `attest-verify` feature.
//!
//! The service (`vta-service`) constructs and serializes THIS shared type rather
//! than maintaining a private duplicate, so the type the endpoint emits and the
//! type a consumer verifies are one and the same.

use serde::{Deserialize, Serialize};

/// A fresh, nonce-bound attestation committing to a digest of the config an
/// un-baked (fleet) enclave booted, plus the canonical view that digest is over.
///
/// Obtain it from `POST /attestation/config-report` with a fresh caller nonce,
/// then verify it with `ConfigAttestationReport::verify` (feature
/// `attest-verify`). `#[serde(deny_unknown_fields)]` so a consumer fails closed
/// on an unexpected shape rather than silently ignoring fields.
///
/// After a successful `verify` / `authenticate`, take every value you trust from
/// the returned `VerifiedConfigAttestation` / `AuthenticatedConfigAttestation`,
/// NOT from this raw response: `configDigestSha384` and `nonce` are cross-checked
/// against the signed evidence during verification (a mismatch fails closed), but
/// `teeType` and `generatedAt` are echoed by the untrusted parent and are
/// informational only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigAttestationReport {
    /// SHA-384 of `configView`, base64 (standard). Also committed as the
    /// attestation `user_data`. A verifier reproduces it by base64-decoding
    /// `configView` and hashing those bytes with SHA-384 — it does **not** need
    /// `vta-config` or a base+overlay re-derivation. `verify`/`authenticate`
    /// cross-check this against the signed digest and fail closed on mismatch.
    pub config_digest_sha384: String,
    /// The canonical, secret-free view of the effective config the enclave
    /// booted, base64 (standard) — the exact bytes hashed into
    /// `configDigestSha384` / `user_data`. Its authenticity is established by the
    /// signed digest; a verifier may then inspect it (e.g. `tee.kms.key_arn`).
    pub config_view: String,
    /// The caller's nonce (hex), echoed; bound into the attestation for freshness.
    /// `verify`/`authenticate` cross-check it against the signed nonce.
    pub nonce: String,
    /// TEE platform that produced the evidence (e.g. `"nitro"`). **Informational
    /// / untrusted:** echoed by the parent and NOT covered by verification — the
    /// evidence is authenticated as an AWS Nitro quote by the verifier itself.
    pub tee_type: String,
    /// Base64 attestation document (COSE_Sign1). A verifier MUST check: signature
    /// chains to the vendor root, `PCR0` matches the approved image, `nonce`
    /// equals theirs, `SHA-384(configView) == user_data`, and the view's
    /// `tee.kms.key_arn` is the tenant's own key.
    pub evidence: String,
    /// Unix seconds when generated. **Informational / untrusted:** echoed by the
    /// parent and NOT covered by verification (freshness comes from the signed
    /// `nonce`, not this timestamp).
    pub generated_at: u64,
}
