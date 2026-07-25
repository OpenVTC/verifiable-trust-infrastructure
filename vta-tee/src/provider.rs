use vti_common::error::AppError;

use super::types::{AttestationReport, TeeStatus, TeeType};

/// Outcome of a provider's structural smoke-check. Returned by
/// [`TeeProvider::smoke_check_structure`].
///
/// This is **not** a verification result. "StructurallyValid" only
/// means the evidence bytes have the expected shape for the TEE
/// platform (e.g. CBOR COSE_Sign1 for Nitro). Cryptographic
/// verification — cert-chain against the vendor root, signature
/// check, PCR-value match — must be performed separately, typically
/// by the remote verifier. For Nitro specifically, see
/// `vta_sdk::attestation::verify_nitro_assertion` (gated behind the
/// `attest-verify` feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralCheckOutcome {
    /// Evidence has the expected shape for the provider. No
    /// cryptographic claim is made by this outcome.
    StructurallyValid,
    /// Evidence is malformed or belongs to a different provider.
    Malformed,
}

/// Trait for TEE attestation providers.
///
/// Each supported TEE platform (AMD SEV-SNP, AWS Nitro, simulated)
/// implements this trait to provide detection, attestation, and
/// a structural smoke-check.
pub trait TeeProvider: Send + Sync {
    /// Return the TEE platform type.
    fn tee_type(&self) -> TeeType;

    /// Detect whether this TEE is available at runtime.
    fn detect(&self) -> Result<TeeStatus, AppError>;

    /// Generate an attestation report binding the given user_data and nonce.
    ///
    /// The `user_data` is typically the VTA DID (UTF-8 encoded).
    /// The `nonce` is a client-provided value for replay prevention.
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationReport, AppError>;

    /// Smoke-check that an attestation report has the expected
    /// structural shape for this provider.
    ///
    /// This is intentionally **not** full cryptographic verification.
    /// Remote parties must verify against the platform vendor's root
    /// of trust (AMD ARK/ASK chain for SEV-SNP, AWS Nitro root
    /// certificate for Nitro). The old `verify` name implied more
    /// than this method delivers and invited callers to treat the
    /// result as a trust decision.
    fn smoke_check_structure(
        &self,
        report: &AttestationReport,
    ) -> Result<StructuralCheckOutcome, AppError>;
}
