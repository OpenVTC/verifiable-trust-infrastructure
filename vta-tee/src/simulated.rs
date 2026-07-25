use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use vti_common::error::AppError;

use super::provider::{StructuralCheckOutcome, TeeProvider};
use super::types::{AttestationReport, TeeStatus, TeeType};

/// Simulated TEE provider for development and testing.
///
/// Generates deterministic, structurally valid attestation reports using
/// SHA-256 hashes instead of hardware-backed signatures. Reports from this
/// provider MUST NOT be treated as authentic attestation evidence.
pub struct SimulatedProvider;

impl TeeProvider for SimulatedProvider {
    fn tee_type(&self) -> TeeType {
        TeeType::Simulated
    }

    fn detect(&self) -> Result<TeeStatus, AppError> {
        Ok(TeeStatus {
            tee_type: TeeType::Simulated,
            detected: true,
            platform_version: Some("simulated-v1".into()),
        })
    }

    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationReport, AppError> {
        // Build a deterministic "evidence" blob by hashing the inputs.
        // This is NOT real attestation — it's structurally similar for testing.
        let mut hasher = Sha256::new();
        hasher.update(b"simulated-tee-evidence-v1:");
        hasher.update(user_data);
        hasher.update(b":");
        hasher.update(nonce);
        let evidence_hash = hasher.finalize();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(AttestationReport {
            tee_type: TeeType::Simulated,
            evidence: BASE64.encode(evidence_hash),
            nonce: hex::encode(nonce),
            generated_at: now,
            vta_did: None, // Caller sets this
        })
    }

    fn smoke_check_structure(
        &self,
        report: &AttestationReport,
    ) -> Result<StructuralCheckOutcome, AppError> {
        if report.tee_type == TeeType::Simulated && !report.evidence.is_empty() {
            Ok(StructuralCheckOutcome::StructurallyValid)
        } else {
            Ok(StructuralCheckOutcome::Malformed)
        }
    }
}
