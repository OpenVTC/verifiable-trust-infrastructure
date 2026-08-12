use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha384};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::tee::TeeState;
use crate::tee::provider::StructuralCheckOutcome;
use crate::tee::types::{AttestationReport, TeeStatus, TeeType};

/// Get the cached TEE detection status.
pub fn get_tee_status(tee_state: &TeeState) -> TeeStatus {
    tee_state.status.clone()
}

/// Generate a fresh attestation report binding the VTA DID and client nonce.
///
/// The server-side structural smoke-check is logged but **not** returned
/// on the wire — there is no honest way for a producer to claim its own
/// attestation is valid in a way the consumer should trust. Consumers
/// must verify via `vta_sdk::attestation::verify_nitro_assertion`
/// (gated behind the `attest-verify` feature) against the vendor root
/// of trust.
pub async fn generate_attestation_report(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
    nonce: &str,
) -> Result<AttestationReport, AppError> {
    // Validate nonce: must be hex-encoded, 1-64 bytes
    let nonce_bytes = hex::decode(nonce)
        .map_err(|e| AppError::Validation(format!("nonce must be hex-encoded: {e}")))?;
    if nonce_bytes.is_empty() || nonce_bytes.len() > 64 {
        return Err(AppError::Validation(
            "nonce must be 1-64 bytes (2-128 hex chars)".into(),
        ));
    }

    // Read VTA DID from config
    let vta_did = config.read().await.vta_did.clone();
    let user_data = vta_did.as_deref().unwrap_or("").as_bytes();

    debug!(
        nonce_len = nonce_bytes.len(),
        "generating attestation report"
    );

    // Generate the report via the platform provider
    let mut report = tee_state.provider.attest(user_data, &nonce_bytes)?;
    report.vta_did = vta_did;

    // Structural smoke-check — NOT full cryptographic verification. The
    // remote verifier is responsible for checking the vendor cert chain,
    // signature, and PCR values. We log the outcome so a malformed
    // evidence blob is visible in the producer's traces; we do NOT
    // expose it on the wire (per typestate discipline — see CLAUDE.md).
    match tee_state.provider.smoke_check_structure(&report)? {
        StructuralCheckOutcome::StructurallyValid => {}
        StructuralCheckOutcome::Malformed => {
            warn!(
                tee_type = %report.tee_type,
                "attestation evidence failed structural smoke-check — \
                 returning anyway, consumer must verify cryptographically"
            );
        }
    }

    Ok(report)
}

/// Get a cached attestation report (no client nonce — uses a timestamp-based nonce).
pub async fn get_cached_report(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
) -> Result<AttestationReport, AppError> {
    // Use a deterministic nonce derived from the current time bucket
    let cache_ttl = {
        #[cfg(feature = "tee")]
        {
            config.read().await.tee.attestation_cache_ttl
        }
        #[cfg(not(feature = "tee"))]
        {
            let _ = config;
            300u64
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_bucket = now / cache_ttl;
    let nonce = hex::encode(time_bucket.to_be_bytes());

    generate_attestation_report(tee_state, config, &nonce).await
}

/// A fresh, nonce-bound attestation that commits to a digest of the config the
/// enclave booted.
///
/// This is the pull path that makes the un-baked config **verifiable**: because
/// the parent supplies `tee.kms.key_arn` (and the rest of the tenant config), a
/// tenant/verifier must be able to confirm which config an instance is actually
/// running before trusting it. The digest is committed as the attestation
/// `user_data` (so it is signed, not merely asserted) and the caller's nonce is
/// bound for freshness. Unlike the boot-time log anchor, this is obtainable on
/// demand and cannot be forged or replayed by the parent.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ConfigAttestationReport {
    /// SHA-384 of the config file bytes, base64 (standard). Also committed as the
    /// attestation `user_data`, so a verifier checks it against the signed doc.
    pub config_digest_sha384: String,
    /// The caller's nonce (hex), echoed; bound into the attestation for freshness.
    pub nonce: String,
    /// TEE platform that produced the evidence.
    pub tee_type: TeeType,
    /// Base64 attestation document (COSE_Sign1). A verifier MUST check: signature
    /// chains to the vendor root, `PCR0` matches the pinned image, `nonce` equals
    /// theirs, and `user_data` equals the SHA-384 of the config they expect (in
    /// particular that `tee.kms.key_arn` is the tenant's own key).
    pub evidence: String,
    /// Unix seconds when generated.
    pub generated_at: u64,
}

/// Generate a [`ConfigAttestationReport`] committing the booted config's digest.
pub async fn generate_config_attestation(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
    nonce: &str,
) -> Result<ConfigAttestationReport, AppError> {
    // Validate nonce (same rules as the DID report path).
    let nonce_bytes = hex::decode(nonce)
        .map_err(|e| AppError::Validation(format!("nonce must be hex-encoded: {e}")))?;
    if nonce_bytes.is_empty() || nonce_bytes.len() > 64 {
        return Err(AppError::Validation(
            "nonce must be 1-64 bytes (2-128 hex chars)".into(),
        ));
    }

    // Digest the exact config file the enclave booted (`config_path` is the file
    // `AppConfig::load` read), so this matches the boot-time attestation anchor.
    let config_path = config.read().await.config_path.clone();
    let bytes = tokio::fs::read(&config_path).await.map_err(|e| {
        AppError::Internal(format!(
            "failed to read config at {} for attestation digest: {e}",
            config_path.display()
        ))
    })?;
    let digest = Sha384::digest(&bytes);

    debug!(
        nonce_len = nonce_bytes.len(),
        "generating config attestation report"
    );

    // Commit the digest into the attestation `user_data`; nonce gives freshness.
    let report = tee_state.provider.attest(digest.as_slice(), &nonce_bytes)?;

    Ok(ConfigAttestationReport {
        config_digest_sha384: BASE64.encode(digest),
        nonce: report.nonce,
        tee_type: report.tee_type,
        evidence: report.evidence,
        generated_at: report.generated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::{BASE64, Digest, Sha384};
    use base64::Engine;

    #[test]
    fn config_digest_is_deterministic_sha384_b64() {
        let input = b"resolver_url = \"ws://127.0.0.1:4445/did/v1/ws\"\n";
        let a = BASE64.encode(Sha384::digest(input));
        let b = BASE64.encode(Sha384::digest(input));
        assert_eq!(a, b, "digest must be deterministic");
        assert_eq!(
            BASE64.decode(&a).unwrap().len(),
            48,
            "SHA-384 digest is 48 bytes"
        );
    }
}
