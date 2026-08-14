use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::AppConfig;
use crate::error::{AppError, tee_attestation_error};
use crate::tee::TeeState;
use crate::tee::provider::StructuralCheckOutcome;
use crate::tee::types::{AttestationReport, TeeStatus};
use vta_sdk::attestation_report::ConfigAttestationReport;

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

/// Generate a [`ConfigAttestationReport`] committing the booted config's digest.
///
/// The shared wire type lives in `vta_sdk::attestation_report` so the endpoint
/// serializes exactly the type a consumer deserializes and verifies (via
/// `ConfigAttestationReport::verify`). This is the pull path that makes the
/// un-baked config verifiable: the enclave returns the canonical secret-free
/// `config_view` it hashed, committed (as the digest) into the signed `user_data`
/// and bound to the caller's nonce — obtainable on demand and, unlike the boot
/// log, not forgeable or replayable by the parent.
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

    // Commit the digest of the EFFECTIVE (post-overlay) config the enclave
    // booted. This is the digest captured at boot into
    // `AppConfig::effective_config_digest` — after ALL effective-config mutations
    // (tenant overlay applied, KMS-injected JWT signing key, DID
    // reconciliation/generation, WebVH backfill, admin bootstrap) — so it reflects
    // the tenant's real key_arn / mediator / anchor / public_url / DID, and matches
    // the boot-time attestation anchor exactly. Capturing after secret injection is
    // safe because `compute_config_attestation_view` strips the secret fields
    // (JWT signing key, `[secrets]`) before serialization, so the view stays
    // secret-free. We do NOT re-read config_path (which, in fleet mode, is only
    // the baked placeholder base).
    //
    // Absence is a *capability* answer, not an internal fault: only the enclave
    // front-end (`vta-enclave`) calls `capture_effective_config_attestation`, so
    // any other `tee`-feature build — the local daemon in simulated mode, for
    // one — reaches here with `None` on every call, forever. That is a 503 (this
    // build does not offer config attestation), never a 500.
    let (digest, view) = {
        let cfg = config.read().await;
        let digest = cfg.effective_config_digest.clone().ok_or_else(|| {
            tee_attestation_error(
                "config attestation is not available on this build — no effective \
                 config digest was captured at boot (the enclave front-end captures it)",
            )
        })?;
        let view = cfg.effective_config_view.clone().ok_or_else(|| {
            tee_attestation_error(
                "config attestation is not available on this build — no effective \
                 config view was captured at boot (the enclave front-end captures it)",
            )
        })?;
        (digest, view)
    };

    debug!(
        nonce_len = nonce_bytes.len(),
        "generating config attestation report"
    );

    // Commit the digest into the attestation `user_data`; nonce gives freshness.
    let report = tee_state.provider.attest(digest.as_slice(), &nonce_bytes)?;

    Ok(ConfigAttestationReport {
        config_digest_sha384: BASE64.encode(&digest),
        config_view: BASE64.encode(&view),
        nonce: report.nonce,
        // Shared wire type is vta-tee-free, so serialize the platform as its
        // snake_case string (identical to `TeeType`'s serde form, e.g. "nitro").
        tee_type: report.tee_type.to_string(),
        evidence: report.evidence,
        generated_at: report.generated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::BASE64;
    use base64::Engine;
    use sha2::{Digest, Sha384};

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
