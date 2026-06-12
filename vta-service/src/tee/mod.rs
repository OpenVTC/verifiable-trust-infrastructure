pub mod admin_bootstrap;
pub mod anchor;
mod detect;
pub mod did_autogen;
pub mod kms_bootstrap;
pub mod mnemonic_guard;
pub mod provider;
mod simulated;
pub mod types;

// Platform-specific providers (compiled on all targets but only functional
// on the correct hardware — detection guards against misuse).
mod nitro;
mod sev_snp;

use std::sync::Arc;

use tracing::{error, info, warn};

use crate::config::TeeConfig;
use crate::config::TeeMode;
use crate::error::{AppError, tee_attestation_error};

use self::detect::detect_tee;
use self::nitro::NitroProvider;
use self::provider::TeeProvider;
use self::sev_snp::SevSnpProvider;
use self::simulated::SimulatedProvider;
use self::types::{TeeStatus, TeeType};

/// Cached TEE state shared via AppState.
#[derive(Clone)]
pub struct TeeState {
    pub provider: Arc<dyn TeeProvider>,
    pub status: TeeStatus,
}

/// Initialize the TEE subsystem based on config.
///
/// Returns `Ok(Some(TeeState))` when TEE is active, `Ok(None)` when disabled,
/// or `Err` when `mode = required` but no TEE hardware is found.
pub fn init_tee(config: &TeeConfig) -> Result<Option<TeeState>, AppError> {
    match config.mode {
        TeeMode::Simulated => {
            warn!("TEE attestation running in SIMULATED mode — not suitable for production");
            let provider = SimulatedProvider;
            let status = provider.detect()?;
            Ok(Some(TeeState {
                provider: Arc::new(provider),
                status,
            }))
        }
        TeeMode::Required | TeeMode::Optional => {
            match detect_tee() {
                Some(TeeType::SevSnp) => {
                    let provider = SevSnpProvider;
                    let status = provider.detect()?;
                    info!(platform_version = ?status.platform_version, "TEE initialized: AMD SEV-SNP");
                    Ok(Some(TeeState {
                        provider: Arc::new(provider),
                        status,
                    }))
                }
                Some(TeeType::Nitro) => {
                    let provider = NitroProvider;
                    let status = provider.detect()?;
                    info!("TEE initialized: AWS Nitro Enclaves");
                    Ok(Some(TeeState {
                        provider: Arc::new(provider),
                        status,
                    }))
                }
                Some(TeeType::Simulated) => {
                    // detect_tee() never returns Simulated, but handle it gracefully
                    unreachable!("detect_tee() should not return Simulated")
                }
                None => {
                    if config.mode == TeeMode::Required {
                        error!(
                            "TEE mode is 'required' but no TEE hardware detected — refusing to start"
                        );
                        Err(tee_attestation_error(
                            "TEE mode is 'required' but no TEE hardware was detected. \
                             Set tee.mode = 'optional' or 'disabled' to run without TEE, \
                             or deploy on TEE-capable hardware (AMD SEV-SNP, AWS Nitro).",
                        ))
                    } else {
                        warn!(
                            "TEE mode is 'optional' but no TEE hardware detected — attestation will not be available"
                        );
                        Ok(None)
                    }
                }
            }
        }
    }
}
