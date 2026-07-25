use super::types::TeeType;
use tracing::{debug, info};

/// Probe the runtime environment for TEE hardware.
///
/// Returns the detected TEE type, or `None` if no TEE is found.
pub fn detect_tee() -> Option<TeeType> {
    // AMD SEV-SNP: check for the guest device
    if std::path::Path::new("/dev/sev-guest").exists() {
        info!("TEE detected: AMD SEV-SNP (/dev/sev-guest)");
        return Some(TeeType::SevSnp);
    }
    // Also check sysfs for SEV status
    if std::path::Path::new("/sys/firmware/sev").exists() {
        debug!("SEV firmware directory exists, checking for SNP support");
        if let Ok(status) = std::fs::read_to_string("/sys/firmware/sev/snp")
            && status.trim() == "1"
        {
            info!("TEE detected: AMD SEV-SNP (sysfs)");
            return Some(TeeType::SevSnp);
        }
    }

    // AWS Nitro Enclaves: check for the NSM device
    if std::path::Path::new("/dev/nsm").exists() {
        info!("TEE detected: AWS Nitro Enclaves (/dev/nsm)");
        return Some(TeeType::Nitro);
    }

    debug!("no TEE hardware detected");
    None
}
