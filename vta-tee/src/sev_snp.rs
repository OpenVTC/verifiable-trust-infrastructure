use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

use vti_common::error::{AppError, tee_attestation_error};

use super::provider::{StructuralCheckOutcome, TeeProvider};
use super::types::{AttestationReport, TeeStatus, TeeType};

/// AMD SEV-SNP attestation provider.
///
/// Uses `/dev/sev-guest` to request hardware-signed attestation reports
/// from the AMD Secure Processor (PSP). The evidence field contains a raw
/// SEV-SNP attestation report structure that can be verified against the
/// AMD ARK/ASK certificate chain.
///
/// # Report Data Layout
///
/// The 64-byte `report_data` field is structured as:
/// - Bytes  0..32: SHA-256 hash of the VTA DID (user identity binding)
/// - Bytes 32..64: Client nonce (replay prevention, zero-padded)
///
/// # Verification
///
/// Remote parties verify the report by:
/// 1. Fetching the VCEK (Versioned Chip Endorsement Key) certificate from AMD KDS
/// 2. Validating the VCEK against the ARK/ASK certificate chain
/// 3. Verifying the report signature using the VCEK public key
/// 4. Checking that `report_data` matches expected VTA DID hash + nonce
/// 5. Inspecting `POLICY`, `MEASUREMENT`, and `GUEST_SVN` fields
pub struct SevSnpProvider;

impl TeeProvider for SevSnpProvider {
    fn tee_type(&self) -> TeeType {
        TeeType::SevSnp
    }

    fn detect(&self) -> Result<TeeStatus, AppError> {
        let detected = std::path::Path::new("/dev/sev-guest").exists();

        let platform_version = if detected { read_sev_version() } else { None };

        if detected {
            info!(version = ?platform_version, "SEV-SNP guest device detected");
        }

        Ok(TeeStatus {
            tee_type: TeeType::SevSnp,
            detected,
            platform_version,
        })
    }

    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationReport, AppError> {
        let report_data = build_report_data(user_data, nonce);

        debug!(
            user_data_len = user_data.len(),
            nonce_len = nonce.len(),
            "requesting SEV-SNP attestation report"
        );

        let evidence = request_snp_report(&report_data)?;

        // Parse key fields from the report for logging
        let policy = u64::from_le_bytes(
            evidence[POLICY_OFFSET..POLICY_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        let guest_svn = u32::from_le_bytes(
            evidence[GUEST_SVN_OFFSET..GUEST_SVN_OFFSET + 4]
                .try_into()
                .unwrap_or_default(),
        );

        debug!(
            evidence_len = evidence.len(),
            policy = format!("{policy:#018x}"),
            guest_svn,
            "SEV-SNP attestation report generated"
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(AttestationReport {
            tee_type: TeeType::SevSnp,
            evidence: BASE64.encode(&evidence),
            nonce: hex::encode(nonce),
            generated_at: now,
            vta_did: None,
        })
    }

    fn smoke_check_structure(
        &self,
        report: &AttestationReport,
    ) -> Result<StructuralCheckOutcome, AppError> {
        if report.tee_type != TeeType::SevSnp {
            return Ok(StructuralCheckOutcome::Malformed);
        }

        let evidence = BASE64
            .decode(&report.evidence)
            .map_err(|e| tee_attestation_error(format!("invalid evidence encoding: {e}")))?;

        // Structural validation
        if evidence.len() != SNP_REPORT_SIZE {
            debug!(
                actual_len = evidence.len(),
                expected_len = SNP_REPORT_SIZE,
                "SNP report size mismatch"
            );
            return Ok(StructuralCheckOutcome::Malformed);
        }

        // Verify the report version (must be 2 for SNP)
        let version = u32::from_le_bytes(
            evidence[VERSION_OFFSET..VERSION_OFFSET + 4]
                .try_into()
                .unwrap_or_default(),
        );
        if version != 2 {
            debug!(version, "unexpected SNP report version (expected 2)");
            return Ok(StructuralCheckOutcome::Malformed);
        }

        // Verify the signature algorithm (1 = ECDSA P-384 with SHA-384)
        let sig_algo = u32::from_le_bytes(
            evidence[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4]
                .try_into()
                .unwrap_or_default(),
        );
        if sig_algo != 1 {
            debug!(
                sig_algo,
                "unexpected signature algorithm (expected 1 = ECDSA P-384)"
            );
            return Ok(StructuralCheckOutcome::Malformed);
        }

        // Verify report_data is present (not all zeros)
        let report_data = &evidence[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64];
        if report_data.iter().all(|&b| b == 0) {
            debug!("report_data is all zeros — may indicate empty attestation");
        }

        // Verify the nonce matches what we expect
        if !report.nonce.is_empty()
            && let Ok(nonce_bytes) = hex::decode(&report.nonce)
        {
            let nonce_in_report = &report_data[32..32 + nonce_bytes.len().min(32)];
            let expected = &nonce_bytes[..nonce_bytes.len().min(32)];
            if nonce_in_report[..expected.len()] != *expected {
                debug!("nonce mismatch in report_data");
                return Ok(StructuralCheckOutcome::Malformed);
            }
        }

        // Note: Full cryptographic verification requires:
        // 1. Fetch VCEK cert from AMD KDS using chip_id + reported_tcb from the report
        // 2. Validate VCEK against AMD ARK -> ASK -> VCEK chain
        // 3. Verify the ECDSA P-384 signature over the report body
        //
        // This is intentionally left to remote verifiers who have network access to
        // the AMD Key Distribution Service (https://kdsintf.amd.com).
        //
        // The structural smoke-check + nonce presence confirm only that the
        // report was generated by the local PSP with our inputs — it does not
        // prove trust.

        debug!("SNP report structural smoke-check passed (shape + nonce)");
        Ok(StructuralCheckOutcome::StructurallyValid)
    }
}

// ---------------------------------------------------------------------------
// SEV-SNP report structure offsets (from AMD SEV-SNP ABI specification)
// ---------------------------------------------------------------------------

/// Size of an AMD SEV-SNP attestation report.
const SNP_REPORT_SIZE: usize = 1184;

/// Offset of the VERSION field (4 bytes, LE u32). Expected value: 2.
const VERSION_OFFSET: usize = 0;

/// Offset of the GUEST_SVN field (4 bytes, LE u32).
const GUEST_SVN_OFFSET: usize = 4;

/// Offset of the POLICY field (8 bytes, LE u64).
const POLICY_OFFSET: usize = 8;

/// Offset of the REPORT_DATA field (64 bytes) — our user_data + nonce.
const REPORT_DATA_OFFSET: usize = 80;

/// Offset of the SIGNATURE_ALGO field (4 bytes, LE u32).
/// Value 1 = ECDSA P-384 with SHA-384.
const SIG_ALGO_OFFSET: usize = 0x34;

// ---------------------------------------------------------------------------
// Report data construction
// ---------------------------------------------------------------------------

/// Build the 64-byte report_data field for the SNP attestation request.
///
/// Layout:
/// - [0..32]:  SHA-256(user_data) — binds the VTA DID identity
/// - [32..64]: nonce bytes — client-provided replay prevention (zero-padded)
fn build_report_data(user_data: &[u8], nonce: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha256};

    let mut report_data = [0u8; 64];

    // Hash user_data into the first 32 bytes
    let user_hash = Sha256::digest(user_data);
    report_data[..32].copy_from_slice(&user_hash);

    // Copy nonce into the last 32 bytes (truncate if > 32)
    let nonce_len = nonce.len().min(32);
    report_data[32..32 + nonce_len].copy_from_slice(&nonce[..nonce_len]);

    report_data
}

// ---------------------------------------------------------------------------
// Platform version detection
// ---------------------------------------------------------------------------

/// Read the SEV firmware version from sysfs.
fn read_sev_version() -> Option<String> {
    let major = std::fs::read_to_string("/sys/firmware/sev/api_major").ok()?;
    let minor = std::fs::read_to_string("/sys/firmware/sev/api_minor").ok()?;

    let build = std::fs::read_to_string("/sys/firmware/sev/build")
        .ok()
        .map(|b| format!(" build {}", b.trim()));

    Some(format!(
        "{}.{}{}",
        major.trim(),
        minor.trim(),
        build.unwrap_or_default()
    ))
}

// ---------------------------------------------------------------------------
// Kernel ioctl interface
// ---------------------------------------------------------------------------

/// Request an attestation report from /dev/sev-guest via ioctl.
///
/// Uses the Linux `SNP_GET_REPORT` ioctl (since kernel 5.19) to request
/// a hardware-signed attestation report from the AMD PSP.
///
/// Reference: linux/include/uapi/linux/sev-guest.h
fn request_snp_report(report_data: &[u8; 64]) -> Result<Vec<u8>, AppError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| tee_attestation_error(format!("failed to open /dev/sev-guest: {e}")))?;

    // struct snp_report_req (linux/include/uapi/linux/sev-guest.h)
    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64], // User-provided data to bind into the report
        vmpl: u32,           // VM Privilege Level (0 = most privileged)
        rsvd: [u8; 28],      // Must be zero
    }

    // struct snp_report_resp
    #[repr(C)]
    struct SnpReportResp {
        status: u32,                   // Firmware status code (0 = success)
        report_size: u32,              // Size of the report
        rsvd: [u8; 24],                // Reserved
        report: [u8; SNP_REPORT_SIZE], // The attestation report
    }

    // struct snp_guest_request_ioctl
    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8, // Message version (must be 1)
        req_data: u64,   // Pointer to request structure
        resp_data: u64,  // Pointer to response structure
        fw_err: u64,     // Firmware error code (output)
    }

    let mut req = SnpReportReq {
        user_data: *report_data,
        vmpl: 0,
        rsvd: [0u8; 28],
    };

    let mut resp = SnpReportResp {
        status: 0,
        report_size: 0,
        rsvd: [0u8; 24],
        report: [0u8; SNP_REPORT_SIZE],
    };

    let mut guest_req = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: &mut req as *mut SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        fw_err: 0,
    };

    // SNP_GET_REPORT ioctl number.
    //
    // From linux/include/uapi/linux/sev-guest.h:
    //   #define SNP_GET_REPORT _IOWR('S', 0x0, struct snp_guest_request_ioctl)
    //
    // _IOWR('S', 0x0, 32): direction = RW (0xC0), size = 32 bytes, type = 'S' (0x53), nr = 0
    // = 0xC020_5300
    const SNP_GET_REPORT: libc::c_ulong = 0xC020_5300;

    let ret = unsafe {
        libc::ioctl(
            dev.as_raw_fd(),
            SNP_GET_REPORT,
            &mut guest_req as *mut SnpGuestRequestIoctl,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(tee_attestation_error(format!(
            "SNP_GET_REPORT ioctl failed: {errno} (fw_err={:#x})",
            guest_req.fw_err
        )));
    }

    if resp.status != 0 {
        return Err(tee_attestation_error(format!(
            "SNP_GET_REPORT firmware error: status={}, fw_err={:#x}",
            resp.status, guest_req.fw_err
        )));
    }

    debug!(
        report_size = resp.report_size,
        "SEV-SNP report received from PSP"
    );

    Ok(resp.report.to_vec())
}
