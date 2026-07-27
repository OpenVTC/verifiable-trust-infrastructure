use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

use vti_common::error::{AppError, tee_attestation_error};

use super::provider::{StructuralCheckOutcome, TeeProvider};
use super::types::{AttestationReport, TeeStatus, TeeType};

/// AWS Nitro Enclaves attestation provider.
///
/// Uses the Nitro Secure Module (NSM) device at `/dev/nsm` to generate
/// attestation documents signed by the AWS Nitro Attestation PKI.
///
/// # Attestation Document
///
/// The evidence field contains a COSE_Sign1 structure (RFC 8152) with:
/// - Protected header: algorithm ES384 (ECDSA P-384 with SHA-384)
/// - Payload: CBOR map with PCRs, module_id, timestamp, nonce, user_data, public_key
/// - Signature: signed by the enclave's attestation certificate
///
/// # Verification
///
/// Remote parties verify by:
/// 1. Parsing the COSE_Sign1 document
/// 2. Extracting the certificate chain from the payload
/// 3. Validating the chain against the AWS Nitro root certificate
///    (available at https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip)
/// 4. Verifying the COSE_Sign1 signature using the leaf certificate
/// 5. Checking PCR values match expected enclave image measurements
/// 6. Validating nonce and user_data fields
pub struct NitroProvider;

impl TeeProvider for NitroProvider {
    fn tee_type(&self) -> TeeType {
        TeeType::Nitro
    }

    fn detect(&self) -> Result<TeeStatus, AppError> {
        let detected = std::path::Path::new("/dev/nsm").exists();

        if detected {
            info!("Nitro Secure Module device detected");
        }

        Ok(TeeStatus {
            tee_type: TeeType::Nitro,
            detected,
            platform_version: if detected {
                Some("nitro-enclave".into())
            } else {
                None
            },
        })
    }

    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationReport, AppError> {
        debug!(
            user_data_len = user_data.len(),
            nonce_len = nonce.len(),
            "requesting Nitro attestation document"
        );

        let evidence = request_nsm_attestation(user_data, nonce)?;

        debug!(
            evidence_len = evidence.len(),
            "Nitro attestation document generated"
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(AttestationReport {
            tee_type: TeeType::Nitro,
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
        if report.tee_type != TeeType::Nitro {
            return Ok(StructuralCheckOutcome::Malformed);
        }

        let evidence = BASE64
            .decode(&report.evidence)
            .map_err(|e| tee_attestation_error(format!("invalid evidence encoding: {e}")))?;

        if evidence.is_empty() {
            return Ok(StructuralCheckOutcome::Malformed);
        }

        // Nitro attestation documents are CBOR-encoded COSE_Sign1 structures.
        // COSE_Sign1 is CBOR tag 18, which encodes as:
        //   - 0xD8 0x12 (2-byte tag for tag number 18)
        // Some implementations may also use the untagged form starting with
        // CBOR array(4): 0x84
        let first_byte = evidence[0];
        let valid_start = first_byte == 0xD8  // CBOR tag (2-byte form)
            || first_byte == 0x84; // CBOR array(4) — untagged COSE_Sign1

        if !valid_start {
            debug!(
                first_byte = format!("{first_byte:#04x}"),
                "unexpected first byte in attestation document"
            );
            return Ok(StructuralCheckOutcome::Malformed);
        }

        // Full cryptographic verification requires:
        // 1. Parse COSE_Sign1 structure
        // 2. Extract the certificate chain from the payload
        // 3. Validate chain against AWS Nitro root certificate
        // 4. Verify signature using the leaf certificate's public key
        // 5. Check PCR values match expected enclave measurements
        //
        // This smoke-check only validates the structural shape.
        debug!("Nitro attestation document structural smoke-check passed");
        Ok(StructuralCheckOutcome::StructurallyValid)
    }
}

// ---------------------------------------------------------------------------
// NSM device interface
// ---------------------------------------------------------------------------

/// Request an attestation document from the Nitro Secure Module.
///
/// The NSM device (`/dev/nsm`) uses an ioctl-based interface. The request
/// and response are CBOR-encoded messages passed via a file descriptor
/// obtained from the device.
///
/// Request: `{ "Attestation": { "user_data": <bytes>, "nonce": <bytes>, "public_key": null } }`
/// Response: `{ "Attestation": { "document": <bytes> } }` (the COSE_Sign1 document)
fn request_nsm_attestation(user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AppError> {
    // Open the NSM device
    let fd = open_nsm_device()?;

    // Build the CBOR-encoded attestation request
    let request = build_nsm_request(user_data, nonce, None);

    // Send request and receive response via ioctl
    let response = nsm_ioctl(fd.as_raw_fd(), &request)?;

    // Parse the CBOR response to extract the attestation document
    extract_attestation_document(&response)
}

/// Request an NSM attestation document with an embedded public key.
///
/// Used by KMS bootstrap to bind an ephemeral RSA public key to the
/// attestation document. KMS uses this to re-encrypt the response so
/// only the enclave (holding the private key) can decrypt it.
///
/// `public_key_der` must be the RSA public key in DER-encoded SPKI format.
pub(crate) fn request_nsm_attestation_for_kms(public_key_der: &[u8]) -> Result<Vec<u8>, AppError> {
    let fd = open_nsm_device()?;
    let request = build_nsm_request(&[], &[], Some(public_key_der));
    let response = nsm_ioctl(fd.as_raw_fd(), &request)?;
    extract_attestation_document(&response)
}

/// RAII wrapper for the NSM file descriptor.
struct NsmFd(std::os::unix::io::RawFd);

impl NsmFd {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0
    }
}

impl Drop for NsmFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

fn open_nsm_device() -> Result<NsmFd, AppError> {
    use std::ffi::CString;

    let path = CString::new("/dev/nsm").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(tee_attestation_error(format!(
            "failed to open /dev/nsm: {err}"
        )));
    }
    Ok(NsmFd(fd))
}

/// Send a request to the NSM device and receive the response.
///
/// The NSM ioctl uses a simple request/response buffer protocol:
/// - Input:  pointer to request CBOR buffer + length
/// - Output: response written into a provided buffer
fn nsm_ioctl(fd: std::os::unix::io::RawFd, request: &[u8]) -> Result<Vec<u8>, AppError> {
    // NSM ioctl request structure (from aws-nitro-enclaves-nsm-api)
    #[repr(C)]
    struct NsmMessage {
        request: NsmIoBuffer,
        response: NsmIoBuffer,
    }

    // Mirrors the kernel `struct nsm_iovec { __u64 addr; __u64 len; }`.
    // `len` MUST be u64: a u32 here leaves 4 bytes of uninitialized padding
    // under #[repr(C)], which the kernel reads as the high bits of the 64-bit
    // length — inflating it to a garbage value and failing the ioctl with
    // EMSGSIZE (os error 90).
    #[repr(C)]
    struct NsmIoBuffer {
        addr: u64,
        len: u64,
    }

    // NSM_IOCTL_REQUEST: _IOWR(0x0A, 0, struct nsm_message)
    const NSM_IOCTL_REQUEST: libc::c_ulong = 0xC020_0A00;

    // Allocate response buffer (NSM documents are typically 2-5 KB)
    let mut response_buf = vec![0u8; 16384];

    let mut msg = NsmMessage {
        request: NsmIoBuffer {
            addr: request.as_ptr() as u64,
            len: request.len() as u64,
        },
        response: NsmIoBuffer {
            addr: response_buf.as_mut_ptr() as u64,
            len: response_buf.len() as u64,
        },
    };

    let ret = unsafe { libc::ioctl(fd, NSM_IOCTL_REQUEST, &mut msg as *mut NsmMessage) };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(tee_attestation_error(format!("NSM ioctl failed: {err}")));
    }

    let actual_len = msg.response.len as usize;
    if actual_len == 0 {
        return Err(tee_attestation_error("empty response from NSM device"));
    }

    response_buf.truncate(actual_len);
    Ok(response_buf)
}

// ---------------------------------------------------------------------------
// CBOR encoding/decoding helpers
// ---------------------------------------------------------------------------

/// Build a CBOR-encoded NSM attestation request.
///
/// When `public_key` is `None`, the request encodes `public_key: null`.
/// When `Some(der_bytes)`, the public key DER is embedded in the attestation
/// document — used by KMS to re-encrypt the response to that key.
///
/// ```text
/// { "Attestation": { "user_data": <bytes>, "nonce": <bytes>, "public_key": <bytes|null> } }
/// ```
fn build_nsm_request(user_data: &[u8], nonce: &[u8], public_key: Option<&[u8]>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + user_data.len() + nonce.len());

    // Map(1)
    buf.push(0xA1);
    // Text "Attestation" (11 bytes)
    encode_cbor_text(&mut buf, b"Attestation");
    // Map(3)
    buf.push(0xA3);
    // "user_data" => bytes
    encode_cbor_text(&mut buf, b"user_data");
    encode_cbor_bytes(&mut buf, user_data);
    // "nonce" => bytes
    encode_cbor_text(&mut buf, b"nonce");
    encode_cbor_bytes(&mut buf, nonce);
    // "public_key" => bytes or null
    encode_cbor_text(&mut buf, b"public_key");
    match public_key {
        Some(pk) => encode_cbor_bytes(&mut buf, pk),
        None => buf.push(0xF6), // CBOR null
    }

    buf
}

/// Extract the attestation document from an NSM CBOR response.
///
/// The response has the shape:
/// ```text
/// { "Attestation": { "document": <bytes> } }
/// ```
///
/// We do a simple scan for the "document" key and extract the following
/// byte string. This avoids a full CBOR parser dependency.
fn extract_attestation_document(response: &[u8]) -> Result<Vec<u8>, AppError> {
    // Look for the "document" text key in the CBOR response
    let marker = b"document";

    // Scan for the marker in the response bytes
    let pos = response
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| tee_attestation_error("NSM response does not contain 'document' field"))?;

    // The byte string follows immediately after the "document" text
    let after_key = pos + marker.len();
    if after_key >= response.len() {
        return Err(tee_attestation_error(
            "NSM response truncated after 'document' key",
        ));
    }

    // Decode the CBOR byte string that follows
    decode_cbor_bytes(&response[after_key..])
}

fn encode_cbor_text(buf: &mut Vec<u8>, text: &[u8]) {
    let len = text.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else if len < 256 {
        buf.push(0x78);
        buf.push(len as u8);
    } else {
        buf.push(0x79);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(text);
}

fn encode_cbor_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(data);
}

/// Decode a CBOR byte string at the start of the given slice.
fn decode_cbor_bytes(data: &[u8]) -> Result<Vec<u8>, AppError> {
    if data.is_empty() {
        return Err(tee_attestation_error("unexpected end of CBOR data"));
    }

    let major = data[0] >> 5;
    if major != 2 {
        return Err(tee_attestation_error(format!(
            "expected CBOR byte string (major type 2), got major type {major}"
        )));
    }

    let additional = data[0] & 0x1F;
    let (len, offset) = if additional < 24 {
        (additional as usize, 1)
    } else if additional == 24 {
        if data.len() < 2 {
            return Err(tee_attestation_error("truncated CBOR length"));
        }
        (data[1] as usize, 2)
    } else if additional == 25 {
        if data.len() < 3 {
            return Err(tee_attestation_error("truncated CBOR length"));
        }
        (((data[1] as usize) << 8) | data[2] as usize, 3)
    } else if additional == 26 {
        if data.len() < 5 {
            return Err(tee_attestation_error("truncated CBOR length"));
        }
        (
            ((data[1] as usize) << 24)
                | ((data[2] as usize) << 16)
                | ((data[3] as usize) << 8)
                | data[4] as usize,
            5,
        )
    } else {
        return Err(tee_attestation_error(format!(
            "unsupported CBOR additional info: {additional}"
        )));
    };

    if data.len() < offset + len {
        return Err(tee_attestation_error(format!(
            "CBOR byte string length {len} exceeds available data"
        )));
    }

    Ok(data[offset..offset + len].to_vec())
}
