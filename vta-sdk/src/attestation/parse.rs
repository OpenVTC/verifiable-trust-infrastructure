//! Parse-only decode of an AWS Nitro attestation quote.
//!
//! [`parse_nitro_quote`] does the COSE_Sign1 + CBOR decode **without** any
//! signature, certificate-chain, PCR, or time checks. It is the structural
//! front half of [`super::verify`]'s [`NitroVerifier`], split out so that:
//!
//!  - it is an ideal `&[u8] -> Result` libFuzzer target (issue #449): both the
//!    COSE decoder ([`coset`]) and the CBOR decoder
//!    ([`aws_nitro_enclaves_nsm_api`]) return `Result`, so the function is
//!    total — no input can panic it; and
//!  - [`NitroVerifier`](super::verify::NitroVerifier) reuses the parsed result
//!    (including the already-decoded [`CoseSign1`]) rather than decoding twice.
//!
//! This mirrors exactly the decode portion of the upstream
//! `nitro_attest::UnparsedAttestationDoc::parse_and_verify`; the verify portion
//! lives in [`super::verify`] so the trust anchor and clock can be injected.

use std::collections::BTreeMap;

use aws_nitro_enclaves_nsm_api::api::{AttestationDoc as NsmAttestationDoc, Digest as NsmDigest};
use coset::{CborSerializable, CoseSign1};

/// Failure decoding the COSE/CBOR structure of a Nitro quote. None of these
/// imply anything about authenticity — only that the bytes are not a
/// well-formed attestation document.
#[derive(Debug, thiserror::Error)]
pub enum NitroParseError {
    /// The outer COSE_Sign1 envelope failed to decode.
    #[error("COSE_Sign1 decode failed: {0}")]
    CoseMalformed(String),
    /// The COSE_Sign1 envelope carried no payload (a detached-payload quote is
    /// not a valid Nitro attestation document).
    #[error("COSE_Sign1 payload missing")]
    PayloadMissing,
    /// The CBOR attestation-document payload failed to decode.
    #[error("attestation-document CBOR decode failed: {0}")]
    CborMalformed(String),
}

/// A structurally-decoded Nitro attestation quote. The fields are taken
/// verbatim from the CBOR payload; **nothing here has been verified** — the
/// certificate chain has not been walked, the COSE signature has not been
/// checked, the PCRs are whatever the bytes claimed, and `timestamp_ms` has
/// not been range-checked.
///
/// Obtain a *verified* one via [`NitroVerifier::verify`](super::verify::NitroVerifier::verify).
#[derive(Debug, Clone)]
pub struct ParsedNitroQuote {
    /// Issuing NSM module id.
    pub module_id: String,
    /// Creation time, milliseconds since the Unix epoch (as claimed).
    pub timestamp_ms: u64,
    /// PCR digest algorithm declared by the document.
    pub digest: NsmDigest,
    /// PCR index → raw digest bytes (zero-valued PCRs are retained here, unlike
    /// the upstream verifier which drops them; the verifier filters on read).
    pub pcrs: BTreeMap<usize, Vec<u8>>,
    /// Leaf (enclave) certificate, DER-encoded — signs the COSE envelope.
    pub certificate_der: Vec<u8>,
    /// Intermediate CA bundle, root-first, DER-encoded.
    pub cabundle_der: Vec<Vec<u8>>,
    /// Optional consumer-supplied public key.
    pub public_key: Option<Vec<u8>>,
    /// Optional `user_data` commitment (the sealed-bootstrap binding lives here).
    pub user_data: Option<Vec<u8>>,
    /// Optional consumer nonce.
    pub nonce: Option<Vec<u8>>,
    /// The decoded COSE envelope, retained so the verifier can check the
    /// signature without re-decoding.
    pub(crate) cose: CoseSign1,
}

/// Decode a Nitro attestation quote's COSE_Sign1 + CBOR structure with **no**
/// authenticity checks. Suitable as a libFuzzer target (`&[u8]` in, `Result`
/// out, total). See [`ParsedNitroQuote`] for the (unverified) result.
pub fn parse_nitro_quote(bytes: &[u8]) -> Result<ParsedNitroQuote, NitroParseError> {
    let cose = CoseSign1::from_slice(bytes)
        .map_err(|e| NitroParseError::CoseMalformed(format!("{e:?}")))?;

    let payload = cose
        .payload
        .as_deref()
        .ok_or(NitroParseError::PayloadMissing)?;

    let doc = NsmAttestationDoc::from_binary(payload)
        .map_err(|e| NitroParseError::CborMalformed(format!("{e:?}")))?;

    Ok(ParsedNitroQuote {
        module_id: doc.module_id,
        timestamp_ms: doc.timestamp,
        digest: doc.digest,
        pcrs: doc
            .pcrs
            .into_iter()
            .map(|(i, v)| (i, v.into_vec()))
            .collect(),
        certificate_der: doc.certificate.into_vec(),
        cabundle_der: doc.cabundle.into_iter().map(|c| c.into_vec()).collect(),
        public_key: doc.public_key.map(|b| b.into_vec()),
        user_data: doc.user_data.map(|b| b.into_vec()),
        nonce: doc.nonce.map(|b| b.into_vec()),
        cose,
    })
}
