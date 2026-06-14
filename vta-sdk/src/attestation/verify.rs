//! Local AWS Nitro attestation verifier with an **injectable trust anchor and
//! clock** (issue #449).
//!
//! The upstream `nitro_attest` crate fuses parse + verify into a single
//! `parse_and_verify(now)` call and bakes the AWS Nitro root-cert fingerprint
//! at build time (`include_bytes!`), so it offers no way to (a) parse without
//! verifying or (b) substitute a different trust anchor for deterministic
//! end-to-end tests. This module reimplements just the **verification glue**
//! upstream keeps private — the certificate-chain walk and the COSE_Sign1
//! signature check — over the *same* audited primitives upstream uses
//! ([`x509_parser`]'s `verify_signature`, [`ring`]'s `ECDSA_P384_SHA384_FIXED`,
//! SHA-256 fingerprinting). It does not reimplement any cryptography.
//!
//! Production verification ([`super::verify_nitro_quote`]) drives this with
//! [`TrustAnchor::AwsProduction`] and the wall clock, exactly matching upstream
//! behaviour; the [`TrustAnchor::RootFingerprint`] + injectable `now` exist for
//! deterministic tests and fuzzing. The `attestation` parity tests
//! cross-check this verifier against upstream so the two cannot silently drift.

use std::iter::once;

use ring::digest::{self, SHA256};
use ring::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA384;
use x509_parser::prelude::FromDer;
use x509_parser::validate::{Validator, X509StructureValidator};

use super::parse::{ParsedNitroQuote, parse_nitro_quote};

/// SHA-256 of the **DER** body of the AWS Nitro Enclaves Root-G1 certificate
/// (`aws_nitro_root_g1.pem`). This is the exact value the upstream
/// `nitro_attest` build bakes from the same cert and the value AWS publishes at
/// <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>.
/// `tests` re-derives it from the vendored PEM and cross-checks it against
/// upstream, so a wrong byte here fails CI.
pub const AWS_NITRO_ROOT_G1_FINGERPRINT: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// The vendored AWS Nitro Root-G1 certificate (PEM). Kept for auditability and
/// to let `tests` re-derive [`AWS_NITRO_ROOT_G1_FINGERPRINT`] from its DER body.
pub const AWS_NITRO_ROOT_G1_PEM: &str = include_str!("aws_nitro_root_g1.pem");

/// The root of trust the chain must terminate in. The chain's root certificate
/// is verified by SHA-256 fingerprint match (the root is self-signed; upstream
/// does the same — it never uses the root's key to verify a signature).
#[derive(Debug, Clone, Copy)]
pub enum TrustAnchor {
    /// The production AWS Nitro Root-G1 anchor ([`AWS_NITRO_ROOT_G1_FINGERPRINT`]).
    AwsProduction,
    /// An arbitrary root fingerprint (SHA-256 of the root cert's DER). For
    /// deterministic tests and fuzzing against a synthetic chain.
    RootFingerprint([u8; 32]),
}

impl TrustAnchor {
    fn fingerprint(&self) -> [u8; 32] {
        match self {
            TrustAnchor::AwsProduction => AWS_NITRO_ROOT_G1_FINGERPRINT,
            TrustAnchor::RootFingerprint(fp) => *fp,
        }
    }
}

/// A full Nitro attestation verifier: walk the certificate chain to the
/// configured [`TrustAnchor`], check each cert's validity window against `now`,
/// and verify the COSE_Sign1 signature with the leaf cert's key.
#[derive(Debug, Clone, Copy)]
pub struct NitroVerifier {
    /// Root of trust the chain must terminate in.
    pub anchor: TrustAnchor,
    /// The instant to evaluate certificate validity windows against.
    pub now: OffsetDateTime,
}

impl NitroVerifier {
    /// Verifier pinned to the production AWS Nitro root at the given instant.
    pub fn aws_production(now: OffsetDateTime) -> Self {
        Self {
            anchor: TrustAnchor::AwsProduction,
            now,
        }
    }

    /// Decode and fully verify `bytes`. On success the returned
    /// [`ParsedNitroQuote`] has been authenticated: its chain terminates in the
    /// trust anchor, every cert was within its validity window at `self.now`,
    /// and the COSE signature checks out under the leaf key. Post-verification
    /// `user_data`/PCR semantics are layered on by the caller.
    pub fn verify(&self, bytes: &[u8]) -> Result<ParsedNitroQuote, NitroVerifyError> {
        let parsed = parse_nitro_quote(bytes)?;
        // Borrow the DER blobs for the chain walk + signature check in an inner
        // scope so the X509 borrows end before we move `parsed` out.
        let leaf_spki_der: Vec<u8> = {
            // Chain order is root-first: cabundle[0..] then the leaf cert.
            let chain_der: Vec<&[u8]> = parsed
                .cabundle_der
                .iter()
                .map(Vec::as_slice)
                .chain(once(parsed.certificate_der.as_slice()))
                .collect();

            if chain_der.is_empty() {
                return Err(NitroVerifyError::NoCertificates);
            }

            let mut parent: Option<X509Certificate> = None;
            let mut leaf_spki: Option<Vec<u8>> = None;
            for (idx, der) in chain_der.iter().enumerate() {
                let cert = parse_cert(der, idx)?;
                verify_cert(&cert, der, parent.as_ref(), self.anchor.fingerprint(), idx)?;
                validate_window(&cert, self.now, idx)?;
                leaf_spki = Some(cert.public_key().subject_public_key.as_ref().to_vec());
                parent = Some(cert);
            }
            // Safe: chain_der is non-empty so the loop set this at least once.
            leaf_spki.expect("non-empty chain sets leaf SPKI")
        };

        // COSE_Sign1 signature over the leaf key (ECDSA P-384 / SHA-384), AAD
        // empty — identical to upstream's `verify_signature(&[], …)`.
        parsed.cose.verify_signature(&[], |sig, data| {
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &leaf_spki_der)
                .verify(data, sig)
                .map_err(|_| NitroVerifyError::CoseSignatureInvalid)
        })?;

        Ok(parsed)
    }
}

/// A certificate-chain or signature verification failure. Distinct from
/// [`NitroParseError`](super::parse::NitroParseError), which means the bytes
/// were not a well-formed document at all.
#[derive(Debug, thiserror::Error)]
pub enum NitroVerifyError {
    /// Structural decode failure (delegated to [`parse_nitro_quote`]).
    #[error(transparent)]
    Parse(#[from] super::parse::NitroParseError),
    /// The document carried no certificates.
    #[error("no certificates in attestation document")]
    NoCertificates,
    /// Certificate `idx` failed to parse as DER.
    #[error("certificate {idx} malformed")]
    CertMalformed { idx: usize },
    /// Certificate `idx` failed X.509 structure validation.
    #[error("certificate {idx} structure invalid")]
    CertStructureInvalid { idx: usize },
    /// Certificate `idx` is signed with an algorithm other than the expected
    /// ECDSA-with-SHA384.
    #[error("certificate {idx} unexpected signature algorithm")]
    UnexpectedAlgorithm { idx: usize },
    /// Certificate `idx`'s signature did not verify against its parent.
    #[error("certificate {idx} signature invalid")]
    SignatureInvalid { idx: usize },
    /// The chain's root fingerprint did not match the trust anchor.
    #[error("root fingerprint mismatch: have {have}, want {want}")]
    RootFingerprintMismatch { have: String, want: String },
    /// Certificate `idx` was expired at the verifier's `now`.
    #[error("certificate {idx} expired")]
    CertExpired { idx: usize },
    /// Certificate `idx` was not yet valid at the verifier's `now`.
    #[error("certificate {idx} not yet valid")]
    CertNotYetValid { idx: usize },
    /// The COSE_Sign1 signature did not verify under the leaf key.
    #[error("COSE signature verification failed")]
    CoseSignatureInvalid,
}

fn parse_cert<'a>(der: &'a [u8], idx: usize) -> Result<X509Certificate<'a>, NitroVerifyError> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|_| NitroVerifyError::CertMalformed { idx })?;
    let mut logger = x509_parser::validate::VecLogger::default();
    if !X509StructureValidator.validate(&cert, &mut logger) {
        return Err(NitroVerifyError::CertStructureInvalid { idx });
    }
    Ok(cert)
}

/// Verify a cert against its parent (or, for the root, by fingerprint match to
/// the trust anchor). Mirrors `nitro_attest::Cert::verify`.
fn verify_cert(
    cert: &X509Certificate,
    der: &[u8],
    parent: Option<&X509Certificate>,
    anchor_fp: [u8; 32],
    idx: usize,
) -> Result<(), NitroVerifyError> {
    if cert.signature_algorithm.oid() != &OID_SIG_ECDSA_WITH_SHA384 {
        return Err(NitroVerifyError::UnexpectedAlgorithm { idx });
    }
    match parent {
        Some(parent) => cert
            .verify_signature(Some(parent.public_key()))
            .map_err(|_| NitroVerifyError::SignatureInvalid { idx }),
        None => {
            let have = digest::digest(&SHA256, der);
            if have.as_ref() != anchor_fp {
                return Err(NitroVerifyError::RootFingerprintMismatch {
                    have: crate::hex::lower(have.as_ref()),
                    want: crate::hex::lower(&anchor_fp),
                });
            }
            Ok(())
        }
    }
}

/// Check a cert's validity window against `now`. Mirrors
/// `nitro_attest::Cert::validate`.
fn validate_window(
    cert: &X509Certificate,
    now: OffsetDateTime,
    idx: usize,
) -> Result<(), NitroVerifyError> {
    if now > cert.validity.not_after.to_datetime() {
        return Err(NitroVerifyError::CertExpired { idx });
    }
    if now < cert.validity.not_before.to_datetime() {
        return Err(NitroVerifyError::CertNotYetValid { idx });
    }
    Ok(())
}
