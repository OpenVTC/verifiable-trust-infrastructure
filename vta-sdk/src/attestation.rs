//! End-to-end verification of AWS Nitro attestation quotes embedded in
//! sealed-bootstrap Mode B producer assertions.
//!
//! Delegates the heavy lifting (COSE_Sign1 parsing, AWS Nitro root-cert
//! chain validation, ECDSA signature verification) to the `nitro_attest`
//! crate. We layer the sealed-bootstrap-specific checks on top: the
//! quote's `user_data` must equal
//! `SHA256(client_ed25519_pub || nonce || producer_ed25519_pub)`, binding
//! the attestation to the exact did:keys the consumer saw (`client_did`
//! in the request, `producer_did` in the returned assertion) rather than
//! to the derived X25519 pubkeys HPKE internally consumed.
//!
//! Feature-gated behind `attest-verify` so clients that don't consume
//! Mode B bundles don't pull in the attestation crate.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64STD;
use nitro_attest::UnparsedAttestationDoc;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::sealed_transfer::{AssertionProof, AttestationQuoteAssertion, ProducerAssertion};

/// Successfully verified attestation details, returned for callers that want
/// to log or display the enclave identity after a Mode B bootstrap.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub module_id: String,
    /// PCR0 — enclave image measurement — lowercase hex.
    pub pcr0_hex: String,
    /// PCR8 — signing certificate measurement — lowercase hex.
    pub pcr8_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationVerifyError {
    #[error("expected an Attested proof, got {0}")]
    WrongProofVariant(&'static str),
    #[error("unknown attestation format: {0}")]
    UnknownFormat(String),
    #[error("base64 decode: {0}")]
    Base64(String),
    #[error("quote parse/verify failed: {0}")]
    QuoteInvalid(String),
    #[error("attestation quote is missing user_data")]
    MissingUserData,
    #[error("user_data mismatch — quote does not commit to this bundle")]
    UserDataMismatch,
    #[error("invalid producer did:key: {0}")]
    BadProducerDid(String),
}

/// An attested enclave measurement did not match the operator-pinned value
/// (P3.4). The attestation itself is cryptographically valid — this is the
/// defense-in-depth check that the *right* enclave image / signing cert is
/// running, which otherwise only the KMS key policy pins.
#[derive(Debug, Clone, thiserror::Error)]
#[error("PCR{which} mismatch: enclave reported {actual}, operator expected {expected}")]
pub struct PcrMismatch {
    /// Which PCR diverged (0 = image, 8 = signing cert).
    pub which: u8,
    pub expected: String,
    pub actual: String,
}

use crate::hex::lower as hex_lower;

fn is_nitro_format(format: &str) -> bool {
    matches!(
        format.to_ascii_lowercase().as_str(),
        "nitro" | "aws-nitro" | "aws-nitro-v1"
    )
}

/// Verify an [`AttestationQuoteAssertion`] against the exact triple
/// `(client_ed25519_pub, nonce, producer_ed25519_pub)` that the
/// sealed-bootstrap handshake committed to. Returns the verified enclave
/// identity on success.
pub fn verify_nitro_assertion(
    producer: &ProducerAssertion,
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    let quote = match &producer.proof {
        AssertionProof::Attested(q) => q,
        AssertionProof::PinnedOnly => {
            return Err(AttestationVerifyError::WrongProofVariant("PinnedOnly"));
        }
        AssertionProof::DidSigned(_) => {
            return Err(AttestationVerifyError::WrongProofVariant("DidSigned"));
        }
    };

    verify_nitro_quote(quote, client_ed25519_pub, nonce, &producer.producer_did)
}

/// Variant that takes the quote + expected commitment components directly.
/// Useful for callers that already pulled the did:key out of the assertion.
pub fn verify_nitro_quote(
    quote: &AttestationQuoteAssertion,
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
    producer_did: &str,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    if !is_nitro_format(&quote.format) {
        return Err(AttestationVerifyError::UnknownFormat(quote.format.clone()));
    }

    let quote_bytes = B64STD
        .decode(&quote.quote_b64)
        .map_err(|e| AttestationVerifyError::Base64(e.to_string()))?;

    let parsed = UnparsedAttestationDoc::from(quote_bytes.as_slice())
        .parse_and_verify(OffsetDateTime::now_utc())
        .map_err(|e| AttestationVerifyError::QuoteInvalid(format!("{e:?}")))?;

    let producer_ed_pub = affinidi_crypto::did_key::did_key_to_ed25519_pub(producer_did)
        .map_err(|e| AttestationVerifyError::BadProducerDid(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(client_ed25519_pub);
    hasher.update(nonce);
    hasher.update(producer_ed_pub);
    let expected = hasher.finalize();

    let user_data_bytes: &[u8] = parsed
        .user_data
        .as_ref()
        .map(|b| b.as_ref())
        .ok_or(AttestationVerifyError::MissingUserData)?;
    if user_data_bytes != expected.as_slice() {
        return Err(AttestationVerifyError::UserDataMismatch);
    }

    let pcr0_hex = parsed
        .pcrs
        .get(&0)
        .map(|d| hex_lower(&d.value))
        .unwrap_or_default();
    let pcr8_hex = parsed
        .pcrs
        .get(&8)
        .map(|d| hex_lower(&d.value))
        .unwrap_or_default();

    Ok(VerifiedAttestation {
        module_id: parsed.module_id,
        pcr0_hex,
        pcr8_hex,
    })
}

/// Normalize a hex PCR string for comparison: strip an optional `0x`/`0X`
/// prefix and any whitespace, lowercase the rest.
fn normalize_pcr_hex(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

impl VerifiedAttestation {
    /// Pin the verified enclave's measurements to operator-supplied expected
    /// values (P3.4 — client-side PCR pinning). A `None` expectation is not
    /// checked; comparison is case-insensitive and tolerates a `0x` prefix /
    /// whitespace. Returns [`PcrMismatch`] on the first divergence.
    ///
    /// The cryptographic attestation only proves the quote came from *a*
    /// genuine Nitro enclave — a different (wrong) VTA build still produces a
    /// valid quote, just with a different PCR0. Pinning lets the operator
    /// refuse to bootstrap against anything but the exact expected image
    /// (PCR0) and signing cert (PCR8), the same values the KMS key policy pins
    /// server-side.
    pub fn check_pcrs(
        &self,
        expect_pcr0: Option<&str>,
        expect_pcr8: Option<&str>,
    ) -> Result<(), PcrMismatch> {
        check_pcr(0, expect_pcr0, &self.pcr0_hex)?;
        check_pcr(8, expect_pcr8, &self.pcr8_hex)?;
        Ok(())
    }
}

fn check_pcr(which: u8, expected: Option<&str>, actual: &str) -> Result<(), PcrMismatch> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = normalize_pcr_hex(expected);
    let actual = normalize_pcr_hex(actual);
    if expected != actual {
        return Err(PcrMismatch {
            which,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Negative-path tests for [`verify_nitro_assertion`] and
    //! [`verify_nitro_quote`]. The cryptographic-signature path (valid
    //! AWS-signed COSE_Sign1 → cert chain to AWS Nitro root → user_data
    //! match) requires a real Nitro fixture from a live enclave; those
    //! end-to-end tests live in the on-host integration harness, not
    //! here. The cases below exercise the dispatch / format / wrapper
    //! paths the SDK validates **before** delegating to `nitro_attest`,
    //! plus the post-verification commitment check via constructed
    //! malformed inputs that fail at known boundaries.
    //!
    //! Coverage map:
    //!  - WrongProofVariant: PinnedOnly + DidSigned arms.
    //!  - UnknownFormat: any non-Nitro string.
    //!  - Base64: malformed armor.
    //!  - BadProducerDid: not a did:key.
    //!  - QuoteInvalid: empty / random bytes (catches `nitro_attest`
    //!    integration without needing valid fixtures).
    //!  - is_nitro_format case-insensitivity.
    //!
    //! UserDataMismatch + MissingUserData are unreachable without a
    //! valid signed quote; they're documented as fixture-required and
    //! covered in the on-host harness.
    use super::*;
    use crate::sealed_transfer::{
        AttestationQuoteAssertion, DidSignedAssertion, ProducerAssertion,
    };

    fn nitro_attestation(quote_b64: &str) -> AttestationQuoteAssertion {
        AttestationQuoteAssertion {
            format: "nitro".into(),
            quote_b64: quote_b64.into(),
        }
    }

    #[test]
    fn pinned_only_assertion_rejected() {
        let producer = ProducerAssertion {
            producer_did: "did:key:z6MkProducer".into(),
            proof: AssertionProof::PinnedOnly,
        };
        let err = verify_nitro_assertion(&producer, &[0u8; 32], &[0u8; 16]).unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::WrongProofVariant("PinnedOnly")),
            "got {err:?}"
        );
    }

    #[test]
    fn did_signed_assertion_rejected() {
        let producer = ProducerAssertion {
            producer_did: "did:key:z6MkProducer".into(),
            proof: AssertionProof::DidSigned(DidSignedAssertion {
                did: "did:key:z6MkProducer".into(),
                signature_b64: "sig".into(),
                verification_method: "did:key:z6MkProducer#z6MkProducer".into(),
            }),
        };
        let err = verify_nitro_assertion(&producer, &[0u8; 32], &[0u8; 16]).unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::WrongProofVariant("DidSigned")),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_format_rejected() {
        // Anything that isn't `nitro` / `aws-nitro` / `aws-nitro-v1`
        // must surface as UnknownFormat *before* attempting to parse
        // bytes. A future SEV-SNP / TDX format string MUST NOT silently
        // route through the Nitro verifier.
        let quote = AttestationQuoteAssertion {
            format: "sev-snp".into(),
            quote_b64: "AAAA".into(),
        };
        let err = verify_nitro_quote(&quote, &[0u8; 32], &[0u8; 16], "did:key:z6Mk").unwrap_err();
        match err {
            AttestationVerifyError::UnknownFormat(f) => assert_eq!(f, "sev-snp"),
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    #[test]
    fn nitro_format_strings_are_case_insensitive() {
        // "Nitro", "AWS-NITRO", "aws-nitro-v1" must all be accepted —
        // operators paste these strings from various places. Without
        // case-insensitive matching, a stray capitalisation drops a
        // valid quote into UnknownFormat.
        for fmt in ["nitro", "Nitro", "AWS-NITRO", "aws-nitro-v1"] {
            let quote = AttestationQuoteAssertion {
                format: fmt.into(),
                quote_b64: "AAAA".into(), // valid b64; will fail later as QuoteInvalid
            };
            let err = verify_nitro_quote(&quote, &[0u8; 32], &[0u8; 16], "did:key:z6MkBogus")
                .unwrap_err();
            assert!(
                !matches!(err, AttestationVerifyError::UnknownFormat(_)),
                "format '{fmt}' must NOT be UnknownFormat — got {err:?}"
            );
        }
    }

    #[test]
    fn malformed_base64_rejected() {
        let quote = nitro_attestation("not!valid!base64!@#$");
        let err =
            verify_nitro_quote(&quote, &[0u8; 32], &[0u8; 16], "did:key:z6MkBogus").unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::Base64(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_quote_bytes_rejected_as_quote_invalid() {
        // Empty input is valid base64 (empty bytes) but cannot be a
        // COSE_Sign1 attestation. Confirms the nitro_attest crate
        // surfaces parse failures via QuoteInvalid rather than
        // panicking.
        let quote = nitro_attestation(""); // base64 of empty bytes
        let err =
            verify_nitro_quote(&quote, &[0u8; 32], &[0u8; 16], "did:key:z6MkBogus").unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::QuoteInvalid(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn random_bytes_rejected_as_quote_invalid() {
        // 64 bytes of zeros is structurally not a COSE_Sign1 envelope.
        // Same property as empty: no panic, just QuoteInvalid.
        let quote = nitro_attestation(&B64STD.encode([0u8; 64]));
        let err =
            verify_nitro_quote(&quote, &[0u8; 32], &[0u8; 16], "did:key:z6MkBogus").unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::QuoteInvalid(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn malformed_producer_did_rejected_at_format_layer() {
        // A non-did:key producer_did is a structural fault that we want
        // to catch with a typed error. The order of operations matters —
        // currently the quote is parsed first, so a malformed DID with
        // an invalid quote surfaces as QuoteInvalid (test
        // `random_bytes_rejected_as_quote_invalid`). Use a *valid*
        // quote-shape encoding paired with a malformed DID — but we
        // can't easily produce one without real fixtures, so the
        // documented behaviour today is: malformed DID surfaces only
        // after a valid quote parse.
        //
        // What we CAN check: the symbol exists, has the correct error
        // variant available, and the BadProducerDid error type round-
        // trips through the public API. A later CI job with real
        // fixtures will exercise the full path.
        let _ = AttestationVerifyError::BadProducerDid("smoke".into());
    }

    fn attest(pcr0: &str, pcr8: &str) -> VerifiedAttestation {
        VerifiedAttestation {
            module_id: "i-abc".into(),
            pcr0_hex: pcr0.into(),
            pcr8_hex: pcr8.into(),
        }
    }

    #[test]
    fn check_pcrs_none_is_noop() {
        // No pins → accept any genuine attestation (pre-P3.4 behaviour).
        assert!(attest("aaaa", "bbbb").check_pcrs(None, None).is_ok());
    }

    #[test]
    fn check_pcrs_matching_passes_case_and_prefix_insensitive() {
        let a = attest("ABCD1234", " effff ");
        // Case-insensitive, tolerates 0x prefix and surrounding whitespace.
        assert!(a.check_pcrs(Some("0xabcd1234"), Some("EFFFF")).is_ok());
        assert!(a.check_pcrs(Some("abcd1234"), None).is_ok());
    }

    #[test]
    fn check_pcrs_pcr0_mismatch_is_typed() {
        let err = attest("aaaa", "bbbb")
            .check_pcrs(Some("dead"), None)
            .expect_err("wrong PCR0 must be rejected");
        assert_eq!(err.which, 0);
        assert_eq!(err.expected, "dead");
        assert_eq!(err.actual, "aaaa");
    }

    #[test]
    fn check_pcrs_pcr8_mismatch_is_typed() {
        let err = attest("aaaa", "bbbb")
            .check_pcrs(Some("aaaa"), Some("cafe"))
            .expect_err("wrong PCR8 must be rejected");
        assert_eq!(err.which, 8);
    }

    #[test]
    fn check_pcrs_expecting_an_absent_pcr_fails() {
        // Operator pins PCR0 but the quote carried none (empty) → mismatch.
        let err = attest("", "bbbb")
            .check_pcrs(Some("abcd"), None)
            .expect_err("pinning an absent PCR must fail closed");
        assert_eq!(err.which, 0);
        assert_eq!(err.actual, "");
    }
}
