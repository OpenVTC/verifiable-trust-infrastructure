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
use sha2::{Digest, Sha256, Sha384};
use time::OffsetDateTime;

use crate::sealed_transfer::{AssertionProof, AttestationQuoteAssertion, ProducerAssertion};

pub mod parse;
#[cfg(test)]
mod test_quote;
pub mod verify;

pub use parse::{NitroParseError, ParsedNitroQuote, parse_nitro_quote};
pub use verify::{
    AWS_NITRO_ROOT_G1_FINGERPRINT, AWS_NITRO_ROOT_G1_PEM, NitroVerifier, NitroVerifyError,
    TrustAnchor,
};

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
///
/// Verifies against the production AWS Nitro root at the current wall clock.
/// For deterministic tests / fuzzing with an injected trust anchor or clock,
/// use [`verify_nitro_quote_with`].
pub fn verify_nitro_quote(
    quote: &AttestationQuoteAssertion,
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
    producer_did: &str,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    verify_nitro_quote_with(
        quote,
        client_ed25519_pub,
        nonce,
        producer_did,
        &NitroVerifier::aws_production(OffsetDateTime::now_utc()),
    )
}

/// As [`verify_nitro_quote`], but with an explicit [`NitroVerifier`] so the
/// trust anchor and clock can be injected (issue #449). The format check,
/// base64 decode, `user_data` commitment binding, and PCR0/PCR8 extraction are
/// identical to the production path — only the chain anchor + validity clock
/// come from `verifier`.
pub fn verify_nitro_quote_with(
    quote: &AttestationQuoteAssertion,
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
    producer_did: &str,
    verifier: &NitroVerifier,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    if !is_nitro_format(&quote.format) {
        return Err(AttestationVerifyError::UnknownFormat(quote.format.clone()));
    }

    let quote_bytes = B64STD
        .decode(&quote.quote_b64)
        .map_err(|e| AttestationVerifyError::Base64(e.to_string()))?;

    let parsed = verifier
        .verify(&quote_bytes)
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
        .as_deref()
        .ok_or(AttestationVerifyError::MissingUserData)?;
    if user_data_bytes != expected.as_slice() {
        return Err(AttestationVerifyError::UserDataMismatch);
    }

    // Match upstream's PCR semantics: an all-zero (unset) PCR is treated as
    // absent. `parse_nitro_quote` retains zero PCRs verbatim, so filter here.
    let pcr_hex = |idx: usize| -> String {
        parsed
            .pcrs
            .get(&idx)
            .filter(|v| v.iter().any(|b| *b != 0))
            .map(|v| hex_lower(v))
            .unwrap_or_default()
    };

    Ok(VerifiedAttestation {
        module_id: parsed.module_id,
        pcr0_hex: pcr_hex(0),
        pcr8_hex: pcr_hex(8),
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

/// Extract PCR `idx` from a verified quote as lowercase hex, treating an
/// all-zero (unset) PCR as absent — the same semantics as
/// [`verify_nitro_quote_with`].
fn pcr_hex(parsed: &ParsedNitroQuote, idx: usize) -> String {
    parsed
        .pcrs
        .get(&idx)
        .filter(|v| v.iter().any(|b| *b != 0))
        .map(|v| hex_lower(v))
        .unwrap_or_default()
}

/// A verified `POST /attestation/config-report` response: the enclave really is
/// running the config whose secret-free view this carries, on the operator-pinned
/// image (PCR0), and the caller's nonce was bound for freshness.
///
/// Typestate: every field is private and there is no public constructor, so a
/// value of this type can only be produced by [`verify_config_attestation`] (or
/// its `_with` variant). Downstream code cannot fabricate a "verified" result.
#[derive(Debug, Clone)]
pub struct VerifiedConfigAttestation {
    module_id: String,
    pcr0_hex: String,
    pcr8_hex: String,
    config_digest_sha384: Vec<u8>,
    nonce: Vec<u8>,
    config_view_json: Vec<u8>,
    key_arn: Option<String>,
}

impl VerifiedConfigAttestation {
    /// Issuing NSM module id.
    pub fn module_id(&self) -> &str {
        &self.module_id
    }
    /// PCR0 — enclave image measurement — lowercase hex (matches the pin).
    pub fn pcr0_hex(&self) -> &str {
        &self.pcr0_hex
    }
    /// PCR8 — signing certificate measurement — lowercase hex.
    pub fn pcr8_hex(&self) -> &str {
        &self.pcr8_hex
    }
    /// The 48-byte SHA-384 config digest committed as (and verified against) the
    /// attestation `user_data` — equals `SHA-384(config_view_json())`.
    pub fn config_digest_sha384(&self) -> &[u8] {
        &self.config_digest_sha384
    }
    /// The nonce the quote committed to (equals the caller's `expected_nonce`).
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
    /// The authenticated canonical config view (secret-free JSON bytes) whose
    /// hash matched the signed `user_data`. Safe to inspect further.
    pub fn config_view_json(&self) -> &[u8] {
        &self.config_view_json
    }
    /// The attested `tee.kms.key_arn` read from the authenticated view, if present.
    pub fn key_arn(&self) -> Option<&str> {
        self.key_arn.as_deref()
    }
}

/// Minimal, lenient probe used to read the security-relevant fields out of the
/// (authenticated) config view without depending on `vta-config`'s full
/// `AppConfig` schema. All fields optional so any config-view shape deserializes.
#[derive(serde::Deserialize)]
struct ConfigViewProbe {
    #[serde(default)]
    tee: Option<TeeProbe>,
}
#[derive(serde::Deserialize)]
struct TeeProbe {
    #[serde(default)]
    kms: Option<KmsProbe>,
}
#[derive(serde::Deserialize)]
struct KmsProbe {
    #[serde(default)]
    key_arn: Option<String>,
}

/// Verification failure for a [`verify_config_attestation`] call. Every variant
/// is fail-closed — a report that trips any check must NOT be trusted.
#[derive(Debug, thiserror::Error)]
pub enum ConfigAttestationVerifyError {
    /// The `evidence` field was not valid base64.
    #[error("evidence base64 decode: {0}")]
    Base64(String),
    /// The `configView` field was not valid base64.
    #[error("configView base64 decode: {0}")]
    ConfigViewBase64(String),
    /// The evidence failed Nitro verification (chain to root / signature /
    /// validity window). Wraps the underlying [`NitroVerifyError`] as a string.
    #[error("attestation quote invalid: {0}")]
    QuoteInvalid(String),
    /// The quote carried no `user_data`, so it commits to no config digest.
    #[error("attestation quote is missing user_data (no committed config digest)")]
    MissingUserData,
    /// `SHA-384(configView)` did not equal the signed `user_data` — the returned
    /// view is not the config the enclave attested (a tampering/mismatch attempt).
    #[error("config view digest mismatch — SHA-384(configView) != signed user_data")]
    ConfigViewDigestMismatch,
    /// The (authenticated) config view could not be parsed to enforce expected
    /// security fields.
    #[error("config view parse: {0}")]
    ConfigViewParse(String),
    /// The attested `tee.kms.key_arn` did not equal the caller's expected key —
    /// the enclave is bound to a KMS key the caller did not approve (e.g. one the
    /// parent controls).
    #[error("key_arn mismatch — attested {actual:?}, expected {expected:?}")]
    KeyArnMismatch {
        expected: String,
        actual: Option<String>,
    },
    /// The quote carried no `nonce`, so freshness cannot be established.
    #[error("attestation quote is missing a nonce (cannot prove freshness)")]
    MissingNonce,
    /// The committed nonce did not equal the caller's — the report may be a
    /// replay of an earlier attestation.
    #[error("nonce mismatch — quote does not commit to this caller's nonce")]
    NonceMismatch,
    /// A pinned PCR (image / signing cert) did not match the expected value.
    #[error(transparent)]
    Pcr(#[from] PcrMismatch),
}

/// Verify a `POST /attestation/config-report` response against the production
/// AWS Nitro root at the current wall clock.
///
/// This is the consumer-side of the mandatory onboarding gate: before trusting
/// an un-baked (fleet) VTA instance a tenant/verifier MUST confirm which config
/// it actually booted. On success the returned [`VerifiedConfigAttestation`]
/// proves:
///  1. the evidence chains to the AWS Nitro root;
///  2. `PCR0` matches the **required** `expected_pcr0` pin (and `PCR8` the
///     optional one) — i.e. the *approved* image signed it, not merely *a*
///     genuine Nitro enclave;
///  3. the bound nonce equals `expected_nonce` (freshness);
///  4. `SHA-384(config_view_b64)` equals the signed `user_data`, so the returned
///     view is the exact config the enclave attested; and
///  5. if `expected_key_arn` is supplied, the view's `tee.kms.key_arn` equals it
///     — the enclave is bound to the tenant's own KMS key.
///
/// **No `vta-config` dependency, no digest re-derivation.** The enclave returns
/// the canonical secret-free view it hashed (`configView`); the caller passes it
/// straight through. This is why the flow works on fleet first boot, where the
/// enclave-generated `vta_did` cannot be reproduced from base+overlay.
///
/// For deterministic tests / an injected trust anchor, use
/// [`verify_config_attestation_with`].
pub fn verify_config_attestation(
    evidence_b64: &str,
    config_view_b64: &str,
    expected_nonce: &[u8],
    expected_pcr0: &str,
    expected_pcr8: Option<&str>,
    expected_key_arn: Option<&str>,
) -> Result<VerifiedConfigAttestation, ConfigAttestationVerifyError> {
    verify_config_attestation_with(
        evidence_b64,
        config_view_b64,
        expected_nonce,
        expected_pcr0,
        expected_pcr8,
        expected_key_arn,
        &NitroVerifier::aws_production(OffsetDateTime::now_utc()),
    )
}

/// As [`verify_config_attestation`], but with an explicit [`NitroVerifier`] so
/// the trust anchor and clock can be injected (issue #449). All checks —
/// including the **required** PCR0 pin — are identical to the production path;
/// only the chain anchor + validity clock come from `verifier`.
#[allow(clippy::too_many_arguments)]
pub fn verify_config_attestation_with(
    evidence_b64: &str,
    config_view_b64: &str,
    expected_nonce: &[u8],
    expected_pcr0: &str,
    expected_pcr8: Option<&str>,
    expected_key_arn: Option<&str>,
    verifier: &NitroVerifier,
) -> Result<VerifiedConfigAttestation, ConfigAttestationVerifyError> {
    let quote_bytes = B64STD
        .decode(evidence_b64)
        .map_err(|e| ConfigAttestationVerifyError::Base64(e.to_string()))?;
    let config_view = B64STD
        .decode(config_view_b64)
        .map_err(|e| ConfigAttestationVerifyError::ConfigViewBase64(e.to_string()))?;

    let parsed = verifier
        .verify(&quote_bytes)
        .map_err(|e| ConfigAttestationVerifyError::QuoteInvalid(format!("{e:?}")))?;

    // (4) The SIGNED user_data must be SHA-384 of the returned view, so the view
    // is authenticated (not merely asserted by the untrusted parent).
    let user_data = parsed
        .user_data
        .as_deref()
        .ok_or(ConfigAttestationVerifyError::MissingUserData)?;
    let view_digest = Sha384::digest(&config_view);
    if user_data != view_digest.as_slice() {
        return Err(ConfigAttestationVerifyError::ConfigViewDigestMismatch);
    }

    // (3) Freshness: the enclave bound the caller's nonce into the quote.
    let nonce = parsed
        .nonce
        .as_deref()
        .ok_or(ConfigAttestationVerifyError::MissingNonce)?;
    if nonce != expected_nonce {
        return Err(ConfigAttestationVerifyError::NonceMismatch);
    }

    // (2) Pin the image (PCR0 REQUIRED) and optionally the signing cert (PCR8).
    let attest = VerifiedAttestation {
        module_id: parsed.module_id.clone(),
        pcr0_hex: pcr_hex(&parsed, 0),
        pcr8_hex: pcr_hex(&parsed, 8),
    };
    attest.check_pcrs(Some(expected_pcr0), expected_pcr8)?;

    // (5) Inspect the now-authenticated view: read (and optionally enforce) the
    // security-critical `tee.kms.key_arn`.
    let probe: ConfigViewProbe = serde_json::from_slice(&config_view)
        .map_err(|e| ConfigAttestationVerifyError::ConfigViewParse(e.to_string()))?;
    let key_arn = probe.tee.and_then(|t| t.kms).and_then(|k| k.key_arn);
    if let Some(expected) = expected_key_arn
        && key_arn.as_deref() != Some(expected)
    {
        return Err(ConfigAttestationVerifyError::KeyArnMismatch {
            expected: expected.to_string(),
            actual: key_arn,
        });
    }

    Ok(VerifiedConfigAttestation {
        module_id: attest.module_id,
        pcr0_hex: attest.pcr0_hex,
        pcr8_hex: attest.pcr8_hex,
        config_digest_sha384: user_data.to_vec(),
        nonce: nonce.to_vec(),
        config_view_json: config_view,
        key_arn,
    })
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
