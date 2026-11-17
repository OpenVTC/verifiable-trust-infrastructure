use std::fmt;

use crate::{Algorithm, FormatRefusal};

/// Why key material could not be used as a signing key.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretError {
    /// An Ed25519 seed is exactly 32 bytes.
    Length { expected: usize, got: usize },
    /// The bytes are not a valid P-256 scalar.
    Invalid(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, got } => {
                write!(f, "a key of {expected} bytes is required, got {got}")
            }
            Self::Invalid(reason) => write!(f, "not a valid signing key: {reason}"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Why a public key could not be read.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyParseError {
    /// The multibase text is not valid.
    Multibase(String),
    /// The multicodec prefix names a key type this crate does not sign with.
    UnsupportedCodec,
    /// The key has the wrong length, or is not a point on its curve.
    InvalidKey(String),
}

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Multibase(reason) => write!(f, "not valid multibase: {reason}"),
            Self::UnsupportedCodec => write!(f, "not an Ed25519 or P-256 public key"),
            Self::InvalidKey(reason) => write!(f, "not a valid public key: {reason}"),
        }
    }
}

impl std::error::Error for KeyParseError {}

/// Why something could not be signed.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The request cannot be turned into bytes to sign; nothing was signed.
    Format(FormatRefusal),
    /// The key signs with another algorithm than the format needs.
    Algorithm { expected: Algorithm, got: Algorithm },
    /// The signer could not make the signature (a remote or hardware signer).
    Signer(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(refusal) => write!(f, "the request cannot be signed: {refusal:?}"),
            Self::Algorithm { expected, got } => write!(
                f,
                "this needs a {} key, got a {} key",
                expected.jose_name(),
                got.jose_name()
            ),
            Self::Signer(reason) => write!(f, "the signer failed: {reason}"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<FormatRefusal> for SignError {
    fn from(refusal: FormatRefusal) -> Self {
        Self::Format(refusal)
    }
}

/// Why a signed artefact did not verify.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The artefact is not shaped as its format requires.
    Malformed(String),
    /// The artefact names another algorithm than the key's.
    Algorithm { expected: Algorithm, got: String },
    /// The signature does not verify.
    Signature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed: {reason}"),
            Self::Algorithm { expected, got } => {
                write!(
                    f,
                    "the key signs with {}, the artefact says {got}",
                    expected.jose_name()
                )
            }
            Self::Signature => write!(f, "the signature does not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}
