use std::fmt;

use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

/// The JOSE algorithm a key signs with, fixed by the key and never by the
/// caller (RFC 8725 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// Ed25519.
    EdDsa,
    /// ECDSA over P-256 with SHA-256.
    Es256,
}

impl Algorithm {
    /// The name the IANA JOSE registry gives it, as a JWS header carries it.
    pub fn jose_name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
}

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

enum Key {
    Ed25519(Zeroizing<[u8; 32]>),
    P256(p256::ecdsa::SigningKey),
}

/// An Ed25519 or P-256 signing key.
///
/// The secret is zeroized when the value is dropped, and never appears in its
/// `Debug` output.
pub struct SigningSecret {
    key: Key,
}

impl SigningSecret {
    /// An Ed25519 key from its 32-byte seed.
    pub fn ed25519(seed: [u8; 32]) -> Self {
        Self {
            key: Key::Ed25519(Zeroizing::new(seed)),
        }
    }

    /// An Ed25519 key from a slice that must be exactly 32 bytes.
    pub fn ed25519_from_slice(seed: &[u8]) -> Result<Self, SecretError> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| SecretError::Length {
            expected: 32,
            got: seed.len(),
        })?;
        Ok(Self::ed25519(seed))
    }

    /// A P-256 key from its big-endian scalar.
    pub fn p256_from_slice(scalar: &[u8]) -> Result<Self, SecretError> {
        let key = p256::ecdsa::SigningKey::from_slice(scalar)
            .map_err(|e| SecretError::Invalid(e.to_string()))?;
        Ok(Self {
            key: Key::P256(key),
        })
    }

    /// The algorithm this key signs with.
    pub fn algorithm(&self) -> Algorithm {
        match self.key {
            Key::Ed25519(_) => Algorithm::EdDsa,
            Key::P256(_) => Algorithm::Es256,
        }
    }

    /// The public half: 32 bytes for Ed25519, the 33-byte compressed SEC1 point
    /// for P-256.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.key {
            Key::Ed25519(seed) => ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            Key::P256(key) => key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
        }
    }

    /// The signature of exactly `message`: 64 bytes for both algorithms (for
    /// ES256, the fixed-width `r || s` a JWS carries).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Ed25519(seed) => ed25519_dalek::SigningKey::from_bytes(seed)
                .sign(message)
                .to_bytes()
                .to_vec(),
            Key::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_bytes().to_vec()
            }
        }
    }
}

impl fmt::Debug for SigningSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningSecret")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier as _;

    use super::*;

    #[test]
    fn an_ed25519_key_signs_what_ed25519_verifies() {
        let secret = SigningSecret::ed25519([7; 32]);
        let signature = secret.sign(b"message");

        let public: [u8; 32] = secret.public_key().try_into().unwrap();
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        assert!(verifying.verify(b"message", &signature).is_ok());
        assert!(verifying.verify(b"another", &signature).is_err());
        assert_eq!(secret.algorithm(), Algorithm::EdDsa);
        assert_eq!(secret.algorithm().jose_name(), "EdDSA");
    }

    #[test]
    fn an_ed25519_signature_is_the_one_the_reference_implementation_makes() {
        let seed = [42u8; 32];
        let expected = ed25519_dalek::SigningKey::from_bytes(&seed)
            .sign(b"hash data")
            .to_bytes()
            .to_vec();

        assert_eq!(SigningSecret::ed25519(seed).sign(b"hash data"), expected);
    }

    #[test]
    fn a_p256_key_signs_what_p256_verifies_in_fixed_width() {
        let secret = SigningSecret::p256_from_slice(&[9u8; 32]).unwrap();
        let signature = secret.sign(b"message");

        assert_eq!(signature.len(), 64);
        let public = secret.public_key();
        assert_eq!(public.len(), 33);
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).unwrap();
        let signature = p256::ecdsa::Signature::from_slice(&signature).unwrap();
        assert!(verifying.verify(b"message", &signature).is_ok());
        assert!(verifying.verify(b"another", &signature).is_err());
        assert_eq!(secret.algorithm(), Algorithm::Es256);
        assert_eq!(secret.algorithm().jose_name(), "ES256");
    }

    #[test]
    fn signing_is_deterministic() {
        for secret in [
            SigningSecret::ed25519([1; 32]),
            SigningSecret::p256_from_slice(&[2; 32]).unwrap(),
        ] {
            assert_eq!(secret.sign(b"same"), secret.sign(b"same"));
            assert_ne!(secret.sign(b"same"), secret.sign(b"other"));
        }
    }

    #[test]
    fn key_material_of_the_wrong_shape_is_refused() {
        assert_eq!(
            SigningSecret::ed25519_from_slice(&[0u8; 31]).unwrap_err(),
            SecretError::Length {
                expected: 32,
                got: 31
            }
        );
        assert!(SigningSecret::ed25519_from_slice(&[0u8; 32]).is_ok());
        assert!(matches!(
            SigningSecret::p256_from_slice(&[0u8; 32]),
            Err(SecretError::Invalid(_))
        ));
        assert!(matches!(
            SigningSecret::p256_from_slice(&[1u8; 5]),
            Err(SecretError::Invalid(_))
        ));
    }

    #[test]
    fn the_debug_form_names_the_algorithm_and_nothing_else() {
        let shown = format!("{:?}", SigningSecret::ed25519([0xAB; 32]));

        assert!(shown.contains("EdDsa"), "{shown}");
        assert!(
            !shown.contains("171") && !shown.to_lowercase().contains("ab, ab"),
            "{shown}"
        );
    }
}
