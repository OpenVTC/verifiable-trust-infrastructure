use std::fmt;

use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

use crate::{KeyParseError, SecretError, SignError, VerifyError};

const ED25519_PUB_CODEC: [u8; 2] = [0xed, 0x01];
const P256_PUB_CODEC: [u8; 2] = [0x80, 0x24];

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

    /// The algorithm a JOSE name spells, if this crate signs with it.
    pub fn from_jose_name(name: &str) -> Option<Self> {
        match name {
            "EdDSA" => Some(Self::EdDsa),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }
}

/// The public half of a signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKey {
    /// The 32-byte Ed25519 public key.
    Ed25519([u8; 32]),
    /// The 33-byte compressed SEC1 point of a P-256 public key.
    P256([u8; 33]),
}

impl PublicKey {
    /// The algorithm this key verifies.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::EdDsa,
            Self::P256(_) => Algorithm::Es256,
        }
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(key) => key,
            Self::P256(key) => key,
        }
    }

    /// Whether `signature` is this key's signature over exactly `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        match self {
            Self::Ed25519(key) => {
                use ed25519_dalek::Verifier as _;
                let key = ed25519_dalek::VerifyingKey::from_bytes(key)
                    .map_err(|e| VerifyError::Malformed(format!("public key: {e}")))?;
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| VerifyError::Signature)?;
                key.verify(message, &signature)
                    .map_err(|_| VerifyError::Signature)
            }
            Self::P256(key) => {
                use p256::ecdsa::signature::Verifier as _;
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .map_err(|e| VerifyError::Malformed(format!("public key: {e}")))?;
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| VerifyError::Signature)?;
                key.verify(message, &signature)
                    .map_err(|_| VerifyError::Signature)
            }
        }
    }

    /// The key as the multibase base58btc string a `did:key` carries: the
    /// multicodec prefix and the key, with a `z` in front.
    pub fn to_multibase(&self) -> String {
        let mut prefixed = match self {
            Self::Ed25519(_) => ED25519_PUB_CODEC.to_vec(),
            Self::P256(_) => P256_PUB_CODEC.to_vec(),
        };
        prefixed.extend_from_slice(self.as_bytes());
        multibase::encode(multibase::Base::Base58Btc, prefixed)
    }

    /// The `did:key` of this key (`z6Mk…` for Ed25519, `zDn…` for P-256).
    pub fn to_did_key(&self) -> String {
        format!("did:key:{}", self.to_multibase())
    }

    /// A public key from a `did:key` or from the multibase string alone. Only
    /// the Ed25519 and P-256 multicodecs name a key this crate signs with.
    pub fn from_did_key(did_or_multibase: &str) -> Result<Self, KeyParseError> {
        let multibase_text = did_or_multibase
            .strip_prefix("did:key:")
            .unwrap_or(did_or_multibase);
        let (_, raw) = multibase::decode(multibase_text)
            .map_err(|e| KeyParseError::Multibase(e.to_string()))?;
        match raw.get(..2) {
            Some(prefix) if prefix == ED25519_PUB_CODEC => {
                let key: [u8; 32] = raw[2..]
                    .try_into()
                    .map_err(|_| KeyParseError::InvalidKey("an Ed25519 key is 32 bytes".into()))?;
                Ok(Self::Ed25519(key))
            }
            Some(prefix) if prefix == P256_PUB_CODEC => {
                let key: [u8; 33] = raw[2..]
                    .try_into()
                    .map_err(|_| KeyParseError::InvalidKey("a P-256 key is 33 bytes".into()))?;
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
                    .map_err(|e| KeyParseError::InvalidKey(e.to_string()))?;
                Ok(Self::P256(key))
            }
            _ => Err(KeyParseError::UnsupportedCodec),
        }
    }
}

/// An Ed25519 public key from multibase text, in the lenient form DID documents
/// use: a multicodec-prefixed key, or a bare 32-byte one.
///
/// **Length disambiguates, not the leading bytes**: a bare key is free to begin
/// with any two bytes at all, including a prefix's, so only a 34-byte value
/// whose first two bytes are the Ed25519 prefix is read as prefixed. Prefer
/// [`PublicKey::from_did_key`], which requires the prefix; this exists for the
/// documents that publish a bare key.
pub fn decode_ed25519_public_key_multibase(mb: &str) -> Result<[u8; 32], KeyParseError> {
    let (_, raw) = multibase::decode(mb).map_err(|e| KeyParseError::Multibase(e.to_string()))?;
    let key = if raw.len() == 34 && raw[..2] == ED25519_PUB_CODEC {
        &raw[2..]
    } else {
        &raw[..]
    };
    key.try_into()
        .map_err(|_| KeyParseError::InvalidKey("an Ed25519 key is 32 bytes".into()))
}

/// Something that signs: a key in memory, or (later) a hardware or remote one.
///
/// Everything this crate signs goes through this trait, so a format is built
/// the same way whatever holds the key.
pub trait Signer {
    /// The algorithm this signer signs with.
    fn algorithm(&self) -> Algorithm;

    /// The public half.
    fn public_key(&self) -> PublicKey;

    /// The signature of exactly `message`: 64 bytes for both algorithms (for
    /// ES256, the fixed-width `r || s` a JWS carries).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

enum Key {
    Ed25519(Zeroizing<[u8; 32]>),
    P256(p256::ecdsa::SigningKey),
}

/// An Ed25519 or P-256 signing key held in memory.
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
    ///
    /// The seed is copied straight into the zeroizing buffer the key keeps, so
    /// no plain copy of it is left behind. Prefer this to [`Self::ed25519`]
    /// where the seed is already held in zeroizing memory.
    pub fn ed25519_from_slice(seed: &[u8]) -> Result<Self, SecretError> {
        if seed.len() != 32 {
            return Err(SecretError::Length {
                expected: 32,
                got: seed.len(),
            });
        }
        let mut held = Zeroizing::new([0u8; 32]);
        held.copy_from_slice(seed);
        Ok(Self {
            key: Key::Ed25519(held),
        })
    }

    /// A P-256 key from a `p256` secret key, without serialising the scalar:
    /// the signing key is built from it directly, so no copy of the scalar is
    /// made outside zeroizing memory.
    pub fn from_p256_secret(secret: &p256::SecretKey) -> Self {
        Self {
            key: Key::P256(p256::ecdsa::SigningKey::from(secret)),
        }
    }

    /// A P-256 key from its big-endian scalar.
    pub fn p256_from_slice(scalar: &[u8]) -> Result<Self, SecretError> {
        let key = p256::ecdsa::SigningKey::from_slice(scalar)
            .map_err(|e| SecretError::Invalid(e.to_string()))?;
        Ok(Self {
            key: Key::P256(key),
        })
    }

    /// The signature of exactly `message`. It cannot fail: use
    /// [`Signer::sign`] where the signer may be one that can.
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Ed25519(seed) => ed25519_dalek::SigningKey::from_bytes(seed)
                .sign(message)
                .to_bytes()
                .to_vec(),
            Key::P256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_bytes().to_vec()
            }
        }
    }
}

impl Signer for SigningSecret {
    fn algorithm(&self) -> Algorithm {
        match self.key {
            Key::Ed25519(_) => Algorithm::EdDsa,
            Key::P256(_) => Algorithm::Es256,
        }
    }

    fn public_key(&self) -> PublicKey {
        match &self.key {
            Key::Ed25519(seed) => PublicKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .to_bytes(),
            ),
            Key::P256(key) => {
                let point = key.verifying_key().to_sec1_point(true);
                let mut compressed = [0u8; 33];
                compressed.copy_from_slice(point.as_bytes());
                PublicKey::P256(compressed)
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.sign_message(message))
    }
}

impl fmt::Debug for SigningSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningSecret")
            .field("algorithm", &Signer::algorithm(self))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ed25519_key_signs_what_its_public_half_verifies() {
        let secret = SigningSecret::ed25519([7; 32]);
        let signature = secret.sign(b"message").unwrap();

        let public = secret.public_key();
        assert_eq!(public.verify(b"message", &signature), Ok(()));
        assert_eq!(
            public.verify(b"another", &signature),
            Err(VerifyError::Signature)
        );
        assert_eq!(secret.algorithm(), Algorithm::EdDsa);
        assert_eq!(public.algorithm(), Algorithm::EdDsa);
    }

    #[test]
    fn an_ed25519_signature_is_the_one_the_reference_implementation_makes() {
        let seed = [42u8; 32];
        let expected = ed25519_dalek::SigningKey::from_bytes(&seed)
            .sign(b"hash data")
            .to_bytes()
            .to_vec();

        assert_eq!(
            SigningSecret::ed25519(seed).sign_message(b"hash data"),
            expected
        );
    }

    #[test]
    fn a_p256_key_signs_in_fixed_width_and_its_public_half_verifies() {
        let secret = SigningSecret::p256_from_slice(&[9u8; 32]).unwrap();
        let signature = secret.sign(b"message").unwrap();

        assert_eq!(signature.len(), 64);
        let public = secret.public_key();
        assert!(matches!(public, PublicKey::P256(_)));
        assert_eq!(public.as_bytes().len(), 33);
        assert_eq!(public.verify(b"message", &signature), Ok(()));
        assert_eq!(
            public.verify(b"another", &signature),
            Err(VerifyError::Signature)
        );
        assert_eq!(secret.algorithm(), Algorithm::Es256);
    }

    #[test]
    fn a_p256_signature_is_the_one_the_reference_implementation_makes() {
        use p256::ecdsa::signature::Signer as _;
        let scalar = [9u8; 32];
        let reference: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&scalar)
            .unwrap()
            .sign(b"hash data");

        assert_eq!(
            SigningSecret::p256_from_slice(&scalar)
                .unwrap()
                .sign_message(b"hash data"),
            reference.to_bytes().to_vec()
        );
    }

    #[test]
    fn signing_is_deterministic() {
        for secret in [
            SigningSecret::ed25519([1; 32]),
            SigningSecret::p256_from_slice(&[2; 32]).unwrap(),
        ] {
            assert_eq!(secret.sign_message(b"same"), secret.sign_message(b"same"));
            assert_ne!(secret.sign_message(b"same"), secret.sign_message(b"other"));
        }
    }

    #[test]
    fn a_signature_under_another_key_does_not_verify() {
        let signature = SigningSecret::ed25519([1; 32]).sign_message(b"m");

        assert_eq!(
            SigningSecret::ed25519([2; 32])
                .public_key()
                .verify(b"m", &signature),
            Err(VerifyError::Signature)
        );
        assert_eq!(
            SigningSecret::ed25519([2; 32])
                .public_key()
                .verify(b"m", &[0u8; 5]),
            Err(VerifyError::Signature)
        );
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

    #[test]
    fn a_did_key_names_the_key_and_reads_back() {
        let ed = SigningSecret::ed25519([3; 32]).public_key();
        let p256 = SigningSecret::p256_from_slice(&[4; 32])
            .unwrap()
            .public_key();

        assert!(ed.to_did_key().starts_with("did:key:z6Mk"));
        assert!(p256.to_did_key().starts_with("did:key:zDn"));
        for key in [ed, p256] {
            assert_eq!(PublicKey::from_did_key(&key.to_did_key()), Ok(key.clone()));
            assert_eq!(PublicKey::from_did_key(&key.to_multibase()), Ok(key));
        }
    }

    #[test]
    fn a_published_ed25519_did_key_reads_back_to_the_same_text() {
        let published = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        let key = PublicKey::from_did_key(published).unwrap();

        assert!(matches!(key, PublicKey::Ed25519(_)));
        assert_eq!(key.to_did_key(), published);
    }

    #[test]
    fn a_did_key_of_another_type_or_shape_is_refused() {
        let x25519 = "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
        assert_eq!(
            PublicKey::from_did_key(x25519),
            Err(KeyParseError::UnsupportedCodec)
        );
        assert!(matches!(
            PublicKey::from_did_key("did:key:not multibase!"),
            Err(KeyParseError::Multibase(_))
        ));
        let truncated = multibase::encode(multibase::Base::Base58Btc, [0xed, 0x01, 1, 2, 3]);
        assert!(matches!(
            PublicKey::from_did_key(&truncated),
            Err(KeyParseError::InvalidKey(_))
        ));
        let off_curve = {
            let mut bytes = vec![0x80, 0x24, 0x02];
            bytes.extend_from_slice(&[0xFF; 32]);
            multibase::encode(multibase::Base::Base58Btc, bytes)
        };
        assert!(matches!(
            PublicKey::from_did_key(&off_curve),
            Err(KeyParseError::InvalidKey(_))
        ));
    }

    #[test]
    fn the_lenient_decoder_reads_a_prefixed_key_a_bare_one_and_nothing_else() {
        let key = SigningSecret::ed25519([6; 32]).public_key();
        let prefixed = key.to_multibase();
        let bare = multibase::encode(multibase::Base::Base58Btc, key.as_bytes());

        assert_eq!(
            decode_ed25519_public_key_multibase(&prefixed)
                .unwrap()
                .as_slice(),
            key.as_bytes()
        );
        assert_eq!(
            decode_ed25519_public_key_multibase(&bare)
                .unwrap()
                .as_slice(),
            key.as_bytes()
        );
        let x25519 = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
        assert!(matches!(
            decode_ed25519_public_key_multibase(x25519),
            Err(KeyParseError::InvalidKey(_))
        ));
        assert!(decode_ed25519_public_key_multibase("not multibase!").is_err());
    }

    #[test]
    fn a_bare_key_that_starts_with_the_prefix_bytes_is_not_truncated() {
        let mut bare = [9u8; 32];
        bare[0] = 0xed;
        bare[1] = 0x01;
        let text = multibase::encode(multibase::Base::Base58Btc, bare);

        assert_eq!(decode_ed25519_public_key_multibase(&text), Ok(bare));
    }

    #[test]
    fn a_jose_name_reads_back_to_its_algorithm_and_others_are_refused() {
        for algorithm in [Algorithm::EdDsa, Algorithm::Es256] {
            assert_eq!(
                Algorithm::from_jose_name(algorithm.jose_name()),
                Some(algorithm)
            );
        }
        assert_eq!(Algorithm::from_jose_name("ES256K"), None);
        assert_eq!(Algorithm::from_jose_name("none"), None);
    }

    #[test]
    fn a_p256_key_from_its_secret_key_is_the_key_its_scalar_names() {
        let scalar = [5u8; 32];
        let secret = p256::SecretKey::from_slice(&scalar).unwrap();
        assert_eq!(
            SigningSecret::from_p256_secret(&secret).public_key(),
            SigningSecret::p256_from_slice(&scalar)
                .unwrap()
                .public_key()
        );
    }

    #[test]
    fn an_ed25519_seed_slice_must_be_32_bytes() {
        assert_eq!(
            SigningSecret::ed25519_from_slice(&[7; 32])
                .unwrap()
                .public_key(),
            SigningSecret::ed25519([7; 32]).public_key()
        );
        assert!(matches!(
            SigningSecret::ed25519_from_slice(&[7; 31]),
            Err(SecretError::Length {
                expected: 32,
                got: 31
            })
        ));
    }
}
