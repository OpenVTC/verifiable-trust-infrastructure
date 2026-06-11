use crate::error::{AppError, key_derivation_error};
use crate::keys::seed_store::SeedStore;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use rand::Rng;
use tracing::{debug, info};

/// Wrapper holding a derived P-256 secret key.
pub struct P256Secret {
    pub secret_key: p256::SecretKey,
}

pub trait Bip32Extension {
    /// Derive an Ed25519 key pair from a seed and BIP32 derivation path.
    ///
    /// Returns `Secret`.
    fn derive_ed25519(&self, path: &str) -> Result<Secret, AppError>;
    /// Derive an X25519 key pair from a seed and BIP32 derivation path.
    ///
    /// Returns `Secret`.
    fn derive_x25519(&self, path: &str) -> Result<Secret, AppError>;
    /// Derive a P-256 key pair from a seed and BIP32 derivation path.
    ///
    /// Uses HMAC-SHA512 domain separation to produce P-256 key material
    /// independent from the Ed25519 key at the same path. This avoids
    /// cross-curve key reuse, Ed25519 clamping artifacts, and group-order bias.
    fn derive_p256(&self, path: &str) -> Result<P256Secret, AppError>;
}

impl Bip32Extension for ExtendedSigningKey {
    fn derive_ed25519(&self, path: &str) -> Result<Secret, AppError> {
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| key_derivation_error(format!("invalid derivation path: {e}")))?;

        let derived = self
            .derive(&derivation_path)
            .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;

        Ok(Secret::generate_ed25519(
            None,
            Some(derived.signing_key.as_bytes()),
        ))
    }

    fn derive_x25519(&self, path: &str) -> Result<Secret, AppError> {
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| key_derivation_error(format!("invalid derivation path: {e}")))?;

        let derived = self
            .derive(&derivation_path)
            .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;

        // Use the same conversion path as DID creation (keys/mod.rs derive_entity_keys):
        // generate Ed25519 secret, then convert to X25519 via Secret::to_x25519().
        // This ensures the runtime key matches the public key in the DID document.
        let ed_secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
        ed_secret
            .to_x25519()
            .map_err(|e| key_derivation_error(format!("X25519 conversion failed: {e}")))
    }

    fn derive_p256(&self, path: &str) -> Result<P256Secret, AppError> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha512;

        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| key_derivation_error(format!("invalid derivation path: {e}")))?;

        let derived = self
            .derive(&derivation_path)
            .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;

        // Domain-separated derivation via HMAC-SHA512.
        // Prevents cross-curve key reuse: the same BIP-32 path produces
        // independent key material for Ed25519 and P-256.
        let mut mac = Hmac::<Sha512>::new_from_slice(b"p256-key-derivation")
            .expect("HMAC accepts any key length");
        mac.update(derived.signing_key.as_bytes());
        mac.update(&derived.chain_code);
        let hmac_output = mac.finalize().into_bytes();

        // First 32 bytes → P-256 scalar. from_bytes() reduces mod n automatically.
        let secret_key =
            p256::SecretKey::from_bytes(p256::FieldBytes::from_slice(&hmac_output[..32]))
                .map_err(|e| key_derivation_error(format!("P-256 key creation failed: {e}")))?;

        Ok(P256Secret { secret_key })
    }
}

/// Load an existing master seed from the store, or generate/derive a new one.
///
/// - If `mnemonic` is provided, validates it as a BIP-39 phrase and derives a
///   64-byte seed via PBKDF2 (with an empty passphrase), then stores it.
/// - If no mnemonic and a seed already exists, returns the existing seed.
/// - If no mnemonic and no seed exists, generates 32 random bytes and stores them.
///
/// `dead_code` allowed: called by the `vta-enclave` binary's bootstrap
/// path, which compiles in a different crate. rustc's dead-code lint
/// doesn't see the cross-crate usage.
#[allow(dead_code)]
pub async fn load_or_generate_seed(
    seed_store: &dyn SeedStore,
    mnemonic: Option<&str>,
) -> Result<ExtendedSigningKey, AppError> {
    if let Some(phrase) = mnemonic {
        let m = bip39::Mnemonic::parse(phrase)
            .map_err(|e| key_derivation_error(format!("invalid BIP-39 mnemonic: {e}")))?;
        let seed = m.to_seed("");
        seed_store.set(&seed).await?;
        info!("master seed derived from mnemonic and stored");
        return ExtendedSigningKey::from_seed(&seed).map_err(|e| {
            key_derivation_error(format!(
                "Couldn't create bip32 root signing key! Reason: {e}"
            ))
        });
    }

    if let Some(existing) = seed_store.get().await? {
        debug!("master seed loaded from store");
        // Master seed in plaintext — wipe on drop (P0.7).
        let existing = zeroize::Zeroizing::new(existing);
        return ExtendedSigningKey::from_seed(&existing).map_err(|e| {
            key_derivation_error(format!(
                "Couldn't create bip32 root signing key! Reason: {e}"
            ))
        });
    }

    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *seed);
    seed_store.set(&*seed).await?;
    info!("new random master seed generated and stored");
    ExtendedSigningKey::from_seed(&*seed).map_err(|e| {
        key_derivation_error(format!(
            "Couldn't create bip32 root signing key! Reason: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    fn get_bip32() -> ExtendedSigningKey {
        ExtendedSigningKey::from_seed(&[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ])
        .unwrap()
    }

    #[test]
    fn test_derive_ed25519_deterministic() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let secret = bip32.derive_ed25519(path).unwrap();

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3u2RHYaCxd1wzvJB6wQEcnrLth65xcNHcGDDSdfwDjmkoG3".to_string()
        );
        assert_eq!(
            secret.get_public_keymultibase().unwrap(),
            "z6MkestKNR7EyyB8yojbPcRoG8rF6iX4uXYkyVbDBsM9Fj5i".to_string()
        );
    }

    #[test]
    fn test_derive_ed25519_different_paths() {
        let bip32 = get_bip32();

        let secret1 = bip32.derive_ed25519("m/44'/0'/0'").unwrap();
        let secret2 = bip32.derive_ed25519("m/44'/0'/1'").unwrap();

        assert_eq!(
            secret1.get_private_keymultibase().unwrap(),
            "z3u2RHYaCxd1wzvJB6wQEcnrLth65xcNHcGDDSdfwDjmkoG3".to_string()
        );
        assert_eq!(
            secret1.get_public_keymultibase().unwrap(),
            "z6MkestKNR7EyyB8yojbPcRoG8rF6iX4uXYkyVbDBsM9Fj5i".to_string()
        );
        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            "z3u2iLUGo3YPXjUFE6LR2z1f84ufRDe4PEeQpvA9dPU8HZ1G".to_string()
        );
        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            "z6Mkw5tnbEgzv7zc4SJmSACo6FbfKLHveK4dCHjar8h2voDE".to_string()
        );
    }

    #[test]
    fn test_derive_x25519_deterministic() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let secret = bip32.derive_x25519(path).unwrap();

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3wenSajog3TCG3QxA8yVvEniVxp2QU9mE3fYgDYQj8j6MHo".to_string()
        );
        assert_eq!(
            secret.get_public_keymultibase().unwrap(),
            "z6LStYM3H4UG8qn79pQwGmSRd81VMETBPjH49uf5SeqJBB7G".to_string()
        );
    }

    #[test]
    fn test_derive_x25519_differs_from_ed25519() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let ed_secret = bip32.derive_ed25519(path).unwrap();
        let x_secret = bip32.derive_x25519(path).unwrap();

        assert_ne!(
            ed_secret.get_public_keymultibase().unwrap(),
            x_secret.get_private_keymultibase().unwrap()
        );
    }

    #[test]
    fn test_invalid_path() {
        let bip32 = get_bip32();
        let result = bip32.derive_ed25519("not/a/valid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_bip39_seed_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m1 = bip39::Mnemonic::parse(phrase).unwrap();
        let m2 = bip39::Mnemonic::parse(phrase).unwrap();
        assert_eq!(m1.to_seed(""), m2.to_seed(""));
        // BIP-39 produces a 64-byte seed
        assert_eq!(m1.to_seed("").len(), 64);
    }

    #[test]
    fn test_bip39_invalid_mnemonic() {
        let result = bip39::Mnemonic::parse("not a valid mnemonic");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Key creation ↔ recovery consistency tests
    //
    // These simulate the two code paths that must agree:
    //   Creation:  derive_entity_keys() in keys/mod.rs  (DID document keys)
    //   Recovery:  init_auth() in server.rs              (restart re-derivation)
    // -----------------------------------------------------------------------

    /// Simulate DID-creation for Ed25519: manual BIP-32 derive → Secret::generate_ed25519.
    /// This mirrors what `derive_entity_keys()` does.
    fn creation_path_ed25519(seed: &[u8], path: &str) -> Secret {
        let root = ExtendedSigningKey::from_seed(seed).unwrap();
        let dp: DerivationPath = path.parse().unwrap();
        let derived = root.derive(&dp).unwrap();
        Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()))
    }

    /// Simulate DID-creation for X25519: manual BIP-32 derive → Ed25519 → to_x25519.
    /// This mirrors what `derive_entity_keys()` does.
    fn creation_path_x25519(seed: &[u8], path: &str) -> Secret {
        let root = ExtendedSigningKey::from_seed(seed).unwrap();
        let dp: DerivationPath = path.parse().unwrap();
        let derived = root.derive(&dp).unwrap();
        let ed = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
        ed.to_x25519().unwrap()
    }

    /// Simulate recovery for Ed25519: Bip32Extension::derive_ed25519.
    /// This mirrors what `init_auth()` does on restart.
    fn recovery_path_ed25519(seed: &[u8], path: &str) -> Secret {
        let root = ExtendedSigningKey::from_seed(seed).unwrap();
        root.derive_ed25519(path).unwrap()
    }

    /// Simulate recovery for X25519: Bip32Extension::derive_x25519.
    /// This mirrors what `init_auth()` does on restart.
    fn recovery_path_x25519(seed: &[u8], path: &str) -> Secret {
        let root = ExtendedSigningKey::from_seed(seed).unwrap();
        root.derive_x25519(path).unwrap()
    }

    #[test]
    fn test_ed25519_creation_matches_recovery() {
        let seed = &[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ];
        for path in ["m/44'/0'/0'", "m/44'/0'/1'", "m/44'/0'/99'"] {
            let created = creation_path_ed25519(seed, path);
            let recovered = recovery_path_ed25519(seed, path);

            assert_eq!(
                created.get_public_keymultibase().unwrap(),
                recovered.get_public_keymultibase().unwrap(),
                "Ed25519 public key mismatch at path {path}: creation vs recovery"
            );
            assert_eq!(
                created.get_private_keymultibase().unwrap(),
                recovered.get_private_keymultibase().unwrap(),
                "Ed25519 private key mismatch at path {path}: creation vs recovery"
            );
        }
    }

    #[test]
    fn test_x25519_creation_matches_recovery() {
        let seed = &[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ];
        for path in ["m/44'/0'/0'", "m/44'/0'/1'", "m/44'/0'/99'"] {
            let created = creation_path_x25519(seed, path);
            let recovered = recovery_path_x25519(seed, path);

            assert_eq!(
                created.get_public_keymultibase().unwrap(),
                recovered.get_public_keymultibase().unwrap(),
                "X25519 public key mismatch at path {path}: creation vs recovery \
                 (the key in the DID document would not match the runtime key)"
            );
            assert_eq!(
                created.get_private_keymultibase().unwrap(),
                recovered.get_private_keymultibase().unwrap(),
                "X25519 private key mismatch at path {path}: creation vs recovery"
            );
        }
    }

    /// Multiple re-derivations from the same seed + path must produce identical
    /// keys (simulates multiple VTA restarts).
    #[test]
    fn test_multiple_restarts_produce_identical_keys() {
        let seed = &[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ];
        let sign_path = "m/44'/0'/0'";
        let ka_path = "m/44'/0'/1'";

        let first_sign = recovery_path_ed25519(seed, sign_path);
        let first_ka = recovery_path_x25519(seed, ka_path);

        for i in 1..=5 {
            let sign = recovery_path_ed25519(seed, sign_path);
            let ka = recovery_path_x25519(seed, ka_path);

            assert_eq!(
                first_sign.get_public_keymultibase().unwrap(),
                sign.get_public_keymultibase().unwrap(),
                "Ed25519 public key drifted on restart {i}"
            );
            assert_eq!(
                first_ka.get_public_keymultibase().unwrap(),
                ka.get_public_keymultibase().unwrap(),
                "X25519 public key drifted on restart {i}"
            );
        }
    }

    /// BIP-39 mnemonic → seed → keys must be fully deterministic.
    #[test]
    fn test_bip39_seed_to_keys_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = bip39::Mnemonic::parse(phrase).unwrap();
        let seed = m.to_seed("");

        let sign1 = creation_path_ed25519(&seed, "m/44'/0'/0'");
        let ka1 = creation_path_x25519(&seed, "m/44'/0'/1'");

        // Repeat from mnemonic
        let m2 = bip39::Mnemonic::parse(phrase).unwrap();
        let seed2 = m2.to_seed("");
        let sign2 = recovery_path_ed25519(&seed2, "m/44'/0'/0'");
        let ka2 = recovery_path_x25519(&seed2, "m/44'/0'/1'");

        assert_eq!(
            sign1.get_public_keymultibase().unwrap(),
            sign2.get_public_keymultibase().unwrap(),
            "Ed25519 key not deterministic from same mnemonic"
        );
        assert_eq!(
            ka1.get_public_keymultibase().unwrap(),
            ka2.get_public_keymultibase().unwrap(),
            "X25519 key not deterministic from same mnemonic"
        );
    }

    /// The stored ka_priv (Ed25519 seed bytes at the KA derivation path) must
    /// reconstruct the same X25519 key when fed through the canonical conversion.
    /// This is how DidSecretsBundle and external importers reconstruct keys.
    #[test]
    fn test_ka_priv_reconstructs_x25519() {
        let seed = &[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ];
        let ka_path = "m/44'/0'/1'";

        // Simulate derive_entity_keys: get ka_priv (Ed25519 seed bytes, multibase)
        let root = ExtendedSigningKey::from_seed(seed).unwrap();
        let dp: DerivationPath = ka_path.parse().unwrap();
        let derived = root.derive(&dp).unwrap();
        let ka_priv = multibase::encode(multibase::Base::Base58Btc, derived.signing_key.as_bytes());

        // Original X25519 key (as would be in DID document)
        let original = creation_path_x25519(seed, ka_path);
        let original_pub = original.get_public_keymultibase().unwrap();

        // Reconstruct from ka_priv (as an external importer would)
        let (_, raw_bytes) = multibase::decode(&ka_priv).unwrap();
        let seed_arr: &[u8; 32] = raw_bytes.as_slice().try_into().unwrap();
        let reconstructed_ed = Secret::generate_ed25519(None, Some(seed_arr));
        let reconstructed_x = reconstructed_ed.to_x25519().unwrap();
        let reconstructed_pub = reconstructed_x.get_public_keymultibase().unwrap();

        assert_eq!(
            original_pub, reconstructed_pub,
            "X25519 key reconstructed from stored ka_priv does not match DID document key"
        );
    }

    /// Ensure the signing key's public multibase matches what ed25519_multibase_pubkey
    /// produces (the format used in DID documents and did:key identifiers).
    #[test]
    fn test_signing_pub_matches_did_document_format() {
        let seed = &[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ];
        let path = "m/44'/0'/0'";

        // What derive_entity_keys stores as signing_pub
        let secret = creation_path_ed25519(seed, path);
        let signing_pub = secret.get_public_keymultibase().unwrap();

        // What the DID document formatter produces from raw bytes
        let root = ExtendedSigningKey::from_seed(seed).unwrap();
        let dp: DerivationPath = path.parse().unwrap();
        let derived = root.derive(&dp).unwrap();
        let raw_pub = ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes())
            .verifying_key()
            .to_bytes();
        let did_doc_pub = vta_sdk::did_key::ed25519_multibase_pubkey(&raw_pub);

        assert_eq!(
            signing_pub, did_doc_pub,
            "Secret::get_public_keymultibase() does not match ed25519_multibase_pubkey()"
        );
    }

    // -----------------------------------------------------------------------
    // P-256 key derivation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_p256_deterministic() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let p256_1 = bip32.derive_p256(path).unwrap();
        let p256_2 = bip32.derive_p256(path).unwrap();

        // Same seed + path must produce the same key
        assert_eq!(p256_1.secret_key.to_bytes(), p256_2.secret_key.to_bytes());

        // Public key must be derivable
        let pk = p256_1.secret_key.public_key();
        let encoded = pk.to_encoded_point(true);
        assert_eq!(
            encoded.len(),
            33,
            "compressed P-256 pubkey should be 33 bytes"
        );
    }

    #[test]
    fn test_derive_p256_different_paths() {
        let bip32 = get_bip32();

        let p256_1 = bip32.derive_p256("m/44'/0'/0'").unwrap();
        let p256_2 = bip32.derive_p256("m/44'/0'/1'").unwrap();

        assert_ne!(
            p256_1.secret_key.to_bytes(),
            p256_2.secret_key.to_bytes(),
            "different paths must produce different keys"
        );
    }

    #[test]
    fn test_derive_p256_sign_verify() {
        let bip32 = get_bip32();
        let p256_secret = bip32.derive_p256("m/44'/0'/0'").unwrap();

        let signing_key = p256::ecdsa::SigningKey::from(&p256_secret.secret_key);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);

        use p256::ecdsa::signature::{Signer, Verifier};
        let message = b"hello VTA signing oracle";
        let sig: p256::ecdsa::Signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_derive_p256_invalid_path() {
        let bip32 = get_bip32();
        let result = bip32.derive_p256("not/a/valid/path");
        assert!(result.is_err());
    }
}
