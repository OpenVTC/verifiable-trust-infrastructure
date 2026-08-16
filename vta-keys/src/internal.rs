//! Non-extractable internal signing keys.
//!
//! An internal key is generated from the system CSPRNG, stored only in the
//! [`INTERNAL_KEYS`] keyspace, and **never leaves this VTA** — not through the
//! key-export surface, not in a backup, not via the mnemonic.
//!
//! ## Why this is a separate module and not a flag on the imported path
//!
//! [`crate::imported`] wraps its secrets under a KEK **derived from the BIP-39
//! master seed** (`derive_kek(seed, salt)`). Anything stored that way is
//! reconstructible offline by whoever holds the 24 words, so a
//! "non-extractable" flag on it would be decorative: the boundary it claims to
//! enforce has already been walked around. Internal keys therefore have their
//! own keyspace and no seed involvement at any point.
//!
//! For the same reason there is deliberately **no `export_secret` here**. The
//! module exposes generate, load-for-signing, and delete. A caller that wants
//! the bytes has to be inside this crate's signing path.
//!
//! ## What this costs
//!
//! **An internal key cannot be recovered.** There is no derivation path, no
//! backup copy, and no mnemonic that reproduces it. If the keyspace is lost,
//! every signature that key was the sole authority for becomes unproducible,
//! permanently. That is the point of the design and also its whole risk; every
//! operator-facing surface that mints one says so.
//!
//! At rest the material is protected by the keyspace's own encryption — which,
//! in a TEE deployment, is the KMS-sealed storage key bound to the enclave
//! measurement. In a non-TEE deployment it is whatever `store.encryption` is
//! configured to be, and an operator with disk access is inside that boundary.
//! Internal keys raise the bar against *export*; they do not by themselves make
//! a non-TEE VTA tamper-proof.

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use vta_sdk::keys::KeyType;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use zeroize::Zeroize;

/// Row prefix inside [`vta_keyspaces::INTERNAL_KEYS`].
const SECRET_PREFIX: &str = "internal:";

/// A stored internal key's private material plus the type needed to use it.
#[derive(Serialize, Deserialize)]
struct StoredInternalSecret {
    key_type: KeyType,
    /// Raw private key bytes. Encrypted at rest by the keyspace, never by a
    /// seed-derived KEK — see the module docs for why that distinction is the
    /// entire point.
    secret: Vec<u8>,
}

/// Generate a fresh internal signing key, store it, and return its public half.
///
/// The private bytes never leave this function except into the keyspace. The
/// caller gets only the public key, because there is no legitimate reason for
/// a mint path to hold the secret — the signing oracle loads it on demand.
pub async fn generate(
    internal_ks: &KeyspaceHandle,
    key_id: &str,
    key_type: KeyType,
) -> Result<Vec<u8>, AppError> {
    if key_id.trim().is_empty() {
        return Err(AppError::Validation(
            "internal key id must be non-empty".into(),
        ));
    }
    if internal_ks
        .get_raw(format!("{SECRET_PREFIX}{key_id}"))
        .await?
        .is_some()
    {
        // Overwriting would destroy the only copy of the previous key with no
        // way to get it back, so refuse rather than silently replace.
        return Err(AppError::Conflict(format!(
            "internal key `{key_id}` already exists; internal keys are never \
             overwritten because the previous key would be unrecoverable"
        )));
    }

    let (mut secret, public) = match key_type {
        KeyType::Ed25519 => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            seed.zeroize();
            let public = signing.verifying_key().to_bytes().to_vec();
            (signing.to_bytes().to_vec(), public)
        }
        KeyType::P256 => {
            let mut raw = [0u8; 32];
            OsRng.fill_bytes(&mut raw);
            let secret = p256::SecretKey::from_slice(&raw)
                .map_err(|e| AppError::Internal(format!("internal P-256 keygen: {e}")))?;
            raw.zeroize();
            let public = secret
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec();
            (secret.to_bytes().to_vec(), public)
        }
        // X25519 is a key-agreement key, not a signing key. Internal keys exist
        // for signing; minting one that cannot sign would only create a key
        // nobody can use and nobody can recover.
        KeyType::X25519 => {
            return Err(AppError::Validation(
                "internal keys are signing keys; X25519 is key-agreement only".into(),
            ));
        }
    };

    let record = StoredInternalSecret {
        key_type,
        secret: secret.clone(),
    };
    secret.zeroize();

    let bytes = serde_json::to_vec(&record)
        .map_err(|e| AppError::Internal(format!("serialize internal secret: {e}")))?;
    internal_ks
        .insert_raw(format!("{SECRET_PREFIX}{key_id}"), bytes)
        .await?;

    Ok(public)
}

/// Load an internal key's private bytes **for signing inside this process**.
///
/// Crate-visible on purpose. Widening this to `pub` would create the export
/// surface the whole module exists to avoid, so a caller outside `vta-keys`
/// cannot obtain the material even by accident.
pub(crate) async fn load_for_signing(
    internal_ks: &KeyspaceHandle,
    key_id: &str,
) -> Result<(KeyType, Vec<u8>), AppError> {
    let blob = internal_ks
        .get_raw(format!("{SECRET_PREFIX}{key_id}"))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("internal key `{key_id}` not found")))?;

    let record: StoredInternalSecret = serde_json::from_slice(&blob)
        .map_err(|e| AppError::Internal(format!("decode internal secret: {e}")))?;

    Ok((record.key_type, record.secret))
}

/// Sign `payload` with an internal key, returning the raw signature.
///
/// The only way internal key material is used. The bytes are zeroized before
/// return on every path, including the error ones.
pub async fn sign(
    internal_ks: &KeyspaceHandle,
    key_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, AppError> {
    let (key_type, mut secret) = load_for_signing(internal_ks, key_id).await?;

    let result = match key_type {
        KeyType::Ed25519 => ed25519_dalek::SigningKey::try_from(secret.as_slice())
            .map_err(|e| AppError::Internal(format!("internal Ed25519 key: {e}")))
            .map(|k| {
                use ed25519_dalek::Signer;
                k.sign(payload).to_bytes().to_vec()
            }),
        KeyType::P256 => affinidi_crypto::p256::sign(&secret, payload)
            .map_err(|e| AppError::Internal(format!("internal P-256 sign: {e}"))),
        KeyType::X25519 => Err(AppError::Internal(
            "an X25519 internal key should never have been stored".into(),
        )),
    };

    secret.zeroize();
    result
}

/// Delete an internal key.
///
/// **Irreversible.** There is no backup and no derivation path, so this is the
/// only operation in the crate that destroys key material outright. Callers are
/// expected to have confirmed with the operator first.
pub async fn delete(internal_ks: &KeyspaceHandle, key_id: &str) -> Result<(), AppError> {
    internal_ks.remove(format!("{SECRET_PREFIX}{key_id}")).await
}

/// True if `key_id` names a stored internal key.
pub async fn exists(internal_ks: &KeyspaceHandle, key_id: &str) -> Result<bool, AppError> {
    Ok(internal_ks
        .get_raw(format!("{SECRET_PREFIX}{key_id}"))
        .await?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::INTERNAL_KEYS).unwrap();
        (dir, store, ks)
    }

    #[tokio::test]
    async fn generate_returns_only_the_public_half_and_signs_with_the_private_one() {
        let (_d, _s, ks) = fresh();
        let public = generate(&ks, "k-internal", KeyType::Ed25519).await.unwrap();
        assert_eq!(public.len(), 32, "Ed25519 public key");

        let sig = sign(&ks, "k-internal", b"payload").await.unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signature");

        // The signature must verify under the returned public key — proving the
        // stored secret really is the counterpart, not just some bytes.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&public.clone().try_into().unwrap()).unwrap();
        vk.verify(b"payload", &Signature::from_slice(&sig).unwrap())
            .expect("signature verifies under the advertised public key");
    }

    /// Two internal keys minted with the same id would be two different keys,
    /// and the first would be gone with no way back. Refuse instead.
    #[tokio::test]
    async fn generating_over_an_existing_internal_key_is_refused() {
        let (_d, _s, ks) = fresh();
        generate(&ks, "k1", KeyType::Ed25519).await.unwrap();
        let err = generate(&ks, "k1", KeyType::Ed25519).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Conflict(m) if m.contains("unrecoverable")),
            "{err:?}"
        );
    }

    /// Every internal key must be independent. If two keys minted in the same
    /// process shared material, the CSPRNG is not being used as intended.
    #[tokio::test]
    async fn internal_keys_are_independent_of_each_other() {
        let (_d, _s, ks) = fresh();
        let a = generate(&ks, "a", KeyType::Ed25519).await.unwrap();
        let b = generate(&ks, "b", KeyType::Ed25519).await.unwrap();
        assert_ne!(a, b, "two internal keys must not share material");
    }

    #[tokio::test]
    async fn p256_internal_keys_sign() {
        let (_d, _s, ks) = fresh();
        let public = generate(&ks, "p", KeyType::P256).await.unwrap();
        assert_eq!(public.len(), 33, "compressed SEC1 point");

        let sig = sign(&ks, "p", b"payload").await.unwrap();
        assert!(
            affinidi_crypto::p256::verify(&public, b"payload", &sig).unwrap(),
            "P-256 signature verifies under the advertised public key"
        );
    }

    /// An internal key exists to sign. A key-agreement key cannot, and minting
    /// one would create something unusable *and* unrecoverable.
    #[tokio::test]
    async fn x25519_internal_keys_are_refused() {
        let (_d, _s, ks) = fresh();
        let err = generate(&ks, "x", KeyType::X25519).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("key-agreement")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_deleted_internal_key_is_gone_for_good() {
        let (_d, _s, ks) = fresh();
        generate(&ks, "doomed", KeyType::Ed25519).await.unwrap();
        assert!(exists(&ks, "doomed").await.unwrap());

        delete(&ks, "doomed").await.unwrap();
        assert!(!exists(&ks, "doomed").await.unwrap());
        assert!(
            sign(&ks, "doomed", b"x").await.is_err(),
            "a deleted internal key cannot be recovered or reused"
        );
    }
}
