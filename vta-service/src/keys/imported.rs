//! Encrypted storage for imported (non-BIP32-derived) secrets.
//!
//! Imported secrets are encrypted at rest using AES-256-GCM with a KEK
//! derived from the BIP-32 master seed via HKDF-SHA256 with a random salt.
//! Each secret's ciphertext is bound to its `key_id:key_type` via AAD.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

const KEK_SALT_KEY: &str = "imported_kek_salt";
const SECRET_PREFIX: &str = "secret:";
const NONCE_LEN: usize = 12;

/// Derive the KEK for imported secret encryption from the master seed and salt.
fn derive_kek(seed: &[u8], salt: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), seed);
    let mut kek = [0u8; 32];
    hkdf.expand(b"vta-imported-secret-encryption", &mut kek)
        .expect("32-byte output is valid for HKDF-SHA256");
    kek
}

/// Build the AAD string for a given key_id and key_type.
fn build_aad(key_id: &str, key_type: &str) -> Vec<u8> {
    format!("{key_id}:{key_type}").into_bytes()
}

/// Get or create the KEK salt. Returns the 32-byte salt.
///
/// The first-ever creation is claimed via `insert_raw_if_absent`: two
/// concurrent first imports must converge on ONE salt. The loser of
/// the race reads the winner's salt back — a plain insert here would
/// overwrite the winner's salt and leave its just-encrypted secret
/// permanently undecryptable.
pub async fn get_or_create_salt(keys_ks: &KeyspaceHandle) -> Result<Vec<u8>, AppError> {
    if let Some(existing) = keys_ks.get_raw(KEK_SALT_KEY).await? {
        return Ok(existing);
    }
    // Generate a new random salt and try to claim the slot.
    use aes_gcm::aead::rand_core::RngCore;
    let mut salt = vec![0u8; 32];
    aes_gcm::aead::OsRng.fill_bytes(&mut salt);
    if keys_ks
        .insert_raw_if_absent(KEK_SALT_KEY, salt.clone())
        .await?
    {
        return Ok(salt);
    }
    keys_ks
        .get_raw(KEK_SALT_KEY)
        .await?
        .ok_or_else(|| AppError::Internal("KEK salt vanished after losing creation race".into()))
}

/// Store the KEK salt (used during backup restore).
pub async fn set_salt(keys_ks: &KeyspaceHandle, salt: &[u8]) -> Result<(), AppError> {
    keys_ks.insert_raw(KEK_SALT_KEY, salt.to_vec()).await?;
    Ok(())
}

/// Get the KEK salt if it exists (for backup export).
pub async fn get_salt(keys_ks: &KeyspaceHandle) -> Result<Option<Vec<u8>>, AppError> {
    keys_ks.get_raw(KEK_SALT_KEY).await
}

/// Encrypt and store an imported secret.
pub async fn store_secret(
    imported_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    seed: &[u8],
    key_id: &str,
    key_type: &str,
    secret_bytes: &[u8],
) -> Result<(), AppError> {
    let salt = get_or_create_salt(keys_ks).await?;
    let mut kek = derive_kek(seed, &salt);

    let cipher =
        Aes256Gcm::new_from_slice(&kek).map_err(|e| AppError::Internal(format!("aes key: {e}")))?;

    // Random nonce
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(key_id, key_type);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: secret_bytes,
                aad: &aad,
            },
        )
        .map_err(|e| AppError::Internal(format!("encrypt imported secret: {e}")))?;

    // Store as nonce || ciphertext
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    imported_ks
        .insert_raw(format!("{SECRET_PREFIX}{key_id}"), blob)
        .await?;

    kek.zeroize();
    Ok(())
}

/// Load and decrypt an imported secret.
pub async fn load_secret(
    imported_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    seed: &[u8],
    key_id: &str,
    key_type: &str,
) -> Result<Vec<u8>, AppError> {
    let blob = imported_ks
        .get_raw(format!("{SECRET_PREFIX}{key_id}"))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("imported secret not found: {key_id}")))?;

    if blob.len() < NONCE_LEN + 1 {
        return Err(AppError::Internal("imported secret blob too short".into()));
    }

    let salt = get_or_create_salt(keys_ks).await?;
    let mut kek = derive_kek(seed, &salt);

    let cipher =
        Aes256Gcm::new_from_slice(&kek).map_err(|e| AppError::Internal(format!("aes key: {e}")))?;

    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let aad = build_aad(key_id, key_type);
    let mut plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &blob[NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| {
            AppError::Internal(
                "imported secret decryption failed (AAD mismatch or corruption)".into(),
            )
        })?;

    kek.zeroize();

    // Return plaintext; caller is responsible for zeroizing
    Ok(std::mem::take(&mut plaintext))
}

/// Delete an imported secret.
///
/// Note on erasure: the store is an LSM tree (fjall), so a `remove` writes a
/// tombstone and the original value's bytes persist in immutable SSTables /
/// the journal until compaction — an in-place "overwrite with zeros" before
/// removing does NOT erase them (it just appends another version) and was
/// removed as ineffective theater (P0.7). This is acceptable because the
/// stored value is *ciphertext* (AES-256-GCM under the seed-derived KEK), not
/// plaintext: a forensic read of un-compacted SSTables yields encrypted bytes,
/// not the secret. True at-rest erasure of the keyspace is the storage layer's
/// job (compaction / encrypted volume), not this function's.
pub async fn delete_secret(imported_ks: &KeyspaceHandle, key_id: &str) -> Result<(), AppError> {
    let store_key = format!("{SECRET_PREFIX}{key_id}");
    imported_ks.remove(store_key).await?;
    Ok(())
}

/// Re-encrypt all imported secrets with a new KEK (used during seed rotation).
pub async fn reencrypt_all(
    imported_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    old_seed: &[u8],
    new_seed: &[u8],
    key_records: &[(String, String)], // (key_id, key_type) for AAD
) -> Result<u32, AppError> {
    let salt = get_or_create_salt(keys_ks).await?;
    let mut old_kek = derive_kek(old_seed, &salt);
    let mut new_kek = derive_kek(new_seed, &salt);

    let old_cipher = Aes256Gcm::new_from_slice(&old_kek)
        .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let new_cipher = Aes256Gcm::new_from_slice(&new_kek)
        .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;

    let mut count = 0u32;

    for (key_id, key_type) in key_records {
        let store_key = format!("{SECRET_PREFIX}{key_id}");
        let Some(blob) = imported_ks.get_raw(store_key.clone()).await? else {
            continue;
        };

        if blob.len() < NONCE_LEN + 1 {
            continue;
        }

        let old_nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
        let aad = build_aad(key_id, key_type);

        // Decrypt with old KEK
        let mut plaintext = old_cipher
            .decrypt(
                old_nonce,
                aes_gcm::aead::Payload {
                    msg: &blob[NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                AppError::Internal(format!(
                    "failed to decrypt imported secret {key_id} during re-encryption"
                ))
            })?;

        // Re-encrypt with new KEK
        use aes_gcm::aead::rand_core::RngCore;
        let mut new_nonce_bytes = [0u8; NONCE_LEN];
        aes_gcm::aead::OsRng.fill_bytes(&mut new_nonce_bytes);
        let new_nonce = Nonce::from_slice(&new_nonce_bytes);

        let new_ciphertext = new_cipher
            .encrypt(
                new_nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| AppError::Internal(format!("re-encrypt: {e}")))?;

        plaintext.zeroize();

        let mut new_blob = Vec::with_capacity(NONCE_LEN + new_ciphertext.len());
        new_blob.extend_from_slice(&new_nonce_bytes);
        new_blob.extend_from_slice(&new_ciphertext);

        imported_ks.insert_raw(store_key, new_blob).await?;
        count += 1;
    }

    old_kek.zeroize();
    new_kek.zeroize();

    Ok(count)
}

/// List all imported secret key IDs (for backup export).
pub async fn list_secret_ids(imported_ks: &KeyspaceHandle) -> Result<Vec<String>, AppError> {
    let raw = imported_ks.prefix_iter_raw(SECRET_PREFIX).await?;
    Ok(raw
        .into_iter()
        .filter_map(|(k, _)| {
            String::from_utf8(k)
                .ok()?
                .strip_prefix(SECRET_PREFIX)
                .map(String::from)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).unwrap();
        (store, dir)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_or_create_salt_converges_on_one_salt_under_concurrency() {
        // Two concurrent first imports must agree on a single KEK salt:
        // a lost overwrite here makes the winner's just-encrypted secret
        // permanently undecryptable.
        let (store, _dir) = temp_store();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let ks = store.keyspace("keys").unwrap();
            handles.push(tokio::spawn(async move {
                get_or_create_salt(&ks).await.expect("salt")
            }));
        }
        let mut salts = Vec::new();
        for h in handles {
            salts.push(h.await.expect("join"));
        }
        let persisted = get_salt(&store.keyspace("keys").unwrap())
            .await
            .unwrap()
            .expect("salt persisted");
        for s in &salts {
            assert_eq!(
                s, &persisted,
                "every concurrent caller must observe the persisted salt"
            );
        }
    }

    #[tokio::test]
    async fn test_store_and_load_secret() {
        let (store, _dir) = temp_store();
        let imported_ks = store.keyspace("imported_secrets").unwrap();
        let keys_ks = store.keyspace("keys").unwrap();
        let seed = [42u8; 32];
        let secret = b"my-secret-key-bytes-32-chars!!!!";

        store_secret(&imported_ks, &keys_ks, &seed, "test-key", "ed25519", secret)
            .await
            .unwrap();

        let loaded = load_secret(&imported_ks, &keys_ks, &seed, "test-key", "ed25519")
            .await
            .unwrap();

        assert_eq!(loaded, secret);
    }

    #[tokio::test]
    async fn test_wrong_aad_fails() {
        let (store, _dir) = temp_store();
        let imported_ks = store.keyspace("imported_secrets").unwrap();
        let keys_ks = store.keyspace("keys").unwrap();
        let seed = [42u8; 32];
        let secret = b"my-secret-key-bytes-32-chars!!!!";

        store_secret(&imported_ks, &keys_ks, &seed, "test-key", "ed25519", secret)
            .await
            .unwrap();

        // Try to load with wrong key_type (wrong AAD)
        let result = load_secret(&imported_ks, &keys_ks, &seed, "test-key", "x25519").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_secret_removes_value() {
        let (store, _dir) = temp_store();
        let imported_ks = store.keyspace("imported_secrets").unwrap();
        let keys_ks = store.keyspace("keys").unwrap();
        let seed = [42u8; 32];

        store_secret(
            &imported_ks,
            &keys_ks,
            &seed,
            "del-key",
            "ed25519",
            b"secret",
        )
        .await
        .unwrap();

        delete_secret(&imported_ks, "del-key").await.unwrap();

        let result = load_secret(&imported_ks, &keys_ks, &seed, "del-key", "ed25519").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reencrypt_all() {
        let (store, _dir) = temp_store();
        let imported_ks = store.keyspace("imported_secrets").unwrap();
        let keys_ks = store.keyspace("keys").unwrap();
        let old_seed = [42u8; 32];
        let new_seed = [99u8; 32];
        let secret = b"my-secret-key-bytes-32-chars!!!!";

        store_secret(&imported_ks, &keys_ks, &old_seed, "rk-1", "ed25519", secret)
            .await
            .unwrap();

        let key_records = vec![("rk-1".to_string(), "ed25519".to_string())];
        let count = reencrypt_all(&imported_ks, &keys_ks, &old_seed, &new_seed, &key_records)
            .await
            .unwrap();
        assert_eq!(count, 1);

        // Old seed can no longer decrypt
        let result = load_secret(&imported_ks, &keys_ks, &old_seed, "rk-1", "ed25519").await;
        assert!(result.is_err());

        // New seed can decrypt
        let loaded = load_secret(&imported_ks, &keys_ks, &new_seed, "rk-1", "ed25519")
            .await
            .unwrap();
        assert_eq!(loaded, secret);
    }
}
