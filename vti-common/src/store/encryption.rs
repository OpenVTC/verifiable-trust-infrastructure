//! AES-256-GCM encryption for keyspace values, bound to their location.
//!
//! # Associated data (the integrity fix)
//!
//! Every value is authenticated against its `(keyspace, key)` location via
//! AES-GCM associated data (AAD). Without it, a value's ciphertext is bound to
//! nothing: an attacker who controls the storage medium (in the Nitro model the
//! parent EC2 instance owns the fjall database) could **cut-and-paste** a
//! ciphertext from one key to another — e.g. resurrect a revoked admin ACL row,
//! or move a value across keyspaces that share the single storage key — without
//! breaking any crypto. Binding `(keyspace, key)` into the AAD makes such a
//! relocation fail authentication.
//!
//! # On-disk format (v1)
//!
//! ```text
//! [4-byte magic "VAE1"][12-byte random nonce][ciphertext + 16-byte GCM tag]
//! ```
//!
//! # Breaking change
//!
//! This is **not** wire-compatible with the previous AAD-less format
//! (`[nonce][ct]`). Values written by an older build cannot be decrypted by
//! this one — by design: a legacy read-fallback would reintroduce the
//! cut-and-paste hole via downgrade (an attacker would just write legacy-format
//! values). Encrypted deployments (TEE, or non-TEE with an explicit
//! `storage_encryption_key`) must re-bootstrap or restore from backup. Stores
//! with no encryption key configured are unaffected — they never encrypted.

use crate::error::AppError;

/// Format magic for AAD-authenticated values. Distinguishes the v1 format
/// from the legacy AAD-less layout so a stale value yields a clear error
/// rather than a confusing GCM authentication failure.
const MAGIC: &[u8; 4] = b"VAE1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Build the AES-GCM associated data binding a value to its location.
///
/// `len(keyspace) ‖ keyspace ‖ key` — the length prefix makes the encoding
/// unambiguous regardless of what bytes the store key contains, so no two
/// distinct `(keyspace, key)` pairs can produce the same AAD.
fn build_aad(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let ks = keyspace.as_bytes();
    let mut aad = Vec::with_capacity(4 + ks.len() + key.len());
    aad.extend_from_slice(&(ks.len() as u32).to_be_bytes());
    aad.extend_from_slice(ks);
    aad.extend_from_slice(key);
    aad
}

/// Encrypt `plaintext` with AES-256-GCM, authenticating it against its
/// `(keyspace, key)` location. Output: `MAGIC ‖ nonce ‖ ct+tag`.
pub fn encrypt_value(
    enc_key: &[u8; 32],
    keyspace: &str,
    store_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};

    let cipher = Aes256Gcm::new_from_slice(enc_key)
        .map_err(|e| AppError::Internal(format!("AES key error: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(keyspace, store_key);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| AppError::Internal(format!("AES-GCM encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// True if `data` is in the v1 AAD-authenticated on-disk format (i.e. it
/// carries the [`MAGIC`] prefix). Used by the boot migration
/// ([`super::KeyspaceHandle::migrate_to_encrypted`]) to tell an
/// already-encrypted row apart from a legacy plaintext one without
/// attempting (and failing) a decrypt. This is a *format* check only — it
/// does not authenticate the value.
pub(crate) fn is_v1_encrypted(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// Decrypt an AAD-authenticated value, verifying it against its
/// `(keyspace, key)` location. Input: `MAGIC ‖ nonce ‖ ct+tag`.
fn decrypt_value(
    enc_key: &[u8; 32],
    keyspace: &str,
    store_key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AppError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};

    if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        return Err(AppError::Internal(
            "encrypted value is not in the AAD-authenticated v1 format \
             (likely written by a pre-integrity-fix build); this store is \
             incompatible — re-bootstrap or restore from backup"
                .into(),
        ));
    }
    let body = &data[MAGIC.len()..];
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::Internal(
            "encrypted value too short (missing nonce or auth tag)".into(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(enc_key)
        .map_err(|e| AppError::Internal(format!("AES key error: {e}")))?;

    let nonce = Nonce::from_slice(&body[..NONCE_LEN]);
    let ciphertext = &body[NONCE_LEN..];
    let aad = build_aad(keyspace, store_key);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| {
            AppError::Internal(format!(
                "AES-GCM decryption failed (corrupt data, wrong key, or value \
                 moved to a different keyspace/key): {e}"
            ))
        })
}

/// Decrypt bytes if an encryption key is provided, otherwise return a copy.
/// `keyspace` and `store_key` identify the value's location for AAD
/// verification.
pub fn maybe_decrypt_bytes(
    enc_key: Option<&[u8; 32]>,
    keyspace: &str,
    store_key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AppError> {
    match enc_key {
        Some(k) => decrypt_value(k, keyspace, store_key, data),
        None => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn round_trip_at_same_location() {
        let ct = encrypt_value(&KEY, "acl", b"acl:did:key:zX", b"secret").unwrap();
        let pt = decrypt_value(&KEY, "acl", b"acl:did:key:zX", &ct).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn cross_key_paste_is_rejected() {
        // A value encrypted for key A must not decrypt when relocated to key B.
        let ct = encrypt_value(&KEY, "acl", b"acl:victim", b"admin-row").unwrap();
        let err = decrypt_value(&KEY, "acl", b"acl:attacker", &ct);
        assert!(err.is_err(), "cross-key paste must fail authentication");
    }

    #[test]
    fn cross_keyspace_paste_is_rejected() {
        // Same key string, different keyspace (both share the storage key).
        let ct = encrypt_value(&KEY, "keys", b"active_seed_id", b"\x01").unwrap();
        let err = decrypt_value(&KEY, "contexts", b"active_seed_id", &ct);
        assert!(
            err.is_err(),
            "cross-keyspace paste must fail authentication"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let ct = encrypt_value(&KEY, "acl", b"k", b"v").unwrap();
        let err = decrypt_value(&[9u8; 32], "acl", b"k", &ct);
        assert!(err.is_err());
    }

    #[test]
    fn legacy_unauthenticated_value_gives_clear_error() {
        // A pre-v1 value (no magic prefix) must be rejected with a
        // format-specific message, not a generic GCM failure.
        let legacy = vec![0u8; NONCE_LEN + TAG_LEN + 4];
        let err = decrypt_value(&KEY, "acl", b"k", &legacy).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("v1 format") || msg.contains("re-bootstrap"),
            "expected a format-incompatibility hint, got: {msg}"
        );
    }

    #[test]
    fn maybe_decrypt_without_key_is_passthrough() {
        let data = b"plain";
        let out = maybe_decrypt_bytes(None, "acl", b"k", data).unwrap();
        assert_eq!(out, data);
    }
}
