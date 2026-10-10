//! Keyed fingerprints of stored secrets.
//!
//! `external/accounts/secret/set/0.1` answers with a fingerprint "computed as
//! a keyed digest under a custodian-held key, so that the fingerprint cannot be
//! used to test guesses offline". A bare hash of an API key is a guessing
//! oracle for anyone who reads the account (`get`, a console, a log); keyed,
//! it only lets an operator see that a secret *changed*.
//!
//! The key is random per custodian and kept beside the secrets it fingerprints,
//! in `external_secrets` — so, like them, it is not in a backup. A restored
//! custodian has neither the secrets nor the key, and the fingerprints it
//! writes when the secrets are set again are new ones.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

const KEY_ROW: &str = "fingerprint-key";
const DOMAIN: &[u8] = b"vta-external-secret-fingerprint/v1\0";

/// The custodian's fingerprint key, created on first use. Concurrent first uses
/// converge on one key (`insert_raw_if_absent`), so no fingerprint is ever
/// computed under a key that was then overwritten.
pub async fn key(external_secrets: &KeyspaceHandle) -> Result<[u8; 32], AppError> {
    if let Some(k) = external_secrets.get_raw(KEY_ROW).await? {
        return to_key(&k);
    }
    let mut fresh = [0u8; 32];
    rand::fill(&mut fresh);
    if external_secrets
        .insert_raw_if_absent(KEY_ROW, fresh.to_vec())
        .await?
    {
        return Ok(fresh);
    }
    let k = external_secrets
        .get_raw(KEY_ROW)
        .await?
        .ok_or_else(|| AppError::Internal("fingerprint key vanished after a race".into()))?;
    to_key(&k)
}

fn to_key(bytes: &[u8]) -> Result<[u8; 32], AppError> {
    bytes
        .try_into()
        .map_err(|_| AppError::Internal("stored fingerprint key is not 32 bytes".into()))
}

/// The fingerprint of `secret` under `key`, as a `DigestMultibase`
/// (base58btc multihash).
///
/// The multihash names sha2-256 truthfully: it is SHA-256 over the HMAC tag,
/// not the HMAC tag labelled as a hash. Multihash has no code for a keyed MAC.
pub fn of(key: &[u8; 32], secret: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(DOMAIN);
    mac.update(secret);
    let tag = mac.finalize().into_bytes();
    let digest = Sha256::digest(tag);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base58Btc, multihash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_depends_on_the_key_and_the_secret() {
        let a = of(&[1; 32], b"secret");
        assert!(a.starts_with("zQm"), "{a}");
        assert_eq!(a, of(&[1; 32], b"secret"));
        assert_ne!(a, of(&[2; 32], b"secret"), "keyed");
        assert_ne!(a, of(&[1; 32], b"secreT"));
    }
}
