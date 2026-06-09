pub mod derivation;
pub mod imported;
pub mod paths;
pub mod seed_store;
pub mod seeds;
pub mod wrapping;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use multibase::Base;

use crate::store::KeyspaceHandle;

pub use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};

/// Encode raw private key bytes as multibase (Base58BTC) with multicodec prefix.
/// This makes private key material self-describing and compatible with
/// `Secret::from_multibase()` in the SSI ecosystem.
pub(crate) fn encode_private_multibase(key_type: &KeyType, raw_bytes: &[u8]) -> String {
    let codec: &[u8] = match key_type {
        KeyType::Ed25519 => &[0x80, 0x26], // ed25519-priv (0x1300)
        KeyType::X25519 => &[0x82, 0x26],  // x25519-priv (0x1302)
        KeyType::P256 => &[0x86, 0x26],    // p256-priv (0x1306)
    };
    let mut buf = Vec::with_capacity(codec.len() + raw_bytes.len());
    buf.extend_from_slice(codec);
    buf.extend_from_slice(raw_bytes);
    multibase::encode(Base::Base58Btc, &buf)
}

/// Encode raw public key bytes as multibase (Base58BTC) with multicodec prefix.
pub(crate) fn encode_public_multibase(key_type: &KeyType, raw_bytes: &[u8]) -> String {
    let codec: &[u8] = match key_type {
        KeyType::Ed25519 => &[0xed, 0x01], // ed25519-pub
        KeyType::X25519 => &[0xec, 0x01],  // x25519-pub
        KeyType::P256 => &[0x80, 0x24],    // p256-pub (0x1200)
    };
    let mut buf = Vec::with_capacity(codec.len() + raw_bytes.len());
    buf.extend_from_slice(codec);
    buf.extend_from_slice(raw_bytes);
    multibase::encode(Base::Base58Btc, &buf)
}

pub fn store_key(key_id: &str) -> String {
    format!("key:{key_id}")
}

pub use vta_sdk::did_key::ed25519_multibase_pubkey;

/// Persist a key as a [`KeyRecord`] in the `"keys"` keyspace.
#[allow(clippy::too_many_arguments)]
pub async fn save_key_record(
    keys_ks: &KeyspaceHandle,
    key_id: &str,
    derivation_path: &str,
    key_type: KeyType,
    public_key: &str,
    label: &str,
    context_id: Option<&str>,
    seed_id: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        derivation_path: derivation_path.to_string(),
        key_type,
        status: KeyStatus::Active,
        public_key: public_key.to_string(),
        label: Some(label.to_string()),
        context_id: context_id.map(String::from),
        seed_id,
        origin: KeyOrigin::Derived,
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(store_key(key_id), &record).await?;
    Ok(())
}

/// Derive an Ed25519 did:key from the BIP-32 seed using a counter-allocated
/// path under `base`, store it as a [`KeyRecord`], and return
/// `(did, private_key_multibase)`.
///
/// The key_id uses the standard did:key fragment format: `{did}#{multibase_pubkey}`.
pub async fn derive_and_store_did_key(
    seed: &[u8],
    base: &str,
    context_id: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
    seed_id: Option<u32>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let dk_path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;
    let derivation_path: DerivationPath = dk_path
        .parse()
        .map_err(|e| format!("Invalid derivation path: {e}"))?;
    let dk_derived = root
        .derive(&derivation_path)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let signing_key = SigningKey::from_bytes(dk_derived.signing_key.as_bytes());
    let public_key = signing_key.verifying_key().to_bytes();

    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let key_id = format!("{did}#{multibase_pubkey}");
    let private_key_multibase =
        encode_private_multibase(&KeyType::Ed25519, dk_derived.signing_key.as_bytes());

    save_key_record(
        keys_ks,
        &key_id,
        &dk_path,
        KeyType::Ed25519,
        &multibase_pubkey,
        label,
        Some(context_id),
        seed_id,
    )
    .await?;

    Ok((did, private_key_multibase))
}

/// Derived signing + key-agreement key data, before DID creation.
#[allow(dead_code)]
pub struct DerivedEntityKeys {
    pub signing_secret: Secret,
    pub signing_path: String,
    pub signing_pub: String,
    pub signing_priv: String,
    pub signing_label: String,
    pub ka_secret: Secret,
    pub ka_path: String,
    pub ka_pub: String,
    pub ka_priv: String,
    pub ka_label: String,
}

/// Pre-rotation key data returned from derivation (stored after DID creation).
pub struct PreRotationKeyData {
    pub path: String,
    pub public_key: String,
    pub label: String,
}

/// Derived VTA sealed-transfer key material, stored as `{vta_did}#sealed-transfer-0`.
///
/// The VTA mints this as a third key at DID creation (alongside `#key-0`
/// signing and `#key-1` key-agreement). Its sole job is signing the
/// sealed-transfer producer assertion (domain-tagged
/// `b"vta-sealed-transfer/v1\0" || client_x25519_pub || bundle_id`).
/// Keeping it separate from `#key-0` (which signs VC Data-Integrity
/// proofs) means:
///   - a compromise of one key does not void the other
///   - each can rotate on its own cadence
///   - audit records carry distinct `verification_method` IDs
///
/// Cryptographic reuse is already blocked by the domain tag, so this is
/// a blast-radius / operational-hygiene win rather than a correctness fix.
pub struct DerivedSealedTransferKey {
    pub path: String,
    pub public_key: String,
    pub private_key: String,
    pub label: String,
}

/// Derive the VTA's sealed-transfer key (`{vta_did}#sealed-transfer-0`)
/// from the BIP-32 seed using a counter-allocated path under `base`.
///
/// Allocates a derivation-path counter but does **not** store a key record —
/// callers must call [`save_sealed_transfer_key_record`] after the DID is known.
pub async fn derive_sealed_transfer_key(
    seed: &[u8],
    base: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<DerivedSealedTransferKey, Box<dyn std::error::Error>> {
    let path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;
    let derived = root
        .derive(
            &path
                .parse::<DerivationPath>()
                .map_err(|e| format!("Invalid derivation path: {e}"))?,
        )
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    let secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
    let public_key = secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;
    let private_key = encode_private_multibase(&KeyType::Ed25519, derived.signing_key.as_bytes());

    Ok(DerivedSealedTransferKey {
        path,
        public_key,
        private_key,
        label: label.to_string(),
    })
}

/// Persist the VTA's sealed-transfer key as a `KeyRecord` at
/// `{did}#sealed-transfer-0`.
pub async fn save_sealed_transfer_key_record(
    did: &str,
    derived: &DerivedSealedTransferKey,
    keys_ks: &KeyspaceHandle,
    context_id: Option<&str>,
    seed_id: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    save_key_record(
        keys_ks,
        &format!("{did}#sealed-transfer-0"),
        &derived.path,
        KeyType::Ed25519,
        &derived.public_key,
        &derived.label,
        context_id,
        seed_id,
    )
    .await
}

/// Derive a signing key (Ed25519) and key-agreement key (X25519) from the
/// BIP-32 seed using counter-allocated paths under `base`.
///
/// Allocates derivation-path counters but does **not** store key records —
/// callers must call [`save_entity_key_records`] after the DID is known.
pub async fn derive_entity_keys(
    seed: &[u8],
    base: &str,
    signing_label: &str,
    ka_label: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<DerivedEntityKeys, Box<dyn std::error::Error>> {
    let signing_path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;
    let ka_path = paths::allocate_path(keys_ks, base)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

    // Signing key (Ed25519)
    let signing_derived = root
        .derive(
            &signing_path
                .parse::<DerivationPath>()
                .map_err(|e| format!("Invalid derivation path: {e}"))?,
        )
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let signing_priv =
        encode_private_multibase(&KeyType::Ed25519, signing_derived.signing_key.as_bytes());
    let signing_secret =
        Secret::generate_ed25519(None, Some(signing_derived.signing_key.as_bytes()));
    let signing_pub = signing_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    // Key-agreement key (X25519)
    let ka_derived = root
        .derive(
            &ka_path
                .parse::<DerivationPath>()
                .map_err(|e| format!("Invalid derivation path: {e}"))?,
        )
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    // Encode as Ed25519 seed — consumers derive X25519 via Secret::to_x25519()
    let ka_priv = encode_private_multibase(&KeyType::Ed25519, ka_derived.signing_key.as_bytes());
    let ka_secret = Secret::generate_ed25519(None, Some(ka_derived.signing_key.as_bytes()));
    let ka_secret = ka_secret
        .to_x25519()
        .map_err(|e| format!("X25519 conversion failed: {e}"))?;
    let ka_pub = ka_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    Ok(DerivedEntityKeys {
        signing_secret,
        signing_path,
        signing_pub,
        signing_priv,
        signing_label: signing_label.to_string(),
        ka_secret,
        ka_path,
        ka_pub,
        ka_priv,
        ka_label: ka_label.to_string(),
    })
}

/// Store entity key records using DID verification method IDs as key_ids.
///
/// Signing key → `{did}#key-0`, key-agreement key → `{did}#key-1`. The
/// `label` field is also stored as the VM id rather than the freeform
/// description carried in `derived.{signing,ka}_label`: belt-and-braces
/// for downstream code that historically adopted the label as the kid
/// (see [`vta_sdk::did_secrets::select_secret_kid`] rule #2). A reader
/// that confuses label and id can no longer break decryption — both
/// agree.
pub async fn save_entity_key_records(
    did: &str,
    derived: &DerivedEntityKeys,
    keys_ks: &KeyspaceHandle,
    context_id: Option<&str>,
    seed_id: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_vm_id = format!("{did}#key-0");
    let ka_vm_id = format!("{did}#key-1");
    save_key_record(
        keys_ks,
        &signing_vm_id,
        &derived.signing_path,
        KeyType::Ed25519,
        &derived.signing_pub,
        &signing_vm_id,
        context_id,
        seed_id,
    )
    .await?;
    save_key_record(
        keys_ks,
        &ka_vm_id,
        &derived.ka_path,
        KeyType::X25519,
        &derived.ka_pub,
        &ka_vm_id,
        context_id,
        seed_id,
    )
    .await?;
    Ok(())
}

// ===========================================================================
// Integration tests: full create → store → recover cycle
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derivation::Bip32Extension;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn test_seed() -> Vec<u8> {
        vec![
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ]
    }

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("failed to open store");
        (store, dir)
    }

    /// Full lifecycle test: derive_entity_keys → save_entity_key_records →
    /// load key records → re-derive from stored paths → verify public keys match.
    ///
    /// This simulates first-boot DID creation followed by a VTA restart.
    #[tokio::test]
    async fn test_create_store_recover_cycle() {
        let seed = test_seed();
        let (store, _dir) = temp_store();
        let keys_ks = store.keyspace("keys").unwrap();
        let did = "did:webvh:abc123:example.com:vta";

        // === CREATION (first boot — derive_entity_keys + save) ===
        let derived = derive_entity_keys(&seed, "m/44'/0'", "signing", "key-agreement", &keys_ks)
            .await
            .unwrap();

        save_entity_key_records(did, &derived, &keys_ks, Some("vta"), Some(0))
            .await
            .unwrap();

        let created_signing_pub = derived.signing_pub.clone();
        let created_ka_pub = derived.ka_pub.clone();

        // === RECOVERY (restart — load key records, re-derive from seed + path) ===
        // This mirrors what init_auth() does in server.rs

        let signing_record: KeyRecord = keys_ks
            .get(store_key(&format!("{did}#key-0")))
            .await
            .unwrap()
            .expect("signing key record not found");
        let ka_record: KeyRecord = keys_ks
            .get(store_key(&format!("{did}#key-1")))
            .await
            .unwrap()
            .expect("KA key record not found");

        assert_eq!(signing_record.key_type, KeyType::Ed25519);
        assert_eq!(ka_record.key_type, KeyType::X25519);
        assert_eq!(signing_record.seed_id, Some(0));

        let root = ExtendedSigningKey::from_seed(&seed).unwrap();

        let recovered_signing = root
            .derive_ed25519(&signing_record.derivation_path)
            .unwrap();
        let recovered_ka = root.derive_x25519(&ka_record.derivation_path).unwrap();

        let recovered_signing_pub = recovered_signing.get_public_keymultibase().unwrap();
        let recovered_ka_pub = recovered_ka.get_public_keymultibase().unwrap();

        // === ASSERTIONS ===

        // Public keys from recovery must match what was stored in the key records
        assert_eq!(
            signing_record.public_key, recovered_signing_pub,
            "stored signing public key does not match recovered key"
        );
        assert_eq!(
            ka_record.public_key, recovered_ka_pub,
            "stored KA public key does not match recovered key"
        );

        // Public keys from recovery must match what DID creation produced
        assert_eq!(
            created_signing_pub, recovered_signing_pub,
            "created signing public key does not match recovered key — \
             DID document would have wrong signing key"
        );
        assert_eq!(
            created_ka_pub, recovered_ka_pub,
            "created KA public key does not match recovered key — \
             DID document would have wrong key-agreement key, \
             DIDComm encryption/decryption will fail"
        );
    }

    /// Test that key records survive store persistence (write → close → reopen → read).
    #[tokio::test]
    async fn test_key_records_survive_store_reopen() {
        let seed = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:abc123:example.com:vta";

        // Create and save
        {
            let config = StoreConfig {
                data_dir: dir.path().to_path_buf(),
            };
            let store = Store::open(&config).unwrap();
            let keys_ks = store.keyspace("keys").unwrap();

            let derived = derive_entity_keys(&seed, "m/44'/0'", "signing", "ka", &keys_ks)
                .await
                .unwrap();

            save_entity_key_records(did, &derived, &keys_ks, Some("vta"), Some(0))
                .await
                .unwrap();

            store.persist().await.unwrap();
        }

        // Reopen and verify
        {
            let config = StoreConfig {
                data_dir: dir.path().to_path_buf(),
            };
            let store = Store::open(&config).unwrap();
            let keys_ks = store.keyspace("keys").unwrap();

            let signing: KeyRecord = keys_ks
                .get(store_key(&format!("{did}#key-0")))
                .await
                .unwrap()
                .expect("signing key not found after reopen");
            let ka: KeyRecord = keys_ks
                .get(store_key(&format!("{did}#key-1")))
                .await
                .unwrap()
                .expect("KA key not found after reopen");

            // Re-derive and compare
            let root = ExtendedSigningKey::from_seed(&seed).unwrap();
            let recovered_sign_pub = root
                .derive_ed25519(&signing.derivation_path)
                .unwrap()
                .get_public_keymultibase()
                .unwrap();
            let recovered_ka_pub = root
                .derive_x25519(&ka.derivation_path)
                .unwrap()
                .get_public_keymultibase()
                .unwrap();

            assert_eq!(signing.public_key, recovered_sign_pub);
            assert_eq!(ka.public_key, recovered_ka_pub);
        }
    }

    /// Test that the derivation path counter allocates unique paths and
    /// each path produces a different key.
    #[tokio::test]
    async fn test_path_allocation_produces_unique_keys() {
        let seed = test_seed();
        let (store, _dir) = temp_store();
        let keys_ks = store.keyspace("keys").unwrap();

        let base = "m/44'/0'";
        let mut pub_keys = Vec::new();

        for _ in 0..5 {
            let path = paths::allocate_path(&keys_ks, base).await.unwrap();
            let root = ExtendedSigningKey::from_seed(&seed).unwrap();
            let secret = root.derive_ed25519(&path).unwrap();
            pub_keys.push(secret.get_public_keymultibase().unwrap());
        }

        // All keys must be distinct
        for i in 0..pub_keys.len() {
            for j in (i + 1)..pub_keys.len() {
                assert_ne!(
                    pub_keys[i], pub_keys[j],
                    "path allocation produced duplicate keys at indices {i} and {j}"
                );
            }
        }
    }

    /// Seed stored as hex (retired seed archival) must produce identical keys
    /// when decoded and used for re-derivation.
    #[tokio::test]
    async fn test_hex_seed_roundtrip() {
        let seed = test_seed();
        let path = "m/44'/0'/0'";

        // Simulate archival: hex-encode and decode
        let hex_seed = hex::encode(&seed);
        let recovered_seed = hex::decode(&hex_seed).unwrap();

        let root_original = ExtendedSigningKey::from_seed(&seed).unwrap();
        let root_recovered = ExtendedSigningKey::from_seed(&recovered_seed).unwrap();

        let sign_orig = root_original.derive_ed25519(path).unwrap();
        let sign_recv = root_recovered.derive_ed25519(path).unwrap();

        assert_eq!(
            sign_orig.get_public_keymultibase().unwrap(),
            sign_recv.get_public_keymultibase().unwrap(),
            "hex-encoded seed round-trip produced different keys"
        );

        let ka_orig = root_original.derive_x25519(path).unwrap();
        let ka_recv = root_recovered.derive_x25519(path).unwrap();

        assert_eq!(
            ka_orig.get_public_keymultibase().unwrap(),
            ka_recv.get_public_keymultibase().unwrap(),
            "hex-encoded seed round-trip produced different X25519 keys"
        );
    }
}
