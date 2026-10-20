//! The service's own identity: the DID every answer is signed as.
//!
//! Provisioned: a VTA mints a `did:webvh` from the `ballot-box` template (`vti-voting-service
//! setup`), and its keys — one [`DidSecretsBundle`] — are kept in the operator's `[secrets]`
//! store ([`load_keys`] / [`save_keys`]), never in `config.toml`. The VTA still custodies them;
//! this is the service's working copy, opened once from the sealed provisioning bundle.
//!
//! Unprovisioned (no `[identity]` in the configuration): a `did:key` from a seed file under the
//! data directory, minted on first start — for tests, reachable over HTTPS only.

use std::{fs, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::sealed_transfer::DidKeyMaterialV2;
use vta_sdk::trust_task_sign::HolderKey;
use vti_common::seed_store::SeedStore;

/// The service's DID and the key it signs with.
#[derive(Debug, Clone)]
pub struct Identity {
    pub did: String,
    pub key: HolderKey,
}

const SEED_FILE: &str = "identity.seed";

impl Identity {
    /// The provisioned identity, signing with its Ed25519 key.
    ///
    /// # Errors
    /// If the bundle holds no Ed25519 key, or one [`HolderKey`] refuses.
    pub fn from_bundle(bundle: &DidSecretsBundle) -> anyhow::Result<Self> {
        let signing = bundle
            .trust_task_signing_key()
            .ok_or_else(|| anyhow::anyhow!("{} has no Ed25519 signing key", bundle.did))?;
        let key = HolderKey::new(&signing.key_id, &signing.private_key_multibase)
            .map_err(|e| anyhow::anyhow!("identity key: {e}"))?;
        Ok(Self {
            did: bundle.did.clone(),
            key,
        })
    }

    /// A `did:key` from a 32-byte Ed25519 seed.
    ///
    /// # Errors
    /// If the seed does not make a key [`HolderKey`] accepts.
    pub fn from_seed(seed: &[u8; 32]) -> anyhow::Result<Self> {
        let signing = ed25519_dalek::SigningKey::from_bytes(seed);
        let public = signing.verifying_key().to_bytes();
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&public)
        );
        let key =
            HolderKey::from_did_key(&did, multibase::encode(multibase::Base::Base58Btc, seed))
                .map_err(|e| anyhow::anyhow!("identity key: {e}"))?;
        Ok(Self { did, key })
    }

    /// Load the identity from `data_dir`, minting it on first start. The seed file is written
    /// owner-only.
    ///
    /// # Errors
    /// If the file cannot be read or written, or holds something other than a seed.
    pub fn load_or_mint(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join(SEED_FILE);
        if path.exists() {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let (_, bytes) = multibase::decode(text.trim())
                .with_context(|| format!("{} is not a multibase seed", path.display()))?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} does not hold 32 bytes", path.display()))?;
            return Self::from_seed(&seed);
        }
        let mut seed = [0u8; 32];
        vti_voting::rand::RngCore::fill_bytes(&mut vti_voting::rand::rngs::OsRng, &mut seed);
        fs::create_dir_all(data_dir)?;
        vti_common::secure_file::write_secret_file(
            &path,
            multibase::encode(multibase::Base::Base58Btc, seed).as_bytes(),
        )
        .with_context(|| format!("writing {}", path.display()))?;
        Self::from_seed(&seed)
    }
}

/// The stored shape. Versioned so a later layout can be told apart from this one.
#[derive(Serialize, Deserialize)]
struct StoredKeys {
    version: u32,
    identity: DidSecretsBundle,
}

const KEYS_VERSION: u32 = 1;

/// The provisioned identity's keys from `store`; `None` when nothing is stored yet.
///
/// # Errors
/// If the store cannot be read or holds something this binary does not read.
pub async fn load_keys(store: &dyn SeedStore) -> anyhow::Result<Option<DidSecretsBundle>> {
    let Some(bytes) = store
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("read the identity's keys from the secret store: {e}"))?
    else {
        return Ok(None);
    };
    let stored: StoredKeys = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("the stored identity keys do not parse: {e}"))?;
    if stored.version != KEYS_VERSION {
        anyhow::bail!(
            "the stored identity keys are version {}, this binary reads version {KEYS_VERSION}",
            stored.version
        );
    }
    Ok(Some(stored.identity))
}

/// Write the identity's keys to `store`.
///
/// # Errors
/// If the store refuses the write.
pub async fn save_keys(store: &dyn SeedStore, identity: &DidSecretsBundle) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&StoredKeys {
        version: KEYS_VERSION,
        identity: identity.clone(),
    })?;
    store
        .set(&bytes)
        .await
        .map_err(|e| anyhow::anyhow!("write the identity's keys to the secret store: {e}"))
}

/// The working copy of the identity's keys from the sealed provisioning bundle's key material,
/// each under the verification-method id the DID document publishes. Extra signing keys are
/// carried too: dropping a key the VTA minted and published would be a silent divergence from
/// the document.
pub fn bundle_from_material(material: &DidKeyMaterialV2) -> DidSecretsBundle {
    let entry = |key: &vta_sdk::sealed_transfer::SlotKeyPair| SecretEntry {
        key_id: key.key_id.clone(),
        key_type: key.key_type.clone(),
        private_key_multibase: key.private_key_multibase.clone(),
    };
    let mut secrets = vec![entry(&material.signing_key), entry(&material.ka_key)];
    secrets.extend(material.additional_signing_keys.iter().map(entry));
    DidSecretsBundle {
        did: material.did.clone(),
        secrets,
    }
}
