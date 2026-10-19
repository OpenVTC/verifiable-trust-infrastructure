//! The service's own identity: the DID every answer is signed as.
//!
//! This version serves as a `did:key` held in a seed file under the data directory, minted on
//! first start. That is enough for a community to name it as `ballotBox` and for every answer
//! to be attributable. A deployment provisioned by a VTA from a DID template (a `did:webvh`
//! with TSP and DIDComm endpoints, as the witness and the room host are) replaces this file;
//! the rest of the service does not change.

use std::{fs, path::Path};

use anyhow::Context;
use vta_sdk::trust_task_sign::HolderKey;

/// The service's DID and the key it signs with.
#[derive(Debug, Clone)]
pub struct Identity {
    pub did: String,
    pub key: HolderKey,
}

const SEED_FILE: &str = "identity.seed";

impl Identity {
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
