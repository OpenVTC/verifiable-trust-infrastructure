//! The witness identities' key material, held in the operator's secret store.
//!
//! One blob in one [`SeedStore`](vti_common::seed_store::SeedStore): every
//! identity's [`DidSecretsBundle`], keyed by DID. The store is whichever
//! backend `[secrets]` selects — the same `vti_secrets::create_seed_store`
//! the VTA and VTC use — so key material never lands in `config.toml`.
//!
//! The VTA that minted the keys still custodies them (it derives them from
//! its seed); this is the witness's working copy, opened once from the sealed
//! provisioning bundle at setup.

use serde::{Deserialize, Serialize};
use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
use vta_sdk::sealed_transfer::DidKeyMaterialV2;
use vti_common::seed_store::SeedStore;

/// The stored shape. Versioned so a later layout can be told apart from this one.
#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    identities: Vec<DidSecretsBundle>,
}

const VERSION: u32 = 1;

/// Every witness identity's key material.
///
/// `Debug` is written by hand and names only the DIDs: the bundles hold
/// private keys, and a derived `Debug` is how key material reaches a log.
#[derive(Default, Clone)]
pub struct WitnessKeyring {
    identities: Vec<DidSecretsBundle>,
}

impl std::fmt::Debug for WitnessKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessKeyring")
            .field(
                "identities",
                &self.identities.iter().map(|b| &b.did).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl WitnessKeyring {
    /// Add or replace the bundle for its DID.
    pub fn insert(&mut self, bundle: DidSecretsBundle) {
        self.identities.retain(|b| b.did != bundle.did);
        self.identities.push(bundle);
    }

    /// The bundle for `did`.
    pub fn get(&self, did: &str) -> Option<&DidSecretsBundle> {
        self.identities.iter().find(|b| b.did == did)
    }

    /// How many identities it holds.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Serialise for the store.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Stored {
            version: VERSION,
            identities: self.identities.clone(),
        })?)
    }

    /// Parse what [`Self::to_bytes`] wrote.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let stored: Stored = serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("the stored witness keys do not parse: {e}"))?;
        if stored.version != VERSION {
            anyhow::bail!(
                "the stored witness keys are version {}, this binary reads version {VERSION}",
                stored.version
            );
        }
        Ok(Self {
            identities: stored.identities,
        })
    }

    /// Read the keyring from `store`; empty when nothing is stored yet.
    pub async fn load(store: &dyn SeedStore) -> anyhow::Result<Self> {
        match store
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("read the witness keys from the secret store: {e}"))?
        {
            Some(bytes) => Self::from_bytes(&bytes),
            None => Ok(Self::default()),
        }
    }

    /// Write the keyring to `store`.
    pub async fn save(&self, store: &dyn SeedStore) -> anyhow::Result<()> {
        store
            .set(&self.to_bytes()?)
            .await
            .map_err(|e| anyhow::anyhow!("write the witness keys to the secret store: {e}"))
    }
}

/// The working copy of one identity's keys, from the sealed provisioning
/// bundle's key material: the primary signing key and the key-agreement key,
/// each under the verification-method id the DID document publishes.
///
/// Extra signing keys are carried too, though the `dtg-witness` template declares
/// none — dropping a key the VTA minted and published would be a silent
/// divergence from the document.
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

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::keys::KeyType;

    fn bundle(did: &str) -> DidSecretsBundle {
        DidSecretsBundle {
            did: did.to_string(),
            secrets: vec![SecretEntry {
                key_id: format!("{did}#key-0"),
                key_type: KeyType::Ed25519,
                private_key_multibase: "zPRIVATE".to_string(),
            }],
        }
    }

    #[test]
    fn a_keyring_round_trips_and_replaces_by_did() {
        let mut ring = WitnessKeyring::default();
        ring.insert(bundle("did:webvh:a:x"));
        ring.insert(bundle("did:webvh:b:x"));
        ring.insert(bundle("did:webvh:a:x"));
        assert_eq!(ring.len(), 2, "a second insert for one DID replaces it");

        let again = WitnessKeyring::from_bytes(&ring.to_bytes().unwrap()).unwrap();
        assert!(again.get("did:webvh:a:x").is_some());
        assert!(again.get("did:webvh:b:x").is_some());
        assert!(again.get("did:webvh:c:x").is_none());
    }

    #[test]
    fn debug_names_the_dids_and_never_the_keys() {
        let mut ring = WitnessKeyring::default();
        ring.insert(bundle("did:webvh:a:x"));
        let shown = format!("{ring:?}");
        assert!(shown.contains("did:webvh:a:x"), "{shown}");
        assert!(!shown.contains("zPRIVATE"), "{shown}");
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let err = WitnessKeyring::from_bytes(br#"{"version":2,"identities":[]}"#).unwrap_err();
        assert!(err.to_string().contains("version 2"), "{err}");
    }
}
