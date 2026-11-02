//! Signing as a party (the network, or a member in tests and the member-side helpers).
//!
//! Signing goes through [`affinidi_data_integrity::Signer`], so a VTA-backed signer drops in
//! where the local [`Secret`] is used today (assumption A5).

use std::sync::Arc;

use affinidi_data_integrity::signer::Signer;
use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use dtg_credentials::DTGCredential;
use serde_json::Value;

use crate::did_key;
use crate::error::{Result, VtnError};

/// A DID and a signer whose verification method belongs to it.
#[derive(Clone)]
pub struct Identity {
    did: String,
    signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("did", &self.did).finish()
    }
}

impl Identity {
    /// Wrap any signer. Its verification method must be a key of `did`.
    pub fn new(did: impl Into<String>, signer: Arc<dyn Signer>) -> Result<Self> {
        let did = did.into();
        if did_key::did_of_verification_method(signer.verification_method()) != did {
            return Err(VtnError::InvalidDid(format!(
                "signer verification method {} does not belong to {did}",
                signer.verification_method()
            )));
        }
        Ok(Self { did, signer })
    }

    /// A local Ed25519 `did:key` identity from a 32-byte seed.
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        let probe = Secret::generate_ed25519(None, Some(seed));
        let did = did_key::did_from_ed25519(probe.get_public_bytes());
        let vm = did_key::verification_method(&did).expect("did:key built above");
        let secret = Secret::generate_ed25519(Some(&vm), Some(seed));
        Self {
            did,
            signer: Arc::new(secret),
        }
    }

    /// An identity from a key the VTA minted: `key_id` is the verification method
    /// (`<did>#key-0`) and `private_key_multibase` the Ed25519 private key, as a
    /// `vta_sdk::did_secrets::SecretEntry` carries them.
    pub fn from_private_key_multibase(
        did: &str,
        key_id: &str,
        private_key_multibase: &str,
    ) -> Result<Self> {
        let secret = Secret::from_multibase(private_key_multibase, Some(key_id))
            .map_err(|e| VtnError::InvalidDid(format!("{key_id}: {e}")))?;
        Self::new(did, Arc::new(secret))
    }

    /// The verification method this identity signs with.
    pub fn verification_method(&self) -> &str {
        self.signer.verification_method()
    }

    /// A fresh random local identity.
    pub fn generate() -> Self {
        let mut secret = Secret::generate_ed25519(None, None);
        let did = did_key::did_from_ed25519(secret.get_public_bytes());
        secret.id = did_key::verification_method(&did).expect("did:key built above");
        Self {
            did,
            signer: Arc::new(secret),
        }
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    /// Validate and sign a DTG credential in place.
    pub async fn sign_credential(&self, credential: &mut DTGCredential) -> Result<()> {
        if credential.issuer() != self.did {
            return Err(VtnError::Rejected(format!(
                "credential issuer {} is not the signer {}",
                credential.issuer(),
                self.did
            )));
        }
        credential.validate()?;
        credential.credential_mut().proof = None;
        let proof =
            DataIntegrityProof::sign(&*credential, self.signer.as_ref(), SignOptions::new())
                .await?;
        credential.credential_mut().proof = Some(proof);
        Ok(())
    }

    /// Sign an arbitrary JSON document (the index, a status list credential) as an
    /// assertion: adds `proof`.
    pub async fn sign_document(&self, document: Value) -> Result<Value> {
        self.sign_document_for(document, crate::verify::ASSERTION_METHOD)
            .await
    }

    /// Sign an arbitrary JSON document with the given `proofPurpose`.
    pub async fn sign_document_for(&self, mut document: Value, purpose: &str) -> Result<Value> {
        let object = document
            .as_object_mut()
            .ok_or_else(|| VtnError::Internal("only JSON objects are signed".into()))?;
        object.remove("proof");
        let proof = DataIntegrityProof::sign(
            &document,
            self.signer.as_ref(),
            SignOptions::new().with_proof_purpose(purpose),
        )
        .await?;
        let proof = serde_json::to_value(proof)?;
        document
            .as_object_mut()
            .expect("checked above")
            .insert("proof".into(), proof);
        Ok(document)
    }
}
