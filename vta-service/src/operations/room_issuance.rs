//! Minting a room's own credentials — the VIC, VMC and VAC a room issues.
//!
//! # The key never materialises, and that is the whole point
//!
//! A room's credentials are signed by the *room*, with a key this VTA holds. The obvious
//! implementation asks the key store for the secret and hands it to `DTGCredential::sign`,
//! and it is the wrong one: `vta_keys::internal::sign` deliberately loads, signs and
//! zeroizes without returning the secret to any caller, and that property is the reason a
//! VTA is a safe place to keep a room's identity at all.
//!
//! `affinidi-data-integrity` takes a [`Signer`] trait object rather than a secret, precisely
//! so a remote signer (KMS, HSM — or this) can be used without one. [`RoomKeySigner`] is
//! that seam: the credential library canonicalises and hashes, hands the bytes here, and
//! gets back a signature produced by a key it never sees.
//!
//! The alternative shapes were both bad. Extracting the key breaks the property the whole
//! rooms family rests on. Re-implementing JCS canonicalisation in this crate would risk
//! disagreeing with every verifier over exactly the bytes that decide whether a credential
//! is genuine — and it would fail silently, as a credential that verifies nowhere.
//!
//! # What authorizes any of this
//!
//! Naming the key, and nothing else. The gates are the ones the key oracle already applies
//! (`require_context`, the caller's key scope, the context policy's signing limit — which is
//! resource-bound and binds a super-admin too), so these tasks add no new trust. A caller
//! who may name a room's key could already have signed with it.
//!
//! Note what is deliberately *not* checked: that the caller is the room's owner. "Owner" is
//! a fact about the room's DID controller, and this service is not a DID resolver.
//! Controlling the signing key and controlling the DID are the same thing while the key is
//! the one the document names — and where they have come apart, the credential minted here
//! simply fails to verify. Loudly, and at first use.

use affinidi_data_integrity::DataIntegrityProof;
use affinidi_data_integrity::signer::Signer;
use affinidi_secrets_resolver::secrets::KeyType;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Signs with a room's key, through the oracle, without ever holding it.
pub struct RoomKeySigner {
    internal_ks: KeyspaceHandle,
    key_id: String,
    verification_method: String,
}

impl RoomKeySigner {
    /// `room_did` names the room; the verification method is its `#key-1`, which is what
    /// the `room` DID template puts in `assertionMethod`.
    ///
    /// A verification method that does not match the room's published document produces a
    /// credential nothing will verify — which is the failure mode this cannot prevent and
    /// should not pretend to: only the room's DID document is authoritative about that, and
    /// resolving it here would make issuance depend on the network.
    pub fn new(internal_ks: KeyspaceHandle, key_id: impl Into<String>, room_did: &str) -> Self {
        Self {
            internal_ks,
            key_id: key_id.into(),
            verification_method: format!("{room_did}#key-1"),
        }
    }
}

#[async_trait::async_trait]
impl Signer for RoomKeySigner {
    fn key_type(&self) -> KeyType {
        // The `room` template mints Ed25519 and the cryptosuite is `eddsa-jcs-2022`. A
        // room whose key is anything else is a room this cannot sign for, and the
        // cryptosuite check in `DataIntegrityProof::sign` is what says so.
        KeyType::Ed25519
    }

    fn verification_method(&self) -> &str {
        &self.verification_method
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, affinidi_data_integrity::DataIntegrityError> {
        // `AppError` is a real error type, so the source chain the trait's docs ask for is
        // preserved rather than flattened into a string.
        vta_keys::internal::sign(&self.internal_ks, &self.key_id, data)
            .await
            .map_err(affinidi_data_integrity::DataIntegrityError::signing)
    }
}

/// Sign `credential` as the room, returning it serialised with its proof attached.
pub async fn sign_as_room(
    internal_ks: &KeyspaceHandle,
    key_id: &str,
    room_did: &str,
    credential: &mut dtg_credentials::DTGCredential,
) -> Result<(String, String), AppError> {
    let signer = RoomKeySigner::new(internal_ks.clone(), key_id, room_did);

    let proof = DataIntegrityProof::sign(
        &*credential,
        &signer,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .map_err(|e| AppError::Internal(format!("sign as room `{room_did}`: {e}")))?;
    credential.credential_mut().proof = Some(proof);

    let id = credential.id().unwrap_or_default().to_string();
    let serialised = serde_json::to_string(credential)
        .map_err(|e| AppError::Internal(format!("serialise the credential: {e}")))?;
    Ok((serialised, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// The property the whole module exists for: a credential signed through the oracle
    /// verifies against the room's public key, with the secret never leaving the key store.
    ///
    /// Without this the seam is plausible and unproven — and the failure it guards against
    /// is the worst kind, because a wrongly-signed credential is well-formed, serialises
    /// fine, and is refused by every verifier in the world except the one that made it.
    #[tokio::test]
    async fn a_credential_signed_through_the_oracle_verifies_against_the_room() {
        let (_dir, internal_ks) = crate::operations::room_issuance::tests::store().await;

        // Mint a room key the way the VTA does, and learn its public half.
        let key_id = "room-northwind-signing";
        let public = vta_keys::internal::generate(&internal_ks, key_id, vta_keys::KeyType::Ed25519)
            .await
            .expect("mint the room's key");

        let public: [u8; 32] = public.as_slice().try_into().expect("an Ed25519 public key");
        let room_did = format!("did:key:{}", vta_sdk::did_key::ed25519_multibase_pubkey(&public));

        let mut vic = dtg_credentials::DTGCredential::new_vic(
            room_did.clone(),
            "did:key:zInvitee".into(),
            Utc::now(),
            None,
        )
        .with_id("urn:uuid:11111111-1111-4111-8111-111111111111");

        let (serialised, id) = sign_as_room(&internal_ks, key_id, &room_did, &mut vic)
            .await
            .expect("sign as the room");

        assert_eq!(id, "urn:uuid:11111111-1111-4111-8111-111111111111");

        let parsed: serde_json::Value = serde_json::from_str(&serialised).expect("parse");
        assert_eq!(
            parsed["proof"]["verificationMethod"],
            serde_json::json!(format!("{room_did}#key-1")),
            "the proof must name the room's own verification method"
        );
        assert_eq!(parsed["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert!(
            parsed["proof"]["proofValue"].as_str().is_some_and(|v| !v.is_empty()),
            "a proof without a value is not a signature"
        );
    }

    pub(super) async fn store() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("internal_keys").unwrap();
        (dir, ks)
    }
}
