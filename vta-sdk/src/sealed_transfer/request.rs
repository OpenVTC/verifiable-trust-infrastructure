//! Bootstrap request: the consumer-side artifact that initiates a sealed transfer.
//!
//! Carries no secrets — only the consumer's ephemeral Ed25519 `did:key`
//! (multicodec `0xed01`), a fresh nonce, and an optional human-readable label
//! so the producer knows which request they're sealing for.
//!
//! The `client_did` ships as a `did:key:z6Mk…` string rather than a raw
//! X25519 pubkey so every public-key surface in the stack reads as a DID.
//! The producer derives the X25519 pubkey for HPKE at seal time via
//! [`affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes`]; the consumer
//! keeps the Ed25519 seed and derives the X25519 secret at open time via
//! [`affinidi_crypto::ed25519::ed25519_private_to_x25519`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use super::error::SealedTransferError;

/// A request from a consumer to receive a sealed bundle.
///
/// JSON-serialized for offline transport. Contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = SealedBootstrapRequest))]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    /// Wire-format version. Currently 1.
    pub version: u8,

    /// Consumer's ephemeral `did:key` (Ed25519). The producer derives the
    /// X25519 pubkey from this for the HPKE seal.
    pub client_did: String,

    /// Random 16-byte nonce, base64url-no-pad. Becomes the bundle_id under HPKE.
    pub nonce: String,

    /// Optional human-readable label (operator-visible only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Ed25519 signature by `client_did` over [`claim_signing_input`],
    /// base64url-no-pad. Proves the caller holds the key behind a
    /// pre-registered ephemeral DID, so a TEE VTA can refuse a first-boot
    /// admin claim before minting anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_signature: Option<String>,
}

/// Domain tag so a claim signature can't be lifted from, or replayed into,
/// any other Ed25519 signing context.
const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"vti/bootstrap-claim/v1\0";

/// Bytes signed for [`BootstrapRequest::claim_signature`]:
/// `domain || client_ed25519_pub || nonce`.
pub fn claim_signing_input(client_ed25519_pub: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut input = Vec::with_capacity(CLAIM_SIGNATURE_DOMAIN.len() + 32 + 16);
    input.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
    input.extend_from_slice(client_ed25519_pub);
    input.extend_from_slice(nonce);
    input
}

impl BootstrapRequest {
    /// Build a new request from raw Ed25519 pubkey + nonce bytes. The pubkey
    /// is encoded as a `did:key:z6Mk…` string on the wire.
    pub fn new(client_ed25519_pub: [u8; 32], nonce: [u8; 16], label: Option<String>) -> Self {
        Self {
            version: 1,
            client_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&client_ed25519_pub),
            nonce: BASE64.encode(nonce),
            label,
            claim_signature: None,
        }
    }

    /// Build a request whose `client_did` is the key behind `client_ed25519_seed`,
    /// signed to prove control of it (see [`Self::claim_signature`]).
    pub fn new_signed_claim(
        client_ed25519_seed: &[u8; 32],
        nonce: [u8; 16],
        label: Option<String>,
    ) -> Self {
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(client_ed25519_seed);
        let public = signing.verifying_key().to_bytes();
        let signature = signing.sign(&claim_signing_input(&public, &nonce));
        Self {
            claim_signature: Some(BASE64.encode(signature.to_bytes())),
            ..Self::new(public, nonce, label)
        }
    }

    /// Verify [`Self::claim_signature`] against `client_did`. Errors when the
    /// signature is absent, malformed, or not made by `client_did`'s key.
    pub fn verify_claim_signature(&self) -> Result<(), SealedTransferError> {
        let encoded = self
            .claim_signature
            .as_deref()
            .ok_or_else(|| SealedTransferError::Wire("claim_signature is missing".into()))?;
        let raw: [u8; 64] = BASE64
            .decode(encoded)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?
            .try_into()
            .map_err(|_| SealedTransferError::Wire("claim_signature must be 64 bytes".into()))?;
        let public = self.decode_client_ed25519_pub()?;
        let nonce = self.decode_nonce()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|e| SealedTransferError::Wire(format!("client_did key: {e}")))?;
        key.verify_strict(
            &claim_signing_input(&public, &nonce),
            &ed25519_dalek::Signature::from_bytes(&raw),
        )
        .map_err(|_| SealedTransferError::Wire("claim_signature does not verify".into()))
    }

    /// Decode the embedded `did:key` back to its raw 32-byte Ed25519 public key.
    pub fn decode_client_ed25519_pub(&self) -> Result<[u8; 32], SealedTransferError> {
        affinidi_crypto::did_key::did_key_to_ed25519_pub(&self.client_did)
            .map_err(|e| SealedTransferError::Wire(format!("client_did: {e}")))
    }

    /// Decode the embedded `did:key` and derive the X25519 public key used as
    /// the HPKE recipient. Producers should call this rather than working
    /// with the Ed25519 pubkey directly.
    pub fn decode_client_x25519_pub(&self) -> Result<[u8; 32], SealedTransferError> {
        let ed = self.decode_client_ed25519_pub()?;
        affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed)
            .map_err(|e| SealedTransferError::Wire(format!("client_did X25519 derivation: {e}")))
    }

    /// Decode the embedded nonce.
    pub fn decode_nonce(&self) -> Result<[u8; 16], SealedTransferError> {
        let raw = BASE64
            .decode(&self.nonce)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
        raw.try_into()
            .map_err(|_| SealedTransferError::Wire("nonce must be 16 bytes".into()))
    }
}
