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
        }
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
