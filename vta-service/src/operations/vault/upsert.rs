//! `vault/upsert/0.1` secret-unsealing — the DIDComm-authcrypt crypto behind
//! the upsert path (P2.4).
//!
//! Moved out of `routes/trust_tasks/vault.rs` so the last bit of secret-bearing
//! crypto leaves the route layer. The route still owns the envelope-variant
//! check (it knows the `SealedEnvelope` wire shape) and the entry merge/store;
//! this unpacks the JWE, cross-checks the authcrypt sender against the
//! authenticated caller, and deserialises the cleartext as a `VaultSecret`.

use affinidi_tdk::messaging::ATM;

use vti_common::vault::VaultSecret;

/// Why unsealing a `didcomm-authcrypt` sealed secret failed. The route maps
/// each onto the canonical `vault/upsert:sealed_secret_invalid` reject (sender
/// mismatch is `permission_denied`).
pub enum UnsealError {
    /// The ATM failed to unpack the JWE.
    UnpackFailed(String),
    /// The unpacked message carries no `from` (sender).
    MissingSender,
    /// The authcrypt sender DID is not the authenticated caller — stops an
    /// attacker relaying someone else's pre-signed seal through their session.
    SenderMismatch { sender: String, caller: String },
    /// The cleartext body is not a `VaultSecret`.
    CleartextInvalid(String),
}

/// Unpack a `didcomm-authcrypt` JWE, verify the sender is `caller_did`, and
/// return the enclosed `VaultSecret`.
///
/// The route has already established that the envelope is the
/// `didcomm-authcrypt` variant and that an ATM is configured.
pub async fn unseal_secret(
    atm: &ATM,
    caller_did: &str,
    jwe: &str,
) -> Result<VaultSecret, UnsealError> {
    let (msg, _metadata) = atm
        .unpack(jwe)
        .await
        .map_err(|e| UnsealError::UnpackFailed(e.to_string()))?;

    // Cross-check: the authcrypt sender's DID must equal the authenticated
    // caller.
    let sender = msg
        .from
        .as_deref()
        .map(|s| s.split('#').next().unwrap_or(s).to_string())
        .ok_or(UnsealError::MissingSender)?;
    if sender != caller_did {
        return Err(UnsealError::SenderMismatch {
            sender,
            caller: caller_did.to_string(),
        });
    }

    serde_json::from_value(msg.body).map_err(|e| UnsealError::CleartextInvalid(e.to_string()))
}
