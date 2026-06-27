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

/// Unpack a `tsp-message` sealed secret via TSP, verify the sender VID is
/// `caller_did`, and return the enclosed `VaultSecret`.
///
/// Mirrors [`unseal_secret`] (the DIDComm-authcrypt path) exactly, adapted for
/// TSP: `atm.tsp().unpack` returns `(payload_bytes, sender_vid)` rather than a
/// DIDComm message, so the cleartext is deserialised from the raw payload bytes
/// and the sender cross-check is against the returned VID (with any `#fragment`
/// stripped) instead of `msg.from`.
///
/// The route has already established that the envelope is the `tsp-message`
/// variant, that an ATM is configured, and that a TSP profile is registered.
///
/// NOTE: every error arm except `UnpackFailed` (`SenderMismatch`,
/// `CleartextInvalid`) is only reachable *after* a successful
/// `atm.tsp().unpack`, which requires a real TSP-sealed message (a sender VID,
/// the recipient's keys, and a mediator-fetched envelope). That path is not
/// unit-testable without live crypto and needs runtime verification against a
/// real TSP message; the route-level configuration gate (the "TSP not
/// configured" reject) is covered by a unit test in `trust_tasks::vault`.
#[cfg(feature = "tsp")]
pub async fn unseal_tsp_secret(
    atm: &ATM,
    profile: &std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    caller_did: &str,
    message: &str,
) -> Result<VaultSecret, UnsealError> {
    let (payload, sender_vid) = atm
        .tsp()
        .unpack(profile, message)
        .await
        .map_err(|e| UnsealError::UnpackFailed(e.to_string()))?;

    // Cross-check: the TSP sender's VID must equal the authenticated caller.
    // Strip any `#fragment` so a fragmented VID still matches the bare DID.
    let sender = sender_vid
        .split('#')
        .next()
        .unwrap_or(&sender_vid)
        .to_string();
    if sender != caller_did {
        return Err(UnsealError::SenderMismatch {
            sender,
            caller: caller_did.to_string(),
        });
    }

    serde_json::from_slice(&payload).map_err(|e| UnsealError::CleartextInvalid(e.to_string()))
}
