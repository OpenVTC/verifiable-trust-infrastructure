//! DIDComm pack / unpack — wraps `affinidi-messaging-didcomm`.
//!
//! **Slice 3b.** A stateful [`DidcommSession`] bound to one holder identity:
//! `unpack` (decrypt/verify inbound) and `pack_authcrypt` (sender-authenticated
//! encrypt outbound). The native layer owns the mediator WebSocket and hands
//! raw envelope bytes here.
//!
//! ## Custody (Tier-2, interim)
//!
//! Per the Mobile Key-Custody Profile, DIDComm needs the holder's **X25519**
//! key for ECDH, which mobile secure hardware cannot hold. So the holder key is
//! **software-held**: native loads it from the keystore (biometric-gated) and
//! passes it at session construction; it lives in app memory while the session
//! is open. When the P-256/Tier-1 enabler lands, the key material moves behind
//! an enclave key-agreement callback **without changing this FFI surface**.

use std::sync::{Arc, Mutex};

use affinidi_messaging_didcomm::DIDCommAgent;
use affinidi_messaging_didcomm::Message;
// didcomm 0.15 moved the key-agreement types into `affinidi-crypto`.
use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_messaging_didcomm::identity::{Mediator, PrivateIdentity, ResolvedIdentity};
use affinidi_messaging_didcomm::message::unpack::UnpackResult;

use crate::error::FfiError;

/// Holder key material for a DIDComm session. **Tier-2 (software-held)** — see
/// the module docs. Native loads these from the keystore and SHOULD zeroize
/// them on session end.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HolderKeys {
    /// The holder DID (used as the authcrypt sender).
    pub did: String,
    /// keyAgreement verification-method id (DID URL fragment).
    pub key_agreement_kid: String,
    /// X25519 key-agreement private key (32 bytes).
    pub key_agreement_private_x25519: Vec<u8>,
    /// signing verification-method id.
    pub signing_kid: String,
    /// Ed25519 signing private key (32 bytes).
    pub signing_private_ed25519: Vec<u8>,
}

/// A resolved peer's public key-agreement key — e.g. from [`crate::resolver`].
/// Needed to authcrypt *to* the peer and to verify the peer's authcrypt.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Peer {
    pub did: String,
    pub key_agreement_kid: String,
    /// X25519 key-agreement public key (32 bytes).
    pub key_agreement_public_x25519: Vec<u8>,
}

/// The outcome of unpacking an inbound DIDComm message.
#[derive(Debug, Clone, uniffi::Record)]
pub struct UnpackedMessage {
    /// The plaintext DIDComm message as JSON (`type`/`body`/`from`/`to`/`id`/…).
    pub message_json: String,
    /// `true` when the message was authcrypt'd (sender-authenticated) or signed.
    /// `false` for anoncrypt and unauthenticated plaintext — do not trust
    /// `from` in that case.
    pub sender_authenticated: bool,
    /// The authenticated sender key id, when present.
    pub sender_kid: Option<String>,
}

/// A DIDComm session bound to one holder identity. Holds the library agent
/// (the holder identity + resolved peers). Thread-safe via an internal lock.
#[derive(uniffi::Object)]
pub struct DidcommSession {
    agent: Mutex<DIDCommAgent>,
    holder_did: String,
}

#[uniffi::export]
impl DidcommSession {
    /// Open a session for the holder, building its [`PrivateIdentity`] from the
    /// supplied (Tier-2, software-held) key material.
    #[uniffi::constructor]
    pub fn new(holder: HolderKeys) -> Result<Arc<Self>, FfiError> {
        let key_agreement_private = PrivateKeyAgreement::from_raw_bytes(
            Curve::X25519,
            &holder.key_agreement_private_x25519,
        )
        .map_err(|e| FfiError::InvalidInput {
            reason: format!("holder keyAgreement key: {e}"),
        })?;
        let signing_private = to_array_32(&holder.signing_private_ed25519, "holder signing key")?;

        let identity = PrivateIdentity {
            did: holder.did.clone(),
            key_agreement_kid: holder.key_agreement_kid,
            key_agreement_private,
            signing_kid: Some(holder.signing_kid),
            signing_private: Some(signing_private),
        };
        let mut agent = DIDCommAgent::new();
        agent.add_identity(identity);
        Ok(Arc::new(Self {
            agent: Mutex::new(agent),
            holder_did: holder.did,
        }))
    }

    /// Add a resolved peer (its key-agreement public key) so the session can
    /// authcrypt to it and verify its authcrypt.
    pub fn add_peer(&self, peer: Peer) -> Result<(), FfiError> {
        let key_agreement_public = PublicKeyAgreement::X25519(to_array_32(
            &peer.key_agreement_public_x25519,
            "peer keyAgreement key",
        )?);
        let resolved = ResolvedIdentity {
            did: peer.did,
            key_agreement_kid: peer.key_agreement_kid,
            key_agreement_public,
            signing_kid: None,
            verifying_key: None,
        };
        self.agent
            .lock()
            .expect("didcomm session lock")
            .add_peer(resolved);
        Ok(())
    }

    /// Decrypt/verify an inbound DIDComm message (authcrypt / anoncrypt / signed
    /// / plaintext). For authcrypt verification, pass the expected `sender_did`
    /// (which must have been added via [`add_peer`](Self::add_peer)).
    pub fn unpack(
        &self,
        packed: String,
        sender_did: Option<String>,
    ) -> Result<UnpackedMessage, FfiError> {
        let result = self
            .agent
            .lock()
            .expect("didcomm session lock")
            .unpack(&packed, sender_did.as_deref())
            .map_err(|e| FfiError::InvalidInput {
                reason: format!("unpack failed: {e}"),
            })?;

        let (message, sender_authenticated, sender_kid) = match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                sender_kid,
                ..
            } => (message, authenticated, sender_kid),
            UnpackResult::Signed {
                message,
                signer_kid,
            } => (message, true, signer_kid),
            UnpackResult::Plaintext(message) => (message, false, None),
            // `UnpackResult` is `#[non_exhaustive]` as of didcomm 0.14; reject
            // any variant this engine version doesn't recognise rather than
            // guess its authentication semantics.
            _ => {
                return Err(FfiError::InvalidInput {
                    reason: "unsupported DIDComm unpack result variant".to_string(),
                });
            }
        };

        Ok(UnpackedMessage {
            message_json: serde_json::to_string(&message).map_err(|e| FfiError::InvalidInput {
                reason: format!("serialize message: {e}"),
            })?,
            sender_authenticated,
            sender_kid,
        })
    }

    /// Authcrypt (sender-authenticated, encrypted) a plaintext DIDComm message
    /// JSON to `recipient_did` — which MUST have been added via
    /// [`add_peer`](Self::add_peer). Returns the JWE the native layer sends
    /// (typically wrapped in a `routing/2.0/forward` to the mediator).
    pub fn pack_authcrypt(
        &self,
        message_json: String,
        recipient_did: String,
    ) -> Result<String, FfiError> {
        let msg: Message = serde_json::from_str(&message_json).map_err(|e| FfiError::Decode {
            reason: format!("not a valid DIDComm message: {e}"),
        })?;
        self.agent
            .lock()
            .expect("didcomm session lock")
            .pack_authcrypt(&msg, &self.holder_did, &recipient_did)
            .map_err(|e| FfiError::InvalidInput {
                reason: format!("authcrypt failed: {e}"),
            })
    }

    /// Anoncrypt (encrypted, *not* sender-authenticated) a plaintext DIDComm
    /// message JSON to `recipient_did` (which MUST have been added via
    /// [`add_peer`](Self::add_peer)). Use when the sender should stay anonymous
    /// to the recipient.
    pub fn pack_anoncrypt(
        &self,
        message_json: String,
        recipient_did: String,
    ) -> Result<String, FfiError> {
        let msg: Message = serde_json::from_str(&message_json).map_err(|e| FfiError::Decode {
            reason: format!("not a valid DIDComm message: {e}"),
        })?;
        self.agent
            .lock()
            .expect("didcomm session lock")
            .pack_anoncrypt(&msg, &recipient_did)
            .map_err(|e| FfiError::InvalidInput {
                reason: format!("anoncrypt failed: {e}"),
            })
    }

    /// Register a mediator route for `recipient_did`. Once set, `pack_authcrypt`
    /// / `pack_anoncrypt` to that recipient are automatically wrapped in a
    /// `routing/2.0/forward` anoncrypt'd to the mediator — which is how the
    /// mobile agent delivers to a peer that is only reachable via its mediator.
    /// `mediator` carries the mediator's resolved key-agreement key.
    pub fn add_route(&self, recipient_did: String, mediator: Peer) -> Result<(), FfiError> {
        let key_agreement_public = PublicKeyAgreement::X25519(to_array_32(
            &mediator.key_agreement_public_x25519,
            "mediator keyAgreement key",
        )?);
        let route = Mediator {
            did: mediator.did,
            key_agreement_kid: mediator.key_agreement_kid,
            key_agreement_public,
        };
        self.agent
            .lock()
            .expect("didcomm session lock")
            .store_mut()
            .add_route(recipient_did, route);
        Ok(())
    }
}

fn to_array_32(bytes: &[u8], what: &str) -> Result<[u8; 32], FfiError> {
    bytes.try_into().map_err(|_| FfiError::InvalidInput {
        reason: format!("{what} must be 32 bytes, got {}", bytes.len()),
    })
}

/// Derive the DIDComm [`HolderKeys`] for an Ed25519 `did:key` holder from its
/// signing seed, so the native layer can open a [`DidcommSession`] without
/// re-implementing key derivation.
///
/// The key-agreement (X25519) key is the **standard ed25519→x25519 conversion**
/// of the holder signing key, so its public half equals the `keyAgreement` a
/// resolver derives from the `did:key`. That means anyone resolving the holder
/// did:key (e.g. a VTA wanting to send an approve-request) can authcrypt to it,
/// and this session — holding the matching private — can unpack it.
///
/// No new cryptography here: this composes the tested TDK conversions
/// (`affinidi_crypto::ed25519::{ed25519_private_to_x25519, ed25519_public_to_x25519}`),
/// per the workspace "Default to DIDs" guidance. `signing_private_ed25519` is
/// the 32-byte Ed25519 seed; it never leaves the device beyond this struct.
#[uniffi::export]
pub fn didcomm_holder_keys(
    did: String,
    signing_private_ed25519: Vec<u8>,
) -> Result<HolderKeys, FfiError> {
    let ed_multikey = did
        .strip_prefix("did:key:")
        .ok_or_else(|| FfiError::InvalidInput {
            reason: format!("expected a did:key, got {did}"),
        })?;
    let signing = to_array_32(&signing_private_ed25519, "holder signing key")?;

    // ed25519 secret → x25519 secret (key agreement private half).
    let key_agreement_private = affinidi_crypto::ed25519::ed25519_private_to_x25519(&signing);
    // ed25519 did:key multikey → x25519 multikey (the keyAgreement vm fragment).
    let (x25519_multikey, _x25519_public) =
        affinidi_crypto::ed25519::ed25519_public_to_x25519(ed_multikey).map_err(|e| {
            FfiError::InvalidInput {
                reason: format!("derive x25519 key agreement from did:key: {e}"),
            }
        })?;

    Ok(HolderKeys {
        did: did.clone(),
        key_agreement_kid: format!("{did}#{x25519_multikey}"),
        key_agreement_private_x25519: key_agreement_private.to_vec(),
        signing_kid: format!("{did}#{ed_multikey}"),
        signing_private_ed25519,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Derive the X25519 public key for a raw private scalar via the library
    // (no extra dependency).
    fn x25519_public(private_32: &[u8]) -> Vec<u8> {
        let sk = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, private_32).unwrap();
        match sk.public_key() {
            PublicKeyAgreement::X25519(p) => p.to_vec(),
            _ => unreachable!("constructed as X25519"),
        }
    }

    fn holder(did: &str, ka_priv: [u8; 32], sign_priv: [u8; 32]) -> HolderKeys {
        HolderKeys {
            did: did.to_string(),
            key_agreement_kid: format!("{did}#key-agreement"),
            key_agreement_private_x25519: ka_priv.to_vec(),
            signing_kid: format!("{did}#signing"),
            signing_private_ed25519: sign_priv.to_vec(),
        }
    }

    fn peer(did: &str, ka_priv: [u8; 32]) -> Peer {
        Peer {
            did: did.to_string(),
            key_agreement_kid: format!("{did}#key-agreement"),
            key_agreement_public_x25519: x25519_public(&ka_priv),
        }
    }

    #[test]
    fn authcrypt_round_trip_between_two_sessions() {
        let alice_ka = [1u8; 32];
        let alice_sign = [2u8; 32];
        let bob_ka = [3u8; 32];
        let bob_sign = [4u8; 32];
        let alice_did = "did:example:alice";
        let bob_did = "did:example:bob";

        let alice = DidcommSession::new(holder(alice_did, alice_ka, alice_sign)).unwrap();
        alice.add_peer(peer(bob_did, bob_ka)).unwrap();
        let bob = DidcommSession::new(holder(bob_did, bob_ka, bob_sign)).unwrap();
        bob.add_peer(peer(alice_did, alice_ka)).unwrap();

        let msg = serde_json::json!({
            "id": "m-1",
            "type": "https://didcomm.org/basicmessage/2.0/message",
            "from": alice_did,
            "to": [bob_did],
            "body": { "content": "hello bob" }
        })
        .to_string();

        let jwe = alice.pack_authcrypt(msg, bob_did.to_string()).unwrap();
        // It's an encrypted envelope, not plaintext.
        assert!(jwe.contains("ciphertext"));

        let unpacked = bob.unpack(jwe, Some(alice_did.to_string())).unwrap();
        assert!(
            unpacked.sender_authenticated,
            "authcrypt is sender-authenticated"
        );
        let m: serde_json::Value = serde_json::from_str(&unpacked.message_json).unwrap();
        assert_eq!(m["body"]["content"], "hello bob");
        assert_eq!(m["from"], alice_did);
    }

    #[test]
    fn rejects_bad_holder_key_length() {
        let mut h = holder("did:example:x", [1u8; 32], [2u8; 32]);
        h.key_agreement_private_x25519 = vec![0u8; 16]; // wrong length
        // (DidcommSession isn't Debug — it holds key material — so match instead
        // of unwrap_err.)
        assert!(matches!(
            DidcommSession::new(h),
            Err(FfiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn anoncrypt_round_trip_is_not_sender_authenticated() {
        let a = "did:example:a2";
        let b = "did:example:b2";
        let b_ka = [7u8; 32];
        let alice = DidcommSession::new(holder(a, [5u8; 32], [6u8; 32])).unwrap();
        alice.add_peer(peer(b, b_ka)).unwrap();
        let bob = DidcommSession::new(holder(b, b_ka, [8u8; 32])).unwrap();

        let msg = serde_json::json!({
            "id": "m", "type": "https://didcomm.org/basicmessage/2.0/message",
            "to": [b], "body": { "content": "anon" }
        })
        .to_string();
        let jwe = alice.pack_anoncrypt(msg, b.to_string()).unwrap();
        let unpacked = bob.unpack(jwe, None).unwrap();
        assert!(
            !unpacked.sender_authenticated,
            "anoncrypt must not be sender-authenticated"
        );
        let m: serde_json::Value = serde_json::from_str(&unpacked.message_json).unwrap();
        assert_eq!(m["body"]["content"], "anon");
    }

    #[test]
    fn authcrypt_with_route_wraps_in_forward_for_the_mediator() {
        let a = "did:example:alice3";
        let b = "did:example:bob3";
        let med = "did:example:mediator3";
        let med_ka = [13u8; 32];

        let alice = DidcommSession::new(holder(a, [9u8; 32], [10u8; 32])).unwrap();
        alice.add_peer(peer(b, [11u8; 32])).unwrap(); // inner authcrypt → bob
        alice.add_route(b.to_string(), peer(med, med_ka)).unwrap(); // outer forward → mediator
        let mediator = DidcommSession::new(holder(med, med_ka, [14u8; 32])).unwrap();

        let msg = serde_json::json!({
            "id": "m", "type": "https://didcomm.org/basicmessage/2.0/message",
            "from": a, "to": [b], "body": { "content": "hi" }
        })
        .to_string();
        let outer = alice.pack_authcrypt(msg, b.to_string()).unwrap();

        // The mediator opens the OUTER (anoncrypt) envelope; it's a forward.
        let at_mediator = mediator.unpack(outer, None).unwrap();
        let fwd: serde_json::Value = serde_json::from_str(&at_mediator.message_json).unwrap();
        assert_eq!(fwd["type"], "https://didcomm.org/routing/2.0/forward");
    }

    /// did:key from a fixed Ed25519 seed.
    fn did_key_from_seed(seed: &[u8; 32]) -> String {
        let pk = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&pk)
    }

    #[test]
    fn didcomm_holder_keys_match_the_did_key_key_agreement() {
        let seed = [7u8; 32];
        let did = did_key_from_seed(&seed);
        let keys = didcomm_holder_keys(did.clone(), seed.to_vec()).unwrap();

        // The crucial invariant: the public half of the derived X25519 private
        // equals the keyAgreement a resolver derives from the did:key — so a
        // sender resolving the did:key authcrypts to a key THIS session can open.
        let ed_multikey = did.strip_prefix("did:key:").unwrap();
        let (x25519_multikey, ka_public_from_did) =
            affinidi_crypto::ed25519::ed25519_public_to_x25519(ed_multikey).unwrap();
        assert_eq!(
            x25519_public(&keys.key_agreement_private_x25519),
            ka_public_from_did,
            "derived agreement key must be reachable at the holder did:key",
        );
        // Kid shapes: `<did>#<x25519-multikey>` and `<did>#<ed25519-multikey>`.
        assert_eq!(keys.key_agreement_kid, format!("{did}#{x25519_multikey}"));
        assert_eq!(keys.signing_kid, format!("{did}#{ed_multikey}"));
        assert_eq!(keys.signing_private_ed25519, seed.to_vec());
    }

    #[test]
    fn derived_holders_authcrypt_round_trip() {
        let alice_did = did_key_from_seed(&[7u8; 32]);
        let bob_did = did_key_from_seed(&[9u8; 32]);
        let alice_keys = didcomm_holder_keys(alice_did.clone(), [7u8; 32].to_vec()).unwrap();
        let bob_keys = didcomm_holder_keys(bob_did.clone(), [9u8; 32].to_vec()).unwrap();

        let peer_of = |k: &HolderKeys| Peer {
            did: k.did.clone(),
            key_agreement_kid: k.key_agreement_kid.clone(),
            key_agreement_public_x25519: x25519_public(&k.key_agreement_private_x25519),
        };

        let alice = DidcommSession::new(alice_keys.clone()).unwrap();
        alice.add_peer(peer_of(&bob_keys)).unwrap();
        let bob = DidcommSession::new(bob_keys.clone()).unwrap();
        bob.add_peer(peer_of(&alice_keys)).unwrap();

        let msg = serde_json::json!({
            "id": "m-stepup",
            "type": "https://trusttasks.org/spec/auth/step-up/approve-request/0.1",
            "from": alice_did,
            "to": [bob_did],
            "body": { "challenge": "abc" }
        })
        .to_string();

        let jwe = alice.pack_authcrypt(msg, bob_did.clone()).unwrap();
        let unpacked = bob.unpack(jwe, Some(alice_did.clone())).unwrap();
        assert!(unpacked.sender_authenticated);
        let m: serde_json::Value = serde_json::from_str(&unpacked.message_json).unwrap();
        assert_eq!(m["from"], alice_did);
        assert_eq!(m["body"]["challenge"], "abc");
    }
}
