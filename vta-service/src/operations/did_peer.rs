//! Shared, method-pure `did:peer:2` construction.
//!
//! A `did:peer:2` is self-contained: its keys and service endpoints are
//! encoded in the identifier itself, so it resolves locally with no hosting,
//! no `did.jsonl`, and no publish step. This module owns the *one* place
//! where the DID gets minted from an Ed25519 signing key + an X25519
//! key-agreement key + a set of services, so both consumers share the exact
//! same encoding:
//!
//! - the offline operator CLI (`vta create-did-peer`, in the binary's
//!   `did_peer` module) — builds a mediator-*URL*-style DIDComm service;
//! - the online provision-integration flow
//!   ([`crate::operations::provision_integration`]) — builds a mediator-*DID*
//!   -style DIDComm service, matching how the built-in `ai-agent` did:webvh
//!   template advertises DIDComm (`serviceEndpoint` = `MEDIATOR_DID`) so a
//!   minted did:peer agent reaches the VTA over the mediator identically.
//!
//! The key shape is fixed: `#key-1` is the Ed25519 verification key
//! (authentication + assertion), `#key-2` is the X25519 key-agreement key
//! (authcrypt + sealed-transfer). This mirrors the mediator-setup generator
//! and the byte-for-byte behaviour of the existing offline CLI.

use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use affinidi_tdk::secrets_resolver::secrets::Secret;

use vta_sdk::did_secrets::SecretEntry;
use vta_sdk::sealed_transfer::template_bootstrap::{DidKeyMaterial, KeyPair};

/// Errors from the shared did:peer construction / secret-mapping helpers.
#[derive(Debug, thiserror::Error)]
pub enum DidPeerError {
    #[error("failed to generate did:peer: {0}")]
    Generate(String),
    #[error("failed to encode key material for {key_id}: {source}")]
    Encode {
        key_id: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("unexpected key type {key_type:?} in generated did:peer secret {key_id}")]
    UnexpectedKeyType {
        key_id: String,
        key_type: affinidi_tdk::secrets_resolver::secrets::KeyType,
    },
    #[error(
        "generated did:peer produced {found} secrets, expected 2 (Ed25519 #key-1 + X25519 #key-2)"
    )]
    SecretCount { found: usize },
    #[error("generated did:peer has no {role} secret ({key_type:?})")]
    MissingKey {
        role: &'static str,
        key_type: vta_sdk::keys::KeyType,
    },
}

/// Fixed `did:peer:2` key shape: an Ed25519 verification key followed by an
/// X25519 encryption key. The two secrets returned by
/// [`DID::generate_did_peer_with_services`] land at `#key-1` / `#key-2`
/// respectively.
fn peer_key_shape() -> Vec<(PeerKeyRole, KeyType)> {
    vec![
        (PeerKeyRole::Verification, KeyType::Ed25519),
        (PeerKeyRole::Encryption, KeyType::X25519),
    ]
}

/// Mint a self-contained `did:peer:2` from freshly-generated keys plus the
/// supplied service entries. Returns the DID string and its secrets
/// (`#key-1` Ed25519, `#key-2` X25519).
///
/// The VTA mints the key material here — callers never supply private keys.
/// This is the single shared construction point: the offline CLI and the
/// online provision path both call it, differing only in the `services`
/// they pass.
pub fn mint_did_peer_with_services(
    services: Vec<PeerService>,
) -> Result<(String, Vec<Secret>), DidPeerError> {
    DID::generate_did_peer_with_services(peer_key_shape(), Some(services))
        .map_err(|e| DidPeerError::Generate(e.to_string()))
}

/// Build the DIDComm service for a did:peer agent that routes through a
/// mediator identified by its *DID* — matching how the built-in `ai-agent`
/// did:webvh template advertises `DIDCommMessaging` (`serviceEndpoint.uri` =
/// `MEDIATOR_DID`). A minted did:peer agent then connects to the VTA over the
/// mediator exactly like a did:webvh agent does; `AgentSession` reads the
/// mediator DID from this service and dials through it.
///
/// The service `type` is `DIDCommMessaging` (the DID document is authoritative
/// for which protocols a party speaks — matched on `type`, per the workspace
/// transport rules), carried as a single long-form endpoint.
pub fn mediator_did_didcomm_service(
    mediator_did: &str,
    accept: Vec<String>,
    routing_keys: Vec<String>,
) -> Vec<PeerService> {
    vec![PeerService {
        type_: "DIDCommMessaging".into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: mediator_did.to_string(),
            accept,
            routing_keys,
        })),
        id: None,
    }]
}

/// Map a TDK [`Secret`]'s key type onto the SDK [`vta_sdk::keys::KeyType`],
/// rejecting anything other than the Ed25519 / X25519 the did:peer key shape
/// produces.
fn sdk_key_type(secret: &Secret) -> Result<vta_sdk::keys::KeyType, DidPeerError> {
    match secret.get_key_type() {
        affinidi_tdk::secrets_resolver::secrets::KeyType::Ed25519 => {
            Ok(vta_sdk::keys::KeyType::Ed25519)
        }
        affinidi_tdk::secrets_resolver::secrets::KeyType::X25519 => {
            Ok(vta_sdk::keys::KeyType::X25519)
        }
        other => Err(DidPeerError::UnexpectedKeyType {
            key_id: secret.id.clone(),
            key_type: other,
        }),
    }
}

/// Convert generated did:peer secrets into [`SecretEntry`] values for a
/// [`vta_sdk::did_secrets::DidSecretsBundle`] (the offline CLI export shape).
pub fn peer_secrets_to_entries(secrets: &[Secret]) -> Result<Vec<SecretEntry>, DidPeerError> {
    let mut entries = Vec::with_capacity(secrets.len());
    for s in secrets {
        let key_type = sdk_key_type(s)?;
        entries.push(SecretEntry {
            key_id: s.id.clone(),
            key_type,
            private_key_multibase: s.get_private_keymultibase().map_err(|e| {
                DidPeerError::Encode {
                    key_id: s.id.clone(),
                    source: Box::new(e),
                }
            })?,
        });
    }
    Ok(entries)
}

/// Convert generated did:peer secrets into the sealed-bundle
/// [`DidKeyMaterial`] shape a did:webvh / did:key agent gets — a single DID
/// with a signing (Ed25519) keypair and a key-agreement (X25519) keypair, so
/// an unchanged consumer opening the bundle with the ephemeral holder key
/// works for both methods.
///
/// The key ids are the secrets' own ids (`{did}#key-1` / `#key-2`), which
/// equal the verification-method ids in the resolved did:peer document.
pub fn peer_secrets_to_did_key_material(
    did: &str,
    secrets: &[Secret],
) -> Result<DidKeyMaterial, DidPeerError> {
    if secrets.len() != 2 {
        return Err(DidPeerError::SecretCount {
            found: secrets.len(),
        });
    }
    let mut signing: Option<KeyPair> = None;
    let mut key_agreement: Option<KeyPair> = None;
    for s in secrets {
        let key_type = sdk_key_type(s)?;
        let public_key_multibase =
            s.get_public_keymultibase()
                .map_err(|e| DidPeerError::Encode {
                    key_id: s.id.clone(),
                    source: Box::new(e),
                })?;
        let private_key_multibase =
            s.get_private_keymultibase()
                .map_err(|e| DidPeerError::Encode {
                    key_id: s.id.clone(),
                    source: Box::new(e),
                })?;
        let kp = KeyPair {
            key_id: s.id.clone(),
            public_key_multibase,
            private_key_multibase,
        };
        match key_type {
            vta_sdk::keys::KeyType::Ed25519 => signing = Some(kp),
            vta_sdk::keys::KeyType::X25519 => key_agreement = Some(kp),
            _ => {
                return Err(DidPeerError::UnexpectedKeyType {
                    key_id: s.id.clone(),
                    key_type: s.get_key_type(),
                });
            }
        }
    }
    Ok(DidKeyMaterial {
        did: did.to_string(),
        signing_key: signing.ok_or(DidPeerError::MissingKey {
            role: "signing",
            key_type: vta_sdk::keys::KeyType::Ed25519,
        })?,
        ka_key: key_agreement.ok_or(DidPeerError::MissingKey {
            role: "key-agreement",
            key_type: vta_sdk::keys::KeyType::X25519,
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_with_mediator_did_service_yields_peer2_and_two_keys() {
        let services = mediator_did_didcomm_service(
            "did:peer:2.Ezmediator.Vzmediator",
            vec!["didcomm/v2".into()],
            vec![],
        );
        let (did, secrets) = mint_did_peer_with_services(services).expect("mint did:peer");
        assert!(did.starts_with("did:peer:2"), "got {did}");
        assert_eq!(secrets.len(), 2);

        let material = peer_secrets_to_did_key_material(&did, &secrets).expect("material");
        assert_eq!(material.did, did);
        assert!(material.signing_key.key_id.contains("#key-1"));
        assert!(!material.signing_key.public_key_multibase.is_empty());
        assert!(!material.signing_key.private_key_multibase.is_empty());
        assert!(material.ka_key.key_id.contains("#key-2"));
        assert!(!material.ka_key.public_key_multibase.is_empty());
        assert!(!material.ka_key.private_key_multibase.is_empty());
    }

    #[test]
    fn secrets_map_to_entries_ed25519_then_x25519() {
        let services = mediator_did_didcomm_service(
            "did:peer:2.Ezmediator",
            vec!["didcomm/v2".into()],
            vec![],
        );
        let (_did, secrets) = mint_did_peer_with_services(services).expect("mint did:peer");
        let entries = peer_secrets_to_entries(&secrets).expect("entries");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].key_id.contains("#key-1"));
        assert_eq!(entries[0].key_type, vta_sdk::keys::KeyType::Ed25519);
        assert!(!entries[0].private_key_multibase.is_empty());
        assert!(entries[1].key_id.contains("#key-2"));
        assert_eq!(entries[1].key_type, vta_sdk::keys::KeyType::X25519);
        assert!(!entries[1].private_key_multibase.is_empty());
    }
}
