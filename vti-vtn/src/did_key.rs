//! `did:key` for Ed25519, the development identity of a network or test member.
//!
//! **Assumption A5**: a production VTN is provisioned on a VTA and takes its `did:webvh`
//! from it (VTI-VTN-001). Until that integration lands, the service runs on a `did:key`
//! derived from a configured seed. `did:key` resolves with no prior relationship, so
//! VTI-VTN-003 still holds.

use crate::error::{Result, VtnError};

const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// `did:key:z6Mk…` for an Ed25519 public key.
pub fn did_from_ed25519(public_key: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&ED25519_PUB_MULTICODEC);
    bytes.extend_from_slice(public_key);
    format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, bytes)
    )
}

/// The verification method of a `did:key`: `did:key:z…#z…`.
pub fn verification_method(did: &str) -> Result<String> {
    let fragment = did
        .strip_prefix("did:key:")
        .ok_or_else(|| VtnError::InvalidDid(did.to_string()))?;
    Ok(format!("{did}#{fragment}"))
}

/// The DID part of a verification method URI.
pub fn did_of_verification_method(vm: &str) -> &str {
    vm.split_once('#').map_or(vm, |(did, _)| did)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_data_integrity_resolver() {
        let public = [7u8; 32];
        let did = did_from_ed25519(&public);
        assert!(did.starts_with("did:key:z6Mk"));
        let vm = verification_method(&did).unwrap();
        let resolved = affinidi_data_integrity::did_vm::resolve_did_key(&vm).unwrap();
        assert_eq!(resolved.public_key_bytes, public);
        assert_eq!(did_of_verification_method(&vm), did);
    }
}
