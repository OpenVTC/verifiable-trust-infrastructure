//! `vta/contexts/secrets/1.0` — the private keys of a context's own DID.

use serde::{Deserialize, Serialize};

use crate::did_secrets::{DidSecretsBundle, SecretEntry};
use crate::keys::KeyType;

/// Ask for the secrets of a context's DID.
///
/// One request for the whole bundle rather than one per key, which is what a
/// caller assembling a [`DidSecretsBundle`] actually wants — and it makes the
/// authorization one decision about one context instead of N decisions about
/// keys that happen to belong to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContextSecretsBody {
    /// The context whose DID's keys are wanted. The caller must be able to act
    /// in it; being able to act in a *different* one confers nothing here.
    ///
    /// Named `id` rather than `context_id` to match the rest of the
    /// `vta/contexts/*` family, where `id` always names the context being
    /// acted on. The spec settles it.
    pub id: String,
}

/// What the VTA answers with: the context's DID and the keys behind it.
///
/// A wire type of its own rather than [`DidSecretsBundle`] directly, because
/// the two are not the same thing. `DidSecretsBundle` is the *internal and
/// on-disk* form — snake_case, shared with `sealed_transfer` and with operator
/// exports that already exist on disk — and `vta/contexts/secrets/1.0`
/// specifies lowerCamelCase members, as SPEC §4.10 requires of every Trust
/// Task. Renaming the existing type would rewrite a format that has already
/// been written to disk to fix a format that has never been on the wire.
///
/// [`From`] in both directions keeps them from drifting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextSecretsResultBody {
    /// The DID the secrets belong to — the one recorded on the context, not
    /// one the caller asked for.
    pub did: String,
    /// One entry per verification method of `did` whose secret is releasable.
    ///
    /// May be empty, and that is not an error: a context whose DID has no
    /// releasable key material is a context that is not provisioned yet.
    pub secrets: Vec<ContextSecretEntry>,
}

/// One private key, named by the verification method it backs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextSecretEntry {
    /// The verification method this key backs, as an absolute DID URL under
    /// the bundle's `did`. It is the DID document that decides this name, so a
    /// consumer installs the key under a kid an inbound message will match.
    pub key_id: String,
    /// What the key is for. Also encoded in `private_key_multibase`'s
    /// multicodec prefix; stated separately so a caller can select by purpose
    /// without decoding every entry.
    pub key_type: KeyType,
    /// The private key, multibase (Base58BTC) over multicodec-prefixed bytes.
    pub private_key_multibase: String,
}

impl From<SecretEntry> for ContextSecretEntry {
    fn from(e: SecretEntry) -> Self {
        Self {
            key_id: e.key_id,
            key_type: e.key_type,
            private_key_multibase: e.private_key_multibase,
        }
    }
}

impl From<ContextSecretEntry> for SecretEntry {
    fn from(e: ContextSecretEntry) -> Self {
        Self {
            key_id: e.key_id,
            key_type: e.key_type,
            private_key_multibase: e.private_key_multibase,
        }
    }
}

impl From<DidSecretsBundle> for ContextSecretsResultBody {
    fn from(b: DidSecretsBundle) -> Self {
        Self {
            did: b.did,
            secrets: b.secrets.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<ContextSecretsResultBody> for DidSecretsBundle {
    fn from(b: ContextSecretsResultBody) -> Self {
        Self {
            did: b.did,
            secrets: b.secrets.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this type exists at all: the wire form is lowerCamelCase
    /// where the on-disk form is snake_case. If someone "simplifies" this
    /// module away by serialising `DidSecretsBundle` directly, this fails.
    #[test]
    fn the_wire_form_is_lower_camel_case() {
        let body = ContextSecretsResultBody {
            did: "did:webvh:QmExample:example.com:rooms:host-1".into(),
            secrets: vec![ContextSecretEntry {
                key_id: "did:webvh:QmExample:example.com:rooms:host-1#key-0".into(),
                key_type: KeyType::Ed25519,
                private_key_multibase: "z3u2en7t5LR2WtQH5PfFqMqtVcSdd7ELrcFtnP63HKq4KLg".into(),
            }],
        };
        let json = serde_json::to_value(&body).unwrap();
        let entry = &json["secrets"][0];
        assert!(entry.get("keyId").is_some(), "expected keyId, got {entry}");
        assert!(entry.get("keyType").is_some());
        assert!(entry.get("privateKeyMultibase").is_some());
        assert!(
            entry.get("key_id").is_none(),
            "snake_case members must not appear on the wire"
        );
        assert_eq!(entry["keyType"], "ed25519");
    }

    /// The two forms carry the same information, so a round trip through the
    /// wire type must not lose or alter any of it.
    #[test]
    fn a_bundle_round_trips_through_the_wire_form() {
        let bundle = DidSecretsBundle {
            did: "did:webvh:QmExample:example.com:rooms:host-1".into(),
            secrets: vec![
                SecretEntry {
                    key_id: "did:webvh:QmExample:example.com:rooms:host-1#key-0".into(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "zSigning".into(),
                },
                SecretEntry {
                    key_id: "did:webvh:QmExample:example.com:rooms:host-1#key-1".into(),
                    key_type: KeyType::X25519,
                    private_key_multibase: "zAgreement".into(),
                },
            ],
        };
        let back: DidSecretsBundle = ContextSecretsResultBody::from(bundle.clone()).into();
        assert_eq!(back.did, bundle.did);
        assert_eq!(back.secrets.len(), 2);
        for (a, b) in back.secrets.iter().zip(&bundle.secrets) {
            assert_eq!(a.key_id, b.key_id);
            assert_eq!(a.key_type, b.key_type);
            assert_eq!(a.private_key_multibase, b.private_key_multibase);
        }
    }

    /// An empty bundle is a provisioning state, not a failure, and must
    /// survive the conversion as an empty array rather than becoming absent.
    #[test]
    fn an_empty_bundle_stays_an_empty_array() {
        let body = ContextSecretsResultBody::from(DidSecretsBundle {
            did: "did:example:123".into(),
            secrets: vec![],
        });
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["secrets"], serde_json::json!([]));
    }
}
