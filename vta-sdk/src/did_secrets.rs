use serde::{Deserialize, Serialize};

use crate::keys::KeyType;

/// A portable bundle of DID secrets for import/export.
///
/// Post-Phase-5 the canonical transport is [`crate::sealed_transfer`]
/// (`SealedPayloadV1::DidSecrets`). On-disk for local operator exports the
/// canonical form is pretty-printed JSON.
///
/// # Example — constructing secrets for DIDComm
///
/// Applications using `affinidi_tdk` can reconstruct `Secret` objects from the
/// entries in this bundle using `Secret::from_multibase()`, which handles all
/// key types (Ed25519, X25519, P-256) via their multicodec prefix:
///
/// ```ignore
/// use affinidi_tdk::secrets_resolver::secrets::Secret;
///
/// let bundle = client.fetch_did_secrets_bundle("my-context").await?;
/// for entry in &bundle.secrets {
///     let secret = Secret::from_multibase(
///         &entry.private_key_multibase,
///         Some(&entry.key_id),
///     )?;
///     resolver.insert(secret);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidSecretsBundle {
    /// The DID these secrets belong to.
    pub did: String,
    /// Secret entries (one per verification method).
    pub secrets: Vec<SecretEntry>,
}

/// A single secret entry within a [`DidSecretsBundle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Verification method ID (e.g. `did:webvh:...#key-0`).
    pub key_id: String,
    /// Key type — determines how to reconstruct the secret.
    pub key_type: KeyType,
    /// Multibase-encoded (Base58BTC) private key with multicodec prefix.
    ///
    /// The multicodec prefix identifies the key type:
    /// - Ed25519 private: `0x1300` — 32-byte Ed25519 seed
    /// - X25519 private: `0x1302` — 32-byte X25519 scalar (from `get_key_secret`)
    ///   or Ed25519 seed for conversion (from provisioning)
    /// - P256 private: `0x1306` — 32-byte P-256 scalar
    ///
    /// Compatible with `Secret::from_multibase()` for direct use in DIDComm.
    pub private_key_multibase: String,
}

/// Convert a [`GetKeySecretResponse`](crate::client::GetKeySecretResponse) into a [`SecretEntry`].
#[cfg(feature = "client")]
impl From<crate::client::GetKeySecretResponse> for SecretEntry {
    fn from(resp: crate::client::GetKeySecretResponse) -> Self {
        Self {
            key_id: resp.key_id,
            key_type: resp.key_type,
            private_key_multibase: resp.private_key_multibase,
        }
    }
}

/// Decide the verification-method id (kid) to publish for a context secret
/// in a [`DidSecretsBundle`], or `None` if the secret must be excluded.
///
/// The kid a VTA-managed mediator matches inbound JWE recipients against
/// must be a verification-method id of the bundle's DID (`{did}#...`).
/// Rules, in order:
///
/// 1. If the store's `record_key_id` is already a VM id of `did`, use it.
///    Every DID-operating-key flow stores exactly this
///    (`save_entity_key_records` → `{did}#key-0` / `#key-1`), so this is
///    the common path.
/// 2. Otherwise, if the human `label` is *itself* a strict VM id of `did`
///    (correct prefix, no embedded whitespace), adopt it. Covers generic
///    `/keys` records whose id defaulted to a derivation path while the
///    label carries the VM id.
/// 3. Otherwise the secret is not a verification method of this DID — an
///    admin `did:key` minted into the same context, or a free-text label
///    such as `"<did:key> signing key"`. Exclude it.
///
/// Rule 3 is the fix for the storm.ws outage (PR #337): the previous
/// logic adopted the label as the kid whenever it merely *started with*
/// `did:` or *contained* `#`, so a decorative label like
/// `"did:key:z6Mkr4J… signing key"` silently overwrote the correct
/// `{did}#key-1` kid. The mediator then found no local secret matching
/// the recipient kid published in its own DID document and failed every
/// unpack with `No local secret matches any JWE recipient`.
///
/// Shared between the online SDK path (`VtaClient::fetch_did_secrets_bundle`)
/// and the offline VTA-service path
/// (`vta_service::operations::export::build_did_secrets_bundle`) so the
/// two cannot drift.
pub fn select_secret_kid(did: &str, record_key_id: &str, label: Option<&str>) -> Option<String> {
    let vm_prefix = format!("{did}#");
    if record_key_id.starts_with(&vm_prefix) {
        return Some(record_key_id.to_string());
    }
    if let Some(label) = label
        && label.starts_with(&vm_prefix)
        && !label.chars().any(char::is_whitespace)
    {
        return Some(label.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json_roundtrip() {
        let bundle = DidSecretsBundle {
            did: "did:webvh:abc123:example.com".to_string(),
            secrets: vec![
                SecretEntry {
                    key_id: "did:webvh:abc123:example.com#key-0".to_string(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "z6Mk...signing".to_string(),
                },
                SecretEntry {
                    key_id: "did:webvh:abc123:example.com#key-1".to_string(),
                    key_type: KeyType::X25519,
                    private_key_multibase: "z6Mk...ka".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: DidSecretsBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.did, bundle.did);
        assert_eq!(decoded.secrets.len(), 2);
        assert_eq!(decoded.secrets[0].key_id, bundle.secrets[0].key_id);
        assert_eq!(decoded.secrets[0].key_type, KeyType::Ed25519);
        assert_eq!(
            decoded.secrets[0].private_key_multibase,
            bundle.secrets[0].private_key_multibase
        );
        assert_eq!(decoded.secrets[1].key_type, KeyType::X25519);
    }

    #[test]
    fn test_serde_json_empty_secrets() {
        let bundle = DidSecretsBundle {
            did: "did:example:123".to_string(),
            secrets: vec![],
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: DidSecretsBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.did, "did:example:123");
        assert!(decoded.secrets.is_empty());
    }

    // `select_secret_kid` lives in this module; its regression tests live
    // here alongside it (moved from `client::secrets`, where the function
    // used to be, in the WS-setup follow-up).
    const KID_DID: &str =
        "did:webvh:QmQjq4GHRH9fwSXCg4884kxpCMT5EUqHB9XY2U7aXisP8R:webvh.storm.ws:mediator-2";

    #[test]
    fn keeps_store_vm_id_and_ignores_decorative_label() {
        // The store key_id is already the canonical VM id; the label is
        // free text. The kid must be the VM id, regardless of label.
        let kid = select_secret_kid(
            KID_DID,
            &format!("{KID_DID}#key-0"),
            Some("did:key:z6Mkr4JCdsEVcQvYKxcyjf39tPmVriDfg3gALvqv4GQHc5BH signing key"),
        );
        assert_eq!(kid.as_deref(), Some(format!("{KID_DID}#key-0").as_str()));
    }

    #[test]
    fn regression_did_prefixed_label_must_not_clobber_key_id() {
        // Exact storm.ws failure mode: a `did:key:… key-agreement key`
        // label must NOT replace the correct `#key-1` kid. The old code
        // returned the label here, which is what bricked DIDComm unpack.
        let kid = select_secret_kid(
            KID_DID,
            &format!("{KID_DID}#key-1"),
            Some("did:key:z6Mkr4JCdsEVcQvYKxcyjf39tPmVriDfg3gALvqv4GQHc5BH key-agreement key"),
        );
        assert_eq!(kid.as_deref(), Some(format!("{KID_DID}#key-1").as_str()));
        assert!(!kid.as_deref().unwrap().contains(' '));
    }

    #[test]
    fn excludes_admin_did_key_minted_into_context() {
        // The admin credential's did:key shares the context tag but is a
        // different DID; its VM id does not belong in this DID's bundle.
        let admin = "did:key:z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf";
        let kid = select_secret_kid(
            KID_DID,
            &format!("{admin}#z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf"),
            Some("admin DID for context mediator-test"),
        );
        assert_eq!(kid, None);
    }

    #[test]
    fn adopts_label_when_it_is_a_strict_vm_id_and_record_id_is_not() {
        // Generic /keys record whose id defaulted to a derivation path,
        // with the real VM id carried in the label.
        let kid = select_secret_kid(KID_DID, "m/26'/2'/3'/4'", Some(&format!("{KID_DID}#key-1")));
        assert_eq!(kid.as_deref(), Some(format!("{KID_DID}#key-1").as_str()));
    }

    #[test]
    fn rejects_label_vm_id_with_trailing_free_text() {
        // A label that starts with the VM prefix but has trailing text is
        // not a VM id — must not be adopted.
        let kid = select_secret_kid(
            KID_DID,
            "m/26'/2'/3'/4'",
            Some(&format!("{KID_DID}#key-1 rotated")),
        );
        assert_eq!(kid, None);
    }
}
