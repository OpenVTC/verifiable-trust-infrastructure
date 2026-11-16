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
#[derive(Clone, Serialize, Deserialize)]
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

/// Written by hand so the private key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEntry")
            .field("key_id", &self.key_id)
            .field("key_type", &self.key_type)
            .field("private_key_multibase", &"<redacted>")
            .finish()
    }
}

impl DidSecretsBundle {
    /// The bundle's Ed25519 assertion key, as a Trust Task signing key.
    ///
    /// A provisioned integration holds a `did:webvh` and the keys under it. Its
    /// verification method is [`SecretEntry::key_id`] — the DID document
    /// decided what the key is called, and that name is in the bundle, so
    /// nothing here has to guess it.
    ///
    /// `None` when the bundle carries no Ed25519 entry: X25519 is a key
    /// agreement key and signs nothing, and P-256 is not what `eddsa-jcs-2022`
    /// verifies.
    ///
    /// This is the bundle's **first** Ed25519 entry, for a caller that holds
    /// the bundle but not the DID's document. A bundle built for a document
    /// leads with the key the document lists for authentication
    /// ([`Self::lead_with_trust_task_signing_key`]; every provisioned bundle
    /// is, through `DidKeyMaterialV2::secrets_bundle`), so the first entry is
    /// that key. A caller that holds the document asks
    /// [`Self::trust_task_signing_key_for`] instead.
    #[must_use]
    pub fn trust_task_signing_key(&self) -> Option<&SecretEntry> {
        self.secrets
            .iter()
            .find(|e| matches!(e.key_type, KeyType::Ed25519))
    }

    /// The bundle's Trust Task signing key as `document` — the current DID
    /// document of [`Self::did`] — assigns it: the key it lists for
    /// authentication, by role (VTI-KEY-150, [`crate::node_keys`]: a key-role
    /// document's `operational` key, otherwise `authentication[0]`).
    ///
    /// Not "the first Ed25519 key": a `did:webs` names every key by itself and
    /// a VTA also holds its pre-rotated successors, so position says nothing
    /// about role. `None` when the document lists no authentication key or the
    /// bundle does not hold the one it lists as an Ed25519 key — never another
    /// key in its place, which would sign a proof no verifier accepts.
    #[must_use]
    pub fn trust_task_signing_key_for(&self, document: &serde_json::Value) -> Option<&SecretEntry> {
        let did = crate::did_scid::strip_src(&self.did);
        let ids = crate::node_keys::NodeKeyIds::from_document(&did, document).ok()?;
        // A document listing no `authentication` falls back to its signing key
        // in `NodeKeyIds`; a Trust Task proof is an authentication proof, so
        // only a key the document lists for it answers here.
        let listed = document
            .get("keyRoles")
            .and_then(|r| r.get("operational"))
            .is_some()
            || document
                .get("authentication")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|a| !a.is_empty());
        if !listed {
            return None;
        }
        self.secrets
            .iter()
            .find(|e| e.key_id == ids.authentication && matches!(e.key_type, KeyType::Ed25519))
    }

    /// Move the key [`Self::trust_task_signing_key_for`] picks to the front, so
    /// [`Self::trust_task_signing_key`] answers it for a caller without the
    /// document. `false`, and the order unchanged, when the bundle holds no
    /// such key.
    pub fn lead_with_trust_task_signing_key(&mut self, document: &serde_json::Value) -> bool {
        let Some(key_id) = self
            .trust_task_signing_key_for(document)
            .map(|e| e.key_id.clone())
        else {
            return false;
        };
        if let Some(at) = self.secrets.iter().position(|e| e.key_id == key_id) {
            let entry = self.secrets.remove(at);
            self.secrets.insert(0, entry);
        }
        true
    }
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
/// For a bundle whose DID is a `did:scid:vh:1` identity, rules 1 and 2 also
/// accept an id under the `did:webvh` log carrying the same SCID — the VTA
/// names key records by the log's own method ids — and publish it under the
/// did:scid DID instead (`did:webvh:<scid>:host#key-1` becomes
/// `did:scid:vh:1:<scid>#key-1`), because that is where the identity's
/// resolved document lists the key (VTI-KEY-161, VTI-KEY-163). A `src` on the
/// bundle DID is ignored: kids are under the bare DID.
///
/// Shared between the online SDK path (`VtaClient::fetch_did_secrets_bundle`)
/// and the offline VTA-service path
/// (`vta_service::operations::export::build_did_secrets_bundle`) so the
/// two cannot drift.
pub fn select_secret_kid(did: &str, record_key_id: &str, label: Option<&str>) -> Option<String> {
    let did = crate::did_scid::strip_src(did);
    let vm_prefix = format!("{did}#");
    let as_kid = |id: &str| {
        if id.starts_with(&vm_prefix) {
            Some(id.to_string())
        } else {
            crate::did_scid::presented_reference(&did, id)
        }
    };
    if let Some(kid) = as_kid(record_key_id) {
        return Some(kid);
    }
    if let Some(label) = label
        && !label.chars().any(char::is_whitespace)
        && let Some(kid) = as_kid(label)
    {
        return Some(kid);
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

    /// VTI-KEY-161/163: a did:scid identity's secrets are published under the
    /// did:scid DID, from records named by its did:webvh log's method ids.
    #[test]
    fn scid_identity_publishes_webvh_records_under_the_scid_did() {
        let scid = "did:scid:vh:1:QmScid";
        assert_eq!(
            select_secret_kid(scid, "did:webvh:QmScid:example.com#key-1", None).as_deref(),
            Some("did:scid:vh:1:QmScid#key-1")
        );
        assert_eq!(
            select_secret_kid(
                "did:scid:vh:1:QmScid?src=example.com",
                "did:scid:vh:1:QmScid#key-0",
                None
            )
            .as_deref(),
            Some("did:scid:vh:1:QmScid#key-0")
        );
        assert_eq!(
            select_secret_kid(scid, "m/26'/1", Some("did:webvh:QmScid:example.com#key-2"))
                .as_deref(),
            Some("did:scid:vh:1:QmScid#key-2")
        );
        // Another log's key is excluded.
        assert_eq!(
            select_secret_kid(scid, "did:webvh:QmOther:example.com#key-1", None),
            None
        );
        // A did:webvh bundle is unchanged: no did:scid kid.
        assert_eq!(
            select_secret_kid(
                "did:webvh:QmScid:example.com",
                "did:webvh:QmScid:example.com#key-1",
                None
            )
            .as_deref(),
            Some("did:webvh:QmScid:example.com#key-1")
        );
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

    // ── the Trust Task signing key, by role ─────────────────────────

    const WEBS: &str = "did:webs:hosting.example:EAid";

    fn entry(key_id: &str, key_type: KeyType) -> SecretEntry {
        SecretEntry {
            key_id: key_id.to_string(),
            key_type,
            private_key_multibase: "zPRIVATE".to_string(),
        }
    }

    /// A did:webs context's keys as the VTA lists them: the pre-rotated
    /// successor (an Ed25519 key under the DID, in no relationship) before
    /// the key-state key.
    fn webs_bundle() -> DidSecretsBundle {
        DidSecretsBundle {
            did: WEBS.to_string(),
            secrets: vec![
                entry(&format!("{WEBS}#pre-rotation-0"), KeyType::Ed25519),
                entry(&format!("{WEBS}#CKa"), KeyType::X25519),
                entry(&format!("{WEBS}#DSigning"), KeyType::Ed25519),
            ],
        }
    }

    fn webs_document() -> serde_json::Value {
        serde_json::json!({
            "id": WEBS,
            "verificationMethod": [
                { "id": "#DSigning", "type": "JsonWebKey" },
                { "id": "#CKa", "type": "JsonWebKey" },
            ],
            "authentication": ["#DSigning"],
            "assertionMethod": ["#DSigning"],
            "keyAgreement": ["#CKa"],
        })
    }

    /// The signing key is the one the document lists for authentication, not
    /// the first Ed25519 key the bundle happens to hold.
    #[test]
    fn the_trust_task_signing_key_is_the_documents_authentication_key() {
        let mut bundle = webs_bundle();
        assert_eq!(
            bundle.trust_task_signing_key().unwrap().key_id,
            format!("{WEBS}#pre-rotation-0"),
            "position alone picks the successor"
        );
        let want = format!("{WEBS}#DSigning");
        assert_eq!(
            bundle
                .trust_task_signing_key_for(&webs_document())
                .unwrap()
                .key_id,
            want
        );
        assert!(bundle.lead_with_trust_task_signing_key(&webs_document()));
        assert_eq!(bundle.trust_task_signing_key().unwrap().key_id, want);
        assert_eq!(bundle.secrets.len(), 3, "reordered, nothing dropped");
    }

    /// A document whose authentication key the bundle does not hold answers
    /// none, and leaves the order alone — never another key in its place.
    #[test]
    fn no_authentication_key_held_is_none_not_a_substitute() {
        let mut bundle = webs_bundle();
        bundle.secrets.retain(|e| !e.key_id.ends_with("#DSigning"));
        assert!(
            bundle
                .trust_task_signing_key_for(&webs_document())
                .is_none()
        );
        assert!(!bundle.lead_with_trust_task_signing_key(&webs_document()));
        assert!(bundle.secrets[0].key_id.ends_with("#pre-rotation-0"));

        let mut no_auth = webs_document();
        no_auth.as_object_mut().unwrap().remove("authentication");
        assert!(webs_bundle().trust_task_signing_key_for(&no_auth).is_none());
    }

    /// A webvh bundle in the order every provisioning has written keeps it.
    #[test]
    fn a_webvh_bundle_keeps_its_order() {
        let did = "did:webvh:QmScid:example.com";
        let mut bundle = DidSecretsBundle {
            did: did.to_string(),
            secrets: vec![
                entry(&format!("{did}#key-0"), KeyType::Ed25519),
                entry(&format!("{did}#key-1"), KeyType::X25519),
            ],
        };
        let doc = serde_json::json!({
            "id": did,
            "authentication": [format!("{did}#key-0")],
            "assertionMethod": [format!("{did}#key-0")],
            "keyAgreement": [format!("{did}#key-1")],
        });
        assert!(bundle.lead_with_trust_task_signing_key(&doc));
        assert_eq!(bundle.secrets[0].key_id, format!("{did}#key-0"));
        assert_eq!(bundle.secrets[1].key_id, format!("{did}#key-1"));
    }
}
