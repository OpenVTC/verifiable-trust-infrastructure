//! A node's own keys, found by role in its own DID document.
//!
//! A node (a VTA, a VTC, a host service) signs, authenticates, decrypts and
//! asserts sealed transfers with keys its DID document lists. Which
//! verification method each is used to be assumed from a fragment —
//! `#key-0` signing, `#key-1` key agreement, `#sealed-transfer-0` — the shape
//! one minting path gives a `did:webvh`. That numbering is a property of the
//! minting path, not of DIDs: a `did:peer` numbers from `#key-1`, a level-1
//! `did:webs` names each key by itself (and so a new id on every rotation),
//! and a `did:webs` key-role identity names each role's key by the key. So a
//! node reads its ids from **its own current document**, which it already
//! holds, by relationship and role (VTI-KEY-150):
//!
//! | Purpose | Key-role document (`keyRoles`) | Otherwise |
//! |---|---|---|
//! | signing (credentials, proofs) | `keyRoles.attestation[0]` | `assertionMethod[0]`, else `authentication[0]` |
//! | authentication (DIDComm, sessions) | `keyRoles.operational[0]` | `authentication[0]` |
//! | key agreement | `keyRoles.messaging[0]` | `keyAgreement[0]` |
//! | sealed-transfer producer assertion | `keyRoles.attestation[0]` | the `assertionMethod` entry whose fragment is `sealed-transfer-0`, as a VTA's own `did:webvh` publishes it |
//!
//! For a `did:webvh` node minted by this workspace these are exactly
//! `#key-0`, `#key-0`, `#key-1` and `#sealed-transfer-0`, so nothing a webvh
//! peer sees changes. A node's secrets must be held under the same ids, which
//! is what a peer and a mediator match on.

use serde_json::Value;

/// The verification-method ids a node's own document gives its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeKeyIds {
    /// The key that signs credentials and Data-Integrity proofs.
    pub signing: String,
    /// The key that authenticates the node (DIDComm, sessions).
    pub authentication: String,
    /// The key agreement key, if the document lists one.
    pub key_agreement: Option<String>,
    /// The key that signs sealed-transfer producer assertions, if any.
    pub sealed_transfer: Option<String>,
}

/// Why a document gives no key ids.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NodeKeyError {
    /// The document lists no signing key in any relationship.
    #[error("the DID document of {0} lists no signing key")]
    NoSigningKey(String),
}

/// The sealed-transfer key's fragment in a VTA's own `did:webvh`.
pub const SEALED_TRANSFER_FRAGMENT: &str = "sealed-transfer-0";

impl NodeKeyIds {
    /// The ids `document`, the current DID document of `did`, gives a node's
    /// keys (see the module documentation).
    ///
    /// # Errors
    /// [`NodeKeyError::NoSigningKey`] if the document lists no signing key.
    pub fn from_document(did: &str, document: &Value) -> Result<Self, NodeKeyError> {
        let roles = document.get("keyRoles").filter(|r| r.is_object());
        let role = |name: &str| -> Option<String> {
            roles?
                .get(name)?
                .as_array()?
                .iter()
                .find_map(|v| v.as_str())
                .map(|id| absolute(did, id))
        };
        let first = |relationship: &str| -> Option<String> {
            document
                .get(relationship)?
                .as_array()?
                .iter()
                .find_map(entry_id)
                .map(|id| absolute(did, &id))
        };

        if roles.is_some() {
            let signing = role("attestation")
                .or_else(|| first("assertionMethod"))
                .ok_or_else(|| NodeKeyError::NoSigningKey(did.to_string()))?;
            return Ok(Self {
                authentication: role("operational")
                    .or_else(|| first("authentication"))
                    .unwrap_or_else(|| signing.clone()),
                key_agreement: role("messaging").or_else(|| first("keyAgreement")),
                sealed_transfer: Some(signing.clone()),
                signing,
            });
        }

        let signing = first("assertionMethod")
            .or_else(|| first("authentication"))
            .ok_or_else(|| NodeKeyError::NoSigningKey(did.to_string()))?;
        let sealed_transfer = document
            .get("assertionMethod")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(entry_id)
            .map(|id| absolute(did, &id))
            .find(|id| fragment(id) == Some(SEALED_TRANSFER_FRAGMENT));
        Ok(Self {
            authentication: first("authentication").unwrap_or_else(|| signing.clone()),
            key_agreement: first("keyAgreement"),
            sealed_transfer,
            signing,
        })
    }

    /// The ids a node minted by this workspace's `did:webvh` path has
    /// (`#key-0`, `#key-1`, `#sealed-transfer-0`): the fallback for a node
    /// whose own document it does not hold locally.
    pub fn conventional(did: &str) -> Self {
        Self {
            signing: format!("{did}#key-0"),
            authentication: format!("{did}#key-0"),
            key_agreement: Some(format!("{did}#key-1")),
            sealed_transfer: Some(format!("{did}#{SEALED_TRANSFER_FRAGMENT}")),
        }
    }
}

/// The fragment of a DID URL, without the `#`.
pub fn fragment(id: &str) -> Option<&str> {
    id.split_once('#').map(|(_, f)| f)
}

/// A relationship entry's id: a reference, or an embedded method's `id`.
fn entry_id(entry: &Value) -> Option<String> {
    match entry {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("id")?.as_str().map(str::to_string),
        _ => None,
    }
}

/// An id made absolute under `did`: a relationship may list `#fragment`.
fn absolute(did: &str, id: &str) -> String {
    match id.strip_prefix('#') {
        Some(fragment) => format!("{did}#{fragment}"),
        None => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:webvh:QmScid:vta.example";

    /// The shape `build_vta_did_document_with_sealed_transfer` publishes.
    fn webvh_vta_document() -> Value {
        json!({
            "id": DID,
            "verificationMethod": [
                { "id": format!("{DID}#key-0"), "type": "Multikey" },
                { "id": format!("{DID}#key-1"), "type": "Multikey" },
                { "id": format!("{DID}#sealed-transfer-0"), "type": "Multikey" },
            ],
            "authentication": [format!("{DID}#key-0")],
            "assertionMethod": [format!("{DID}#key-0"), format!("{DID}#sealed-transfer-0")],
            "keyAgreement": [format!("{DID}#key-1")],
        })
    }

    #[test]
    fn a_webvh_vta_document_gives_the_conventional_ids() {
        let ids = NodeKeyIds::from_document(DID, &webvh_vta_document()).unwrap();
        assert_eq!(ids, NodeKeyIds::conventional(DID));
    }

    #[test]
    fn a_document_without_a_sealed_transfer_key_has_none() {
        let mut doc = webvh_vta_document();
        doc["assertionMethod"] = json!([format!("{DID}#key-0")]);
        let ids = NodeKeyIds::from_document(DID, &doc).unwrap();
        assert_eq!(ids.signing, format!("{DID}#key-0"));
        assert_eq!(ids.sealed_transfer, None);
    }

    #[test]
    fn relative_ids_and_embedded_methods_are_made_absolute() {
        let doc = json!({
            "id": DID,
            "authentication": [{ "id": "#key-1", "type": "Multikey" }],
            "keyAgreement": ["#key-2"],
        });
        let ids = NodeKeyIds::from_document(DID, &doc).unwrap();
        assert_eq!(ids.signing, format!("{DID}#key-1"));
        assert_eq!(ids.authentication, format!("{DID}#key-1"));
        assert_eq!(
            ids.key_agreement.as_deref(),
            Some(format!("{DID}#key-2").as_str())
        );
    }

    #[test]
    fn a_key_role_document_is_read_by_role() {
        let did = "did:webs:host.example:EAid";
        let doc = json!({
            "id": did,
            "assertionMethod": ["#DAttest"],
            "authentication": ["#DOper"],
            "keyAgreement": ["#CMsg"],
            "keyRoles": {
                "attestation": ["#DAttest"],
                "operational": ["#DOper"],
                "messaging": ["#CMsg"],
            },
        });
        let ids = NodeKeyIds::from_document(did, &doc).unwrap();
        assert_eq!(ids.signing, format!("{did}#DAttest"));
        assert_eq!(ids.authentication, format!("{did}#DOper"));
        assert_eq!(
            ids.key_agreement.as_deref(),
            Some(format!("{did}#CMsg").as_str())
        );
        assert_eq!(
            ids.sealed_transfer.as_deref(),
            Some(format!("{did}#DAttest").as_str())
        );
    }

    #[test]
    fn a_document_with_no_signing_key_is_refused() {
        let doc = json!({ "id": DID, "keyAgreement": ["#key-1"] });
        assert!(matches!(
            NodeKeyIds::from_document(DID, &doc),
            Err(NodeKeyError::NoSigningKey(_))
        ));
    }
}
