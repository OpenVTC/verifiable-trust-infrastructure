//! This VTA's own keys, found by role in its own DID document.
//!
//! The VTA signs, authenticates, decrypts and asserts sealed transfers with keys
//! its own DID document lists. Each has two names: the **verification method**
//! the document gives it, which a proof or a `kid` names and a peer resolves,
//! and the **key record** it is stored under. Both used to be assumed —
//! `{did}#key-0`, `#key-1`, `#sealed-transfer-0` — which is the shape one
//! minting path gives a `did:webvh` and nothing more general. They are read from
//! the document instead ([`vta_sdk::node_keys`]), so a VTA whose identity names
//! its keys otherwise signs and decrypts under the ids it publishes.
//!
//! The document is the VTA's own, read from its own store — its `did:webvh` log,
//! or the key event stream of a `did:webs` it holds — never resolved: an answer
//! that depends on the network is one a host can shape. A VTA whose document is
//! not held locally falls back to the `did:webvh` convention, which is what every
//! VTA minted by this workspace's webvh path publishes.
//!
//! - **The record** is the document's method id under the DID the records are
//!   named for: the VTA DID, or for a `did:scid` VTA the `did:webvh` log that
//!   verifies it (VTI-KEY-161).
//! - **The method** is the same fragment under the VTA DID as configured.
//! - **A `did:key` VTA** keeps its records under `#key-0` (signing only; its
//!   X25519 key is converted from the Ed25519 one at runtime), and its one
//!   method is `did:key:<id>#<id>`.

use vta_sdk::node_keys::{self, NodeKeyIds};

use crate::store::KeyspaceHandle;

/// One of the VTA's keys: where it is stored, and the method its document gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfKey {
    /// The key record's id (`keys` keyspace, through `store_key`).
    pub record_id: String,
    /// The verification method a proof or `kid` names.
    pub vm_id: String,
}

impl SelfKey {
    /// The method's fragment, without `#`.
    pub fn fragment(&self) -> &str {
        node_keys::fragment(&self.vm_id).unwrap_or_default()
    }
}

/// The VTA's keys by role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfKeys {
    /// Signs credentials, Data-Integrity proofs and approval tokens.
    pub signing: SelfKey,
    /// Key agreement; `None` for a `did:key` VTA, whose X25519 key is converted
    /// from its signing key rather than stored.
    pub key_agreement: Option<SelfKey>,
    /// Signs sealed-transfer producer assertions, if the identity has one.
    pub sealed_transfer: Option<SelfKey>,
}

impl SelfKeys {
    /// The keys `ids` (from the document of `key_record_did`) give a VTA
    /// configured as `vta_did`.
    pub fn from_ids(vta_did: &str, key_record_did: &str, ids: &NodeKeyIds) -> Self {
        let key = |record_id: &str| SelfKey {
            vm_id: match node_keys::fragment(record_id) {
                Some(fragment) => format!("{vta_did}#{fragment}"),
                None => record_id.to_string(),
            },
            record_id: record_id.to_string(),
        };
        let _ = key_record_did;
        Self {
            signing: key(&ids.signing),
            key_agreement: ids.key_agreement.as_deref().map(key),
            sealed_transfer: ids.sealed_transfer.as_deref().map(key),
        }
    }

    /// A `did:key` VTA's keys.
    pub fn did_key(vta_did: &str) -> Self {
        let id = vta_did.strip_prefix("did:key:").unwrap_or(vta_did);
        Self {
            signing: SelfKey {
                record_id: format!("{vta_did}#key-0"),
                vm_id: format!("{vta_did}#{id}"),
            },
            key_agreement: None,
            sealed_transfer: Some(SelfKey {
                record_id: format!("{vta_did}#{}", node_keys::SEALED_TRANSFER_FRAGMENT),
                vm_id: format!("{vta_did}#{}", node_keys::SEALED_TRANSFER_FRAGMENT),
            }),
        }
    }
}

/// The DID the VTA's own key records are named under: the VTA DID itself, or for
/// a `did:scid` VTA DID, the `did:webvh` log recorded for it. Falls back to the
/// VTA DID, whose lookups then fail with the usual "run setup first".
pub async fn key_record_did_for(vta_did: &str, webvh_ks: Option<&KeyspaceHandle>) -> String {
    #[cfg(feature = "webvh")]
    if vta_sdk::did_scid::is_scid(vta_did)
        && let Some(ks) = webvh_ks
        && let Ok(Some(log_did)) = crate::webvh_store::log_did_for(ks, vta_did).await
    {
        return log_did;
    }
    let _ = webvh_ks;
    vta_did.to_string()
}

/// The VTA's own current DID document, from its own store, if it holds it.
async fn own_document(
    did: &str,
    webvh_ks: Option<&KeyspaceHandle>,
    webs_ks: Option<&KeyspaceHandle>,
) -> Option<serde_json::Value> {
    #[cfg(feature = "webvh")]
    if did.starts_with("did:webvh:")
        && let Some(ks) = webvh_ks
    {
        let log = crate::webvh_store::get_did_log(ks, did).await.ok()??;
        return crate::operations::protocol::document::current_document_from_log(&log).ok();
    }
    #[cfg(feature = "webs")]
    if did.starts_with("did:webs:")
        && let Some(ks) = webs_ks
    {
        let record = crate::webs_store::get(ks, did).await.ok()??;
        let parsed = affinidi_did_webs::DidWebs::parse(did).ok()?;
        let document =
            affinidi_did_webs::resolve_from_artifacts(&parsed, &record.keri_cesr, None).ok()?;
        return serde_json::to_value(&document).ok();
    }
    let _ = (did, webvh_ks, webs_ks);
    None
}

/// This VTA's keys, read from its own document (see the module documentation).
pub async fn self_keys(
    vta_did: &str,
    webvh_ks: Option<&KeyspaceHandle>,
    webs_ks: Option<&KeyspaceHandle>,
) -> SelfKeys {
    if vta_did.starts_with("did:key:") {
        return SelfKeys::did_key(vta_did);
    }
    let key_record_did = key_record_did_for(vta_did, webvh_ks).await;
    let ids = match own_document(&key_record_did, webvh_ks, webs_ks).await {
        Some(document) => match NodeKeyIds::from_document(&key_record_did, &document) {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(
                    did = %key_record_did, error = %e,
                    "this VTA's own DID document gives no signing key; using the did:webvh convention"
                );
                NodeKeyIds::conventional(&key_record_did)
            }
        },
        None => NodeKeyIds::conventional(&key_record_did),
    };
    SelfKeys::from_ids(vta_did, &key_record_did, &ids)
}

/// [`self_keys`] for the running service.
pub async fn self_keys_from_state(state: &crate::server::AppState, vta_did: &str) -> SelfKeys {
    #[cfg(feature = "webvh")]
    let webvh_ks = Some(&state.webvh_ks);
    #[cfg(not(feature = "webvh"))]
    let webvh_ks = None;
    self_keys(vta_did, webvh_ks, Some(&state.webs_ks)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A VTA's own did:webvh document as the creation path renders it
    /// (`build_vta_did_document_with_sealed_transfer`, over keys derived the way
    /// `create_did_webvh` derives them): its ids are exactly the ones every
    /// webvh peer has always seen.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn a_webvh_vta_document_from_the_creation_path_gives_todays_ids() {
        let ts = crate::test_support::open_test_store().await;
        let seed = [9u8; 32];
        let derived = crate::keys::derive_entity_keys(
            &seed,
            "m/26'/2'/0'",
            "vta signing key",
            "vta key-agreement key",
            &ts.keys_ks,
        )
        .await
        .expect("derive");
        let sealed = crate::keys::derive_sealed_transfer_key(
            &seed,
            "m/26'/2'/0'",
            "vta sealed-transfer key",
            &ts.keys_ks,
        )
        .await
        .expect("derive");
        let config = crate::test_support::test_app_config(ts.data_dir.clone());
        let did = "did:webvh:QmScid:vta.example";
        let template =
            crate::operations::did_webvh::document::build_vta_did_document_with_sealed_transfer(
                &derived, &sealed, &config, true, &None,
            );
        let document: serde_json::Value =
            serde_json::from_str(&template.to_string().replace("{DID}", did)).unwrap();

        let ids = NodeKeyIds::from_document(did, &document).expect("ids");
        assert_eq!(ids, NodeKeyIds::conventional(did));
        let keys = SelfKeys::from_ids(did, did, &ids);
        assert_eq!(keys.signing.record_id, format!("{did}#key-0"));
        assert_eq!(keys.signing.vm_id, format!("{did}#key-0"));
        assert_eq!(
            keys.key_agreement.map(|k| k.vm_id),
            Some(format!("{did}#key-1"))
        );
        assert_eq!(
            keys.sealed_transfer.map(|k| k.vm_id),
            Some(format!("{did}#sealed-transfer-0"))
        );
    }

    /// A did:webs key-role identity (affinidi-did-webs `key_roles`): its keys
    /// are found by role, under the ids its document gives them.
    #[cfg(feature = "webs")]
    #[test]
    fn a_did_webs_key_role_document_is_read_by_role() {
        use affinidi_did_webs::key_roles::{KeyRoles, VerificationKey};
        use affinidi_did_webs::{CreateConfig, DidWebs, KeyAgreementKey, create_controlled};
        use affinidi_keri::controller::{Inception, KeySigner, NextKey};
        use affinidi_keri_core::threshold::Threshold;

        let controller = crate::operations::did_webs::ed25519_signer(&[1u8; 32]).unwrap();
        let next = crate::operations::did_webs::ed25519_signer(&[2u8; 32]).unwrap();
        let attestation = VerificationKey::Ed25519([3u8; 32]);
        let operational = VerificationKey::Ed25519([4u8; 32]);
        let roles = KeyRoles::new()
            .with_attestation(attestation.clone())
            .with_operational(operational.clone())
            .with_messaging(KeyAgreementKey::X25519([5u8; 32]));
        let config = CreateConfig::builder("node.example")
            .controlled(Inception::new(
                vec![controller.public_key().unwrap()],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(next.public_key().unwrap())],
                Threshold::Simple(1),
            ))
            .key_roles(roles)
            .build();
        let created = create_controlled(config, &[&controller as &dyn KeySigner]).unwrap();
        let did = created.did().to_string();
        let parsed = DidWebs::parse(&did).unwrap();
        let document = serde_json::to_value(
            affinidi_did_webs::resolve_from_artifacts(
                &parsed,
                &created.artifacts().keri_cesr,
                None,
            )
            .unwrap(),
        )
        .unwrap();

        let ids = NodeKeyIds::from_document(&did, &document).expect("ids");
        let attest = format!("{did}#{}", attestation.to_cesr().unwrap());
        let oper = format!("{did}#{}", operational.to_cesr().unwrap());
        assert_eq!(ids.signing, attest);
        assert_eq!(ids.sealed_transfer.as_deref(), Some(attest.as_str()));
        assert_eq!(ids.authentication, oper);
        let ka = ids.key_agreement.expect("messaging key");
        assert!(ka.starts_with(&format!("{did}#")), "{ka}");
        // The KEL's own key is in no relationship of a key-role document.
        let kel_key = format!("{did}#{}", controller.public_key().unwrap());
        assert!(![&ids.signing, &ids.authentication, &ka].contains(&&kel_key));
    }

    #[test]
    fn a_did_key_vta_signs_under_its_one_method_and_stores_at_key_0() {
        let did = "did:key:z6MkExample";
        let keys = SelfKeys::did_key(did);
        assert_eq!(keys.signing.record_id, format!("{did}#key-0"));
        assert_eq!(keys.signing.vm_id, format!("{did}#z6MkExample"));
        assert!(keys.key_agreement.is_none());
    }

    #[test]
    fn a_scid_vta_names_methods_under_its_own_did_and_records_under_the_log() {
        let log = "did:webvh:QmScid:vta.example";
        let scid = "did:scid:vh:1:QmScid?src=vta.example";
        let keys = SelfKeys::from_ids(scid, log, &NodeKeyIds::conventional(log));
        assert_eq!(keys.signing.record_id, format!("{log}#key-0"));
        assert_eq!(keys.signing.vm_id, format!("{scid}#key-0"));
        assert_eq!(keys.signing.fragment(), "key-0");
    }
}
