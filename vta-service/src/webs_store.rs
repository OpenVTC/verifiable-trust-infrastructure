//! `did:webs` DID records ([`vta_keyspaces::WEBS`]).
//!
//! One row per identifier this VTA holds: what it published (`keri.cesr`), the
//! controller state that continues the key event log, and the key records
//! that sign it. The row is backed up, so a restored VTA can rotate and update
//! the identifier (`docs/05-design-notes/did-webs-in-the-vta.md`, decision 6).
//!
//! The context purge reads only `contextId` and is built without the `webs`
//! feature, so a build that cannot create a `did:webs` still removes the
//! records of a deleted context.

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

const DID_PREFIX: &str = "did:";

fn did_key(did: &str) -> String {
    format!("{DID_PREFIX}{did}")
}

/// A `did:webs` identifier this VTA holds.
#[cfg(feature = "webs")]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebsDidRecord {
    /// The `did:webs:{host}:{path}:{aid}` identifier.
    pub did: String,
    /// The identifier's KERI AID, the DID's last segment.
    pub aid: String,
    /// The trust context the identifier and its keys belong to.
    pub context_id: String,
    /// The did-hosting server it is published on.
    pub server_id: String,
    /// The slot on that server: the DID's path, ending in the AID.
    pub mnemonic: String,
    /// The host domain the DID names, when the server serves several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// A label for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The published key event stream, `keri.cesr`.
    #[serde(with = "base64_bytes")]
    pub keri_cesr: Vec<u8>,
    /// Where the controller is in its key event log: the next event is signed
    /// from here.
    pub state: affinidi_keri::controller::ControllerState,
    /// The key record of the current signing key.
    pub signing_key_id: String,
    /// The key record of the committed successor, installed by the next
    /// rotation.
    pub next_key_id: String,
    /// The key record of the designated key agreement key (a key-role
    /// identity's `messaging` key).
    pub key_agreement_key_id: String,
    /// A key-role identity's `attestation` key record (VTI-KEY-072); `None`
    /// for an identity without key roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_key_id: Option<String>,
    /// A key-role identity's `operational` key record; `None` without key
    /// roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational_key_id: Option<String>,
    /// The DID class it was created in (VTI-KEY-190 – 193), fixed for its
    /// life. `None` for a DID `vta/webs/dids/create/0.1` made, which states
    /// none and is never inferred one: the family reads that as "not a service
    /// DID".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_class: Option<WebsDidClass>,
    /// The DID template it was shaped from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<WebsTemplateUse>,
    /// Whether its host serves it. `false` only for this VTA's own identity
    /// between setup, which mints it offline, and first boot, which registers
    /// it (`operations::did_webs::publish_own_identity`). A record written
    /// before this existed was published by its create.
    #[serde(default = "published_default")]
    pub published: bool,
    /// A rotation signed but not yet accepted by the host. While one is staged
    /// nothing else is written: every write publishes it again first, since
    /// the successor it installs has signed it and cannot sign another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged: Option<StagedRotation>,
    /// The last rotation committed to no next keys: the identifier is ended,
    /// and nothing more is signed as it.
    #[serde(default)]
    pub deactivated: bool,
    /// Whether the host confirmed removing the slot of a deactivated DID.
    #[serde(default)]
    pub slot_removed: bool,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub updated_at: String,
}

/// A `did:webs` DID's class (VTI-KEY-190 – 193; `vta/webs/_shared/0.2`
/// `WebsDidClass`), as the record keeps it.
#[cfg(feature = "webs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebsDidClass {
    /// One relationship, community or trust context (VTI-KEY-190).
    Relationship,
    /// A person's own identity (VTI-KEY-191).
    Persona,
    /// A node's or a service's durable identity (VTI-KEY-192).
    Service,
}

#[cfg(feature = "webs")]
impl WebsDidClass {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relationship => "relationship",
            Self::Persona => "persona",
            Self::Service => "service",
        }
    }
}

/// The DID template a `did:webs` was shaped from: its name, the scope it
/// resolved in (`builtin`, `global`, or a context id) and its `kind`, the DID's
/// integration kind. Recorded, never published.
#[cfg(feature = "webs")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebsTemplateUse {
    pub name: String,
    pub scope: String,
    pub kind: String,
}

/// A signed rotation, staged before it is published.
#[cfg(feature = "webs")]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedRotation {
    /// The whole stream with the rotation appended: what is published.
    #[serde(with = "base64_bytes")]
    pub keri_cesr: Vec<u8>,
    /// The controller state after the rotation.
    pub state: affinidi_keri::controller::ControllerState,
    /// The key record that becomes the signing key: the successor installed.
    pub signing_key_id: String,
    /// The key record of the new successor; `None` for a deactivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_key_id: Option<String>,
    /// The key record the rotation retires.
    pub retired_key_id: String,
}

#[cfg(feature = "webs")]
mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

/// Store `record`, replacing any row for its DID.
#[cfg(feature = "webs")]
pub async fn put(ks: &KeyspaceHandle, record: &WebsDidRecord) -> Result<(), AppError> {
    ks.insert(did_key(&record.did), record).await
}

/// The record for `did`, if this VTA holds it.
#[cfg(feature = "webs")]
pub async fn get(ks: &KeyspaceHandle, did: &str) -> Result<Option<WebsDidRecord>, AppError> {
    ks.get(did_key(did)).await
}

/// Every record, in key order.
#[cfg(feature = "webs")]
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<WebsDidRecord>, AppError> {
    ks.prefix_iter_raw(DID_PREFIX)
        .await?
        .into_iter()
        .map(|(_, value)| serde_json::from_slice(&value).map_err(AppError::from))
        .collect()
}

/// The records of `context_id`.
#[cfg(feature = "webs")]
pub async fn list_by_context(
    ks: &KeyspaceHandle,
    context_id: &str,
) -> Result<Vec<WebsDidRecord>, AppError> {
    Ok(list(ks)
        .await?
        .into_iter()
        .filter(|r| r.context_id == context_id)
        .collect())
}

/// Remove the record for `did`.
#[cfg(feature = "webs")]
pub async fn delete(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.remove(did_key(did)).await
}

/// Remove every record of `context_id`, returning how many went.
///
/// Reads only `contextId`, so it runs in a build without the `webs` feature.
/// A row it cannot read is left in place and reported, never guessed at.
pub async fn purge_context(ks: &KeyspaceHandle, context_id: &str) -> Result<usize, AppError> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Scoped {
        context_id: String,
    }
    let mut removed = 0;
    for (key, value) in ks.prefix_iter_raw(DID_PREFIX).await? {
        let scoped: Scoped = serde_json::from_slice(&value).map_err(|e| {
            AppError::Internal(format!(
                "a did:webs record under {} is unreadable: {e}",
                String::from_utf8_lossy(&key)
            ))
        })?;
        if scoped.context_id == context_id {
            ks.remove(key).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(feature = "webs")]
fn published_default() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn keyspace() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(vta_keyspaces::WEBS).unwrap();
        (dir, ks)
    }

    #[tokio::test]
    async fn a_context_purge_takes_only_that_contexts_records() {
        let (_dir, ks) = keyspace().await;
        for (did, ctx) in [("did:webs:a:E1", "acme"), ("did:webs:a:E2", "other")] {
            ks.insert(
                did_key(did),
                &serde_json::json!({ "did": did, "contextId": ctx }),
            )
            .await
            .unwrap();
        }
        assert_eq!(purge_context(&ks, "acme").await.unwrap(), 1);
        assert!(
            ks.get_raw(did_key("did:webs:a:E1"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ks.get_raw(did_key("did:webs:a:E2"))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn an_unreadable_row_fails_the_purge_rather_than_surviving_it_silently() {
        let (_dir, ks) = keyspace().await;
        ks.insert_raw(did_key("did:webs:a:E1"), b"not json".to_vec())
            .await
            .unwrap();
        assert!(purge_context(&ks, "acme").await.is_err());
    }
}
