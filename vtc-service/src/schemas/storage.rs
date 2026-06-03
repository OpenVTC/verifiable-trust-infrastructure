//! CRUD helpers for [`super::SchemaEntry`] over the `schemas:` keyspace.
//!
//! Keys: `schemas:<percent-encoded-type-uri>` — the URI is percent-encoded so
//! `:` / `/` in a type URI don't collide with the prefix delimiter (mirroring
//! [`crate::endorsement_types::storage`]).

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{SchemaEntry, SchemaKind};

pub const SCHEMAS_PREFIX: &[u8] = b"schemas:";

fn encode_uri(uri: &str) -> String {
    let mut out = String::with_capacity(uri.len());
    for b in uri.bytes() {
        match b {
            b':' | b'/' | b'%' => out.push_str(&format!("%{b:02x}")),
            _ => out.push(b as char),
        }
    }
    out
}

fn key(uri: &str) -> Vec<u8> {
    let mut k = SCHEMAS_PREFIX.to_vec();
    k.extend_from_slice(encode_uri(uri).as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<SchemaEntry, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("SchemaEntry decode: {e}")))
}

/// Fetch a registered schema by its type URI.
pub async fn get_schema(
    ks: &KeyspaceHandle,
    type_uri: &str,
) -> Result<Option<SchemaEntry>, AppError> {
    match ks.get_raw(key(type_uri)).await? {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Fast existence check — avoids deserialising the row.
pub async fn schema_exists(ks: &KeyspaceHandle, type_uri: &str) -> Result<bool, AppError> {
    Ok(ks.get_raw(key(type_uri)).await?.is_some())
}

/// Register / overwrite a schema (keyed by `type_uri`).
pub async fn store_schema(ks: &KeyspaceHandle, entry: &SchemaEntry) -> Result<(), AppError> {
    ks.insert(
        String::from_utf8(key(&entry.type_uri)).expect("ascii key"),
        entry,
    )
    .await
}

/// Remove a registered schema.
pub async fn delete_schema(ks: &KeyspaceHandle, type_uri: &str) -> Result<(), AppError> {
    ks.remove(key(type_uri)).await
}

/// List all registered schemas (community config — not a privacy-sensitive
/// enumeration). Ordered by key.
pub async fn list_schemas(ks: &KeyspaceHandle) -> Result<Vec<SchemaEntry>, AppError> {
    let mut pairs = ks.prefix_iter_raw(SCHEMAS_PREFIX.to_vec()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    pairs.iter().map(|(_, v)| decode(v)).collect()
}

/// List only the schemas of a given [`SchemaKind`] (e.g. all `Issues` types the
/// admin UI offers, or all `Accepts` criteria for a ceremony).
pub async fn list_by_kind(
    ks: &KeyspaceHandle,
    kind: SchemaKind,
) -> Result<Vec<SchemaEntry>, AppError> {
    Ok(list_schemas(ks)
        .await?
        .into_iter()
        .filter(|s| s.kind == kind)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::super::{SchemaKind, is_issues_registered};
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("schemas").unwrap();
        (dir, store, ks)
    }

    fn membership_issues() -> SchemaEntry {
        SchemaEntry {
            type_uri: "https://openvtc.org/credentials/MembershipCredential".into(),
            dtg_type: Some("MembershipCredential".into()),
            credential_schema: Some(json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"]
            })),
            kind: SchemaKind::Issues,
            description: Some("Community membership".into()),
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        }
    }

    #[tokio::test]
    async fn store_get_list_delete_round_trip() {
        let (_dir, _store, ks) = temp_ks().await;
        let entry = membership_issues();

        assert!(!schema_exists(&ks, &entry.type_uri).await.unwrap());
        store_schema(&ks, &entry).await.unwrap();

        // URI with `:` and `/` round-trips through the key encoding.
        let got = get_schema(&ks, &entry.type_uri).await.unwrap().unwrap();
        assert_eq!(got, entry);
        assert!(schema_exists(&ks, &entry.type_uri).await.unwrap());

        let all = list_schemas(&ks).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], entry);

        delete_schema(&ks, &entry.type_uri).await.unwrap();
        assert!(get_schema(&ks, &entry.type_uri).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn is_issues_registered_only_for_issues_kind() {
        let (_dir, _store, ks) = temp_ks().await;
        let issues = membership_issues();
        store_schema(&ks, &issues).await.unwrap();

        let mut accepts = issues.clone();
        accepts.type_uri = "https://openvtc.org/credentials/SomeEvidence".into();
        accepts.kind = SchemaKind::Accepts;
        store_schema(&ks, &accepts).await.unwrap();

        assert!(is_issues_registered(&ks, &issues.type_uri).await.unwrap());
        assert!(
            !is_issues_registered(&ks, &accepts.type_uri).await.unwrap(),
            "an Accepts type is not issuable"
        );
        assert!(
            !is_issues_registered(&ks, "https://unknown").await.unwrap(),
            "an unregistered type is not issuable"
        );
    }

    #[tokio::test]
    async fn list_by_kind_partitions() {
        let (_dir, _store, ks) = temp_ks().await;
        store_schema(&ks, &membership_issues()).await.unwrap();
        let mut accepts = membership_issues();
        accepts.type_uri = "https://openvtc.org/credentials/Evidence".into();
        accepts.kind = SchemaKind::Accepts;
        store_schema(&ks, &accepts).await.unwrap();

        assert_eq!(
            list_by_kind(&ks, SchemaKind::Issues).await.unwrap().len(),
            1
        );
        assert_eq!(
            list_by_kind(&ks, SchemaKind::Accepts).await.unwrap().len(),
            1
        );
    }
}
