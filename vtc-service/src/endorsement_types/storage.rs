//! CRUD helpers for [`super::EndorsementType`] over the
//! `endorsement_types:` keyspace.
//!
//! Keys: `endorsement_types:<percent-encoded-uri>`. We
//! percent-encode the URI so colons and slashes in the type
//! URI (`https://example.com/v1/skills/rust`) don't collide
//! with the prefix delimiter.

use vti_common::audit::AuditKey;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::EndorsementType;

pub const ENDORSEMENT_TYPES_PREFIX: &[u8] = b"endorsement_types:";

fn encode_uri(uri: &str) -> String {
    // Replace bytes that overlap with our `:`-delimited keyspace
    // discipline. Hex-encode `:` and `/` — the rest pass through
    // (most URI-safe chars are also safe in fjall keys).
    let mut out = String::with_capacity(uri.len());
    for b in uri.bytes() {
        match b {
            b':' | b'/' | b'%' => out.push_str(&format!("%{:02x}", b)),
            _ => out.push(b as char),
        }
    }
    out
}

fn key(uri: &str) -> Vec<u8> {
    let mut k = ENDORSEMENT_TYPES_PREFIX.to_vec();
    k.extend_from_slice(encode_uri(uri).as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<EndorsementType, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("EndorsementType decode: {e}")))
}

pub async fn get_type(ks: &KeyspaceHandle, uri: &str) -> Result<Option<EndorsementType>, AppError> {
    let raw = ks.get_raw(key(uri)).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Fast existence check — avoids deserialising the row.
pub async fn type_exists(ks: &KeyspaceHandle, uri: &str) -> Result<bool, AppError> {
    Ok(ks.get_raw(key(uri)).await?.is_some())
}

pub async fn store_type(ks: &KeyspaceHandle, t: &EndorsementType) -> Result<(), AppError> {
    ks.insert(String::from_utf8(key(&t.type_uri)).expect("ascii key"), t)
        .await
}

pub async fn delete_type(ks: &KeyspaceHandle, uri: &str) -> Result<(), AppError> {
    ks.remove(key(uri)).await
}

/// Every registered type, unpaginated and in key order.
///
/// [`list_types`] needs an [`AuditKey`] to sign its page cursor, which a
/// boot-time sweep has no use for. Callers that want a page still want
/// `list_types`; this is for the whole registry at once.
pub async fn all_types(ks: &KeyspaceHandle) -> Result<Vec<EndorsementType>, AppError> {
    let mut pairs = ks
        .prefix_iter_raw(ENDORSEMENT_TYPES_PREFIX.to_vec())
        .await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    pairs.iter().map(|(_, v)| decode(v)).collect()
}

pub async fn list_types(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<EndorsementType>, AppError> {
    let mut pairs = ks
        .prefix_iter_raw(ENDORSEMENT_TYPES_PREFIX.to_vec())
        .await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    let snapshot_id: u64 = pairs.len() as u64;
    paginate(pairs, cursor, limit, &audit_key.key, snapshot_id, decode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vti_common::audit::AuditKeyStore;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, AuditKey, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("endorsement_types").unwrap();
        let audit_key_ks = store.keyspace("audit_key").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
        (ks, key_store.active().await.unwrap(), dir)
    }

    fn fresh(uri: &str) -> EndorsementType {
        EndorsementType {
            type_uri: uri.into(),
            claim_schema: None,
            description: None,
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        }
    }

    #[tokio::test]
    async fn round_trip_with_colons_and_slashes() {
        let (ks, _audit, _dir) = temp_ks().await;
        let t = fresh("https://example.com/v1/skills/rust");
        store_type(&ks, &t).await.unwrap();
        let got = get_type(&ks, "https://example.com/v1/skills/rust")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn type_exists_is_fast_lookup() {
        let (ks, _audit, _dir) = temp_ks().await;
        assert!(!type_exists(&ks, "https://x.example/t").await.unwrap());
        let t = fresh("https://x.example/t");
        store_type(&ks, &t).await.unwrap();
        assert!(type_exists(&ks, "https://x.example/t").await.unwrap());
    }

    #[tokio::test]
    async fn delete_clears_row() {
        let (ks, _audit, _dir) = temp_ks().await;
        let t = fresh("https://x.example/t");
        store_type(&ks, &t).await.unwrap();
        delete_type(&ks, "https://x.example/t").await.unwrap();
        assert!(!type_exists(&ks, "https://x.example/t").await.unwrap());
        // Idempotent.
        delete_type(&ks, "https://x.example/t").await.unwrap();
    }

    /// `all_types` returns the whole registry in key order, with no cursor and
    /// no audit key — what the boot-time `claimSchema` scan walks.
    #[tokio::test]
    async fn all_types_returns_every_row_in_key_order() {
        let (ks, _audit, _dir) = temp_ks().await;
        assert!(all_types(&ks).await.unwrap().is_empty());
        for uri in [
            "https://x.example/c",
            "https://x.example/a",
            "https://x.example/b",
        ] {
            store_type(&ks, &fresh(uri)).await.unwrap();
        }
        let uris: Vec<String> = all_types(&ks)
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.type_uri)
            .collect();
        assert_eq!(
            uris,
            vec![
                "https://x.example/a",
                "https://x.example/b",
                "https://x.example/c"
            ]
        );
    }

    #[tokio::test]
    async fn list_paginates_alphabetically() {
        let (ks, audit, _dir) = temp_ks().await;
        for uri in [
            "https://b.example/t",
            "https://a.example/t",
            "https://c.example/t",
        ] {
            store_type(&ks, &fresh(uri)).await.unwrap();
        }
        let p = list_types(&ks, &audit, None, 10).await.unwrap();
        assert_eq!(p.items.len(), 3);
        // Sorted by encoded-key lexicographic order.
        let uris: Vec<_> = p.items.iter().map(|x| x.type_uri.clone()).collect();
        let mut sorted = uris.clone();
        sorted.sort();
        assert_eq!(uris, sorted);
    }

    #[tokio::test]
    async fn keys_with_overlapping_prefixes_round_trip() {
        // Edge case: "https://a.example/" and "https://a.example/x"
        // would naively collide on a non-encoded key. Verify
        // both round-trip independently.
        let (ks, _audit, _dir) = temp_ks().await;
        store_type(&ks, &fresh("https://a.example/")).await.unwrap();
        store_type(&ks, &fresh("https://a.example/x"))
            .await
            .unwrap();
        assert!(type_exists(&ks, "https://a.example/").await.unwrap());
        assert!(type_exists(&ks, "https://a.example/x").await.unwrap());
    }
}
