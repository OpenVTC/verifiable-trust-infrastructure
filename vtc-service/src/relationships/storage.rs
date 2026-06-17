//! CRUD helpers for [`super::Relationship`] over the
//! `relationships:` + `relationships_by_did:` keyspaces.

use uuid::Uuid;
use vti_common::audit::AuditKey;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::Relationship;

/// Primary keyspace prefix. Each VRC lives at
/// `relationships:<uuid>`.
pub const RELATIONSHIPS_PREFIX: &[u8] = b"relationships:";

/// Secondary-index prefix. Each `(did, vrc-id)` pair lives at
/// `relationships_by_did:<did>:<vrc-id>` so a `prefix_iter` on
/// `relationships_by_did:<did>:` lists only that DID's edges.
pub const RELATIONSHIPS_BY_DID_PREFIX: &[u8] = b"relationships_by_did:";

fn primary_key(id: Uuid) -> Vec<u8> {
    let mut k = RELATIONSHIPS_PREFIX.to_vec();
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

fn index_key(did: &str, id: Uuid) -> Vec<u8> {
    let mut k = RELATIONSHIPS_BY_DID_PREFIX.to_vec();
    k.extend_from_slice(did.as_bytes());
    k.push(b':');
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<Relationship, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("Relationship decode: {e}")))
}

/// Retrieve a relationship by id. `Ok(None)` if absent.
pub async fn get_relationship(
    primary: &KeyspaceHandle,
    id: Uuid,
) -> Result<Option<Relationship>, AppError> {
    let raw = primary.get_raw(primary_key(id)).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Store the row + write both secondary-index entries
/// (issuer + subject). Writes are best-effort-CAS-paired —
/// a crash between the primary write and the index writes
/// leaves the primary row visible to `get_relationship` and
/// invisible to per-DID list queries; the next list call's
/// orphan-tolerant walk handles this without operator
/// intervention.
pub async fn store_relationship(
    primary: &KeyspaceHandle,
    index: &KeyspaceHandle,
    rel: &Relationship,
) -> Result<(), AppError> {
    primary
        .insert(
            String::from_utf8(primary_key(rel.id)).expect("ascii key"),
            rel,
        )
        .await?;
    // Index entries store just the relationship id as the
    // value — the primary keyspace holds the body. Storing
    // the id explicitly (rather than relying on the key
    // suffix) keeps the value self-describing for tooling.
    let id_value = serde_json::json!({ "id": rel.id.to_string() });
    index
        .insert(
            String::from_utf8(index_key(&rel.issuer_did, rel.id)).expect("ascii key"),
            &id_value,
        )
        .await?;
    if rel.subject_did != rel.issuer_did {
        index
            .insert(
                String::from_utf8(index_key(&rel.subject_did, rel.id)).expect("ascii key"),
                &id_value,
            )
            .await?;
    }
    Ok(())
}

/// Delete the row + both index entries. Idempotent: deleting
/// an absent row is a no-op (matches the rest of the
/// workspace's storage helpers).
pub async fn delete_relationship(
    primary: &KeyspaceHandle,
    index: &KeyspaceHandle,
    id: Uuid,
) -> Result<(), AppError> {
    // Look up the row first so we know which index entries
    // to clear. If the primary row is absent the caller
    // path (route layer) should have 404'd already; we
    // still walk best-effort to clean up any orphan index
    // rows.
    if let Some(rel) = get_relationship(primary, id).await? {
        primary.remove(primary_key(id)).await?;
        index.remove(index_key(&rel.issuer_did, id)).await?;
        if rel.subject_did != rel.issuer_did {
            index.remove(index_key(&rel.subject_did, id)).await?;
        }
    } else {
        primary.remove(primary_key(id)).await?;
    }
    Ok(())
}

/// Find an existing relationship by VRC SHA-256 hash. Walks
/// the primary keyspace; small VTCs are fine (a Phase 5
/// scaling pass adds a hash-keyed secondary index if
/// needed). Used for idempotent publish: a second publish
/// of the same VRC body returns the existing id.
pub async fn find_by_hash(
    primary: &KeyspaceHandle,
    vrc_sha256: &str,
) -> Result<Option<Relationship>, AppError> {
    let pairs = primary
        .prefix_iter_raw(RELATIONSHIPS_PREFIX.to_vec())
        .await?;
    for (_k, v) in pairs {
        if let Ok(rel) = decode(&v)
            && rel.vrc_sha256 == vrc_sha256
        {
            return Ok(Some(rel));
        }
    }
    Ok(None)
}

/// List **every** relationship (full primary-keyspace scan). For the admin
/// connections-graph view, which needs the whole edge set at once. Communities
/// are small enough (and the graph view is admin-only) that an unpaginated scan
/// is acceptable here; the per-DID [`list_for_did`] stays the paginated path.
pub async fn list_all(primary: &KeyspaceHandle) -> Result<Vec<Relationship>, AppError> {
    let pairs = primary
        .prefix_iter_raw(RELATIONSHIPS_PREFIX.to_vec())
        .await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        match decode(&v) {
            Ok(rel) => out.push(rel),
            Err(e) => tracing::warn!(error = %e, "skipping unparseable relationship row"),
        }
    }
    Ok(out)
}

/// Paginated list of relationships where `did` is either
/// issuer or subject. Walks the secondary index, then loads
/// the primary rows lazily — orphan index entries (where the
/// primary row is missing) are silently skipped. Cursor signed
/// under `audit_key`, same pattern as other paginated listers.
pub async fn list_for_did(
    primary: &KeyspaceHandle,
    index: &KeyspaceHandle,
    audit_key: &AuditKey,
    did: &str,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<Relationship>, AppError> {
    let mut index_prefix = RELATIONSHIPS_BY_DID_PREFIX.to_vec();
    index_prefix.extend_from_slice(did.as_bytes());
    index_prefix.push(b':');
    let mut idx_pairs = index.prefix_iter_raw(index_prefix).await?;
    idx_pairs.sort_by(|(a, _), (b, _)| a.cmp(b));

    // Resolve each index entry to its primary row, dropping
    // orphans. The paginate helper expects `(key, bytes)`
    // pairs of the same shape it would see from a direct
    // prefix scan of the primary keyspace; we synthesise
    // that by re-using the index key (sortable by id) and
    // packing the primary row's bytes.
    let mut hydrated: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(idx_pairs.len());
    for (idx_key, _idx_val) in idx_pairs {
        // Extract the trailing UUID segment from the index key
        // — last `:`-delimited piece.
        let key_str = match std::str::from_utf8(&idx_key) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Some(id_str) = key_str.rsplit(':').next() else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(id_str) else {
            continue;
        };
        if let Some(raw) = primary.get_raw(primary_key(id)).await? {
            // P0.11: the prefix `relationships_by_did:<did>:` also matches a
            // *longer* DID that has `<did>` as a colon-delimited prefix —
            // `did:webvh:scid:host` vs `did:webvh:scid:host:acme` — because
            // `did:webvh` DIDs legitimately contain colons. Such a hydrated
            // row belongs to a different DID, so post-filter on the actual
            // edge endpoints before including it. Undecodable rows are skipped
            // (orphan-tolerant, same as a missing primary row).
            match decode(&raw) {
                Ok(rel) if rel.issuer_did == did || rel.subject_did == did => {
                    hydrated.push((idx_key, raw));
                }
                _ => {}
            }
        }
    }

    let snapshot_id: u64 = hydrated.len() as u64;
    paginate(hydrated, cursor, limit, &audit_key.key, snapshot_id, decode)
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

    async fn temp_kss() -> (KeyspaceHandle, KeyspaceHandle, AuditKey, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let primary = store.keyspace("relationships").unwrap();
        let index = store.keyspace("relationships_by_did").unwrap();
        let audit_key_ks = store.keyspace("audit_key").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
        let audit_key = key_store.active().await.unwrap();
        (primary, index, audit_key, dir)
    }

    fn fresh(issuer: &str, subject: &str) -> Relationship {
        let id = Uuid::new_v4();
        Relationship {
            id,
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            vrc_jsonld: serde_json::json!({
                "type": ["VerifiableCredential", "VerifiableRecognitionCredential"],
                "issuer": issuer,
                "credentialSubject": { "id": subject, "endorsement": { "type": "endorses" } }
            }),
            vrc_sha256: format!("{:x}", id.as_u128()),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn round_trip() {
        let (primary, index, _audit, _dir) = temp_kss().await;
        let rel = fresh("did:key:zA", "did:key:zB");
        store_relationship(&primary, &index, &rel).await.unwrap();
        let got = get_relationship(&primary, rel.id).await.unwrap().unwrap();
        assert_eq!(got, rel);
    }

    #[tokio::test]
    async fn list_all_returns_every_edge() {
        let (primary, index, _audit, _dir) = temp_kss().await;
        let r1 = fresh("did:key:zA", "did:key:zB");
        let r2 = fresh("did:key:zB", "did:key:zC");
        store_relationship(&primary, &index, &r1).await.unwrap();
        store_relationship(&primary, &index, &r2).await.unwrap();

        let all = list_all(&primary).await.unwrap();
        assert_eq!(all.len(), 2);
        let ids: std::collections::HashSet<_> = all.iter().map(|r| r.id).collect();
        assert!(ids.contains(&r1.id) && ids.contains(&r2.id));
    }

    #[tokio::test]
    async fn delete_clears_primary_and_index() {
        let (primary, index, _audit, _dir) = temp_kss().await;
        let rel = fresh("did:key:zA", "did:key:zB");
        store_relationship(&primary, &index, &rel).await.unwrap();
        delete_relationship(&primary, &index, rel.id).await.unwrap();
        assert!(get_relationship(&primary, rel.id).await.unwrap().is_none());
        // Index entries gone too.
        let pairs = index
            .prefix_iter_raw(RELATIONSHIPS_BY_DID_PREFIX.to_vec())
            .await
            .unwrap();
        assert!(pairs.is_empty());
    }

    #[tokio::test]
    async fn list_for_issuer_returns_issued() {
        let (primary, index, audit, _dir) = temp_kss().await;
        let r1 = fresh("did:key:zA", "did:key:zB");
        let r2 = fresh("did:key:zA", "did:key:zC");
        let r3 = fresh("did:key:zX", "did:key:zY"); // unrelated
        for r in [&r1, &r2, &r3] {
            store_relationship(&primary, &index, r).await.unwrap();
        }
        let page = list_for_did(&primary, &index, &audit, "did:key:zA", None, 10)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
        let dids: Vec<_> = page.items.iter().map(|r| r.id).collect();
        assert!(dids.contains(&r1.id));
        assert!(dids.contains(&r2.id));
    }

    #[tokio::test]
    async fn list_for_subject_returns_received() {
        let (primary, index, audit, _dir) = temp_kss().await;
        let r1 = fresh("did:key:zA", "did:key:zSubject");
        let r2 = fresh("did:key:zB", "did:key:zSubject");
        let r3 = fresh("did:key:zC", "did:key:zOther");
        for r in [&r1, &r2, &r3] {
            store_relationship(&primary, &index, r).await.unwrap();
        }
        let page = list_for_did(&primary, &index, &audit, "did:key:zSubject", None, 10)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
    }

    #[tokio::test]
    async fn list_paginates_with_cursor() {
        let (primary, index, audit, _dir) = temp_kss().await;
        for _ in 0..10 {
            let rel = fresh("did:key:zHub", &format!("did:key:z{}", Uuid::new_v4()));
            store_relationship(&primary, &index, &rel).await.unwrap();
        }
        let page1 = list_for_did(&primary, &index, &audit, "did:key:zHub", None, 3)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 3);
        let cursor_str = page1.next_cursor.as_ref().expect("more pages");
        let cursor = Cursor::decode(cursor_str, &audit.key).expect("decode cursor");
        let page2 = list_for_did(&primary, &index, &audit, "did:key:zHub", Some(&cursor), 3)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 3);
        // No overlap between pages.
        let ids1: std::collections::HashSet<_> = page1.items.iter().map(|r| r.id).collect();
        for r in &page2.items {
            assert!(!ids1.contains(&r.id));
        }
    }

    #[tokio::test]
    async fn find_by_hash_returns_existing_row() {
        let (primary, index, _audit, _dir) = temp_kss().await;
        let mut rel = fresh("did:key:zA", "did:key:zB");
        rel.vrc_sha256 = "deadbeef".into();
        store_relationship(&primary, &index, &rel).await.unwrap();
        let got = find_by_hash(&primary, "deadbeef").await.unwrap();
        assert_eq!(got.map(|r| r.id), Some(rel.id));
        let miss = find_by_hash(&primary, "feedface").await.unwrap();
        assert!(miss.is_none());
    }

    #[tokio::test]
    async fn list_does_not_leak_colon_prefix_colliding_did() {
        // P0.11: `did:webvh` DIDs contain colons, so the index scan for
        // `did:webvh:s:h` would otherwise also match the keys of
        // `did:webvh:s:h:x` (whose index keys share the scanned prefix),
        // leaking another member's relationship rows.
        let (primary, index, audit, _dir) = temp_kss().await;
        let short = fresh("did:webvh:s:h", "did:key:zPeer");
        let long = fresh("did:webvh:s:h:x", "did:key:zPeer2");
        store_relationship(&primary, &index, &short).await.unwrap();
        store_relationship(&primary, &index, &long).await.unwrap();

        // Querying the shorter DID must return only its own edge.
        let page = list_for_did(&primary, &index, &audit, "did:webvh:s:h", None, 10)
            .await
            .unwrap();
        let ids: Vec<_> = page.items.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![short.id], "must return only the exact DID's edge");
        assert!(
            !ids.contains(&long.id),
            "colon-extended DID's edge must not leak"
        );

        // …and the longer DID still finds its own edge.
        let page_long = list_for_did(&primary, &index, &audit, "did:webvh:s:h:x", None, 10)
            .await
            .unwrap();
        assert_eq!(
            page_long.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![long.id]
        );
    }

    #[tokio::test]
    async fn self_loop_writes_one_index_entry() {
        // Edge case: issuer == subject. We only write one
        // index entry so list_for_did returns the row once.
        let (primary, index, audit, _dir) = temp_kss().await;
        let rel = fresh("did:key:zSelf", "did:key:zSelf");
        store_relationship(&primary, &index, &rel).await.unwrap();
        let page = list_for_did(&primary, &index, &audit, "did:key:zSelf", None, 10)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "self-edge must list once, not twice");
    }
}
