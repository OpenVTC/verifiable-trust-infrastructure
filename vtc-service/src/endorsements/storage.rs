//! CRUD helpers for [`super::Endorsement`] over the
//! `endorsements:` keyspace.

use uuid::Uuid;
use vti_common::audit::AuditKey;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::Endorsement;

pub const ENDORSEMENTS_PREFIX: &[u8] = b"endorsements:";

fn key(id: Uuid) -> Vec<u8> {
    let mut k = ENDORSEMENTS_PREFIX.to_vec();
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<Endorsement, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("Endorsement decode: {e}")))
}

pub async fn get_endorsement(
    ks: &KeyspaceHandle,
    id: Uuid,
) -> Result<Option<Endorsement>, AppError> {
    let raw = ks.get_raw(key(id)).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

pub async fn store_endorsement(ks: &KeyspaceHandle, end: &Endorsement) -> Result<(), AppError> {
    ks.insert(String::from_utf8(key(end.id)).expect("ascii key"), end)
        .await
}

/// Hard-delete the row. Used only by tests + the (unlikely)
/// row-cleanup admin path — the canonical revoke uses
/// [`mark_revoked`] which preserves the audit trail.
pub async fn delete_endorsement(ks: &KeyspaceHandle, id: Uuid) -> Result<(), AppError> {
    ks.remove(key(id)).await
}

/// Stamp `revoked_at = now` on the row + persist. Returns the
/// updated row; `Ok(None)` if the id is absent.
pub async fn mark_revoked(ks: &KeyspaceHandle, id: Uuid) -> Result<Option<Endorsement>, AppError> {
    let Some(mut row) = get_endorsement(ks, id).await? else {
        return Ok(None);
    };
    if row.revoked_at.is_none() {
        row.revoked_at = Some(chrono::Utc::now());
        store_endorsement(ks, &row).await?;
    }
    Ok(Some(row))
}

/// Count endorsements of `endorsement_type` that haven't been
/// revoked. Used by the type-registry delete path: refuses
/// `DELETE /v1/endorsement-types/{uri}` when at least one
/// live endorsement still references the type.
pub async fn count_live_by_type(
    ks: &KeyspaceHandle,
    endorsement_type: &str,
) -> Result<usize, AppError> {
    let pairs = ks.prefix_iter_raw(ENDORSEMENTS_PREFIX.to_vec()).await?;
    let mut count = 0;
    for (_k, v) in pairs {
        if let Ok(row) = decode(&v)
            && row.endorsement_type == endorsement_type
            && !row.is_revoked()
        {
            count += 1;
        }
    }
    Ok(count)
}

/// Every endorsement of `endorsement_type` naming `subject_did`, revoked ones
/// included, oldest first. A full scan: the keyspace has no subject index, and
/// the callers — granting a role, departing, counting a vetting statement —
/// are rare next to the size of a community's endorsement set.
pub async fn endorsements_for_subject(
    ks: &KeyspaceHandle,
    subject_did: &str,
    endorsement_type: &str,
) -> Result<Vec<Endorsement>, AppError> {
    let pairs = ks.prefix_iter_raw(ENDORSEMENTS_PREFIX.to_vec()).await?;
    let mut rows: Vec<Endorsement> = pairs
        .into_iter()
        .filter_map(|(_k, v)| decode(&v).ok())
        .filter(|row| row.subject_did == subject_did && row.endorsement_type == endorsement_type)
        .collect();
    rows.sort_by_key(|row| row.created_at);
    Ok(rows)
}

pub async fn list_endorsements(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<Endorsement>, AppError> {
    let mut pairs = ks.prefix_iter_raw(ENDORSEMENTS_PREFIX.to_vec()).await?;
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
        let ks = store.keyspace("endorsements").unwrap();
        let audit_key_ks = store.keyspace("audit_key").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
        let audit_key = key_store.active().await.unwrap();
        (ks, audit_key, dir)
    }

    fn fresh(end_type: &str, issuer: &str, subject: &str) -> Endorsement {
        let id = Uuid::new_v4();
        Endorsement {
            id,
            endorsement_type: end_type.into(),
            issuer_did: issuer.into(),
            subject_did: subject.into(),
            claim: serde_json::json!({ "level": "expert" }),
            status_list_index: 0,
            vec_id: format!("urn:uuid:{id}"),
            created_at: Utc::now(),
            revoked_at: None,
            valid_until: None,
        }
    }

    #[tokio::test]
    async fn endorsements_for_subject_filters_by_subject_and_type() {
        let (ks, _audit, _dir) = temp_ks().await;
        let mine = fresh("CommunityRole", "did:webvh:vtc", "did:key:zA");
        let other_type = fresh("https://example.com/v1/x", "did:webvh:vtc", "did:key:zA");
        let other_subject = fresh("CommunityRole", "did:webvh:vtc", "did:key:zB");
        for row in [&mine, &other_type, &other_subject] {
            store_endorsement(&ks, row).await.unwrap();
        }
        mark_revoked(&ks, mine.id).await.unwrap();
        let rows = endorsements_for_subject(&ks, "did:key:zA", "CommunityRole")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "revoked rows are returned too");
        assert_eq!(rows[0].id, mine.id);
        assert!(rows[0].is_revoked());
    }

    #[test]
    fn a_row_written_before_valid_until_still_decodes() {
        let row = fresh("https://example.com/v1/x", "did:webvh:vtc", "did:key:zS");
        let mut v = serde_json::to_value(&row).unwrap();
        assert!(v.get("validUntil").is_none());
        v.as_object_mut().unwrap().remove("revokedAt");
        let back: Endorsement = serde_json::from_value(v).unwrap();
        assert_eq!(back.valid_until, None);
    }

    #[tokio::test]
    async fn round_trip() {
        let (ks, _audit, _dir) = temp_ks().await;
        let end = fresh(
            "https://example.com/v1/skills/rust",
            "did:webvh:vtc",
            "did:key:zS",
        );
        store_endorsement(&ks, &end).await.unwrap();
        let got = get_endorsement(&ks, end.id).await.unwrap().unwrap();
        assert_eq!(got, end);
    }

    #[tokio::test]
    async fn mark_revoked_sets_timestamp() {
        let (ks, _audit, _dir) = temp_ks().await;
        let end = fresh("https://example.com/v1/x", "did:webvh:vtc", "did:key:zS");
        store_endorsement(&ks, &end).await.unwrap();
        let updated = mark_revoked(&ks, end.id).await.unwrap().unwrap();
        assert!(updated.revoked_at.is_some());
        // Idempotent — revoking twice doesn't clobber the
        // timestamp.
        let updated2 = mark_revoked(&ks, end.id).await.unwrap().unwrap();
        assert_eq!(updated.revoked_at, updated2.revoked_at);
    }

    #[tokio::test]
    async fn mark_revoked_returns_none_for_unknown_id() {
        let (ks, _audit, _dir) = temp_ks().await;
        let missing = mark_revoked(&ks, Uuid::new_v4()).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn count_live_by_type_excludes_revoked() {
        let (ks, _audit, _dir) = temp_ks().await;
        let t = "https://example.com/v1/skills/rust";
        let e1 = fresh(t, "did:webvh:vtc", "did:key:zA");
        let e2 = fresh(t, "did:webvh:vtc", "did:key:zB");
        let e3 = fresh(
            "https://example.com/v1/skills/python",
            "did:webvh:vtc",
            "did:key:zC",
        );
        store_endorsement(&ks, &e1).await.unwrap();
        store_endorsement(&ks, &e2).await.unwrap();
        store_endorsement(&ks, &e3).await.unwrap();
        // 2 live of type t.
        assert_eq!(count_live_by_type(&ks, t).await.unwrap(), 2);
        // Revoke one.
        mark_revoked(&ks, e1.id).await.unwrap();
        assert_eq!(count_live_by_type(&ks, t).await.unwrap(), 1);
        // Other type counts independently.
        assert_eq!(
            count_live_by_type(&ks, "https://example.com/v1/skills/python")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn list_paginates() {
        let (ks, audit, _dir) = temp_ks().await;
        for _ in 0..7 {
            let e = fresh("https://example.com/v1/x", "did:webvh:vtc", "did:key:z");
            store_endorsement(&ks, &e).await.unwrap();
        }
        let p1 = list_endorsements(&ks, &audit, None, 3).await.unwrap();
        assert_eq!(p1.items.len(), 3);
        assert!(p1.next_cursor.is_some());
        let cursor = Cursor::decode(p1.next_cursor.as_ref().unwrap(), &audit.key).unwrap();
        let p2 = list_endorsements(&ks, &audit, Some(&cursor), 10)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 4);
        assert!(p2.next_cursor.is_none());
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (ks, _audit, _dir) = temp_ks().await;
        let id = Uuid::new_v4();
        delete_endorsement(&ks, id).await.unwrap();
        delete_endorsement(&ks, id).await.unwrap();
        assert!(get_endorsement(&ks, id).await.unwrap().is_none());
    }
}
