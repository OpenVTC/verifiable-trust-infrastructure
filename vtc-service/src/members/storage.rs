//! CRUD helpers for [`super::Member`] over the `members` keyspace.

use vti_common::audit::AuditKey;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::{Disposition, Member};

/// Hard cap on the bytes-on-disk size of `Member.extensions`. The
/// route layer enforces this at write time (mirrors the
/// `CommunityProfile.extensions` rule from M0.7.1).
pub const MEMBER_EXTENSIONS_MAX_BYTES: usize = 16 * 1024;

/// The disposition value the join-approval flow writes by default
/// — [`Disposition::PolicyDefault`], which resolves to
/// `Tombstone` in Phase 1.
pub const DEFAULT_DEPARTURE_PREFERENCE: Disposition = Disposition::PolicyDefault;

const PREFIX: &[u8] = b"members:";

fn member_key(did: &str) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(did.as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<Member, AppError> {
    serde_json::from_slice(bytes).map_err(|e| AppError::Internal(format!("Member decode: {e}")))
}

/// Retrieve a member by DID. `Ok(None)` if absent.
pub async fn get_member(ks: &KeyspaceHandle, did: &str) -> Result<Option<Member>, AppError> {
    let raw = ks.get_raw(member_key(did)).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Store (create or overwrite) a member. Enforces the
/// `extensions` size cap.
pub async fn store_member(ks: &KeyspaceHandle, member: &Member) -> Result<(), AppError> {
    let extensions_bytes = serde_json::to_vec(&member.extensions)
        .map_err(|e| AppError::Internal(format!("Member extensions serialize: {e}")))?;
    if extensions_bytes.len() > MEMBER_EXTENSIONS_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "member.extensions exceeds {} bytes (got {})",
            MEMBER_EXTENSIONS_MAX_BYTES,
            extensions_bytes.len(),
        )));
    }
    ks.insert(
        String::from_utf8(member_key(&member.did)).expect("member key is ASCII"),
        member,
    )
    .await
}

/// Delete a member by DID. Idempotent.
pub async fn delete_member(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.remove(member_key(did)).await
}

/// Return every member. Whole-keyspace walk — use
/// [`list_members_paginated`] from user-facing routes.
pub async fn list_members(ks: &KeyspaceHandle) -> Result<Vec<Member>, AppError> {
    let raw = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match decode(&v) {
            Ok(member) => out.push(member),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable member row"),
        }
    }
    Ok(out)
}

/// Paginated list. Cursor signed under `audit_key`.
pub async fn list_members_paginated(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<Member>, AppError> {
    let mut pairs = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
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

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let ks = store.keyspace("members").expect("ks");
        (ks, dir)
    }

    fn fresh(did: &str) -> Member {
        Member::fresh(did)
    }

    #[tokio::test]
    async fn round_trip_through_keyspace() {
        let (ks, _dir) = temp_ks().await;
        let m = fresh("did:key:zMember1");
        store_member(&ks, &m).await.unwrap();
        let got = get_member(&ks, "did:key:zMember1").await.unwrap().unwrap();
        assert_eq!(got.did, m.did);
        assert_eq!(got.departure_preference, Disposition::PolicyDefault);
        assert!(!got.publish_consent);
        assert!(got.status_list_index.is_none());
    }

    #[tokio::test]
    async fn list_returns_every_member() {
        let (ks, _dir) = temp_ks().await;
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_member(&ks, &fresh(did)).await.unwrap();
        }
        let list = list_members(&ks).await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        store_member(&ks, &fresh("did:key:zD")).await.unwrap();
        delete_member(&ks, "did:key:zD").await.unwrap();
        delete_member(&ks, "did:key:zD").await.unwrap();
        assert!(get_member(&ks, "did:key:zD").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn extensions_size_limit_enforced() {
        let (ks, _dir) = temp_ks().await;
        let big = "a".repeat(MEMBER_EXTENSIONS_MAX_BYTES + 1);
        let mut m = fresh("did:key:zBig");
        m.extensions = serde_json::json!(big);
        let err = store_member(&ks, &m).await.expect_err("size limit hit");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn paginated_walks_members() {
        let (ks, _dir) = temp_ks().await;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let audit_key = AuditKeyStore::new(store.keyspace("audit_key").unwrap())
            .ensure_initial(&[0xAB; 32])
            .await
            .unwrap();

        for did in [
            "did:key:zA",
            "did:key:zB",
            "did:key:zC",
            "did:key:zD",
            "did:key:zE",
        ] {
            store_member(&ks, &fresh(did)).await.unwrap();
        }
        let page1 = list_members_paginated(&ks, &audit_key, None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        assert_eq!(page1.items[0].did, "did:key:zA");
        assert_eq!(page1.items[1].did, "did:key:zB");
    }

    #[test]
    fn member_round_trips_through_json_with_camel_case_fields() {
        let m = Member {
            did: "did:key:zX".into(),
            joined_at: Utc::now(),
            status_list_index: Some(42),
            publish_consent: true,
            departure_preference: Disposition::Historical,
            current_vmc_id: Some("vmc-1".into()),
            current_role_vec_id: Some("vec-1".into()),
            extensions: serde_json::json!({ "team": "platform" }),
            removed_at: None,
            personhood: false,
            personhood_asserted_at: None,
            reciprocal_vc_id: None,
            accepted_at: None,
        };
        let json = serde_json::to_value(&m).unwrap();
        assert!(json["joinedAt"].is_string());
        assert_eq!(json["statusListIndex"], 42);
        assert_eq!(json["publishConsent"], true);
        assert_eq!(json["departurePreference"], "historical");
        assert_eq!(json["currentVmcId"], "vmc-1");
        assert_eq!(json["currentRoleVecId"], "vec-1");
        assert_eq!(json["personhood"], false);
        assert!(json["personhoodAssertedAt"].is_null());
        let parsed: Member = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn member_round_trips_with_personhood_asserted() {
        let now = Utc::now();
        let m = Member {
            did: "did:key:zPerson".into(),
            joined_at: now,
            status_list_index: None,
            publish_consent: false,
            departure_preference: Disposition::PolicyDefault,
            current_vmc_id: None,
            current_role_vec_id: None,
            extensions: serde_json::Value::Null,
            removed_at: None,
            personhood: true,
            personhood_asserted_at: Some(now),
            reciprocal_vc_id: None,
            accepted_at: None,
        };
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["personhood"], true);
        assert!(json["personhoodAssertedAt"].is_string());
        let parsed: Member = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn member_backward_compat_pre_phase4_row_deserialises() {
        // Hand-crafted JSON from before M4.1 — no `personhood`
        // or `personhoodAssertedAt` keys. Round-trips with the
        // new fields defaulted (`false`, `None`).
        let raw = serde_json::json!({
            "did": "did:key:zLegacy",
            "joinedAt": "2026-01-15T00:00:00Z",
            "publishConsent": false,
            "departurePreference": "tombstone",
            "extensions": null
        });
        let parsed: Member = serde_json::from_value(raw).expect("legacy row deserialises");
        assert_eq!(parsed.did, "did:key:zLegacy");
        assert!(!parsed.personhood);
        assert!(parsed.personhood_asserted_at.is_none());
    }

    #[test]
    fn disposition_default_is_policy_default() {
        let m = Member::fresh("did:key:z");
        assert_eq!(m.departure_preference, Disposition::PolicyDefault);
        assert_eq!(m.departure_preference.resolve(), Disposition::Tombstone);
    }

    #[test]
    fn disposition_purge_resolves_to_itself() {
        assert_eq!(Disposition::Purge.resolve(), Disposition::Purge);
        assert_eq!(Disposition::Tombstone.resolve(), Disposition::Tombstone);
        assert_eq!(Disposition::Historical.resolve(), Disposition::Historical);
    }
}
