//! CRUD helpers for [`Policy`] rows and the per-purpose active
//! pointer.
//!
//! Two keyspaces:
//! - `policies:<uuid>` — every uploaded revision, keyed by UUID.
//!   Survives archival; rows are only ever deleted on operator
//!   action (M2.3.1's purge path lands in a follow-up milestone).
//! - `active_policies:<purpose>` — one row per [`PolicyPurpose`]
//!   pointing at the currently-active [`Policy::id`] for that
//!   purpose. M2.3's activate endpoint flips this pointer
//!   atomically; M2.6 / M2.7 / M2.13 read it to pick which compiled
//!   module to feed to the harness.
//!
//! ## Why two keyspaces instead of one
//!
//! Plan §D3: keeping the active pointer in its own keyspace lets the
//! activation flow do a single atomic put-of-a-tiny-value instead of
//! rewriting the entire Policy row (which carries the Rego source).
//! It also matches the boot-time recompile loop, which only needs
//! to walk the active-pointer keyspace (9 entries max) — not the
//! full revision history.

use chrono::Utc;
use uuid::Uuid;
use vti_common::audit::AuditKey;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::model::{Policy, PolicyPurpose};

const POLICY_PREFIX: &[u8] = b"policies:";
const ACTIVE_PREFIX: &[u8] = b"active_policies:";

fn policy_key(id: Uuid) -> Vec<u8> {
    let mut k = POLICY_PREFIX.to_vec();
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

fn active_key(purpose: PolicyPurpose) -> Vec<u8> {
    let mut k = ACTIVE_PREFIX.to_vec();
    k.extend_from_slice(purpose.as_str().as_bytes());
    k
}

fn decode(bytes: &[u8]) -> Result<Policy, AppError> {
    serde_json::from_slice(bytes).map_err(|e| AppError::Internal(format!("Policy decode: {e}")))
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

/// Retrieve a policy by id. `Ok(None)` if absent.
pub async fn get_policy(ks: &KeyspaceHandle, id: Uuid) -> Result<Option<Policy>, AppError> {
    let raw = ks.get_raw(policy_key(id)).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Persist a policy row (create or overwrite by id).
///
/// The route layer (M2.3) is responsible for the version-bump
/// invariant — this helper never edits `version`. Callers are
/// expected to set `version = next_version_for(purpose)` before
/// calling [`store_policy`].
pub async fn store_policy(ks: &KeyspaceHandle, policy: &Policy) -> Result<(), AppError> {
    ks.insert(
        String::from_utf8(policy_key(policy.id)).expect("policy key is ASCII"),
        policy,
    )
    .await
}

/// Delete a policy row. Idempotent.
///
/// Does **not** clear the active pointer — a policy can only be
/// deleted when no purpose points at it, but the invariant lives
/// at the route layer (M2.3) so the storage helper stays
/// unconditionally usable from boot-time fixups.
pub async fn delete_policy(ks: &KeyspaceHandle, id: Uuid) -> Result<(), AppError> {
    ks.remove(policy_key(id)).await
}

/// Return every policy row. Whole-keyspace walk — prefer
/// [`list_policies_paginated`] from user-facing routes.
pub async fn list_policies(ks: &KeyspaceHandle) -> Result<Vec<Policy>, AppError> {
    let raw = ks.prefix_iter_raw(POLICY_PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match decode(&v) {
            Ok(p) => out.push(p),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable policy row"),
        }
    }
    Ok(out)
}

/// Paginated walk over `policies:*`. Cursor signed under `audit_key`
/// so a captured cursor can't be replayed against an evicted page
/// boundary. Mirrors the pattern `list_members_paginated` uses.
pub async fn list_policies_paginated(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<Policy>, AppError> {
    let mut pairs = ks.prefix_iter_raw(POLICY_PREFIX.to_vec()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    let snapshot_id: u64 = pairs.len() as u64;
    paginate(pairs, cursor, limit, &audit_key.key, snapshot_id, decode)
}

/// Highest `version` previously recorded for `purpose`. Returns `0`
/// when no rows exist for the purpose (so the next upload will land
/// as `version = 1`). M2.3's upload endpoint adds one.
pub async fn max_version_for(ks: &KeyspaceHandle, purpose: PolicyPurpose) -> Result<u32, AppError> {
    let rows = list_policies(ks).await?;
    Ok(rows
        .into_iter()
        .filter(|p| p.purpose == purpose)
        .map(|p| p.version)
        .max()
        .unwrap_or(0))
}

// ---------------------------------------------------------------------------
// Active-pointer CRUD
// ---------------------------------------------------------------------------

/// Get the active policy id for `purpose`. `Ok(None)` if no policy
/// is currently active for that purpose (boot before defaults
/// load, or after an operator explicitly unsets via M2.3.x).
pub async fn get_active_policy_id(
    ks: &KeyspaceHandle,
    purpose: PolicyPurpose,
) -> Result<Option<Uuid>, AppError> {
    let raw = ks.get_raw(active_key(purpose)).await?;
    match raw {
        Some(bytes) => {
            let s = std::str::from_utf8(&bytes)
                .map_err(|e| AppError::Internal(format!("active policy pointer not utf-8: {e}")))?;
            let id = Uuid::parse_str(s)
                .map_err(|e| AppError::Internal(format!("active policy pointer not uuid: {e}")))?;
            Ok(Some(id))
        }
        None => Ok(None),
    }
}

/// Set the active policy id for `purpose`. Overwrites any prior
/// pointer.
///
/// The route layer (M2.3 activate) is responsible for:
/// 1. Verifying the target policy exists + `purpose` matches.
/// 2. Stamping [`Policy::activated_at`] on the new row.
/// 3. Emitting `PolicyActivated` audit (M2.17).
///
/// This helper just persists the pointer.
pub async fn set_active_policy_id(
    ks: &KeyspaceHandle,
    purpose: PolicyPurpose,
    id: Uuid,
) -> Result<(), AppError> {
    ks.insert_raw(active_key(purpose), id.to_string().into_bytes())
        .await
}

/// Clear the active pointer for `purpose`. Idempotent. After this,
/// [`get_active_policy_id`] returns `Ok(None)`. Phase 2's M2.3
/// activate flow does **not** use this — it overwrites the pointer
/// rather than clearing it — but boot-time fixup paths
/// (e.g. archive-the-last-revision-of-this-purpose) need a way to
/// strand a purpose unmapped.
pub async fn clear_active_policy_id(
    ks: &KeyspaceHandle,
    purpose: PolicyPurpose,
) -> Result<(), AppError> {
    ks.remove(active_key(purpose)).await
}

// ---------------------------------------------------------------------------
// Construction helpers
// ---------------------------------------------------------------------------

/// Build a fresh [`Policy`] row from an upload-time tuple.
/// `version` is left to the caller (typically `max_version_for(…) +
/// 1`) so this helper doesn't open a TOCTOU window with concurrent
/// uploads. M2.3 serialises uploads behind a per-purpose lock.
pub fn new_policy(
    purpose: PolicyPurpose,
    rego_source: String,
    sha256: [u8; 32],
    author_did: String,
    version: u32,
) -> Policy {
    Policy {
        id: Uuid::new_v4(),
        purpose,
        rego_source,
        sha256,
        activated_at: None,
        author_did,
        created_at: Utc::now(),
        version,
        name: None,
        description: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use vti_common::audit::AuditKeyStore;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_keyspaces() -> (KeyspaceHandle, KeyspaceHandle, AuditKey, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let policies_ks = store.keyspace("policies").expect("policies ks");
        let active_ks = store.keyspace("active_policies").expect("active ks");
        let audit_key = AuditKeyStore::new(store.keyspace("audit_key").unwrap())
            .ensure_initial(&[0xAA; 32])
            .await
            .expect("audit key");
        (policies_ks, active_ks, audit_key, dir)
    }

    fn sample(purpose: PolicyPurpose, version: u32, marker: u8) -> Policy {
        let src = format!("package vtc.test\nimport rego.v1\n\n# v{version}-marker:{marker}\n");
        let sha: [u8; 32] = Sha256::digest(src.as_bytes()).into();
        new_policy(purpose, src, sha, "did:key:zAdmin".into(), version)
    }

    /// Round-trip every PolicyPurpose through the policies keyspace.
    /// Acceptance bullet 1 from M2.2.1.
    #[tokio::test]
    async fn round_trip_every_purpose() {
        let (policies_ks, _active_ks, _ak, _dir) = temp_keyspaces().await;
        for (i, purpose) in PolicyPurpose::ALL.into_iter().enumerate() {
            let p = sample(purpose, 1, i as u8);
            store_policy(&policies_ks, &p).await.unwrap();
            let got = get_policy(&policies_ks, p.id).await.unwrap().unwrap();
            assert_eq!(got, p, "round-trip mismatch for {purpose:?}");
        }
        // All nine rows visible via list.
        let all = list_policies(&policies_ks).await.unwrap();
        assert_eq!(all.len(), PolicyPurpose::ALL.len());
    }

    /// `delete_policy` is idempotent and stops `get_policy` finding
    /// the row. Lifecycle invariant for the M2.3 archive path.
    #[tokio::test]
    async fn delete_is_idempotent() {
        let (policies_ks, _active_ks, _ak, _dir) = temp_keyspaces().await;
        let p = sample(PolicyPurpose::Join, 1, 0);
        store_policy(&policies_ks, &p).await.unwrap();
        delete_policy(&policies_ks, p.id).await.unwrap();
        delete_policy(&policies_ks, p.id).await.unwrap();
        assert!(get_policy(&policies_ks, p.id).await.unwrap().is_none());
    }

    /// `max_version_for` scopes its query to a single purpose so
    /// concurrent uploads to different purposes don't collide on
    /// version numbers.
    #[tokio::test]
    async fn max_version_is_purpose_scoped() {
        let (policies_ks, _active_ks, _ak, _dir) = temp_keyspaces().await;
        store_policy(&policies_ks, &sample(PolicyPurpose::Join, 1, 0))
            .await
            .unwrap();
        store_policy(&policies_ks, &sample(PolicyPurpose::Join, 2, 1))
            .await
            .unwrap();
        store_policy(&policies_ks, &sample(PolicyPurpose::Removal, 5, 0))
            .await
            .unwrap();

        assert_eq!(
            max_version_for(&policies_ks, PolicyPurpose::Join)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            max_version_for(&policies_ks, PolicyPurpose::Removal)
                .await
                .unwrap(),
            5
        );
        assert_eq!(
            max_version_for(&policies_ks, PolicyPurpose::Personhood)
                .await
                .unwrap(),
            0,
            "purpose with no rows must return 0"
        );
    }

    /// Paginated walk returns rows in stable order and offers a
    /// cursor when the page is full. Acceptance bullet 2 from
    /// M2.2.1.
    #[tokio::test]
    async fn paginated_walks_policies() {
        let (policies_ks, _active_ks, audit_key, _dir) = temp_keyspaces().await;
        for i in 0..5 {
            let mut p = sample(PolicyPurpose::Join, (i + 1) as u32, i as u8);
            // Deterministic ids so the sort + cursor are reproducible
            // across runs.
            p.id = Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0000 + i as u128);
            store_policy(&policies_ks, &p).await.unwrap();
        }
        let page = list_policies_paginated(&policies_ks, &audit_key, None, 2)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(
            page.next_cursor.is_some(),
            "expected cursor for partial page"
        );
    }

    /// Active-pointer set + get round-trips per purpose, and unset
    /// purposes return `None`. Acceptance bullet 3 from M2.2.1.
    #[tokio::test]
    async fn active_pointer_set_get_round_trips() {
        let (_policies_ks, active_ks, _ak, _dir) = temp_keyspaces().await;
        let join_id = Uuid::new_v4();
        let removal_id = Uuid::new_v4();

        // Initially every purpose is unmapped.
        for purpose in PolicyPurpose::ALL {
            assert!(
                get_active_policy_id(&active_ks, purpose)
                    .await
                    .unwrap()
                    .is_none(),
                "purpose {purpose:?} should start unmapped"
            );
        }

        set_active_policy_id(&active_ks, PolicyPurpose::Join, join_id)
            .await
            .unwrap();
        set_active_policy_id(&active_ks, PolicyPurpose::Removal, removal_id)
            .await
            .unwrap();
        assert_eq!(
            get_active_policy_id(&active_ks, PolicyPurpose::Join)
                .await
                .unwrap(),
            Some(join_id)
        );
        assert_eq!(
            get_active_policy_id(&active_ks, PolicyPurpose::Removal)
                .await
                .unwrap(),
            Some(removal_id)
        );
        // Other purposes still unmapped.
        assert!(
            get_active_policy_id(&active_ks, PolicyPurpose::Personhood)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Reassigning the pointer overwrites in place — no orphaned
    /// pointer rows.
    #[tokio::test]
    async fn active_pointer_overwrites_in_place() {
        let (_policies_ks, active_ks, _ak, _dir) = temp_keyspaces().await;
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        set_active_policy_id(&active_ks, PolicyPurpose::Join, first)
            .await
            .unwrap();
        set_active_policy_id(&active_ks, PolicyPurpose::Join, second)
            .await
            .unwrap();
        assert_eq!(
            get_active_policy_id(&active_ks, PolicyPurpose::Join)
                .await
                .unwrap(),
            Some(second)
        );
    }

    /// `clear_active_policy_id` is idempotent and strands the
    /// purpose unmapped.
    #[tokio::test]
    async fn active_pointer_clear_is_idempotent() {
        let (_policies_ks, active_ks, _ak, _dir) = temp_keyspaces().await;
        let id = Uuid::new_v4();
        set_active_policy_id(&active_ks, PolicyPurpose::Removal, id)
            .await
            .unwrap();
        clear_active_policy_id(&active_ks, PolicyPurpose::Removal)
            .await
            .unwrap();
        clear_active_policy_id(&active_ks, PolicyPurpose::Removal)
            .await
            .unwrap();
        assert!(
            get_active_policy_id(&active_ks, PolicyPurpose::Removal)
                .await
                .unwrap()
                .is_none()
        );
    }
}
