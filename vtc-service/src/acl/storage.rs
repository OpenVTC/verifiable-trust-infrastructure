//! CRUD helpers for [`super::VtcAclEntry`].
//!
//! Mirrors the shape of `vti_common::acl`'s helper set but speaks
//! the VTC's role taxonomy. The on-disk key prefix (`acl:`) is
//! unchanged, so a vtc-service binary built against this module
//! can read rows that Phase 0 wrote via `vti_common::acl::*`
//! without an explicit migration.
//!
//! ## What's intentionally missing
//!
//! - `check_acl` / `check_acl_full` — those return a
//!   `vti_common::acl::Role`. Auth-time role checks still flow
//!   through those helpers; vtc-service's PR-1 keeps consuming
//!   them as-is and only the storage path reshapes. Phase-2
//!   tightens the auth helpers to use `VtcRole` once the
//!   downstream session / passkey code is ready for the shift.
//! - `validate_role_assignment` — same reason. Phase-2.
//!
//! ## Pagination
//!
//! [`list_acl_entries_paginated`] returns a
//! [`vti_common::pagination::Paginated`] for the GET-list
//! endpoints under §M1.4. The unpaginated
//! [`list_acl_entries`] keeps the call sites that walked the
//! full keyspace (audit, emergency-bootstrap cleanup) working
//! without rewriting them.

use vti_common::acl::Role;
use vti_common::audit::AuditKey;
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::entry::{VtcAclEntry, decode, iter};

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Map a stored entry to the `vti_common::acl::Role` the JWT/session layer
/// understands.
///
/// **Any administrative role** signs in (`vtc-admin-roles.md` §6): a
/// moderator, an auditor or an approver reaches the console as well as a
/// community administrator. What each may then *do* is never read from the
/// session — every gate asks the entry's capabilities at execution time
/// ([`super::VtcAclEntry::can`], [`require_capability`]). So the session role
/// is only "an administrator of some kind", and is `Admin` for all of them.
///
/// An entry with no administrative role is refused with a clean `Forbidden`,
/// whatever its community role — `member`, `issuer` and the community role
/// `admin` with no administrative authority alike. Fails closed, and the
/// message carries neither serde internals nor the role name (this is consumed
/// on the unauthenticated `/auth/challenge` path).
pub fn auth_role_for(entry: &VtcAclEntry) -> Result<Role, AppError> {
    if entry.admin.is_administrator() {
        Ok(Role::Admin)
    } else {
        Err(AppError::Forbidden(
            "DID is not permitted to authenticate on this VTC".into(),
        ))
    }
}

/// VTC analogue of `vti_common::acl::check_acl_full`: resolve a DID's auth
/// role from the VTC ACL.
///
/// **Use this — not `vti_common::acl::check_acl[_full]` — for every
/// auth-time ACL gate on the VTC store.** This decoder never 500s on a VTC
/// role; it returns a clean `Forbidden` for absent / expired / non-administrator
/// rows. P0.16.
///
/// The context list it returns is always empty: a VTC entry holds no contexts
/// (**VTI-VTC-010**). That makes every administrator's session claims read as
/// unscoped to the shared `vti_common` helpers — which is why **no gate in this
/// service may be a claims check**. Each operation asks the capability it needs
/// of the signer's live entry ([`require_capability`]).
pub async fn resolve_auth_role(
    acl_ks: &KeyspaceHandle,
    did: &str,
) -> Result<(Role, Vec<String>), AppError> {
    let entry = get_acl_entry(acl_ks, did)
        .await?
        .ok_or_else(|| AppError::Forbidden(format!("DID not in ACL: {did}")))?;
    if entry.is_expired(now_epoch()) {
        return Err(AppError::Forbidden(format!("ACL entry expired: {did}")));
    }
    let role = auth_role_for(&entry)?;
    Ok((role, Vec::new()))
}

/// Read `did`'s live entry and require it to hold `cap` at `resource`
/// (`None` = community-wide). **The** gate every administrative operation
/// goes through (**VTI-ACL-030**, **-034**, **-036**): read now, never from a
/// session or credential summarising it.
///
/// A missing, expired or insufficient entry is `Forbidden`, naming the
/// capability so the operator knows which grant is missing.
pub async fn require_capability(
    acl_ks: &KeyspaceHandle,
    did: &str,
    cap: super::Capability,
    resource: Option<&super::ResourceQualifier>,
) -> Result<VtcAclEntry, AppError> {
    let entry = get_acl_entry(acl_ks, did).await?;
    match entry {
        Some(e) if e.can(cap, resource) => Ok(e),
        _ => Err(capability_refusal(did, cap, resource)),
    }
}

/// [`require_capability`] at any qualifier.
pub async fn require_any_capability(
    acl_ks: &KeyspaceHandle,
    did: &str,
    cap: super::Capability,
) -> Result<VtcAclEntry, AppError> {
    let entry = get_acl_entry(acl_ks, did).await?;
    match entry {
        Some(e) if e.can_any(cap) => Ok(e),
        _ => Err(capability_refusal(did, cap, None)),
    }
}

/// The refusal for a missing capability.
pub fn capability_refusal(
    did: &str,
    cap: super::Capability,
    resource: Option<&super::ResourceQualifier>,
) -> AppError {
    let at = resource.map(|r| format!(" at {r}")).unwrap_or_default();
    AppError::Forbidden(format!(
        "{did} does not hold {cap}{at} — this operation needs it (VTI-ACL-030). An \
         administrator holding vtc.roles.assign can grant it with acl/update"
    ))
}

/// Retrieve an ACL entry by DID. `Ok(None)` if absent.
pub async fn get_acl_entry(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<VtcAclEntry>, AppError> {
    let key = acl_key(did);
    let raw = ks.get_raw(key.as_bytes()).await?;
    match raw {
        Some(bytes) => {
            let mut entry = decode(&bytes)?;
            // A custom role's ceiling is its definition as stored now
            // (VTI-ACL-011: none stored, nothing conferred).
            super::roles::resolve(ks, &mut entry).await?;
            Ok(Some(entry))
        }
        None => Ok(None),
    }
}

/// Store (create or overwrite) an ACL entry.
pub async fn store_acl_entry(ks: &KeyspaceHandle, entry: &VtcAclEntry) -> Result<(), AppError> {
    ks.insert(acl_key(&entry.did), entry).await?;
    if !entry.resource_grants.is_empty() {
        super::resource_grant::index_holder(ks, &entry.did, true).await?;
    }
    // Authority moved: open console streams re-check their callers' readable
    // topics before their next byte (`crate::admin_events`).
    crate::admin_events::notify_authority();
    Ok(())
}

/// Delete an ACL entry by DID. Idempotent — `Ok(())` whether the
/// row existed or not.
///
/// The resource grants the entry held go with it — they confer nothing
/// without a live entry (**VTI-ACL-037**) — and are kept aside for the
/// git-namespace lifecycle, which records each revocation and orphans what the
/// subject owned alone ([`super::resource_grant::keep_departed`]).
pub async fn delete_acl_entry(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    if let Some(bytes) = ks.get_raw(acl_key(did).as_bytes()).await?
        && let Ok(entry) = decode(&bytes)
        && !entry.resource_grants.is_empty()
    {
        super::resource_grant::keep_departed(ks, did, &entry.resource_grants).await?;
    }
    ks.remove(acl_key(did)).await?;
    super::resource_grant::index_holder(ks, did, false).await?;
    crate::admin_events::notify_authority();
    Ok(())
}

/// Return every ACL entry in the keyspace. Unbounded — intended
/// for whole-keyspace operations like audit emission +
/// emergency-bootstrap cleanup, not for user-facing list
/// endpoints. Use [`list_acl_entries_paginated`] for those.
pub async fn list_acl_entries(ks: &KeyspaceHandle) -> Result<Vec<VtcAclEntry>, AppError> {
    let mut entries = iter(ks).await?;
    super::roles::resolve_all(ks, &mut entries).await?;
    Ok(entries)
}

/// Paginated list. Signs the cursor under `audit_key` so it can't
/// be forged across communities.
///
/// Phase-1 implementation walks the full keyspace and slices
/// in-memory. The hot-path keyspace size is bounded by the
/// community's member count; for the Phase-1 communities (target
/// 10k–100k members) this is fine. A streaming
/// `prefix_iter_raw_after(key)` helper that lets fjall do the
/// slicing lands in Phase 3 once registry-scale communities
/// surface.
pub async fn list_acl_entries_paginated(
    ks: &KeyspaceHandle,
    audit_key: &AuditKey,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<Paginated<VtcAclEntry>, AppError> {
    let mut pairs = ks.prefix_iter_raw(b"acl:".to_vec()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    let snapshot_id: u64 = pairs.len() as u64;
    let mut page = paginate(pairs, cursor, limit, &audit_key.key, snapshot_id, decode)?;
    super::roles::resolve_all(ks, &mut page.items).await?;
    Ok(page)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AdminAuthority, VtcRole};
    use vti_common::audit::AuditKeyStore;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let ks = store.keyspace("acl").expect("ks");
        (ks, dir)
    }

    fn entry(did: &str, role: VtcRole) -> VtcAclEntry {
        VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            admin: AdminAuthority::none(),
            delegated_by: None,
            created_at: 1,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
        }
    }

    #[tokio::test]
    async fn store_then_get_round_trip() {
        let (ks, _dir) = temp_ks().await;
        let e = entry("did:key:zMember1", VtcRole::Member);
        store_acl_entry(&ks, &e).await.unwrap();
        let got = get_acl_entry(&ks, "did:key:zMember1")
            .await
            .unwrap()
            .expect("entry present");
        assert_eq!(got, e);
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_did() {
        let (ks, _dir) = temp_ks().await;
        assert!(
            get_acl_entry(&ks, "did:key:zNobody")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (ks, _dir) = temp_ks().await;
        let e = entry("did:key:zDelete", VtcRole::Member);
        store_acl_entry(&ks, &e).await.unwrap();
        delete_acl_entry(&ks, "did:key:zDelete").await.unwrap();
        // Second delete on an absent row.
        delete_acl_entry(&ks, "did:key:zDelete").await.unwrap();
        assert!(
            get_acl_entry(&ks, "did:key:zDelete")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_acl_entries_returns_every_row() {
        let (ks, _dir) = temp_ks().await;
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_acl_entry(&ks, &entry(did, VtcRole::Member))
                .await
                .unwrap();
        }
        let listed = list_acl_entries(&ks).await.unwrap();
        assert_eq!(listed.len(), 3);
    }

    #[tokio::test]
    async fn paginated_walks_the_keyspace() {
        let (ks, _dir) = temp_ks().await;
        let dir = tempfile::tempdir().unwrap();
        let store2 = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let audit_key_ks = store2.keyspace("audit_key").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        let audit_key = key_store.ensure_initial(&[0xAB; 32]).await.unwrap();

        // Seed 5 members.
        for did in [
            "did:key:zA",
            "did:key:zB",
            "did:key:zC",
            "did:key:zD",
            "did:key:zE",
        ] {
            store_acl_entry(&ks, &entry(did, VtcRole::Member))
                .await
                .unwrap();
        }

        // First page (limit 2).
        let page1 = list_acl_entries_paginated(&ks, &audit_key, None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        assert_eq!(page1.items[0].did, "did:key:zA");
        assert_eq!(page1.items[1].did, "did:key:zB");

        // Decode the wire cursor + walk the next page.
        let cursor1 =
            Cursor::decode(page1.next_cursor.as_deref().unwrap(), &audit_key.key).unwrap();
        let page2 = list_acl_entries_paginated(&ks, &audit_key, Some(&cursor1), 2)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        assert_eq!(page2.items[0].did, "did:key:zC");
        assert_eq!(page2.items[1].did, "did:key:zD");

        // Last page (no further cursor).
        let cursor2 =
            Cursor::decode(page2.next_cursor.as_deref().unwrap(), &audit_key.key).unwrap();
        let page3 = list_acl_entries_paginated(&ks, &audit_key, Some(&cursor2), 2)
            .await
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert_eq!(page3.items[0].did, "did:key:zE");
        assert!(page3.next_cursor.is_none());
    }

    // ---- P0.16: entry → auth Role resolution ----

    /// Console sign-in admits any administrative role, not only a community
    /// administrator (`vtc-admin-roles.md` §6).
    #[test]
    fn any_administrative_role_maps_to_the_admin_session_role() {
        use crate::acl::capability::AdminRole;
        for role in AdminRole::BUILT_IN {
            let mut e = entry("did:key:zA", VtcRole::Member);
            e.admin = AdminAuthority::for_role(role.clone());
            assert_eq!(auth_role_for(&e).unwrap(), Role::Admin, "{role}");
        }
    }

    #[test]
    fn entries_without_an_administrative_role_are_cleanly_forbidden() {
        use axum::response::IntoResponse;
        for role in [
            VtcRole::Admin,
            VtcRole::Moderator,
            VtcRole::Issuer,
            VtcRole::Member,
            VtcRole::custom("editor").unwrap(),
        ] {
            let err = auth_role_for(&entry("did:key:zA", role.clone()))
                .expect_err("no administrative role must not map to an auth role");
            // 403, not 500 — the whole point of P0.16.
            assert_eq!(
                err.into_response().status(),
                axum::http::StatusCode::FORBIDDEN,
                "{role} must yield 403"
            );
        }
    }

    #[test]
    fn forbidden_message_carries_no_serde_internals_or_role_name() {
        let AppError::Forbidden(msg) =
            auth_role_for(&entry("did:key:zA", VtcRole::Moderator)).unwrap_err()
        else {
            panic!("expected Forbidden");
        };
        assert!(!msg.contains("variant"), "must not leak serde text: {msg}");
        assert!(
            !msg.contains("moderator"),
            "must not enumerate the role to an unauth caller: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_auth_role_admits_an_administrator_with_no_contexts() {
        let (ks, _dir) = temp_ks().await;
        let mut e = entry("did:key:zAdmin", VtcRole::Member);
        e.admin = AdminAuthority::for_role(crate::acl::capability::AdminRole::Auditor);
        store_acl_entry(&ks, &e).await.unwrap();

        let (role, contexts) = resolve_auth_role(&ks, "did:key:zAdmin").await.unwrap();
        assert_eq!(role, Role::Admin);
        assert_eq!(
            contexts,
            Vec::<String>::new(),
            "a VTC entry holds no contexts"
        );
    }

    #[tokio::test]
    async fn require_capability_reads_the_live_entry() {
        use crate::acl::Capability;
        let (ks, _dir) = temp_ks().await;
        let mut e = entry("did:key:zAud", VtcRole::Member);
        e.admin = AdminAuthority::for_role(crate::acl::capability::AdminRole::Auditor);
        store_acl_entry(&ks, &e).await.unwrap();
        assert!(
            require_capability(&ks, "did:key:zAud", Capability::AuditRead, None)
                .await
                .is_ok()
        );
        assert!(matches!(
            require_capability(&ks, "did:key:zAud", Capability::ConfigAdmin, None).await,
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            require_capability(&ks, "did:key:zNobody", Capability::AuditRead, None).await,
            Err(AppError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn resolve_auth_role_forbids_non_admin_absent_and_expired() {
        let (ks, _dir) = temp_ks().await;

        // No administrative role → clean Forbidden.
        store_acl_entry(&ks, &entry("did:key:zMod", VtcRole::Moderator))
            .await
            .unwrap();
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zMod").await,
            Err(AppError::Forbidden(_))
        ));

        // Absent DID → Forbidden.
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zNobody").await,
            Err(AppError::Forbidden(_))
        ));

        // Expired admin row → Forbidden (expiry honoured).
        let mut expired = entry("did:key:zStale", VtcRole::Admin);
        expired.admin = AdminAuthority::community_admin();
        expired.expires_at = Some(1); // long past
        store_acl_entry(&ks, &expired).await.unwrap();
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zStale").await,
            Err(AppError::Forbidden(_))
        ));
    }
}
