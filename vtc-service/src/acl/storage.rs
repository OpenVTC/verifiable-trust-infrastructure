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
use vti_common::auth::extractor::AuthClaims;
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::pagination::{Cursor, Paginated, paginate};
use vti_common::store::KeyspaceHandle;

use super::VtcRole;
use super::entry::{VtcAclEntry, decode, iter};

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Map a stored [`VtcRole`] to the `vti_common::acl::Role` the JWT/session
/// layer understands.
///
/// Phase 1's auth/session/passkey stack is keyed to the VTA role taxonomy;
/// only `Admin` has a session-layer equivalent. The other VTC roles
/// (`Moderator`/`Issuer`/`Member`/`Custom`) are valid ACL records but carry
/// no JWT-session semantics yet (Phase 2 makes `AuthClaims` VtcRole-aware),
/// so they're refused with a clean `Forbidden`. Fails closed — no privilege
/// is granted, and the message carries neither serde internals nor the role
/// name (this is consumed on the unauthenticated `/auth/challenge` path).
pub fn map_vtc_role_to_auth_role(role: &VtcRole) -> Result<Role, AppError> {
    match role {
        VtcRole::Admin => Ok(Role::Admin),
        VtcRole::Moderator | VtcRole::Issuer | VtcRole::Member | VtcRole::Custom(_) => Err(
            AppError::Forbidden("DID is not permitted to authenticate on this VTC".into()),
        ),
    }
}

/// VTC analogue of `vti_common::acl::check_acl_full`: resolve a DID's auth
/// role + allowed contexts from the VTC ACL, decoding the row as a
/// [`VtcAclEntry`] and mapping `VtcRole → Role`.
///
/// **Use this — not `vti_common::acl::check_acl[_full]` — for every
/// auth-time ACL gate on the VTC store.** The vti-common helpers decode the
/// row into the VTA `Role` taxonomy and hard-error
/// (`AppError::Serialization` → HTTP 500 leaking the serde text) on any
/// VTC-only role string. This decoder never 500s on a VTC role; it returns a
/// clean `Forbidden` for absent / expired / non-admin rows. P0.16.
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
    let role = map_vtc_role_to_auth_role(&entry.role)?;
    Ok((role, entry.allowed_contexts))
}

/// Retrieve an ACL entry by DID. `Ok(None)` if absent.
pub async fn get_acl_entry(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<VtcAclEntry>, AppError> {
    let key = acl_key(did);
    let raw = ks.get_raw(key.as_bytes()).await?;
    match raw {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

/// Store (create or overwrite) an ACL entry.
pub async fn store_acl_entry(ks: &KeyspaceHandle, entry: &VtcAclEntry) -> Result<(), AppError> {
    ks.insert(acl_key(&entry.did), entry).await
}

/// Delete an ACL entry by DID. Idempotent — `Ok(())` whether the
/// row existed or not.
pub async fn delete_acl_entry(ks: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    ks.remove(acl_key(did)).await
}

/// Validate that `caller` is allowed to assign `target_role`.
///
/// Mirrors `vti_common::acl::validate_role_assignment` but speaks
/// VTC's role taxonomy:
///
/// - Only an `Admin` AuthClaims (vti-common's `Role::Admin`) can
///   assign `VtcRole::Admin`.
/// - Otherwise (`Moderator`, `Issuer`, `Member`, `Custom`), the
///   caller must hold the vti-common `Role::Admin` or
///   `Role::Initiator` role — the existing "management-level"
///   caller bar.
///
/// AuthClaims' `role` field is still keyed to
/// `vti_common::acl::Role` because Phase 1 keeps the JWT shape
/// from Phase 0 unchanged. Phase 2 swaps the auth layer to a
/// VtcRole-aware AuthClaims; for now this thin shim does the
/// VTC-side mapping.
pub fn validate_vtc_role_assignment(
    caller: &AuthClaims,
    target_role: &VtcRole,
) -> Result<(), AppError> {
    use vti_common::acl::Role as ViRole;
    if matches!(
        caller.role,
        ViRole::Monitor | ViRole::Reader | ViRole::Application
    ) {
        return Err(AppError::Forbidden(
            "insufficient role to assign roles".into(),
        ));
    }
    if matches!(target_role, VtcRole::Admin) && caller.role != ViRole::Admin {
        return Err(AppError::Forbidden(
            "only admins can assign the admin role".into(),
        ));
    }
    Ok(())
}

/// Return every ACL entry in the keyspace. Unbounded — intended
/// for whole-keyspace operations like audit emission +
/// emergency-bootstrap cleanup, not for user-facing list
/// endpoints. Use [`list_acl_entries_paginated`] for those.
pub async fn list_acl_entries(ks: &KeyspaceHandle) -> Result<Vec<VtcAclEntry>, AppError> {
    iter(ks).await
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
    paginate(pairs, cursor, limit, &audit_key.key, snapshot_id, decode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::VtcRole;
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
            allowed_contexts: vec![],
            created_at: 1,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
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

    // ---- P0.16: VtcRole → auth Role resolution ----

    #[test]
    fn admin_maps_to_admin_role() {
        assert_eq!(
            map_vtc_role_to_auth_role(&VtcRole::Admin).unwrap(),
            Role::Admin
        );
    }

    #[test]
    fn non_admin_roles_are_cleanly_forbidden() {
        use axum::response::IntoResponse;
        for role in [
            VtcRole::Moderator,
            VtcRole::Issuer,
            VtcRole::Member,
            VtcRole::custom("editor").unwrap(),
        ] {
            let err = map_vtc_role_to_auth_role(&role)
                .expect_err("non-admin role must not map to an auth role");
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
        let AppError::Forbidden(msg) = map_vtc_role_to_auth_role(&VtcRole::Moderator).unwrap_err()
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
    async fn resolve_auth_role_admits_admin_with_contexts() {
        let (ks, _dir) = temp_ks().await;
        let mut e = entry("did:key:zAdmin", VtcRole::Admin);
        e.allowed_contexts = vec!["ctx-a".into()];
        store_acl_entry(&ks, &e).await.unwrap();

        let (role, contexts) = resolve_auth_role(&ks, "did:key:zAdmin").await.unwrap();
        assert_eq!(role, Role::Admin);
        assert_eq!(contexts, vec!["ctx-a".to_string()]);
    }

    #[tokio::test]
    async fn resolve_auth_role_forbids_non_admin_absent_and_expired() {
        let (ks, _dir) = temp_ks().await;

        // Non-admin VTC role → clean Forbidden (would 500 via the VTA
        // decoder pre-P0.16).
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
        expired.expires_at = Some(1); // long past
        store_acl_entry(&ks, &expired).await.unwrap();
        assert!(matches!(
            resolve_auth_role(&ks, "did:key:zStale").await,
            Err(AppError::Forbidden(_))
        ));
    }
}
