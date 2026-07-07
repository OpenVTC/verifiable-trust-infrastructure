use affinidi_tdk::didcomm::Message;

use crate::acl::check_acl_full;
use crate::auth::AuthClaims;
use crate::auth::session::{now_epoch, resolve_did_session};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Extract sender DID from a DIDComm message and look up their ACL entry,
/// returning unified `AuthClaims`.
///
/// Routes through [`check_acl_full`] (rather than the lower-level
/// `get_acl_entry`) so that `expires_at` is enforced identically to the
/// REST path. A time-bounded ACL grant must stop working over both
/// transports the moment it lapses; previously the DIDComm-side lookup
/// skipped the expiry check, leaving expired credentials live for any
/// caller still talking via DIDComm.
pub async fn auth_from_message(
    msg: &Message,
    acl_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
) -> Result<AuthClaims, AppError> {
    let did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

    auth_from_did(did, acl_ks, sessions_ks).await
}

/// Resolve an envelope-authenticated sender DID into unified `AuthClaims`.
///
/// This is the DID-based core shared by every intrinsic-sender transport
/// (DIDComm authcrypt via [`auth_from_message`], raw-TSP via
/// `messaging::tsp_inbound`). The caller has *already* proven the sender
/// DID cryptographically — by unpacking an authcrypt envelope, or by
/// TSP unpack returning the verified `sender_vid` — so this function only
/// performs ACL lookup + session resolution + claim construction, never
/// signature verification.
///
/// Routes through [`check_acl_full`] (rather than the lower-level
/// `get_acl_entry`) so that `expires_at` is enforced identically to the
/// REST path. A time-bounded ACL grant must stop working over every
/// transport the moment it lapses.
///
/// Resolves (get-or-creates) the caller's **canonical, DID-keyed session** via
/// [`resolve_did_session`] and returns the session's *persisted* `acr`/`amr`
/// rather than a hardcoded `aal1`. This is what makes intrinsic-sender callers
/// first-class in the step-up flow: a step-up elevation recorded on this
/// session while handling one message is observed by the caller's subsequent
/// messages, instead of being reset to `aal1` every time.
pub async fn auth_from_did(
    did: &str,
    acl_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
) -> Result<AuthClaims, AppError> {
    // Strip any fragment (e.g. did:key:z6Mk...#z6Mk... → did:key:z6Mk...)
    let base_did = did.split('#').next().unwrap_or(did);

    let (role, allowed_contexts) = check_acl_full(acl_ks, base_did).await?;

    // Get-or-create the persistent session keyed on the DID. The session_id
    // *is* the DID, so the delegated step-up records this id and elevates this
    // exact row; a later message resolves the same row and sees the raised acr
    // (or the post-window downgrade back to aal1, applied inside the resolver).
    let session = resolve_did_session(sessions_ks, base_did, now_epoch()).await?;

    Ok(AuthClaims {
        did: base_did.to_string(),
        role,
        allowed_contexts,
        session_id: session.session_id,
        // Intrinsic-sender auth carries no JWT, hence no access-token expiry.
        access_expires_at: 0,
        // Trust the session's persisted assurance level. A freshly-created
        // session is `aal1` with a single `did` factor; an elevated one reports
        // `aal2` until its window lapses.
        amr: session.amr,
        acr: session.acr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEntry, Role, store_acl_entry};
    use crate::auth::session::now_epoch;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn message_from(did: &str) -> Message {
        // Builds the minimal message shape `auth_from_message` consumes —
        // only `from` is read by the function under test.
        Message::build(
            "test-id".to_string(),
            "https://example.com/test/1.0/ping".to_string(),
            serde_json::json!({}),
        )
        .from(did.to_string())
        .finalize()
    }

    async fn fresh_acl_ks() -> (Store, KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let acl_ks = store.keyspace(crate::keyspaces::ACL).unwrap();
        let sessions_ks = store.keyspace(crate::keyspaces::SESSIONS).unwrap();
        (store, acl_ks, sessions_ks, dir)
    }

    /// An expired ACL entry must be rejected over DIDComm with the same
    /// `Forbidden` outcome the REST `check_acl_full` path produces. This
    /// pins the cross-transport invariant the previous direct-lookup
    /// implementation broke.
    #[tokio::test]
    async fn rejects_expired_entry() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zExpired";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into()])
                .with_created_at(now_epoch().saturating_sub(7200))
                .with_expires_at(Some(now_epoch().saturating_sub(60))), // expired one minute ago
        )
        .await
        .unwrap();

        let msg = message_from(did);
        let err = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(ref m) if m.contains("expired")),
            "expected Forbidden(expired), got {err:?}"
        );
    }

    /// A current (non-expired) entry resolves to the right role + contexts.
    /// Ensures the refactor didn't accidentally break the happy path.
    #[tokio::test]
    async fn accepts_unexpired_entry_with_role_and_contexts() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zLive";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into(), "ctx-b".into()])
                .with_expires_at(Some(now_epoch() + 3600)),
        )
        .await
        .unwrap();

        let msg = message_from(did);
        let claims = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.did, did);
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.allowed_contexts, vec!["ctx-a", "ctx-b"]);
    }

    /// DID-fragment senders (e.g. `did:key:z…#z…`) must collapse to the
    /// base DID for the ACL lookup. Pre-existing behaviour preserved.
    #[tokio::test]
    async fn fragment_in_sender_collapses_to_base_did() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let base = "did:key:zBase";
        store_acl_entry(&acl_ks, &AclEntry::new(base, Role::Reader, "test"))
            .await
            .unwrap();

        let msg = message_from(&format!("{base}#zBase"));
        let claims = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.did, base);
    }

    /// `auth_from_did` (the transport-neutral core) resolves a DID with a
    /// live ACL entry to the right role + contexts. This is the path the
    /// TSP inbound loop drives directly (sender DID, no DIDComm message).
    #[tokio::test]
    async fn auth_from_did_resolves_role_and_contexts() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zDidCore";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test")
                .with_contexts(vec!["ctx-a".into(), "ctx-b".into()])
                .with_expires_at(Some(now_epoch() + 3600)),
        )
        .await
        .unwrap();

        let claims = auth_from_did(did, &acl_ks, &sessions_ks).await.unwrap();
        assert_eq!(claims.did, did);
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.allowed_contexts, vec!["ctx-a", "ctx-b"]);
    }

    /// A DID with no ACL entry errors (peer not authorized) — the TSP loop
    /// relies on this to drop unknown senders.
    #[tokio::test]
    async fn auth_from_did_unknown_did_errors() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let err = auth_from_did("did:key:zUnknownPeer", &acl_ks, &sessions_ks)
            .await
            .unwrap_err();
        // No ACL entry → check_acl_full surfaces a not-found / forbidden
        // class error; the exact variant is the ACL layer's, we just pin
        // that it is an error (never silently authorized).
        assert!(
            matches!(err, AppError::Forbidden(_) | AppError::NotFound(_)),
            "expected unauthorized-class error, got {err:?}"
        );
    }

    /// Fragmented DID collapses to base for the core too.
    #[tokio::test]
    async fn auth_from_did_fragment_collapses() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let base = "did:key:zCoreBase";
        store_acl_entry(&acl_ks, &AclEntry::new(base, Role::Reader, "test"))
            .await
            .unwrap();

        let claims = auth_from_did(&format!("{base}#zCoreBase"), &acl_ks, &sessions_ks)
            .await
            .unwrap();
        assert_eq!(claims.did, base);
    }

    #[tokio::test]
    async fn missing_sender_is_authentication_error() {
        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let mut msg = message_from("did:key:zAnything");
        msg.from = None;
        let err = auth_from_message(&msg, &acl_ks, &sessions_ks)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "got {err:?}");
    }

    /// First contact reports `aal1`, keyed on the DID. After a step-up elevates
    /// that same `session:{did}` row, the *next* message reports the elevated
    /// acr — the whole point of a persistent, transport-agnostic session. Before
    /// this change `auth_from_did` hardcoded `aal1`, so a verified elevation was
    /// invisible and the caller could never clear a step-up gate over DIDComm.
    #[tokio::test]
    async fn auth_from_did_reports_persisted_elevated_acr() {
        use crate::auth::session::{get_session, update_session};

        let (_store, acl_ks, sessions_ks, _dir) = fresh_acl_ks().await;
        let did = "did:key:zElevatedCaller";
        store_acl_entry(
            &acl_ks,
            &AclEntry::new(did, Role::Admin, "test").with_expires_at(Some(now_epoch() + 3600)),
        )
        .await
        .unwrap();

        // First contact → aal1, session_id is the DID.
        let first = auth_from_did(did, &acl_ks, &sessions_ks).await.unwrap();
        assert_eq!(first.acr, "aal1");
        assert_eq!(first.session_id, did);

        // Elevate the row as the step-up handler does.
        let mut s = get_session(&sessions_ks, did).await.unwrap().unwrap();
        s.acr = "aal2".into();
        s.acr_expires_at = Some(now_epoch() + 900);
        update_session(&sessions_ks, &s).await.unwrap();

        // Next message observes the elevation.
        let next = auth_from_did(did, &acl_ks, &sessions_ks).await.unwrap();
        assert_eq!(next.acr, "aal2");
    }
}
