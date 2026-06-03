//! Issue an **InvitationCredential** (VIC) to a non-member DID — task 2.1.
//!
//! The community invites an as-yet-unknown holder by issuing a VIC sealed to
//! their key and delivered out-of-band (the relayer≠holder / air-gap pattern;
//! the transport itself is Phase 3). This module is the **issuance op**: it
//! allocates a revocation-list slot (so the invite is revocable), issues the
//! VIC through the DTG catalog ([`super::dtg::issue_invitation`]) signed by the
//! community's local key, and persists the status-list state only after the VIC
//! builds — so a build failure never permanently burns a slot.

use affinidi_status_list::StatusPurpose;
use chrono::Duration;
use serde_json::Value;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::status_list;

use super::dtg;
use super::signer::LocalSigner;
use super::vmc::CredentialStatusRef;

/// Default validity for an invitation — short-lived, since an invite is a
/// one-shot onboarding artifact.
pub const DEFAULT_INVITATION_VALIDITY: Duration = Duration::days(7);

/// Issue a revocable Invitation credential to `subject_did` (a non-member).
///
/// Allocates a slot in the community's **revocation** status list, issues the
/// VIC via the catalog, and stores the updated status-list state. Returns the
/// signed VIC as JSON.
///
/// Errors: [`AppError::Internal`] if the revocation list is not provisioned or
/// is exhausted.
pub async fn issue_invitation(
    signer: &LocalSigner,
    status_lists_ks: &KeyspaceHandle,
    schemas_ks: &KeyspaceHandle,
    subject_did: &str,
    validity: Duration,
) -> Result<Value, AppError> {
    let mut row = status_list::get_state(status_lists_ks, StatusPurpose::Revocation)
        .await?
        .ok_or_else(|| {
            AppError::Internal(
                "revocation status list not provisioned — set `public_url` + restart".into(),
            )
        })?;

    let slot = status_list::allocate(&mut row).ok_or_else(|| {
        AppError::Internal(format!(
            "revocation status list exhausted (capacity = {})",
            row.capacity
        ))
    })?;

    let status_ref = CredentialStatusRef::revocation(row.list_credential_id.clone(), slot);
    let id = format!("urn:uuid:{}", Uuid::new_v4());

    // Build first; persist the burned slot only on success.
    let vic =
        dtg::issue_invitation(signer, subject_did, Some(&id), Some(&status_ref), validity).await?;

    // Issue-time schema validation (task 2.3): if an InvitationCredential schema
    // is registered in the schema store, the VIC must conform before the slot is
    // committed — so a non-conforming invite never burns a revocation slot.
    crate::schemas::validate_issued(schemas_ks, &vic).await?;

    status_list::store_state(status_lists_ks, &row).await?;

    Ok(vic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_list::{StatusListState, get_state};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_VTC_DID.into(), &[0xCC; 32])
    }

    /// A provisioned revocation status list + an (empty) schemas keyspace.
    async fn provisioned() -> (tempfile::TempDir, Store, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store
            .keyspace("status_lists")
            .expect("status_lists keyspace");
        let schemas_ks = store.keyspace("schemas").expect("schemas keyspace");
        let state = StatusListState::new(
            StatusPurpose::Revocation,
            format!("{TEST_VTC_DID}/v1/status-lists/revocation"),
        );
        status_list::store_state(&ks, &state)
            .await
            .expect("seed list");
        (dir, store, ks, schemas_ks)
    }

    #[tokio::test]
    async fn issues_a_revocable_vic_and_burns_a_slot() {
        let (_dir, _store, ks, schemas_ks) = provisioned().await;
        let s = signer();

        let assigned_before = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap()
            .count_assigned();

        let vic = issue_invitation(&s, &ks, &schemas_ks, "did:key:zInvitee", Duration::days(7))
            .await
            .expect("issue VIC");

        // Catalog Invitation type + revocable + subject is the invitee.
        let types: Vec<String> = serde_json::from_value(vic["type"].clone()).unwrap();
        assert!(
            types.iter().any(|t| t == "InvitationCredential"),
            "{types:?}"
        );
        assert_eq!(vic["credentialSubject"]["id"], "did:key:zInvitee");
        assert!(
            vic.get("credentialStatus").is_some(),
            "VIC must be revocable"
        );
        s.verify(&serde_json::from_value(vic.clone()).unwrap())
            .expect("VIC proof verifies");

        // A slot was allocated + persisted.
        let assigned_after = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap()
            .count_assigned();
        assert_eq!(
            assigned_after,
            assigned_before + 1,
            "issuing a VIC must burn exactly one revocation slot"
        );
    }

    #[tokio::test]
    async fn refuses_when_revocation_list_not_provisioned() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("status_lists").unwrap();
        let schemas_ks = store.keyspace("schemas").unwrap();
        let s = signer();
        let err = issue_invitation(&s, &ks, &schemas_ks, "did:key:zInvitee", Duration::days(7))
            .await
            .expect_err("must refuse without a provisioned list");
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
    }

    /// A registered InvitationCredential schema is enforced at issue time, and a
    /// non-conforming invite never burns a revocation slot.
    #[tokio::test]
    async fn registered_schema_is_enforced_and_slot_not_burned_on_violation() {
        use crate::schemas::{SchemaEntry, SchemaKind, store_schema};
        let (_dir, _store, ks, schemas_ks) = provisioned().await;
        let s = signer();

        // Require a `invitedBy` subject field the catalog VIC subject ({id})
        // never has → every VIC fails validation.
        store_schema(
            &schemas_ks,
            &SchemaEntry {
                type_uri: "InvitationCredential".into(),
                dtg_type: Some("InvitationCredential".into()),
                credential_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["id", "invitedBy"]
                })),
                kind: SchemaKind::Issues,
                description: None,
                created_at: chrono::Utc::now(),
                created_by_did: "did:key:zAdmin".into(),
            },
        )
        .await
        .unwrap();

        let before = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap()
            .count_assigned();

        let err = issue_invitation(&s, &ks, &schemas_ks, "did:key:zInvitee", Duration::days(7))
            .await
            .expect_err("non-conforming VIC must be refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");

        let after = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap()
            .count_assigned();
        assert_eq!(after, before, "a rejected VIC must not burn a slot");
    }
}
