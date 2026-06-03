//! Issue an **InvitationCredential** (VIC) to a non-member DID — task 2.1.
//!
//! The community invites an as-yet-unknown holder by issuing a VIC sealed to
//! their key and delivered out-of-band (the relayer≠holder / air-gap pattern;
//! the transport itself is Phase 3). This module is the **issuance op**: it
//! allocates a revocation-list slot (so the invite is revocable), issues the
//! VIC through the DTC catalog ([`super::dtc::issue_invitation`]) signed by the
//! community's local key, and persists the status-list state only after the VIC
//! builds — so a build failure never permanently burns a slot.

use affinidi_status_list::StatusPurpose;
use chrono::Duration;
use serde_json::Value;
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::status_list;

use super::dtc;
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
        dtc::issue_invitation(signer, subject_did, Some(&id), Some(&status_ref), validity).await?;
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

    async fn provisioned_status_ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store
            .keyspace("status_lists")
            .expect("status_lists keyspace");
        let state = StatusListState::new(
            StatusPurpose::Revocation,
            format!("{TEST_VTC_DID}/v1/status-lists/revocation"),
        );
        status_list::store_state(&ks, &state)
            .await
            .expect("seed list");
        (dir, store, ks)
    }

    #[tokio::test]
    async fn issues_a_revocable_vic_and_burns_a_slot() {
        let (_dir, _store, ks) = provisioned_status_ks().await;
        let s = signer();

        let assigned_before = get_state(&ks, StatusPurpose::Revocation)
            .await
            .unwrap()
            .unwrap()
            .count_assigned();

        let vic = issue_invitation(&s, &ks, "did:key:zInvitee", Duration::days(7))
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
        let s = signer();
        let err = issue_invitation(&s, &ks, "did:key:zInvitee", Duration::days(7))
            .await
            .expect_err("must refuse without a provisioned list");
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
    }
}
