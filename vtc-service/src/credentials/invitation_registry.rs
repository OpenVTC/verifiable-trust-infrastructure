//! Registry of **issued** Invitation Credentials (VICs) — the durable record
//! the list + revoke operator surfaces read.
//!
//! One row per VIC `id`, recording its revocation status-list slot (so a revoke
//! can flip the right bit), the invitee, the granted role, who issued it, and
//! its revocation state. Stored in the `invitations` keyspace.
//!
//! This is the issuer-side counterpart to the redeemed-VIC ledger
//! ([`super::invitation_verify::ConsumedInvitation`], `consumed_invitations`):
//! one tracks invitations we *issued*, the other tracks invitations someone
//! *redeemed*.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

const PREFIX: &[u8] = b"invitation:";

fn key(id: &str) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

/// A persisted record of one issued VIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationRecord {
    /// The VIC `id` (`urn:uuid:…`).
    pub id: String,
    /// The invited (subject) DID.
    pub subject_did: String,
    /// Revocation status-list slot this VIC occupies — the bit a revoke flips.
    pub slot: u32,
    /// The role the invitation grants on join, if any (`member` when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The operator DID that issued it.
    pub issued_by: String,
    /// When it was issued.
    pub issued_at: DateTime<Utc>,
    /// The VIC's `validUntil` (RFC3339), echoed for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// When it was revoked, if it has been. `None` = live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl InvitationRecord {
    /// Whether this invitation has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Persist (or overwrite) an invitation record.
pub async fn store_invitation(
    ks: &KeyspaceHandle,
    record: &InvitationRecord,
) -> Result<(), AppError> {
    ks.insert(key(&record.id), record).await
}

/// Fetch one invitation record by VIC `id`.
pub async fn get_invitation(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<InvitationRecord>, AppError> {
    ks.get::<InvitationRecord>(key(id)).await
}

/// List every issued invitation record (newest first).
pub async fn list_invitations(ks: &KeyspaceHandle) -> Result<Vec<InvitationRecord>, AppError> {
    let raw = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
    let mut out: Vec<InvitationRecord> = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match serde_json::from_slice::<InvitationRecord>(&v) {
            Ok(r) => out.push(r),
            Err(e) => tracing::warn!(error = %e, "skipping unparseable invitation row"),
        }
    }
    out.sort_by(|a, b| b.issued_at.cmp(&a.issued_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("invitations").unwrap();
        (dir, store, ks)
    }

    fn rec(id: &str, at: &str) -> InvitationRecord {
        InvitationRecord {
            id: id.into(),
            subject_did: "did:key:zInvitee".into(),
            slot: 7,
            role: Some("moderator".into()),
            issued_by: "did:key:zAdmin".into(),
            issued_at: at.parse().unwrap(),
            valid_until: None,
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn round_trip_and_list_newest_first() {
        let (_d, _s, ks) = ks().await;
        store_invitation(&ks, &rec("urn:uuid:a", "2026-01-01T00:00:00Z"))
            .await
            .unwrap();
        store_invitation(&ks, &rec("urn:uuid:b", "2026-02-01T00:00:00Z"))
            .await
            .unwrap();

        let got = get_invitation(&ks, "urn:uuid:a").await.unwrap().unwrap();
        assert_eq!(got.slot, 7);
        assert!(!got.is_revoked());

        let all = list_invitations(&ks).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "urn:uuid:b", "newest first");
    }
}
