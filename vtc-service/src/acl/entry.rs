//! `VtcAclEntry` — the VTC's per-DID auth-gate record.
//!
//! Replaces `vti_common::acl::AclEntry` for vtc-side storage so the
//! `role` field can carry [`super::VtcRole`] (with `Moderator`,
//! `Issuer`, `Member`, `Custom(_)` variants beyond the
//! VTA-flavoured `vti_common::acl::Role` taxonomy).
//!
//! ## Wire shape
//!
//! Stored under `acl:<did>` in the `acl` keyspace, same key prefix
//! as the prior `vti_common::acl::AclEntry` shape. The on-disk JSON
//! is field-compatible with the old shape:
//!
//! - `did`, `label`, `allowed_contexts`, `created_at`, `created_by`,
//!   `expires_at` are byte-identical.
//! - `role` was previously a `vti_common::acl::Role`, serialised
//!   `#[serde(rename_all = "lowercase")]` → `"admin"`, etc.
//!   `VtcRole`'s wire shape is the same plain string with a
//!   `custom:<name>` prefix for the new `Custom` variant
//!   (`role.rs` module docs explain the choice). Rows written by
//!   Phase 0's bootstrap path with `Role::Admin` decode to
//!   `VtcRole::Admin` without migration.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::VtcRole;

/// One ACL entry. 1:1 with a [`crate::members::Member`] row by
/// DID, but kept in a separate keyspace because the auth path
/// reads ACL rows on every request and shouldn't pay the cost of
/// loading the richer Member metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VtcAclEntry {
    pub did: String,
    pub role: VtcRole,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Unix-epoch seconds of the last mutation, and who made it.
    ///
    /// Canonical `acl/_shared` carries `updatedAt`/`updatedBy`, and now
    /// that role changes (`acl/change-role`) and entry rewrites
    /// (`acl/grant`) are distinct operations, "when did this last
    /// change, and by whom" is answerable — previously every entry
    /// looked as though it had never moved since creation.
    ///
    /// `#[serde(default)]` keeps rows written before this field
    /// deserializable; they report `None` rather than pretending the
    /// creation time was an update.
    #[serde(default)]
    pub updated_at: Option<u64>,
    #[serde(default)]
    pub updated_by: Option<String>,
    /// Unix-epoch seconds at which this entry expires and should be
    /// pruned by the background sweeper. `None` is permanent.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl VtcAclEntry {
    /// Returns `true` once this entry has passed its
    /// `expires_at`. Permanent entries (`None`) never expire.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self.expires_at {
            Some(deadline) => now_unix >= deadline,
            None => false,
        }
    }
}

/// Decode a `VtcAclEntry` from raw bytes. Public so the
/// [`super::storage`] helpers + pagination callers can reuse the
/// same decode path without duplicating the JSON tax.
pub(crate) fn decode(bytes: &[u8]) -> Result<VtcAclEntry, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AppError::Internal(format!("VtcAclEntry decode: {e}")))
}

/// Iterate `acl:<did>` rows, decoding each into a `VtcAclEntry`.
/// Helper for `list_acl_entries` + paginated walkers.
pub(crate) async fn iter(ks: &KeyspaceHandle) -> Result<Vec<VtcAclEntry>, AppError> {
    let raw = ks.prefix_iter_raw(b"acl:".to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match decode(&v) {
            Ok(entry) => out.push(entry),
            Err(err) => {
                tracing::warn!(error = %err, "skipping unparseable acl entry");
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn is_expired_returns_false_for_permanent_entries() {
        let entry = sample_entry(None);
        assert!(!entry.is_expired(u64::MAX));
    }

    #[test]
    fn is_expired_returns_true_after_deadline() {
        let entry = sample_entry(Some(100));
        assert!(!entry.is_expired(50));
        assert!(entry.is_expired(101));
    }

    #[test]
    fn round_trip_through_json() {
        let entry = sample_entry(Some(200));
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed = decode(&bytes).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn decodes_legacy_role_admin_wire_shape() {
        // Phase 0's bootstrap path wrote rows via
        // `vti_common::acl::store_acl_entry` with `Role::Admin`
        // serialised as the lowercase string `"admin"`. Confirm
        // the new shape decodes those rows without migration.
        let legacy = json!({
            "did": "did:key:zAdmin",
            "role": "admin",
            "label": null,
            "allowed_contexts": [],
            "created_at": 0,
            "created_by": "did:key:vtc-install"
        });
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let entry = decode(&bytes).unwrap();
        assert_eq!(entry.role, VtcRole::Admin);
        assert_eq!(entry.did, "did:key:zAdmin");
        assert_eq!(entry.expires_at, None);
    }

    #[test]
    fn custom_role_round_trips() {
        let entry = VtcAclEntry {
            did: "did:key:zEditor".into(),
            role: VtcRole::custom("editor").unwrap(),
            label: Some("badge holder".into()),
            allowed_contexts: vec![],
            created_at: 1,
            created_by: "did:key:zAdmin".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        };
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed = decode(&bytes).unwrap();
        assert_eq!(parsed.role, VtcRole::Custom("editor".into()));
        assert_eq!(parsed, entry);
    }

    fn sample_entry(expires_at: Option<u64>) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zSomeMember".into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: 42,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at,
        }
    }
}
