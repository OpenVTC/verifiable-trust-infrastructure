//! VTC admin-entry domain model — multi-passkey + extensions.
//!
//! Implements **M0.6.1** of the VTC MVP Phase 0 plan. The spec (§5.2,
//! §5.3) calls for admin ACL entries to carry `passkeys:
//! Vec<RegisteredPasskey>` and an `extensions: JsonValue` slot.
//! Touching the shared `vti_common::acl::AclEntry` would break VTA
//! (which uses the same struct with its own `Role` enum), so this
//! module stores the extension as a **sister record** under
//! `admin:<did>` in the `passkey` keyspace:
//!
//! - `acl:<did>` → `AclEntry` — the canonical auth-gating record
//!   (Role::Admin), continues to power `AdminAuth` and friends.
//! - `admin:<did>` → `AdminEntry` — the VTC-specific multi-passkey
//!   + extensions metadata.
//!
//! Both records are written atomically by
//! [`crate::routes::admin::bootstrap`] under a single AppState
//! reference. Phase-1 will unify these into a single VTC ACL shape
//! when the shared crate gains generic-over-Role support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// One device's worth of registered passkey metadata. Lives inside
/// [`AdminEntry::passkeys`]; the actual credential bytes that
/// `webauthn-rs` needs for re-authentication live in the
/// `pk_user:<uuid>` records this passkey was already written to at
/// `claim/finish` time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct RegisteredPasskey {
    /// Hex-encoded WebAuthn credential id. Matches the
    /// `CredentialMapping` key in the passkey store.
    pub credential_id: String,
    /// Operator-supplied label (e.g. `"MacBook Air Touch ID"`).
    pub label: String,
    /// WebAuthn transports — `usb`, `nfc`, `ble`, `internal`, …
    #[serde(default)]
    pub transports: Vec<String>,
    pub registered_at: DateTime<Utc>,
    /// Updated by passkey-login on every successful assertion.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// VTC-specific admin metadata. One per admin DID. The list of
/// passkeys is the source of truth for "which devices can act as
/// this admin" — the `pk_user:<uuid>` records this list points into
/// hold the credential bytes themselves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminEntry {
    pub did: String,
    #[serde(default)]
    pub passkeys: Vec<RegisteredPasskey>,
    /// Community-owned extensibility slot. Bounded by the same
    /// 16 KiB cap the community-profile extension uses (enforced by
    /// route handlers, not this module).
    #[serde(default)]
    pub extensions: Value,
    pub created_at: DateTime<Utc>,
}

impl AdminEntry {
    /// New empty entry — used at bootstrap before the first passkey
    /// gets appended in the same transaction.
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            passkeys: Vec::new(),
            extensions: Value::Null,
            created_at: Utc::now(),
        }
    }
}

const PREFIX: &[u8] = b"admin:";

fn key(did: &str) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(did.as_bytes());
    k
}

pub async fn get_admin_entry(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<AdminEntry>, AppError> {
    ks.get(key(did)).await
}

pub async fn store_admin_entry(ks: &KeyspaceHandle, entry: &AdminEntry) -> Result<(), AppError> {
    ks.insert(key(&entry.did), entry).await
}

pub async fn list_admin_entries(ks: &KeyspaceHandle) -> Result<Vec<AdminEntry>, AppError> {
    let raw = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        match serde_json::from_slice(&v) {
            Ok(e) => out.push(e),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable admin entry"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("passkey-admin-test").expect("ks");
        (ks, dir)
    }

    fn sample_passkey(cred_id: &str, label: &str) -> RegisteredPasskey {
        RegisteredPasskey {
            credential_id: cred_id.into(),
            label: label.into(),
            transports: vec!["internal".into()],
            registered_at: DateTime::parse_from_rfc3339("2026-05-12T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            last_used_at: None,
        }
    }

    #[tokio::test]
    async fn round_trip_stores_and_retrieves() {
        let (ks, _dir) = temp_ks();
        let mut entry = AdminEntry::new("did:key:zAdmin");
        entry.passkeys.push(sample_passkey("deadbeef", "yubikey"));
        entry.extensions = serde_json::json!({"team": "platform"});

        store_admin_entry(&ks, &entry).await.unwrap();
        let got = get_admin_entry(&ks, "did:key:zAdmin")
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got, entry);
    }

    #[tokio::test]
    async fn list_returns_every_admin() {
        let (ks, _dir) = temp_ks();
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_admin_entry(&ks, &AdminEntry::new(did)).await.unwrap();
        }
        let entries = list_admin_entries(&ks).await.unwrap();
        assert_eq!(entries.len(), 3);
        let dids: std::collections::HashSet<_> = entries.iter().map(|e| e.did.as_str()).collect();
        for d in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            assert!(dids.contains(d));
        }
    }

    #[test]
    fn deserialises_legacy_shape_without_extensions() {
        // A future migration might write `admin:` records without
        // some of the newer fields. `#[serde(default)]` on
        // `passkeys` + `extensions` keeps such rows readable; this
        // test pins the contract.
        let legacy = r#"{
            "did": "did:key:zLegacy",
            "createdAt": "2026-05-12T00:00:00Z"
        }"#;
        let entry: AdminEntry = serde_json::from_str(legacy).expect("legacy shape parses");
        assert_eq!(entry.did, "did:key:zLegacy");
        assert!(entry.passkeys.is_empty());
        assert_eq!(entry.extensions, Value::Null);
    }

    #[test]
    fn passkey_serialises_to_camel_case() {
        let pk = sample_passkey("ab", "label");
        let json = serde_json::to_value(&pk).unwrap();
        assert!(json["credentialId"].is_string());
        assert!(json["registeredAt"].is_string());
        assert!(json["lastUsedAt"].is_null());
    }
}
