//! Per-DID, per-log-version key handle store.
//!
//! Webvh log entries reference keys by their public-key multibase
//! (`update_keys`) or by hash (`next_key_hashes`). The VTA needs to be
//! able to map "this hash from log entry version-id N" → "the secret
//! material I should use" without scanning the entire keys keyspace.
//!
//! This module keeps a per-DID, per-version index of key handles:
//!
//! ```text
//! webvh:<scid>:<version-id>:<hash>
//!     ↳ active webvh authorization key (signs the next log entry)
//!
//! webvh:<scid>:<version-id>:pre-rotation:<hash>
//!     ↳ committed pre-rotation key (referenced from this entry's
//!       `next_key_hashes`; promoted to active in the next entry)
//!
//! webvh:<scid>:<version-id>:vm:<fragment-id>:<hash>
//!     ↳ verificationMethod key in the DID document at this version
//!
//! superseded:webvh:<scid>:<version-id>:...
//!     ↳ any of the above, after a subsequent log entry has supplanted
//!       them. Retained for audit / recovery; never deleted.
//! ```
//!
//! Values are [`WebvhKeyHandle`] structs carrying enough metadata to
//! re-derive the secret from the BIP-32 seed (`derivation_path` +
//! `seed_id`). The secret itself is never persisted — same convention
//! as the legacy `key:{key_id}` records.
//!
//! Lazy migration of legacy `key:{key_id}` records into this convention
//! happens in [`super::update::load_active_update_key`], not here. This
//! module is the canonical store; the migration story is the
//! responsibility of the caller that owns the legacy fallback path.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vti_common::error::AppError;

use crate::store::KeyspaceHandle;

/// Role of a key in webvh's signing / verification model.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebvhKeyRole {
    /// Authorization key — currently in `update_keys` for this version,
    /// allowed to sign the next log entry.
    UpdateKey,
    /// Pre-rotation commitment — referenced from `next_key_hashes` of
    /// this version's log entry; not yet authorized to sign. Promoted
    /// to `UpdateKey` when the next log entry includes it in
    /// `update_keys`.
    PreRotation,
    /// VerificationMethod in the DID document at this version. The
    /// fragment id (`#key-N`) is stable across the lifetime of this
    /// version; subsequent rotations mint fresh fragment ids.
    Verification { fragment_id: u32 },
}

/// Persisted handle for a webvh-managed key. Carries enough metadata to
/// re-derive the secret from the seed; the secret itself is never
/// stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebvhKeyHandle {
    pub scid: String,
    /// Webvh log-entry version-id that introduced this key
    /// (e.g. "3-z6Mk...").
    pub version_id: String,
    /// Hash committed in the log entry (`base58btc(sha256(multibase))`,
    /// matching the form webvh uses in `next_key_hashes`).
    pub hash: String,
    /// Multibase-encoded public key (matching the form webvh uses in
    /// `update_keys`).
    pub public_key: String,
    /// BIP-32 derivation path under the active seed. Re-derive the
    /// secret with `ExtendedSigningKey::from_seed(seed).derive(path)`.
    pub derivation_path: String,
    /// Active seed id when the key was minted. Lets the caller pick
    /// the right seed if the VTA later supports multi-seed.
    pub seed_id: Option<u32>,
    pub role: WebvhKeyRole,
    pub label: String,
    pub created_at: DateTime<Utc>,
}

const ACTIVE_PREFIX: &str = "webvh:";
const SUPERSEDED_PREFIX: &str = "superseded:webvh:";

/// Build the storage key for a handle. Mirrors the prefix layout
/// documented at the top of the module.
fn storage_key(handle: &WebvhKeyHandle) -> String {
    storage_key_for(&handle.scid, &handle.version_id, &handle.role, &handle.hash)
}

fn storage_key_for(scid: &str, version_id: &str, role: &WebvhKeyRole, hash: &str) -> String {
    match role {
        WebvhKeyRole::UpdateKey => {
            format!("{ACTIVE_PREFIX}{scid}:{version_id}:{hash}")
        }
        WebvhKeyRole::PreRotation => {
            format!("{ACTIVE_PREFIX}{scid}:{version_id}:pre-rotation:{hash}")
        }
        WebvhKeyRole::Verification { fragment_id } => {
            format!("{ACTIVE_PREFIX}{scid}:{version_id}:vm:{fragment_id}:{hash}")
        }
    }
}

fn supersede_key_for(active_key: &str) -> String {
    // `webvh:abc:1:hash` → `superseded:webvh:abc:1:hash`
    format!("{SUPERSEDED_PREFIX}{}", &active_key[ACTIVE_PREFIX.len()..])
}

/// Persist a handle under the active prefix.
pub async fn install(keys_ks: &KeyspaceHandle, handle: &WebvhKeyHandle) -> Result<(), AppError> {
    keys_ks.insert(storage_key(handle), handle).await
}

/// Direct lookup by `(scid, version_id, role, hash)`. O(1) — every
/// caller in the update flow has these three pieces from the log entry.
///
/// Test-only today: the production update flow scans by hash via
/// [`find_handle_by_hash`] because callers don't yet thread the
/// `version_id` through. Kept available for tests + future migration.
#[cfg(test)]
pub async fn load_handle(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    version_id: &str,
    role: WebvhKeyRole,
    hash: &str,
) -> Result<Option<WebvhKeyHandle>, AppError> {
    keys_ks
        .get::<WebvhKeyHandle>(storage_key_for(scid, version_id, &role, hash))
        .await
}

/// Convenience: scan every active version of a SCID for the given hash.
/// Returns the first match across versions, regardless of role. Used by
/// pre-rotation promotion (the previous version's `pre-rotation:<hash>`
/// becomes the next version's active update key under the same hash).
pub async fn find_handle_by_hash(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    hash: &str,
) -> Result<Option<WebvhKeyHandle>, AppError> {
    let prefix = format!("{ACTIVE_PREFIX}{scid}:");
    let raw_keys = keys_ks.prefix_keys(prefix.as_bytes().to_vec()).await?;
    for raw in raw_keys {
        let key = match std::str::from_utf8(&raw) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !key.ends_with(hash) {
            continue;
        }
        if let Some(handle) = keys_ks.get::<WebvhKeyHandle>(raw).await? {
            return Ok(Some(handle));
        }
    }
    Ok(None)
}

/// Move every handle for `(scid, version_id)` from the active prefix
/// to the `superseded:` prefix. Idempotent — re-running on an
/// already-superseded version is a no-op.
pub async fn supersede_keys_for_version(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    version_id: &str,
) -> Result<(), AppError> {
    // Match every shape: `webvh:<scid>:<version-id>:<hash>`,
    // `webvh:<scid>:<version-id>:pre-rotation:<hash>`,
    // `webvh:<scid>:<version-id>:vm:<frag>:<hash>`.
    let prefix = format!("{ACTIVE_PREFIX}{scid}:{version_id}:");
    let raw_keys = keys_ks.prefix_keys(prefix.as_bytes().to_vec()).await?;
    for raw in raw_keys {
        let key = match std::str::from_utf8(&raw) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        let handle: Option<WebvhKeyHandle> = keys_ks.get(raw.clone()).await?;
        let Some(handle) = handle else {
            continue;
        };
        let new_key = supersede_key_for(&key);
        keys_ks.insert(new_key.into_bytes(), &handle).await?;
        keys_ks.remove(raw).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn test_keys_ks() -> KeyspaceHandle {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        // Leak the tempdir so the keyspace stays valid for the test.
        // Test fixture only — no production code does this.
        std::mem::forget(dir);
        let store = Store::open(&cfg).expect("open store");
        store.keyspace(crate::keyspaces::KEYS).expect("keyspace")
    }

    fn handle(scid: &str, version_id: &str, role: WebvhKeyRole, hash: &str) -> WebvhKeyHandle {
        WebvhKeyHandle {
            scid: scid.into(),
            version_id: version_id.into(),
            hash: hash.into(),
            public_key: format!("z6Mk{hash}Pub"),
            derivation_path: "m/26'/0'/0'/0".into(),
            seed_id: Some(1),
            role,
            label: "test".into(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn install_and_load_round_trip_for_each_role() {
        let ks = test_keys_ks().await;
        let scid = "Q123";
        let v1 = "1-zVer";

        let update_handle = handle(scid, v1, WebvhKeyRole::UpdateKey, "zHashUpdate");
        let pre_handle = handle(scid, v1, WebvhKeyRole::PreRotation, "zHashPre");
        let vm_handle = handle(
            scid,
            v1,
            WebvhKeyRole::Verification { fragment_id: 7 },
            "zHashVm",
        );

        install(&ks, &update_handle).await.unwrap();
        install(&ks, &pre_handle).await.unwrap();
        install(&ks, &vm_handle).await.unwrap();

        let loaded = load_handle(&ks, scid, v1, WebvhKeyRole::UpdateKey, "zHashUpdate")
            .await
            .unwrap()
            .expect("update key handle present");
        assert_eq!(loaded.public_key, update_handle.public_key);

        let loaded_pre = load_handle(&ks, scid, v1, WebvhKeyRole::PreRotation, "zHashPre")
            .await
            .unwrap()
            .expect("pre-rotation handle present");
        assert_eq!(loaded_pre.role, WebvhKeyRole::PreRotation);

        let loaded_vm = load_handle(
            &ks,
            scid,
            v1,
            WebvhKeyRole::Verification { fragment_id: 7 },
            "zHashVm",
        )
        .await
        .unwrap()
        .expect("vm handle present");
        assert!(matches!(
            loaded_vm.role,
            WebvhKeyRole::Verification { fragment_id: 7 }
        ));
    }

    #[tokio::test]
    async fn find_handle_by_hash_finds_across_roles_and_versions() {
        let ks = test_keys_ks().await;
        let scid = "Q123";

        // Same hash committed as pre-rotation in v1 and promoted to
        // update_key in v2 — exactly the lifecycle of a webvh
        // pre-rotation key.
        let pre_v1 = handle("Q123", "1-zV", WebvhKeyRole::PreRotation, "zHashShared");
        let update_v2 = handle("Q123", "2-zV", WebvhKeyRole::UpdateKey, "zHashShared");
        install(&ks, &pre_v1).await.unwrap();
        install(&ks, &update_v2).await.unwrap();

        // Either match is acceptable; the function returns the first
        // hit. The test exercises that the function FINDS something
        // when the hash exists under any version + role.
        let found = find_handle_by_hash(&ks, scid, "zHashShared")
            .await
            .unwrap()
            .expect("should find handle by hash");
        assert_eq!(found.hash, "zHashShared");
    }

    #[tokio::test]
    async fn supersede_moves_all_roles_for_a_version() {
        let ks = test_keys_ks().await;
        let scid = "Q123";
        let v1 = "1-zVer";

        install(&ks, &handle(scid, v1, WebvhKeyRole::UpdateKey, "zU"))
            .await
            .unwrap();
        install(&ks, &handle(scid, v1, WebvhKeyRole::PreRotation, "zP"))
            .await
            .unwrap();
        install(
            &ks,
            &handle(
                scid,
                v1,
                WebvhKeyRole::Verification { fragment_id: 0 },
                "zV",
            ),
        )
        .await
        .unwrap();

        // Untouched: a different version keeps its handles after supersede.
        install(&ks, &handle(scid, "2-zVer", WebvhKeyRole::UpdateKey, "zU2"))
            .await
            .unwrap();

        supersede_keys_for_version(&ks, scid, v1).await.unwrap();

        // v1 active entries are gone.
        assert!(
            load_handle(&ks, scid, v1, WebvhKeyRole::UpdateKey, "zU")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            load_handle(&ks, scid, v1, WebvhKeyRole::PreRotation, "zP")
                .await
                .unwrap()
                .is_none()
        );

        // v1 superseded entries are present.
        let superseded_key = format!("{SUPERSEDED_PREFIX}{scid}:{v1}:zU");
        let restored: Option<WebvhKeyHandle> = ks.get(superseded_key.into_bytes()).await.unwrap();
        assert!(restored.is_some(), "superseded entry should exist");

        // v2 entry untouched.
        assert!(
            load_handle(&ks, scid, "2-zVer", WebvhKeyRole::UpdateKey, "zU2")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn supersede_is_idempotent() {
        let ks = test_keys_ks().await;
        let scid = "Q";
        let v1 = "1-z";
        install(&ks, &handle(scid, v1, WebvhKeyRole::UpdateKey, "zU"))
            .await
            .unwrap();

        supersede_keys_for_version(&ks, scid, v1).await.unwrap();
        // No-op the second time around — must not panic or error.
        supersede_keys_for_version(&ks, scid, v1).await.unwrap();
    }
}
